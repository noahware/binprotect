#include "pe_rtti.hpp"
#include <ranges>
#include <spdlog/spdlog.h>

struct complete_object_locator_t
{
	[[nodiscard]] bool is_signature_valid() const
	{
		return signature == 0 || signature == 1;
	}

	[[nodiscard]] bool is_valid(const binwrite::rva_t this_rva) const
	{
		return is_signature_valid() && this_rva.value() == self_rva;
	}

	std::uint32_t signature;
	std::uint32_t offset;
	std::uint32_t constructor_offset;
	std::uint32_t type_rva;
	std::uint32_t hierarchy_rva;
	std::uint32_t self_rva;
};

static std::shared_ptr<binwrite::dir64_reloc_symbol_ref_t> dir64_reloc_ref_at(const binwrite::portable_executable_t& pe, const binwrite::rva_t rva)
{
	return pe.find_symbol_ref<binwrite::dir64_reloc_symbol_ref_t>(rva);
}

struct type_descriptor_t
{
	[[nodiscard]] bool is_valid(const binwrite::portable_executable_t& pe, const binwrite::rva_t this_rva) const
	{
		const auto vftable_ref = dir64_reloc_ref_at(pe, this_rva);

		if (!vftable_ref)
		{
			return false;
		}

		const auto vftable_rva = vftable_ref->target()->rva();

		if (!vftable_rva)
		{
			return false;
		}

		const auto virtual_function_entry = dir64_reloc_ref_at(pe, *vftable_rva);

		if (!virtual_function_entry || !virtual_function_entry->target()->rva() ||
			!pe.is_in_code_section(*virtual_function_entry->target()->rva()))
		{
			return false;
		}

		constexpr std::string_view target_name = ".";//".?A";
		constexpr auto target_name_length = static_cast<binwrite::rva_t::size_type>(target_name.size());

		if (!pe.is_rva_valid(this_rva.value() + target_name_length))
		{
			return false;
		}

		return target_name == to_string(target_name_length);
	}

	[[nodiscard]] std::string_view to_string(const std::size_t count) const
	{
		return std::string_view{ reinterpret_cast<const char*>(name), count };
	}

	[[nodiscard]] std::string_view to_string() const
	{
		return std::string_view{ reinterpret_cast<const char*>(name) };
	}

	std::uint64_t vftable_address;
	std::uint64_t unk;
	char name[1];
};

struct base_class_array_t
{
	std::uint32_t class_rvas[1];
};

struct base_class_descriptor_t
{
	std::uint32_t type_rva;
	std::uint32_t element_count;
	std::uint32_t member_displacement;
	std::uint32_t unk;
	std::uint32_t unk1;
	std::uint32_t attributes;
	std::uint32_t hierarchy_rva;
};

struct hierarchy_descriptor_t
{
	[[nodiscard]] bool is_signature_valid() const
	{
		return signature == 0 || signature == 1;
	}

	[[nodiscard]] bool is_valid(const binwrite::portable_executable_t& pe) const
	{
		return is_signature_valid() && base_class_count < 0x1000 && pe.is_in_data_section(binwrite::rva_t{ base_class_list_rva });
	}

	std::uint32_t signature;
	std::uint32_t attributes;
	std::uint32_t base_class_count;
	std::uint32_t base_class_list_rva;
};

static bool parse_type_descriptor(const binwrite::portable_executable_t& pe, const binwrite::rva_t descriptor_rva)
{
	if (!descriptor_rva.value() || !pe.is_in_data_section(descriptor_rva))
	{
		return false;
	}

	const auto type_descriptor = reinterpret_cast<const type_descriptor_t*>(pe.data() + descriptor_rva.value());

	return type_descriptor->is_valid(pe, descriptor_rva);
}

static bool parse_hierarchy_descriptor(binwrite::portable_executable_t& pe, const binwrite::rva_t descriptor_rva)
{
	if (!descriptor_rva.value() || !pe.is_in_data_section(descriptor_rva))
	{
		return false;
	}

	const auto hierarchy_descriptor = reinterpret_cast<const hierarchy_descriptor_t*>(pe.data() + descriptor_rva.value());

	if (!hierarchy_descriptor->is_valid(pe))
	{
		return false;
	}

	const auto base_class_list = reinterpret_cast<const base_class_array_t*>(pe.data() + hierarchy_descriptor->
		base_class_list_rva);

	std::vector<const std::uint32_t*> pending_refs = { };

	for (std::uint32_t i = 0; i < hierarchy_descriptor->base_class_count; i++)
	{
		const std::uint32_t* const class_rva = &base_class_list->class_rvas[i];

		if (!pe.is_rva_valid(*class_rva))
		{
			return false;
		}

		const auto base_class = reinterpret_cast<const base_class_descriptor_t*>(pe.data() + *class_rva);

		if (!pe.is_rva_valid(base_class->hierarchy_rva))
		{
			return false;
		}

		pending_refs.push_back(&base_class->hierarchy_rva);
		pending_refs.push_back(&base_class->type_rva);
		pending_refs.push_back(class_rva);
	}

	for (const auto ref : pending_refs)
	{
		pe.add_data_symbol_ref(ref);
	}

	pe.add_data_symbol_ref(&hierarchy_descriptor->base_class_list_rva);

	return true;
}

static bool parse_complete_object_locator(binwrite::portable_executable_t& pe, const binwrite::rva_t rva,
                                          std::unordered_set<binwrite::rva_t::value_type>& type_descriptor_rvas)
{
	const auto object_locator = reinterpret_cast<const complete_object_locator_t*>(pe.data() + rva.value());

	if (!pe.is_in_data_section(rva) || !object_locator->is_valid(rva))
	{
		return false;
	}

	if (!parse_type_descriptor(pe, binwrite::rva_t{ object_locator->type_rva }))
	{
		return false;
	}

	if (!parse_hierarchy_descriptor(pe, binwrite::rva_t{ object_locator->hierarchy_rva }))
	{
		return false;
	}

	pe.add_data_symbol_ref(&object_locator->type_rva);
	pe.add_data_symbol_ref(&object_locator->hierarchy_rva);
	pe.add_data_symbol_ref(&object_locator->self_rva);

	type_descriptor_rvas.insert(object_locator->type_rva);

	return true;
}

binwrite::rtti_info_t binwrite::parse_rtti(portable_executable_t& pe)
{
	std::unordered_set<rva_t::value_type> type_descriptor_rvas;

	for (const auto& section : std::views::values(pe.sections()))
	{
		if (!section->data())
		{
			continue;
		}

		constexpr std::uint16_t step = sizeof(std::uint64_t);

		const rva_t end_rva{ section->end_rva().value() - step };

		for (rva_t rva = section->rva(); rva < end_rva; rva.set_value(rva.value() + step))
		{
			if (const auto dir64_reloc = dir64_reloc_ref_at(pe, rva))
			{
				const auto self_rva = dir64_reloc->self()->rva();
				const auto target_rva = dir64_reloc->target()->rva();

				if (!self_rva || !target_rva)
				{
					continue;
				}

				if (type_descriptor_rvas.contains(self_rva->value()))
				{
					continue;
				}

				if (!parse_complete_object_locator(pe, *target_rva, type_descriptor_rvas))
				{
					if (parse_type_descriptor(pe, *self_rva))
					{
						type_descriptor_rvas.insert(self_rva->value());
					}
				}
			}
		}
	}

	return { type_descriptor_rvas };
}
