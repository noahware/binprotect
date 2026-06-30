#include "pe_exceptions.hpp"
#include <ranges>

struct throw_info_t
{
	std::uint32_t attributes;
	std::uint32_t pmfn_unwind;
	std::uint32_t forward_compat;
	std::uint32_t catchable_type_array;
};

struct catchable_type_array_t
{
	std::uint32_t count;
	std::uint32_t type_rvas[1];
};

struct catchable_type_t
{
	std::uint32_t attributes;
	std::uint32_t rva_type;
	std::uint32_t mdisp;
	std::uint32_t pdisp;
	std::uint32_t vdisp;
	std::uint32_t size_of_thrown_object;
	std::uint32_t optional_copy_constructor_rva;
};

template <class Fn>
static void for_each_throw_info(binwrite::portable_executable_t& pe, Fn&& callback)
{
	for (const auto& section : std::views::values(pe.sections()))
	{
		if (!section->data())
		{
			continue;
		}

		constexpr std::uint16_t step = sizeof(std::uint32_t);
		constexpr std::uint16_t throw_info_size = sizeof(throw_info_t);

		const binwrite::rva_t end_rva{ section->end_rva().value() - throw_info_size };

		for (binwrite::rva_t rva = section->rva(); rva < end_rva; rva.set_value(rva.value() + step))
		{
			const auto throw_info = reinterpret_cast<const throw_info_t*>(pe.data() + rva.value());

			const binwrite::rva_t catchable_types_rva{ throw_info->catchable_type_array };

			if (!throw_info->catchable_type_array || !pe.is_in_data_section(catchable_types_rva))
			{
				continue;
			}

			const auto catchable_types = reinterpret_cast<const catchable_type_array_t*>(pe.data() + catchable_types_rva.value());

			if (!catchable_types->count || 0x1000 < catchable_types->count)
			{
				continue;
			}

			const std::uint32_t table_size = sizeof(catchable_type_array_t) + sizeof(std::uint32_t) * (catchable_types->count - 1);

			if (!pe.is_rva_valid(catchable_types_rva.value() + table_size))
			{
				continue;
			}

			callback(throw_info, catchable_types);
		}
	}
}

void binwrite::queue_throw_info_code_targets(portable_executable_t& pe)
{
	for_each_throw_info(pe, [&](const throw_info_t* throw_info, const catchable_type_array_t* catchable_types)
	{
		for (std::uint32_t i = 0; i < catchable_types->count; i++)
		{
			if (!pe.is_rva_valid(catchable_types->type_rvas[i]))
			{
				return;
			}

			const auto type = reinterpret_cast<const catchable_type_t*>(pe.data() + catchable_types->type_rvas[i]);

			if (type->optional_copy_constructor_rva && pe.is_in_code_section(rva_t{ type->optional_copy_constructor_rva }))
			{
				pe.add_to_disassembly_queue(pe.add_rva(type->optional_copy_constructor_rva));
			}
		}

		const rva_t pmfn_unwind_rva{ throw_info->pmfn_unwind };

		if (throw_info->pmfn_unwind && pe.is_rva_valid(pmfn_unwind_rva) && pe.is_in_code_section(pmfn_unwind_rva))
		{
			pe.add_to_disassembly_queue(pe.add_rva(pmfn_unwind_rva));
		}
	});
}

void binwrite::parse_throw_info(portable_executable_t& pe, const rtti_info_t& rtti_result)
{
	for_each_throw_info(pe, [&](const throw_info_t* throw_info, const catchable_type_array_t* catchable_types)
	{
		std::vector<const std::uint32_t*> pending_refs;

		for (std::uint32_t i = 0; i < catchable_types->count; i++)
		{
			const std::uint32_t* const type_rva = &catchable_types->type_rvas[i];
			const auto type = reinterpret_cast<const catchable_type_t*>(pe.data() + *type_rva);

			if (!pe.is_rva_valid(*type_rva) || !rtti_result.type_descriptor_rvas.contains(type->rva_type))
			{
				return;
			}

			if (type->optional_copy_constructor_rva)
			{
				pending_refs.push_back(&type->optional_copy_constructor_rva);
			}

			pending_refs.push_back(&type->rva_type);
			pending_refs.push_back(type_rva);
		}

		for (const auto ref : pending_refs)
		{
			pe.add_data_symbol_ref(ref);
		}

		pe.add_data_symbol_ref(&throw_info->catchable_type_array);

		const rva_t pmfn_unwind_rva{ throw_info->pmfn_unwind };

		if (throw_info->pmfn_unwind && pe.is_rva_valid(pmfn_unwind_rva))
		{
			pe.add_data_symbol_ref(&throw_info->pmfn_unwind);
		}

		const rva_t forward_compat_rva{ throw_info->forward_compat };

		if (throw_info->forward_compat && pe.is_rva_valid(forward_compat_rva))
		{
			pe.add_data_symbol_ref(&throw_info->forward_compat);
		}
	});
}
