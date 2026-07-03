#include "binary.hpp"

#include <spdlog/spdlog.h>

void binwrite::binary_t::update_rva_references()
{
	for (const auto& rva_ref : rva_refs_)
	{
		rva_ref->update_reference(*this);
	}

	update_section_headers();

	for (std::uint64_t i = 0; i < rva_refs_.size();)
	{
		const auto& rva_ref = rva_refs_[i];

		const auto result = rva_ref->update_reference(*this);

		if (!result)
		{
			if (result.error() == rva_ref_t::error_t::instruction_length_changed)
			{
				update_section_headers();

				i = 0;

				continue;
			}

			spdlog::error("unable to update rva reference at 0x{:X} (target=0x{:X}, is_code={}, error={})",
				rva_ref->self().value(), rva_ref->target()->value(),
				rva_ref->is_code_reference(), static_cast<int>(result.error()));
		}

		i++;
	}

	update_relocations();

	update_section_headers();
}

void binwrite::binary_t::update_section_rvas(const rva_t disruption_rva, const rva_t::size_type disruption_size)
{
	for (const auto& [name, section] : sections_)
	{
		section->process_disruption(disruption_rva, disruption_size);
	}
}

void binwrite::binary_t::update_rvas(const rva_t disruption_rva, const rva_t::size_type disruption_size,
                                     const bool inclusive, const bool update_sections)
{
	if (update_sections)
	{
		update_section_rvas(disruption_rva, disruption_size);
	}

	for (const auto& rva : rvas_)
	{
		rva->process_disruption(disruption_rva, disruption_size, inclusive);
	}

	for (const auto& rva_ref : rva_refs_)
	{
		rva_ref->process_disruption(disruption_rva, disruption_size);
	}

	bb_index_dirty_ = true;
	fn_index_dirty_ = true;

	for (const auto& function : functions_)
	{
		function->set_basic_blocks_dirty(true);
	}
}

std::shared_ptr<binwrite::rva_ref_t> binwrite::binary_t::find_rva_ref(const rva_t ref_rva,
                                                                      const bool must_be_code_reference) const
{
	for (const auto& rva_ref : rva_refs_)
	{
		const auto& ref = rva_ref;

		if (must_be_code_reference && !ref->is_code_reference())
		{
			continue;
		}

		if (ref->self() == ref_rva)
		{
			return rva_ref;
		}
	}

	return { };
}

std::vector<std::shared_ptr<binwrite::rva_ref_t>> binwrite::binary_t::find_all_targetted_rva_refs(const rva_t target_rva) const
{
	std::vector<std::shared_ptr<rva_ref_t>> refs;

	for (const auto& rva_ref : rva_refs_)
	{
		if (*rva_ref->target() == target_rva)
		{
			refs.push_back(rva_ref);
		}
	}

	return refs;
}

std::shared_ptr<binwrite::rva_t> binwrite::binary_t::add_rva(const rva_t::value_type value, const bool force_inclusive)
{
	for (const auto& existing_rva : rvas_)
	{
		if (existing_rva->value() == value &&
			existing_rva->force_inclusive() == force_inclusive)
		{
			return existing_rva;
		}
	}

	const auto rva = std::make_shared<rva_t>(value, force_inclusive);
	rvas_.push_back(rva);

	return rva;
}

std::shared_ptr<binwrite::rva_t> binwrite::binary_t::add_rva(const rva_t rva, const bool force_inclusive)
{
	return add_rva(rva.value(), force_inclusive);
}

void binwrite::binary_t::add_rva_ref(std::shared_ptr<rva_ref_t> ref)
{
	rva_refs_.push_back(std::move(ref));
}

void binwrite::binary_t::add_symbol_ref(std::shared_ptr<symbol_ref_t> ref)
{
	symbol_refs_.push_back(std::move(ref));
}

std::shared_ptr<binwrite::code_symbol_ref_t> binwrite::binary_t::add_code_ref(
	const std::shared_ptr<basic_block_t>& self,
	const instruction_t& instruction,
	const std::shared_ptr<symbol_t>& target)
{
	auto ref = std::make_shared<code_symbol_ref_t>(
		target, self,
		static_cast<symbol_ref_t::size_type>(instruction.size())
	);
	ref->set_self_instr_id(instruction.id());
	symbol_refs_.push_back(ref);
	return ref;
}

bool binwrite::binary_t::is_rva_valid(const rva_t rva) const
{
	return rva.value() < size();
}

bool binwrite::binary_t::is_rva_valid(const rva_t::value_type rva) const
{
	return is_rva_valid(rva_t{ rva });
}

void binwrite::binary_t::redirect_rva_ref(const rva_t self, const rva_t new_target)
{
	const auto added_rva = add_rva(new_target);

	for (const auto& rva_ref : rva_refs_)
	{
		if (rva_ref->self() == self)
		{
			rva_ref->set_target(added_rva);
		}
	}
}

std::shared_ptr<binwrite::rva_t> binwrite::binary_t::add_relocation_rva(const rva_t::value_type target)
{
	return add_rva(target, true);
}

std::shared_ptr<binwrite::rva_t> binwrite::binary_t::add_relocation_rva(const rva_t target)
{
	return add_relocation_rva(target.value());
}
