#include "binary.hpp"

#include <spdlog/spdlog.h>

std::optional<binwrite::pending_ref_t> binwrite::binary_t::find_pending_ref(const rva_t self_rva) const
{
	const auto it = pending_ref_index_.find(self_rva.value());

	if (it == pending_ref_index_.end())
	{
		return std::nullopt;
	}

	return pending_refs_[it->second];
}

void binwrite::binary_t::record_pending_ref(const pending_ref_t& ref)
{
	// the index keeps the first record at a location, matching the old first-match lookup
	pending_ref_index_.emplace(ref.self, pending_refs_.size());

	pending_refs_.push_back(ref);
}

void binwrite::binary_t::record_code_ref(const rva_t self, const rva_t target, const std::uint32_t instruction_size)
{
	record_pending_ref({
		.self = self.value(),
		.target = target.value(),
		.previous_target = 0,
		.size = instruction_size,
		.target_alignment = 1,
		.kind = pending_ref_kind_t::code
	});
}

void binwrite::binary_t::record_dir64_ref(const rva_t self, const rva_t target)
{
	record_pending_ref({
		.self = self.value(),
		.target = target.value(),
		.previous_target = 0,
		.size = sizeof(std::uint64_t),
		.target_alignment = 1,
		.kind = pending_ref_kind_t::dir64_reloc
	});
}

void binwrite::binary_t::record_fh4_ref(const rva_t self, const rva_t target, const rva_t previous_target,
                                        const std::uint32_t encoded_size)
{
	record_pending_ref({
		.self = self.value(),
		.target = target.value(),
		.previous_target = previous_target.value(),
		.size = encoded_size,
		.target_alignment = 1,
		.kind = pending_ref_kind_t::fh4_encoded
	});
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
		target, self, static_cast<symbol_ref_t::size_type>(instruction.size())
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
