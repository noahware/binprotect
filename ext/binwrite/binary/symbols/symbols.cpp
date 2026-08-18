#include "../binary.hpp"
#include "../../block/basic_block.hpp"
#include "../../block/data_block.hpp"
#include "../../disassembler/disassembler.hpp"
#include "../pe/cxx_frame_handler4.hpp"

#include <cstring>
#include <spdlog/spdlog.h>

static bool write_data_reference(binwrite::binary_t& binary, const std::optional<binwrite::rva_t> self_rva,
	const std::optional<binwrite::rva_t> target_rva, const binwrite::symbol_ref_t::size_type encoding_size)
{
	if (!self_rva || !target_rva)
	{
		return false;
	}

	const binwrite::rva_t::value_type target_value = target_rva->value();

	std::uint8_t* const destination = binary.data() + self_rva->value();

	const auto source = reinterpret_cast<const std::uint8_t*>(&target_value);

	const auto copy_size = std::min(encoding_size,
		static_cast<binwrite::symbol_ref_t::size_type>(sizeof(binwrite::rva_t::size_type)));

	std::memset(destination, 0, encoding_size);
	std::memcpy(destination, source, copy_size);

	return true;
}

bool binwrite::data_symbol_ref_t::patch_reference(binary_t& binary)
{
	const auto target_rva = anchor_ == anchor_t::at_end ? target_->end_rva() : target_->rva();

	return write_data_reference(binary, self_->rva(), target_rva, encoding_size_);
}

static std::optional<binwrite::rva_t> resolve_instr_rva(const std::shared_ptr<binwrite::symbol_t>& symbol,
	const binwrite::instruction_t::id_type instr_id)
{
	const auto base = symbol->rva();

	if (!base || instr_id == 0)
	{
		return base;
	}

	const auto block = std::dynamic_pointer_cast<binwrite::basic_block_t>(symbol);

	if (!block)
	{
		return base;
	}

	const auto offset = block->byte_offset_of_instruction_id(instr_id);

	if (offset == binwrite::basic_block_t::invalid_index)
	{
		return base;
	}

	return binwrite::rva_t{ base->value() + offset };
}

std::optional<binwrite::rva_t> binwrite::code_symbol_ref_t::effective_self_rva() const
{
	return resolve_instr_rva(self_, self_instr_id_);
}

bool binwrite::code_symbol_ref_t::patch_reference(binary_t& binary)
{
	const auto self_rva = effective_self_rva();
	const auto target_rva = target_->rva();

	if (!self_rva || !target_rva)
	{
		return false;
	}

	auto* const instruction_bytes = binary.data() + self_rva->value();

	const auto offset = find_displacement_offset(instruction_bytes, encoding_size_);

	if (!offset)
	{
		return false;
	}

	const auto displacement = compute_displacement(*self_rva, *target_rva);

	std::memcpy(instruction_bytes + *offset, &displacement, sizeof(std::int32_t));

	return true;
}

std::int32_t binwrite::code_symbol_ref_t::compute_displacement(const rva_t self_rva, const rva_t target_rva) const
{
	const auto rip = static_cast<std::int64_t>(self_rva.value() + encoding_size_);

	return static_cast<std::int32_t>(static_cast<std::int64_t>(target_rva.value()) - rip);
}

std::int32_t binwrite::msvc_jmp_table_symbol_ref_t::compute_displacement(const rva_t, const rva_t target_rva) const
{
	return static_cast<std::int32_t>(target_rva.value());
}

bool binwrite::code_symbol_ref_t::widen_encoding(binary_t&)
{
	const auto block = std::dynamic_pointer_cast<basic_block_t>(self_);

	if (!block)
	{
		return true;
	}

	const auto index = self_instr_id_
		? block->instruction_index_by_id(self_instr_id_)
		: 0;

	if (index == basic_block_t::invalid_index)
	{
		return true;
	}

	const auto& instruction = block->at(index);

	if (instruction.size() >= 5)
	{
		encoding_size_ = instruction.size();

		return true;
	}

	const auto widened = widen_instruction(instruction);

	if (!widened)
	{
		const auto rva = block->original_rva();

		spdlog::error("failed to widen instruction at rva 0x{:X} size={}",
			rva ? rva->value() : 0, instruction.size());

		return false;
	}

	block->replace_instruction(index, *widened);

	encoding_size_ = widened->size();

	return true;
}

bool binwrite::dir64_reloc_symbol_ref_t::patch_reference(binary_t& binary)
{
	const auto self_rva = self_->rva();
	const auto target_rva = target_->rva();

	if (!self_rva || !target_rva)
	{
		return false;
	}

	const std::uint64_t va = binary.image_base() + target_rva->value();
	auto* const destination = reinterpret_cast<std::uint64_t*>(binary.data() + self_rva->value());
	*destination = va;

	return true;
}

bool binwrite::llvm_jmp_table_symbol_ref_t::patch_reference(binary_t& binary)
{
	const auto self_rva = self_->rva();
	const auto target_rva = target_->rva();
	const auto base_rva = table_base_->rva();

	if (!self_rva || !target_rva || !base_rva)
	{
		return false;
	}

	const auto offset = static_cast<std::int32_t>(target_rva->value() - base_rva->value());
	std::memcpy(binary.data() + self_rva->value(), &offset, sizeof(std::int32_t));

	return true;
}

bool binwrite::fh4_encoded_symbol_ref_t::patch_reference(binary_t& binary)
{
	const auto self_rva = self_->rva();
	const auto target_rva = target_->rva();
	const auto prev_rva = previous_target_->rva();

	if (!self_rva || !target_rva || !prev_rva)
	{
		return false;
	}

	const auto delta = static_cast<std::uint32_t>(
		static_cast<std::int32_t>(target_rva->value() - prev_rva->value()));

	std::uint8_t encoded[5];
	encoded[0] = 0x0F;
	std::memcpy(encoded + 1, &delta, sizeof(std::uint32_t));

	std::memcpy(binary.data() + self_rva->value(), encoded, 5);

	return true;
}

bool binwrite::fh4_encoded_symbol_ref_t::widen_encoding(binary_t& binary)
{
	if (self_->size() >= 5)
	{
		encoding_size_ = 5;
		return true;
	}

	auto block = std::dynamic_pointer_cast<data_block_t>(self_);

	if (!block)
	{
		return false;
	}

	block->resize(5);
	encoding_size_ = 5;

	return true;
}
