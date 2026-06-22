#include "../binary.hpp"
#include "../../block/basic_block.hpp"
#include "../../disassembler/disassembler.hpp"

bool binwrite::data_symbol_ref_t::patch_reference(binary_t& binary)
{
	const auto self_rva = self_->rva();
	const auto target_rva = target_->rva();

	if (!self_rva || !target_rva)
	{
		return false;
	}

	const rva_t::value_type target_value = target_rva->value();

	std::uint8_t* const destination = binary.data() + self_rva->value();
	const auto source = reinterpret_cast<const std::uint8_t*>(&target_value);

	const size_type copy_size = std::min(encoding_size_, static_cast<size_type>(sizeof(rva_t::size_type)));

	std::memset(destination, 0, encoding_size_);
	std::memcpy(destination, source, copy_size);

	return true;
}

bool binwrite::code_symbol_ref_t::patch_reference(binary_t& binary)
{
	const auto self_rva = self_->rva();
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

bool binwrite::code_symbol_ref_t::widen_encoding()
{
	const auto block = std::dynamic_pointer_cast<basic_block_t>(self_);

	if (!block)
	{
		return true;
	}

	const auto& instruction = block->at(0);

	if (instruction.size() >= 5)
	{
		encoding_size_ = instruction.size();

		return true;
	}

	const auto widened = widen_instruction(instruction);

	if (!widened)
	{
		return false;
	}

	block->replace_instruction(0, *widened);

	encoding_size_ = widened->size();

	return true;
}
