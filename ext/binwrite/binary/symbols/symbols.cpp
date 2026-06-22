#include "../binary.hpp"
#include "../../block/basic_block.hpp"
#include "../../block/data_block.hpp"
#include "../../disassembler/disassembler.hpp"

#include <cstring>

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

bool binwrite::fh4_encoded_symbol_ref_t::widen_encoding()
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
