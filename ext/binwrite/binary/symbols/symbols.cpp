#include "../binary.hpp"
#include "../../block/basic_block.hpp"

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

	const rva_t instruction_rva = *self_rva;

	auto* const buffer = binary.data() + instruction_rva.value();

	auto assembler_instruction = make_assembler_instruction(buffer);

	if (!assembler_instruction)
	{
		return false;
	}

	if (!update_displacement(*assembler_instruction, instruction_rva))
	{
		return false;
	}

	const auto compilation = assembler_instruction->compile_bytes();

	if (!compilation)
	{
		return false;
	}

	const auto& [full_bytes, compiled_size] = *compilation;

	if (compiled_size != encoding_size_)
	{
		return false;
	}

	std::memcpy(binary.data() + instruction_rva.value(), full_bytes.data(), compiled_size);

	return true;
}

bool binwrite::code_symbol_ref_t::update_displacement(assembler_instruction_t& instruction, const rva_t instruction_rva) const
{
	const auto target_rva = target_->rva();

	if (!target_rva)
	{
		return false;
	}

	const rva_t::value_type rip = instruction_rva.value() + encoding_size_;
	const auto difference = static_cast<std::int64_t>(target_rva->value()) - static_cast<std::int64_t>(rip);

	bool updated = false;

	for (auto& operand : instruction.operands())
	{
		if (operand.is_imm() && (instruction.is_call() || instruction.is_jump()))
		{
			const encoder_operand_t::imm_t imm = { .s = difference };

			operand.set_imm(imm);

			updated = true;
		}
		else if (operand.is_mem())
		{
			if (encoder_operand_t::mem_t mem = operand.mem(); mem.base == register_t::rip)
			{
				mem.displacement = difference;

				operand.set_mem(mem);

				updated = true;
			}
		}
	}

	return updated;
}

bool binwrite::msvc_jmp_table_symbol_ref_t::update_displacement(assembler_instruction_t& instruction, const rva_t) const
{
	const auto target_rva = target_->rva();

	if (!target_rva)
	{
		return false;
	}

	for (auto& operand : instruction.operands())
	{
		if (operand.is_mem())
		{
			encoder_operand_t::mem_t mem = operand.mem();

			mem.displacement = target_rva->value();

			operand.set_mem(mem);
		}
	}

	return true;
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
