#include "flag_behaviour.hpp"
#include "../assembler/assembler.hpp"

static void update_flag_from_stack(std::vector<binwrite::instruction_t>& instructions, const std::uint8_t bit, const binwrite::register_family_t& unused_register_family)
{
	instructions.push_back(and_instruction(encode_unsigned_imm_operand(1), unused_register_family.qword).value()); // clear all other bits in unused register

	if (bit != 0)
	{
		instructions.push_back(shl_instruction(unused_register_family.qword, bit).value()); // clear all other bits in unused register
	}

	const binwrite::encoder_operand_t stack_rflags = encode_mem_operand(binwrite::register_t::rsp, 0, 8);

	instructions.push_back(and_instruction(encode_unsigned_imm_operand(~(1ull << bit)), stack_rflags).value()); // clear flag
	instructions.push_back(or_instruction(unused_register_family.qword, stack_rflags).value()); // set flag IF unused register was set to 1 before
}

static void emulate_add_auxiliary_flag(std::vector<binwrite::instruction_t>& instructions, const binwrite::encoder_operand_t& result, const binwrite::register_family_t& x_copy_register_family, const binwrite::encoder_operand_t& x_copy_register, const binwrite::encoder_operand_t& y, const binwrite::register_family_t& unused_register_family, const binwrite::encoder_operand_t& unused_register)
{
	instructions.push_back(push_instruction(x_copy_register_family.qword).value());

	instructions.push_back(mov_instruction(y, unused_register).value());

	const binwrite::encoder_operand_t mask_immediate = encode_unsigned_imm_operand(0xF);

	instructions.push_back(and_instruction(mask_immediate, x_copy_register).value());
	instructions.push_back(and_instruction(mask_immediate, unused_register).value());

	instructions.push_back(add_instruction(x_copy_register, unused_register).value());

	instructions.push_back(pop_instruction(x_copy_register_family.qword).value());

	instructions.push_back(cmp_instruction(mask_immediate, unused_register).value());

	instructions.push_back(setnbe_instruction(unused_register_family.byte).value()); // byte = 1 if there was an auxiliary carry

	update_flag_from_stack(instructions, 4, unused_register_family);
}

static void emulate_add_carry_flag(std::vector<binwrite::instruction_t>& instructions, const binwrite::encoder_operand_t& result, const binwrite::encoder_operand_t& x_copy, const binwrite::register_family_t& unused_register_family, const binwrite::encoder_operand_t& unused_register)
{
	instructions.push_back(cmp_instruction(x_copy, result).value());
	instructions.push_back(setb_instruction(unused_register_family.byte).value()); // byte = 1 if result < x

	update_flag_from_stack(instructions, 0, unused_register_family);
}

static void emulate_add_overflow_flag(std::vector<binwrite::instruction_t>& instructions, const binwrite::encoder_operand_t& result, const binwrite::register_family_t& x_copy_register_family, const binwrite::encoder_operand_t& x_copy_register, const binwrite::encoder_operand_t& y, const binwrite::register_family_t& unused_register_family, const binwrite::encoder_operand_t& unused_register)
{
	instructions.push_back(push_instruction(x_copy_register_family.qword).value());

	instructions.push_back(mov_instruction(y, unused_register).value());

	instructions.push_back(xor_instruction(result, x_copy_register).value());
	instructions.push_back(xor_instruction(result, unused_register).value());

	instructions.push_back(and_instruction(x_copy_register, unused_register).value());

	instructions.push_back(pop_instruction(x_copy_register_family.qword).value());

	instructions.push_back(sets_instruction(unused_register_family.byte).value()); // byte = 1 if the both signedness of the operands don't match with the result

	update_flag_from_stack(instructions, 11, unused_register_family);
}

// only auxiliary flag, carry flag, overflow flag needed
static void emulate_add_flag_behaviour(std::vector<binwrite::instruction_t>& instructions, const binwrite::encoder_operand_t& result, const binwrite::register_family_t& x_copy_register_family, const binwrite::encoder_operand_t& x_copy_register, const binwrite::encoder_operand_t& y, const binwrite::register_family_t& unused_register_family, const binwrite::encoder_operand_t& unused_register)
{
	instructions.push_back(pushfq_instruction().value());

	emulate_add_auxiliary_flag(instructions, result, x_copy_register_family, x_copy_register, y, unused_register_family, unused_register);
	emulate_add_carry_flag(instructions, result, x_copy_register, unused_register_family, unused_register);
	emulate_add_overflow_flag(instructions, result, x_copy_register_family, x_copy_register, y, unused_register_family, unused_register);

	instructions.push_back(popfq_instruction().value());
}

std::vector<binwrite::instruction_t> binprotect::mba::emulate_flag_behaviour(
	const binwrite::disassembled_instruction_t& instruction, const binwrite::encoder_operand_t& result,
	const binwrite::register_family_t& x_copy_register_family, const binwrite::encoder_operand_t& x_copy_register,
	const binwrite::encoder_operand_t& y, const binwrite::register_family_t& unused_register_family,
	const binwrite::encoder_operand_t& unused_register)
{
	std::vector<binwrite::instruction_t> instructions = { };

	if (instruction.is_sub())
	{
		// calculates all flags as if sub had taken place
		instructions.push_back(cmp_instruction(y, x_copy_register).value());
	}
	else
	{
		// calculates sign flag, zero flag, parity flag for us. sets overflow flag and carry flag to 0
		// this will correctly emulate the flag behaviour for 'and', 'or', 'xor'
		instructions.push_back(test_instruction(result, result).value());

		// 'add' still needs auxiliary carry flag, carry flag, and overflow flag to be calculated
		if (instruction.is_add())
		{
			emulate_add_flag_behaviour(instructions, result, x_copy_register_family, x_copy_register, y, unused_register_family, unused_register);
		}
	}

	return instructions;
}

std::deque<binprotect::mba::flag_dependant_t> binprotect::mba::find_flag_dependent_instructions(const std::span<const binwrite::instruction_t> instructions)
{
	std::deque<flag_dependant_t> flag_dependants = { };

	std::int64_t closest_writer_index = -1;

	for (std::uint32_t i = 0; i < instructions.size(); i++)
	{
		const auto& instruction = instructions[i];
		const auto& disassembled_instruction = instruction.disassemble();

		if (disassembled_instruction.writes_flags())
		{
			closest_writer_index = i;
		}

		const bool is_last_instruction = i == instructions.size() - 1;

		if ((is_last_instruction || disassembled_instruction.reads_flags()) && closest_writer_index != -1)
		{
			flag_dependants.emplace_front(i, static_cast<std::uint32_t>(closest_writer_index));

			closest_writer_index = -1;
		}
	}

	return flag_dependants;
}

bool binprotect::mba::should_instruction_emulate_flags(std::deque<flag_dependant_t>& flag_dependants, const std::uint32_t i, std::vector<binwrite::instruction_t>& obfuscated_instructions)
{
	while (!flag_dependants.empty())
	{
		const auto closest_entry = flag_dependants.back();

		if (i <= closest_entry.dependant_index)
		{
			if (i == closest_entry.closest_writer_index)
			{
				flag_dependants.pop_back();

				return true;
			}

			break;
		}

		flag_dependants.pop_back();
	}

	return false;
}
