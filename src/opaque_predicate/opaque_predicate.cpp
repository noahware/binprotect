#if 0
#include "opaque_predicate.hpp"

#include <spdlog/spdlog.h>

#include <binwrite/util/random.hpp>
#include "../assembler/assembler.hpp"
#include "../mba/flag_behaviour.hpp"

static void insert_jz_to_block(binwrite::binary_t& binary,
	binwrite::basic_block_t& source_block,
	const binwrite::basic_block_t::size_type index,
	const binwrite::basic_block_t& target_block)
{
	const auto destination_placeholder = encode_unsigned_imm_operand(1);
	const auto instruction = jz_instruction(destination_placeholder).value();

	source_block.insert(binary, instruction, index);

	const binwrite::rva_t instruction_rva = source_block.instruction_rva(index);

	binary.add_rva_ref(std::make_shared<binwrite::code_rva_ref_t>(target_block.rva(), instruction_rva, instruction.size()));
}

static void insert_jnz_to_block(binwrite::binary_t& binary,
	binwrite::basic_block_t& source_block,
	const binwrite::basic_block_t::size_type index,
	const binwrite::basic_block_t& target_block)
{
	const auto destination_placeholder = encode_unsigned_imm_operand(1);
	const auto instruction = jnz_instruction(destination_placeholder).value();

	source_block.insert(binary, instruction, index);

	const binwrite::rva_t instruction_rva = source_block.instruction_rva(index);

	binary.add_rva_ref(std::make_shared<binwrite::code_rva_ref_t>(target_block.rva(), instruction_rva, instruction.size()));
}

static void push_jump_to_block(binwrite::binary_t& binary,
	const std::shared_ptr<binwrite::basic_block_t>& source_block,
	const std::shared_ptr<binwrite::basic_block_t>& target_block)
{
	const auto destination_placeholder = encode_unsigned_imm_operand(1);
	const auto jump_instruction = jmp_instruction(destination_placeholder).value();

	source_block->push(binary, jump_instruction, false, true);

	const binwrite::rva_t jump_instruction_rva = source_block->last_instruction_rva();

	binary.add_rva_ref(std::make_shared<binwrite::code_rva_ref_t>(target_block->rva(), jump_instruction_rva, jump_instruction.size()));
}

static std::shared_ptr<binwrite::basic_block_t> copy_basic_block(binwrite::binary_t& binary, binwrite::basic_block_t& basic_block, const binwrite::rva_t rva)
{
	const auto block_instructions = basic_block.instructions();

	return binary.create_basic_block(rva, block_instructions);
}

static std::vector<binwrite::decoded_operand_t> collect_block_operands(binwrite::basic_block_t& basic_block)
{
	std::vector<binwrite::decoded_operand_t> block_operands;

	for (const auto& instruction : basic_block.instructions())
	{
		const auto& instruction_disassembly = instruction.disassemble();
		const auto& visible_operands = instruction_disassembly.visible_operands();

		block_operands.insert(block_operands.end(), visible_operands.begin(), visible_operands.end());
	}

	return block_operands;
}

static void shuffle_block_copy(binwrite::binary_t& binary, binwrite::basic_block_t& basic_block)
{
	const auto block_operands = collect_block_operands(basic_block);

	std::vector<binwrite::instruction_t> shuffled_instructions;

	for (auto& instruction : basic_block.instructions())
	{
		auto& instruction_disassembly = instruction.disassemble();
		const auto& visible_operands = instruction_disassembly.visible_operands();

		for (auto& visible_operand : visible_operands)
		{
			visible_operand = binwrite::util::random_entry<binwrite::decoded_operand_t>(block_operands);
		}

		if (const auto new_instruction = make_assembler_instruction(instruction_disassembly))
		{
			if (const auto compiled_instruction = new_instruction->compile())
			{
				shuffled_instructions.push_back(*compiled_instruction);
			}
		}
	}

	const binwrite::basic_block_t::size_type count = basic_block.count();

	basic_block.push(binary, shuffled_instructions, false, true);

	basic_block.erase(binary, 0, count);
}

static void pow_register(std::vector<binwrite::instruction_t>& instructions, const binwrite::register_t reg, const binwrite::register_t holder, const std::uint32_t power)
{
	instructions.push_back(mov_instruction(reg, holder).value());

	for (std::uint32_t i = 0; i < power - 1; i++)
	{
		instructions.push_back(imul_instruction(holder, reg).value());
	}
}

static void obfuscate_zero_flag(std::vector<binwrite::instruction_t>& instructions,
	const binwrite::register_t holder_register, const bool shuffled_blocks)
{
	instructions.push_back(pushfq_instruction().value());

	instructions.push_back(mov_instruction(encode_stack_mem_operand(0, 8), holder_register).value());

	instructions.push_back(xor_instruction(encode_unsigned_imm_operand(1 << 6), holder_register).value());

	if (!shuffled_blocks)
	{
		instructions.push_back(xor_instruction(encode_unsigned_imm_operand(1 << 6), holder_register).value());
	}

	instructions.push_back(mov_instruction(holder_register, encode_stack_mem_operand(0, 8)).value());

	instructions.push_back(popfq_instruction().value());
}

static std::vector<binwrite::register_t> random_registers(const std::uint32_t count)
{
	std::vector<binwrite::register_family_t> register_families;
	std::vector<binwrite::register_t> registers;

	for (std::uint32_t i = 0; i < count; i++)
	{
		const auto family = binwrite::register_family_t::random(register_families);

		register_families.push_back(family);
		registers.push_back(family.qword);
	}

	return registers;
}

static std::vector<binwrite::instruction_t> form_fermat_opaque(const bool shuffled_blocks)
{
	std::vector<binwrite::instruction_t> instructions;

	instructions.push_back(pushfq_instruction().value());

	constexpr std::uint32_t variable_count = 3;

	const auto registers = random_registers(variable_count + 1);

	for (const auto& reg : registers)
	{
		instructions.push_back(push_instruction(reg).value());
	}

	// load variables
	instructions.push_back(lea_instruction(encode_mem_operand(binwrite::register_t::rsp, binwrite::util::random_integral<std::uint16_t>(), 8), registers[0]).value());
	instructions.push_back(lea_instruction(encode_mem_operand(binwrite::register_t::rip, binwrite::util::random_integral<std::uint16_t>(), 8), registers[1]).value());
	instructions.push_back(sub_instruction(encode_unsigned_imm_operand(binwrite::util::random_integral<std::uint16_t>()), registers[2]).value());

	const std::uint32_t power = binwrite::util::random_integral<std::uint32_t>(3, 7);

	const binwrite::register_t holder_register = registers[variable_count];

	// raise power of variables
	for (std::uint32_t i = 0; i < variable_count; i++)
	{
		const auto& variable_reg = registers[i];

		pow_register(instructions, variable_reg, holder_register, power);
	}

	// x^p + y^p == z^p
	instructions.push_back(add_instruction(registers[1], registers[0]).value());
	instructions.push_back(cmp_instruction(registers[0], registers[2]).value());

	obfuscate_zero_flag(instructions, holder_register, shuffled_blocks);

	for (const auto& reg : registers | std::views::reverse)
	{
		instructions.push_back(pop_instruction(reg).value());
	}

	return instructions;
}

void binprotect::opaque_predicate::do_pass(binwrite::binary_t& binary,
	binwrite::basic_block_t& basic_block,
	std::vector<std::shared_ptr<binwrite::basic_block_t>>& opaque_blocks)
{
	basic_block.insert(binary, popfq_instruction().value(), 0);

	const auto block_copy = copy_basic_block(binary, basic_block, basic_block.end_rva());

	shuffle_block_copy(binary, *block_copy);

	insert_jz_to_block(binary, basic_block, 0, *block_copy);

	const auto original_block = binary.split_basic_block(basic_block, 1);

	const bool shuffle_blocks = binwrite::util::random_bool();

	std::shared_ptr<binwrite::basic_block_t> start_block = original_block;
	std::shared_ptr<binwrite::basic_block_t> end_block = block_copy;

	if (shuffle_blocks)
	{
		original_block->move_entire(binary, block_copy->end_rva());

		binary.redirect_rva_ref(*basic_block.rva(), *original_block->rva());

		std::swap(start_block, end_block);
	}

	const auto& last_instruction = original_block->last_instruction();
	const auto& last_instruction_disassembly = last_instruction.disassemble();

	if (!last_instruction_disassembly.is_unconditional_jump() && !last_instruction_disassembly.is_ret())
	{
		const auto fallthrough_rva = end_block->end_rva();

		if (const auto fallthrough_block = binary.find_basic_block(fallthrough_rva))
		{
			push_jump_to_block(binary, start_block, fallthrough_block);
		}
	}

	basic_block.insert(binary, form_fermat_opaque(shuffle_blocks), 0);

	opaque_blocks.push_back(original_block);
	opaque_blocks.push_back(block_copy);
}
#endif
