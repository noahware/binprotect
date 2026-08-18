#include "opaque_predicate.hpp"
#include "../assembler/assembler.hpp"

#include <binwrite/util/random.hpp>
#include <spdlog/spdlog.h>
#include <ranges>

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

	if (block_operands.empty())
	{
		return;
	}

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

	basic_block.push(binary, shuffled_instructions);

	basic_block.erase(binary, 0, count);
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

static void pow_register(std::vector<binwrite::instruction_t>& instructions,
	const binwrite::register_t reg, const binwrite::register_t holder, const std::uint32_t power)
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

	instructions.push_back(lea_instruction(encode_mem_operand(binwrite::register_t::rsp, binwrite::util::random_integral<std::uint16_t>(), 8), registers[0]).value());
	instructions.push_back(lea_instruction(encode_mem_operand(binwrite::register_t::rip, binwrite::util::random_integral<std::uint16_t>(), 8), registers[1]).value());
	instructions.push_back(sub_instruction(encode_unsigned_imm_operand(binwrite::util::random_integral<std::uint16_t>()), registers[2]).value());

	const std::uint32_t power = binwrite::util::random_integral<std::uint32_t>(3, 7);

	const binwrite::register_t holder_register = registers[variable_count];

	for (std::uint32_t i = 0; i < variable_count; i++)
	{
		const auto& variable_reg = registers[i];

		pow_register(instructions, variable_reg, holder_register, power);
	}

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
	const std::shared_ptr<binwrite::basic_block_t>& basic_block,
	std::vector<std::shared_ptr<binwrite::basic_block_t>>& opaque_blocks)
{
	basic_block->insert(binary, popfq_instruction().value(), 0);

	const auto block_copy = binary.create_basic_block_after(basic_block, basic_block->instructions());

	shuffle_block_copy(binary, *block_copy);

	const auto jz_placeholder = encode_unsigned_imm_operand(1);
	const auto jz_instr = jz_instruction(jz_placeholder).value();

	const auto& inserted_jz = basic_block->insert(binary, jz_instr, 0);

	auto jz_ref = binary.add_code_ref(basic_block, inserted_jz, block_copy);

	const auto original_block = basic_block->split_at(binary, 1);

	if (!original_block)
	{
		spdlog::error("unable to split basic block for opaque predicate");
		return;
	}

	const auto refs_to_migrate = binary.find_all_symbol_refs_by_self(basic_block);

	for (const auto& ref : refs_to_migrate)
	{
		const auto code_ref = std::dynamic_pointer_cast<binwrite::code_symbol_ref_t>(ref);

		if (!code_ref || code_ref->self_instr_id() == 0)
		{
			continue;
		}

		if (original_block->instruction_index_by_id(code_ref->self_instr_id()) != binwrite::basic_block_t::invalid_index)
		{
			ref->set_self(original_block);
		}
	}

	const bool shuffle_blocks = binwrite::util::random_bool();

	auto start_block = original_block;
	auto end_block = block_copy;

	if (shuffle_blocks)
	{
		original_block->move_after(block_copy);

		jz_ref->set_target(original_block);

		std::swap(start_block, end_block);
	}

	const auto& last_instruction = original_block->last_instruction();
	const auto& last_instruction_disassembly = last_instruction.disassemble();

	if (!last_instruction_disassembly.is_unconditional_jump() && !last_instruction_disassembly.is_ret())
	{
		const auto section = end_block->section();

		if (section)
		{
			auto it = end_block->list_iterator();
			++it;

			if (it != section->symbols().end())
			{
				const auto fallthrough_block = std::dynamic_pointer_cast<binwrite::basic_block_t>(*it);

				if (fallthrough_block)
				{
					const auto jmp_placeholder = encode_unsigned_imm_operand(1);
					const auto jmp_instr = jmp_instruction(jmp_placeholder).value();

					const auto& pushed_jmp = start_block->push(binary, jmp_instr);

					binary.add_code_ref(start_block, pushed_jmp, fallthrough_block);
				}
			}
		}
	}

	basic_block->insert(binary, form_fermat_opaque(shuffle_blocks), 0);

	opaque_blocks.push_back(original_block);
	opaque_blocks.push_back(block_copy);
}
