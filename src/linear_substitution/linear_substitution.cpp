#if 0
#include "linear_substitution.hpp"
#include "../assembler/assembler.hpp"

#include <binwrite/util/random.hpp>
#include <spdlog/spdlog.h>

static std::int64_t generate_random_signed_constant(const std::uint32_t bit_count)
{
	switch (bit_count)
	{
	case 8:
		return binwrite::util::random_integral<std::int64_t>(std::numeric_limits<std::int8_t>::min(), std::numeric_limits<std::int8_t>::max());
	case 16:
		return binwrite::util::random_integral<std::int16_t>();
	case 32:
	case 64:
		return binwrite::util::random_integral<std::int32_t>();
	default: ;
	}

	return 0;
}

static std::int64_t overflow_signed_constant(const std::int64_t value, const std::uint32_t bit_count)
{
	switch (bit_count)
	{
	case 8:
		return static_cast<std::int8_t>(value);
	case 16:
		return static_cast<std::int16_t>(value);
	case 32:
		return static_cast<std::int32_t>(value);
	default: ;
	}

	return value;
}

static std::uint64_t generate_random_unsigned_constant(const std::uint32_t bit_count)
{
	switch (bit_count)
	{
	case 8:
		return binwrite::util::random_integral<std::uint64_t>(std::numeric_limits<std::uint8_t>::min(), std::numeric_limits<std::uint8_t>::max());
	case 16:
		return binwrite::util::random_integral<std::uint16_t>();
	case 32:
	case 64:
		return binwrite::util::random_integral<std::uint32_t>();
	default: ;
	}

	return 0;
}

static std::uint64_t overflow_unsigned_constant(const std::uint64_t value, const std::uint32_t bit_count)
{
	switch (bit_count)
	{
	case 8:
		return static_cast<std::uint8_t>(value);
	case 16:
		return static_cast<std::uint16_t>(value);
	case 32:
		return static_cast<std::uint32_t>(value);
	default: ;
	}

	return value;
}

static std::array<binwrite::encoder_operand_t, 2> generate_obfuscated_imm_operands(const binwrite::decoded_operand_t::imm_t imm, const binwrite::decoded_operand_t::size_type destination_operand_size)
{
	binwrite::encoder_operand_t first;
	binwrite::encoder_operand_t second;

	if (imm.is_signed)
	{
		const std::int64_t value = imm.value.s;

		const std::int64_t random = generate_random_signed_constant(destination_operand_size);

		first = encode_signed_imm_operand(overflow_signed_constant(value + random, destination_operand_size));
		second = encode_signed_imm_operand(random);
	}
	else
	{
		const std::uint64_t value = imm.value.u;

		const std::uint64_t random = generate_random_unsigned_constant(destination_operand_size);

		first = encode_unsigned_imm_operand(value + random);
		second = encode_unsigned_imm_operand(random);
	}

	return { first, second };
}

static void substitute_imm_operand(std::vector<binwrite::instruction_t>& instructions,
								   const binwrite::disassembled_instruction_t& instruction_disassembly,
                                   binwrite::decoded_operand_t& operand,
                                   const binwrite::decoded_operand_t::size_type destination_operand_size,
                                   const binwrite::register_family_t& unused_register_family,
                                   const binwrite::register_t unused_register)
{
	const auto imm = operand.imm();

	const auto operands = generate_obfuscated_imm_operands(imm, destination_operand_size);

	// instruction will be reassembled with this operand as a register instead
	operand.set_reg({ .value = unused_register });

	instructions.push_back(push_instruction(unused_register_family.qword).value());
	instructions.push_back(pushfq_instruction().value());

	instructions.push_back(mov_instruction(operands[0], unused_register).value());
	instructions.push_back(sub_instruction(operands[1], unused_register).value());

	instructions.push_back(popfq_instruction().value());
	instructions.push_back(push_instruction(unused_register_family.qword).value()); // alignment of stack

	const auto reassembled_instruction = binwrite::make_assembler_instruction(instruction_disassembly);

	instructions.push_back(reassembled_instruction->compile().value());
	instructions.push_back(pop_instruction(unused_register_family.qword).value()); // restore that alignment
	instructions.push_back(pop_instruction(unused_register_family.qword).value());
}

static void substitute_mem_operand(std::vector<binwrite::instruction_t>& instructions,
                                   const binwrite::disassembled_instruction_t& instruction_disassembly,
                                   binwrite::decoded_operand_t& operand,
                                   const binwrite::register_family_t& unused_register_family)
{
	auto mem = operand.mem();

	std::int64_t value = mem.has_displacement ? mem.displacement : 0;

	constexpr std::uint32_t displacement_bit_count = 32;

	const std::int64_t random = generate_random_signed_constant(displacement_bit_count);

	if (mem.base == binwrite::register_t::rsp)
	{
		value += 16;
	}

	const auto first = encode_signed_imm_operand(overflow_signed_constant(value + random, displacement_bit_count));
	const auto second = encode_signed_imm_operand(random);

	instructions.push_back(push_instruction(unused_register_family.qword).value());
	instructions.push_back(pushfq_instruction().value());

	const binwrite::register_t base = mem.base;

	if (base != binwrite::register_t::none)
	{
		instructions.push_back(mov_instruction(base, unused_register_family.qword).value());
		instructions.push_back(add_instruction(first, unused_register_family.qword).value());
	}
	else
	{
		instructions.push_back(mov_instruction(first, unused_register_family.qword).value());
	}

	instructions.push_back(sub_instruction(second, unused_register_family.qword).value());

	mem.base = unused_register_family.qword;
	mem.has_displacement = false;
	operand.set_mem(mem);

	instructions.push_back(popfq_instruction().value());
	instructions.push_back(push_instruction(unused_register_family.qword).value()); // alignment of stack

	const auto reassembled_instruction = binwrite::make_assembler_instruction(instruction_disassembly);

	instructions.push_back(reassembled_instruction->compile().value());
	instructions.push_back(pop_instruction(unused_register_family.qword).value()); // restore that alignment
	instructions.push_back(pop_instruction(unused_register_family.qword).value());
}

static std::vector<binwrite::instruction_t> substitute_single_instruction(
	binwrite::disassembled_instruction_t& instruction_disassembly)
{
	const auto operands = instruction_disassembly.visible_operands();

	if (operands.empty())
	{
		return { };
	}

	const auto& destination_operand = operands[0];

	const binwrite::decoded_operand_t::size_type operand_size = destination_operand.size();

	const binwrite::register_family_t unused_register_family = instruction_disassembly.find_unused_register();
	const binwrite::register_t unused_register = unused_register_family.of_size(operand_size);

	std::vector<binwrite::instruction_t> instructions = { };

	bool substituted = false;

	for (auto& operand : operands)
	{
		if (operand.is_reg())
		{
			const auto reg = operand.reg().value;
			const auto family = reg.family();

			if (family == binwrite::register_family_t::sp)
			{
				return { };
			}
		} 
		else if (!substituted && operand.is_imm())
		{
			substitute_imm_operand(instructions, instruction_disassembly, operand, operand_size, unused_register_family, unused_register);

			substituted = true;
		}
		else if (operand.is_mem())
		{
			if (!substituted)
			{
				substitute_mem_operand(instructions, instruction_disassembly, operand, unused_register_family);

				substituted = true;
			}
			else
			{
				auto mem = operand.mem();

				if (mem.base == binwrite::register_t::rsp)
				{
					const std::int64_t value = mem.has_displacement ? mem.displacement : 0;

					mem.displacement = value + 16;
					mem.has_displacement = true;

					operand.set_mem(mem);
				}
			}
		}
	}

	return instructions;
}

void binprotect::linear_substitution::do_pass(binwrite::binary_t& binary, binwrite::basic_block_t& basic_block,
                                              const should_skip_memory_operands_fn& should_skip_memory_operands)
{
	const std::span<const binwrite::instruction_t> original_instructions = basic_block.instructions();
	const std::vector instructions(original_instructions.begin(), original_instructions.end());

	std::uint32_t added = 0;

	for (std::uint32_t i = 1; i < instructions.size(); i++)
	{
		const auto& instruction = instructions[i];
		auto disassembled_instruction = instruction.disassemble();

		const std::uint32_t basic_block_index = i + added;
		const binwrite::rva_t instruction_rva = basic_block.instruction_rva(basic_block_index);

		if (disassembled_instruction.rip_relative() || disassembled_instruction.writes_stack_pointer() ||
			disassembled_instruction.has_lock() || binary.find_rva_ref(instruction_rva))
		{
			continue;
		}

		if (should_skip_memory_operands && should_skip_memory_operands(disassembled_instruction, instruction_rva) &&
			disassembled_instruction.has_visible_mem_operand())
		{
			continue;
		}

		std::vector<binwrite::instruction_t> obfuscated_instructions;

		try
		{
			obfuscated_instructions = substitute_single_instruction(disassembled_instruction);
		}
		catch (const std::exception&)
		{
			const auto& original_disassembly = instruction.disassemble();

			spdlog::error("unable to linearly substitute '{}'", original_disassembly.to_string());

			continue;
		}

		if (obfuscated_instructions.empty())
		{
			continue;
		}

		basic_block.insert(binary, obfuscated_instructions, basic_block_index);
		basic_block.erase(binary, basic_block_index + static_cast<std::uint32_t>(obfuscated_instructions.size()));

		added += static_cast<std::uint32_t>(obfuscated_instructions.size()) - 1;
	}
}
#endif
