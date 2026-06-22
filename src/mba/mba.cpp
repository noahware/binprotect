#if 0
#include "mba.hpp"
#include "flag_behaviour.hpp"

#include <binwrite/util/random.hpp>
#include "../assembler/assembler.hpp"

#include <spdlog/spdlog.h>
#include <functional>
#include <algorithm>
#include <vector>

using mba_callback_t = std::function<void(std::vector<binwrite::instruction_t>& instructions,
	const binwrite::encoder_operand_t& x,
	const binwrite::encoder_operand_t& y,
	const binwrite::encoder_operand_t& unused_register,
	const binwrite::encoder_operand_t& second_unused_register)>;

#define MBA_CALLBACK(callback) (mba_callback_t)[](std::vector<binwrite::instruction_t>& instructions,\
                                  const binwrite::encoder_operand_t& x, const binwrite::encoder_operand_t& y, const binwrite::encoder_operand_t& unused_register,\
								  const binwrite::encoder_operand_t& second_unused_register) -> void\
								  {\
									  callback\
								  }

static std::vector<binwrite::instruction_t> mba_stub(
	const binwrite::disassembled_instruction_t& disassembled_instruction, bool should_emulate_flags,
	std::span<const mba_callback_t> callbacks);

static std::vector<binwrite::instruction_t> mba_obfuscate_add(const binwrite::disassembled_instruction_t& instruction, const bool should_emulate_flags)
{
	const std::array callbacks = {
		MBA_CALLBACK(
			// (x + y) can be obfuscated to ((x & y) + (x | y))

			// unused register = (x & y)
			instructions.push_back(and_instruction(y, unused_register).value());

		// x = (x | y)
		instructions.push_back(or_instruction(y, x).value());

		// x = x + unused register
		instructions.push_back(add_instruction(unused_register, x).value());
	),
	MBA_CALLBACK(
		// (x + y) = (x ^ y) + 2(x & y)
		instructions.push_back(and_instruction(y, unused_register).value());
		instructions.push_back(xor_instruction(y, x).value());
		instructions.push_back(shl_instruction(unused_register, 1).value());

		instructions.push_back(add_instruction(unused_register, x).value());
	),
	MBA_CALLBACK(
		// (x + y) = 2(x | y) - (x ^ y)
		instructions.push_back(xor_instruction(y, unused_register).value());

		instructions.push_back(or_instruction(second_unused_register, x).value());
		instructions.push_back(shl_instruction(x, 1).value());

		instructions.push_back(sub_instruction(unused_register, x).value());
	)
	};

	return mba_stub(instruction, should_emulate_flags, callbacks);
}

static std::vector<binwrite::instruction_t> mba_obfuscate_and(const binwrite::disassembled_instruction_t& instruction, const bool should_emulate_flags)
{
	const std::array callbacks = {
		MBA_CALLBACK(
			// (x & y) = (x + y) - (x | y)

			instructions.push_back(or_instruction(y, unused_register).value());
			instructions.push_back(add_instruction(y, x).value());
			instructions.push_back(sub_instruction(unused_register, x).value());
		),
		MBA_CALLBACK(
			// (x & y) = (~x | y) - (~x)

			instructions.push_back(not_instruction(unused_register).value());
			instructions.push_back(not_instruction(x).value());

			instructions.push_back(or_instruction(second_unused_register, x).value());

			instructions.push_back(sub_instruction(unused_register, x).value());
		)
	};

	return mba_stub(instruction, should_emulate_flags, callbacks);
}

static std::vector<binwrite::instruction_t> mba_obfuscate_xor(const binwrite::disassembled_instruction_t& instruction, const bool should_emulate_flags)
{
	const std::array callbacks = {
		MBA_CALLBACK(
			// (x ^ y) = (x | y) - (x & y)

			instructions.push_back(and_instruction(y, unused_register).value());
			instructions.push_back(or_instruction(y, x).value());
			instructions.push_back(sub_instruction(unused_register, x).value());
		)
	};

	return mba_stub(instruction, should_emulate_flags, callbacks);
}

static std::vector<binwrite::instruction_t> mba_obfuscate_sub(const binwrite::disassembled_instruction_t& instruction, const bool should_emulate_flags)
{
	const std::array callbacks = {
		MBA_CALLBACK(
			// (x - y) = 2(x & ~y) - (x ^ y) 
			instructions.push_back(xor_instruction(y, unused_register).value());

			instructions.push_back(not_instruction(second_unused_register).value());
			instructions.push_back(and_instruction(second_unused_register, x).value());
			instructions.push_back(shl_instruction(x, 1).value());

			instructions.push_back(sub_instruction(unused_register, x).value());
		),
		MBA_CALLBACK(
			// (x - y) = (x & ~y) - (~x & y)
			instructions.push_back(not_instruction(unused_register).value());
			instructions.push_back(not_instruction(second_unused_register).value());

			instructions.push_back(and_instruction(y, unused_register).value());
			instructions.push_back(and_instruction(second_unused_register, x).value());

			instructions.push_back(sub_instruction(unused_register, x).value());
		),
		MBA_CALLBACK(
			// (x - y) = (x ^ y) - 2(~x & y)
			instructions.push_back(not_instruction(unused_register).value());
			instructions.push_back(and_instruction(y, unused_register).value());
			instructions.push_back(shl_instruction(unused_register, 1).value());

			instructions.push_back(xor_instruction(y, x).value());

			instructions.push_back(sub_instruction(unused_register, x).value());
		)
	};

	return mba_stub(instruction, should_emulate_flags, callbacks);
}

static std::vector<binwrite::instruction_t> mba_obfuscate_or(const binwrite::disassembled_instruction_t& instruction, const bool should_emulate_flags)
{
	const std::array callbacks = {
		MBA_CALLBACK(
			// (x | y) = (~x | ~y) + (x + y + 1)
			const binwrite::encoder_operand_t constant = encode_unsigned_imm_operand(1);

			instructions.push_back(add_instruction(y, unused_register).value());
			instructions.push_back(add_instruction(constant, unused_register).value());

			instructions.push_back(not_instruction(second_unused_register).value());
			instructions.push_back(not_instruction(x).value());

			instructions.push_back(or_instruction(second_unused_register, x).value());

			instructions.push_back(add_instruction(unused_register, x).value());
		),
		MBA_CALLBACK(
			// (x | y) = (x & ~y) + y

			instructions.push_back(not_instruction(second_unused_register).value());
			instructions.push_back(and_instruction(second_unused_register, x).value());
			instructions.push_back(not_instruction(second_unused_register).value());

			instructions.push_back(add_instruction(second_unused_register, x).value());
		)
	};

	return mba_stub(instruction, should_emulate_flags, callbacks);
}


static void emulate_flag_behaviour(std::vector<binwrite::instruction_t>& instructions,
                                   const binwrite::disassembled_instruction_t& disassembled_instruction,
                                   const binwrite::encoder_operand_t& x,
                                   const binwrite::encoder_operand_t& y,
                                   const binwrite::register_family_t unused_register_family,
                                   const binwrite::encoder_operand_t& unused_register,
                                   const binwrite::register_family_t second_unused_register_family, 
                                   const binwrite::encoder_operand_t& second_unused_register)
{
	instructions.insert(instructions.begin() + 4, push_instruction(unused_register_family.qword).value());
	instructions.insert(instructions.begin() + 4, pushfq_instruction().value());

	instructions.push_back(pop_instruction(unused_register_family.qword).value()); // restore 'x' value into unused register
	instructions.push_back(popfq_instruction().value());

	const auto flag_emulation_instructions = binprotect::mba::emulate_flag_behaviour(
		disassembled_instruction, x, unused_register_family,
		unused_register, y, second_unused_register_family,
		second_unused_register);

	instructions.insert(instructions.end(), flag_emulation_instructions.begin(), flag_emulation_instructions.end());
}

static std::vector<binwrite::instruction_t> execute_mba_callback(const mba_callback_t& callback,
                                                                 const binwrite::disassembled_instruction_t& disassembled_instruction,
                                                                 const binwrite::encoder_operand_t& x,
                                                                 const binwrite::encoder_operand_t& y,
                                                                 const binwrite::decoded_operand_t::size_type destination_size,
                                                                 const bool should_emulate_flags,
                                                                 const binwrite::register_family_t unused_register_family,
                                                                 const binwrite::register_family_t second_unused_register_family)
{
	std::vector<binwrite::instruction_t> instructions = { };

	const binwrite::encoder_operand_t unused_register(unused_register_family.of_size(destination_size));
	const binwrite::encoder_operand_t second_unused_register(second_unused_register_family.of_size(destination_size));

	instructions.push_back(push_instruction(unused_register_family.qword).value());
	instructions.push_back(push_instruction(second_unused_register_family.qword).value());

	instructions.push_back(mov_instruction(x, unused_register).value());
	instructions.push_back(mov_instruction(y, second_unused_register).value());

	callback(instructions, x, y, unused_register, second_unused_register);

	if (should_emulate_flags)
	{
		emulate_flag_behaviour(instructions, disassembled_instruction, x, y, unused_register_family, unused_register,
		                       second_unused_register_family, second_unused_register);
	}

	instructions.push_back(pop_instruction(second_unused_register_family.qword).value());
	instructions.push_back(pop_instruction(unused_register_family.qword).value());

	return instructions;
}

static std::vector<binwrite::instruction_t> mba_stub(const binwrite::disassembled_instruction_t& disassembled_instruction,
													 const bool should_emulate_flags, const std::span<const mba_callback_t> callbacks)
{
	const auto& visible_operands = disassembled_instruction.visible_operands();

	if (callbacks.empty() || visible_operands.size() < 2)
	{
		return { };
	}

	const auto& decoded_x = visible_operands[0];

	const binwrite::encoder_operand_t x(decoded_x);
	const binwrite::encoder_operand_t y(visible_operands[1]);

	const binwrite::register_family_t unused_register_family = disassembled_instruction.find_unused_register();
	const binwrite::register_family_t second_unused_register_family = disassembled_instruction.find_unused_register(unused_register_family);

	const auto& callback = binwrite::util::random_entry<mba_callback_t>(callbacks);

	return execute_mba_callback(callback, disassembled_instruction, x, y, decoded_x.size(), should_emulate_flags,
	                            unused_register_family, second_unused_register_family);
}

void binprotect::mba::do_pass(binwrite::binary_t& binary, binwrite::basic_block_t& basic_block,
                              const bool flag_dependant, const should_skip_memory_operands_fn& should_skip_memory_operands)
{
	const std::span<const binwrite::instruction_t> original_instructions = basic_block.instructions();
	const std::vector instructions(original_instructions.begin(), original_instructions.end());

	auto flag_dependants = flag_dependant ? find_flag_dependent_instructions(instructions) : std::deque<flag_dependant_t>{ };

	std::uint32_t added = 0;

	for (std::uint32_t i = 0; i < instructions.size(); i++)
	{
		const auto& instruction = instructions[i];
		const auto& disassembled_instruction = instruction.disassemble();

		const std::uint32_t basic_block_index = i + added;
		const binwrite::rva_t instruction_rva = basic_block.instruction_rva(basic_block_index);

		if (disassembled_instruction.rip_relative() || disassembled_instruction.rsp_relative() ||
			disassembled_instruction.has_lock() || binary.find_rva_ref(instruction_rva))
		{
			continue;
		}

		if (should_skip_memory_operands && should_skip_memory_operands(disassembled_instruction, instruction_rva) &&
			disassembled_instruction.has_visible_mem_operand())
		{
			continue;
		}

		std::vector<binwrite::instruction_t> obfuscated_instructions = { };

		try
		{
			const bool should_emulate_flags = should_instruction_emulate_flags(flag_dependants, i, obfuscated_instructions);

			const binwrite::mnemonic_t mnemonic = disassembled_instruction.mnemonic();

			// switch statement isn't compatible with the mnemonic_t members as they aren't constexpr
			if (mnemonic == binwrite::mnemonic_t::add)
			{
				obfuscated_instructions = mba_obfuscate_add(disassembled_instruction, should_emulate_flags);
			}
			else if (mnemonic == binwrite::mnemonic_t::sub)
			{
				obfuscated_instructions = mba_obfuscate_sub(disassembled_instruction, should_emulate_flags);
			}
			else if (mnemonic == binwrite::mnemonic_t::and_)
			{
				obfuscated_instructions = mba_obfuscate_and(disassembled_instruction, should_emulate_flags);
			}
			else if (mnemonic == binwrite::mnemonic_t::or_)
			{
				obfuscated_instructions = mba_obfuscate_or(disassembled_instruction, should_emulate_flags);
			}
			else if (mnemonic == binwrite::mnemonic_t::xor_)
			{
				obfuscated_instructions = mba_obfuscate_xor(disassembled_instruction, should_emulate_flags);
			}
		}
		catch (const std::exception&)
		{
			spdlog::error("unable to do mixed boolean arithmetic pass on '{}'", disassembled_instruction.to_string());
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
