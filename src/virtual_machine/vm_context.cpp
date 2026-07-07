#include "vm_context.hpp"
#include <spdlog/spdlog.h>

void vm_context_t::enter_virtualized_state(binwrite::binary_t& binary)
{
	std::vector<binwrite::instruction_t> instructions;

	push_registers(instructions);

	entry_block_ = previous_block_ = binary.create_basic_block(instructions);
	virtualized_state_ = true;

	basic_blocks_.push_back(entry_block_);
}

void vm_context_t::exit_virtualized_state(binwrite::binary_t& binary)
{
	free_instruction();

	if (!virtualized_state_)
	{
		return;
	}

	std::vector<binwrite::instruction_t> instructions;

	pop_registers(instructions);

	previous_block_->push(binary, instructions, true);
	previous_block_->push(binary, ret_instruction().value(), true);

	segments_.push_back({ entry_block_, previous_block_, stack_registers_ });

	virtualized_state_ = false;
	previous_block_ = { };

	shuffle_registers();
}

void vm_context_t::process_instruction(const binwrite::disassembled_instruction_t& instruction_disassembly)
{
	const auto& visible_operands = instruction_disassembly.visible_operands();
	const auto& hidden_operands = instruction_disassembly.hidden_operands();

	std::vector<binwrite::instruction_t> hidden_unload_instructions;
	std::vector<hardware_register_t> hidden_registers;

	process_hidden_operands(current_instruction_.load, hidden_unload_instructions, hidden_registers, hidden_operands);

	const auto obfuscated_operands = load_instruction(visible_operands);

	handle_instruction(instruction_disassembly, visible_operands, obfuscated_operands);

	unload_instruction(instruction_disassembly, visible_operands, obfuscated_operands);

	current_instruction_.unload.insert(current_instruction_.unload.end(), hidden_unload_instructions.begin(), hidden_unload_instructions.end());
}

void vm_context_t::compile_instruction(binwrite::binary_t& binary)
{
	if (!virtualized_state_)
	{
		enter_virtualized_state(binary);
	}

	previous_block_->push(binary, current_instruction_.load, true);

	const auto handler_block = binary.create_basic_block(current_instruction_.handler);

	push_jump_to_block(binary, previous_block_, handler_block);

	previous_block_ = binary.create_basic_block(current_instruction_.unload);

	basic_blocks_.push_back(previous_block_);
	basic_blocks_.push_back(handler_block);

	push_jump_to_block(binary, handler_block, previous_block_);

	free_instruction();
}

hardware_register_t vm_context_t::random_hardware_register()
{
	if (free_registers_.empty())
	{
		throw std::runtime_error("ran out of available hardware registers");
	}

	const auto free_register = free_registers_.back();

	free_registers_.pop_back();

	return hardware_register_t(shared_from_this(), free_register);
}

void vm_context_t::free_hardware_register(const hardware_register_t& hardware_register)
{
	free_registers_.push_front(hardware_register.value());
}

void vm_context_t::shuffle_registers()
{
	binwrite::util::shuffle<binwrite::register_family_t>(stack_registers_);
}

void vm_context_t::push_registers(std::vector<binwrite::instruction_t>& instructions) const
{
	instructions.push_back(push_instruction(binwrite::register_t::rbp).value());
	push_register(instructions, binwrite::register_family_t::flags);

	for (const auto register_family : stack_registers_)
	{
		instructions.push_back(push_instruction(register_family.qword).value());
	}

	instructions.push_back(lea_instruction(encode_mem_operand(binwrite::register_t::rsp, 0, 8), binwrite::register_t::rbp).value());
}

void vm_context_t::pop_registers(std::vector<binwrite::instruction_t>& instructions) const
{
	for (const auto register_family : stack_registers_ | std::views::reverse)
	{
		instructions.push_back(pop_instruction(register_family.qword).value());
	}

	instructions.push_back(popfq_instruction().value());
	instructions.push_back(pop_instruction(binwrite::register_t::rbp).value());
}

std::optional<vm_context_t::offset_type> vm_context_t::register_stack_offset(const binwrite::register_t reg) const
{
	offset_type offset = 0;

	for (const auto stack_register : stack_registers_ | std::views::reverse)
	{
		if (reg.in_same_family(stack_register.qword))
		{
			return offset;
		}

		offset += stack_register_size;
	}

	return std::nullopt;
}

void vm_context_t::free_instruction()
{
	current_instruction_ = { };
	temporary_holding_registers_.clear();
}

std::vector<std::unique_ptr<obfuscated_operand_t>> vm_context_t::load_instruction(const std::span<const binwrite::decoded_operand_t> operands)
{
	std::vector<binwrite::instruction_t>& instructions = current_instruction_.load;
	std::vector<std::unique_ptr<obfuscated_operand_t>> obfuscated_operands(operands.size());

	allocate_operands(instructions, operands.size());

	save_instruction_operands(instructions, operands, obfuscated_operands);

	return obfuscated_operands;
}

void vm_context_t::handle_instruction(const binwrite::disassembled_instruction_t& instruction_disassembly,
                                      const std::span<const binwrite::decoded_operand_t> original_operands,
                                      const std::span<const std::unique_ptr<obfuscated_operand_t>> obfuscated_operands)
{
	std::vector<hardware_register_t> holding_registers(original_operands.size());
	std::vector<binwrite::encoder_operand_t> redirected_operands(original_operands.size());

	std::vector<binwrite::instruction_t>& instructions = current_instruction_.handler;

	load_instruction_operands(instructions, instruction_disassembly, holding_registers, redirected_operands,
	                          original_operands, obfuscated_operands);

	recompile_instruction_operands(instructions, instruction_disassembly, redirected_operands);

	save_instruction_results(instructions, obfuscated_operands, holding_registers);
}

void vm_context_t::unload_instruction(const binwrite::disassembled_instruction_t& instruction_disassembly,
                                      const std::span<const binwrite::decoded_operand_t> operands,
                                      const std::span<const std::unique_ptr<obfuscated_operand_t>> obfuscated_operands)
{
	std::vector<binwrite::instruction_t>& instructions = current_instruction_.unload;

	write_instruction_results(instructions, instruction_disassembly, operands, obfuscated_operands);

	free_operands(instructions, operands.size());
}

void vm_context_t::save_instruction_operands(std::vector<binwrite::instruction_t>& instructions,
                                             const std::span<const binwrite::decoded_operand_t> operands,
                                             const std::span<std::unique_ptr<obfuscated_operand_t>> obfuscated_operands)
{
	const offset_type operand_offset = calculate_operand_offset(operands.size());

	for (size_type i = 0; i < operands.size(); i++)
	{
		const auto& original_operand = operands[i];

		const hardware_register_t holder = random_hardware_register();

		const auto redirected_operand = redirect_operand(instructions, original_operand, operand_offset);

		std::unique_ptr<obfuscated_operand_t> obfuscated_operand = obfuscate_operand(instructions, redirected_operand, original_operand, holder);

		write_operand(instructions, holder, i);

		obfuscated_operands[i] = std::move(obfuscated_operand);
	}
}

void vm_context_t::load_instruction_operands(std::vector<binwrite::instruction_t>& instructions,
                                             const binwrite::disassembled_instruction_t& instruction_disassembly,
                                             const std::span<hardware_register_t> holding_registers,
                                             const std::span<binwrite::encoder_operand_t> redirected_operands,
                                             const std::span<const binwrite::decoded_operand_t> original_operands,
                                             const std::span<const std::unique_ptr<obfuscated_operand_t>> obfuscated_operands)
{
	for (size_type i = 0; i < original_operands.size(); i++)
	{
		const auto& original_operand = original_operands[i];
		const auto& obfuscated_operand = obfuscated_operands[i];

		const auto operand_width = static_cast<std::uint16_t>(instruction_disassembly.operand_width());

		hardware_register_t operand_holder = read_operand(instructions, i);

		obfuscated_operand->decode_value(instructions, operand_holder);

		redirected_operands[i] = operand_holder->of_size(original_operand.is_imm() ? operand_width : original_operand.size());
		holding_registers[i] = std::move(operand_holder);
	}
}

void vm_context_t::process_hidden_operands(std::vector<binwrite::instruction_t>& load_instructions,
                                           std::vector<binwrite::instruction_t>& unload_instructions,
                                           std::vector<hardware_register_t>& holding_registers,
                                           const std::span<const binwrite::decoded_operand_t> hidden_operands)
{
	for (const auto& hidden_operand : hidden_operands)
	{
		if (hidden_operand.is_reg())
		{
			const auto reg = hidden_operand.reg().value;

			process_hidden_register(load_instructions, unload_instructions, holding_registers, hidden_operand, reg);
		}
		else if (hidden_operand.is_mem())
		{
			const auto mem = hidden_operand.mem();
			const auto base = mem.base;
			const auto index = mem.index;

			if (base != binwrite::register_t::none)
			{
				process_hidden_register(load_instructions, unload_instructions, holding_registers, hidden_operand, base);
			}

			if (index != binwrite::register_t::none && index != base)
			{
				process_hidden_register(load_instructions, unload_instructions, holding_registers, hidden_operand, index);
			}
		}
	}
}

void vm_context_t::process_hidden_register(std::vector<binwrite::instruction_t>& load_instructions,
                                           std::vector<binwrite::instruction_t>& unload_instructions,
                                           std::vector<hardware_register_t>& holding_registers,
                                           const binwrite::decoded_operand_t& hidden_operand,
                                           const binwrite::register_t reg)
{
	if (!reg.is_general_purpose())
	{
		return;
	}

	const auto family = reg.family();

	if (std::ranges::contains(holding_registers, family, &hardware_register_t::value))
	{
		return;
	}

	std::erase(free_registers_, family);

	const auto redirected_operand = redirect_operand(load_instructions, reg);

	load_instructions.push_back(mov_instruction(redirected_operand, family.qword).value());

	if (hidden_operand.is_write_action())
	{
		unload_instructions.push_back(mov_instruction(family.qword, redirected_operand).value());
	}

	holding_registers.emplace_back(shared_from_this(), family);
}

void vm_context_t::recompile_instruction_operands(std::vector<binwrite::instruction_t>& instructions,
                                                  const binwrite::disassembled_instruction_t& instruction_disassembly,
                                                  const std::span<const binwrite::encoder_operand_t> operands)
{
	bool uses_flags = instruction_disassembly.reads_flags() || instruction_disassembly.writes_flags();

	if (!uses_flags)
	{
		for (const auto& hidden : instruction_disassembly.hidden_operands())
		{
			if (hidden.is_reg())
			{
				const auto reg = hidden.reg().value;

				if (reg == binwrite::register_t::rflags ||
					reg == binwrite::register_t::eflags ||
					reg == binwrite::register_t::flags)
				{
					uses_flags = true;
					break;
				}
			}
		}
	}

	const offset_type operand_offset = calculate_operand_offset(operands.size());

	if (uses_flags)
	{
		load_flags(instructions, operand_offset);
	}

	binwrite::assembler_instruction_t reassembled_instruction = make_assembler_instruction(instruction_disassembly).value();

	reassembled_instruction.set_operands(operands);

	instructions.push_back(reassembled_instruction.compile().value());

	if (uses_flags)
	{
		save_flags(instructions, operand_offset);
	}
}

void vm_context_t::save_instruction_results(std::vector<binwrite::instruction_t>& instructions,
                                             const std::span<const std::unique_ptr<obfuscated_operand_t>> obfuscated_operands,
                                             const std::span<const hardware_register_t> holding_registers)
{
	for (size_type i = 0; i < obfuscated_operands.size(); i++)
	{
		const auto& obfuscated_operand = obfuscated_operands[i];

		if (obfuscated_operand->is_result())
		{
			const hardware_register_t& result_holder = holding_registers[i];

			obfuscated_operand->encode_value(instructions, result_holder);

			write_operand(instructions, result_holder, i);
		}
	}
}

void vm_context_t::write_instruction_results(std::vector<binwrite::instruction_t>& instructions,
                                             const binwrite::disassembled_instruction_t& instruction_disassembly,
                                             const std::span<const binwrite::decoded_operand_t> operands,
                                             const std::span<const std::unique_ptr<obfuscated_operand_t>> obfuscated_operands)
{
	const offset_type operand_offset = calculate_operand_offset(operands.size());

	for (size_type i = 0; i < operands.size(); i++)
	{
		const auto& obfuscated_operand = obfuscated_operands[i];

		if (obfuscated_operand->is_result())
		{
			const auto& original_destination = operands[i];

			const hardware_register_t& result_holder = read_operand(instructions, i);

			obfuscated_operand->decode_value(instructions, result_holder);

			const auto& destination_redirected = redirect_operand(instructions, original_destination, operand_offset);

			const auto operand_width = static_cast<std::uint16_t>(instruction_disassembly.operand_width());
			const auto result_register = original_destination.is_reg() ? result_holder->qword : result_holder->of_size(operand_width);

			instructions.push_back(mov_instruction(result_register, destination_redirected).value());
		}
	}
}

vm_context_t::offset_type vm_context_t::calculate_operand_offset(const size_type index)
{
	return static_cast<offset_type>(operand_size * index);
}

binwrite::encoder_operand_t vm_context_t::redirect_operand(std::vector<binwrite::instruction_t>& instructions,
	const binwrite::encoder_operand_t& operand, const std::int64_t stack_offset)
{
	if (operand.is_reg())
	{
		const auto reg = operand.reg().value;
		const auto family = reg.family();

		if (family == binwrite::register_family_t::sp)
		{
			const std::uint16_t register_width = reg.width();

			const std::int64_t displacement = static_cast<std::int64_t>(stack_offset + initial_stack_size());

			hardware_register_t holder = random_hardware_register();
			const auto sized_holder = holder->of_size(register_width);

			instructions.push_back(mov_instruction(reg, sized_holder).value());
			instructions.push_back(add_instruction(encode_signed_imm_operand(displacement), sized_holder).value());
			temporary_holding_registers_.push_back(std::move(holder));

			return sized_holder;
		}

		return register_to_stack(family.qword, 64, stack_offset);
	}

	if (operand.is_mem())
	{
		const auto mem = operand.mem();
		const auto base_width = mem.base.width();

		binwrite::register_t base_register = binwrite::register_t::none;
		binwrite::register_family_t base_family = binwrite::register_family_t::none;

		hardware_register_t base_holder;

		if (mem.base != binwrite::register_t::none)
		{
			const binwrite::encoder_operand_t base = register_to_stack(mem.base, base_width, stack_offset);
			base_holder = random_hardware_register();

			base_register = base_holder->of_size(base_width);
			base_family = mem.base.family();

			instructions.push_back(mov_instruction(base, base_register).value());
		}

		binwrite::register_t index_register = binwrite::register_t::none;

		hardware_register_t index_holder;

		if (mem.index != binwrite::register_t::none)
		{
			const auto index_width = mem.index.width();

			const binwrite::encoder_operand_t index = register_to_stack(mem.index, index_width, stack_offset);
			index_holder = random_hardware_register();

			index_register = index_holder->of_size(index_width);

			instructions.push_back(mov_instruction(index, index_register).value());
		}

		std::int64_t displacement = mem.displacement;

		if (base_family == binwrite::register_family_t::sp)
		{
			displacement += static_cast<std::int64_t>(stack_offset + initial_stack_size());
		}

		if (base_holder.value() != binwrite::register_family_t::none)
		{
			temporary_holding_registers_.push_back(std::move(base_holder));
		}

		if (index_holder.value() != binwrite::register_family_t::none)
		{
			temporary_holding_registers_.push_back(std::move(index_holder));
		}

		return encode_mem_operand(base_register, displacement, mem.size, index_register, mem.scale);
	}

	return operand;
}

binwrite::encoder_operand_t vm_context_t::register_to_stack(const binwrite::register_t reg,
                                                            const std::uint16_t operand_width,
                                                            std::int64_t additional_displacement) const
{
	const auto stack_offset = register_stack_offset(reg);

	if (!stack_offset)
	{
		return reg;
	}

	if (reg.is_high_byte())
	{
		additional_displacement += 1;
	}

	return encode_stack_mem_operand(*stack_offset + additional_displacement, operand_width / 8);
}

binwrite::encoder_operand_t vm_context_t::flags_to_stack(const std::int64_t additional_displacement) const
{
	const size_type flags_index = stack_registers_.size();
	const offset_type stack_offset = static_cast<offset_type>(flags_index * stack_register_size);

	return encode_stack_mem_operand(stack_offset + additional_displacement, 8);
}

hardware_register_t vm_context_t::read_operand(std::vector<binwrite::instruction_t>& instructions,
                                               const size_type index)
{
	const binwrite::encoder_operand_t stack_memory = encode_stack_mem_operand(static_cast<std::int64_t>(operand_size * index), operand_size);

	hardware_register_t holder = random_hardware_register();

	instructions.push_back(mov_instruction(stack_memory, holder->qword).value());

	return holder;
}

void vm_context_t::load_flags(std::vector<binwrite::instruction_t>& instructions, const std::int64_t operand_offset)
{
	const hardware_register_t holder = random_hardware_register();

	instructions.push_back(mov_instruction(flags_to_stack(operand_offset), holder->qword).value());
	instructions.push_back(push_instruction(holder->qword).value());
	instructions.push_back(popfq_instruction().value());
}

void vm_context_t::save_flags(std::vector<binwrite::instruction_t>& instructions, const std::int64_t operand_offset)
{
	const hardware_register_t holder = random_hardware_register();

	instructions.push_back(pushfq_instruction().value());
	instructions.push_back(mov_instruction(encode_stack_mem_operand(0, 8), holder->qword).value());
	instructions.push_back(popfq_instruction().value());

	instructions.push_back(mov_instruction(holder->qword, flags_to_stack(operand_offset)).value());
}
