#include "virtual_machine.hpp"
#include "vm_context.hpp"

#include <algorithm>
#include <binwrite/arch/mnemonic/mnemonic.hpp>
#include <binwrite/binary/pe/pe_exceptions.hpp>
#include <spdlog/spdlog.h>

static bool is_safe_vm_instruction(const binwrite::disassembled_instruction_t& instruction)
{
	if (instruction.rip_relative() || instruction.writes_stack_pointer() || instruction.has_lock() || instruction.is_lea() || instruction.is_nop() || instruction.is_jump() || instruction.is_call() || instruction.is_ret() || instruction.is_int())
	{
		return false;
	}

	const auto& visible_operands = instruction.visible_operands();

	if (visible_operands.empty() && instruction.mnemonic() != binwrite::mnemonic_t::movsb &&
		instruction.mnemonic() != binwrite::mnemonic_t::cpuid_)
	{
		return false;
	}

	for (const auto& operand : visible_operands)
	{
		if (operand.size() > 64)
		{
			return false;
		}

		if (!(operand.is_reg() || operand.is_imm() || operand.is_mem()))
		{
			return false;
		}

		if (operand.is_reg() && (operand.reg().value.family() == binwrite::register_family_t::sp ||
			operand.reg().value.family() == binwrite::register_family_t::bp))
		{
			return false;
		}

		if (operand.is_mem())
		{
			const auto mem = operand.mem();
			if (mem.base.family() == binwrite::register_family_t::sp ||
				mem.base.family() == binwrite::register_family_t::bp ||
				mem.index.family() == binwrite::register_family_t::sp ||
				mem.index.family() == binwrite::register_family_t::bp)
			{
				return false;
			}
		}
	}

	return true;
}

static void insert_call_to_block(binwrite::binary_t& binary,
	const std::shared_ptr<binwrite::basic_block_t>& source_block,
	const binwrite::basic_block_t::size_type index,
	const std::shared_ptr<binwrite::basic_block_t>& target_block)
{
	const auto destination_placeholder = encode_unsigned_imm_operand(1);
	const auto instruction = call_instruction(destination_placeholder).value();

	source_block->insert(binary, instruction, index);

	const auto ref = std::make_shared<binwrite::code_symbol_ref_t>(
		target_block, source_block,
		static_cast<binwrite::symbol_ref_t::size_type>(instruction.size()));

	ref->set_self_instr_id(source_block->at(index).id());

	binary.add_symbol_ref(ref);
}

std::shared_ptr<vm_context_t> binprotect::vm::do_pass(binwrite::binary_t& binary, binwrite::basic_block_t& basic_block,
                             std::vector<std::shared_ptr<binwrite::basic_block_t>>& virtual_machine_blocks)
{
	const auto context = std::make_shared<vm_context_t>(binwrite::register_family_t::general_purpose);

	const std::span<const binwrite::instruction_t> original_instructions = basic_block.instructions();
	const std::vector instructions(original_instructions.begin(), original_instructions.end());

	std::uint32_t erased = 0;

	for (std::uint32_t i = 0; i < instructions.size(); i++)
	{
		const auto& instruction = instructions[i];
		const auto& disassembled_instruction = instruction.disassemble();

		if (!is_safe_vm_instruction(disassembled_instruction))
		{
			context->exit_virtualized_state(binary);

			continue;
		}

		const auto basic_block_index = i - erased;

		if (basic_block.rva())
		{
			const binwrite::rva_t instruction_rva = basic_block.instruction_rva(basic_block_index);

			if (binary.find_rva_ref(instruction_rva))
			{
				context->exit_virtualized_state(binary);

				continue;
			}
		}

		try
		{
			const bool requires_entry = !context->in_virtualized_state();

			context->process_instruction(disassembled_instruction);
			context->compile_instruction(binary);

			if (requires_entry)
			{
				const auto entry_block = context->entry_block();
				const auto source_block = std::static_pointer_cast<binwrite::basic_block_t>(basic_block.shared_from_this());

				insert_call_to_block(binary, source_block, basic_block_index, entry_block);

				basic_block.erase(binary, basic_block_index + 1);
			}
			else
			{
				basic_block.erase(binary, basic_block_index);

				erased++;
			}
		}
		catch (const std::exception&)
		{
			context->exit_virtualized_state(binary);

			spdlog::error("unable to do virtualization pass on '{}'", disassembled_instruction.to_string());
		}
	}

	context->exit_virtualized_state(binary);

	const auto& context_blocks = context->basic_blocks();

	virtual_machine_blocks.insert(virtual_machine_blocks.end(), context_blocks.begin(), context_blocks.end());

	return context;
}

void binprotect::vm::emit_runtime_functions(binwrite::portable_executable_t& pe,
                                            const std::vector<std::shared_ptr<vm_context_t>>& vm_contexts,
											const std::shared_ptr<binwrite::rva_t>& exception_directory_rva,
                                            const std::shared_ptr<binwrite::rva_t>& unwind_insertion_rva)
{
	if (!exception_directory_rva || !unwind_insertion_rva)
	{
		return;
	}

	for (const auto& vm_context : vm_contexts)
	{
		for (const auto& vm_segment : vm_context->segments())
		{
			const auto& entry_block = vm_segment.entry_block;
			const auto& exit_block = vm_segment.exit_block;
			const auto& stack_registers = vm_segment.stack_registers;

			std::vector<std::pair<std::uint8_t, portable_executable::unwind_register_t>> pushed_registers;
			std::vector<portable_executable::unwind_code_t> unwind_codes;

			std::uint8_t current_offset = 2;

			for (const auto& register_family : stack_registers)
			{
				const auto reg = register_family.qword;

				pushed_registers.emplace_back(current_offset, binwrite::get_unwind_register(reg));

				current_offset += (reg.value() >= binwrite::register_t::r8.value()) ? 2 : 1;
			}

			const std::uint8_t set_fp_offset = current_offset;
			current_offset += 4;

			unwind_codes.emplace_back(set_fp_offset, portable_executable::unwind_opcode_t::set_frame_register, 0);

			for (auto it = pushed_registers.rbegin(); it != pushed_registers.rend(); ++it)
			{
				unwind_codes.emplace_back(it->first, portable_executable::unwind_opcode_t::push_non_volatile, static_cast<std::uint8_t>(it->second));
			}

			unwind_codes.emplace_back(static_cast<std::uint8_t>(1),
			                          portable_executable::unwind_opcode_t::stack_allocate_small, 0);

			unwind_codes.emplace_back(static_cast<std::uint8_t>(1),
			                          portable_executable::unwind_opcode_t::push_non_volatile,
			                          static_cast<std::uint8_t>(portable_executable::unwind_register_t::rbp));

			pe.add_runtime_function({
				.begin_symbol = entry_block,
				.end_symbol = exit_block,
				.unwind_codes = std::move(unwind_codes),
				.frame_register = portable_executable::unwind_register_t::rbp,
				.frame_offset = 0,
				.prolog_size = current_offset,
				.flags = 0
			});
		}
	}
}
