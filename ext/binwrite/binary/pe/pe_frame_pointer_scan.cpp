#include "pe_exceptions.hpp"
#include "../../assembler/assembler.hpp"
#include "../../arch/mnemonic/mnemonic.hpp"
#include "../../disassembler/disassembler.hpp"

#include <algorithm>
#include <portable-executable/image.hpp>
using block_insertion_list_t = std::vector<std::tuple<std::shared_ptr<binwrite::basic_block_t>, binwrite::instruction_t, std::uint32_t>>;

namespace binwrite
{
	void assign_runtime_function_basic_block(const binary_t& binary,
		const std::shared_ptr<function_t>& function,
		const std::shared_ptr<basic_block_t>& basic_block,
		rva_t begin, rva_t end,
		std::unordered_set<rva_t::value_type>& visited);

	void assign_runtime_function_jump_table_blocks(const binary_t& binary,
		const std::shared_ptr<function_t>& function,
		const std::shared_ptr<basic_block_t>& basic_block,
		rva_t begin, rva_t end,
		std::unordered_set<rva_t::value_type>& visited);

	[[nodiscard]] bool scan_function_for_rewrite_conflicts(
		const function_t& function,
		const std::shared_ptr<basic_block_t>& entry_block,
		const portable_executable::unwind_info_t* unwind_info,
		register_family_t frame_register_family,
		const portable_executable::runtime_function_t* runtime_function,
		const binary_t& binary);

	void reassemble_displacement_instruction(
		portable_executable_t& pe,
		const std::shared_ptr<basic_block_t>& basic_block,
		std::uint32_t instruction_index,
		instruction_t& instruction,
		const instruction_t& compiled_instruction,
		block_insertion_list_t& block_instructions);

	void adjust_displacements_in_block(
		portable_executable_t& pe,
		const std::shared_ptr<basic_block_t>& basic_block,
		std::int64_t current_stack_offset,
		block_insertion_list_t& block_instructions,
		register_family_t check_family,
		bool stop_at_epilogue,
		const std::vector<register_family_t>& extra_families = { });

	void collect_extra_stack_pointer_families(
		const std::shared_ptr<basic_block_t>& basic_block,
		std::vector<register_family_t>& extra_families,
		register_family_t check_family);

	void assign_handler_blocks_to_function(
		portable_executable_t& pe,
		const std::shared_ptr<function_t>& function,
		const std::vector<rva_t>& handler_rvas);

	void insert_exit_block_pops(
		const std::shared_ptr<function_t>& function,
		portable_executable_t& pe,
		block_insertion_list_t& block_instructions,
		const instruction_t& pop_instruction);

	void apply_deferred_insertions(
		portable_executable_t& pe,
		std::vector<std::pair<std::shared_ptr<symbol_ref_t>, std::vector<std::uint8_t>>>& unwind_info_insertions,
		const std::vector<std::pair<std::shared_ptr<rva_t>, std::vector<std::uint8_t>>>& unwind_code_insertions,
		const block_insertion_list_t& block_instructions);

	void adjust_catch_handler_displacements(
		portable_executable_t& pe,
		const std::vector<rva_t>& catch_rvas,
		std::int64_t current_stack_offset,
		block_insertion_list_t& block_instructions,
		std::vector<rva_t>& processed_catch_functions);
}

static bool rva_in_runtime_function_range(const binwrite::rva_t rva, const binwrite::rva_t begin,
                                          const binwrite::rva_t end)
{
	return begin <= rva && rva < end;
}

static std::int64_t compute_prologue_stack_offset(
	const std::shared_ptr<binwrite::basic_block_t>& entry_block,
	const portable_executable::unwind_info_t* unwind_info)
{
	std::int64_t stack_offset = 0;
	std::uint32_t offset = 0;
	const auto instructions = entry_block->instructions();

	for (std::uint32_t j = 0; j < instructions.size(); j++)
	{
		if (offset >= unwind_info->size_of_prolog)
		{
			break;
		}

		auto disassembly = instructions[j].disassemble();
		offset += disassembly.size();

		if (disassembly.writes_stack_pointer())
		{
			if (disassembly.mnemonic() == binwrite::mnemonic_t::push)
			{
				stack_offset += 8;
			}
			else if (disassembly.is_sub())
			{
				const auto source = disassembly.visible_operands()[1];

				if (source.is_imm())
				{
					const auto imm = source.imm();
					stack_offset += imm.is_signed
						? static_cast<std::int32_t>(imm.value.s)
						: static_cast<std::uint32_t>(imm.value.u);
				}
			}
		}
	}

	return stack_offset;
}

static std::optional<binwrite::instruction_t> nop_instruction()
{
	const auto instruction = binwrite::make_assembler_instruction(binwrite::mnemonic_t::nop, {});

	if (!instruction)
	{
		return std::nullopt;
	}

	return instruction->compile();
}

void binwrite::assign_runtime_function_basic_block(const binary_t& binary,
	const std::shared_ptr<function_t>& function,
	const std::shared_ptr<basic_block_t>& basic_block,
	const rva_t begin, const rva_t end,
	std::unordered_set<rva_t::value_type>& visited)
{
	if (!basic_block)
	{
		return;
	}

	const auto block_rva = *basic_block->rva();

	if (!rva_in_runtime_function_range(block_rva, begin, end) || !visited.insert(block_rva.value()).second)
	{
		return;
	}

	if (!function->find_basic_block(block_rva))
	{
		function->add_basic_block(basic_block);
	}

	const auto& last_instruction = basic_block->last_instruction();
	const auto& last_disassembly = last_instruction.disassemble();

	if (last_disassembly.is_ret())
	{
		return;
	}

	if (last_disassembly.is_jump())
	{
		if (const auto code_rva_ref = binary.find_rva_ref(basic_block->last_instruction_rva()))
		{
			if (const auto target_basic_block = binary.find_basic_block(*code_rva_ref->target()))
			{
				assign_runtime_function_basic_block(binary, function, target_basic_block, begin, end, visited);
			}
		}

		assign_runtime_function_jump_table_blocks(binary, function, basic_block, begin, end, visited);
	}

	if (!last_disassembly.is_unconditional_jump())
	{
		const auto end_rva = basic_block->end_rva();
		const auto ft_block = binary.find_basic_block(end_rva);
		if (ft_block)
		{
			assign_runtime_function_basic_block(binary, function, ft_block, begin, end, visited);
		}
	}
}

void binwrite::assign_runtime_function_jump_table_blocks(const binary_t& binary,
	const std::shared_ptr<function_t>& function,
	const std::shared_ptr<basic_block_t>& basic_block,
	const rva_t begin, const rva_t end,
	std::unordered_set<rva_t::value_type>& visited)
{
	for (const auto& target_rva : binary.jump_table_targets(basic_block->last_instruction_rva()))
	{
		if (!rva_in_runtime_function_range(*target_rva, begin, end))
		{
			continue;
		}

		if (const auto target_basic_block = binary.find_basic_block(*target_rva))
		{
			assign_runtime_function_basic_block(binary, function, target_basic_block, begin, end, visited);
		}
	}
}

bool binwrite::scan_function_for_rewrite_conflicts(
	const function_t& function,
	const std::shared_ptr<basic_block_t>& entry_block,
	const portable_executable::unwind_info_t* unwind_info,
	const register_family_t frame_register_family,
	const portable_executable::runtime_function_t* runtime_function,
	const binary_t& binary)
{
	if (entry_block->count() > 0)
	{
		const auto& first_instruction = entry_block->at(0).disassemble();

		if (first_instruction.is_call() || first_instruction.is_jump())
		{
			return true;
		}
	}

	const std::int64_t prologue_stack_offset = compute_prologue_stack_offset(entry_block, unwind_info);

	for (const auto& basic_block : function.basic_blocks())
	{
		const auto instructions = basic_block->instructions();

		for (std::uint64_t i = 0; i < instructions.size(); i++)
		{
			auto& instruction = instructions[i];
			auto& disassembly = instruction.disassemble();

			if (disassembly.mnemonic() != mnemonic_t::pop &&
				disassembly.writes_register_family(frame_register_family))
			{
				return true;
			}

			if (disassembly.is_jump() && !resolve_instruction_rva(disassembly, basic_block->instruction_rva(i)))
			{
				const auto jump_table_targets = binary.jump_table_targets(basic_block->instruction_rva(i));

				if (jump_table_targets.empty())
				{
					return true;
				}

				bool all_owned = true;

				for (const auto& target_rva : jump_table_targets)
				{
					if (*target_rva < rva_t{ runtime_function->begin_address } ||
						rva_t{ runtime_function->end_address } <= *target_rva ||
						!function.find_basic_block(*target_rva))
					{
						all_owned = false;
						break;
					}
				}

				if (!all_owned)
				{
					return true;
				}
			}

			for (auto& visible_operand : disassembly.visible_operands())
			{
				if (!visible_operand.is_mem())
				{
					continue;
				}

				auto mem = visible_operand.mem();
				const auto base_family = mem.base.family();

				if ((base_family == register_family_t::sp && mem.index != register_t::none) ||
					(visible_operand.is_write_action() && base_family == frame_register_family))
				{
					return true;
				}

				if (base_family == register_family_t::sp &&
					!disassembly.writes_stack_pointer() &&
					mem.displacement >= prologue_stack_offset)
				{
					if (basic_block == entry_block && function.basic_blocks().size() > 1)
					{
						rva_t::value_type offset = 0;

						for (std::uint64_t k = 0; k < i; k++)
						{
							offset += basic_block->at(k).size();
						}

						if (offset >= unwind_info->size_of_prolog)
						{
							return true;
						}
					}
				}
			}
		}
	}

	return false;
}

void binwrite::reassemble_displacement_instruction(
	portable_executable_t& pe,
	const std::shared_ptr<basic_block_t>& basic_block,
	const std::uint32_t instruction_index,
	instruction_t& instruction,
	const instruction_t& compiled_instruction,
	block_insertion_list_t& block_instructions)
{
	const std::int64_t size_diff = instruction.size() - compiled_instruction.size();

	if (0 <= size_diff)
	{
		pe.insert(basic_block->instruction_rva(instruction_index), compiled_instruction.bytes());
		pe.erase(rva_t{ basic_block->instruction_rva(instruction_index).value() + compiled_instruction.size() }, instruction.size());

		const auto nop = nop_instruction();

		for (std::int32_t z = 0; z < size_diff; z++)
		{
			pe.insert(rva_t{ basic_block->instruction_rva(instruction_index).value() }, nop->bytes());
		}

		instruction = compiled_instruction;
	}
	else
	{
		const auto instruction_size = instruction.size();
		std::vector<std::uint8_t> nop_bytes(instruction_size, 0x90);
		std::memcpy(pe.data() + basic_block->instruction_rva(instruction_index).value(), nop_bytes.data(), nop_bytes.size());

		instruction = instruction_t{ nop_bytes };

		std::uint32_t previous_count = 0;

		for (const auto& [block, existing_instruction, index] : block_instructions)
		{
			if (basic_block == block && index <= instruction_index)
			{
				previous_count++;
			}
		}

		block_instructions.emplace_back(basic_block, compiled_instruction, instruction_index + previous_count);
	}
}

void binwrite::adjust_displacements_in_block(
	portable_executable_t& pe,
	const std::shared_ptr<basic_block_t>& basic_block,
	const std::int64_t current_stack_offset,
	block_insertion_list_t& block_instructions,
	const register_family_t check_family,
	const bool stop_at_epilogue,
	const std::vector<register_family_t>& extra_families)
{
	const auto instructions = basic_block->instructions();

	for (std::uint32_t j = 0; j < instructions.size(); j++)
	{
		auto& instruction = instructions[j];
		auto& disassembly = instruction.disassemble();

		if (stop_at_epilogue && disassembly.writes_stack_pointer()
			&& (disassembly.is_add() || disassembly.mnemonic() == mnemonic_t::pop))
		{
			break;
		}

		for (auto& visible_operand : disassembly.visible_operands())
		{
			if (!visible_operand.is_mem())
			{
				continue;
			}

			auto mem = visible_operand.mem();
			const auto base_family = mem.base.family();

			const bool family_match = base_family == check_family ||
				std::ranges::contains(extra_families, base_family);

			if (!family_match || current_stack_offset > mem.displacement)
			{
				continue;
			}

			mem.displacement += 16;
			visible_operand.set_mem(mem);

			const auto reassembled = make_assembler_instruction(disassembly);
			const auto compiled = reassembled->compile();

			basic_block->replace_instruction(j, *compiled);
		}
	}
}

void binwrite::collect_extra_stack_pointer_families(
	const std::shared_ptr<basic_block_t>& basic_block,
	std::vector<register_family_t>& extra_families,
	const register_family_t check_family)
{
	for (const auto& instruction : basic_block->instructions())
	{
		const auto& disassembly = instruction.disassemble();
		const auto visible_operands = disassembly.visible_operands();

		if (disassembly.is_mov() && 2 <= visible_operands.size())
		{
			const auto& destination_operand = visible_operands[0];
			const auto& source_operand = visible_operands[1];

			if (destination_operand.is_reg() && source_operand.is_reg())
			{
				const auto source_register = source_operand.reg().value;

				if (source_register.family() == check_family)
				{
					const auto destination_register = destination_operand.reg().value;
					extra_families.push_back(destination_register.family());
				}
			}
		}
	}
}

void binwrite::assign_handler_blocks_to_function(
	portable_executable_t& pe,
	const std::shared_ptr<function_t>& function,
	const std::vector<rva_t>& handler_rvas)
{
	for (const auto& handler_rva : handler_rvas)
	{
		if (function->find_basic_block(handler_rva))
		{
			continue;
		}

		const auto basic_block = pe.find_basic_block(handler_rva);

		if (basic_block)
		{
			pe.assign_basic_block_to_function(function, basic_block);
		}
	}
}

void binwrite::insert_exit_block_pops(
	const std::shared_ptr<function_t>& function,
	portable_executable_t& pe,
	block_insertion_list_t& block_instructions,
	const instruction_t& pop_instruction)
{
	const auto exits = function->exit_blocks(pe);

	for (const auto& exit_block : exits)
	{
		if (!pe.jump_table_targets(exit_block->last_instruction_rva()).empty())
		{
			continue;
		}

		std::uint32_t previous_count = 0;

		for (const auto& [block, instruction, index] : block_instructions)
		{
			if (exit_block == block)
			{
				previous_count++;
			}
		}

		const std::uint32_t pop_index = static_cast<std::uint32_t>(exit_block->count()) - 1 + previous_count;

		block_instructions.emplace_back(exit_block, pop_instruction, pop_index);
		block_instructions.emplace_back(exit_block, pop_instruction, pop_index);
	}
}

void binwrite::apply_deferred_insertions(
	portable_executable_t& pe,
	std::vector<std::pair<std::shared_ptr<symbol_ref_t>, std::vector<std::uint8_t>>>& unwind_info_insertions,
	const std::vector<std::pair<std::shared_ptr<rva_t>, std::vector<std::uint8_t>>>& unwind_code_insertions,
	const block_insertion_list_t& block_instructions)
{
	const auto data_section = pe.data_section();

	for (auto& [symbol_ref, bytes] : unwind_info_insertions)
	{
		if (bytes.size() % 2)
		{
			bytes.push_back(0);
		}

		const auto new_block = pe.create_data_block(*data_section, bytes);

		const auto all_refs_at_self = pe.find_all_symbol_refs_by_self(symbol_ref->self());
		for (const auto& ref : all_refs_at_self)
		{
			ref->set_target(new_block);
		}
	}

	for (const auto& [rva, bytes] : unwind_code_insertions)
	{
		const auto containing_symbol = pe.find_containing_symbol(*rva);

		if (const auto data_block = std::dynamic_pointer_cast<data_block_t>(containing_symbol))
		{
			const auto offset = rva->value() - data_block->rva()->value();
			data_block->insert_bytes(offset, bytes);
		}
	}

	std::unordered_map<basic_block_t*, std::uint32_t> index_zero_counts;

	for (const auto& [basic_block, instruction, index] : block_instructions)
	{
		const bool inclusive = index != 0;
		basic_block->insert(pe, instruction, index, inclusive);

		if (index == 0)
		{
			index_zero_counts[basic_block.get()]++;
		}
	}

	for (const auto& [block_ptr, count] : index_zero_counts)
	{
		const auto block = std::dynamic_pointer_cast<basic_block_t>(block_ptr->shared_from_this());
		const auto remainder = block->split_at(pe, count);

		if (!remainder)
		{
			continue;
		}

		for (const auto& ref : pe.find_all_symbol_refs_by_self(block))
		{
			ref->set_self(remainder);
		}
	}
}

void binwrite::adjust_catch_handler_displacements(
	portable_executable_t& pe,
	const std::vector<rva_t>& catch_rvas,
	const std::int64_t current_stack_offset,
	block_insertion_list_t& block_instructions,
	std::vector<rva_t>& processed_catch_functions)
{
	std::vector frame_families = { binwrite::register_family_t::dx };

	for (const auto& catch_rva : catch_rvas)
	{
		if (std::ranges::contains(processed_catch_functions, catch_rva))
		{
			continue;
		}

		const auto catch_function = pe.find_function(catch_rva);

		if (!catch_function)
		{
			continue;
		}

		processed_catch_functions.push_back(catch_rva);

		for (const auto& basic_block : catch_function->basic_blocks())
		{
			collect_extra_stack_pointer_families(basic_block, frame_families, register_family_t::dx);

			adjust_displacements_in_block(pe, basic_block, current_stack_offset, block_instructions,
				register_family_t::none, true, frame_families);
		}
	}
}

void binwrite::split_prologues(portable_executable_t& pe, const exception_context_t& context)
{
	for (const auto& prologue : context.fh_prologues)
	{
		if (prologue.prolog_size == 0)
		{
			continue;
		}

		const auto prologue_end_rva = prologue.begin->value() + prologue.prolog_size;

		const auto basic_block = pe.find_basic_block(*prologue.begin);

		if (!basic_block)
		{
			continue;
		}

		rva_t::value_type accumulated_rva = basic_block->rva()->value();
		basic_block_t::size_type split_index = 0;
		bool exact_boundary = false;

		for (std::int64_t j = 0; j < basic_block->count(); j++)
		{
			if (accumulated_rva == prologue_end_rva)
			{
				split_index = static_cast<basic_block_t::size_type>(j);
				exact_boundary = true;
				break;
			}

			if (accumulated_rva > prologue_end_rva)
			{
				break;
			}

			accumulated_rva += basic_block->at(j).size();
		}

		if (exact_boundary && split_index > 0 && split_index < basic_block->count())
		{
			const auto new_block = pe.split_basic_block(*basic_block, split_index);

			basic_block->set_skip(true);
		}
	}
}
