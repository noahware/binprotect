#include "pe_exceptions.hpp"
#include "../../util/serialize.hpp"
#include "../../assembler/assembler.hpp"
#include "../../arch/mnemonic/mnemonic.hpp"
#include "../../disassembler/disassembler.hpp"

#include <algorithm>
#include <set>
#include <portable-executable/image.hpp>
#include <spdlog/spdlog.h>

using block_insertion_list_t = std::vector<std::tuple<std::shared_ptr<binwrite::basic_block_t>, binwrite::instruction_t, std::uint32_t>>;

namespace binwrite
{
	void assign_runtime_function_basic_block(const binary_t& binary,
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

	void adjust_catch_handler_displacements(
		portable_executable_t& pe,
		const std::vector<rva_t>& catch_rvas,
		std::int64_t current_stack_offset,
		block_insertion_list_t& block_instructions,
		std::vector<rva_t>& processed_catch_functions);

	void apply_deferred_insertions(
		portable_executable_t& pe,
		std::vector<std::pair<std::shared_ptr<symbol_ref_t>, std::vector<std::uint8_t>>>& unwind_info_insertions,
		const std::vector<std::pair<std::shared_ptr<rva_t>, std::vector<std::uint8_t>>>& unwind_code_insertions,
		const block_insertion_list_t& block_instructions);
}

static std::optional<binwrite::instruction_t> push_instr(const binwrite::encoder_operand_t& source)
{
	return make_assembler_instruction(binwrite::mnemonic_t::push, std::array{ source })->compile();
}

static std::optional<binwrite::instruction_t> pop_instr(const binwrite::encoder_operand_t& source)
{
	return make_assembler_instruction(binwrite::mnemonic_t::pop, std::array{ source })->compile();
}

static std::optional<binwrite::instruction_t> lea_instr(const binwrite::encoder_operand_t& source,
                                                        const binwrite::encoder_operand_t& destination)
{
	return make_assembler_instruction(binwrite::mnemonic_t::lea, std::array{ destination, source })->compile();
}

static binwrite::encoder_operand_t stack_mem_operand(const std::int64_t displacement, const std::uint16_t size)
{
	binwrite::encoder_operand_t operand = {};

	operand.set_mem({
		.displacement = displacement, .scale = 0, .base = binwrite::register_t::rsp,
		.index = binwrite::register_t::none, .size = size
	});

	return operand;
}

static bool has_unwind_register_conflict(
	const portable_executable::unwind_info_t* unwind_info,
	const portable_executable::unwind_register_t unwind_register)
{
	for (auto& unwind_code : *unwind_info)
	{
		if ((unwind_code.opcode == portable_executable::unwind_opcode_t::push_non_volatile &&
			unwind_code.info == static_cast<std::uint8_t>(unwind_register)) ||
			(unwind_code.opcode == portable_executable::unwind_opcode_t::save_non_volatile &&
			unwind_code.info == static_cast<std::uint8_t>(unwind_register)))
		{
			return true;
		}
	}

	return false;
}

static portable_executable::unwind_info_t* find_shared_unwind_refs(binwrite::portable_executable_t& pe,
                                                                   const portable_executable::runtime_function_t*
                                                                   runtime_function,
                                                                   const std::shared_ptr<binwrite::rva_t>& directory_rva,
                                                                   const std::uint32_t count,
                                                                   std::vector<std::uint8_t>& buffer,
                                                                   binwrite::exception_context_t& context,
                                                                   std::vector<std::uint8_t>& copied_unwind_info)
{
	auto* original_unwind_info = reinterpret_cast<portable_executable::unwind_info_t*>(
		buffer.data() + runtime_function->unwind_info_rva);

	auto updated_runtime_function = reinterpret_cast<const portable_executable::runtime_function_t*>(
		pe.data() + directory_rva->value());

	std::vector<std::shared_ptr<binwrite::symbol_ref_t>> targeting_refs;

	for (std::uint32_t j = 0; j < count; j++, updated_runtime_function++)
	{
		if (updated_runtime_function->begin_address == runtime_function->begin_address &&
			updated_runtime_function->end_address == runtime_function->end_address)
		{
			const auto ref_rva = static_cast<binwrite::rva_t::value_type>(
				reinterpret_cast<const std::uint8_t*>(&updated_runtime_function->unwind_info_rva) - pe.data());
			const auto unwind_info_ref = pe.find_data_symbol_ref_at(binwrite::rva_t{ ref_rva });

			if (!unwind_info_ref)
			{
				continue;
			}

			targeting_refs = pe.find_all_symbol_refs_targeting(unwind_info_ref->target());
		}
	}

	if (1 < targeting_refs.size())
	{
		const auto language_specific_data = original_unwind_info->language_specific_data<const std::uint8_t>();
		const auto end = original_unwind_info->has_handler() ? language_specific_data + 4 : language_specific_data;
		const auto start = reinterpret_cast<const std::uint8_t*>(original_unwind_info);

		copied_unwind_info.insert(copied_unwind_info.end(), start, end);
	}
	else if (!context.unwind_info_insertion_rva)
	{
		context.unwind_info_insertion_rva = pe.add_rva(runtime_function->unwind_info_rva);
	}

	return original_unwind_info;
}

struct prologue_adjustment_result_t
{
	std::int64_t stack_offset;
	std::uint32_t last_instruction_index;
};

static prologue_adjustment_result_t adjust_prologue_displacements(binwrite::portable_executable_t& pe,
                                                                  const binwrite::function_t& function,
                                                                  const std::shared_ptr<binwrite::basic_block_t>& entry_block,
                                                                  const portable_executable::unwind_info_t* unwind_info,
                                                                  block_insertion_list_t& block_instructions)
{
	std::int64_t current_stack_offset = 0;
	std::uint32_t last_instruction_index = static_cast<std::uint32_t>(entry_block->count() - 1);
	std::uint32_t current_instruction_offset = 0;
	const auto instructions = entry_block->instructions();

	for (std::uint32_t j = 0; j < instructions.size(); j++)
	{
		auto& instruction = instructions[j];

		if (unwind_info->size_of_prolog <= current_instruction_offset)
		{
			break;
		}

		auto disassembly = instruction.disassemble();
		current_instruction_offset += disassembly.size();

		if (function.basic_blocks().size() != 1)
		{
			for (auto& visible_operand : disassembly.visible_operands())
			{
				if (!visible_operand.is_mem())
				{
					continue;
				}

				auto mem = visible_operand.mem();
				const auto base_family = mem.base.family();

				if (base_family == binwrite::register_family_t::sp && current_stack_offset <= mem.displacement)
				{
					mem.displacement += 16;
					visible_operand.set_mem(mem);

					const auto reassembled = make_assembler_instruction(disassembly);
					const auto compiled = reassembled->compile();

					reassemble_displacement_instruction(pe, entry_block, j, instruction, *compiled, block_instructions);
				}
			}
		}

		if (disassembly.writes_stack_pointer())
		{
			if (disassembly.mnemonic() == binwrite::mnemonic_t::push)
			{
				last_instruction_index = j;
				current_stack_offset += 8;
			}

			if (disassembly.is_sub())
			{
				last_instruction_index = j;

				const auto source = disassembly.visible_operands()[1];

				const auto imm = source.imm();
				current_stack_offset += imm.is_signed
					? static_cast<std::int32_t>(imm.value.s)
					: static_cast<std::uint32_t>(imm.value.u);
			}
		}
	}

	return { current_stack_offset, last_instruction_index };
}

struct frame_pointer_setup_t
{
	binwrite::instruction_t push_instruction;
	binwrite::instruction_t lea_instruction;
	binwrite::instruction_t pop_instruction;
	portable_executable::unwind_code_t push_code;
	portable_executable::unwind_code_t frame_pointer_code;
	binwrite::instruction_t::size_type added_size;
};

static frame_pointer_setup_t build_frame_pointer_setup(const binwrite::register_t frame_register,
                                                       const portable_executable::unwind_register_t unwind_register,
                                                       const portable_executable::unwind_info_t* unwind_info)
{
	constexpr std::int64_t frame_offset = 0;
	const auto stack_operand = stack_mem_operand(frame_offset * 16, 8);

	const auto push = push_instr(frame_register);
	const auto lea = lea_instr(stack_operand, frame_register);
	const auto pop = pop_instr(frame_register);

	const auto added_size = static_cast<binwrite::instruction_t::size_type>(2 * (lea->size() + push->size()));

	const portable_executable::unwind_code_t push_code(
		push->size(), portable_executable::unwind_opcode_t::push_non_volatile,
		static_cast<std::uint8_t>(unwind_register));

	const portable_executable::unwind_code_t frame_pointer_code(
		unwind_info->size_of_prolog + added_size + lea->size(),
		portable_executable::unwind_opcode_t::set_frame_register,
		static_cast<std::uint8_t>(unwind_register));

	return { *push, *lea, *pop, push_code, frame_pointer_code, added_size };
}

static void apply_frame_pointer_unwind_info(binwrite::portable_executable_t& pe, portable_executable::unwind_info_t* unwind_info,
	const std::vector<std::uint8_t>& buffer,
	const portable_executable::unwind_code_t& push_code,
	const portable_executable::unwind_code_t& frame_pointer_code,
	const portable_executable::unwind_register_t unwind_register,
	const binwrite::instruction_t::size_type added_size,
	std::vector<std::uint8_t>& copied_unwind_info,
	const std::shared_ptr<binwrite::rva_t>& directory_rva,
	const std::uint32_t count,
	const portable_executable::runtime_function_t* runtime_function,
	std::vector<std::pair<std::shared_ptr<binwrite::rva_t>, std::vector<std::uint8_t>>>& unwind_code_insertions,
	std::vector<std::pair<std::shared_ptr<binwrite::symbol_ref_t>, std::vector<std::uint8_t>>>& unwind_info_insertions)
{
	std::uint8_t& unwind_code_count = unwind_info->unwind_code_count;

	const auto codes_end = reinterpret_cast<std::uint8_t*>(&unwind_info->codes[unwind_code_count]);
	const auto codes_start = reinterpret_cast<std::uint8_t*>(&unwind_info->codes[0]);
	const binwrite::rva_t codes_end_rva(static_cast<binwrite::rva_t::value_type>(codes_end - buffer.data()));
	const binwrite::rva_t codes_start_rva(static_cast<binwrite::rva_t::value_type>(codes_start - buffer.data()));

	const auto push_bytes = binwrite::util::serialize_bytes(push_code);
	const auto frame_pointer_bytes = binwrite::util::serialize_bytes(frame_pointer_code);

	unwind_code_count += 4;
	constexpr std::uint8_t frame_offset = 0;
	unwind_info->frame_offset = frame_offset;
	unwind_info->frame_register = unwind_register;
	unwind_info->size_of_prolog += added_size;

	std::vector<std::uint8_t> start_bytes;
	std::vector<std::uint8_t> end_bytes;

	start_bytes.insert(start_bytes.end(), frame_pointer_bytes.begin(), frame_pointer_bytes.end());
	start_bytes.insert(start_bytes.end(), frame_pointer_bytes.begin(), frame_pointer_bytes.end());

	end_bytes.insert(end_bytes.end(), push_bytes.begin(), push_bytes.end());
	end_bytes.insert(end_bytes.end(), push_bytes.begin(), push_bytes.end());

	if (!copied_unwind_info.empty())
	{
		auto updated_runtime_function = reinterpret_cast<const portable_executable::runtime_function_t*>(
			pe.data() + directory_rva->value());

		for (std::uint32_t j = 0; j < count; j++, updated_runtime_function++)
		{
			if (updated_runtime_function->begin_address != runtime_function->begin_address ||
				updated_runtime_function->end_address != runtime_function->end_address)
			{
				continue;
			}

			const auto ref_rva = static_cast<binwrite::rva_t::value_type>(
				reinterpret_cast<const std::uint8_t*>(&updated_runtime_function->unwind_info_rva) - pe.data());
			const auto unwind_info_ref = pe.find_data_symbol_ref_at(binwrite::rva_t{ ref_rva });

			if (!unwind_info_ref)
			{
				continue;
			}

			const std::uint32_t codes_end_offset = static_cast<std::uint32_t>(codes_end - reinterpret_cast<const std::uint8_t*>(unwind_info));
			const std::uint32_t codes_start_offset = static_cast<std::uint32_t>(codes_start - reinterpret_cast<const std::uint8_t*>(unwind_info));

			copied_unwind_info.insert(copied_unwind_info.begin() + codes_end_offset, end_bytes.begin(), end_bytes.end());
			copied_unwind_info.insert(copied_unwind_info.begin() + codes_start_offset, start_bytes.begin(), start_bytes.end());

			unwind_info_insertions.emplace_back(unwind_info_ref, copied_unwind_info);
			break;
		}
	}
	else
	{
		unwind_code_insertions.emplace_back(pe.add_rva(codes_end_rva), end_bytes);
		unwind_code_insertions.emplace_back(pe.add_rva(codes_start_rva), start_bytes);

		const binwrite::rva_t info_start_rva(static_cast<binwrite::rva_t::value_type>(
			reinterpret_cast<const std::uint8_t*>(unwind_info) - buffer.data()));
		const auto containing_symbol = pe.find_containing_symbol(info_start_rva);

		if (const auto data_block = std::dynamic_pointer_cast<binwrite::data_block_t>(containing_symbol))
		{
			constexpr auto header_size = sizeof(portable_executable::unwind_info_t) - sizeof(portable_executable::unwind_code_t);
			const auto offset = info_start_rva.value() - data_block->rva()->value();
			const auto src = reinterpret_cast<const std::uint8_t*>(unwind_info);

			std::copy(src, src + header_size, data_block->bytes().begin() + offset);
		}
	}
}

void binwrite::rewrite_frame_pointers(portable_executable_t& pe, exception_context_t& context)
{
	auto buffer = pe.buffer();
	auto* image = reinterpret_cast<portable_executable::image_t*>(buffer.data());

	std::unordered_map<rva_t::value_type, std::shared_ptr<function_t>> function_map;

	for (const auto& function : pe.functions())
	{
		function_map[function->rva()->value()] = function;
	}

	block_insertion_list_t block_instructions;
	std::vector<std::pair<std::shared_ptr<rva_t>, std::vector<std::uint8_t>>> unwind_code_insertions;
	std::vector<std::pair<std::shared_ptr<symbol_ref_t>, std::vector<std::uint8_t>>> unwind_info_insertions;

	const auto data_directory = image->nt_headers()->optional_header.data_directories.exception_directory;

	if (!data_directory.present())
	{
		return;
	}

	const auto directory_rva = pe.add_rva(data_directory.virtual_address);
	const std::uint32_t count = data_directory.size / sizeof(portable_executable::runtime_function_t);
	auto runtime_function = reinterpret_cast<const portable_executable::runtime_function_t*>(
		buffer.data() + data_directory.virtual_address);

	std::vector<rva_t> processed_catch_functions;

	for (std::uint32_t f = 0; f < count; f++, runtime_function++)
	{
		const auto function = function_map[runtime_function->begin_address];

		if (!function)
		{
			continue;
		}

		std::vector<std::uint8_t> copied_unwind_info;
		auto* original_unwind_info = find_shared_unwind_refs(
			pe, runtime_function, directory_rva, count, buffer, context, copied_unwind_info);

		const auto entry_block = function->entry_block();

		std::unordered_set<rva_t::value_type> visited;
		assign_runtime_function_basic_block(pe, function, entry_block,
			rva_t{ runtime_function->begin_address }, rva_t{ runtime_function->end_address }, visited);

		auto* unwind_info = copied_unwind_info.empty() ? original_unwind_info :
			reinterpret_cast<portable_executable::unwind_info_t*>(copied_unwind_info.data());

		if (unwind_info->has_frame_pointer())
		{
			continue;
		}

		const register_t frame_register = register_family_t::bp.qword;
		const auto unwind_register = get_unwind_register(frame_register);

		if (scan_function_for_rewrite_conflicts(*function, entry_block, original_unwind_info, register_family_t::bp,
		                                        runtime_function, pe))
		{
			function->set_basic_blocks_skip(true);

			continue;
		}

		if (has_unwind_register_conflict(unwind_info, unwind_register))
		{
			function->set_basic_blocks_skip(true);

			continue;
		}

		auto [current_stack_offset, last_instruction_index] =
			adjust_prologue_displacements(pe, *function, entry_block, unwind_info, block_instructions);

		const auto setup = build_frame_pointer_setup(frame_register, unwind_register, unwind_info);

		const auto unwind_codes = unwind_info->unwind_codes();

		for (std::uint32_t y = 0; y < unwind_codes.size();)
		{
			unwind_codes[y].offset += setup.added_size;
			y += unwind_codes[y].node_count();
		}

		assign_handler_blocks_to_function(pe, function, context.func_handlers[runtime_function->begin_address]);

		block_instructions.emplace_back(entry_block, setup.lea_instruction, last_instruction_index + 1);
		block_instructions.emplace_back(entry_block, setup.lea_instruction, last_instruction_index + 1);
		block_instructions.emplace_back(entry_block, setup.push_instruction, 0);
		block_instructions.emplace_back(entry_block, setup.push_instruction, 0);

		std::vector<register_family_t> frame_families = { };

		collect_extra_stack_pointer_families(entry_block, frame_families, register_family_t::sp);

		for (const auto& basic_block : function->basic_blocks())
		{
			if (function->basic_blocks().size() != 1 && basic_block == entry_block)
			{
				adjust_displacements_in_block(pe, basic_block, current_stack_offset, block_instructions,
					register_family_t::none, true, frame_families);

				continue;
			}

			adjust_displacements_in_block(pe, basic_block, current_stack_offset, block_instructions,
				register_family_t::sp, true, frame_families);
		}

		adjust_catch_handler_displacements(pe, context.catch_handlers[runtime_function->begin_address],
			current_stack_offset, block_instructions, processed_catch_functions);

		insert_exit_block_pops(function, pe, block_instructions, setup.pop_instruction);

		apply_frame_pointer_unwind_info(pe, unwind_info, buffer, setup.push_code, setup.frame_pointer_code,
			unwind_register, setup.added_size, copied_unwind_info,
			directory_rva, count, runtime_function, unwind_code_insertions, unwind_info_insertions);
	}

	apply_deferred_insertions(pe, unwind_info_insertions, unwind_code_insertions, block_instructions);
}
