#include <binwrite/binary/pe/pe.hpp>
#include <binwrite/binary/pe/pe_exceptions.hpp>
#include <binwrite/binary/pe/pe_rtti.hpp>
#include <binwrite/binary/symbols/map_parsing.hpp>
#include <binwrite/binary/symbols/pdb_parsing.hpp>

#include <spdlog/spdlog.h>

#include <cstdint>
#include <fstream>
#include <ranges>
#include <string>
#include <vector>

#include "config/config.hpp"
//#include "virtual_machine/virtual_machine.hpp"
//#include "virtual_machine/vm_context.hpp"
//#include "control_flow/control_flow_flattening.hpp"
//#include "linear_substitution/linear_substitution.hpp"
//#include "opaque_predicate/opaque_predicate.hpp"
//#include "mba/mba.hpp"

static std::vector<std::uint8_t> read_file_from_disk(const std::string& path)
{
	std::ifstream file(path, std::ios::binary);

	if (file.is_open())
	{
		return { std::istreambuf_iterator(file), { } };
	}

	return { };
}

static void write_file_to_disk(const std::string& path, const std::vector<std::uint8_t>& buffer)
{
	std::ofstream file(path, std::ios::binary);

	if (file.is_open())
	{
		file.write(reinterpret_cast<const char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
	}
}

/*static void mutate_basic_block(const binprotect::config::obfuscation_t& config,
                               binwrite::binary_t& binary, binwrite::basic_block_t& basic_block,
                               const binwrite::exception_context_t& exceptions = {})
{
	const auto should_skip_memory_operands = [&exceptions]([[maybe_unused]] const binwrite::disassembled_instruction_t& instruction,
	                                        const binwrite::rva_t rva) -> bool
		{
			return exceptions.is_in_seh_range(rva.value());
		};

	if (config.linear_substitution)
	{
		binprotect::linear_substitution::do_pass(binary, basic_block, should_skip_memory_operands);
	}

	bool is_first_pass = true;

	for (std::uint32_t j = 0; j < config.mixed_boolean_arithmetic_count; j++)
	{
		binprotect::mba::do_pass(binary, basic_block, is_first_pass, should_skip_memory_operands);

		is_first_pass = false;
	}
}

static void run_obfuscation_loop(
	binwrite::binary_t& binary,
	const binwrite::exception_context_t& context,
	const binprotect::config::obfuscation_t& config,
	const std::shared_ptr<binwrite::rva_t>& vm_insertion_rva,
	std::vector<std::shared_ptr<binwrite::basic_block_t>>& virtual_machine_blocks,
	std::vector<std::shared_ptr<vm_context_t>>& vm_contexts,
	std::vector<std::shared_ptr<binwrite::basic_block_t>>& opaque_blocks)
{
	const auto original_basic_blocks = binary.basic_blocks();
	const std::vector basic_blocks(original_basic_blocks.begin(), original_basic_blocks.end());

	for (const auto& basic_block : basic_blocks)
	{
		bool virtualized = false;

		if (basic_block->should_skip())
		{
			continue;
		}

		const auto basic_block_rva = basic_block->rva();
		const auto block_rva_value = basic_block_rva->value();

		if (config.virtual_machine && !context.is_in_seh_range(block_rva_value))
		{
			if (const auto vm_context = binprotect::vm::do_pass(binary, *basic_block, vm_insertion_rva, virtual_machine_blocks))
			{
				vm_contexts.push_back(vm_context);
				virtualized = !vm_context->basic_blocks().empty();
			}
		}

		if (config.opaque_predicates && !context.is_in_fh_range(block_rva_value))
		{
			binprotect::opaque_predicate::do_pass(binary, *basic_block, opaque_blocks);
		}

		if (!virtualized)
		{
			mutate_basic_block(config, binary, *basic_block, context);
		}

		basic_block->clear_disassembly();
	}
}

static std::vector<std::shared_ptr<vm_context_t>> obfuscate_binary_blocks(
	binwrite::binary_t& binary, const binprotect::config::obfuscation_t& config,
	const binwrite::exception_context_t& exceptions_context = {})
{
	const auto code_section = binary.code_section();

	std::vector<std::shared_ptr<binwrite::basic_block_t>> virtual_machine_blocks;
	std::vector<std::shared_ptr<vm_context_t>> vm_contexts;
	std::vector<std::shared_ptr<binwrite::basic_block_t>> opaque_blocks;
	const auto vm_insertion_rva = binary.add_rva(code_section->rva().value() + code_section->size());

	run_obfuscation_loop(binary, exceptions_context, config, vm_insertion_rva,
		virtual_machine_blocks, vm_contexts, opaque_blocks);

	for (const auto& basic_block : opaque_blocks)
	{
		if (basic_block->should_skip())
		{
			continue;
		}

		mutate_basic_block(config, binary, *basic_block);

		basic_block->clear_disassembly();
	}

	return vm_contexts;
}

static void obfuscate_exceptions_pe_binary(binwrite::portable_executable_t& pe, const binprotect::config::obfuscation_t& config)
{
	auto exceptions_context = binwrite::parse_exception_directory(pe);

	pe.disassemble();

	binwrite::split_prologues(pe, exceptions_context);
	binwrite::rewrite_frame_pointers(pe, exceptions_context);

	if (config.control_flow_flattening)
	{
		const auto is_block_fixed = [&exceptions_context](const binwrite::rva_t::value_type rva) -> bool
			{
				return exceptions_context.is_in_seh_range(rva);
			};

		for (const auto& function : pe.functions())
		{
			const auto function_rva = function->rva()->value();

			if (exceptions_context.is_fh_function(function_rva) || exceptions_context.is_handler_function(function_rva))
			{
				continue;
			}

			binprotect::control_flow::flattening::do_pass(pe, *function, is_block_fixed);
		}
	}

	const auto vm_contexts = obfuscate_binary_blocks(pe, config, exceptions_context);

	binprotect::vm::emit_runtime_functions(pe, vm_contexts, exceptions_context.exception_directory_rva,
	                                       exceptions_context.unwind_info_insertion_rva);
}

static void obfuscate_non_exceptions_binary(binwrite::binary_t& binary, const binprotect::config::obfuscation_t& config)
{
	binary.disassemble();

	if (config.control_flow_flattening)
	{
		for (const auto& function : binary.functions())
		{
			binprotect::control_flow::flattening::do_pass(binary, *function);
		}
	}

	obfuscate_binary_blocks(binary, config);
}

static void realign_unwind_info(binwrite::portable_executable_t& pe)
{
	const auto image = pe.image();

	std::vector<std::shared_ptr<binwrite::rva_t>> unwind_info_rvas;

	for (const auto rf : image->runtime_functions())
	{
		const auto unwind_info_rva = static_cast<std::uint32_t>(reinterpret_cast<const std::uint8_t*>(rf.unwind_info) - image->as<const std::uint8_t*>());

		unwind_info_rvas.push_back(pe.add_rva(unwind_info_rva));
	}

	std::ranges::sort(unwind_info_rvas, [](const auto& a, const auto& b) { return a->value() < b->value(); });

	for (const auto& rva : unwind_info_rvas)
	{
		constexpr std::uint32_t alignment = sizeof(std::uint32_t);

		if (const auto padding_size = (alignment - rva->value() % alignment) % alignment)
		{
			pe.insert(*rva, static_cast<binwrite::rva_t::size_type>(padding_size), true);
		}
	}
}*/

static void write_output_binary(const binwrite::binary_t& binary, const std::string& config_output_path)
{
	const std::string& output_path = config_output_path.empty() ? "output.exe" : config_output_path;

	write_file_to_disk(output_path, binary.buffer());

	spdlog::info("wrote output binary at '{}'", output_path);
}

std::int32_t main(const std::int32_t argc, const char** const argv)
{
	const auto config = binprotect::config::parse(argc, argv);

	if (!config)
	{
		spdlog::error("unable to parse config arguments");

		return 0;
	}

	std::vector<std::uint8_t> buffer = read_file_from_disk(config->input_binary_file_path);

	if (buffer.empty())
	{
		spdlog::error("unable to read input file '{}'", config->input_binary_file_path);

		return 0;
	}

	binwrite::portable_executable_t pe(std::move(buffer));

	pe.decompress();
	pe.parse();

	bool exceptions_support = pe.has_exceptions_directory();

	if (config->symbol_file_path.empty() || (!binwrite::symbols::pdb::parse(pe, config->symbol_file_path) &&
		!binwrite::symbols::map::parse(pe, config->symbol_file_path)))
	{
		spdlog::warn("unable to find or parse symbol file '{}'", config->symbol_file_path);

		exceptions_support = false;
	}

	binwrite::exception_context_t exceptions_context;

	if (exceptions_support)
	{
		exceptions_context = binwrite::parse_exception_directory(pe);
	}

	binwrite::queue_throw_info_code_targets(pe);

	pe.disassemble();

	const auto rtti_result = binwrite::parse_rtti(pe);
	binwrite::parse_throw_info(pe, rtti_result);

	if (exceptions_support)
	{
		//binwrite::split_prologues(pe, exceptions_context);
		//binwrite::rewrite_frame_pointers(pe, exceptions_context);
	}

	pe.clear_symbol_rvas();

	pe.recompile();

	write_output_binary(pe, config->output_binary_file_path);

	return 0;
}
