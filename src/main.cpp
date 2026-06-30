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
#include "linear_substitution/linear_substitution.hpp"
#include "mba/mba.hpp"

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

	if (exceptions_support)
	{
		auto exceptions_context = binwrite::parse_exception_directory(pe);
	}

	binwrite::queue_throw_info_code_targets(pe);

	pe.disassemble();

	const auto rtti_result = binwrite::parse_rtti(pe);
	binwrite::parse_throw_info(pe, rtti_result);

	for (const auto& basic_block : pe.basic_blocks())
	{
		if (basic_block->should_skip())
		{
			continue;
		}

		if (config->linear_substitution)
		{
			binprotect::linear_substitution::do_pass(pe, *basic_block);
		}

		for (std::uint8_t pass = 0; pass < config->mixed_boolean_arithmetic_count; pass++)
		{
			binprotect::mba::do_pass(pe, *basic_block, true);
		}
	}

	spdlog::info("applied linear substitution: {}, mba passes: {}",
		config->linear_substitution ? "yes" : "no", config->mixed_boolean_arithmetic_count);

	pe.clear_symbol_rvas();
	pe.recompile();



	write_output_binary(pe, config->output_binary_file_path);


	return 0;
}
