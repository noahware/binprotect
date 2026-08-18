#include "pe.hpp"
#include "../rva/rva.hpp"
#include "../../block/data_block.hpp"

#include <portable-executable/image.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <unordered_map>
#include <vector>

using namespace binwrite;

static constexpr symbol_t::size_type runtime_function_field_size = sizeof(std::uint32_t);
static constexpr symbol_t::size_type runtime_function_size = sizeof(portable_executable::runtime_function_t);

static std::vector<std::uint8_t> compile_unwind_info(const runtime_function_params_t& params)
{
	const auto unwind_code_count = static_cast<std::uint8_t>(params.unwind_codes.size());
	const std::uint32_t aligned_code_count = (unwind_code_count + 1) & ~1;
	const std::uint32_t unwind_info_size = offsetof(portable_executable::unwind_info_t, codes)
		+ aligned_code_count * sizeof(portable_executable::unwind_code_t);

	std::vector<std::uint8_t> unwind_info_bytes(unwind_info_size, 0);
	auto* unwind_info = reinterpret_cast<portable_executable::unwind_info_t*>(unwind_info_bytes.data());

	unwind_info->version = 1;
	unwind_info->flags = params.flags;
	unwind_info->size_of_prolog = params.prolog_size;
	unwind_info->unwind_code_count = unwind_code_count;
	unwind_info->frame_register = params.frame_register;
	unwind_info->frame_offset = params.frame_offset;

	for (std::uint8_t i = 0; i < unwind_code_count; i++)
	{
		unwind_info->codes[i] = params.unwind_codes[i];
	}

	return unwind_info_bytes;
}

// the headers are emitted from their own symbol, so header fields have to be edited inside of it
static std::uint8_t* find_header_field(binary_t& binary, const rva_t field_rva)
{
	const auto block = std::dynamic_pointer_cast<data_block_t>(binary.find_containing_symbol(field_rva));

	if (!block || !block->rva())
	{
		return nullptr;
	}

	const auto offset = field_rva.value() - block->rva()->value();

	if (block->bytes().size() < offset + sizeof(std::uint32_t))
	{
		return nullptr;
	}

	return block->bytes().data() + offset;
}

void binwrite::portable_executable_t::add_runtime_function(const runtime_function_params_t& params)
{
	if (!params.begin_symbol || !params.end_symbol)
	{
		spdlog::error("unable to add runtime function without a begin and end symbol");

		return;
	}

	const auto& directory = image()->nt_headers()->optional_header.data_directories.exception_directory;

	const rva_t directory_rva_field{ static_cast<rva_t::value_type>(
		reinterpret_cast<const std::uint8_t*>(&directory.virtual_address) - data()) };
	const rva_t directory_size_field{ static_cast<rva_t::value_type>(
		reinterpret_cast<const std::uint8_t*>(&directory.size) - data()) };

	// the directory's header field references the start of the runtime function table
	const auto directory_ref = find_data_symbol_ref_at(directory_rva_field);
	const auto table_start = directory_ref ? directory_ref->target() : nullptr;
	const auto table_section = table_start ? table_start->section() : nullptr;

	auto* const table_size_field = find_header_field(*this, directory_size_field);

	if (!table_section || !table_size_field)
	{
		spdlog::error("unable to find exception directory symbols");

		return;
	}

	std::uint32_t table_size = 0;
	std::memcpy(&table_size, table_size_field, sizeof(table_size));

	const auto unwind_section = data_section();

	if (!unwind_section)
	{
		spdlog::error("unable to find a data section for unwind info");

		return;
	}

	const auto unwind_info = create_data_block(*unwind_section, compile_unwind_info(params));
	unwind_info->set_required_alignment(4);

	constexpr std::array<std::uint8_t, runtime_function_field_size> empty_field = { };

	const std::array entry_fields = {
		create_data_block(*table_section, empty_field),
		create_data_block(*table_section, empty_field),
		create_data_block(*table_section, empty_field)
	};

	// the table is kept sorted by finalize_exception_directory, so appending at the end is enough here
	const auto& section_symbols = table_section->symbols();

	if (!section_symbols.empty())
	{
		auto anchor = section_symbols.back();

		for (const auto& field : entry_fields)
		{
			if (field == anchor)
			{
				continue;
			}

			field->move_after(anchor);
			anchor = field;
		}
	}

	add_symbol_ref(std::make_shared<data_symbol_ref_t>(params.begin_symbol, entry_fields[0], runtime_function_field_size));

	auto end_ref = std::make_shared<data_symbol_ref_t>(params.end_symbol, entry_fields[1], runtime_function_field_size);
	end_ref->set_anchor(data_symbol_ref_t::anchor_t::at_end);
	add_symbol_ref(end_ref);

	add_symbol_ref(std::make_shared<data_symbol_ref_t>(unwind_info, entry_fields[2], runtime_function_field_size));

	table_size += runtime_function_size;
	std::memcpy(table_size_field, &table_size, sizeof(table_size));
}

// note: currently never gets past the lookup below. main.cpp calls clear_symbol_rvas() before
// recompile(), and find_data_symbol_ref_at matches on symbol rvas, so table_start is always null
// here and the function returns immediately. running it after recompile()'s first layout pass does
// find the table, but then the field walk below collects whole data blocks rather than 4 byte
// fields (it only holds once add_runtime_function has split them), overshooting table_size. sorting
// the runtime function table therefore needs that walk fixed, not just a reordered call
void binwrite::portable_executable_t::finalize_exception_directory()
{
	const auto& directory = image()->nt_headers()->optional_header.data_directories.exception_directory;

	const rva_t directory_rva_field{ static_cast<rva_t::value_type>(
		reinterpret_cast<const std::uint8_t*>(&directory.virtual_address) - data()) };
	const rva_t directory_size_field{ static_cast<rva_t::value_type>(
		reinterpret_cast<const std::uint8_t*>(&directory.size) - data()) };

	const auto directory_ref = find_data_symbol_ref_at(directory_rva_field);
	const auto table_start = directory_ref ? directory_ref->target() : nullptr;
	const auto table_section = table_start ? table_start->section() : nullptr;

	auto* const table_size_field = find_header_field(*this, directory_size_field);

	if (!table_section || !table_size_field)
	{
		return;
	}

	std::uint32_t table_size = 0;
	std::memcpy(&table_size, table_size_field, sizeof(table_size));

	if (table_size < runtime_function_size)
	{
		return;
	}

	// map each field symbol to whatever it points at, so an entry's begin address can be looked up per field
	std::unordered_map<const symbol_t*, std::shared_ptr<symbol_t>> field_targets;
	field_targets.reserve(symbol_refs_.size());

	for (const auto& ref : symbol_refs_)
	{
		const auto data_ref = std::dynamic_pointer_cast<data_symbol_ref_t>(ref);

		if (!data_ref)
		{
			continue;
		}

		if (const auto self = ref->self())
		{
			field_targets.emplace(self.get(), ref->target());
		}
	}

	std::vector<std::shared_ptr<symbol_t>> field_symbols;
	field_symbols.reserve(table_size / runtime_function_field_size);

	std::uint32_t covered_bytes = 0;

	for (auto it = table_start->list_iterator(); it != table_section->symbols().end() && covered_bytes < table_size; ++it)
	{
		field_symbols.push_back(*it);
		covered_bytes += (*it)->size();
	}

	if (field_symbols.size() % 3 != 0)
	{
		spdlog::warn("exception directory finalize: field count {} is not a multiple of 3", field_symbols.size());

		return;
	}

	struct entry_triple_t
	{
		std::array<std::shared_ptr<symbol_t>, 3> fields;
		rva_t::value_type sort_key;
	};

	std::vector<entry_triple_t> triples;
	triples.reserve(field_symbols.size() / 3);

	for (std::size_t i = 0; i + 2 < field_symbols.size(); i += 3)
	{
		entry_triple_t triple;

		triple.fields = { field_symbols[i], field_symbols[i + 1], field_symbols[i + 2] };
		triple.sort_key = 0;

		const auto begin_it = field_targets.find(field_symbols[i].get());

		if (begin_it != field_targets.end() && begin_it->second)
		{
			if (const auto begin_rva = begin_it->second->rva())
			{
				triple.sort_key = begin_rva->value();
			}
		}

		triples.push_back(std::move(triple));
	}

	std::ranges::stable_sort(triples, [](const entry_triple_t& a, const entry_triple_t& b)
	{
		return a.sort_key < b.sort_key;
	});

	auto anchor = field_symbols.front();

	if (anchor != triples.front().fields[0])
	{
		triples.front().fields[0]->move_before(anchor);
		anchor = triples.front().fields[0];
	}

	for (std::size_t t = 0; t < triples.size(); t++)
	{
		for (std::size_t f = (t == 0 ? 1 : 0); f < 3; f++)
		{
			const auto& field = triples[t].fields[f];

			if (field == anchor)
			{
				continue;
			}

			field->move_after(anchor);
			anchor = field;
		}
	}
}

void binwrite::portable_executable_t::finalize_before_recompile()
{
	finalize_exception_directory();
}
