#include "binary.hpp"
#include "../disassembler/disassembler.hpp"
#include "../../portable-executable/image.hpp"

#include <spdlog/spdlog.h>
#include <algorithm>
#include <ranges>
#include <unordered_map>
#include <unordered_set>

#include "../../../src/assembler/assembler.hpp"

void binwrite::binary_t::parse()
{
	find_sections();
	find_data_rvas();
}

void binwrite::binary_t::insert(const rva_t rva, const std::span<const std::uint8_t> data, const bool inclusive)
{
	buffer_.insert(buffer_.begin() + rva.value(), data.begin(), data.end());

	update_rvas(rva, static_cast<rva_t::size_type>(data.size()), inclusive);
}

void binwrite::binary_t::insert(const rva_t rva, const rva_t::size_type size, const bool inclusive)
{
	buffer_.insert(buffer_.begin() + rva.value(), size, 0);

	update_rvas(rva, size, inclusive);
}

void binwrite::binary_t::erase(const rva_t rva, const rva_t::size_type size, const bool inclusive)
{
	const auto start = buffer_.begin() + rva.value();

	buffer_.erase(start, start + size);

	update_rvas(rva, -size, inclusive);
}

std::span<std::shared_ptr<binwrite::function_t>> binwrite::binary_t::functions()
{
	return functions_;
}

std::span<const std::shared_ptr<binwrite::function_t>> binwrite::binary_t::functions() const
{
	return functions_;
}

std::shared_ptr<binwrite::function_t> binwrite::binary_t::find_function(const rva_t rva) const
{
	if (fn_index_dirty_)
	{
		reindex_functions();
	}

	const auto it = fn_index_.find(rva.value());

	if (it == fn_index_.end())
	{
		return { };
	}

	return it->second;
}

void binwrite::binary_t::add_function(const std::shared_ptr<function_t>& function)
{
	const auto rva = *function->rva();

	if (find_function(rva))
	{
		return;
	}

	functions_.push_back(function);
	fn_index_[rva.value()] = function;
}

void binwrite::binary_t::remove_function(const std::shared_ptr<function_t>& function)
{
	std::erase(functions_, function);
}

std::shared_ptr<binwrite::data_block_t> binwrite::binary_t::create_data_block(
	section_t& section, const std::span<const std::uint8_t> bytes, const std::optional<rva_t> rva)
{
	const auto data_block = std::make_shared<data_block_t>(bytes);

	data_block->set_rva(rva);

	section.add_symbol(data_block);
	symbols_.push_back(data_block);

	if (rva)
	{
		disassembly_symbol_map_[rva->value()] = data_block;
	}

	return data_block;
}

std::shared_ptr<binwrite::basic_block_t> binwrite::binary_t::create_basic_block(
	section_t& section, const std::span<const instruction_t> instructions, const std::optional<rva_t> rva)
{
	const auto basic_block = std::make_shared<basic_block_t>(instructions);

	for (auto& instruction : basic_block->instructions())
	{
		assign_instruction_id_if_needed(instruction);
	}

	basic_block->set_rva(rva);

	if (rva)
	{
		basic_block->set_block_rva(add_rva(*rva));
	}

	section.add_symbol(basic_block);
	symbols_.push_back(basic_block);
	basic_blocks_.push_back(basic_block);

	if (rva)
	{
		bb_index_[rva->value()] = basic_block;
		bb_interval_index_[rva->value()] = basic_block;
		disassembly_symbol_map_[rva->value()] = basic_block;
	}

	return basic_block;
}

std::shared_ptr<binwrite::basic_block_t> binwrite::binary_t::create_basic_block(
	const std::span<const instruction_t> instructions)
{
	return create_basic_block(*code_section(), instructions);
}

std::shared_ptr<binwrite::basic_block_t> binwrite::binary_t::create_basic_block_after(
	const std::shared_ptr<basic_block_t>& after_block, const std::span<const instruction_t> instructions)
{
	const auto basic_block = create_basic_block(instructions);

	basic_block->move_after(after_block);

	return basic_block;
}

std::shared_ptr<binwrite::basic_block_t> binwrite::binary_t::create_basic_block_before(
	const std::shared_ptr<basic_block_t>& before_block, const std::span<const instruction_t> instructions)
{
	const auto basic_block = create_basic_block(instructions);

	basic_block->move_before(before_block);

	return basic_block;
}

std::shared_ptr<binwrite::function_t> binwrite::binary_t::create_function(const std::string& name, const rva_t rva)
{
	if (const auto existing_function = find_function(rva))
	{
		return existing_function;
	}

	const auto added_rva = add_rva(rva);
	const auto function = std::make_shared<function_t>(name, added_rva);

	functions_.push_back(function);
	fn_index_[rva.value()] = function;

	add_to_disassembly_queue(added_rva);

	return function;
}

std::shared_ptr<binwrite::function_t> binwrite::binary_t::create_function(const rva_t rva)
{
	const std::string name = std::format("sub_{:X}", rva.value());

	return create_function(name, rva);
}

void binwrite::binary_t::unlink_basic_block(std::shared_ptr<basic_block_t> basic_block)
{
	if (!std::erase(basic_blocks_, basic_block))
	{
		return;
	}

	for (const auto& function : functions_)
	{
		function->unlink_basic_block(basic_block);
	}

	if (const auto rva = basic_block->rva())
	{
		bb_index_.erase(rva->value());
		bb_interval_index_.erase(rva->value());
	}
}

void binwrite::binary_t::reanchor_split_refs(const std::shared_ptr<basic_block_t>& original,
                                             const std::shared_ptr<basic_block_t>& split_off)
{
	if (!original || !split_off)
	{
		return;
	}

	const auto moved = [&split_off](const instruction_t::id_type id)
	{
		return id != 0 && split_off->instruction_index_by_id(id) != basic_block_t::invalid_index;
	};

	for (const auto& symbol_ref : symbol_refs_)
	{
		if (const auto code_ref = std::dynamic_pointer_cast<code_symbol_ref_t>(symbol_ref);
			code_ref && code_ref->self() == original && moved(code_ref->self_instr_id()))
		{
			code_ref->set_self(split_off);

			continue;
		}

		// the end of the original block is now the end of the block split off of it
		if (const auto data_ref = std::dynamic_pointer_cast<data_symbol_ref_t>(symbol_ref);
			data_ref && data_ref->anchor() == data_symbol_ref_t::anchor_t::at_end
			&& data_ref->target() == original)
		{
			data_ref->set_target(split_off);
		}
	}
}

std::span<std::shared_ptr<binwrite::basic_block_t>> binwrite::binary_t::basic_blocks()
{
	return basic_blocks_;
}

std::span<const std::shared_ptr<binwrite::basic_block_t>> binwrite::binary_t::basic_blocks() const
{
	return basic_blocks_;
}

std::shared_ptr<binwrite::basic_block_t> binwrite::binary_t::find_basic_block(const rva_t rva) const
{
	if (bb_index_dirty_)
	{
		reindex_basic_blocks();
	}

	const auto it = bb_index_.find(rva.value());

	if (it == bb_index_.end())
	{
		return { };
	}

	return it->second;
}

std::shared_ptr<binwrite::basic_block_t> binwrite::binary_t::find_containing_basic_block(const rva_t rva) const
{
	if (bb_index_dirty_)
	{
		reindex_basic_blocks();
	}

	// upper_bound gives first block with start > rva, decrement to get candidate whose start <= rva
	const auto it = bb_interval_index_.upper_bound(rva.value());

	if (it == bb_interval_index_.begin())
	{
		return { };
	}

	const auto& candidate = std::prev(it)->second;

	if (candidate->contains(rva))
	{
		return candidate;
	}

	return { };
}

bool binwrite::binary_t::is_inside_basic_block(const rva_t rva) const
{
	return find_containing_basic_block(rva) != nullptr;
}

std::span<const std::shared_ptr<binwrite::rva_t>> binwrite::binary_t::jump_table_targets(const rva_t dispatcher_rva) const
{
	const auto it = jump_table_targets_.find(dispatcher_rva.value());

	if (it == jump_table_targets_.end())
	{
		return { };
	}

	return it->second;
}

std::shared_ptr<binwrite::basic_block_t> binwrite::binary_t::split_basic_block(basic_block_t& basic_block, const basic_block_t::size_type index)
{
	if (index <= 0)
	{
		return { };
	}

	const auto split_rva = basic_block.instruction_rva(index);

	const basic_block_t::size_type split_count = basic_block.count() - index;

	const auto original_block_instructions = basic_block.instructions();

	const auto start = original_block_instructions.begin() + index;
	const auto end = start + split_count;

	const std::vector new_block_instructions(start, end);
	const auto offset_rva = add_rva(split_rva);

	basic_block.erase(*this, index, split_count, false);

	auto new_basic_block = std::make_shared<basic_block_t>();

	new_basic_block->set_rva(split_rva);
	new_basic_block->set_block_rva(offset_rva);
	new_basic_block->push(*this, new_block_instructions, true);

	basic_blocks_.push_back(new_basic_block);
	symbols_.push_back(new_basic_block);

	bb_index_[split_rva.value()] = new_basic_block;
	bb_interval_index_[split_rva.value()] = new_basic_block;

	if (const auto section = find_section(split_rva))
	{
		const auto original_shared = basic_block.shared_from_this();

		section->add_symbol(new_basic_block);
		section->move_symbol_after(original_shared, new_basic_block);
	}

	for (const auto& function : functions_)
	{
		for (const auto& function_block : function->basic_blocks())
		{
			if (*function_block == basic_block)
			{
				function->add_basic_block(new_basic_block);

				break;
			}
		}
	}

	reanchor_split_refs(std::dynamic_pointer_cast<basic_block_t>(basic_block.shared_from_this()), new_basic_block);

	return new_basic_block;
}

std::vector<std::shared_ptr<binwrite::rva_t>> binwrite::binary_t::rvas()
{
	return rvas_;
}

std::vector<std::shared_ptr<binwrite::rva_ref_t>> binwrite::binary_t::rva_refs()
{
	return rva_refs_;
}

std::unordered_map<std::string, std::shared_ptr<binwrite::section_t>>& binwrite::binary_t::sections()
{
	return sections_;
}

const std::unordered_map<std::string, std::shared_ptr<binwrite::section_t>>& binwrite::binary_t::sections() const
{
	return sections_;
}

std::vector<std::shared_ptr<binwrite::section_t>> binwrite::binary_t::ordered_sections() const
{
	const auto sections_view = sections_ | std::views::values;

	std::vector ordered_sections(sections_view.begin(), sections_view.end());

	std::ranges::sort(ordered_sections,
		[](const std::shared_ptr<section_t>& left, const std::shared_ptr<section_t>& right)
		{
			return left->rva() < right->rva();
		}
	);

	return ordered_sections;
}

void binwrite::binary_t::add_data_symbol(const rva_t rva)
{
	data_symbols_.push_back(add_rva(rva));
}

bool binwrite::binary_t::is_data_symbol(const rva_t rva) const
{
	for (const auto& data_symbol : data_symbols_)
	{
		if (*data_symbol == rva)
		{
			return true;
		}
	}

	return false;
}

std::shared_ptr<binwrite::section_t> binwrite::binary_t::find_section(const std::string& name) const
{
	const auto it = sections_.find(name);

	if (name.empty() || it == sections_.end())
	{
		return { };
	}

	return it->second;
}

std::shared_ptr<binwrite::section_t> binwrite::binary_t::find_section(const rva_t rva) const
{
	for (const auto& section : sections_ | std::views::values)
	{
		if (section->contains(rva))
		{
			return section;
		}
	}

	return { };
}

std::shared_ptr<binwrite::section_t> binwrite::binary_t::code_section() const
{
	for (const auto& section : sections_ | std::views::values)
	{
		if (section->code())
		{
			return section;
		}
	}

	return { };
}

std::shared_ptr<binwrite::section_t> binwrite::binary_t::data_section() const
{
	std::shared_ptr<section_t> result;

	for (const auto& section : sections_ | std::views::values)
	{
		if (section->data() && (!result || section->rva() < result->rva()))
		{
			result = section;
		}
	}

	return result;
}

bool binwrite::binary_t::is_in_code_section(const rva_t rva) const
{
	if (!is_rva_valid(rva))
	{
		return false;
	}

	for (const auto& section : sections_ | std::views::values)
	{
		if (section->code() && section->contains(rva))
		{
			return true;
		}
	}

	return false;
}

bool binwrite::binary_t::is_in_data_section(const rva_t rva) const
{
	if (!is_rva_valid(rva))
	{
		return false;
	}

	for (const auto& section : sections_ | std::views::values)
	{
		if (section->data() && section->contains(rva))
		{
			return true;
		}
	}

	return false;
}

std::vector<std::uint8_t>& binwrite::binary_t::buffer()
{
	return buffer_;
}

const std::vector<std::uint8_t>& binwrite::binary_t::buffer() const
{
	return buffer_;
}

std::size_t binwrite::binary_t::size() const
{
	return buffer_.size();
}

std::uint8_t* binwrite::binary_t::data()
{
	return buffer_.data();
}

const std::uint8_t* binwrite::binary_t::data() const
{
	return buffer_.data();
}

void binwrite::binary_t::reindex_basic_blocks() const
{
	bb_index_.clear();
	bb_index_.reserve(basic_blocks_.size());

	bb_interval_index_.clear();

	for (const auto& basic_block : basic_blocks_)
	{
		const auto rva = basic_block->rva();

		if (!rva)
		{
			continue;
		}

		bb_index_[rva->value()] = basic_block;
		bb_interval_index_[rva->value()] = basic_block;
	}

	bb_index_dirty_ = false;
}

void binwrite::binary_t::recompile()
{
	finalize_before_recompile();

	for (const auto& symbol_ref : symbol_refs_)
	{
		if (!symbol_ref->widen_encoding(*this))
		{
			spdlog::error("unable to widen symbol reference's encoding");

			return;
		}
	}

	const std::size_t alignment = section_alignment();

	{
		rva_t::value_type offset = 0;

		for (const auto& section : ordered_sections())
		{
			const auto section_offset = offset;

			for (const auto& symbol : section->symbols())
			{
				const auto sym_align = symbol->required_alignment();
				if (sym_align > 1)
				{
					const auto misalignment = offset % sym_align;
					if (misalignment != 0)
					{
						offset += sym_align - misalignment;
					}
				}

				symbol->set_rva(rva_t{ offset });
				offset += symbol->size();
			}

			const auto section_size = offset - section_offset;
			const auto padding_needed = (alignment - (section_size % alignment)) % alignment;

			section->set_rva(rva_t{ section_offset });
			section->set_size(static_cast<section_t::size_type>(section_size));
			section->set_padding(static_cast<section_t::size_type>(padding_needed));

			offset += static_cast<rva_t::value_type>(padding_needed);
		}
	}

	update_relocations();

	std::vector<std::uint8_t> final_buffer;

	for (const auto& section : ordered_sections())
	{
		const auto section_offset = final_buffer.size();

		for (const auto& symbol : section->symbols())
		{
			const auto sym_align = symbol->required_alignment();
			if (sym_align > 1)
			{
				const auto pos = final_buffer.size();
				const auto misalignment = pos % sym_align;
				if (misalignment != 0)
				{
					final_buffer.insert(final_buffer.end(), sym_align - misalignment, 0);
				}
			}

			symbol->set_rva(rva_t{ static_cast<rva_t::value_type>(final_buffer.size()) });
			symbol->emit_bytes(final_buffer);
		}

		const auto section_size = final_buffer.size() - section_offset;
		const auto padding_needed = (alignment - (section_size % alignment)) % alignment;

		section->set_rva(rva_t{ static_cast<rva_t::value_type>(section_offset) });
		section->set_size(static_cast<section_t::size_type>(section_size));
		section->set_padding(static_cast<section_t::size_type>(padding_needed));

		final_buffer.insert(final_buffer.end(), padding_needed, section->padding_value());
	}

	buffer_ = std::move(final_buffer);

	for (const auto& symbol_ref : symbol_refs_)
	{
		if (!symbol_ref->patch_reference(*this))
		{
			spdlog::error("failed to patch ref type: {}", typeid(*symbol_ref).name());
		}
	}

	update_section_headers();
}

void binwrite::binary_t::reindex_functions() const
{
	fn_index_.clear();
	fn_index_.reserve(functions_.size());

	for (const auto& function : functions_)
	{
		fn_index_[function->rva()->value()] = function;
	}

	fn_index_dirty_ = false;
}

void binwrite::binary_t::add_jump_table_target(const rva_t dispatcher_rva, const std::shared_ptr<rva_t>& target)
{
	auto& targets = jump_table_targets_[dispatcher_rva.value()];

	for (const auto& existing_target : targets)
	{
		if (*existing_target == *target)
		{
			return;
		}
	}

	targets.push_back(target);
}
