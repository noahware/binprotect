#include "basic_block.hpp"

#include <spdlog/spdlog.h>

#include "../binary/binary.hpp"

void binwrite::basic_block_t::recompute_size()
{
	total_size_ = 0;

	for (const auto& instruction : instructions_)
	{
		total_size_ += instruction.size();
	}
}

binwrite::rva_t binwrite::basic_block_t::original_end_rva() const
{
	return rva_t{ original_rva_->value() + total_size_ };
}

[[nodiscard]] binwrite::rva_t binwrite::basic_block_t::original_instruction_rva(const size_type index) const
{
	if (index <= 0)
	{
		return *original_rva_;
	}

	if (index >= count())
	{
		return original_end_rva();
	}

	rva_t::value_type offset = 0;

	for (size_type i = 0; i < index; i++)
	{
		offset += instructions_[i].size();
	}

	return rva_t{ original_rva_->value() + offset };
}

binwrite::symbol_t::size_type binwrite::basic_block_t::index_from_byte_offset(const size_type byte_offset) const
{
	size_type offset = 0;

	for (size_type i = 0; i < count(); i++)
	{
		if (offset == byte_offset)
		{
			return i;
		}

		offset += instructions_[i].size();
	}

	return invalid_index;
}

binwrite::basic_block_t::size_type binwrite::basic_block_t::instruction_index(const rva_t target_rva) const
{
	const auto target_offset = target_rva.value() - original_rva_->value();

	return index_from_byte_offset(target_offset);
}

std::vector<std::uint8_t> group_instruction_bytes(const std::span<const binwrite::instruction_t> instructions)
{
	std::vector<std::uint8_t> bytes;

	for (const auto& instruction : instructions)
	{
		const auto current_bytes = instruction.bytes();

		bytes.insert(bytes.end(), current_bytes.begin(), current_bytes.end());
	}

	return bytes;
}

binwrite::instruction_t& binwrite::basic_block_t::push(binary_t& binary, const instruction_t& instruction)
{
	push(binary, std::array{ instruction });

	return instructions_.back();
}

void binwrite::basic_block_t::push(binary_t& binary, const std::span<const instruction_t> instructions)
{
	const auto first_added = instructions_.size();

	instructions_.insert(instructions_.end(), instructions.begin(), instructions.end());

	for (auto i = first_added; i < instructions_.size(); i++)
	{
		binary.assign_instruction_id_if_needed(instructions_[i]);
	}

	recompute_size();
}

binwrite::instruction_t& binwrite::basic_block_t::insert(binary_t& binary, const instruction_t& instruction, const size_type index)
{
	insert(binary, std::array{ instruction }, index);

	return instructions_[index];
}

void binwrite::basic_block_t::insert(binary_t& binary, const std::span<const instruction_t> instructions, const size_type index)
{
	const auto begin = instructions_.begin() + index;
	const auto inserted_count = static_cast<size_type>(instructions.size());

	instructions_.insert(begin, instructions.begin(), instructions.end());

	for (size_type i = 0; i < inserted_count; i++)
	{
		binary.assign_instruction_id_if_needed(instructions_[index + i]);
	}

	recompute_size();
}

void binwrite::basic_block_t::erase(binary_t& binary, const size_type index, const size_type count)
{
	const auto first_instruction = instructions_.begin() + index;

	instructions_.erase(first_instruction, first_instruction + count);

	recompute_size();
}

void binwrite::basic_block_t::erase(binary_t& binary, const size_type index)
{
	return erase(binary, index, 1);
}

std::shared_ptr<binwrite::basic_block_t> binwrite::basic_block_t::split_at(binary_t& binary, const size_type index)
{
	if (index == 0 || index >= count())
	{
		return { };
	}

	std::optional<rva_t> split_rva;

	if (original_rva_)
	{
		split_rva = original_instruction_rva(index);
	}

	const auto begin = instructions_.begin() + index;
	const auto end = instructions_.end();

	const auto owning_section = section();
	const std::span new_instructions(begin, end);

	const auto new_basic_block = binary.create_basic_block(*owning_section, new_instructions, split_rva);

	instructions_.erase(begin, end);
	recompute_size();

	new_basic_block->move_after(shared_from_this());

	binary.reanchor_split_refs(std::dynamic_pointer_cast<basic_block_t>(shared_from_this()), new_basic_block);

	return new_basic_block;
}

std::shared_ptr<binwrite::symbol_t> binwrite::basic_block_t::split(binary_t& binary, const size_type byte_offset)
{
	if (!byte_offset)
	{
		return { };
	}

	const auto index = index_from_byte_offset(byte_offset);

	if (index == invalid_index)
	{
		return { };
	}

	return split_at(binary, index);
}

