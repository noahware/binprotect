#include "basic_block.hpp"

#include <spdlog/spdlog.h>

#include "../binary/binary.hpp"

void binwrite::basic_block_t::clear_disassembly()
{
	for (auto& instruction : instructions_)
	{
		instruction.clear_disassembly();
	}
}

binwrite::rva_t binwrite::basic_block_t::end_rva() const
{
	return rva_t{ rva_->value() + total_size_ };
}

[[nodiscard]] binwrite::rva_t binwrite::basic_block_t::instruction_rva(const size_type index) const
{
	if (index <= 0)
	{
		return *rva_;
	}

	if (index >= count())
	{
		return end_rva();
	}

	rva_t::value_type offset = 0;

	for (size_type i = 0; i < index; i++)
	{
		offset += instructions_[i].size();
	}

	return rva_t{ rva_->value() + offset };
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
	const auto target_offset = target_rva.value() - rva_->value();

	return index_from_byte_offset(target_offset);
}

void binwrite::basic_block_t::move_entire(binary_t& binary, rva_t destination) const
{
	const rva_t original_block_rva = *rva_;

	if (original_block_rva == destination)
	{
		return;
	}

	const rva_t::size_type block_size = static_cast<std::int32_t>(end_rva().value() - original_block_rva.value());

	std::vector<std::pair<std::shared_ptr<rva_ref_t>, rva_t::value_type>> references_in_block = { };

	for (const auto& rva_ref : binary.rva_refs())
	{
		if (contains(rva_ref->self()))
		{
			const auto offset = rva_ref->self().value() - original_block_rva.value();

			references_in_block.emplace_back(rva_ref, offset);
		}
	}

	std::vector<std::pair<std::shared_ptr<rva_t>, rva_t::value_type>> rvas_pointing_to_block = { };

	for (const auto& rva : binary.rvas())
	{
		if (contains(*rva))
		{
			const auto offset = rva->value() - original_block_rva.value();

			rvas_pointing_to_block.emplace_back(rva, offset);
		}
	}

	const auto block_start = binary.data() + rva_->value();

	std::vector block_data(block_start, block_start + block_size);

	binary.insert(destination, block_data, true);

	if (destination < original_block_rva)
	{
		binary.erase(rva_t{ original_block_rva.value() + block_size }, block_size, true);
	}
	else
	{
		binary.erase(original_block_rva, block_size, true);

		destination = rva_t{ destination.value() - block_size };
	}

	for (const auto& [reference, value] : references_in_block)
	{
		rva_t self = reference->self();

		self.set_value(destination.value() + value);

		reference->set_self(self);
	}

	for (const auto& [rva_finger, value] : rvas_pointing_to_block)
	{
		rva_finger->set_value(destination.value() + value);
	}

	*rva_ = destination;
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

static binwrite::rva_t::size_type group_instructions_size(const std::span<const binwrite::instruction_t> instructions)
{
	binwrite::rva_t::size_type size = 0;

	for (const auto& instruction : instructions)
	{
		size += static_cast<binwrite::rva_t::size_type>(instruction.size());
	}

	return size;
}

void binwrite::basic_block_t::push(binary_t& binary, const instruction_t& instruction, const bool pre_existing, const bool inclusive)
{
	push(binary, std::array{ instruction }, pre_existing, inclusive);
}

void binwrite::basic_block_t::push(binary_t& binary, const std::span<const instruction_t> instructions, const bool pre_existing, const bool inclusive)
{
	if (!pre_existing)
	{
		const rva_t rva = end_rva();
		const auto bytes = group_instruction_bytes(instructions);

		binary.insert(rva, bytes, inclusive);
	}

	instructions_.insert(instructions_.end(), instructions.begin(), instructions.end());
	total_size_ += group_instructions_size(instructions);
}

void binwrite::basic_block_t::insert(binary_t& binary, const instruction_t& instruction, const size_type index, const bool inclusive)
{
	insert(binary, std::array{ instruction }, index, inclusive);
}

void binwrite::basic_block_t::insert(binary_t& binary, const std::span<const instruction_t> instructions, const size_type index, const bool inclusive)
{
	const auto begin = instructions_.begin() + index;

	instructions_.insert(begin, instructions.begin(), instructions.end());
	total_size_ += group_instructions_size(instructions);
}

void binwrite::basic_block_t::erase(binary_t& binary, const size_type index, const size_type count, const bool affects_buffer)
{
	const auto first_instruction = instructions_.begin() + index;
	const auto last_instruction = first_instruction + count;
	const rva_t::size_type erased_size = group_instructions_size({ first_instruction, last_instruction });

	if (affects_buffer)
	{
		const rva_t rva = instruction_rva(index);

		binary.erase(rva, erased_size);
	}

	instructions_.erase(first_instruction, last_instruction);
	total_size_ -= erased_size;
}

void binwrite::basic_block_t::erase(binary_t& binary, const size_type index, const bool affects_buffer)
{
	return erase(binary, index, 1, affects_buffer);
}

void binwrite::basic_block_t::clear(binary_t& binary)
{
	erase(binary, 0, count(), true);
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

	const auto begin = instructions_.begin() + index;
	const auto end = instructions_.end();

	const auto owning_section = section();
	const std::span new_instructions(begin, end);

	const auto new_basic_block = binary.create_basic_block(*owning_section, new_instructions);

	instructions_.erase(begin, end);
	total_size_ -= new_basic_block->total_size_;

	new_basic_block->move_after(shared_from_this());

	return new_basic_block;
}

