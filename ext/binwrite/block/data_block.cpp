#include "data_block.hpp"
#include "../binary/binary.hpp"

std::shared_ptr<binwrite::symbol_t> binwrite::data_block_t::split(binary_t& binary, const size_type byte_offset)
{
	if (!byte_offset)
	{
		return { };
	}

	const auto begin = bytes_.begin() + byte_offset;
	const auto end = bytes_.end();

	const auto owning_section = section();
	const std::span new_bytes(begin, end);

	const auto new_data_block = binary.create_data_block(*owning_section, new_bytes);

	bytes_.erase(begin, end);

	new_data_block->move_after(shared_from_this());

	return new_data_block;
}
