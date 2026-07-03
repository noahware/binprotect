#pragma once
#include <binwrite/binary/binary.hpp>

namespace binprotect::opaque_predicate
{
	void do_pass(binwrite::binary_t& binary, const std::shared_ptr<binwrite::basic_block_t>& basic_block,
	             std::vector<std::shared_ptr<binwrite::basic_block_t>>& opaque_blocks);
}
