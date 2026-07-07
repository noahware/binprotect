#pragma once
#include <binwrite/binary/binary.hpp>
#include <functional>

namespace binprotect::control_flow::flattening
{
	void do_pass(binwrite::binary_t& binary, binwrite::function_t& function,
		const std::function<bool(const std::shared_ptr<binwrite::basic_block_t>&)>& is_block_fixed = {});
}
