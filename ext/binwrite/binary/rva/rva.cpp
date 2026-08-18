#include "rva.hpp"
#include <memory>
#include <spdlog/spdlog.h>

#include "../../disassembler/disassembler.hpp"
#include "../binary.hpp"
#include "../pe/cxx_frame_handler4.hpp"

binwrite::rva_t::value_type binwrite::rva_t::value() const
{
	return value_;
}

void binwrite::rva_t::set_value(const value_type value)
{
	value_ = value;
}
