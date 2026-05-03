#include "data_block.hpp"
#include "../binary/binary.hpp"

bool binwrite::data_symbol_ref_t::emit_reference(binary_t& binary, const rva_t self_rva, const rva_t target_rva)
{
	const rva_t::value_type target_value = target_rva.value();

	std::uint8_t* const destination = binary.data() + self_rva.value();
	const auto source = reinterpret_cast<const std::uint8_t*>(&target_value);

	const size_type copy_size = std::min(encoding_size_, static_cast<size_type>(sizeof(rva_t::size_type)));

	std::memset(destination, 0, encoding_size_);
	std::memcpy(destination, source, copy_size);

	return true;
}
