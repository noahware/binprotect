#pragma once
#include <vector>

#include "../binary/symbols/symbols.hpp"

namespace binwrite
{
	class data_block_t : public symbol_t
	{
	public:
		[[nodiscard]] size_type size() const override
		{
			return bytes_.size();
		}

		void emit_bytes(std::vector<std::uint8_t>& buffer) const override
		{
			buffer.insert(buffer.end(), bytes_.begin(), bytes_.end());
		}

	protected:
		std::vector<std::uint8_t> bytes_;
	};
}
