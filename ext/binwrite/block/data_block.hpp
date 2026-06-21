#pragma once
#include <span>
#include <vector>

#include "../binary/symbols/symbols.hpp"
#include "binwrite/binary/section/section.hpp"

namespace binwrite
{
	class data_block_t : public symbol_t
	{
	public:
		data_block_t() noexcept = default;

		explicit data_block_t(const std::span<const std::uint8_t> bytes) noexcept
				:	bytes_(bytes.begin(), bytes.end()) { }

		[[nodiscard]] size_type size() const noexcept override
		{
			return static_cast<size_type>(bytes_.size());
		}

		void emit_bytes(std::vector<std::uint8_t>& buffer) const override
		{
			buffer.insert(buffer.end(), bytes_.begin(), bytes_.end());
		}

		[[nodiscard]] std::shared_ptr<symbol_t> split(binary_t& binary, size_type byte_offset) override;

	protected:
		std::vector<std::uint8_t> bytes_;
	};
}
