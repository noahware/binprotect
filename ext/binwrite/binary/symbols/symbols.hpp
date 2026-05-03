#pragma once
#include <vector>
#include <memory>

namespace binwrite
{
	class section_t;

	class symbol_t
	{
	public:
		using size_type = std::uint32_t;

		symbol_t() = default;

		[[nodiscard]] virtual size_type size() const = 0;
		virtual void emit_bytes(std::vector<std::uint8_t>& buffer) const = 0;
	};
}
