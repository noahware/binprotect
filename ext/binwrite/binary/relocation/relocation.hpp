#pragma once
#include "../symbols/symbols.hpp"

#include <memory>

namespace binwrite
{
	class relocation_t
	{
	public:
		using reloc_type = std::uint16_t;

		relocation_t() = default;

		explicit relocation_t(std::shared_ptr<symbol_t> target)
				:	target_(std::move(target)) { }

		[[nodiscard]] std::shared_ptr<symbol_t> target() const
		{
			return target_;
		}

		[[nodiscard]] virtual reloc_type type() const = 0;

	protected:
		std::shared_ptr<symbol_t> target_;
	};
}
