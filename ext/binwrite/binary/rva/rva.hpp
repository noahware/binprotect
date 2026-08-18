#pragma once
#include <cstdint>
#include <expected>
#include <memory>

#include "../../assembler/assembler.hpp"
#include "../../arch/instruction/instruction.hpp"

namespace binwrite
{
	class binary_t;

	class rva_t
	{
	public:
		using value_type = std::uint32_t;
		using size_type = std::int32_t;

		rva_t() = default;

		explicit rva_t(const value_type value)
				:	value_(value) { }

		[[nodiscard]] value_type value() const;
		void set_value(value_type value);

		bool operator==(const rva_t& other) const
		{
			return value_ == other.value_;
		}

		bool operator!=(const rva_t& other) const
		{
			return value_ != other.value_;
		}

		bool operator<(const rva_t& other) const
		{
			return value_ < other.value_;
		}

		bool operator>(const rva_t& other) const
		{
			return value_ > other.value_;
		}

		bool operator<=(const rva_t& other) const
		{
			return value_ <= other.value_;
		}

		bool operator>=(const rva_t& other) const
		{
			return value_ >= other.value_;
		}

	protected:
		value_type value_ = 0;
	};

}
