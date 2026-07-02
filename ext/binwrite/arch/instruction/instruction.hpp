#pragma once
#include <array>
#include <memory>
#include <cstring>
#include <span>
#include <stdexcept>

#include "../../disassembler/disassembler.hpp"

namespace binwrite
{
	class instruction_t
	{
	public:
		using size_type = std::uint8_t;
		using id_type = std::uint32_t;
		using value_type = std::span<std::uint8_t>;
		using const_value_type = std::span<const std::uint8_t>;

		constexpr static size_type max_size = 15;

		explicit instruction_t(const const_value_type bytes, disassembled_instruction_t disassembly)
				:	bytes_({}),
					size_(static_cast<size_type>(bytes.size())),
					disassembly_(std::make_unique<disassembled_instruction_t>(std::move(disassembly)))
		{
			if (max_size < size_)
			{
				throw std::runtime_error("instruction bytes too long");
			}

			std::memcpy(bytes_.data(), bytes.data(), bytes.size());
		}

		explicit instruction_t(const const_value_type bytes)
				:	bytes_({}),
					size_(static_cast<size_type>(bytes.size())),
					disassembly_(nullptr)
		{
			if (max_size < size_)
			{
				throw std::runtime_error("instruction bytes too long");
			}

			std::memcpy(bytes_.data(), bytes.data(), bytes.size());
		}

		instruction_t(const instruction_t& right)
				:	size_(right.size_),
					id_(right.id_),
					disassembly_(nullptr)
		{
			std::memcpy(bytes_.data(), right.bytes_.data(), right.size_);
		}

		instruction_t& operator=(const instruction_t& right)
		{
			if (this != &right)
			{
				disassembly_.reset();
				size_ = right.size_;
				id_ = right.id_;

				std::memcpy(bytes_.data(), right.bytes_.data(), right.size_);
			}

			return *this;
		}

		[[nodiscard]] value_type bytes()
		{
			return { bytes_.begin(), size_ };
		}

		[[nodiscard]] const_value_type bytes() const
		{
			return { bytes_.begin(), size_ };
		}

		[[nodiscard]] size_type size() const
		{
			return size_;
		}

		[[nodiscard]] id_type id() const
		{
			return id_;
		}

		void set_id(const id_type id)
		{
			id_ = id;
		}

		[[nodiscard]] disassembled_instruction_t& disassemble()
		{
			create_disassembly();

			return *disassembly_;
		}

		[[nodiscard]] const disassembled_instruction_t& disassemble() const
		{
			create_disassembly();

			return *disassembly_;
		}

		void clear_disassembly()
		{
			disassembly_.reset();
		}

	protected:
		void create_disassembly() const
		{
			if (disassembly_)
			{
				return;
			}

			const disassembler_t disassembler;

			auto disassembly = disassembler.disassemble({ bytes_.data(), size_ });

			if (!disassembly)
			{
				throw std::runtime_error("unable to disassemble instruction");
			}

			disassembly_ = std::make_unique<disassembled_instruction_t>(std::move(*disassembly));
		}

		std::array<std::uint8_t, max_size> bytes_;
		size_type size_;
		id_type id_ = 0;

		mutable std::unique_ptr<disassembled_instruction_t> disassembly_ = {};
	};
}
