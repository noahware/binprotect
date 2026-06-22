#pragma once
#include <vector>

#include "../binary/rva/rva.hpp"
#include "../binary/symbols/symbols.hpp"
#include "../arch/instruction/instruction.hpp"

std::vector<std::uint8_t> group_instruction_bytes(std::span<const binwrite::instruction_t> instructions);

namespace binwrite
{
	class binary_t;

	class basic_block_t : public symbol_t
	{
	public:
		constexpr static size_type invalid_index = -1;

		basic_block_t() = default;

		explicit basic_block_t(const std::span<const instruction_t> instructions)
				:	instructions_(instructions.begin(), instructions.end())
		{
			rebuild_offsets();
		}

		[[nodiscard]] std::shared_ptr<rva_t> rva() const
		{
			return rva_;
		}

		[[nodiscard]] bool should_skip() const
		{
			return skip_;
		}

		void set_skip(const bool state)
		{
			skip_ = state;
		}

		void clear_disassembly();

		[[nodiscard]] rva_t end_rva() const;
		[[nodiscard]] rva_t instruction_rva(size_type index) const;
		[[nodiscard]] size_type instruction_index(rva_t target_rva) const;

		void move_entire(binary_t& binary, rva_t destination) const;

		void push(binary_t& binary, const instruction_t& instruction, bool pre_existing = false, bool inclusive = false);
		void push(binary_t& binary, std::span<const instruction_t> instructions, bool pre_existing = false, bool inclusive = false);

		void insert(binary_t& binary, const instruction_t& instruction, size_type index, bool inclusive = false);
		void insert(binary_t& binary, std::span<const instruction_t> instructions, size_type index, bool inclusive = false);

		void erase(binary_t& binary, size_type index, size_type count, bool affects_buffer = true);
		void erase(binary_t& binary, size_type index, bool affects_buffer = true);

		void clear(binary_t& binary);

		[[nodiscard]] instruction_t& last_instruction()
		{
			return instructions_.at(count() - 1);
		}

		[[nodiscard]] const instruction_t& last_instruction() const
		{
			return instructions_.at(count() - 1);
		}

		[[nodiscard]] rva_t last_instruction_rva() const
		{
			return instruction_rva(count() - 1);
		}

		[[nodiscard]] instruction_t& at(const size_type index)
		{
			return instructions_.at(index);
		}

		[[nodiscard]] const instruction_t& at(const size_type index) const
		{
			return instructions_.at(index);
		}

		[[nodiscard]] std::span<instruction_t> instructions()
		{
			return { instructions_ };
		}

		[[nodiscard]] std::span<const instruction_t> instructions() const
		{
			return { instructions_ };
		}

		[[nodiscard]] size_type count() const
		{
			return static_cast<size_type>(instructions_.size());
		}

		[[nodiscard]] bool contains(const rva_t rva) const
		{
			return *rva_ <= rva && rva < end_rva();
		}

		bool operator==(const basic_block_t& other) const
		{
			return rva_ == other.rva_;
		}

		[[nodiscard]] size_type size() const override
		{
			return total_size_;
		}

		void emit_bytes(std::vector<std::uint8_t>& buffer) const override
		{
			for (const auto& instruction : instructions_)
			{
				const auto bytes = instruction.bytes();

				buffer.insert(buffer.end(), bytes.begin(), bytes.end());
			}
		}

		[[nodiscard]] std::shared_ptr<symbol_t> split(binary_t& binary, size_type byte_offset) override;

	protected:
		size_type index_from_byte_offset(size_type byte_offset) const;

		void rebuild_offsets();

		std::shared_ptr<rva_t> rva_;
		std::vector<instruction_t> instructions_;
		std::vector<rva_t::value_type> instruction_offsets_;
		rva_t::value_type total_size_ = 0;

		bool skip_ = false;
	};
}
