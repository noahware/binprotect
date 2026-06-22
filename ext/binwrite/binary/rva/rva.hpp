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

		explicit rva_t(const value_type value, const bool force_inclusive)
				:	value_(value),
					force_inclusive_(force_inclusive) { }

		[[nodiscard]] value_type value() const;
		void set_value(value_type value);

		[[nodiscard]] bool force_inclusive() const;
		void set_force_inclusive(bool force_inclusive);

		void process_disruption(rva_t disruption_rva, size_type disruption_size, bool inclusive);

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
		bool force_inclusive_ = false;
	};

	class rva_ref_t
	{
	public:
		rva_ref_t(std::shared_ptr<rva_t> target, const rva_t self)
				:	target_(std::move(target)),
					self_(self) { }

		enum class error_t : std::uint8_t
		{
			cant_compile = 0,
			cant_predict_size,
			cant_update_operand,
			cant_make_assembler_instruction,
			instruction_length_changed
		};

		virtual std::expected<void, error_t> update_reference(binary_t& binary) = 0;

		[[nodiscard]] rva_t self() const;
		void set_self(rva_t self);

		[[nodiscard]] std::shared_ptr<rva_t> target() const;
		void set_target(std::shared_ptr<rva_t> target);

		void process_disruption(rva_t disruption_rva, rva_t::size_type disruption_size);

		virtual bool is_code_reference()
		{
			return false;
		}

	protected:
		std::shared_ptr<rva_t> target_;
		rva_t self_;
	};

	class code_rva_ref_t : public rva_ref_t
	{
	public:
		using size_type = instruction_t::size_type;

		code_rva_ref_t(std::shared_ptr<rva_t> target, const rva_t self, const size_type size)
				:	rva_ref_t(std::move(target), self),
					size_(size) {}

		std::expected<void, error_t> update_reference(binary_t& binary) override;

		bool is_code_reference() override
		{
			return true;
		}

		[[nodiscard]] size_type instruction_size() const noexcept
		{
			return size_;
		}

	protected:
		virtual bool update_rva_in_assembler_instruction(assembler_instruction_t& instruction) const;

		std::expected<void, error_t> compile_and_patch(binary_t& binary, const assembler_instruction_t& instruction);

		instruction_t::size_type size_;
	};

	class data_rva_ref_t : public rva_ref_t
	{
	public:
		using size_type = std::uint8_t;

		data_rva_ref_t(std::shared_ptr<rva_t> target, const rva_t self, const size_type size)
				:	rva_ref_t(std::move(target), self),
					size_(size) { }

		std::expected<void, error_t> update_reference(binary_t& binary) override;

		[[nodiscard]] size_type encoding_size() const noexcept
		{
			return size_;
		}

	protected:
		size_type size_ = 0;
	};

	class msvc_jmp_table_ref_t : public code_rva_ref_t
	{
	public:
		msvc_jmp_table_ref_t(std::shared_ptr<rva_t> target, const rva_t self, const size_type size)
			: code_rva_ref_t(std::move(target), self, size) { }

		bool update_rva_in_assembler_instruction(assembler_instruction_t& instruction) const override;
	};

	class llvm_jmp_table_entry_t : public rva_ref_t
	{
	public:
		llvm_jmp_table_entry_t(std::shared_ptr<rva_t> target, const rva_t self, std::shared_ptr<rva_t> table_base)
				:	rva_ref_t(std::move(target), self),
					table_base_(std::move(table_base)) { }

		using value_type = std::int32_t;
		using size_type = std::uint32_t;

		std::expected<void, error_t> update_reference(binary_t& binary) override;

	protected:
		std::shared_ptr<rva_t> table_base_;
	};

	class pe_dir64_reloc_t : public rva_ref_t
	{
	public:
		using size_type = std::uint8_t;

		pe_dir64_reloc_t(std::shared_ptr<rva_t> target, const rva_t self)
				:	rva_ref_t(std::move(target), self),
					original_target_value_(*target_) { }

		std::expected<void, error_t> update_reference(binary_t& binary) override;

	protected:
		rva_t original_target_value_;
	};

	class pe_fh4_encoded_entry_t : public rva_ref_t
	{
	public:
		using size_type = std::uint8_t;

		pe_fh4_encoded_entry_t(std::shared_ptr<rva_t> chunk_rva, std::shared_ptr<rva_t> previous_entry_target, const size_type encoded_size, std::shared_ptr<rva_t> target, const rva_t self)
				:	rva_ref_t(std::move(target), self),
					chunk_rva_(std::move(chunk_rva)),
					previous_entry_target_(std::move(previous_entry_target)),
					size_(encoded_size) { }

		std::expected<void, error_t> update_reference(binary_t& binary) override;

	protected:
		std::shared_ptr<rva_t> chunk_rva_;
		std::shared_ptr<rva_t> previous_entry_target_;
		size_type size_;
	};
}
