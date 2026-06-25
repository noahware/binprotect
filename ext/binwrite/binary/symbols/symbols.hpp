#pragma once
#include "../rva/rva.hpp"
#include <vector>
#include <memory>
#include <optional>
#include <list>

#include "binwrite/binary/section/section.hpp"

namespace binwrite
{
	class binary_t;

	class symbol_t : public std::enable_shared_from_this<symbol_t>
	{
	public:
		friend class section_t;

		using size_type = std::uint32_t;

		symbol_t() = default;

		explicit symbol_t(std::weak_ptr<section_t> section, const std::optional<rva_t> rva = std::nullopt)
				:	section_(std::move(section)),
					rva_(rva) { }

		[[nodiscard]] virtual size_type size() const = 0;
		[[nodiscard]] virtual std::shared_ptr<symbol_t> split(binary_t& binary, size_type byte_offset) = 0;

		virtual void emit_bytes(std::vector<std::uint8_t>& buffer) const = 0;

		void set_rva(const std::optional<rva_t> rva)
		{
			rva_ = rva;
		}

		[[nodiscard]] std::optional<rva_t> rva() const noexcept
		{
			return rva_;
		}

		[[nodiscard]] std::optional<rva_t> end_rva() const noexcept
		{
			if (!rva_)
			{
				return std::nullopt;
			}

			return rva_t{ rva_->value() + size() };
		}

		void move_after(const std::shared_ptr<symbol_t>& location)
		{
			const auto destination_section = location->section();

			destination_section->move_symbol_after(location, shared_from_this());
		}

		[[nodiscard]] std::shared_ptr<section_t> section() const
		{
			return section_.lock();
		}

		[[nodiscard]] symbol_list_t::iterator list_iterator() const noexcept
		{
			return list_iterator_;
		}

		void set_required_alignment(const std::uint32_t alignment) noexcept
		{
			required_alignment_ = alignment;
		}

		[[nodiscard]] std::uint32_t required_alignment() const noexcept
		{
			return required_alignment_;
		}

	protected:
		std::weak_ptr<section_t> section_;
		symbol_list_t::iterator list_iterator_;

		std::optional<rva_t> rva_;
		std::uint32_t required_alignment_ = 1;
	};

	class symbol_ref_t
	{
	public:
		using size_type = std::uint32_t;

		symbol_ref_t() = default;

		symbol_ref_t(std::shared_ptr<symbol_t> target, std::shared_ptr<symbol_t> self, const size_type encoding_size)
				:	self_(std::move(self)),
					target_(std::move(target)),
					encoding_size_(encoding_size) { }

		[[nodiscard]] std::shared_ptr<symbol_t> self() const
		{
			return self_;
		}

		[[nodiscard]] std::shared_ptr<symbol_t> target() const
		{
			return target_;
		}

		virtual bool patch_reference(binary_t& binary) = 0;

		virtual bool widen_encoding()
		{
			return true;
		}

		void set_target(std::shared_ptr<symbol_t> target)
		{
			target_ = std::move(target);
		}

	protected:
		std::shared_ptr<symbol_t> self_;
		std::shared_ptr<symbol_t> target_;

		size_type encoding_size_;
	};

	class data_symbol_ref_t : public symbol_ref_t
	{
	public:
		using symbol_ref_t::symbol_ref_t;

		bool patch_reference(binary_t& binary) override;
	};

	class code_symbol_ref_t : public symbol_ref_t
	{
	public:
		code_symbol_ref_t(std::shared_ptr<symbol_t> target, std::shared_ptr<symbol_t> self,
		                  const size_type encoding_size)
				:	symbol_ref_t(std::move(target), std::move(self), encoding_size) { }

		bool patch_reference(binary_t& binary) override;
		bool widen_encoding() override;

	protected:
		[[nodiscard]] virtual std::int32_t compute_displacement(rva_t self_rva, rva_t target_rva) const;
	};

	class msvc_jmp_table_symbol_ref_t : public code_symbol_ref_t
	{
	public:
		using code_symbol_ref_t::code_symbol_ref_t;

	protected:
		[[nodiscard]] std::int32_t compute_displacement(rva_t self_rva, rva_t target_rva) const override;
	};

	class dir64_reloc_symbol_ref_t : public symbol_ref_t
	{
	public:
		dir64_reloc_symbol_ref_t(std::shared_ptr<symbol_t> target, std::shared_ptr<symbol_t> self)
				:	symbol_ref_t(std::move(target), std::move(self), 8)
		{
		}

		bool patch_reference(binary_t& binary) override;
	};

	class llvm_jmp_table_symbol_ref_t : public symbol_ref_t
	{
	public:
		llvm_jmp_table_symbol_ref_t(std::shared_ptr<symbol_t> target, std::shared_ptr<symbol_t> self,
		                            std::shared_ptr<symbol_t> table_base)
				:	symbol_ref_t(std::move(target), std::move(self), 4),
					table_base_(std::move(table_base))
		{
		}

		bool patch_reference(binary_t& binary) override;

	protected:
		std::shared_ptr<symbol_t> table_base_;
	};

	class fh4_encoded_symbol_ref_t : public symbol_ref_t
	{
	public:
		fh4_encoded_symbol_ref_t(std::shared_ptr<symbol_t> target, std::shared_ptr<symbol_t> self,
		                         std::shared_ptr<symbol_t> previous_target)
				:	symbol_ref_t(std::move(target), std::move(self), 5),
					previous_target_(std::move(previous_target))
		{
		}

		bool patch_reference(binary_t& binary) override;
		bool widen_encoding() override;

	protected:
		std::shared_ptr<symbol_t> previous_target_;
	};
}
