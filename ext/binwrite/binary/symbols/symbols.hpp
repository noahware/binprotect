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
	class section_t;
	class symbol_t;

	using symbol_list_t = std::list<std::shared_ptr<symbol_t>>;

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
			const auto current_section = section();

			current_section->move_symbol_after(location, shared_from_this());
		}

	protected:
		[[nodiscard]] std::shared_ptr<section_t> section() const
		{
			return section_.lock();
		}

		std::weak_ptr<section_t> section_;
		symbol_list_t::iterator list_iterator_;

		std::optional<rva_t> rva_;
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

	protected:
		std::shared_ptr<symbol_t> self_;
		std::shared_ptr<symbol_t> target_;

		size_type encoding_size_;
	};

	class data_symbol_ref_t : public symbol_ref_t
	{
	public:
		bool patch_reference(binary_t& binary) override;
	};
}
