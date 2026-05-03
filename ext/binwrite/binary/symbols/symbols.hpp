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

	class symbol_ref_t
	{
	public:
		using size_type = std::uint32_t;

		symbol_ref_t() = default;

		symbol_ref_t(std::shared_ptr<symbol_t> target, std::shared_ptr<symbol_t> self)
				:	self_(std::move(self)),
					target_(std::move(target)) { }

		[[nodiscard]] std::shared_ptr<symbol_t> self() const
		{
			return self_;
		}

		[[nodiscard]] std::shared_ptr<symbol_t> target() const
		{
			return target_;
		}

		virtual bool widen_encoding() = 0;
		virtual bool emit_reference(binary_t& binary, rva_t self_rva, rva_t target_rva) = 0;

	protected:
		std::shared_ptr<symbol_t> self_;
		std::shared_ptr<symbol_t> target_;
	};
}
