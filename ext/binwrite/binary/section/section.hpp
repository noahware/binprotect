#pragma once
#include "../rva/rva.hpp"

namespace binwrite
{
	class symbol_t;
	class binary_t;

	class section_t
	{
	public:
		using size_type = std::uint32_t;

		section_t() = default;

		explicit section_t(const rva_t rva, const size_type size, const size_type padding, const bool code_section)
				:	rva_(rva),
					size_(size),
					padding_(padding),
					code_(code_section) { }

		void process_disruption(rva_t disruption_rva, rva_t::size_type disruption_size);

		void insert(binary_t& binary, rva_t section_offset, std::span<const std::uint8_t> data);

		[[nodiscard]] rva_t rva() const;
		void set_rva(rva_t rva);

		[[nodiscard]] rva_t end_rva() const;

		[[nodiscard]] bool contains(rva_t rva) const;
		[[nodiscard]] bool code() const;
		[[nodiscard]] bool data() const;

		[[nodiscard]] size_type size() const;
		void set_size(size_type size);

		[[nodiscard]] size_type padding() const;
		void set_padding(size_type padding);

		void remove_padding(size_type size);
		void add_padding(size_type size);

		[[nodiscard]] std::uint8_t padding_value() const
		{
			return code() ? 0xCC : 0x00;
		}

		[[nodiscard]] std::span<std::shared_ptr<symbol_t>> symbols()
		{
			return symbols_;
		}

		[[nodiscard]] std::span<const std::shared_ptr<symbol_t>> symbols() const
		{
			return symbols_;
		}

	protected:
		std::vector<std::shared_ptr<symbol_t>> symbols_;

		rva_t rva_;
		size_type size_;
		size_type padding_;
		bool code_;
	};
}
