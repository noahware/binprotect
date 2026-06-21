#pragma once
#include <list>

#include "../rva/rva.hpp"
#include "binwrite/binary/symbols/symbols.hpp"

namespace binwrite
{
	class symbol_t;
	class binary_t;

	class section_t
	{
	public:
		using size_type = std::uint32_t;

		section_t() = default;

		explicit section_t(binary_t& binary, rva_t rva, size_type size, size_type padding, bool code_section,
		                   bool headers_section = false);

		void process_disruption(rva_t disruption_rva, rva_t::size_type disruption_size);

		void insert(binary_t& binary, rva_t section_offset, std::span<const std::uint8_t> data);

		[[nodiscard]] rva_t rva() const;
		void set_rva(rva_t rva);

		[[nodiscard]] rva_t end_rva() const;

		[[nodiscard]] bool contains(rva_t rva) const;
		[[nodiscard]] bool code() const;
		[[nodiscard]] bool data() const;
		[[nodiscard]] bool headers() const;

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

		void add_symbol(std::shared_ptr<symbol_t> symbol)
		{
			const auto it = symbols_.insert(symbols_.end(), std::move(symbol));

			(*it)->list_iterator_ = it;
		}

		[[nodiscard]] auto symbols() const
		{
			return symbols_;
		}

		void move_symbol_after(const std::shared_ptr<symbol_t>& location, const std::shared_ptr<symbol_t>& movable_symbol)
		{
			if (location == movable_symbol)
			{
				return;
			}

			const auto next = std::next(location->list_iterator_);

			symbols_.splice(next, symbols_, movable_symbol->list_iterator_);
		}

	protected:
		symbol_list_t symbols_;

		rva_t rva_;
		size_type size_;
		size_type padding_;
		bool code_;
		bool headers_;
	};
}
