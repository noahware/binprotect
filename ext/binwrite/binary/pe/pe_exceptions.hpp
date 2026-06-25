#pragma once
#include "pe.hpp"
#include "pe_rtti.hpp"

#include <algorithm>
#include <unordered_set>
#include <set>

namespace binwrite
{
	[[nodiscard]] portable_executable::unwind_register_t get_unwind_register(register_t reg);

	struct exception_context_t
	{
		struct function_range_t
		{
			std::shared_ptr<rva_t> begin;
			std::shared_ptr<rva_t> end;
		};

		struct prologue_info_t
		{
			std::shared_ptr<rva_t> begin;
			std::uint8_t prolog_size;
		};

		std::vector<function_range_t> fh_function_ranges;
		std::vector<prologue_info_t> fh_prologues;
		std::shared_ptr<rva_t> exception_directory_rva;
		std::shared_ptr<rva_t> unwind_info_insertion_rva;

		std::unordered_map<rva_t::value_type, std::vector<rva_t>> func_handlers;
		std::unordered_map<rva_t::value_type, std::vector<rva_t>> catch_handlers;
		std::vector<std::shared_ptr<rva_t>> handler_function_rvas;
		std::vector<function_range_t> seh_code_ranges;

		[[nodiscard]] bool is_fh_function(const rva_t::value_type function_rva) const
		{
			return std::ranges::any_of(fh_function_ranges,
				[function_rva](const auto& range) { return range.begin->value() == function_rva; });
		}

		[[nodiscard]] bool is_in_fh_range(const rva_t::value_type rva) const
		{
			return std::ranges::any_of(fh_function_ranges,
				[rva](const auto& range) { return range.begin->value() <= rva && rva < range.end->value(); });
		}

		[[nodiscard]] bool is_in_seh_range(const rva_t::value_type rva) const
		{
			return std::ranges::any_of(seh_code_ranges,
				[rva](const auto& range) { return range.begin->value() <= rva && rva < range.end->value(); });
		}

		[[nodiscard]] bool is_handler_function(const rva_t::value_type function_rva) const
		{
			return std::ranges::any_of(handler_function_rvas,
				[function_rva](const auto& rva) { return rva->value() == function_rva; });
		}
	};

	exception_context_t parse_exception_directory(portable_executable_t& pe);
	void queue_throw_info_code_targets(portable_executable_t& pe);
	void parse_throw_info(portable_executable_t& pe, const rtti_info_t& rtti_result);
	void rewrite_frame_pointers(portable_executable_t& pe, exception_context_t& context);
	void split_prologues(portable_executable_t& pe, const exception_context_t& context);
}
