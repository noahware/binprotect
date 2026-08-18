#pragma once
#include "../binary.hpp"
#include "../relocation/relocation.hpp"

#include <portable-executable/image.hpp>

#include <array>

namespace binwrite
{
	class pe_relocation_t : public relocation_t
	{
	public:
		pe_relocation_t() = default;

		explicit pe_relocation_t(std::shared_ptr<symbol_t> target, const portable_executable::relocation_type_t type)
				:	relocation_t(std::move(target)),
					type_(type) { }

		[[nodiscard]] reloc_type type() const override
		{
			return static_cast<reloc_type>(type_);
		}

	protected:
		portable_executable::relocation_type_t type_;
	};

	struct runtime_function_params_t
	{
		std::shared_ptr<symbol_t> begin_symbol;
		std::shared_ptr<symbol_t> end_symbol;
		std::vector<portable_executable::unwind_code_t> unwind_codes;
		portable_executable::unwind_register_t frame_register;
		std::uint8_t frame_offset;
		std::uint8_t prolog_size;
		std::uint8_t flags;
	};

	class portable_executable_t final : public binary_t
	{
	public:
		explicit portable_executable_t(std::vector<std::uint8_t> buffer)
				:	binary_t(std::move(buffer)) {}

		[[nodiscard]] std::uint64_t image_base() const override;
		[[nodiscard]] rva_t entry_point() const override;
		[[nodiscard]] std::size_t section_alignment() const override;

		void decompress() override;
		void compress() override;

		[[nodiscard]] portable_executable::image_t* image();
		[[nodiscard]] const portable_executable::image_t* image() const;

		[[nodiscard]] bool has_exceptions_directory() const;
		[[nodiscard]] bool is_inside_runtime_function(rva_t rva) const;

		void add_runtime_function(const runtime_function_params_t& params);

	protected:
		struct runtime_function_t
		{
			rva_t begin;
			rva_t end;
		};

		std::vector<runtime_function_t> runtime_functions_;

		void finalize_exception_directory();

		void find_sections() override;
		void update_section_headers() override;
		void update_relocations() override;
		bool is_definitely_in_code_range(rva_t rva) const override;


		void copy_sections(std::vector<std::uint8_t>& to, bool decompress);

		void add_load_config_table_rvas(const portable_executable::load_config_directory_t::table_t& table);
		void add_load_config_rvas(const portable_executable::image_t* img);
		void add_misc_rvas(const portable_executable::nt_headers_t* nt_headers);
		void add_data_directory_rvas(const portable_executable::nt_headers_t* nt_headers);
		void add_import_rvas(const portable_executable::nt_headers_t* nt_headers);
		void add_delay_import_rvas(const portable_executable::nt_headers_t* nt_headers);
		void parse_import_thunk_rvas(const portable_executable::thunk_data_t* original_thunk);
		void add_debug_rvas(const portable_executable::nt_headers_t* nt_headers);
		void add_resource_rvas(const portable_executable::nt_headers_t* nt_headers);
		void parse_resource_directory_rvas(const portable_executable::resource_directory_t* root_directory,
		                                   const portable_executable::resource_directory_t* directory,
		                                   std::uint16_t depth = 0);
		void add_export_rvas(const portable_executable::nt_headers_t* nt_headers);
		void add_relocation_rvas(const portable_executable::nt_headers_t* nt_headers);
		void add_unwind_info_rvas(const portable_executable::unwind_info_t* unwind_info);
		void add_exception_rvas(const portable_executable::nt_headers_t* nt_headers);
		void find_data_rvas() override;
		void finalize_before_recompile() override;
	};
}
