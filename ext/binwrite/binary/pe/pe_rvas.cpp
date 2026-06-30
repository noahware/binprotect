#include "pe.hpp"

#include <spdlog/spdlog.h>

void binwrite::portable_executable_t::add_load_config_table_rvas(
	const portable_executable::load_config_directory_t::table_t& table)
{
	if (table.virtual_address)
	{
		const rva_t entries_rva(static_cast<rva_t::value_type>(table.virtual_address - image_base()));

		auto entry = reinterpret_cast<const std::uint32_t*>(data() + entries_rva.value());

		for (std::size_t i = 0; i < table.size; i++, entry++)
		{
			add_data_rva_ref(entry);
		}
	}
}

void binwrite::portable_executable_t::add_load_config_rvas(const portable_executable::image_t* const img)
{
	const auto load_config = img->load_config();

	if (!load_config)
	{
		return;
	}

	if (load_config->dynamic_value_reloc_table_rva)
	{
		add_data_rva_ref(&load_config->dynamic_value_reloc_table_rva);
	}

	if (load_config->hot_patch_table_rva)
	{
		add_data_rva_ref(&load_config->hot_patch_table_rva);
	}

	add_load_config_table_rvas(load_config->guard_cf_function_table);
	add_load_config_table_rvas(load_config->se_handler_table);
	add_load_config_table_rvas(load_config->guard_address_taken_iat_entry_table);
	add_load_config_table_rvas(load_config->guard_long_jump_target_table);
	add_load_config_table_rvas(load_config->guard_eh_continuation_table);
}

void binwrite::portable_executable_t::add_misc_rvas(const portable_executable::nt_headers_t* const nt_headers)
{
	const auto entry_point_ptr = &nt_headers->optional_header.address_of_entry_point;

	if (*entry_point_ptr)
	{
		add_to_disassembly_queue(add_rva(*entry_point_ptr));

		add_data_rva_ref(entry_point_ptr);
	}
}

void binwrite::portable_executable_t::add_data_directory_rvas(const portable_executable::nt_headers_t* const nt_headers)
{
	for (const auto& directory : nt_headers->optional_header.data_directories.entries)
	{
		if (!directory.present())
		{
			continue;
		}

		add_data_rva_ref(&directory.virtual_address);
	}
}

void binwrite::portable_executable_t::add_resource_rvas(const portable_executable::nt_headers_t* const nt_headers)
{
	const auto resource_directory_header = nt_headers->optional_header.data_directories.resource_directory;

	if (!resource_directory_header.present())
	{
		return;
	}

	const auto directory = reinterpret_cast<const portable_executable::resource_directory_t*>(data() + resource_directory_header.virtual_address);

	parse_resource_directory_rvas(directory, directory);
}

void binwrite::portable_executable_t::parse_resource_directory_rvas(const portable_executable::resource_directory_t* const root_directory, const portable_executable::resource_directory_t* const directory, const std::uint16_t depth)
{
	for (const portable_executable::resource_directory_entry_t* entry = directory->begin(); entry != directory->end(); entry++)
	{
		if (entry->is_directory())
		{
			parse_resource_directory_rvas(root_directory, entry->as_directory(root_directory), depth + 1);
		}
		else // is data
		{
			const auto data_entry = entry->as_data(root_directory);

			add_data_rva_ref(&data_entry->data_rva);
		}
	}
}

void binwrite::portable_executable_t::add_import_rvas(const portable_executable::nt_headers_t* const nt_headers)
{
	const auto import_directory_header = nt_headers->optional_header.data_directories.import_directory;

	if (!import_directory_header.present())
	{
		return;
	}

	auto import_descriptor = reinterpret_cast<const portable_executable::import_descriptor_t*>(data() + import_directory_header.virtual_address);

	while (import_descriptor->misc.characteristics)
	{
		add_data_rva_ref(&import_descriptor->misc.original_first_thunk);
		add_data_rva_ref(&import_descriptor->first_thunk);
		add_data_rva_ref(&import_descriptor->name);

		const auto original_thunk = reinterpret_cast<const portable_executable::thunk_data_t*>(data() + import_descriptor->misc.original_first_thunk);

		parse_import_thunk_rvas(original_thunk);

		import_descriptor++;
	}
}

void binwrite::portable_executable_t::add_delay_import_rvas(const portable_executable::nt_headers_t* const nt_headers)
{
	const auto delay_import_directory_header = nt_headers->optional_header.data_directories.delay_import_directory;

	if (!delay_import_directory_header.present())
	{
		return;
	}

	auto import_descriptor = reinterpret_cast<const portable_executable::delay_load_descriptor_t*>(data() + delay_import_directory_header.virtual_address);

	while (import_descriptor->import_address_table_rva)
	{
		add_data_rva_ref(&import_descriptor->dll_name_rva);
		add_data_rva_ref(&import_descriptor->module_handle_rva);
		add_data_rva_ref(&import_descriptor->import_address_table_rva);
		add_data_rva_ref(&import_descriptor->import_name_table_rva);
		add_data_rva_ref(&import_descriptor->bound_import_address_table_rva);
		add_data_rva_ref(&import_descriptor->unload_information_table_rva);

		const auto original_thunk = reinterpret_cast<const portable_executable::thunk_data_t*>(data() + import_descriptor->import_name_table_rva);

		parse_import_thunk_rvas(original_thunk);

		import_descriptor++;
	}
}

void binwrite::portable_executable_t::parse_import_thunk_rvas(const portable_executable::thunk_data_t* original_thunk)
{
	while (original_thunk->function)
	{
		if (!original_thunk->is_ordinal)
		{
			add_data_rva_ref(&original_thunk->address);
		}

		original_thunk++;
	}
}

void binwrite::portable_executable_t::add_debug_rvas(const portable_executable::nt_headers_t* const nt_headers)
{
	const auto debug_directory_header = nt_headers->optional_header.data_directories.debug_directory;

	if (!debug_directory_header.present())
	{
		return;
	}

	const std::uint32_t entry_count = debug_directory_header.size / sizeof(portable_executable::debug_directory_t);

	auto entry = reinterpret_cast<portable_executable::debug_directory_t*>(data() + debug_directory_header.virtual_address);
	const auto end = entry + entry_count;

	while (entry < end)
	{
		add_data_rva_ref(&entry->virtual_address);

		// todo: remove when starting to use compression
		entry->pointer_to_raw_data = entry->virtual_address;
		add_data_rva_ref(&entry->pointer_to_raw_data);

		entry++;
	}
}

void binwrite::portable_executable_t::add_export_rvas(const portable_executable::nt_headers_t* const nt_headers)
{
	const auto export_directory_header = nt_headers->optional_header.data_directories.export_directory;

	if (!export_directory_header.present())
	{
		return;
	}

	const auto export_directory = reinterpret_cast<const portable_executable::export_directory_t*>(data() + export_directory_header.virtual_address);

	if (export_directory->name)
	{
		add_data_rva_ref(&export_directory->name);
	}

	add_data_rva_ref(&export_directory->address_of_functions);
	add_data_rva_ref(&export_directory->address_of_names);
	add_data_rva_ref(&export_directory->address_of_name_ordinals);

	const auto functions = reinterpret_cast<const std::uint32_t*>(data() + export_directory->address_of_functions);
	const auto names = reinterpret_cast<const std::uint32_t*>(data() + export_directory->address_of_names);
	const auto name_ordinals = reinterpret_cast<const std::uint16_t*>(data() + export_directory->address_of_name_ordinals);

	for (std::uint32_t i = 0; i < export_directory->number_of_names; i++)
	{
		const auto current_ordinal = name_ordinals[i];
		const auto current_function_ptr = &functions[current_ordinal];

		add_data_rva_ref(current_function_ptr);
		add_data_rva_ref(&names[i]);

		add_to_disassembly_queue(add_rva(*current_function_ptr));
	}
}

void binwrite::portable_executable_t::add_relocation_rvas(const portable_executable::nt_headers_t* const nt_headers)
{
	const auto relocation_directory_header = nt_headers->optional_header.data_directories.basereloc_directory;

	if (!relocation_directory_header.present())
	{
		return;
	}

	auto block_descriptor = reinterpret_cast<const portable_executable::raw_relocation_block_descriptor_t*>(data() + relocation_directory_header.virtual_address);

	while (block_descriptor->virtual_address)
	{
		const std::uint32_t size = block_descriptor->size_of_block - sizeof(*block_descriptor);
		const std::uint32_t entry_count = size / sizeof(portable_executable::relocation_entry_descriptor_t);

		auto entry_descriptor = reinterpret_cast<const portable_executable::relocation_entry_descriptor_t*>(block_descriptor + 1);

		for (std::uint32_t i = 0; i < entry_count; i++, entry_descriptor++)
		{
			const auto rva = add_relocation_rva(block_descriptor->virtual_address + entry_descriptor->offset);
			const auto type = entry_descriptor->type;

			if (type == portable_executable::relocation_type_t::absolute)
			{
				continue;
			}

			relocations_.push_back(std::make_shared<pe_relocation_t>(find_or_split_symbol(*rva), type));

			if (type == portable_executable::relocation_type_t::dir64)
			{
				const auto image_offsetted_target = *reinterpret_cast<std::uint64_t*>(data() + rva->value());

				const auto target_rva = add_rva(static_cast<std::uint32_t>(image_offsetted_target - image_base()));

				if (is_in_code_section(*target_rva))
				{
					const bool risky = !static_cast<bool>(find_function(*target_rva)) || is_inside_runtime_function(*target_rva);

					add_to_disassembly_queue(target_rva, risky);
				}

				add_rva_ref(std::make_shared<pe_dir64_reloc_t>(target_rva, *rva));
			}
			else
			{
				spdlog::warn("non-dir64 relocation found");
			}
		}

		block_descriptor = reinterpret_cast<decltype(block_descriptor)>(reinterpret_cast<const std::uint8_t*>(block_descriptor) + block_descriptor->size_of_block);
	}
}

void binwrite::portable_executable_t::add_unwind_info_rvas(const portable_executable::unwind_info_t* const unwind_info)
{
	if (unwind_info->has_chained_function())
	{
		const auto* const chained = unwind_info->language_specific_data<portable_executable::runtime_function_t>();

		add_data_rva_ref(&chained->begin_address);
		add_data_rva_ref(&chained->end_address);
		add_data_rva_ref(&chained->unwind_info_rva, false, 4);
	}
	else if (unwind_info->has_handler())
	{
		const auto* const handler_rva = unwind_info->language_specific_data<std::uint32_t>();

		add_data_rva_ref(handler_rva);
	}
}

void binwrite::portable_executable_t::add_exception_rvas(const portable_executable::nt_headers_t* nt_headers)
{
	const auto data_directory = nt_headers->optional_header.data_directories.exception_directory;

	if (!data_directory.present())
	{
		return;
	}

	const std::uint32_t count = data_directory.size / sizeof(portable_executable::runtime_function_t);
	const auto* runtime_function = reinterpret_cast<const portable_executable::runtime_function_t*>(data() + data_directory.virtual_address);

	for (std::uint32_t i = 0; i < count; i++, runtime_function++)
	{
		if (runtime_function->begin_address < runtime_function->end_address)
		{
			runtime_functions_.push_back({
				.begin = add_rva(runtime_function->begin_address),
				.end = add_rva(runtime_function->end_address)
			});
		}

		add_data_rva_ref(&runtime_function->begin_address);
		add_data_rva_ref(&runtime_function->end_address);
		add_data_rva_ref(&runtime_function->unwind_info_rva, false, 4);

		if (runtime_function->unwind_info_rva && is_rva_valid(rva_t{ runtime_function->unwind_info_rva }))
		{
			const auto* const unwind_info = reinterpret_cast<const portable_executable::unwind_info_t*>(
				data() + runtime_function->unwind_info_rva);

			add_unwind_info_rvas(unwind_info);
		}
	}
}

void binwrite::portable_executable_t::find_data_rvas()
{
	const auto img = image();
	const auto nt_headers = img->nt_headers();

	add_load_config_rvas(img);
	add_data_directory_rvas(nt_headers);
	add_import_rvas(nt_headers);
	add_delay_import_rvas(nt_headers);
	add_debug_rvas(nt_headers);
	add_export_rvas(nt_headers);
	add_resource_rvas(nt_headers);
	add_exception_rvas(nt_headers);
	add_relocation_rvas(nt_headers);

	add_misc_rvas(nt_headers);
}
