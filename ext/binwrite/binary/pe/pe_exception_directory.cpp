#include "pe_exceptions.hpp"
#include "cxx_frame_handler3.hpp"
#include "cxx_frame_handler4.hpp"
#include "../rva/rva.hpp"
#include "../../disassembler/disassembler.hpp"

#include <portable-executable/image.hpp>
#include <spdlog/spdlog.h>

#include <set>

using namespace binwrite;

portable_executable::unwind_register_t binwrite::get_unwind_register(const register_t reg)
{
	const auto rax = register_t::rax;
	const auto qword = reg.family().qword;

	return static_cast<portable_executable::unwind_register_t>(qword.value() - rax.value());
}

static void process_unwind_info(binary_t& binary, const rva_t function_rva, const portable_executable::unwind_info_t* const info)
{
	if (info->has_chained_function())
	{
		return;
	}

	binary.create_function(function_rva);
}

static void register_func_info_handler(portable_executable_t& pe,
	const std::int32_t* const rva_field, const std::uint32_t rva_value,
	std::vector<rva_t>& vec)
{
	pe.add_data_rva_ref(rva_field);
	pe.add_to_disassembly_queue(pe.add_rva(rva_value));
	vec.emplace_back(rva_value);
}

struct c_scope_table_entry_t
{
	std::uint32_t begin_rva;
	std::uint32_t end_rva;
	std::uint32_t handler_rva;
	std::uint32_t target_rva;
};

struct c_scope_table_t
{
	std::uint32_t entry_count;
	c_scope_table_entry_t table[1];
};

static bool parse_c_scope_table(portable_executable_t& pe, const std::uint32_t* const language_data,
	std::vector<exception_context_t::function_range_t>& seh_code_ranges,
	std::vector<rva_t>& func_handlers)
{
	const auto scope_table = reinterpret_cast<const c_scope_table_t*>(language_data);

	if (!scope_table->entry_count || 0x1000 <= scope_table->entry_count)
	{
		return false;
	}

	for (std::uint32_t i = 0; i < scope_table->entry_count; i++)
	{
		const auto table_entry = &scope_table->table[i];

		if (!pe.is_rva_valid(table_entry->begin_rva) ||
			!pe.is_rva_valid(table_entry->end_rva) ||
			!pe.is_rva_valid(table_entry->handler_rva) ||
			!pe.is_rva_valid(table_entry->target_rva))
		{
			return false;
		}

		seh_code_ranges.push_back({
			.begin = pe.add_rva(table_entry->begin_rva),
			.end = pe.add_rva(table_entry->end_rva)
			});

		if (pe.is_in_code_section(rva_t{ table_entry->begin_rva }))
		{
			pe.add_data_rva_ref(&table_entry->begin_rva);
		}

		if (pe.is_in_code_section(rva_t{ table_entry->end_rva }))
		{
			pe.add_data_rva_ref(&table_entry->end_rva);
		}

		if (pe.is_in_code_section(rva_t{ table_entry->handler_rva }))
		{
			pe.add_data_rva_ref(&table_entry->handler_rva);

			pe.add_to_disassembly_queue(pe.add_rva(table_entry->handler_rva));
		}

		if (pe.is_in_code_section(rva_t{ table_entry->target_rva }))
		{
			pe.add_data_rva_ref(&table_entry->target_rva);

			pe.add_to_disassembly_queue(pe.add_rva(table_entry->target_rva));
			func_handlers.emplace_back(table_entry->target_rva);
		}
	}

	return true;
}

static void register_func_info_refs(portable_executable_t& pe, const cfh4::func_info4_t& func_info,
	const std::uint32_t data_rva)
{
	const auto program_start_rva = pe.add_rva(0);

	if (func_info.unwind_map_ref.ptr)
	{
		pe.add_data_rva_ref(reinterpret_cast<const std::int32_t*>(func_info.unwind_map_ref.ptr));
	}

	if (func_info.try_block_map_ref.ptr)
	{
		pe.add_data_rva_ref(reinterpret_cast<const std::int32_t*>(func_info.try_block_map_ref.ptr));
	}

	if (func_info.ip_to_state_map_ref.ptr)
	{
		pe.add_data_rva_ref(reinterpret_cast<const std::int32_t*>(func_info.ip_to_state_map_ref.ptr));
	}

	if (func_info.disp_frame_ref.ptr && func_info.header.is_catch)
	{
		const rva_t::value_type rva = static_cast<rva_t::value_type>(func_info.disp_frame_ref.ptr - pe.data());

		std::array<std::uint8_t, 5> encoded_bytes = { };
		std::memcpy(encoded_bytes.data(), func_info.disp_frame_ref.ptr, sizeof(encoded_bytes));

		std::uint8_t* bytes_buffer = encoded_bytes.data();
		std::uint8_t* start_buffer = bytes_buffer;

		const auto target = pe.add_rva(cfh4::read_unsigned(&bytes_buffer));
		const std::uint32_t encoded_size = static_cast<std::uint32_t>(bytes_buffer - start_buffer);

		std::shared_ptr<rva_t> chunk_rva = pe.add_rva(data_rva);

		pe.add_rva_ref(std::make_shared<pe_fh4_encoded_entry_t>(chunk_rva, program_start_rva, encoded_size, target, rva_t{ rva }));
	}
}

static void parse_ip_to_state_map(portable_executable_t& pe,
	const cfh4::func_info4_t& func_info,
	const std::uint64_t image_base,
	const std::int32_t function_start,
	const std::uint32_t begin_address)
{
	cfh4::ip_to_state_map4_t ip2state_map(&func_info, image_base, function_start);

	std::shared_ptr<rva_t> chunk_rva = pe.add_rva(func_info.disp_ip_to_state_map);
	std::shared_ptr<rva_t> prev_ip2state = pe.add_rva(begin_address);

	for (auto entry : ip2state_map)
	{
		const rva_t::value_type rva = static_cast<rva_t::value_type>(entry.ip_ref.ptr - pe.data());

		const auto ip2rva = std::make_shared<pe_fh4_encoded_entry_t>(chunk_rva, prev_ip2state, entry.ip_ref.size, pe.add_rva(entry.ip), rva_t{ rva });

		pe.add_rva_ref(ip2rva);

		prev_ip2state = ip2rva->target();
	}
}

static bool parse_try_block_handlers(portable_executable_t& pe,
	const cfh4::func_info4_t& func_info,
	const std::uint64_t image_base,
	const std::int32_t function_start,
	const std::uint32_t begin_address,
	std::vector<rva_t>& func_handlers,
	std::vector<rva_t>& catch_handlers,
	bool& catches_seh)
{
	cfh4::try_block_map4_t try_block_map(&func_info, image_base);

	for (auto entry : try_block_map)
	{
		pe.add_data_rva_ref(reinterpret_cast<std::int32_t*>(entry.disp_handler_array_ref.ptr));

		if (!pe.is_in_data_section(rva_t{ static_cast<rva_t::value_type>(entry.disp_handler_array) }))
		{
			return false;
		}

		std::shared_ptr<rva_t> chunk_rva = pe.add_rva(func_info.disp_try_block_map);

		cfh4::handler_map4_t handler_map(&entry, image_base, function_start);

		for (auto handler_entry : handler_map)
		{
			if (handler_entry.disp_type)
			{
				pe.add_data_rva_ref(reinterpret_cast<std::int32_t*>(handler_entry.disp_type_ref.ptr));
			}
			else // catches SEH if type == 0
			{
				catches_seh = true;
			}
			
			pe.add_data_rva_ref(reinterpret_cast<std::int32_t*>(handler_entry.disp_of_handler_ref.ptr));

			const auto first_cont_ptr = handler_entry.disp_of_handler_ref.ptr + 4;
			std::shared_ptr<rva_t> function_rva = pe.add_rva(begin_address);

			if (handler_entry.header.cont_is_rva)
			{
				func_handlers.emplace_back(static_cast<std::uint32_t>(handler_entry.continuation_address[0]));
				pe.add_to_disassembly_queue(pe.add_rva(static_cast<std::uint32_t>(handler_entry.continuation_address[0])));

				if (handler_entry.header.cont_type() == cfh4::handler_type_header_t::cont_type_t::one)
				{
					pe.add_data_rva_ref(reinterpret_cast<std::int32_t*>(first_cont_ptr));
				}
				else if (handler_entry.header.cont_type() == cfh4::handler_type_header_t::cont_type_t::two)
				{
					pe.add_data_rva_ref(reinterpret_cast<std::int32_t*>(first_cont_ptr));
					pe.add_data_rva_ref(reinterpret_cast<std::int32_t*>(first_cont_ptr + 4));

					func_handlers.emplace_back(static_cast<std::uint32_t>(handler_entry.continuation_address[1]));
					pe.add_to_disassembly_queue(pe.add_rva(static_cast<std::uint32_t>(handler_entry.continuation_address[1])));
				}
			}
			else
			{
				func_handlers.emplace_back(static_cast<std::uint32_t>(handler_entry.continuation_address[0]));
				pe.add_to_disassembly_queue(pe.add_rva(static_cast<std::uint32_t>(handler_entry.continuation_address[0])));

				const auto first_cont_rva = pe.add_rva(static_cast<std::uint32_t>(handler_entry.continuation_address[0]));

				if (handler_entry.header.cont_type() == cfh4::handler_type_header_t::cont_type_t::one)
				{
					const rva_t::value_type rva = static_cast<rva_t::value_type>(first_cont_ptr - pe.data());
					const auto cont_size = handler_entry.cont_ref[0].size;

					pe.add_rva_ref(std::make_shared<pe_fh4_encoded_entry_t>(chunk_rva, function_rva, cont_size, first_cont_rva, rva_t{ rva }));
				}
				else if (handler_entry.header.cont_type() == cfh4::handler_type_header_t::cont_type_t::two)
				{
					const rva_t::value_type rva = static_cast<rva_t::value_type>(first_cont_ptr - pe.data());
					const auto first_size = handler_entry.cont_ref[0].size;
					const auto second_size = handler_entry.cont_ref[1].size;

					const auto second_cont_rva = pe.add_rva(static_cast<std::uint32_t>(handler_entry.continuation_address[1]));

					pe.add_rva_ref(std::make_shared<pe_fh4_encoded_entry_t>(chunk_rva, function_rva, first_size, first_cont_rva, rva_t{ rva }));
					pe.add_rva_ref(std::make_shared<pe_fh4_encoded_entry_t>(chunk_rva, function_rva, second_size, second_cont_rva, rva_t{ rva + first_size }));

					func_handlers.emplace_back(static_cast<std::uint32_t>(handler_entry.continuation_address[1]));
					pe.add_to_disassembly_queue(pe.add_rva(static_cast<std::uint32_t>(handler_entry.continuation_address[1])));
				}
			}

			catch_handlers.emplace_back(static_cast<std::uint32_t>(handler_entry.disp_of_handler));
			pe.add_to_disassembly_queue(pe.add_rva(static_cast<std::uint32_t>(handler_entry.disp_of_handler)));

			spdlog::info("catch handler 0x{:X}", handler_entry.disp_of_handler);
		}
	}

	return true;
}

static bool parse_cxx_funcinfo4(portable_executable_t& pe,
	const portable_executable::runtime_function_t* const runtime_function,
	const std::uint32_t* const language_data,
	std::vector<rva_t>& func_handlers,
	std::vector<rva_t>& catch_handlers,
	bool& catches_seh)
{
	const auto& buffer = pe.buffer();
	const auto data_rva = language_data;

	if (static_cast<std::int64_t>(buffer.size()) <= *data_rva)
	{
		return false;
	}

	const auto data = pe.data() + *data_rva;

	pe.add_data_rva_ref(data_rva);

	cfh4::func_info4_t func_info;
	const std::uint64_t image_base = reinterpret_cast<std::uint64_t>(pe.data());
	const std::int32_t function_start = static_cast<std::int32_t>(runtime_function->begin_address);

	const auto header_size = cfh4::decompress_func_info(data, func_info, image_base, static_cast<std::int32_t>(pe.size()), function_start);

	if (header_size == -1)
	{
		return false;
	}

	if (func_info.header.has_try_block_map && func_info.disp_try_block_map)
	{
		if (!pe.is_in_data_section(rva_t{ static_cast<rva_t::value_type>(func_info.disp_try_block_map) }) ||
			!parse_try_block_handlers(pe, func_info, image_base, function_start,
				runtime_function->begin_address, func_handlers, catch_handlers,
				catches_seh)
			)
		{
			return false;
		}
	}

	register_func_info_refs(pe, func_info, *data_rva);

	if (func_info.disp_ip_to_state_map)
	{
		if (!pe.is_in_data_section(rva_t{ static_cast<rva_t::value_type>(func_info.disp_ip_to_state_map) }))
		{
			return false;
		}

		parse_ip_to_state_map(pe, func_info, image_base, function_start, runtime_function->begin_address);
	}

	if (func_info.disp_unwind_map)
	{
		if (!pe.is_in_data_section(rva_t{ static_cast<rva_t::value_type>(func_info.disp_ip_to_state_map) }))
		{
			return false;
		}

		cfh4::unwind_map4_t unwind_map(&func_info, image_base);

		for (const auto entry : unwind_map)
		{
			if (entry.action)
			{
				register_func_info_handler(pe,
					reinterpret_cast<const std::int32_t*>(entry.action_ref.ptr),
					static_cast<std::uint32_t>(entry.action),
					catch_handlers);
			}
		}
	}

	return true;
}

static bool parse_cxx_funcinfo3(portable_executable_t& pe,
	const std::uint32_t* const language_data,
	std::vector<rva_t>& catch_handlers,
	bool& catches_seh)
{
	const auto& buffer = pe.buffer();
	const auto data_rva = *language_data;

	if (static_cast<std::int64_t>(buffer.size()) < static_cast<std::int64_t>(data_rva) + static_cast<std::int64_t>(sizeof(cfh3::func_info_t)))
	{
		return false;
	}

	const auto* const func_info = reinterpret_cast<const cfh3::func_info_t*>(pe.data() + data_rva);

	if (!cfh3::is_fh3_magic(func_info->magic_and_bbt))
	{
		return false;
	}

	const auto in_bounds = [&buffer](const std::int64_t offset, const std::int64_t size) -> bool
		{
			return 0 <= offset && offset + size <= static_cast<std::int64_t>(buffer.size());
		};

	pe.add_data_rva_ref(language_data);

	if (func_info->disp_unwind_map)
	{
		pe.add_data_rva_ref(&func_info->disp_unwind_map);
	}

	if (func_info->disp_try_block_map)
	{
		pe.add_data_rva_ref(&func_info->disp_try_block_map);
	}

	if (func_info->disp_ip_to_state_map)
	{
		pe.add_data_rva_ref(&func_info->disp_ip_to_state_map);
	}

	if (func_info->disp_es_type_list)
	{
		pe.add_data_rva_ref(&func_info->disp_es_type_list);
	}

	if (func_info->disp_unwind_map && 0 < func_info->max_state)
	{
		const std::int64_t base = func_info->disp_unwind_map;
		const std::int64_t total = static_cast<std::int64_t>(func_info->max_state) * static_cast<std::int64_t>(sizeof(cfh3::unwind_map_entry_t));

		if (!in_bounds(base, total))
		{
			return false;
		}

		for (std::int32_t i = 0; i < func_info->max_state; i++)
		{
			const auto* const entry = reinterpret_cast<const cfh3::unwind_map_entry_t*>(
				pe.data() + base + static_cast<std::int64_t>(i) * sizeof(cfh3::unwind_map_entry_t));

			if (entry->action)
			{
				register_func_info_handler(pe, &entry->action, static_cast<std::uint32_t>(entry->action), catch_handlers);
			}
		}
	}

	if (func_info->disp_try_block_map && func_info->n_try_blocks)
	{
		const std::int64_t base = func_info->disp_try_block_map;
		const std::int64_t total = static_cast<std::int64_t>(func_info->n_try_blocks) * static_cast<std::int64_t>(sizeof(cfh3::try_block_map_entry_t));

		if (!in_bounds(base, total))
		{
			return false;
		}

		for (std::uint32_t i = 0; i < func_info->n_try_blocks; i++)
		{
			const auto* const entry = reinterpret_cast<const cfh3::try_block_map_entry_t*>(
				pe.data() + base + static_cast<std::int64_t>(i) * sizeof(cfh3::try_block_map_entry_t));

			if (!entry->disp_handler_array || entry->n_catches <= 0)
			{
				continue;
			}

			pe.add_data_rva_ref(&entry->disp_handler_array);

			const std::int64_t handler_base = entry->disp_handler_array;
			const std::int64_t handler_total = static_cast<std::int64_t>(entry->n_catches) * static_cast<std::int64_t>(sizeof(cfh3::handler_type_t));

			if (!in_bounds(handler_base, handler_total))
			{
				return false;
			}

			for (std::int32_t j = 0; j < entry->n_catches; j++)
			{
				const auto* const handler = reinterpret_cast<const cfh3::handler_type_t*>(
					pe.data() + handler_base + static_cast<std::int64_t>(j) * sizeof(cfh3::handler_type_t));

				if (handler->disp_type)
				{
					pe.add_data_rva_ref(&handler->disp_type);
				}
				else // catches SEH if type == 0
				{
					catches_seh = true;
				}

				if (handler->disp_of_handler)
				{
					register_func_info_handler(pe, &handler->disp_of_handler,
						static_cast<std::uint32_t>(handler->disp_of_handler), catch_handlers);

					spdlog::info("catch handler 0x{:X}", handler->disp_of_handler);
				}
			}
		}
	}

	if (func_info->disp_ip_to_state_map && func_info->n_ip_map_entries)
	{
		const std::int64_t base = func_info->disp_ip_to_state_map;
		const std::int64_t total = static_cast<std::int64_t>(func_info->n_ip_map_entries) * static_cast<std::int64_t>(sizeof(cfh3::ip_to_state_entry_t));

		if (!in_bounds(base, total))
		{
			return false;
		}

		for (std::uint32_t i = 0; i < func_info->n_ip_map_entries; i++)
		{
			const auto* const entry = reinterpret_cast<const cfh3::ip_to_state_entry_t*>(
				pe.data() + base + static_cast<std::int64_t>(i) * sizeof(cfh3::ip_to_state_entry_t));

			pe.add_data_rva_ref(&entry->ip);
		}
	}

	return true;
}

exception_context_t binwrite::parse_exception_directory(portable_executable_t& pe)
{
	exception_context_t context;

	const auto image = pe.image();

	if (portable_executable::data_directory_t data_directory = image->nt_headers()->optional_header.data_directories.
		exception_directory; data_directory.present())
	{
		context.exception_directory_rva = pe.add_rva(data_directory.virtual_address);

		const std::uint32_t count = data_directory.size / sizeof(portable_executable::runtime_function_t);
		auto runtime_function = reinterpret_cast<const portable_executable::runtime_function_t*>(pe.data() + data_directory.virtual_address);

		for (std::uint32_t i = 0; i < count; i++, runtime_function++)
		{
			pe.add_data_rva_ref(&runtime_function->begin_address);
			pe.add_data_rva_ref(&runtime_function->end_address);
			pe.add_data_rva_ref(&runtime_function->unwind_info_rva);

			pe.add_to_disassembly_queue(pe.add_rva(runtime_function->begin_address));

			const auto unwind_info = reinterpret_cast<const portable_executable::unwind_info_t*>(pe.data() + runtime_function->unwind_info_rva);

			process_unwind_info(pe, rva_t{ runtime_function->begin_address }, unwind_info);

			if (unwind_info->size_of_prolog)
			{
				context.fh_prologues.push_back({ .begin = pe.add_rva(runtime_function->begin_address), .prolog_size = unwind_info->size_of_prolog });
			}

			if (unwind_info->has_chained_function())
			{
				const auto chained_function = unwind_info->language_specific_data<portable_executable::runtime_function_t>();
				pe.add_to_disassembly_queue(pe.add_rva(chained_function->begin_address));

				pe.add_data_rva_ref(&chained_function->begin_address);
				pe.add_data_rva_ref(&chained_function->end_address);
				pe.add_data_rva_ref(&chained_function->unwind_info_rva);
			}

			if (unwind_info->has_handler())
			{
				const auto handler = unwind_info->language_specific_data<std::uint32_t>();
				const auto language_data = unwind_info->language_specific_data<std::uint32_t>() + 1;
				const auto handler_rva = pe.add_rva(*handler);

				pe.add_data_rva_ref(handler);
				pe.create_function(*handler_rva);

				context.handler_function_rvas.push_back(pe.add_rva(runtime_function->begin_address));
				context.handler_function_rvas.push_back(handler_rva);

				bool fh_catches_seh = false;

				const auto current_function_range = [&]() -> exception_context_t::function_range_t
					{
						return { .begin = pe.add_rva(runtime_function->begin_address), .end =
							pe.add_rva(runtime_function->end_address) };
					};

				if (parse_c_scope_table(pe, language_data, context.seh_code_ranges,
					context.func_handlers[runtime_function->begin_address]))
				{
					spdlog::info("successfully parsed C_SCOPE_TABLE at 0x{:X}", runtime_function->unwind_info_rva);
				}
				else if (parse_cxx_funcinfo3(pe, language_data,
					context.catch_handlers[runtime_function->begin_address],
					fh_catches_seh))
				{
					spdlog::info("successfully parsed FuncInfo3 at 0x{:X}", runtime_function->unwind_info_rva);

					context.fh_function_ranges.push_back(current_function_range());
				}
				else if (parse_cxx_funcinfo4(pe, runtime_function, language_data,
					context.func_handlers[runtime_function->begin_address],
					context.catch_handlers[runtime_function->begin_address],
					fh_catches_seh))
				{
					spdlog::info("successfully parsed FuncInfo4 at 0x{:X}", runtime_function->unwind_info_rva);

					context.fh_function_ranges.push_back(current_function_range());
				}

				if (fh_catches_seh)
				{
					context.seh_code_ranges.push_back(current_function_range());
				}
			}
		}
	}

	return context;
}
