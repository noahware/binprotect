#include "pe.hpp"
#include "../../block/basic_block.hpp"
#include "../../util/serialize.hpp"

#include <spdlog/spdlog.h>
#include <algorithm>

using reloc_pages_t = std::map<std::uint32_t, std::vector<portable_executable::relocation_entry_descriptor_t>>;

std::uint64_t binwrite::portable_executable_t::image_base() const
{
	const auto img = image();

	return img->nt_headers()->optional_header.image_base;
}

binwrite::rva_t binwrite::portable_executable_t::entry_point() const
{
	const auto img = image();

	return rva_t{ img->nt_headers()->optional_header.address_of_entry_point };
}

std::size_t binwrite::portable_executable_t::section_alignment() const
{
	const auto img = image();

	return img->nt_headers()->optional_header.section_alignment;
}

void binwrite::portable_executable_t::decompress()
{
	const auto img = image();
	const auto nt_headers = img->nt_headers();

	std::vector<std::uint8_t> new_buffer(nt_headers->optional_header.size_of_image);

	copy_sections(new_buffer, true);

	buffer_ = std::move(new_buffer);
}

void binwrite::portable_executable_t::compress()
{
	const auto img = image();
	const auto nt_headers = img->nt_headers();

	const auto section_headers = nt_headers->section_headers();
	const std::uint16_t section_count = nt_headers->file_header.number_of_sections;

	const auto last_section = &section_headers[section_count - 1];
	const std::uint32_t raw_size = last_section->pointer_to_raw_data + last_section->size_of_raw_data;

	std::vector<std::uint8_t> new_buffer(raw_size);

	copy_sections(new_buffer, false);

	buffer_ = std::move(new_buffer);
}

portable_executable::image_t* binwrite::portable_executable_t::image()
{
	return reinterpret_cast<portable_executable::image_t*>(data());
}

const portable_executable::image_t* binwrite::portable_executable_t::image() const
{
	return reinterpret_cast<const portable_executable::image_t*>(data());
}

bool binwrite::portable_executable_t::has_exceptions_directory() const
{
	const auto img = image();
	const auto& data_directories = img->nt_headers()->optional_header.data_directories;

	return data_directories.exception_directory.present();
}

bool binwrite::portable_executable_t::is_inside_runtime_function(rva_t rva) const
{
	return std::ranges::any_of(runtime_functions_,
		[rva](const runtime_function_t& runtime_function)
		{
			return *runtime_function.begin <= rva && rva < *runtime_function.end;
		}
	);
}

static reloc_pages_t collect_reloc_pages(const std::span<const std::shared_ptr<binwrite::relocation_t>> relocations)
{
	reloc_pages_t reloc_pages;

	for (const auto& relocation : relocations)
	{
		const auto target_rva = relocation->target()->rva();

		if (!target_rva)
		{
			continue;
		}

		const auto pfn = target_rva->value() >> 12;

		auto& page_entry = reloc_pages[pfn];

		const std::uint16_t offset = target_rva->value() & 0xFFF;

		page_entry.emplace_back(offset, static_cast<portable_executable::relocation_type_t>(relocation->type()));
	}

	return reloc_pages;
}

static void compile_relocation_block_descriptor(std::vector<std::uint8_t>& bytes, const std::uint32_t page_frame_number, const std::uint16_t entry_count)
{
	constexpr std::uint32_t descriptor_size = sizeof(portable_executable::raw_relocation_block_descriptor_t);
	const std::uint32_t entries_size = entry_count * sizeof(portable_executable::relocation_entry_descriptor_t);

	const std::uint32_t block_size = descriptor_size + entries_size;

	const std::uint32_t block_virtual_address = page_frame_number << 12;

	const portable_executable::raw_relocation_block_descriptor_t block_descriptor = {
			.virtual_address = block_virtual_address,
			.size_of_block = block_size
	};

	const auto serialized_block_descriptor = binwrite::util::serialize_bytes(block_descriptor);

	bytes.insert(bytes.end(), serialized_block_descriptor.begin(), serialized_block_descriptor.end());
}

static void process_relocation_block_padding(std::vector<portable_executable::relocation_entry_descriptor_t>& entry_descriptors)
{
	const std::uint64_t entry_count = entry_descriptors.size();

	if (entry_count % 2 != 0)
	{
		constexpr portable_executable::relocation_entry_descriptor_t padding_entry = {
			.offset = 0, .type = portable_executable::relocation_type_t::absolute
		};

		entry_descriptors.push_back(padding_entry);
	}
}

static std::vector<std::uint8_t> compile_relocation_directory(reloc_pages_t& reloc_pages)
{
	std::vector<std::uint8_t> bytes = { };

	for (auto& [pfn, entry_descriptors] : reloc_pages)
	{
		process_relocation_block_padding(entry_descriptors);

		const std::uint16_t entry_count = static_cast<std::uint16_t>(entry_descriptors.size());

		compile_relocation_block_descriptor(bytes, pfn, entry_count);

		for (const auto& entry_descriptor : entry_descriptors)
		{
			const auto serialized_entry_descriptor = binwrite::util::serialize_bytes(entry_descriptor);

			bytes.insert(bytes.end(), serialized_entry_descriptor.begin(), serialized_entry_descriptor.end());
		}
	}

	return bytes;
}

void binwrite::portable_executable_t::update_relocations()
{
	const auto relocation_directory_header = image()->nt_headers()->optional_header.data_directories.basereloc_directory;

	if (!relocation_directory_header.present())
	{
		return;
	}

	const rva_t directory_rva(relocation_directory_header.virtual_address);

	// <pfn, list of relocs for that page>
	reloc_pages_t reloc_pages = collect_reloc_pages(relocations_);

	const auto new_directory = compile_relocation_directory(reloc_pages);

	const rva_t erasal_rva(directory_rva.value() + static_cast<std::uint32_t>(new_directory.size()));

	insert(directory_rva, new_directory);
	erase(erasal_rva, static_cast<rva_t::size_type>(relocation_directory_header.size));

	image()->nt_headers()->optional_header.data_directories.basereloc_directory.size = static_cast<std::uint32_t>(new_directory.size());
}

bool binwrite::portable_executable_t::is_definitely_in_code_range(const rva_t rva) const
{
	if (find_function(rva))
	{
		return true;
	}

	return is_inside_runtime_function(rva);
}
