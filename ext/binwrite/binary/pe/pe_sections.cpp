#include "pe.hpp"

void binwrite::portable_executable_t::find_sections()
{
	const auto img = image();

	const auto nt_headers = img->nt_headers();
	const auto section_headers = nt_headers->section_headers();
	const auto section_count = nt_headers->file_header.number_of_sections;

	for (std::uint16_t i = 0; i < section_count; i++)
	{
		const auto section = &section_headers[i];
		const auto next_section = section + 1;

		const auto virtual_address = section->virtual_address;
		const auto next_virtual_address = i + 1 < section_count
			? next_section->virtual_address
			: nt_headers->optional_header.size_of_image;

		const auto section_name = section->to_str();
		const bool code_section = section->characteristics.cnt_code && !section->characteristics.cnt_uninit_data;

		const auto total_size = next_virtual_address - virtual_address;
		const auto padding_size = total_size - section->virtual_size;

		sections_[section_name] = std::make_shared<section_t>(rva_t{ virtual_address }, section->virtual_size, padding_size, code_section);
	}
}

void binwrite::portable_executable_t::copy_sections(std::vector<std::uint8_t>& to, const bool decompress)
{
	const auto img = image();

	for (const auto& section : img->sections())
	{
		const std::uint32_t raw_offset = section.pointer_to_raw_data;
		const std::uint32_t virtual_offset = section.virtual_address;
		const std::uint32_t size = section.size_of_raw_data;

		const auto destination_offset = decompress ? virtual_offset : raw_offset;
		const auto source_offset = decompress ? raw_offset : virtual_offset;

		std::memcpy(to.data() + destination_offset, buffer_.data() + source_offset, size);
	}

	const std::uint32_t size_of_headers = img->nt_headers()->optional_header.size_of_headers;

	std::memcpy(to.data(), buffer_.data(), size_of_headers);
}

binwrite::rva_t::value_type binwrite::portable_executable_t::process_section_alignment(
	const std::shared_ptr<section_t>& info, const std::uint32_t section_alignment)
{
	const rva_t::value_type unaligned_section_end = info->end_rva().value();
	const rva_t::value_type aligned_section_end = portable_executable::image_t::calculate_alignment(unaligned_section_end, section_alignment);

	const rva_t::value_type excess = unaligned_section_end % section_alignment;

	if (!excess)
	{
		return aligned_section_end;
	}

	const rva_t padding_rva(unaligned_section_end - info->padding());

	if (excess <= info->padding())
	{
		const auto excess_begin = buffer_.begin() + padding_rva.value();

		buffer_.erase(excess_begin, excess_begin + static_cast<rva_t::size_type>(excess));

		update_rvas(padding_rva, -static_cast<std::int32_t>(excess), true, false);

		info->remove_padding(excess);

		return unaligned_section_end - excess;
	}

	const auto padding_size = static_cast<std::int32_t>(aligned_section_end - unaligned_section_end);

	const std::uint8_t padding_value = info->code() ? 0xCC : 0x00;

	const auto it = buffer_.begin() + padding_rva.value();

	buffer_.insert(it, padding_size, padding_value);

	update_rvas(padding_rva, padding_size, true, false);

	info->add_padding(padding_size);

	return aligned_section_end;
}

void binwrite::portable_executable_t::update_section_headers()
{
	const std::uint32_t size_of_headers = image()->nt_headers()->optional_header.size_of_headers;
	const std::int64_t headers_size = std::min(static_cast<std::int64_t>(size_of_headers), static_cast<std::int64_t>(buffer_.size()));

	std::vector headers_buffer(buffer_.begin(), buffer_.begin() + headers_size);

	const auto img = reinterpret_cast<portable_executable::image_t*>(headers_buffer.data());
	const auto nt_headers = img->nt_headers();

	rva_t section_rva(0);

	for (auto& section_header : img->sections())
	{
		if (!section_rva.value())
		{
			section_rva.set_value(section_header.virtual_address);
		}

		const auto section_name = section_header.to_str();
		const auto& info = sections_[section_name];

		info->set_rva(section_rva);

		const std::uint32_t section_alignment = nt_headers->optional_header.section_alignment;

		const rva_t aligned_section_end(process_section_alignment(info, section_alignment));

		section_header.virtual_address = section_rva.value();
		section_header.virtual_size = info->size();

		section_header.pointer_to_raw_data = section_header.virtual_address;
		section_header.size_of_raw_data = section_header.virtual_size;

		section_rva = aligned_section_end;
	}

	nt_headers->optional_header.size_of_image = section_rva.value();

	std::memcpy(data(), headers_buffer.data(), headers_buffer.size());
}
