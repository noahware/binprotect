#pragma once
#include <cstdint>
#include <optional>
#include <span>

#include "disassembled_instruction.hpp"

namespace binwrite
{
	class rva_t;

	class disassembler_t
	{
	public:
		disassembler_t();

		[[nodiscard]] std::optional<disassembled_instruction_t> disassemble(std::span<const std::uint8_t> instruction) const;
		[[nodiscard]] std::optional<disassembled_instruction_t> disassemble(const std::uint8_t* instruction) const;

	protected:
		[[nodiscard]] bool decode_instruction(std::span<const std::uint8_t> instruction, ZydisDecoderContext* context, ZydisDecodedInstruction* decoded_instruction) const;
		[[nodiscard]] bool decode_operands(const ZydisDecoderContext* context, const ZydisDecodedInstruction* instruction, std::span<ZydisDecodedOperand> operands) const;

		ZydisDecoder decoder_;
	};

	std::optional<std::uint32_t> resolve_instruction_rva(const disassembled_instruction_t& instruction, rva_t instruction_rva);

	std::optional<std::uint8_t> find_displacement_offset(const std::uint8_t* instruction, std::uint32_t size);
}
