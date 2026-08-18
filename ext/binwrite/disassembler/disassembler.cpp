#include "disassembler.hpp"
#include "../binary/rva/rva.hpp"

binwrite::disassembler_t::disassembler_t()
{
	ZydisDecoderInit(&decoder_, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
}

std::optional<binwrite::disassembled_instruction_t> binwrite::disassembler_t::disassemble(
	const std::span<const std::uint8_t> instruction) const
{
	ZydisDecoderContext context;
	ZydisDecodedInstruction decoded_instruction;

	if (!decode_instruction(instruction, &context, &decoded_instruction))
	{
		return std::nullopt;
	}

	std::vector<ZydisDecodedOperand> decoded_operands(decoded_instruction.operand_count);

	if (!decode_operands(&context, &decoded_instruction, decoded_operands))
	{
		return std::nullopt;
	}

	std::vector<decoded_operand_t> wrapped_operands(decoded_operands.begin(), decoded_operands.end());

	return disassembled_instruction_t{ decoded_instruction, std::move(wrapped_operands) };
}

std::optional<binwrite::disassembled_instruction_t> binwrite::disassembler_t::disassemble(
	const std::uint8_t* const instruction) const
{
	return disassemble(std::span<const std::uint8_t>{ instruction, instruction + ZYDIS_MAX_INSTRUCTION_LENGTH });
}

bool binwrite::disassembler_t::decode_instruction(const std::span<const std::uint8_t> instruction,
	ZydisDecoderContext* const context, ZydisDecodedInstruction* const decoded_instruction) const
{
	const auto status = ZydisDecoderDecodeInstruction(&decoder_, context, instruction.data(), instruction.size(), decoded_instruction);

	return ZYAN_SUCCESS(status);
}

bool binwrite::disassembler_t::decode_operands(const ZydisDecoderContext* const context,
                                               const ZydisDecodedInstruction* const instruction, const std::span<ZydisDecodedOperand> operands) const
{
	const ZyanU8 operand_count = static_cast<ZyanU8>(operands.size());

	const auto status = ZydisDecoderDecodeOperands(&decoder_, context, instruction, operands.data(), operand_count);

	return ZYAN_SUCCESS(status);
}

std::optional<std::uint8_t> binwrite::find_displacement_offset(const std::uint8_t* const instruction, const std::uint32_t size)
{
	thread_local const auto decoder = []() { ZydisDecoder d; ZydisDecoderInit(&d, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64); return d; }();

	ZydisDecodedInstruction decoded;
	ZydisDecoderContext context;

	if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&decoder, &context, instruction, size, &decoded)))
	{
		return std::nullopt;
	}

	if (decoded.raw.disp.size == 32)
	{
		return decoded.raw.disp.offset;
	}

	if (decoded.attributes & ZYDIS_ATTRIB_IS_RELATIVE)
	{
		if (decoded.raw.imm[0].size == 32)
		{
			return decoded.raw.imm[0].offset;
		}
	}

	return std::nullopt;
}

std::optional<std::uint32_t> binwrite::resolve_instruction_rva(const disassembled_instruction_t& instruction,
                                                               const rva_t instruction_rva)
{
	if (!instruction.relative())
	{
		return std::nullopt;
	}

	const std::uint32_t rip = instruction_rva.value() + instruction.size();

	for (const auto& operand : instruction.visible_operands())
	{
		if (operand.is_imm() && operand.imm().is_relative)
		{
			const auto imm = operand.imm();

			return rip + (imm.is_signed ? static_cast<std::int32_t>(imm.value.s) : static_cast<std::uint32_t>(imm.value.u));
		}

		if (operand.is_mem() && operand.mem().base == register_t::rip)
		{
			return rip + static_cast<std::int32_t>(operand.mem().displacement);
		}
	}

	return std::nullopt;
}
