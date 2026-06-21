#include "assembler.hpp"
#include "../arch/instruction/instruction.hpp"
#include "../arch/mnemonic/mnemonic.hpp"

bool binwrite::encoder_operand_t::is_imm() const
{
	return value_.type == ZYDIS_OPERAND_TYPE_IMMEDIATE;
}

binwrite::encoder_operand_t::imm_t binwrite::encoder_operand_t::imm() const
{
	return imm_t{ .u = value_.imm.u };
}

void binwrite::encoder_operand_t::set_imm(const imm_t imm)
{
	value_.type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
	value_.imm.u = imm.u;
}

bool binwrite::encoder_operand_t::is_mem() const
{
	return value_.type == ZYDIS_OPERAND_TYPE_MEMORY;
}

binwrite::encoder_operand_t::mem_t binwrite::encoder_operand_t::mem() const
{
	mem_t mem;

	mem.base = register_t(value_.mem.base);
	mem.index = register_t(value_.mem.index);
	mem.displacement = value_.mem.displacement;
	mem.scale = value_.mem.scale;
	mem.size = value_.mem.size;

	return mem;
}

void binwrite::encoder_operand_t::set_mem(const mem_t mem)
{
	value_.type = ZYDIS_OPERAND_TYPE_MEMORY;
	value_.mem.base = mem.base;
	value_.mem.index = mem.index;
	value_.mem.displacement = mem.displacement;
	value_.mem.scale = mem.scale;
	value_.mem.size = mem.size;
}

bool binwrite::encoder_operand_t::is_reg() const
{
	return value_.type == ZYDIS_OPERAND_TYPE_REGISTER;
}

binwrite::encoder_operand_t::reg_t binwrite::encoder_operand_t::reg() const
{
	return reg_t{ .value = register_t(value_.reg.value) };
}

void binwrite::encoder_operand_t::set_reg(const reg_t reg)
{
	value_.type = ZYDIS_OPERAND_TYPE_REGISTER;
	value_.reg.value = reg.value;
}

binwrite::encoder_operand_t::operator ZydisEncoderOperand&()
{
	return value_;
}

binwrite::encoder_operand_t::operator const ZydisEncoderOperand&() const
{
	return value_;
}

std::span<binwrite::encoder_operand_t> binwrite::assembler_instruction_t::operands()
{
	const auto start = reinterpret_cast<encoder_operand_t*>(request_.operands);
	const auto end = start + request_.operand_count;

	return { start, end };
}

std::span<const binwrite::encoder_operand_t> binwrite::assembler_instruction_t::operands() const
{
	const auto start = reinterpret_cast<const encoder_operand_t*>(request_.operands);
	const auto end = start + request_.operand_count;

	return { start, end };
}

void binwrite::assembler_instruction_t::set_operands(const std::span<const encoder_operand_t> new_operands)
{
	std::memcpy(request_.operands, new_operands.data(), sizeof(encoder_operand_t) * new_operands.size());

	request_.operand_count = static_cast<std::uint8_t>(new_operands.size());
}

std::optional<binwrite::instruction_t> binwrite::assembler_instruction_t::compile() const
{
	const auto compiled_bytes = compile_bytes();

	if (!compiled_bytes)
	{
		return std::nullopt;
	}

	const std::span bytes_view(compiled_bytes->first.begin(), compiled_bytes->second);

	return instruction_t{ bytes_view };
}

std::optional<std::pair<binwrite::assembler_instruction_t::bytes_t, binwrite::assembler_instruction_t::size_type>> binwrite::assembler_instruction_t::compile_bytes() const
{
	bytes_t bytes;

	auto size = static_cast<ZyanUSize>(sizeof(bytes));

	const auto status = ZydisEncoderEncodeInstruction(&request_, bytes.data(), &size);

	if (!ZYAN_SUCCESS(status))
	{
		return { };
	}

	return std::pair{ bytes, static_cast<size_type>(size) };
}

std::optional<binwrite::assembler_instruction_t::size_type> binwrite::assembler_instruction_t::predict_size() const
{
	const auto compiled = compile_bytes();

	if (!compiled)
	{
		return std::nullopt;
	}

	return compiled->second;
}

bool binwrite::assembler_instruction_t::is_jump() const
{
	return ZYDIS_MNEMONIC_JB <= request_.mnemonic && request_.mnemonic <= ZYDIS_MNEMONIC_JZ;
}

bool binwrite::assembler_instruction_t::is_conditional_jump() const
{
	return is_jump() && request_.mnemonic != ZYDIS_MNEMONIC_JMP;
}

bool binwrite::assembler_instruction_t::is_call() const
{
	return request_.mnemonic == ZYDIS_MNEMONIC_CALL;
}

std::optional<binwrite::assembler_instruction_t> binwrite::make_assembler_instruction(
	const disassembled_instruction_t& instruction)
{
	const auto unconverted_operands = instruction.visible_operands();

	const ZydisDecodedInstruction& decoded_instruction(instruction);
	const std::vector<ZydisDecodedOperand> decoded_operands(unconverted_operands.begin(), unconverted_operands.end());

	const ZyanU8 operand_count = static_cast<ZyanU8>(decoded_operands.size());

	ZydisEncoderRequest request;
		
	const auto status = ZydisEncoderDecodedInstructionToEncoderRequest(&decoded_instruction, decoded_operands.data(), operand_count, &request);

	if (!ZYAN_SUCCESS(status))
	{
		return std::nullopt;
	}

	request.branch_type = ZYDIS_BRANCH_TYPE_NONE;
	request.branch_width = ZYDIS_BRANCH_WIDTH_NONE;

	return assembler_instruction_t{ request };
}

std::optional<binwrite::assembler_instruction_t> binwrite::make_assembler_instruction(
	const std::uint8_t* const instruction)
{
	const disassembler_t disassembler;

	const auto disassembled_instruction = disassembler.disassemble(instruction);

	if (!disassembled_instruction)
	{
		return std::nullopt;
	}

	return make_assembler_instruction(*disassembled_instruction);
}

std::optional<binwrite::assembler_instruction_t> binwrite::make_assembler_instruction(const mnemonic_t mnemonic, const std::span<const encoder_operand_t> operands)
{
	if (6 <= operands.size())
	{
		return std::nullopt;
	}

	ZydisEncoderRequest request = { };

	request.mnemonic = mnemonic;
	request.operand_count = static_cast<ZyanU8>(operands.size());

	for (std::uint64_t i = 0; i < operands.size(); i++)
	{
		const encoder_operand_t& operand = operands[i];
	
		request.operands[i] = operand;
	}

	return assembler_instruction_t{ request };
}
