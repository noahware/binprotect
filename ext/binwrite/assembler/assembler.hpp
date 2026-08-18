#pragma once
#include "../disassembler/disassembler.hpp"

#include <array>

namespace binwrite
{
	class instruction_t;
	class mnemonic_t;

	class encoder_operand_t
	{
	public:
		encoder_operand_t() = default;

		explicit encoder_operand_t(const ZydisEncoderOperand& value)
				:	value_(value) { }

		encoder_operand_t(const register_t& value)
		{
			set_reg({ value });
		}

		encoder_operand_t(const ZydisDecodedOperand& decoded_operand)
		{
			value_.type = decoded_operand.type;

			switch (value_.type)
			{
			case ZYDIS_OPERAND_TYPE_REGISTER:
				value_.reg.value = decoded_operand.reg.value;

				break;
			case ZYDIS_OPERAND_TYPE_MEMORY:
				value_.mem.base = decoded_operand.mem.base;
				value_.mem.index = decoded_operand.mem.index;
				value_.mem.scale = decoded_operand.mem.scale;
				value_.mem.displacement = decoded_operand.mem.disp.value;
				value_.mem.size = decoded_operand.size / 8;

				break;
			case ZYDIS_OPERAND_TYPE_POINTER:
				value_.ptr.segment = decoded_operand.ptr.segment;
				value_.ptr.offset = decoded_operand.ptr.offset;

				break;
			case ZYDIS_OPERAND_TYPE_IMMEDIATE:
				value_.imm.u = decoded_operand.imm.value.u;

				break;
			case ZYDIS_OPERAND_TYPE_UNUSED:
			default: ;
			}
		}

		encoder_operand_t(const decoded_operand_t& decoded_operand)
				:	encoder_operand_t(static_cast<ZydisDecodedOperand>(decoded_operand)) { }

		union imm_t
		{
			std::uint64_t u;
			std::int64_t s;
		};

		struct mem_t
		{
			std::int64_t displacement;
			std::uint8_t scale;
			register_t base;
			register_t index;
			std::uint16_t size;
		};

		struct reg_t
		{
			register_t value;
		};

		[[nodiscard]] bool is_imm() const;
		[[nodiscard]] imm_t imm() const;
		void set_imm(imm_t imm);

		[[nodiscard]] bool is_mem() const;
		[[nodiscard]] mem_t mem() const;
		void set_mem(mem_t mem);

		[[nodiscard]] bool is_reg() const;
		[[nodiscard]] reg_t reg() const;
		void set_reg(reg_t reg);

		operator ZydisEncoderOperand&();
		operator const ZydisEncoderOperand&() const;

	protected:
		ZydisEncoderOperand value_ = { };
	};

	// the sizes must be equal because of how encoder_operand_t spans over a memory range of ZydisEncoderOperand
	static_assert(sizeof(encoder_operand_t) == sizeof(ZydisEncoderOperand),
	              "sizeof(encoder_operand_t) should be equal to sizeof(ZydisEncoderOperand)");

	class assembler_instruction_t
	{
	public:
		explicit assembler_instruction_t(const ZydisEncoderRequest& request)
				:	request_(request) { }

		using size_type = std::uint32_t;

		constexpr static size_type max_length = 15;

		using bytes_t = std::array<std::uint8_t, max_length>;

		[[nodiscard]] std::span<encoder_operand_t> operands();
		[[nodiscard]] std::span<const encoder_operand_t> operands() const;

		void set_operands(std::span<const encoder_operand_t> new_operands);

		[[nodiscard]] std::optional<instruction_t> compile() const;
		[[nodiscard]] std::optional<std::pair<bytes_t, size_type>> compile_bytes() const;
		[[nodiscard]] std::optional<size_type> predict_size() const;

		[[nodiscard]] bool is_jump() const;
		[[nodiscard]] bool is_conditional_jump() const;
		[[nodiscard]] bool is_call() const;

	protected:
		ZydisEncoderRequest request_;
	};

	std::optional<assembler_instruction_t> make_assembler_instruction(const disassembled_instruction_t& instruction);
	std::optional<assembler_instruction_t> make_assembler_instruction(const std::uint8_t* instruction);

	std::optional<assembler_instruction_t> make_assembler_instruction(mnemonic_t mnemonic, std::span<const encoder_operand_t> operands);

	std::optional<instruction_t> widen_instruction(const instruction_t& instruction);
}
