#pragma once
#include <memory>
#include <deque>
#include <span>
#include <string>
#include <vector>

#include <binwrite/arch/instruction/instruction.hpp>
#include <binwrite/assembler/assembler.hpp>
#include <binwrite/binary/binary.hpp>
#include <binwrite/util/random.hpp>

#include "../assembler/assembler.hpp"
#include "hardware_register.hpp"
#include "operand.hpp"

struct vm_instruction_t
{
	std::vector<binwrite::instruction_t> load = { };
	std::vector<binwrite::instruction_t> handler = { };
	std::vector<binwrite::instruction_t> unload = { };
};

struct vm_segment_t
{
	std::shared_ptr<binwrite::basic_block_t> entry_block;
	std::shared_ptr<binwrite::basic_block_t> exit_block;
	std::vector<binwrite::register_family_t> stack_registers;
};

class vm_context_t : public std::enable_shared_from_this<vm_context_t>
{
public:
	using size_type = std::uint64_t;
	using offset_type = std::uint32_t;

	static constexpr size_type operand_size = 8;
	static constexpr size_type stack_register_size = 8;

	explicit vm_context_t(const std::span<const binwrite::register_family_t> stack_registers)
			:	stack_registers_(stack_registers.begin(), stack_registers.end())
	{
		shuffle_registers();

		for (binwrite::register_family_t& stack_register : stack_registers_)
		{
			free_registers_.push_back(stack_register);
		}
	}

	void enter_virtualized_state(binwrite::binary_t& binary);
	void exit_virtualized_state(binwrite::binary_t& binary);

	void process_instruction(const binwrite::disassembled_instruction_t& instruction_disassembly);
	void compile_instruction(binwrite::binary_t& binary);

	[[nodiscard]] hardware_register_t random_hardware_register();
	void free_hardware_register(const hardware_register_t& hardware_register);

	[[nodiscard]] size_type initial_stack_size() const
	{
		constexpr size_type special_register_count = 3; // rbp, rflags, return address

		const size_type total_register_count = stack_registers_.size() + special_register_count;

		return total_register_count * stack_register_size;
	}

	[[nodiscard]] bool in_virtualized_state() const
	{
		return virtualized_state_;
	}

	[[nodiscard]] std::shared_ptr<binwrite::basic_block_t> entry_block() const
	{
		return entry_block_;
	}

	[[nodiscard]] std::span<std::shared_ptr<binwrite::basic_block_t>> basic_blocks()
	{
		return basic_blocks_;
	}

	[[nodiscard]] std::span<const std::shared_ptr<binwrite::basic_block_t>> basic_blocks() const
	{
		return basic_blocks_;
	}

	[[nodiscard]] const std::vector<binwrite::register_family_t>& stack_register_order() const
	{
		return stack_registers_;
	}

	[[nodiscard]] const std::vector<vm_segment_t>& segments() const
	{
		return segments_;
	}

protected:
	void shuffle_registers();

	void push_registers(std::vector<binwrite::instruction_t>& instructions) const;
	void pop_registers(std::vector<binwrite::instruction_t>& instructions) const;

	[[nodiscard]] std::optional<offset_type> register_stack_offset(binwrite::register_t reg) const;

	void free_instruction();

	std::vector<std::unique_ptr<obfuscated_operand_t>> load_instruction(std::span<const binwrite::decoded_operand_t> operands);

	void handle_instruction(const binwrite::disassembled_instruction_t& instruction_disassembly,
							std::span<const binwrite::decoded_operand_t> original_operands,
							std::span<const std::unique_ptr<obfuscated_operand_t>> obfuscated_operands);

	void unload_instruction(const binwrite::disassembled_instruction_t& instruction_disassembly,
	                        std::span<const binwrite::decoded_operand_t> operands,
							std::span<const std::unique_ptr<obfuscated_operand_t>> obfuscated_operands);

	void save_instruction_operands(std::vector<binwrite::instruction_t>& instructions,
	                               std::span<const binwrite::decoded_operand_t> operands,
	                               std::span<std::unique_ptr<obfuscated_operand_t>> obfuscated_operands);

	void load_instruction_operands(std::vector<binwrite::instruction_t>& instructions,
	                               const binwrite::disassembled_instruction_t& instruction_disassembly,
	                               std::span<hardware_register_t> holding_registers,
	                               std::span<binwrite::encoder_operand_t> redirected_operands,
	                               std::span<const binwrite::decoded_operand_t> original_operands,
	                               std::span<const std::unique_ptr<obfuscated_operand_t>> obfuscated_operands);

	void process_hidden_operands(std::vector<binwrite::instruction_t>& load_instructions,
	                             std::vector<binwrite::instruction_t>& unload_instructions,
	                             std::vector<hardware_register_t>& holding_registers,
	                             std::span<const binwrite::decoded_operand_t> hidden_operands);

	void process_hidden_register(std::vector<binwrite::instruction_t>& load_instructions,
	                             std::vector<binwrite::instruction_t>& unload_instructions,
	                             std::vector<hardware_register_t>& holding_registers,
	                             const binwrite::decoded_operand_t& hidden_operand,
	                             binwrite::register_t reg);

	void recompile_instruction_operands(std::vector<binwrite::instruction_t>& instructions,
	                                    const binwrite::disassembled_instruction_t& instruction_disassembly,
	                                    std::span<const binwrite::encoder_operand_t> operands);

	static void save_instruction_results(std::vector<binwrite::instruction_t>& instructions,
	                                      std::span<const std::unique_ptr<obfuscated_operand_t>> obfuscated_operands,
	                                      std::span<const hardware_register_t> holding_registers);

	void write_instruction_results(std::vector<binwrite::instruction_t>& instructions,
	                               const binwrite::disassembled_instruction_t& instruction_disassembly,
	                               std::span<const binwrite::decoded_operand_t> operands,
	                               std::span<const std::unique_ptr<obfuscated_operand_t>> obfuscated_operands);

	[[nodiscard]] static offset_type calculate_operand_offset(size_type index);

	[[nodiscard]] binwrite::encoder_operand_t redirect_operand(std::vector<binwrite::instruction_t>& instructions,
	                                                           const binwrite::encoder_operand_t& operand,
	                                                           std::int64_t stack_offset = 0);

	[[nodiscard]] binwrite::encoder_operand_t register_to_stack(binwrite::register_t reg,
	                                                            std::uint16_t operand_width,
	                                                            std::int64_t additional_displacement = 0) const;

	[[nodiscard]] binwrite::encoder_operand_t flags_to_stack(std::int64_t additional_displacement = 0) const;

	[[nodiscard]] hardware_register_t read_operand(std::vector<binwrite::instruction_t>& instructions,
	                                               size_type index);

	void load_flags(std::vector<binwrite::instruction_t>& instructions, std::int64_t operand_offset);

	void save_flags(std::vector<binwrite::instruction_t>& instructions, std::int64_t operand_offset);

	static void write_operand(std::vector<binwrite::instruction_t>& instructions, const hardware_register_t& holder,
	                          const size_type index)
	{
		const binwrite::encoder_operand_t stack_memory = encode_stack_mem_operand(static_cast<std::int64_t>(operand_size * index), operand_size);

		instructions.push_back(mov_instruction(holder->qword, stack_memory).value());
	}

	static void allocate_operands(std::vector<binwrite::instruction_t>& instructions, const size_type count)
	{
		if (!count)
		{
			return;
		}

		const binwrite::encoder_operand_t stack_displacement = encode_unsigned_imm_operand(operand_size * count);

		instructions.push_back(sub_instruction(stack_displacement, binwrite::register_t::rsp).value());
	}

	static void free_operands(std::vector<binwrite::instruction_t>& instructions, const size_type count)
	{
		if (!count)
		{
			return;
		}

		const binwrite::encoder_operand_t stack_displacement = encode_unsigned_imm_operand(operand_size * count);

		instructions.push_back(add_instruction(stack_displacement, binwrite::register_t::rsp).value());
	}

	static void push_register(std::vector<binwrite::instruction_t>& instructions,
		const binwrite::register_family_t register_family)
	{
		if (register_family == binwrite::register_family_t::flags)
		{
			instructions.push_back(pushfq_instruction().value());

			return;
		}

		if (binwrite::util::random_bool())
		{
			instructions.push_back(push_instruction(register_family.qword).value());
		}
		else
		{
			const binwrite::encoder_operand_t stack_displacement = encode_unsigned_imm_operand(8);
			const binwrite::encoder_operand_t stack_memory = encode_stack_mem_operand(0, 8);

			instructions.push_back(sub_instruction(stack_displacement, binwrite::register_t::rsp).value());
			instructions.push_back(mov_instruction(register_family.qword, stack_memory).value());
		}
	}

	static void pop_register(std::vector<binwrite::instruction_t>& instructions,
	                         const binwrite::register_family_t register_family)
	{
		if (register_family == binwrite::register_family_t::flags)
		{
			instructions.push_back(popfq_instruction().value());

			return;
		}

		if (binwrite::util::random_bool())
		{
			instructions.push_back(pop_instruction(register_family.qword).value());
		}
		else
		{
			const binwrite::encoder_operand_t stack_displacement = encode_unsigned_imm_operand(8);
			const binwrite::encoder_operand_t stack_memory = encode_stack_mem_operand(0, 8);

			instructions.push_back(mov_instruction(stack_memory, register_family.qword).value());
			instructions.push_back(add_instruction(stack_displacement, binwrite::register_t::rsp).value());
		}
	}

	static void push_jump_to_block(binwrite::binary_t& binary,
	                               const std::shared_ptr<binwrite::basic_block_t>& source_block,
	                               const std::shared_ptr<binwrite::basic_block_t>& target_block)
	{
		const auto destination_placeholder = encode_unsigned_imm_operand(1);
		const auto jump_instruction = jmp_instruction(destination_placeholder).value();

		source_block->push(binary, jump_instruction);

		const auto ref = std::make_shared<binwrite::code_symbol_ref_t>(
			target_block, source_block,
			static_cast<binwrite::symbol_ref_t::size_type>(jump_instruction.size()));

		ref->set_self_instr_id(source_block->last_instruction().id());

		binary.add_symbol_ref(ref);
	}

	vm_instruction_t current_instruction_ = { };
	std::shared_ptr<binwrite::basic_block_t> previous_block_ = { };
	std::shared_ptr<binwrite::basic_block_t> entry_block_ = { };
	std::vector<vm_segment_t> segments_ = { };

	std::vector<std::shared_ptr<binwrite::basic_block_t>> basic_blocks_ = { };

	std::vector<binwrite::register_family_t> stack_registers_ = { };
	std::deque<binwrite::register_family_t> free_registers_ = { };
	std::vector<hardware_register_t> temporary_holding_registers_ = { };

	bool virtualized_state_ = false;
};
