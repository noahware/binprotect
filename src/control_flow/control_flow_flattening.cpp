#if 0
#include "control_flow_flattening.hpp"
#include "../assembler/assembler.hpp"

#include <binwrite/disassembler/disassembler.hpp>
#include <binwrite/util/random.hpp>
#include <spdlog/spdlog.h>
#include <algorithm>
#include <ranges>

struct cff_block_t
{
	std::shared_ptr<binwrite::basic_block_t> basic_block;

	std::shared_ptr<binwrite::basic_block_t> fallthrough_block;
	std::shared_ptr<binwrite::basic_block_t> target_block;

	std::uint32_t id = 0;
};

static std::vector<cff_block_t> collect_cff_blocks(const binwrite::binary_t& binary, binwrite::function_t& function)
{
	std::vector<cff_block_t> cff_blocks;

	for (const auto& basic_block : function.basic_blocks())
	{
		std::uint32_t id;

		do
		{
			id = binwrite::util::random_integral<std::uint16_t>();
		} while (std::ranges::any_of(cff_blocks, [id](const cff_block_t& cff_block) { return cff_block.id == id; }));

		const auto fallthrough_block = function.fallthrough_block(basic_block);
		const auto target_block = function.target_block(binary, basic_block);

		cff_blocks.emplace_back(basic_block, fallthrough_block, target_block, id);
	}

	return cff_blocks;
}

static std::vector<cff_block_t>::iterator find_cff_block(std::vector<cff_block_t>& cff_blocks, const binwrite::rva_t target_rva)
{
	const auto it = std::ranges::find_if(cff_blocks,
		[target_rva](const cff_block_t& cff_block)
		{
			return *cff_block.basic_block->rva() == target_rva;
		}
	);

	return it;
}

static std::vector<binwrite::instruction_t> set_block_id_instructions(const cff_block_t& target_cff_block,
                                                                      const binwrite::register_family_t  id_register_family)
{
	const auto id_operand = encode_unsigned_imm_operand(target_cff_block.id);

	std::vector<binwrite::instruction_t> instructions = { };

	instructions.push_back(pushfq_instruction().value());
	instructions.push_back(push_instruction(id_register_family.qword).value());
	instructions.push_back(mov_instruction(id_operand, id_register_family.dword).value());

	return instructions;
}

static std::shared_ptr<binwrite::basic_block_t> insert_dispatcher_block(binwrite::binary_t& binary,
	binwrite::function_t& function,
	const std::shared_ptr<binwrite::basic_block_t>& entry_block)
{
	const auto marker_instruction = nop_instruction().value();
	const auto original_count = entry_block->count();

	entry_block->push(binary, marker_instruction, false, true);

	const auto split_block = binary.split_basic_block(*entry_block,
		static_cast<binwrite::basic_block_t::size_type>(original_count));

	return split_block;
}

static void insert_block_jump_stub(binwrite::binary_t& binary,
                                   const std::shared_ptr<binwrite::basic_block_t>& stub_basic_block,
                                   const cff_block_t& cff_block,
                                   const binwrite::register_family_t id_register_family,
                                   const binwrite::basic_block_t::size_type entry_stub_size)
{
	const auto jmp_destination_operand = encode_unsigned_imm_operand(1);
	const auto id_operand = encode_unsigned_imm_operand(cff_block.id);

	const auto jump_instruction = jmp_instruction(jmp_destination_operand).value();
	const auto jump_nz_instruction = jnz_instruction(jmp_destination_operand).value();

	const std::array instructions = {
		cmp_instruction(id_operand, id_register_family.dword).value(),
		jump_nz_instruction,
		pop_instruction(id_register_family.qword).value(),
		popfq_instruction().value(),
		jump_instruction
	};

	stub_basic_block->insert(binary, instructions, entry_stub_size, true);

	const binwrite::rva_t jnz_rva = stub_basic_block->instruction_rva(entry_stub_size + 1);
	const binwrite::rva_t block_jmp_rva = stub_basic_block->instruction_rva(entry_stub_size + 4);

	const binwrite::rva_t next_branch_rva = stub_basic_block->instruction_rva(entry_stub_size + 5);

	binary.add_rva_ref(std::make_shared<binwrite::code_rva_ref_t>(binary.add_rva(next_branch_rva), jnz_rva, jump_nz_instruction.size()));
	binary.add_rva_ref(std::make_shared<binwrite::code_rva_ref_t>(cff_block.basic_block->rva(), block_jmp_rva, jump_instruction.size()));
}

static void insert_fallthrough_block_stub(binwrite::binary_t& binary,
                                          const std::shared_ptr<binwrite::basic_block_t>& basic_block,
                                          const std::shared_ptr<binwrite::rva_t>& stub_insert_rva,
                                          const cff_block_t& fallthrough_cff_block,
                                          const binwrite::register_family_t id_register_family)
{
	const auto jmp_destination_operand = encode_unsigned_imm_operand(1);
	const auto jump_instruction = jmp_instruction(jmp_destination_operand).value();

	const auto set_id_instructions = set_block_id_instructions(fallthrough_cff_block, id_register_family);

	basic_block->push(binary, set_id_instructions, false, true);
	basic_block->push(binary, jump_instruction, false, true);

	const binwrite::rva_t jmp_rva = basic_block->last_instruction_rva();

	binary.add_rva_ref(std::make_shared<binwrite::code_rva_ref_t>(stub_insert_rva, jmp_rva, jump_instruction.size()));
}

static void insert_target_block_stub(binwrite::binary_t& binary,
                                     const std::shared_ptr<binwrite::basic_block_t>& basic_block,
                                     const std::shared_ptr<binwrite::rva_t>& stub_insert_rva,
                                     const cff_block_t& target_cff_block,
                                     const binwrite::register_family_t id_register_family,
                                     const binwrite::rva_t last_instruction_rva)
{
	const binwrite::rva_t end_rva = basic_block->end_rva();

	insert_fallthrough_block_stub(binary, basic_block, stub_insert_rva, target_cff_block, id_register_family);

	binary.redirect_rva_ref(last_instruction_rva, end_rva);
}

static void process_cff_fallthrough_block(binwrite::binary_t& binary,
                                      const cff_block_t& cff_block,
                                      std::vector<cff_block_t>& cff_blocks,
                                      const std::shared_ptr<binwrite::rva_t>& stub_insert_rva,
                                      const binwrite::register_family_t id_register_family)
{
	if (const auto& fallthrough_block = cff_block.fallthrough_block)
	{
		const auto fallthrough_cff_block = find_cff_block(cff_blocks, *fallthrough_block->rva());

		if (fallthrough_cff_block == cff_blocks.end())
		{
			spdlog::warn("couldn't find fallthrough cff block at 0x{:X} for block at 0x{:X}",
				fallthrough_block->rva()->value(), cff_block.basic_block->rva()->value());

			return;
		}

		insert_fallthrough_block_stub(binary, cff_block.basic_block, stub_insert_rva, *fallthrough_cff_block, id_register_family);
	}
}

static void process_cff_target_block(binwrite::binary_t& binary, const cff_block_t& cff_block,
                                      std::vector<cff_block_t>& cff_blocks,
                                      const std::shared_ptr<binwrite::rva_t>& stub_insert_rva,
                                      const binwrite::register_family_t id_register_family,
                                      const binwrite::rva_t last_instruction_rva)
{
	if (const auto& target_block = cff_block.target_block)
	{
		const auto target_cff_block = find_cff_block(cff_blocks, *target_block->rva());

		if (target_cff_block == cff_blocks.end())
		{
			spdlog::warn("couldn't find target cff block for control flow flattening");

			return;
		}

		insert_target_block_stub(binary, cff_block.basic_block, stub_insert_rva, *target_cff_block, id_register_family,
		                         last_instruction_rva);
	}
}

static void flatten_blocks(binwrite::binary_t& binary, const std::shared_ptr<binwrite::rva_t>& stub_insert_rva,
                           const std::shared_ptr<binwrite::basic_block_t>& stub_basic_block,
                           const std::shared_ptr<binwrite::basic_block_t>& entry_block,
                           const binwrite::register_family_t id_register_family,
                           std::vector<cff_block_t>& cff_blocks,
                           const std::function<bool(binwrite::rva_t::value_type)>& is_block_fixed)
{
	const binwrite::basic_block_t::size_type entry_stub_size = stub_basic_block->count();

	for (const auto& cff_block : cff_blocks)
	{
		const auto& basic_block = cff_block.basic_block;

		if (basic_block != entry_block && !(is_block_fixed && is_block_fixed(basic_block->rva()->value())))
		{
			basic_block->move_entire(binary, stub_basic_block->end_rva());
		}

		insert_block_jump_stub(binary, stub_basic_block, cff_block, id_register_family, entry_stub_size);

		const auto last_instruction_rva = basic_block->last_instruction_rva();

		process_cff_fallthrough_block(binary, cff_block, cff_blocks, stub_insert_rva, id_register_family);

		process_cff_target_block(binary, cff_block, cff_blocks, stub_insert_rva, id_register_family, last_instruction_rva);
	}
}

void binprotect::control_flow::flattening::do_pass(binwrite::binary_t& binary, binwrite::function_t& function,
                                                   const std::function<bool(binwrite::rva_t::value_type)>& is_block_fixed)
{
	if (function.basic_blocks().size() <= 1)
	{
		return;
	}

	std::vector<cff_block_t> cff_blocks = collect_cff_blocks(binary, function);

	const binwrite::register_family_t id_register_family = binwrite::register_family_t::random();

	const auto entry_block = function.entry_block();
	const auto dispatcher_block = insert_dispatcher_block(binary, function, entry_block);

	if (!dispatcher_block)
	{
		spdlog::error("unable to create dispatcher block for control flow flattening");

		return;
	}

	const auto stub_insert_rva = dispatcher_block->rva();

	binwrite::util::shuffle<cff_block_t>(cff_blocks);

	flatten_blocks(binary, stub_insert_rva, dispatcher_block, entry_block, id_register_family, cff_blocks, is_block_fixed);

	dispatcher_block->push(binary, int3_instruction(), false, true);
}
#endif
