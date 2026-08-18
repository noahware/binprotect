#include "control_flow_flattening.hpp"
#include "../assembler/assembler.hpp"

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

static std::shared_ptr<binwrite::basic_block_t> find_fallthrough_block(
	const binwrite::function_t& function,
	const std::shared_ptr<binwrite::basic_block_t>& basic_block)
{
	const auto& last_instruction = basic_block->last_instruction();
	const auto disassembly = last_instruction.disassemble();

	if (disassembly.is_unconditional_jump() || disassembly.is_ret())
	{
		return {};
	}

	const auto section = basic_block->section();

	if (!section)
	{
		return {};
	}

	auto it = basic_block->list_iterator();
	++it;

	if (it == section->symbols().end())
	{
		return {};
	}

	const auto next_block = std::dynamic_pointer_cast<binwrite::basic_block_t>(*it);

	if (!next_block)
	{
		return {};
	}

	for (const auto& fn_block : function.basic_blocks())
	{
		if (fn_block == next_block)
		{
			return next_block;
		}
	}

	return {};
}

static std::shared_ptr<binwrite::basic_block_t> find_target_block(
	const binwrite::binary_t& binary,
	const binwrite::function_t& function,
	const std::shared_ptr<binwrite::basic_block_t>& basic_block)
{
	const auto& last_instruction = basic_block->last_instruction();
	const auto disassembly = last_instruction.disassemble();

	if (!disassembly.is_jump())
	{
		return {};
	}

	const auto last_instr_id = last_instruction.id();

	for (const auto& ref : binary.find_all_symbol_refs_by_self(basic_block))
	{
		const auto code_ref = std::dynamic_pointer_cast<binwrite::code_symbol_ref_t>(ref);

		if (!code_ref || code_ref->self_instr_id() != last_instr_id)
		{
			continue;
		}

		const auto target = std::dynamic_pointer_cast<binwrite::basic_block_t>(ref->target());

		if (!target)
		{
			continue;
		}

		for (const auto& fn_block : function.basic_blocks())
		{
			if (fn_block == target)
			{
				return target;
			}
		}
	}

	return {};
}

static std::vector<cff_block_t> collect_cff_blocks(const binwrite::binary_t& binary,
	binwrite::function_t& function)
{
	std::vector<cff_block_t> cff_blocks;

	for (const auto& basic_block : function.basic_blocks())
	{
		std::uint32_t id;

		do
		{
			id = binwrite::util::random_integral<std::uint16_t>();
		} while (std::ranges::any_of(cff_blocks, [id](const cff_block_t& cff_block) { return cff_block.id == id; }));

		const auto fallthrough = find_fallthrough_block(function, basic_block);
		const auto target = find_target_block(binary, function, basic_block);

		cff_blocks.emplace_back(basic_block, fallthrough, target, id);
	}

	return cff_blocks;
}

static std::vector<cff_block_t>::iterator find_cff_block(std::vector<cff_block_t>& cff_blocks,
	const std::shared_ptr<binwrite::basic_block_t>& target_block)
{
	return std::ranges::find_if(cff_blocks,
		[&target_block](const cff_block_t& cff_block)
		{
			return cff_block.basic_block == target_block;
		}
	);
}

static std::vector<binwrite::instruction_t> set_block_id_instructions(const cff_block_t& target_cff_block,
	const binwrite::register_family_t id_register_family)
{
	const auto id_operand = encode_unsigned_imm_operand(target_cff_block.id);

	std::vector<binwrite::instruction_t> instructions;

	instructions.push_back(pushfq_instruction().value());
	instructions.push_back(push_instruction(id_register_family.qword).value());
	instructions.push_back(mov_instruction(id_operand, id_register_family.dword).value());

	return instructions;
}

static std::shared_ptr<binwrite::basic_block_t> insert_dispatcher_anchor(binwrite::binary_t& binary,
	const std::shared_ptr<binwrite::basic_block_t>& entry_block)
{
	const auto original_count = entry_block->count();

	entry_block->push(binary, nop_instruction().value());

	const auto anchor_block = entry_block->split_at(binary, original_count);

	if (!anchor_block)
	{
		return {};
	}

	for (const auto& ref : binary.find_all_symbol_refs_by_self(entry_block))
	{
		const auto code_ref = std::dynamic_pointer_cast<binwrite::code_symbol_ref_t>(ref);

		if (!code_ref || code_ref->self_instr_id() == 0)
		{
			continue;
		}

		if (anchor_block->instruction_index_by_id(code_ref->self_instr_id()) != binwrite::basic_block_t::invalid_index)
		{
			ref->set_self(anchor_block);
		}
	}

	return anchor_block;
}

static std::shared_ptr<binwrite::basic_block_t> build_dispatcher_chain(binwrite::binary_t& binary,
	const std::shared_ptr<binwrite::basic_block_t>& anchor_block,
	const std::vector<cff_block_t>& cff_blocks,
	const binwrite::register_family_t id_register_family)
{
	std::vector<std::shared_ptr<binwrite::basic_block_t>> comparison_blocks;
	auto insert_after = std::static_pointer_cast<binwrite::symbol_t>(anchor_block);

	const auto far_operand = encode_unsigned_imm_operand(1);

	for (const auto& cff_block : cff_blocks)
	{
		const auto id_operand = encode_unsigned_imm_operand(cff_block.id);

		const std::array instructions = {
			cmp_instruction(id_operand, id_register_family.dword).value(),
			jnz_instruction(far_operand).value(),
			pop_instruction(id_register_family.qword).value(),
			popfq_instruction().value(),
			jmp_instruction(far_operand).value()
		};

		const auto comp_block = binary.create_basic_block_after(
			std::dynamic_pointer_cast<binwrite::basic_block_t>(insert_after), instructions);
		comparison_blocks.push_back(comp_block);
		insert_after = comp_block;
	}

	const std::array trap_instructions = { int3_instruction() };
	const auto trap_block = binary.create_basic_block_after(
		std::dynamic_pointer_cast<binwrite::basic_block_t>(insert_after), trap_instructions);

	for (std::size_t i = 0; i < comparison_blocks.size(); i++)
	{
		const auto& comp = comparison_blocks[i];
		const std::shared_ptr<binwrite::symbol_t> next_target = (i + 1 < comparison_blocks.size())
			? std::static_pointer_cast<binwrite::symbol_t>(comparison_blocks[i + 1])
			: std::static_pointer_cast<binwrite::symbol_t>(trap_block);

		binary.add_code_ref(comp, comp->at(1), next_target);
		binary.add_code_ref(comp, comp->at(4), cff_blocks[i].basic_block);
	}

	return trap_block;
}

static std::shared_ptr<binwrite::basic_block_t> create_set_id_stub(binwrite::binary_t& binary,
	const std::shared_ptr<binwrite::basic_block_t>& insert_after,
	const std::shared_ptr<binwrite::basic_block_t>& anchor_block,
	const cff_block_t& target_cff_block,
	const binwrite::register_family_t id_register_family)
{
	auto instructions = set_block_id_instructions(target_cff_block, id_register_family);
	instructions.push_back(jmp_instruction(encode_unsigned_imm_operand(1)).value());

	const auto stub_block = binary.create_basic_block_after(insert_after, instructions);

	binary.add_code_ref(stub_block, stub_block->last_instruction(), anchor_block);

	return stub_block;
}

static void flatten_blocks(binwrite::binary_t& binary,
	const std::shared_ptr<binwrite::basic_block_t>& anchor_block,
	const std::shared_ptr<binwrite::basic_block_t>& trap_block,
	const std::shared_ptr<binwrite::basic_block_t>& entry_block,
	const binwrite::register_family_t id_register_family,
	std::vector<cff_block_t>& cff_blocks,
	const std::function<bool(const std::shared_ptr<binwrite::basic_block_t>&)>& is_block_fixed)
{
	for (const auto& cff_block : cff_blocks)
	{
		const auto& basic_block = cff_block.basic_block;

		if (basic_block != entry_block && !(is_block_fixed && is_block_fixed(basic_block)))
		{
			basic_block->move_after(trap_block);
		}

		auto insert_after = basic_block;

		if (const auto& fallthrough_block = cff_block.fallthrough_block)
		{
			const auto fallthrough_cff_it = find_cff_block(cff_blocks, fallthrough_block);

			if (fallthrough_cff_it == cff_blocks.end())
			{
				spdlog::warn("couldn't find fallthrough cff block");
				continue;
			}

			insert_after = create_set_id_stub(binary, insert_after, anchor_block,
				*fallthrough_cff_it, id_register_family);
		}

		if (const auto& target_block = cff_block.target_block)
		{
			const auto target_cff_it = find_cff_block(cff_blocks, target_block);

			if (target_cff_it == cff_blocks.end())
			{
				spdlog::warn("couldn't find target cff block for control flow flattening");
				continue;
			}

			const auto target_stub = create_set_id_stub(binary, insert_after, anchor_block,
				*target_cff_it, id_register_family);

			const auto& last_instruction = basic_block->last_instruction();
			const auto last_instr_id = last_instruction.id();

			for (const auto& ref : binary.find_all_symbol_refs_by_self(basic_block))
			{
				const auto code_ref = std::dynamic_pointer_cast<binwrite::code_symbol_ref_t>(ref);

				if (!code_ref || code_ref->self_instr_id() != last_instr_id)
				{
					continue;
				}

				ref->set_target(target_stub);
				break;
			}
		}
	}
}

void binprotect::control_flow::flattening::do_pass(binwrite::binary_t& binary, binwrite::function_t& function,
	const std::function<bool(const std::shared_ptr<binwrite::basic_block_t>&)>& is_block_fixed)
{
	if (function.basic_blocks().size() <= 1)
	{
		return;
	}

	std::vector<cff_block_t> cff_blocks = collect_cff_blocks(binary, function);

	const binwrite::register_family_t id_register_family = binwrite::register_family_t::random();

	const auto entry_block = function.entry_block();
	const auto anchor_block = insert_dispatcher_anchor(binary, entry_block);

	if (!anchor_block)
	{
		spdlog::error("unable to create dispatcher anchor for control flow flattening");
		return;
	}

	binwrite::util::shuffle<cff_block_t>(cff_blocks);

	const auto trap_block = build_dispatcher_chain(binary, anchor_block, cff_blocks, id_register_family);

	flatten_blocks(binary, anchor_block, trap_block, entry_block, id_register_family, cff_blocks, is_block_fixed);
}
