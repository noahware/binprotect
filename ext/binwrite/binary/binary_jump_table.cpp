#include "binary.hpp"
#include "spdlog/spdlog.h"

static std::int32_t estimate_jump_table_count(
	const binwrite::basic_block_t& basic_block,
	const std::map<binwrite::rva_t::value_type, std::shared_ptr<binwrite::symbol_t>>& symbol_map)
{
	const auto dispatch_rva = static_cast<const binwrite::symbol_t&>(basic_block).rva();

	if (!dispatch_rva)
	{
		return -1;
	}

	auto it = symbol_map.find(dispatch_rva->value());

	if (it == symbol_map.end() || it == symbol_map.begin())
	{
		return -1;
	}

	constexpr int max_blocks = 5;
	int checked = 0;

	while (checked < max_blocks)
	{
		--it;

		const auto bb = std::dynamic_pointer_cast<binwrite::basic_block_t>(it->second);

		if (!bb || bb->count() == 0)
		{
			if (it == symbol_map.begin())
			{
				break;
			}

			continue;
		}

		++checked;

		for (std::uint32_t j = 0; j + 1 < bb->count(); j++)
		{
			const auto& disassembly = bb->at(j).disassemble();

			if (!disassembly.is_cmp() && !disassembly.is_sub())
			{
				continue;
			}

			if (!bb->at(j + 1).disassemble().is_conditional_jump())
			{
				continue;
			}

			const auto operands = disassembly.visible_operands();

			if (operands.size() >= 2 && operands[0].is_reg() && operands[1].is_imm())
			{
				return static_cast<std::int32_t>(operands[1].imm().value.s) + 1;
			}
		}

		if (it == symbol_map.begin())
		{
			break;
		}
	}

	return -1;
}

static std::optional<binwrite::decoded_operand_t::mem_t> extract_jump_table_mov_operand(const binwrite::disassembled_instruction_t& mov_disassembly, const bool ignore_scale = false)
{
	const auto& mov_operands = mov_disassembly.visible_operands();

	if (mov_operands.size() < 2)
	{
		return { };
	}

	const auto& mov_operand = mov_operands[1];

	if (!mov_operand.is_mem())
	{
		return { };
	}

	const auto mem = mov_operand.mem();

	if ((!ignore_scale && mem.scale != 4) ||
		mem.index == binwrite::register_t::none ||
		mem.base == binwrite::register_t::none)
	{
		return { };
	}

	return mem;
}

static std::optional<binwrite::disassembled_instruction_t> extract_jump_table_lea_disassembly(
	const binwrite::basic_block_t& basic_block, const binwrite::basic_block_t::size_type lea_index,
	const binwrite::decoded_operand_t::mem_t mem)
{
	const auto& lea_instruction = basic_block.at(lea_index);
	const auto& lea_disassembly = lea_instruction.disassemble();

	const auto lea_operands = lea_disassembly.visible_operands();

	if (lea_operands.empty())
	{
		return { };
	}

	const auto reg = lea_operands[0];

	if (!reg.is_reg() || reg.reg().value != mem.base)
	{
		return { };
	}

	return lea_disassembly;
}

static binwrite::rva_t::value_type symbol_base_rva(const binwrite::basic_block_t& block)
{
	const auto rva_opt = static_cast<const binwrite::symbol_t&>(block).rva();

	return rva_opt ? rva_opt->value() : 0;
}

static binwrite::symbol_t::size_type instruction_byte_offset(const binwrite::basic_block_t& block,
	const binwrite::basic_block_t::size_type index)
{
	binwrite::symbol_t::size_type offset = 0;

	for (binwrite::basic_block_t::size_type j = 0; j < index; j++)
	{
		offset += block.at(j).size();
	}

	return offset;
}

static binwrite::rva_t last_instruction_rva_from_symbol(const binwrite::basic_block_t& block)
{
	const auto base = symbol_base_rva(block);
	const auto last_size = block.at(block.count() - 1).size();

	return binwrite::rva_t{ base + block.size() - last_size };
}

bool binwrite::binary_t::process_multi_level_jump_table(basic_block_t& pre_mov_block,
	const rva_t entry_table_base, const rva_t dispatcher_rva)
{
	if (pre_mov_block.count() == 0)
	{
		return false;
	}

	const auto movzx_index = pre_mov_block.count() - 1;
	const auto& movzx_instruction = pre_mov_block.at(movzx_index);
	const auto& movzx_disassembly = movzx_instruction.disassemble();

	if (!movzx_disassembly.is_movzx())
	{
		return false;
	}

	const auto mem = extract_jump_table_mov_operand(movzx_disassembly, true);

	if (!mem)
	{
		return false;
	}

	const auto displacement = static_cast<rva_t::value_type>(mem->displacement);
	const std::uint32_t inner_table_size = displacement - entry_table_base.value();
	const std::int32_t inner_table_count = static_cast<std::int32_t>(inner_table_size / 4);

	const auto base = symbol_base_rva(pre_mov_block);
	const auto movzx_byte_offset = instruction_byte_offset(pre_mov_block, movzx_index);
	const rva_t movzx_rva{ base + movzx_byte_offset };

	std::shared_ptr<symbol_t> self_symbol;
	basic_block_t::size_type self_instr_index = movzx_index;

	if (movzx_byte_offset > 0)
	{
		auto new_symbol = pre_mov_block.split(*this, movzx_byte_offset);

		if (!new_symbol)
		{
			return false;
		}

		new_symbol->set_rva(movzx_rva);
		disassembly_symbol_map_[movzx_rva.value()] = new_symbol;
		self_symbol = new_symbol;
		self_instr_index = 0;
	}
	else
	{
		self_symbol = pre_mov_block.shared_from_this();
	}

	auto target_symbol = find_or_create_symbol(rva_t{ displacement });

	if (target_symbol)
	{
		auto ref = std::make_shared<msvc_jmp_table_symbol_ref_t>(
			target_symbol, self_symbol, static_cast<symbol_ref_t::size_type>(movzx_disassembly.size())
		);

		if (const auto self_block = std::dynamic_pointer_cast<basic_block_t>(self_symbol))
		{
			ref->set_self_instr_id(self_block->at(self_instr_index).id());
		}

		symbol_refs_.push_back(ref);
	}

	add_msvc_jmp_table_ref(entry_table_base, inner_table_count, dispatcher_rva);

	return true;
}

bool binwrite::binary_t::process_jump_table_instruction(basic_block_t& basic_block,
	const disassembled_instruction_t& mov_disassembly,
	const basic_block_t::size_type mov_index,
	const basic_block_t::size_type lea_index)
{
	const auto mem = extract_jump_table_mov_operand(mov_disassembly);

	if (!mem)
	{
		return false;
	}

	const auto lea_disassembly = extract_jump_table_lea_disassembly(basic_block, lea_index, *mem);

	if (!lea_disassembly)
	{
		return false;
	}

	const auto base = symbol_base_rva(basic_block);

	if (!base)
	{
		return false;
	}

	const std::int32_t count = estimate_jump_table_count(basic_block, disassembly_symbol_map_);
	const rva_t dispatcher_rva = last_instruction_rva_from_symbol(basic_block);

	if (mem->has_displacement)
	{
		const auto displacement = static_cast<rva_t::value_type>(mem->displacement);
		const auto byte_offset = instruction_byte_offset(basic_block, mov_index);
		const rva_t mov_rva{ base + byte_offset };

		std::shared_ptr<symbol_t> self_symbol;
		basic_block_t::size_type self_instr_index = mov_index;

		if (byte_offset > 0)
		{
			auto new_symbol = basic_block.split(*this, byte_offset);

			if (!new_symbol)
			{
				return false;
			}

			new_symbol->set_rva(mov_rva);
			disassembly_symbol_map_[mov_rva.value()] = new_symbol;
			self_symbol = new_symbol;
			self_instr_index = 0;
		}
		else
		{
			self_symbol = basic_block.shared_from_this();
		}

		auto target_symbol = find_or_create_symbol(rva_t{ displacement });

		if (target_symbol)
		{
			auto ref = std::make_shared<msvc_jmp_table_symbol_ref_t>(
				target_symbol, self_symbol, static_cast<symbol_ref_t::size_type>(mov_disassembly.size())
			);

			if (const auto self_block = std::dynamic_pointer_cast<basic_block_t>(self_symbol))
			{
				ref->set_self_instr_id(self_block->at(self_instr_index).id());
			}

			symbol_refs_.push_back(ref);
		}

		if (!process_multi_level_jump_table(basic_block, rva_t{ displacement }, dispatcher_rva))
		{
			add_msvc_jmp_table_ref(rva_t{ displacement }, count, dispatcher_rva);
		}

		return byte_offset > 0;
	}
	else
	{
		const auto lea_byte_offset = instruction_byte_offset(basic_block, lea_index);
		const rva_t lea_rva{ base + lea_byte_offset };

		if (const auto table_base = resolve_instruction_rva(*lea_disassembly, lea_rva))
		{
			add_llvm_jmp_table_ref(rva_t{ *table_base }, count, dispatcher_rva);
		}
	}

	return false;
}

void binwrite::binary_t::find_jump_tables(basic_block_t& basic_block)
{
	const auto& instructions = basic_block.instructions();

	std::optional<basic_block_t::size_type> latest_lea = std::nullopt;

	for (std::uint32_t i = 0; i < instructions.size(); i++)
	{
		const auto& instruction = instructions[i];
		const auto& disassembled_instruction = instruction.disassemble();

		if (disassembled_instruction.is_lea() && disassembled_instruction.rip_relative())
		{
			latest_lea = i;
		}
		else if (latest_lea && disassembled_instruction.is_mov())
		{
			if (process_jump_table_instruction(basic_block, disassembled_instruction, i, *latest_lea))
			{
				break;
			}
		}
	}
}

void binwrite::binary_t::add_llvm_jmp_table_ref(const rva_t table_base, const std::int32_t count, const rva_t dispatcher_rva)
{
	auto table_base_symbol = find_or_create_symbol(table_base);

	if (!table_base_symbol)
	{
		return;
	}

	rva_t table_entry = table_base;

	std::int32_t i = 0;

	while (count == -1 || i++ < count)
	{
		const auto offset = *reinterpret_cast<const std::int32_t*>(data() + table_entry.value());
		const rva_t target_rva{ table_base.value() + offset };

		if (!is_in_code_section(target_rva))
		{
			break;
		}

		auto self_symbol = find_or_create_symbol(table_entry);
		auto target_symbol = find_or_create_symbol(target_rva, 0);

		if (self_symbol && target_symbol)
		{
			auto symbol_ref = std::make_shared<llvm_jmp_table_symbol_ref_t>(
				target_symbol, self_symbol, table_base_symbol
			);

			symbol_refs_.push_back(symbol_ref);
			symbol_ref_map_[table_entry.value()] = symbol_ref;
		}

		const auto target_rva_ptr = std::make_shared<rva_t>(target_rva);

		add_jump_table_target(dispatcher_rva, target_rva_ptr);
		add_to_disassembly_queue(target_rva_ptr);

		table_entry.set_value(table_entry.value() + sizeof(std::int32_t));
	}
}

void binwrite::binary_t::add_msvc_jmp_table_ref(const rva_t table_base, const std::int32_t count, const rva_t dispatcher_rva)
{
	rva_t table_entry = table_base;

	std::int32_t i = 0;

	while (count == -1 || i++ < count)
	{
		const auto entry = reinterpret_cast<const rva_t::value_type*>(data() + table_entry.value());

		if (!is_in_code_section(rva_t{ *entry }))
		{
			break;
		}

		add_data_rva_ref(entry);

		const auto target_rva = add_rva(*entry);
		add_jump_table_target(dispatcher_rva, target_rva);
		add_to_disassembly_queue(target_rva);

		table_entry.set_value(table_entry.value() + sizeof(llvm_jmp_table_entry_t::size_type));
	}
}
