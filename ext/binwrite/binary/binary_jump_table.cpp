#include "binary.hpp"

static std::shared_ptr<binwrite::basic_block_t> previous_basic_block(const binwrite::basic_block_t& basic_block)
{
	const auto sec = basic_block.section();

	if (!sec)
	{
		return nullptr;
	}

	const auto& symbols = sec->symbols();
	auto it = basic_block.list_iterator();

	if (it == symbols.begin())
	{
		return nullptr;
	}

	--it;

	return std::dynamic_pointer_cast<binwrite::basic_block_t>(*it);
}

static std::int32_t estimate_jump_table_count(const binwrite::basic_block_t& basic_block)
{
	const auto last_block = previous_basic_block(basic_block);

	if (!last_block || last_block->count() < 2)
	{
		return -1;
	}

	const auto& index_instruction = last_block->at(last_block->count() - 2);
	const auto& index_disassembly = index_instruction.disassemble();

	if (!index_disassembly.is_sub() && !index_disassembly.is_cmp())
	{
		return -1;
	}

	const auto index_operands = index_disassembly.visible_operands();

	if (!index_operands.empty() && index_operands[1].is_imm())
	{
		const auto imm = index_operands[1].imm();

		return static_cast<std::int32_t>(imm.value.s) + 1;
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
	}
	else
	{
		self_symbol = pre_mov_block.shared_from_this();
	}

	auto target_symbol = find_or_create_symbol(rva_t{ displacement });

	if (target_symbol)
	{
		symbol_refs_.push_back(std::make_shared<msvc_jmp_table_symbol_ref_t>(
			target_symbol, self_symbol, static_cast<symbol_ref_t::size_type>(movzx_disassembly.size())
		));
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

	const std::int32_t count = estimate_jump_table_count(basic_block);
	const rva_t dispatcher_rva = last_instruction_rva_from_symbol(basic_block);

	if (mem->has_displacement)
	{
		const auto displacement = static_cast<rva_t::value_type>(mem->displacement);
		const auto byte_offset = instruction_byte_offset(basic_block, mov_index);
		const rva_t mov_rva{ base + byte_offset };

		std::shared_ptr<symbol_t> self_symbol;

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
		}
		else
		{
			self_symbol = basic_block.shared_from_this();
		}

		auto target_symbol = find_or_create_symbol(rva_t{ displacement });

		if (target_symbol)
		{
			symbol_refs_.push_back(std::make_shared<msvc_jmp_table_symbol_ref_t>(
				target_symbol, self_symbol, static_cast<symbol_ref_t::size_type>(mov_disassembly.size())
			));
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
		auto target_symbol = find_or_create_symbol(target_rva);

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

		const auto ref = add_data_rva_ref(entry);

		add_jump_table_target(dispatcher_rva, ref->target());
		add_to_disassembly_queue(ref->target());

		table_entry.set_value(table_entry.value() + sizeof(llvm_jmp_table_entry_t::size_type));
	}
}
