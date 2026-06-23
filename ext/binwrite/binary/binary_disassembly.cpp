#include "binary.hpp"

#include <algorithm>
#include <typeinfo>
#include <spdlog/spdlog.h>

static void process_function_basic_block(const binwrite::binary_t& binary,
                                         const std::shared_ptr<binwrite::function_t>& function,
                                         const std::shared_ptr<binwrite::basic_block_t>& current_block);

static void process_basic_block_target_branch(const binwrite::binary_t& binary,
                                              const std::shared_ptr<binwrite::function_t>& function,
                                              const std::shared_ptr<binwrite::basic_block_t>& current_block,
                                              const binwrite::disassembled_instruction_t& last_instruction_disassembly)
{
	const auto last_instruction_rva = current_block->last_instruction_rva();

	const auto code_rva_ref = binary.find_rva_ref(last_instruction_rva);

	if (!code_rva_ref)
	{
		const auto jt_targets = binary.jump_table_targets(last_instruction_rva);

		if (jt_targets.empty())
		{
			spdlog::error("unable to find code rva ref of conditional jump at 0x{:X}", last_instruction_rva.value());
			return;
		}

		for (const auto& jt_target : jt_targets)
		{
			const auto target_block = binary.find_basic_block(*jt_target);

			if (!target_block)
			{
				continue;
			}

			if (!binary.find_function(*jt_target) && !function->find_basic_block(*jt_target))
			{
				function->add_basic_block(target_block);

				process_function_basic_block(binary, function, target_block);
			}
		}

		return;
	}

	const auto target_rva = *code_rva_ref->target();

	const auto target_basic_block = binary.find_basic_block(target_rva);

	if (!target_basic_block)
	{
		spdlog::error("unable to find target basic block");

		return;
	}

	if (!binary.find_function(target_rva) && !function->find_basic_block(target_rva))
	{
		function->add_basic_block(target_basic_block);

		process_function_basic_block(binary, function, target_basic_block);
	}
}

static void process_basic_block_fallthrough_branch(const binwrite::binary_t& binary,
                                                   const std::shared_ptr<binwrite::function_t>& function,
                                                   const std::shared_ptr<binwrite::basic_block_t>& current_block)
{
	const auto fallthrough_rva = current_block->end_rva();

	const auto fallthrough_basic_block = binary.find_basic_block(fallthrough_rva);

	if (!fallthrough_basic_block)
	{
		spdlog::error("unable to find fallthrough basic block");

		return;
	}

	if (!binary.find_function(fallthrough_rva) && !function->find_basic_block(fallthrough_rva))
	{
		function->add_basic_block(fallthrough_basic_block);

		process_function_basic_block(binary, function, fallthrough_basic_block);
	}
}

static void process_function_basic_block(const binwrite::binary_t& binary,
                                         const std::shared_ptr<binwrite::function_t>& function,
                                         const std::shared_ptr<binwrite::basic_block_t>& current_block)
{
	const auto& last_instruction = current_block->last_instruction();
	const auto& last_instruction_disassembly = last_instruction.disassemble();

	if (last_instruction_disassembly.is_ret())
	{
		return;
	}

	if (last_instruction_disassembly.is_jump())
	{
		process_basic_block_target_branch(binary, function, current_block, last_instruction_disassembly);
	}

	if (!last_instruction_disassembly.is_unconditional_jump())
	{
		process_basic_block_fallthrough_branch(binary, function, current_block);
	}
}

void binwrite::binary_t::assign_function_basic_blocks()
{
	std::vector<std::shared_ptr<function_t>> removal_functions = { };

	for (const auto& function : functions_)
	{
		const auto basic_block = find_basic_block(*function->rva());

		if (!basic_block)
		{
			removal_functions.push_back(function);

			continue;
		}

		assign_basic_block_to_function(function, basic_block);

		spdlog::info("{} has {} basic block(s)", function->name(), function->basic_blocks().size());
	}

	for (const auto& function : removal_functions)
	{
		remove_function(function);
	}
}

void binwrite::binary_t::assign_basic_block_to_function(const std::shared_ptr<function_t>& function,
                                                        const std::shared_ptr<basic_block_t>& basic_block) const
{
	function->add_basic_block(basic_block);

	process_function_basic_block(*this, function, basic_block);
}

void binwrite::binary_t::process_instruction_rip_relativity(const disassembled_instruction_t& disassembled_instruction,
                                                            const rva_t instruction_rva, const rva_t next_instruction_rva,
	                                                        std::vector<std::shared_ptr<rva_t>>& risky_references)
{
	if (const auto raw_target_rva = resolve_instruction_rva(disassembled_instruction, instruction_rva))
	{
		const auto target_rva = add_rva(*raw_target_rva);

		add_rva_ref(std::make_shared<code_rva_ref_t>(target_rva, rva_t{ instruction_rva }, disassembled_instruction.size()));

		const bool is_risky_reference = disassembled_instruction.is_lea();

		if (disassembled_instruction.is_control_flow() && is_in_code_section(*target_rva))
		{
			if (disassembled_instruction.is_conditional_jump())
			{
				const auto fallthrough_rva = add_rva(next_instruction_rva);

				add_to_disassembly_queue(fallthrough_rva);
			}

			add_to_disassembly_queue(target_rva);
		}
		else if (is_risky_reference && is_in_code_section(*target_rva) &&
			(!is_data_symbol(*target_rva) || is_definitely_in_code_range(*target_rva)))
		{
			risky_references.push_back(target_rva);
		}
	}
}

bool binwrite::binary_t::collect_basic_block_instructions(const disassembler_t& disassembler,
                                                          std::vector<instruction_t>& instructions,
                                                          const rva_t block_rva, std::uint32_t& block_size,
                                                          const bool is_risky,
                                                          std::vector<std::shared_ptr<rva_t>>& risky_references)
{
	rva_t instruction_rva = block_rva;

	while (true)
	{
		if (instruction_rva.value() == 0x5D72)
		{
			//__debugbreak();
		}

		constexpr std::size_t max_padding_count = 16;

		if (instruction_rva.value() + max_padding_count <= buffer_.size())
		{
			const auto* p = buffer_.data() + instruction_rva.value();
			bool all_zero = true;
			bool all_cc = true;

			for (std::uint32_t k = 0; k < max_padding_count; k++)
			{
				if (p[k] != 0x00) all_zero = false;
				if (p[k] != 0xCC) all_cc = false;
			}

			if (all_zero || all_cc)
			{
				break;
			}
		}

		const auto instruction_address = reinterpret_cast<const std::uint8_t*>(buffer_.data() + instruction_rva.value());
		const auto disassembled_instruction = disassembler.disassemble(instruction_address);

		if (!disassembled_instruction)
		{
			if (is_risky)
			{
				return false;
			}

			break;
		}

		if (const auto existing = find_containing_symbol(instruction_rva))
		{
			const auto existing_rva = existing->rva();

			if (existing_rva && *existing_rva != instruction_rva)
			{
				const auto byte_offset = static_cast<symbol_t::size_type>(
					instruction_rva.value() - existing_rva->value());

				if (const auto new_symbol = existing->split(*this, byte_offset))
				{
					new_symbol->set_rva(instruction_rva);
					disassembly_symbol_map_[instruction_rva.value()] = new_symbol;
				}
			}

			break;
		}

		const rva_t next_instruction_rva(instruction_rva.value() + disassembled_instruction->size());

		const instruction_t::const_value_type instruction_bytes(instruction_address, disassembled_instruction->size());

		process_instruction_rip_relativity(*disassembled_instruction, instruction_rva, next_instruction_rva, risky_references);

		instructions.emplace_back(instruction_bytes, *disassembled_instruction);

		if (disassembled_instruction->is_jump() || disassembled_instruction->is_ret() ||
			disassembled_instruction->is_int() || disassembled_instruction->is_ud())
		{
			break;
		}

		block_size += disassembled_instruction->size();
		instruction_rva = next_instruction_rva;
	}

	return true;
}

std::shared_ptr<binwrite::symbol_t> binwrite::binary_t::find_containing_symbol(const rva_t rva) const
{
	const auto it = disassembly_symbol_map_.upper_bound(rva.value());

	if (it == disassembly_symbol_map_.begin())
	{
		return { };
	}

	const auto& candidate = std::prev(it)->second;
	const auto end = candidate->end_rva();

	if (!end || rva >= *end)
	{
		return { };
	}

	return candidate;
}

std::shared_ptr<binwrite::symbol_t> binwrite::binary_t::find_or_split_symbol(const rva_t rva)
{
	auto containing = find_containing_symbol(rva);

	if (!containing)
	{
		return { };
	}

	const auto containing_rva = containing->rva();

	if (!containing_rva || *containing_rva == rva)
	{
		return containing;
	}

	const auto byte_offset = static_cast<symbol_t::size_type>(rva.value() - containing_rva->value());

	auto new_symbol = containing->split(*this, byte_offset);

	if (!new_symbol)
	{
		return { };
	}

	new_symbol->set_rva(rva);
	disassembly_symbol_map_[rva.value()] = new_symbol;

	return new_symbol;
}

std::shared_ptr<binwrite::symbol_t> binwrite::binary_t::find_or_create_symbol(const rva_t rva, const symbol_t::size_type size)
{
	if (auto symbol = find_or_split_symbol(rva))
	{
		return symbol;
	}

	if (const auto it = disassembly_symbol_map_.find(rva.value()); it != disassembly_symbol_map_.end())
	{
		return it->second;
	}

	auto section = find_section(rva);

	if (!section)
	{
		return { };
	}

	return create_data_block_from_rva(*section, rva, size);
}

void binwrite::binary_t::fill_code_section_empty_space()
{
	for (const auto& section : sections_ | std::views::values)
	{
		if (!section->code())
		{
			continue;
		}

		std::vector<std::shared_ptr<symbol_t>> sorted_symbols;

		for (const auto& symbol : section->symbols())
		{
			if (symbol->rva())
			{
				sorted_symbols.push_back(symbol);
			}
		}

		const rva_t section_start = section->rva();
		const rva_t section_end{ section_start.value() + section->size() };

		if (sorted_symbols.empty())
		{
			if (section->size() > 0)
			{
				create_data_block_from_rva(*section, section_start, section->size());
			}

			continue;
		}

		std::ranges::sort(sorted_symbols, [](const auto& a, const auto& b)
		{
			return a->rva()->value() < b->rva()->value();
		});

		const rva_t first_rva = *sorted_symbols.front()->rva();

		if (section_start < first_rva)
		{
			const auto gap_size = first_rva.value() - section_start.value();

			create_data_block_from_rva(*section, section_start, gap_size);
		}

		for (std::size_t i = 0; i + 1 < sorted_symbols.size(); i++)
		{
			const auto end_rva = sorted_symbols[i]->end_rva();
			const auto next_rva = sorted_symbols[i + 1]->rva();

			if (!end_rva || !next_rva)
			{
				continue;
			}

			if (*end_rva < *next_rva)
			{
				const auto gap_size = next_rva->value() - end_rva->value();

				create_data_block_from_rva(*section, *end_rva, gap_size);
			}
		}

		const auto last_end = sorted_symbols.back()->end_rva();

		if (last_end && *last_end < section_end)
		{
			const auto gap_size = section_end.value() - last_end->value();

			create_data_block_from_rva(*section, *last_end, gap_size);
		}

		section->sort_by_rva();
	}
}

void binwrite::binary_t::erase_symbol(std::shared_ptr<symbol_t> symbol)
{
	if (const auto section = symbol->section())
	{
		section->remove_symbol(symbol);
	}

	std::erase(symbols_, symbol);

	if (const auto rva = symbol->rva())
	{
		disassembly_symbol_map_.erase(rva->value());
	}

	if (const auto bb = std::dynamic_pointer_cast<basic_block_t>(symbol))
	{
		std::erase(basic_blocks_, bb);
		bb_index_dirty_ = true;
	}
}

void binwrite::binary_t::clear_symbol_rvas()
{
	for (const auto& symbol : symbols_)
	{
		symbol->set_rva(std::nullopt);
	}
}

void binwrite::binary_t::process_disassembly_queue()
{
	const disassembler_t disassembler;

	bb_index_dirty_ = false;
	fn_index_dirty_ = false;

	std::unordered_map<symbol_t*, std::shared_ptr<symbol_t>> placeholder_replacements;

	while (!disassembly_queue_.empty())
	{
		const auto entry = disassembly_queue_.front();
		disassembly_queue_.pop_front();

		std::shared_ptr<symbol_t> placeholder;

		if (const auto it = disassembly_symbol_map_.find(entry.rva->value()); it != disassembly_symbol_map_.end())
		{
			if (const auto db = std::dynamic_pointer_cast<data_block_t>(it->second); db && db->size() == 0)
			{
				placeholder = db;
				erase_symbol(placeholder);
			}
		}

		std::vector<instruction_t> instructions = { };
		std::vector<std::shared_ptr<rva_t>> risky_references = { };

		std::uint32_t block_size = 0;

		if (!collect_basic_block_instructions(disassembler, instructions, *entry.rva, block_size, entry.risky, risky_references) ||
			instructions.empty())
		{
			continue;
		}

		const auto section = find_section(*entry.rva);

		auto basic_block = create_basic_block(*section, instructions, *entry.rva);

		if (placeholder)
		{
			placeholder_replacements[placeholder.get()] = basic_block;
		}

		find_jump_tables(*basic_block);

		for (const auto& risky_rva : risky_references)
		{
			if (find_rva_ref(*risky_rva))
			{
				continue;
			}

			add_to_disassembly_queue(risky_rva, true);
		}
	}

	if (!placeholder_replacements.empty())
	{
		for (const auto& ref : symbol_refs_)
		{
			if (const auto it = placeholder_replacements.find(ref->target().get()); it != placeholder_replacements.end())
			{
				ref->set_target(it->second);
			}
		}
	}

	split_basic_blocks_in_data();
}

void binwrite::binary_t::split_basic_blocks_in_data()
{
	for (const auto& rva_ref : rva_refs_)
	{
		const auto overlapping_block = find_containing_basic_block(rva_ref->self());

		if (!overlapping_block)
		{
			continue;
		}

		const auto jump_table_entry = std::dynamic_pointer_cast<llvm_jmp_table_entry_t>(rva_ref);
		const auto data_ref = std::dynamic_pointer_cast<data_rva_ref_t>(rva_ref);

		if (jump_table_entry || data_ref)
		{
			const auto index = overlapping_block->instruction_index(rva_ref->self());

			const auto split_block = split_basic_block(*overlapping_block, index);

			unlink_basic_block(split_block);
		}
	}
}

void binwrite::binary_t::populate_data_symbol_refs()
{
	struct convertible_ref_t
	{
		rva_t self_rva;
		rva_t::value_type target_rva_value;
		data_rva_ref_t::size_type encoding_size;
	};

	std::vector<convertible_ref_t> candidates;

	for (const auto& ref : rva_refs_)
	{
		if (typeid(*ref) != typeid(data_rva_ref_t))
		{
			continue;
		}

		const auto& data_ref = static_cast<const data_rva_ref_t&>(*ref);

		const rva_t self_rva = data_ref.self();
		const rva_t::value_type target_value = data_ref.target()->value();

		if (target_value == 0 || !is_rva_valid(rva_t{ target_value }))
		{
			continue;
		}

		candidates.push_back({ self_rva, target_value, data_ref.encoding_size() });
	}

	std::ranges::sort(candidates, [](const auto& a, const auto& b)
	{
		return a.self_rva < b.self_rva;
	});

	for (const auto& candidate : candidates)
	{
		auto self_symbol = find_or_split_symbol(candidate.self_rva);

		if (!self_symbol)
		{
			continue;
		}

		const rva_t target_rva{ candidate.target_rva_value };

		auto target_symbol = find_or_split_symbol(target_rva);

		if (!target_symbol)
		{
			continue;
		}

		symbol_refs_.push_back(std::make_shared<data_symbol_ref_t>(
			target_symbol,
			self_symbol,
			static_cast<symbol_ref_t::size_type>(candidate.encoding_size)
		));
	}

	spdlog::info("data symbol refs: {}", symbol_refs_.size());
}

void binwrite::binary_t::populate_code_symbol_refs()
{
	struct convertible_ref_t
	{
		rva_t self_rva;
		rva_t::value_type target_rva_value;
		code_rva_ref_t::size_type instruction_size;
	};

	std::vector<convertible_ref_t> candidates;

	for (const auto& ref : rva_refs_)
	{
		if (typeid(*ref) != typeid(code_rva_ref_t))
		{
			continue;
		}

		const auto& code_ref = static_cast<const code_rva_ref_t&>(*ref);

		const rva_t self_rva = code_ref.self();
		const rva_t::value_type target_value = code_ref.target()->value();

		if (!is_rva_valid(rva_t{ target_value }))
		{
			continue;
		}

		candidates.push_back({ self_rva, target_value, code_ref.instruction_size() });
	}

	std::ranges::sort(candidates, [](const auto& a, const auto& b)
	{
		return a.self_rva < b.self_rva;
	});

	for (const auto& candidate : candidates)
	{
		auto self_symbol = find_or_split_symbol(candidate.self_rva);

		if (!self_symbol)
		{
			continue;
		}

		const rva_t target_rva{ candidate.target_rva_value };

		auto target_symbol = find_or_split_symbol(target_rva);

		if (!target_symbol)
		{
			continue;
		}

		symbol_refs_.push_back(std::make_shared<code_symbol_ref_t>(
			target_symbol,
			self_symbol,
			static_cast<symbol_ref_t::size_type>(candidate.instruction_size)
		));
	}

	const auto code_ref_count = symbol_refs_.size() - std::ranges::count_if(symbol_refs_, [](const auto& ref)
	{
		return typeid(*ref) == typeid(data_symbol_ref_t);
	});

	spdlog::info("code symbol refs: {} (from {} candidates)", code_ref_count, candidates.size());
}

void binwrite::binary_t::populate_dir64_reloc_symbol_refs()
{
	struct candidate_t
	{
		rva_t self_rva;
		rva_t::value_type target_rva_value;
	};

	std::vector<candidate_t> candidates;

	for (const auto& ref : rva_refs_)
	{
		if (typeid(*ref) != typeid(pe_dir64_reloc_t))
		{
			continue;
		}

		const rva_t self_rva = ref->self();
		const rva_t::value_type target_value = ref->target()->value();

		if (target_value == 0 || !is_rva_valid(rva_t{ target_value }))
		{
			continue;
		}

		candidates.push_back({ self_rva, target_value });
	}

	std::ranges::sort(candidates, [](const auto& a, const auto& b)
	{
		return a.self_rva < b.self_rva;
	});

	for (const auto& candidate : candidates)
	{
		auto self_symbol = find_or_split_symbol(candidate.self_rva);

		if (!self_symbol)
		{
			continue;
		}

		const rva_t target_rva{ candidate.target_rva_value };

		auto target_symbol = find_or_split_symbol(target_rva);

		if (!target_symbol)
		{
			continue;
		}

		auto symbol_ref = std::make_shared<dir64_reloc_symbol_ref_t>(target_symbol, self_symbol);

		symbol_refs_.push_back(symbol_ref);
		symbol_ref_map_[candidate.self_rva.value()] = symbol_ref;
	}

	spdlog::info("dir64 reloc symbol refs: {}", candidates.size());
}

void binwrite::binary_t::populate_fh4_encoded_symbol_refs()
{
	struct candidate_t
	{
		rva_t self_rva;
		rva_t::value_type target_rva_value;
		rva_t::value_type previous_target_rva_value;
		std::uint32_t encoded_size;
	};

	std::vector<candidate_t> candidates;

	for (const auto& ref : rva_refs_)
	{
		if (typeid(*ref) != typeid(pe_fh4_encoded_entry_t))
		{
			continue;
		}

		const auto& entry = static_cast<const pe_fh4_encoded_entry_t&>(*ref);

		const rva_t self_rva = entry.self();
		const rva_t::value_type target_value = entry.target()->value();

		candidates.push_back({ self_rva, target_value, entry.previous_entry_target()->value(), entry.encoded_size() });
	}

	std::ranges::sort(candidates, [](const auto& a, const auto& b)
	{
		return a.self_rva < b.self_rva;
	});

	const auto find_or_split_symbol = [this](const rva_t rva) -> std::shared_ptr<symbol_t>
	{
		auto containing = find_containing_symbol(rva);

		if (!containing)
		{
			return { };
		}

		const auto containing_rva = containing->rva();

		if (!containing_rva)
		{
			return { };
		}

		if (*containing_rva == rva)
		{
			return containing;
		}

		const auto byte_offset = static_cast<symbol_t::size_type>(rva.value() - containing_rva->value());

		auto new_symbol = containing->split(*this, byte_offset);

		if (!new_symbol)
		{
			return { };
		}

		new_symbol->set_rva(rva);
		disassembly_symbol_map_[rva.value()] = new_symbol;

		return new_symbol;
	};

	std::size_t count = 0;

	for (const auto& candidate : candidates)
	{
		auto self_symbol = find_or_split_symbol(candidate.self_rva);

		if (!self_symbol)
		{
			continue;
		}

		const rva_t target_rva{ candidate.target_rva_value };

		auto target_symbol = find_or_split_symbol(target_rva);

		if (!target_symbol)
		{
			continue;
		}

		const rva_t prev_rva{ candidate.previous_target_rva_value };

		auto prev_symbol = find_or_split_symbol(prev_rva);

		if (!prev_symbol)
		{
			continue;
		}

		auto symbol_ref = std::make_shared<fh4_encoded_symbol_ref_t>(target_symbol, self_symbol, prev_symbol);

		symbol_refs_.push_back(symbol_ref);
		symbol_ref_map_[candidate.self_rva.value()] = symbol_ref;
		count++;
	}

	spdlog::info("fh4 encoded symbol refs: {}", count);
}

void binwrite::binary_t::disassemble()
{
	process_disassembly_queue();
	fill_code_section_empty_space();
	populate_data_symbol_refs();
	populate_code_symbol_refs();
	populate_dir64_reloc_symbol_refs();
	populate_fh4_encoded_symbol_refs();
	assign_function_basic_blocks();

	spdlog::info("basic block count: {}", basic_blocks_.size());

	clear_symbol_rvas();
}

bool binwrite::binary_t::is_inside_disassembly_queue(const rva_t rva) const
{
	return disassembly_queue_set_.contains(rva.value());
}

void binwrite::binary_t::add_to_disassembly_queue(const std::shared_ptr<rva_t>& rva, const bool risky)
{
	if (!is_in_code_section(*rva))
	{
		return;
	}

	if (!disassembly_queue_set_.contains(rva->value()) && !find_basic_block(*rva))
	{
		disassembly_queue_.emplace_back(rva, risky);
		disassembly_queue_set_.insert(rva->value());
	}
}
