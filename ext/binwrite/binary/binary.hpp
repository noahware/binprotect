#pragma once
#include "../block/data_block.hpp"
#include "function/function.hpp"
#include "section/section.hpp"

#include <unordered_map>
#include <unordered_set>
#include <map>
#include <vector>
#include <string>
#include <memory>
#include <span>
#include <queue>
#include <chrono>
#include <ranges>

namespace binwrite
{
	class relocation_t;
	class section_t;

	struct pending_disasm_t
	{
		std::shared_ptr<rva_t> rva;
		bool risky;
	};

	class binary_t
	{
	public:
		explicit binary_t(std::vector<std::uint8_t> buffer)
				:	buffer_(std::move(buffer)) { }

		virtual ~binary_t() = default;

		void parse();

		void disassemble();

		void insert(rva_t rva, std::span<const std::uint8_t> data, bool inclusive = false);
		void insert(rva_t rva, rva_t::size_type size, bool inclusive = false);

		void erase(rva_t rva, rva_t::size_type size, bool inclusive = false);

		virtual void decompress() = 0;
		virtual void compress() = 0;

		[[nodiscard]] virtual std::uint64_t image_base() const = 0;
		[[nodiscard]] virtual rva_t entry_point() const = 0;
		[[nodiscard]] virtual std::size_t section_alignment() const = 0;

		[[nodiscard]] std::span<std::shared_ptr<function_t>> functions();
		[[nodiscard]] std::span<const std::shared_ptr<function_t>> functions() const;

		std::shared_ptr<function_t> find_function(rva_t rva) const;
		std::shared_ptr<function_t> create_function(const std::string& name, rva_t rva);
		std::shared_ptr<function_t> create_function(rva_t rva);

		void add_function(const std::shared_ptr<function_t>& function);
		void remove_function(const std::shared_ptr<function_t>& function);

		std::shared_ptr<data_block_t> create_data_block(section_t& section, std::span<const std::uint8_t> bytes,
		                                                std::optional<rva_t> rva = std::nullopt);

		std::shared_ptr<basic_block_t> create_basic_block(section_t& section,
		                                                  std::span<const instruction_t> instructions,
		                                                  std::optional<rva_t> rva = std::nullopt);

		void unlink_basic_block(std::shared_ptr<basic_block_t> basic_block);

		[[nodiscard]] std::span<std::shared_ptr<basic_block_t>> basic_blocks();
		[[nodiscard]] std::span<const std::shared_ptr<basic_block_t>> basic_blocks() const;

		[[nodiscard]] std::shared_ptr<basic_block_t> find_basic_block(rva_t rva) const;
		[[nodiscard]] std::shared_ptr<basic_block_t> find_containing_basic_block(rva_t rva) const;
		[[nodiscard]] bool is_inside_basic_block(rva_t rva) const;
		[[nodiscard]] std::span<const std::shared_ptr<rva_t>> jump_table_targets(rva_t dispatcher_rva) const;
		std::shared_ptr<basic_block_t> split_basic_block(basic_block_t& basic_block, basic_block_t::size_type index);

		[[nodiscard]] std::vector<std::shared_ptr<rva_t>> rvas();
		[[nodiscard]] std::vector<std::shared_ptr<rva_ref_t>> rva_refs();

		[[nodiscard]] std::unordered_map<std::string, std::shared_ptr<section_t>>& sections();
		[[nodiscard]] const std::unordered_map<std::string, std::shared_ptr<section_t>>& sections() const;

		[[nodiscard]] std::vector<std::shared_ptr<section_t>> ordered_sections() const;

		void add_data_symbol(rva_t rva);
		[[nodiscard]] bool is_data_symbol(rva_t rva) const;

		[[nodiscard]] std::shared_ptr<section_t> find_section(const std::string& name) const;
		[[nodiscard]] std::shared_ptr<section_t> find_section(rva_t rva) const;
		[[nodiscard]] std::shared_ptr<section_t> code_section() const;
		[[nodiscard]] std::shared_ptr<section_t> data_section() const;

		[[nodiscard]] bool is_in_code_section(rva_t rva) const;
		[[nodiscard]] bool is_in_data_section(rva_t rva) const;

		[[nodiscard]] std::vector<std::uint8_t>& buffer();
		[[nodiscard]] const std::vector<std::uint8_t>& buffer() const;

		[[nodiscard]] std::size_t size() const;

		[[nodiscard]] std::uint8_t* data();
		[[nodiscard]] const std::uint8_t* data() const;

		void update_rva_references();

		void update_rvas(rva_t disruption_rva, rva_t::size_type disruption_size, bool inclusive = false, bool update_sections = true);

		[[nodiscard]] std::shared_ptr<rva_ref_t> find_rva_ref(rva_t ref_rva, bool must_be_code_reference = false) const;
		[[nodiscard]] std::vector<std::shared_ptr<rva_ref_t>> find_all_targetted_rva_refs(rva_t target_rva) const;

		template <class T>
		[[nodiscard]] std::shared_ptr<T> find_symbol_ref(const rva_t self_rva) const
		{
			const auto it = symbol_ref_map_.find(self_rva.value());

			if (it == symbol_ref_map_.end())
			{
				return { };
			}

			return std::dynamic_pointer_cast<T>(it->second);
		}

		std::shared_ptr<rva_t> add_rva(rva_t::value_type value, bool force_inclusive = false);
		std::shared_ptr<rva_t> add_rva(rva_t rva, bool force_inclusive = false);

		[[nodiscard]] bool is_rva_valid(rva_t rva) const;
		[[nodiscard]] bool is_rva_valid(rva_t::value_type rva) const;

		void add_rva_ref(std::shared_ptr<rva_ref_t> ref);
		void redirect_rva_ref(rva_t self, rva_t new_target);
		void add_jump_table_target(rva_t dispatcher_rva, const std::shared_ptr<rva_t>& target);

		[[nodiscard]] bool is_inside_disassembly_queue(rva_t rva) const;
		void add_to_disassembly_queue(const std::shared_ptr<rva_t>& rva, bool risky = false);

		void reindex_basic_blocks() const;
		void reindex_functions() const;

		template <class T>
		std::shared_ptr<rva_ref_t> add_data_rva_ref(const T* const value, const bool force_inclusive = false)
		{
			const rva_t data_reference(static_cast<rva_t::value_type>(reinterpret_cast<const std::uint8_t*>(value) - data()));

			if (const auto existing_ref = find_rva_ref(data_reference))
			{
				return existing_ref;
			}

			const auto data_rva = add_rva(static_cast<rva_t::value_type>(*value), force_inclusive);

			const auto ref = std::make_shared<data_rva_ref_t>(data_rva, data_reference, static_cast<data_rva_ref_t::size_type>(sizeof(T)));

			add_rva_ref(ref);

			return ref;
		}

		void assign_basic_block_to_function(const std::shared_ptr<function_t>& function, const std::shared_ptr<basic_block_t>& basic_block) const;

		void recompile();

	protected:
		virtual void find_data_rvas() = 0;
		virtual void find_sections() = 0;
		virtual void update_section_headers() = 0;
		virtual void update_relocations() = 0;
		virtual bool is_definitely_in_code_range(rva_t rva) const = 0;

		std::shared_ptr<symbol_t> find_containing_symbol(rva_t rva) const;
		std::shared_ptr<symbol_t> find_or_split_symbol(rva_t rva);
		void fill_code_section_empty_space();
		void erase_symbol(std::shared_ptr<symbol_t> symbol);
		void clear_symbol_rvas();
		void process_disassembly_queue();
		void split_basic_blocks_in_data();
		void populate_data_symbol_refs();
		void populate_code_symbol_refs();
		void populate_dir64_reloc_symbol_refs();
		void populate_llvm_jmp_table_symbol_refs();
		void populate_fh4_encoded_symbol_refs();

		void process_instruction_rip_relativity(const disassembled_instruction_t& disassembled_instruction,
		                                        rva_t instruction_rva, rva_t next_instruction_rva,
		                                        std::vector<std::shared_ptr<rva_t>>& risky_references);

		bool collect_basic_block_instructions(const disassembler_t& disassembler, std::vector<instruction_t>& instructions, rva_t block_rva, std::uint32_t& block_size,
		                                      bool is_risky, std::vector<std::shared_ptr<rva_t>>& risky_references);

		bool process_multi_level_jump_table(const basic_block_t& basic_block, rva_t entry_table_base,
		                                    basic_block_t::size_type mov_index);

		void process_jump_table_instruction(const basic_block_t& basic_block,
		                                    const disassembled_instruction_t& mov_disassembly,
		                                    basic_block_t::size_type mov_index,
		                                    basic_block_t::size_type lea_index);

		std::shared_ptr<data_block_t> create_data_block_from_rva(section_t& section, const rva_t rva, const symbol_t::size_type size)
		{
			const std::span<const std::uint8_t> bytes(data() + rva.value(), size);

			return create_data_block(section, bytes, rva);
		}

		void find_jump_tables(const basic_block_t& basic_block);

		void assign_function_basic_blocks();

		void update_section_rvas(rva_t disruption_rva, rva_t::size_type disruption_size);

		std::shared_ptr<rva_t> add_relocation_rva(rva_t::value_type target);
		std::shared_ptr<rva_t> add_relocation_rva(rva_t target);

		void add_llvm_jmp_table_ref(rva_t table_base, std::int32_t count, rva_t dispatcher_rva);
		void add_msvc_jmp_table_ref(rva_t table_base, std::int32_t count, rva_t dispatcher_rva);

		std::vector<std::uint8_t> buffer_;
		std::unordered_map<std::string, std::shared_ptr<section_t>> sections_;

		std::vector<std::shared_ptr<symbol_t>> symbols_;
		std::vector<std::shared_ptr<symbol_ref_t>> symbol_refs_;
		std::unordered_map<rva_t::value_type, std::shared_ptr<symbol_ref_t>> symbol_ref_map_;

		std::vector<std::shared_ptr<rva_t>> rva_blocks_;

		std::vector<std::shared_ptr<rva_t>> rvas_;
		std::vector<std::shared_ptr<rva_ref_t>> rva_refs_;

		std::vector<std::shared_ptr<basic_block_t>> basic_blocks_;
		std::unordered_map<rva_t::value_type, std::vector<std::shared_ptr<rva_t>>> jump_table_targets_;
		std::deque<pending_disasm_t> disassembly_queue_;
		std::unordered_set<rva_t::value_type> disassembly_queue_set_;

		std::vector<std::shared_ptr<rva_t>> data_symbols_;
		std::vector<std::shared_ptr<function_t>> functions_;

		std::vector<std::shared_ptr<relocation_t>> relocations_;

		mutable std::map<rva_t::value_type, std::shared_ptr<symbol_t>> disassembly_symbol_map_;

		// lookup caches - mutable because they are rebuilt lazily from const lookup methods
		mutable bool bb_index_dirty_ = true;
		mutable std::unordered_map<rva_t::value_type, std::shared_ptr<basic_block_t>> bb_index_;
		mutable std::map<rva_t::value_type, std::shared_ptr<basic_block_t>> bb_interval_index_;

		mutable bool fn_index_dirty_ = true;
		mutable std::unordered_map<rva_t::value_type, std::shared_ptr<function_t>> fn_index_;
	};
}
