#pragma once
#include "../../block/basic_block.hpp"

#include <unordered_map>

namespace binwrite
{
	class binary_t;

	class function_t
	{
	public:
		function_t() = default;

		explicit function_t(std::string name, std::shared_ptr<rva_t> rva)
				:	name_(std::move(name)),
					rva_(std::move(rva)) { }

		void add_basic_block(std::shared_ptr<basic_block_t> basic_block);
		void unlink_basic_block(std::shared_ptr<basic_block_t> basic_block);

		void set_basic_blocks_skip(bool state) const;
		void set_basic_blocks_dirty(bool state);

		[[nodiscard]] std::shared_ptr<basic_block_t> find_basic_block(rva_t rva) const;
		[[nodiscard]] std::shared_ptr<basic_block_t> entry_block() const;

		[[nodiscard]] std::vector<std::shared_ptr<basic_block_t>> exit_blocks(const binary_t& binary) const;

		[[nodiscard]] std::shared_ptr<basic_block_t> fallthrough_block(const std::shared_ptr<basic_block_t>& basic_block) const;
		[[nodiscard]] std::shared_ptr<basic_block_t> target_block(const binary_t& binary, const std::shared_ptr<basic_block_t>& basic_block) const;

		[[nodiscard]] std::span<std::shared_ptr<basic_block_t>> basic_blocks();
		[[nodiscard]] std::span<const std::shared_ptr<basic_block_t>> basic_blocks() const;

		[[nodiscard]] std::shared_ptr<rva_t> rva() const;

		[[nodiscard]] std::string_view name() const;

		void reindex_basic_blocks() const;

	protected:
		std::string name_ = { };
		std::shared_ptr<rva_t> rva_ = { };

		std::vector<std::shared_ptr<basic_block_t>> basic_blocks_;

		mutable bool bb_index_dirty_ = true;
		mutable std::unordered_map<rva_t::value_type, std::shared_ptr<basic_block_t>> bb_index_;
	};
}
