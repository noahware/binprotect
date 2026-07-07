#pragma once
#include <binwrite/binary/binary.hpp>
#include <binwrite/binary/pe/pe.hpp>

class vm_context_t;

namespace binprotect::vm
{
	std::shared_ptr<vm_context_t> do_pass(binwrite::binary_t& binary, binwrite::basic_block_t& basic_block,
	             std::vector<std::shared_ptr<binwrite::basic_block_t>>& virtual_machine_blocks);

	void emit_runtime_functions(binwrite::portable_executable_t& pe,
	                            const std::vector<std::shared_ptr<vm_context_t>>& vm_contexts,
								const std::shared_ptr<binwrite::rva_t>& exception_directory_rva,
	                            const std::shared_ptr<binwrite::rva_t>& unwind_insertion_rva);
}
