#ifndef DED_CORE_H
#define DED_CORE_H

#include <cstdint>

#include "binary.h"
#include "analyzer.h"
#include "disassembler.h"


uint64_t rt_disasm(const Binary& b, Disasm::Disassembler& d, Analyzer::Address& a, std::map<uint64_t, Analyzer::Address>& addr_list);
void ls_disasm(const Binary& b, Disasm::Disassembler& d);

#endif // DED_CORE_H
