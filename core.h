#ifndef _DED_CORE_H
#define _DED_CORE_H

#include <cstdint>
#include <vector>
#include <list>

#include "binary.h"


enum class Address_type { Nccf, Main, Call, Jump, JmpX };

struct XRef {
    uint64_t address;
    uint32_t insn_id;
    std::string istr;

    XRef(uint64_t addr, uint32_t id, std::string s)
		: address(addr), insn_id(id), istr(s){}
};

struct Address {
    uint64_t value;
    bool visited;
    Address_type type;
    std::vector<XRef> xref;

	Address(const uint64_t a, bool b, Address_type t)
		: value(a), visited(b), type(t){}
};


std::list<Address> analyze(const Binary& b);

void rt_disasm(const Binary &b, Address &a, std::list<Address> &addr_list);
void ls_disasm(const Binary &b);


#endif // _DED_CORE_H
