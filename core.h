#ifndef _DED_CORE_H
#define _DED_CORE_H

#include <cstdint>
#include <list>

#include "binary.h"


enum class Address_type { Main, Call, Jump, JmpX };

struct Address {
    uint64_t value;
    bool visited;
    Address_type type;

	Address(const uint64_t a, bool b, Address_type t)
		: value(a), visited(b), type(t){}
};

inline bool equ_addr(Address a, Address b)
{
    return (a.value == b.value);
}

inline bool cmp_addr(Address a, Address b)
{
    return (a.value < b.value);
}


std::list<Address> search_addr(const Binary &b);

void rt_disasm(const Binary &b, Address &a, std::list<Address> &addr_list);
void ls_disasm(const Binary &b);


#endif // _DED_CORE_H
