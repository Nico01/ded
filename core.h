#ifndef _DED_CORE_H
#define _DED_CORE_H

#include <cstdint>
#include <list>


enum class Address_type { Undefined, Call, Jump };

struct Address {
    uint64_t value;
    bool visited;
    Address_type type;

    Address(){}

	Address(const uint64_t a)
		: value(a), visited(false), type(Address_type::Undefined){}

	Address(const uint64_t a, bool b)
		: value(a), visited(b), type(Address_type::Undefined){}

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


std::list<Address> search_addr(uint64_t addr, size_t size, uint8_t *buffer, Address_type t);

void rt_disasm(uint64_t entry, uint64_t addr, size_t size, uint8_t *buffer, Address call, std::list<Address> jump);
void ls_disasm(uint64_t addr, size_t size, uint8_t *buffer);


#endif // _DED_CORE_H
