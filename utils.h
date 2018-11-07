#ifndef DED_UTILS_H
#define DED_UTILS_H

#include <cstdio>
#include <cctype>
#include <map>

#include "analyzer.h"
#include "binary.h"

struct Gap {
    uint64_t next_addr;
    uint64_t last_addr;

    Gap() : next_addr(0), last_addr(0) {}
    void fill_gap(const Binary& b);
};

void print_addr_list(const std::map<uint64_t, Analyzer::Address>& l, uint64_t last_vaddr);

#endif // DED_UTILS_H
