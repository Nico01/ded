#ifndef DED_UTILS_H
#define DED_UTILS_H

#include <cstdio>
#include <cctype>

#include "binary.h"

struct Gap {
    uint64_t next_addr;
    uint64_t last_addr;

    Gap() : next_addr(0), last_addr(0) {}
    void fill_gap(const Binary& b);
};

#endif // DED_UTILS_H
