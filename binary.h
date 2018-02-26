#ifndef _DED_BINARY_H_
#define _DED_BINARY_H_

#include <string>
#include <vector>
#include <cstdint>


struct Binary {
    std::string name;
    std::vector<uint8_t> data;
    size_t size;
    uint64_t entry;

    Binary(std::string s);
};


#endif //_DED_BINARY_H_
