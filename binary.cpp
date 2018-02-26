#include <fstream>
#include <cstdio>

#include "binary.h"

Binary::Binary(std::string s)
{
    std::ifstream f(s, std::ifstream::binary);

    if (!f.is_open()) {
        fprintf(stderr, "Error %s: No such file or directory\n", s.c_str());
        exit(EXIT_FAILURE);
    }

    f.seekg (0, f.end);
    size = f.tellg();
    f.seekg (0, f.beg);

    if (size == 0) {
        fprintf(stderr, "Error %s: empty file\n", s.c_str());
        f.close();
        exit(EXIT_FAILURE);
    }

    uint8_t *buffer = new uint8_t [size];

    f.read(reinterpret_cast<char*>(buffer), size);

    data.assign(buffer, buffer + size);

    delete[] buffer;
    f.close();
}

