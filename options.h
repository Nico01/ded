#ifndef DED_OPTIONS_H
#define DED_OPTIONS_H

#include <string>
#include <cstdint>


struct Options {
    std::string filename {};
    std::string syntaxt {};
    bool mz = false;
    bool recursive = false;
    bool hdr = false;
    bool verbose = false;
    bool entry = false;
    bool syntax = false;
    uint64_t ep = 0;

    Options(int argc, char *argv[]);
};


void usage(std::string s);



#endif // DED_OPTIONS_H
