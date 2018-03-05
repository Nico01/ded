#ifndef _DED_OPTIONS_H_
#define _DED_OPTIONS_H_

#include <string>
#include <cstdint>


struct Options {
    std::string filename {};
    bool mz = false;
    bool recursive = false;
    bool hdr = false;
    bool verbose = false;
    bool entry = false;
    uint64_t ep = 0;

    Options(int argc, char *argv[]);
};


void usage(std::string s);



#endif //_DED_OPTIONS_H_
