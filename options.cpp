#include <getopt.h>
#include "options.h"

Options::Options(int argc, char *argv[])
{
    int c;

    while ((c = getopt(argc, argv, "Hmhrs:f:")) != -1) {
        switch (c) {
        case 'H':
            usage(argv[0]);
            break;
        case 'm':
            mz = true;
            break;
        case 'h':
            hdr = true;
            break;
        case 'r':
            recursive = true;
            break;
        case 's':
            entry = true;
            ep = strtol(optarg, NULL, 16);
            break;
        case 'f':
            filename = std::string {optarg};
            break;
        default:
            usage(std::string {argv[0]});
        }
    }
}

void usage(std::string s)
{
    fprintf(stderr,
            "\nUsage: %s <option> -f <file>\n"
            "\n\tOptions:\n"
            "\n\t-H    display this information\n"
            "\n\t-m    disassemble DOS MZ 16 bits executable\n"
            "\n\t-h    if -m display the DOS MZ header\n"
            "\n\t-r    disassemble file using recursive traversal algorithm (experimental)\n"
            "\n\t-s    specifies an entry point\n\n"
            "\n\t-f    input file\n\n"
            "\n\tNote:"
            "\n\tif no flags are given the input file is treated as a headerless 16 bits\n"
            "\texecutable (.COM) and the linear sweep algorithm is used.\n\n",
            s.c_str());

    exit(EXIT_FAILURE);
}
