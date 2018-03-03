// DOS Executable Disassembler

#include "core.h"
#include "binary.h"
#include "options.h"

#include <cstdio>


static void disasm(Options o, Binary b);


int main(int argc, char *argv[])
{
    if (argc < 2)
        usage(std::string {argv[0]});

    Options opts(argc, argv);

    if (opts.filename.empty()) {
        fprintf(stderr, "Invalid file name\n");
        usage(std::string {argv[0]});
    }

    Binary bin(opts);

    printf("File %s\t Size %zu (0x%zx) bytes\n", opts.filename.c_str(), bin.fsize, bin.fsize);

    disasm(opts, bin);

    return 0;
}


static void disasm(Options o, Binary b)
{
    if (o.recursive) {
        std::list<Address> addr_list = search_addr(b);

        for (auto& i : addr_list)
            if ((i.type != Address_type::JmpX) && !i.visited)
                rt_disasm(b, i, addr_list);
    } else
        ls_disasm(b);
}

