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

    printf("File %s\t Size %zu (0x%zx) bytes\n\n", opts.filename.c_str(), bin.fsize, bin.fsize);

    printf("DEBUG: exe size %zu (0x%zx) bytes\n\n", bin.size, bin.size);

    disasm(opts, bin);

    return 0;
}

static void print_addr_list(std::list<Address> l)
{
    printf("\n\nAddress list size: %zu\n", l.size());

    for (auto& i : l) {
        switch (i.type) {
        case Address_type::Main:
            printf("0x%06lx: Main function\n", i.value);
            break;
        case Address_type::Call:
            printf("0x%06lx: function                  \t(visited: %s)\n", i.value, i.visited ? "true" : "false");
            break;
        case Address_type::Jump:
            printf("0x%06lx: branch address            \t(visited: %s)\n", i.value, i.visited ? "true" : "false");
            break;
        case Address_type::JmpX:
            printf("0x%06lx: conditional branch address\t(visited: %s)\n", i.value, i.visited ? "true" : "false");
            break;
        }
    }
}

static void disasm(Options o, Binary b)
{
    if (o.recursive) {
        std::list<Address> addr_list = search_addr(b);

        for (auto& i : addr_list)
            if ((i.type != Address_type::JmpX) && !i.visited)
                rt_disasm(b, i, addr_list);

        if (o.verbose)
            print_addr_list(addr_list);

    } else
        ls_disasm(b);
}

