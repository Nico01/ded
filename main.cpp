// DOS Executable Disassembler

#include "core.h"
#include "binary.h"
#include "options.h"
#include "analyzer.h"
#include "disassembler.h"
#include "utils.h"


static void disasm(const Options& o, const Binary& b);


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

    fprintf(stderr, ";File %s\t Size %zu (0x%zx) bytes\n\n", opts.filename.c_str(), bin.fsize, bin.fsize);

    //fprintf(stderr, ";DEBUG: exe size %zu (0x%zx) bytes\n\n", bin.size, bin.size);

    disasm(opts, bin);

    return 0;
}

static void print_addr_list(const std::map<uint64_t, Analyzer::Address>& l, uint64_t last_vaddr)
{
    fprintf(stderr, "\n\n; Statistics: Address list size %zu\n\n", l.size());

    int a = 0, b = 0, c = 0;

    auto f = [](const Analyzer::Address& l)
    {
        fprintf(stderr, ";\t \t ~ xref: {\n;\t\t\t");
        for (auto& x: l.xref)
            fprintf(stderr, "'0x%lx, %s' ", x.address, x.istr.c_str());
        fprintf(stderr, "\n;\t\t}\n\n");
    };

    for (auto& [addr, val] : l) {
        if (addr > last_vaddr)
            continue;

        switch (val.type) {
        case Analyzer::Address_type::Start:
            fprintf(stderr, ";\t 0x%06lx: Start function (entry point )\n", addr);
            break;
        case Analyzer::Address_type::Call:
            fprintf(stderr, ";\t 0x%06lx: function                  \t(visited: %s)\n",
                addr, val.visited ? "true" : "false");
            f(val);
            a += (val.visited ? 1 : 0);
            break;
        case Analyzer::Address_type::Jump:
            fprintf(stderr, ";\t 0x%06lx: branch address            \t(visited: %s)\n",
                addr, val.visited ? "true" : "false");
            f(val);
            b += (val.visited ? 1 : 0);
            break;
        case Analyzer::Address_type::JmpX:
            fprintf(stderr, ";\t 0x%06lx: conditional branch address\t(visited: %s)\n",
                addr, val.visited ? "true" : "false");
            f(val);
            c += (val.visited ? 1 : 0);
            break;
        default:
            break;
        }
    }
    fprintf(stderr, "\n; Reached: %d function - %d branch address - %d conditional branch address\n\n", a + 1, b, c);
}

static void disasm(const Options& o, const Binary& b)
{
    Disasm::Disassembler d;
    Gap g;

    if (o.recursive) {
        std::map<uint64_t, Analyzer::Address> addr_list = Analyzer::analyze(b, d);

        for (auto& [addr, val] : addr_list)
            if ((val.type != Analyzer::Address_type::JmpX) && !val.visited) {
                if ((addr != 0) && (g.last_addr != 0))
                    if ((addr - g.last_addr) > 0x500) //random value
                        continue;

                g.last_addr = rt_disasm(b, d, val, addr_list);
            }

        //fprintf(stderr, "\n;DEBUG - last address visited: 0x%06lx\n", g.last_addr);

        g.next_addr = b.fsize;

        g.fill_gap(b);

        if (o.verbose)
            print_addr_list(addr_list, g.last_addr);

    } else
        ls_disasm(b, d);
}

