// DOS Executable Disassembler

#include "core.h"
#include "binary.h"
#include "options.h"
#include "analyzer.h"
#include "disassembler.h"
#include "utils.h"


static cs_opt_value str_to_opt(std::string s)
{
    if (s == "intel")
        return CS_OPT_SYNTAX_INTEL;
    else if (s == "att")
        return CS_OPT_SYNTAX_ATT;
    else if (s == "masm")
        return CS_OPT_SYNTAX_MASM;
    else
        return CS_OPT_SYNTAX_INTEL;
}

static void disasm(const Options& o, const Binary& b)
{
    Disasm::Disassembler d;

    if (o.syntax)
        d.set_syntax(str_to_opt(o.syntaxt));

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
