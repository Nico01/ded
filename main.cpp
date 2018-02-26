// DOS Executable Disassembler

#include "core.h"
#include "mz_exe.h"
#include "binary.h"
#include "options.h"

#include <cstdio>



static int rtd(Options o, Binary b);
static int lsd(Options o, Binary b);


int main(int argc, char *argv[])
{
    if (argc < 2)
        usage(std::string {argv[0]});

    Options opts(argc, argv);

    if (opts.filename.empty()) {
        fprintf(stderr, "Invalid file name\n");
        usage(std::string {argv[0]});
    }

    Binary bin(opts.filename);

    if (opts.recursive) {
        int err = rtd(opts, bin);
        if (err)
            return EXIT_FAILURE;
    } else {
        int err = lsd(opts, bin);
        if (err)
            return EXIT_FAILURE;
    }

    return 0;
}

static int rtd(Options o, Binary b)
{
    uint64_t exe_entry;

    if (o.mz) {
        Mz mz(o.filename);

        if (!mz.is_ok()) {
            fprintf(stderr, "%s: File format not recognized\n", o.filename.c_str());
            return 1;
        }

        if (o.entry)
            exe_entry = o.ep;
        else
            exe_entry = mz.get_entry();

        if (exe_entry > b.size)
            exe_entry = 0x1c;

        if (o.hdr)
            mz.disp_header();

        b.entry = exe_entry;

        std::list<Address> proc_addr = search_addr(b, Address_type::Call);
        std::list<Address> labl_addr = search_addr(b, Address_type::Jump);

        for (auto& i : proc_addr) {
            if (!i.visited && i.value < b.size)
                rt_disasm(b, i.value, i, proc_addr, labl_addr);
        }

    } else {
        if (o.entry)
            exe_entry = o.ep;
        else
            exe_entry = 0;

        b.entry = exe_entry;

        std::list<Address> proc_addr = search_addr(b, Address_type::Call);
        std::list<Address> labl_addr = search_addr(b, Address_type::Jump);

        for (auto& i : proc_addr) {
            if (!i.visited && i.value < b.size)
                rt_disasm(b, i.value, i, proc_addr, labl_addr);
        }
    }

    return 0;
}

static int lsd(Options o, Binary b)
{
    uint64_t exe_entry;

    if (o.mz) {
        Mz mz(o.filename);

        if (!mz.is_ok()) {
            fprintf(stderr, "%s: File format not recognized\n", o.filename.c_str());
            return 1;
        }

        if (o.entry)
            exe_entry = o.ep;
        else
            exe_entry = mz.get_entry();

        if (exe_entry > b.size)
            exe_entry = 0x1c;

        if (o.hdr)
            mz.disp_header();

        b.entry = exe_entry;

        ls_disasm(b);

    } else {
        if (o.entry)
            exe_entry = o.ep;
        else
            exe_entry = 0;

        b.entry = exe_entry;

        ls_disasm(b);
    }

    return 0;
}


