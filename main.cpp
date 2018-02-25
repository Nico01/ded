// DOS Executable Disassembler

#include "core.h"
#include "mz_exe.h"
#include "options.h"

#include <cstdio>



static int rtd(Options o, size_t size, uint8_t *buffer);
static int lsd(Options o, size_t size, uint8_t *buffer);


int main(int argc, char *argv[])
{
    FILE *fp;

    if (argc < 2)
        usage(std::string {argv[0]});

    Options opts(argc, argv);

    if (opts.filename.empty()) {
       fprintf(stderr, "Invalid file name\n");
      usage(std::string {argv[0]});
    }

    if ((fp = fopen(opts.filename.c_str(), "rb")) == nullptr) {
        perror("Error");
        exit(EXIT_FAILURE);
    }

    fseek(fp, 0, SEEK_END);
    size_t size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (size == 0) {
        fprintf(stderr, "%s: File size %zu\n", opts.filename.c_str(), size);
        fclose(fp);
        exit(EXIT_FAILURE);
    }

    uint8_t *buffer = new uint8_t[size];

    fread(buffer, size, 1, fp);

    if (opts.recursive) {
        int err = rtd(opts, size, buffer);
        if (err)
            goto end;
    } else {
        int err = lsd(opts, size, buffer);
        if (err)
            goto end;
    }

end:
    delete[] buffer;
    fclose(fp);

    return 0;
}

static int rtd(Options o, size_t size, uint8_t *buffer)
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

        if (exe_entry > size)
            exe_entry = 0x1c;

        if (o.hdr)
            mz.disp_header();

        std::list<Address> proc_addr = search_addr(exe_entry, mz.get_exe_size(), buffer, Address_type::Call);
        std::list<Address> labl_addr = search_addr(exe_entry, mz.get_exe_size(), buffer, Address_type::Jump);

        for (auto& i : proc_addr) {
            if (!i.visited && i.value < size)
                rt_disasm(exe_entry, i.value, mz.get_exe_size(), buffer, i, labl_addr);
        }

    } else {
        if (o.entry)
            exe_entry = o.ep;
        else
            exe_entry = 0;

        std::list<Address> proc_addr = search_addr(exe_entry, size, buffer, Address_type::Call);
        std::list<Address> labl_addr = search_addr(exe_entry, size, buffer, Address_type::Jump);

        for (auto& i : proc_addr) {
            if (!i.visited && i.value < size)
                rt_disasm(exe_entry, i.value, size, buffer, i, labl_addr);
        }
    }

    return 0;
}

static int lsd(Options o, size_t size, uint8_t *buffer)
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

        if (exe_entry > size)
            exe_entry = 0x1c;

        if (o.hdr)
            mz.disp_header();

        ls_disasm(exe_entry, mz.get_exe_size(), buffer);

    } else {
        if (o.entry)
            exe_entry = o.ep;
        else
            exe_entry = 0;

        ls_disasm(exe_entry, size, buffer);
    }

    return 0;
}


