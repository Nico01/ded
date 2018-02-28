#include <fstream>
#include <cstdio>

#include "binary.h"

Binary::Binary(const Options &o)
{
    std::ifstream f(o.filename, std::ifstream::binary);

    if (!f.is_open()) {
        fprintf(stderr, "Error %s: No such file or directory\n", o.filename.c_str());
        exit(EXIT_FAILURE);
    }

    f.seekg (0, f.end);
    fsize = f.tellg();
    f.seekg (0, f.beg);

    if (fsize == 0) {
        fprintf(stderr, "Error %s: empty file\n", o.filename.c_str());
        f.close();
        exit(EXIT_FAILURE);
    }

    uint8_t *buffer = new uint8_t [fsize];

    f.read(reinterpret_cast<char*>(buffer), fsize);

    data.assign(buffer, buffer + fsize);

    delete[] buffer;

    if (o.mz) {
        f.seekg (0, f.beg);
        f.read(reinterpret_cast<char*>(&Header), sizeof(Header));

        if (Header.signature != MZ_Signature) {
            fprintf(stderr, "%s: File format not recognized\n", o.filename.c_str());
            f.close();
            exit(EXIT_FAILURE);
        }

        if (o.hdr)
            disp_header();
    }

    set_entry(o);
    set_exe_size(o);

    f.close();
}

void Binary::set_entry(const Options &o)
{
    if (o.entry) {
        if (o.ep >= fsize) {
            fprintf(stderr, "Entry point must be less than binary size\n");
            exit(EXIT_FAILURE);
        } else {
            entry = o.ep;
        }
    } else {
        if (o.mz) {
            entry = ((Header.header_paragraphs + Header.cs) << 4) + Header.ip;
                if (entry > fsize)
                    entry = 0x1c;
        } else {
            entry = 0;
        }
    }


}

void Binary::set_exe_size(const Options &o)
{
    if (o.mz) {
        size = Header.blocks_in_file * 512 - (Header.header_paragraphs * 16);
        if (Header.bytes_in_last_block)
            size -= (512 - Header.bytes_in_last_block);
    } else {
        size = fsize;
    }
}

void Binary::disp_header() const
{
    printf("DOS Header:\n");
    printf("Magic number                    0x%x\n", Header.signature);
    printf("Bytes in last pages             0x%x\n", Header.bytes_in_last_block);
    printf("Pages in file                   0x%x\n", Header.blocks_in_file);
    printf("Relocations                     0x%x\n", Header.num_relocs);
    printf("Size of header                  0x%x\n", Header.header_paragraphs);
    printf("Minimum extra paragraphs        0x%x\n", Header.min_extra_paragraphs);
    printf("Maximum extra paragraphs        0x%x\n", Header.max_extra_paragraphs);
    printf("Initial ss:sp                   0x%x:0x%x\n", Header.ss, Header.sp);
    printf("Checksum                        0x%x\n", Header.checksum);
    printf("Initial cs:ip                   0x%x:0x%x\n", Header.cs, Header.ip);
    printf("Address of relocation table     0x%x\n", Header.reloc_table_offset);
    printf("Overlay number                  0x%x\n\n", Header.overlay_number);
}
