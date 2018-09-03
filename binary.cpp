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

        if (Header.num_relocs)
            relocate(f);

        if (o.hdr)
            disp_header();
    }

    type = (o.mz ? Bin_type::Exe : Bin_type::Com);

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

void Binary::relocate(std::ifstream& f)
{
    size_t rsize = Header.num_relocs * sizeof(Relocation);

    Relocation *reloc = new Relocation[rsize];

    f.seekg (Header.reloc_table_offset, f.beg);
    f.read(reinterpret_cast<char*>(reloc), rsize);

    for (int i = 0; i < Header.num_relocs; ++i)
        Reloc.push_back(reloc[i]);

    for (auto& x : Reloc)
        RelocationTable.push_back((x.segment << 4) + x.offset);

    delete[] reloc;
}

void Binary::disp_header() const
{
    fprintf(stderr, "DOS Header:\n");
    fprintf(stderr, "Magic number                    0x%x\n", Header.signature);
    fprintf(stderr, "Bytes in last pages             0x%x\n", Header.bytes_in_last_block);
    fprintf(stderr, "Pages in file                   0x%x\n", Header.blocks_in_file);
    fprintf(stderr, "Relocations                     0x%x\n", Header.num_relocs);
    fprintf(stderr, "Size of header                  0x%x\n", Header.header_paragraphs);
    fprintf(stderr, "Minimum extra paragraphs        0x%x\n", Header.min_extra_paragraphs);
    fprintf(stderr, "Maximum extra paragraphs        0x%x\n", Header.max_extra_paragraphs);
    fprintf(stderr, "Initial ss:sp                   0x%x:0x%x\n", Header.ss, Header.sp);
    fprintf(stderr, "Checksum                        0x%x\n", Header.checksum);
    fprintf(stderr, "Initial cs:ip                   0x%x:0x%x\n", Header.cs, Header.ip);
    fprintf(stderr, "Address of relocation table     0x%x\n", Header.reloc_table_offset);
    fprintf(stderr, "Overlay number                  0x%x\n\n", Header.overlay_number);

    if (Header.num_relocs) {
        fprintf(stderr, "Relocations table:\n");
        fprintf(stderr, "\toffset:segment\n");

        for (auto& x : Reloc)
            fprintf(stderr, "\t0x%04x:0x%04x\n", x.offset, x.segment);

        fprintf(stderr, "Relocated address:\n");
        for (auto& x : RelocationTable)
            fprintf(stderr, "\t0x%06x\n", x);

        fprintf(stderr, "_________________________________________\n\n");
    }
}
