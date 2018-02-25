#include <fstream>
#include <cstdio>

#include "mz_exe.h"


Mz::Mz(std::string s)
{
    std::ifstream f;

    f.open(s, std::ifstream::binary);

    if (!f.is_open()) {
        fprintf(stderr, "File error\n");
        exit(EXIT_FAILURE);
    }

    f.read((char *) &Header, sizeof(Header));
    f.close();
}

bool Mz::is_ok() const
{
    if (Header.signature == MZ_Signature)
        return true;

    return false;
}

uint64_t Mz::get_entry() const
{
    return ((Header.header_paragraphs + Header.cs) << 4) + Header.ip;
}

size_t Mz::get_exe_size() const
{
    size_t size = Header.blocks_in_file * 512 - (Header.header_paragraphs * 16);
    if (Header.bytes_in_last_block)
        size -= (512 - Header.bytes_in_last_block);

    return size;
}

void Mz::disp_header() const
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

