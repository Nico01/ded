#ifndef DED_BINARY_H
#define DED_BINARY_H

#include <string>
#include <vector>
#include <cstdint>

#include "options.h"

struct Relocation {
    uint16_t offset;
    uint16_t segment;
};

enum class Bin_type {
    Com,
    Exe,
};

class Binary {
public:
    Bin_type type;
    std::vector<uint8_t> data;
    size_t fsize;
    size_t size;
    uint64_t entry;

    Binary(const Options &o);

    int get_paragraphs() const {
        return Header.header_paragraphs;
    }

private:
    const uint16_t MZ_Signature = 0x5A4D;

    struct {
        uint16_t signature;
        uint16_t bytes_in_last_block;
        uint16_t blocks_in_file;
        uint16_t num_relocs;
        uint16_t header_paragraphs;
        uint16_t min_extra_paragraphs;
        uint16_t max_extra_paragraphs;
        uint16_t ss;
        uint16_t sp;
        uint16_t checksum;
        uint16_t ip;
        uint16_t cs;
        uint16_t reloc_table_offset;
        uint16_t overlay_number;
    } Header;

    std::vector<Relocation> Reloc;
    std::vector<uint32_t> RelocationTable;

    void set_entry(const Options &o);
    void set_exe_size(const Options &o);
    void relocate(std::ifstream& f);
    void disp_header() const;
};


#endif // DED_BINARY_H
