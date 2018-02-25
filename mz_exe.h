#ifndef _DED_MZ_H_
#define _DED_MZ_H_

#include <string>
#include <cstdint>


class Mz {
public:
    Mz(std::string s);
    bool is_ok() const;
    uint64_t get_entry() const;
    size_t get_exe_size() const;
    void disp_header() const;

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

/*
    struct {
        uint16_t offset;
        uint16_t segment;
    } Reloc;
*/
};

#endif //_DED_MZ_H_
