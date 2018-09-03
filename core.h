#ifndef DED_CORE_H
#define DED_CORE_H

#include <cstdint>

#include "binary.h"
#include "analyzer.h"
#include "disassembler.h"

enum class Reg_name {
    AL, AH, AX, BL, BH, BX, CL, CH, CX, DL, DH, DX, SP, BP, SI, DI, ES, CS, SS, DS
};

struct Registers {
    union { struct { uint8_t al; uint8_t ah; }; uint16_t ax; };
    union { struct { uint8_t bl; uint8_t bh; }; uint16_t bx; };
    union { struct { uint8_t cl; uint8_t ch; }; uint16_t cx; };
    union { struct { uint8_t dl; uint8_t dh; }; uint16_t dx; };

//    uint16_t sp, bp, si, di;
//    uint16_t es, cs, ss, ds;

    void set_reg(const cs_insn insn);
};


uint64_t rt_disasm(const Binary& b, Disasm::Disassembler& d, Analyzer::Address& a, std::map<uint64_t, Analyzer::Address>& addr_list);
void ls_disasm(const Binary& b, Disasm::Disassembler& d);

#endif // DED_CORE_H
