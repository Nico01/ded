#ifndef _DED_DISASM_H
#define _DED_DISASM_H

#include <cstdint>
#include <string>
#include <capstone/capstone.h>

namespace Disasm {

struct Instruction {
    uint32_t id;
    uint64_t address;
    size_t size;
    std::string opcodes;
    std::string mnemonic;
    std::string op_str;
    uint8_t groups[8];
    uint8_t groups_count;
    uint8_t op_count;
	cs_x86_op operands[8];

    Instruction(cs_insn insn);
    void print();
    bool print_r(const uint8_t reg_ah);
    bool change_cf();
    uint64_t get_target_addr();
    std::tuple<uint8_t, bool> get_reg_ah();
};


struct Disassembler {
    csh handle;
    cs_insn *insn;

    Disassembler();
    ~Disassembler();
};

} // Disasm

#endif // _DED_DISASM_H
