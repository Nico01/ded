/**/
#include <tuple>
#include <cstring>
#include <cstdlib>
#include <iomanip>
#include <sstream>

#include "disassembler.h"


Disasm::Disassembler::Disassembler()
{
    cs_err e = cs_open(CS_ARCH_X86, CS_MODE_16, &this->handle);

    if (e != CS_ERR_OK) {
        fprintf(stderr, "ERROR: Failed to initialize engine!\n");
        fprintf(stderr, "cs_open: %s\n", cs_strerror(e));
        exit(EXIT_FAILURE);
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
}

Disasm::Disassembler::~Disassembler()
{
    cs_close(&this->handle);
}

static std::string get_opcodes_str(const cs_insn insn)
{
    std::stringstream ss;

    for (auto i = 0; i < insn.size; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<uint16_t>(insn.bytes[i]) << " ";

    return ss.str();
}

Disasm::Instruction::Instruction(const cs_insn insn)
{
    this->id = insn.id;
    this->address = insn.address;
    this->size = insn.size;
    this->opcodes = get_opcodes_str(insn);
    this->mnemonic = insn.mnemonic;
    this->op_str = insn.op_str;

    memcpy(&this->groups, &insn.detail->groups, 8);

    this->groups_count = insn.detail->groups_count;
    this->op_count = insn.detail->x86.op_count;

    memcpy(&this->operands, &insn.detail->x86.operands, sizeof(cs_x86_op) * 8);
}

void Disasm::Instruction::print()
{
    printf("0x%06" PRIx64 ":\t %-20s\t%s  %s\n",
        this->address, this->opcodes.c_str(), this->mnemonic.c_str(), this->op_str.c_str());
}

// Return true if the instruction change the control flow
bool Disasm::Instruction::change_cf()
{
    for (int i = 0; i < this->groups_count; i++) {
        if (this->groups[i] == X86_GRP_JUMP || this->groups[i] ==X86_GRP_CALL)
            return true;
    }

    return false;
}

// Return the address of a direct branch instruction zero
uint64_t Disasm::Instruction::get_target_addr()
{
    if (this->op_count == 1 && this->operands[0].type == X86_OP_IMM)
        return this->operands[0].imm;

    return 0;
}

// Return the content of AH/AX if available or false
std::tuple<uint8_t, bool> Disasm::Instruction::get_reg_ah()
{
    if (this->op_count == 2) {
        if (this->operands[0].type == X86_OP_REG && this->operands[1].type == X86_OP_IMM) {
            if (this->operands[0].reg == X86_REG_AH)
                return { this->operands[1].imm, true };

            if (this->operands[0].reg == X86_REG_AX)
                return { this->operands[1].imm >> 8, true };
        }
    }
    return { 0xff, false };
}

