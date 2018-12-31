#include "core.h"
#include "utils.h"
#include "insnfmt.h"


void Registers::set_reg(const cs_insn insn)
{
    if (insn.detail->x86.op_count == 2) {
        if (insn.detail->x86.operands[0].type == X86_OP_REG && insn.detail->x86.operands[1].type == X86_OP_IMM) {
            uint16_t value = insn.detail->x86.operands[1].imm;

            switch (insn.detail->x86.operands[0].reg) {
            case X86_REG_AL:
                this->al = value;
                break;
            case X86_REG_AH:
                this->ah = value;
                break;
            case X86_REG_AX:
                this->ax = value;
                break;
            case X86_REG_BL:
                this->bl = value;
                break;
            case X86_REG_BH:
                this->bh = value;
                break;
            case X86_REG_BX:
                this->bx = value;
                break;
            case X86_REG_CL:
                this->cl = value;
                break;
            case X86_REG_CH:
                this->ch = value;
                break;
            case X86_REG_CX:
                this->cx = value;
                break;
            case X86_REG_DL:
                this->dl = value;
                break;
            case X86_REG_DH:
                this->dh = value;
                break;
            case X86_REG_DX:
                this->dx = value;
                break;
            default:
                break;

            }
        }
    }
}


enum class CA_Mode { Uncond, Cond };

static bool check_address(std::map<uint64_t, Analyzer::Address>& l, const uint64_t addr, CA_Mode m)
{
    auto it = l.find(addr);

    if (it != l.end()) {
        switch (m) {
        case CA_Mode::Uncond:
            if (it->second.type == Analyzer::Address_type::Call || it->second.type == Analyzer::Address_type::Jump)
                if (it->second.value == addr)
                    return true;
            return false;
        case CA_Mode::Cond:
            if (it->second.type == Analyzer::Address_type::JmpX && !it->second.visited) {
                it->second.visited = true;
                print_label(it->second);
            }
        }
    }

    return false;
}

uint64_t rt_disasm(const Binary& b, Disasm::Disassembler& d, Analyzer::Address& a, std::map<uint64_t, Analyzer::Address>& addr_list)
{
    a.visited = true;

    static Gap g;
    static Registers reg;

    uint64_t addr = a.value;
    size_t size = b.size;
    const uint8_t *code = &b.data.at(addr);

    cs_insn *insn = cs_malloc(d.handle);

    g.next_addr = a.value;

    g.fill_gap(b);
    //fprintf(stderr, "DEBUG: g.next_addr 0x%06lx, g.last_addr 0x%06lx, gap size %zu\n", g.next_addr, g.last_addr, g.next_addr - g.last_addr);

    print_label(a);

    while (cs_disasm_iter(d.handle, &code, &size, &addr, insn)) {
        reg.set_reg(*insn);

        g.last_addr = addr;

        if (print_insn_r(*insn, reg.ah))
            break;

        if (check_address(addr_list, addr, CA_Mode::Uncond) || cs_insn_group(d.handle, insn, CS_GRP_RET) ||
            cs_insn_group(d.handle, insn, CS_GRP_IRET) || addr >= b.fsize)
            break;

        check_address(addr_list, addr, CA_Mode::Cond);
    }
    cs_free(insn, 1);

    return g.last_addr;
}

void ls_disasm(const Binary& b, Disasm::Disassembler& d)
{
    printf(".start:\n");


    uint64_t addr = b.entry;
    size_t size = b.size;
    const uint8_t *code = &b.data.at(addr);

    cs_insn *insn = cs_malloc(d.handle);

    while (cs_disasm_iter(d.handle, &code, &size, &addr, insn)) {
        print_insn(*insn);
    }

    cs_free(insn, 1);
}

