#include <algorithm>

#include "analyzer.h"


static uint64_t addr_in_range(uint64_t a, size_t min, size_t max)
{
    if ((a > min) && (a < max))
        return a;

    return 0;
}

static uint64_t get_target_addr(const Binary& b, const cs_insn insn)
{
    cs_detail *d = insn.detail;
    uint64_t addr;

    if (insn.id == X86_INS_LCALL) { // TODO Experimental
        if (d->x86.op_count == 2 && d->x86.operands[0].type == X86_OP_IMM && d->x86.operands[1].type == X86_OP_IMM) {
            switch (b.type) {
            case Bin_type::Exe:
                addr = (((b.get_paragraphs() + d->x86.operands[0].imm) << 4)) + d->x86.operands[1].imm;
                //printf("DEBUG: exe lcall Address 0x%lx\n", addr);
                return addr_in_range(addr, b.entry, b.fsize);
            case Bin_type::Com:
                addr = (d->x86.operands[0].imm << 4) + d->x86.operands[1].imm;
                //printf("DEBUG: com lcall Address 0x%lx\n", addr);
                return addr_in_range(addr, b.entry, b.fsize);
            }
        }
    }
    else if (d->x86.op_count == 1 && d->x86.operands[0].type == X86_OP_IMM)
        return addr_in_range(d->x86.operands[0].imm, b.entry, b.fsize);

    return 0;
}

static Analyzer::Address_type get_address_type(csh handle, const cs_insn *insn)
{
    if (cs_insn_group(handle, insn, CS_GRP_CALL))
        return Analyzer::Address_type::Call;

    if (cs_insn_group(handle, insn, CS_GRP_JUMP)) {
        if (insn->id == X86_INS_JMP)
            return Analyzer::Address_type::Jump;
        else
            return Analyzer::Address_type::JmpX;
    }

    return Analyzer::Address_type::Nccf;
}

static void search_addr(const Binary& b, Disasm::Disassembler& d, uint64_t address, std::map<uint64_t, Analyzer::Address>& l)
{
    size_t size = b.size;
    const uint8_t *code = &b.data.at(address);

    cs_insn *insn = cs_malloc(d.handle);

    while (cs_disasm_iter(d.handle, &code, &size, &address, insn)) {
        if (address >= b.fsize)
            break;

        Analyzer::Address_type type = get_address_type(d.handle, insn);

        if (type != Analyzer::Address_type::Nccf) {
            uint64_t taddr = get_target_addr(b, *insn);
            if (taddr != 0) {
                auto a = Analyzer::Address(taddr, false, type);
                a.xref.push_back(Analyzer::XRef(insn->address, insn->id, std::string {cs_insn_name(d.handle, insn->id)}));
                auto [it, ok] = l.try_emplace(taddr, Analyzer::Address(a));
                if (!ok) {
                    it->second.xref.push_back(Analyzer::XRef(insn->address, insn->id, cs_insn_name(d.handle, insn->id)));
                    // Adjust address type if a function is reached via jump
                    if (it->second.type == Analyzer::Address_type::Jump && type == Analyzer::Address_type::Call)
                        it->second.type = Analyzer::Address_type::Call;
                }
            }
        }
    }
    cs_free(insn, 1);
}

std::map<uint64_t, Analyzer::Address> Analyzer::analyze(const Binary& b, Disasm::Disassembler& d)
{
    std::map<uint64_t, Analyzer::Address> l;

    l.emplace(b.entry, Analyzer::Address(b.entry, false, Analyzer::Address_type::Start));

    search_addr(b, d, b.entry, l); // first pass

    for (auto& [addr, nn] : l)
        search_addr(b, d, addr, l); // 2nd pass

    // remove duplicate elements from xref vector
    for (auto& [nn, addr] : l) {
        std::sort(addr.xref.begin(), addr.xref.end(), [](Analyzer::XRef a, Analyzer::XRef b)
        {
            return a.address < b.address;
        });

        auto last = std::unique(addr.xref.begin(), addr.xref.end(), [](Analyzer::XRef a, Analyzer::XRef b)
        {
            return a.address == b.address;
        });

        addr.xref.erase(last, addr.xref.end());
    }

    return l;
}
