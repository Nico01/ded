#include "core.h"

#include <list>
#include <cstring>
#include <cstdlib>
#include <iomanip>
#include <sstream>
#include <capstone/capstone.h>
#include <cinttypes>

const char *int21h[] = {
    "Terminate process",                            // 0x00
    "Character input with echo",                    // 0x01
    "Character output",                             // 0x02
    "Auxiliary input",                              // 0x03
    "Auxiliary output",                             // 0x04
    "Printer output",                               // 0x05
    "Direct console i/o",                           // 0x06
    "Unfiltered char i w/o echo",                   // 0x07
    "Character input without echo",                 // 0x08
    "Display string",                               // 0x09
    "Buffered keyboard input",                      // 0x0a
    "Check input status",                           // 0x0b
    "Flush input buffer and then input",            // 0x0c
    "Disk reset",                                   // 0x0d
    "Select disk",                                  // 0x0e
    "Open file",                                    // 0x0f
    "Close file",                                   // 0x10
    "Find first file",                              // 0x11
    "Find next file",                               // 0x12
    "Delete file",                                  // 0x13
    "Sequential read",                              // 0x14
    "Sequential write",                             // 0x15
    "Create file",                                  // 0x16
    "Rename file",                                  // 0x17
    "Reserved",                                     // 0x18
    "Get current disk",                             // 0x19
    "Set DTA address",                              // 0x1a
    "Get default drive data",                       // 0x1b
    "Get drive data",                               // 0x1c
    "Reserved",                                     // 0x1d
    "Reserved",                                     // 0x1e
    "Get disk parameter block for default drive",   // 0x1f
    "Reserved",                                     // 0x20
    "Random read",                                  // 0x21
    "Random write",                                 // 0x22
    "Get file size",                                // 0x23
    "Set relative record number",                   // 0x24
    "Set interrupt vector",                         // 0x25
    "Create new PSP",                               // 0x26
    "Random block read",                            // 0x27
    "Random block write",                           // 0x28
    "Parse filename",                               // 0x29
    "Get date",                                     // 0x2a
    "Set date",                                     // 0x2b
    "Get time",                                     // 0x2c
    "Set time",                                     // 0x2d
    "Set verify flag",                              // 0x2e
    "Get DTA address",                              // 0x2f
    "Get MSDOS version number",                     // 0x30
    "Terminate and stay resident",                  // 0x31
    "Get disk parameter block for specified drive", // 0x32
    "Get or set break flag",                        // 0x33
    "Get InDOS flag pointer",                       // 0x34
    "Get interrupt vector",                         // 0x35
    "Get drive allocation info",                    // 0x36
    "Get or set switch character",                  // 0x37
    "Get or set country info",                      // 0x38
    "Create directory",                             // 0x39
    "Delete directory",                             // 0x3a
    "Set current directory",                        // 0x3b
    "Create file",                                  // 0x3c
    "Open file",                                    // 0x3d
    "Close file",                                   // 0x3e
    "Read file or device",                          // 0x3f
    "Write file or device",                         // 0x40
    "Delete file",                                  // 0x41
    "Set file pointer",                             // 0x42
    "Get or set file attributes",                   // 0x43
    "IOCTL (i/o control)",                          // 0x44
    "Duplicate handle",                             // 0x45
    "Redirect handle",                              // 0x46
    "Get current directory",                        // 0x47
    "Alloate memory block",                         // 0x48
    "Release memory block",                         // 0x49
    "Resize memory block",                          // 0x4a
    "Execute program (exec)",                       // 0x4b
    "Terminate process with return code",           // 0x4c
    "Get return code",                              // 0x4d
    "Find first file",                              // 0x4e
    "Find next file",                               // 0x4f
    "Set current PSP",                              // 0x50
    "Get current PSP",                              // 0x51
    "Get DOS internal pointers (SYSVARS)",          // 0x52
    "Create disk parameter block",                  // 0x53
    "Get verify flag",                              // 0x54
    "Create program PSP",                           // 0x55
    "Rename file",                                  // 0x56
    "Get or set file date & time",                  // 0x57
    "Get or set allocation strategy",               // 0x58
    "Get extended error information",               // 0x59
    "Create temporary file",                        // 0x5a
    "Create new file",                              // 0x5b
    "Lock or unlock file region",                   // 0x5c
    "File sharing functions",                       // 0x5d
    "Get machine name",                             // 0x5e
    "Device redirection",                           // 0x5f
    "Qualify filename",                             // 0x60
    "Reserved",                                     // 0x61
    "Get PSP address",                              // 0x62
    "Get DBCS lead byte table",                     // 0x63
    "Set wait for external event flag",             // 0x64
    "Get extended country information",             // 0x65
    "Get or set code page",                         // 0x66
    "Set handle count",                             // 0x67
    "Commit file",                                  // 0x68
    "Get or set media id",                          // 0x69
    "Commit file",                                  // 0x6a
    "Reserved",                                     // 0x6b
    "Extended open file"                            // 0x6c
};

/*
char *int10h[] = {
    [0x00] = "Set video mode",                                        // 0x00
    [0x01] = "Set cursor type",                                       // 0x01
    [0x02] = "Set cursor position",                                   // 0x02
    [0x03] = "Read cursor position",                                  // 0x03
    [0x04] = "Read light pen",                                        // 0x04
    [0x05] = "Select active display page",                            // 0x05
    [0x06] = "Scroll active page up",                                 // 0x06
    [0x07] = "Scroll active page down",                               // 0x07
    [0x08] = "Read character and attribute at cursor",                // 0x08
    [0x09] = "Write character and attribute at cursor",               // 0x09
    [0x0a] = "Write character at current cursor",                     // 0x0a
    [0x0b] = "Set color palette",                                     // 0x0b
    [0x0c] = "Write graphics pixel at coordinate",                    // 0x0c
    [0x0d] = "Read graphics pixel at coordinate",                     // 0x0d
    [0x0e] = "Write text in teletype mode",                           // 0x0e
    [0x0f] = "Get current video state",                               // 0x0f
    [0x10] = "Set/get palette registers (EGA/VGA)",                   // 0x10
    [0x11] = "Character generator routine (EGA/VGA)",                 // 0x11
    [0x12] = "Video subsystem configuration (EGA/VGA)",               // 0x12
    [0x13] = "Write string",                                          // 0x13
    [0x14] = "Load LCD char font (convertible)",                      // 0x14
    [0x15] = "Return physical display parms (convertible)",           // 0x15
    [0x1a] = "Video Display Combination (VGA)",                       // 0x1a
    [0x1b] = "Video BIOS Functionality/State Information (MCGA/VGA)", // 0x1b
    [0x1c] = "Save/Restore Video State  (VGA only)",                  // 0x1c
    [0xfe] = "Get DESQView/TopView Virtual Screen Regen Buffer",      // 0xfe
    [0xff] = "Update DESQView/TopView Virtual Screen Regen Buffer"    // 0xff
};
*/


static std::string get_opcodes(const cs_insn insn)
{
    std::stringstream ss;

    for (auto i = 0; i < insn.size; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<uint16_t>(insn.bytes[i]) << " ";

    return ss.str();
}

static uint8_t get_reg_ah(const cs_insn insn)
{
    cs_detail *detail = insn.detail;
    uint8_t reg_ah = 0xff;

    if (detail->x86.op_count == 2) {
        if (detail->x86.operands[0].type == X86_OP_REG && detail->x86.operands[1].type == X86_OP_IMM) {
            if (detail->x86.operands[0].reg == X86_REG_AH)
                reg_ah = detail->x86.operands[1].imm;

            if (detail->x86.operands[0].reg == X86_REG_AX)
                reg_ah = detail->x86.operands[1].imm >> 8;

            return reg_ah;
        }
    }
    return reg_ah;
}

static void print_insn(const cs_insn insn)
{
    std::string opcodes = get_opcodes(insn);

    printf("0x%06" PRIx64 ":\t %-20s\t%s  %s\n", insn.address, opcodes.c_str(), insn.mnemonic, insn.op_str);
}

static void print_comment(const cs_insn insn, const uint8_t r_ah)
{
    cs_detail *detail = insn.detail;
    std::string opcodes = get_opcodes(insn);

    switch (detail->x86.operands[0].imm) {
    case 0x21:
        if (r_ah != 0xff) {
            printf("0x%06" PRIx64 ":\t %-20s\t%s  %s ; %s\n", insn.address, opcodes.c_str(),
                   insn.mnemonic, insn.op_str, int21h[r_ah]);

            if (r_ah == 0x4c)
                printf("========\n");
        }
        break;
    case 0x20:
        printf("0x%06" PRIx64 ":\t %-20s\t%s  %s ; exit()\n", insn.address, opcodes.c_str(),
               insn.mnemonic, insn.op_str);
        printf("========\n");
        break;
    default:
        printf("0x%06" PRIx64 ":\t %-20s\t%s  %s\n", insn.address, opcodes.c_str(), insn.mnemonic,
               insn.op_str);
    }
}

std::list<Address> search_addr(const Binary &b)
{
    csh handle;
    cs_detail *detail;

    if (cs_open(CS_ARCH_X86, CS_MODE_16, &handle) != CS_ERR_OK) {
        fprintf(stderr, "ERROR: Failed to initialize engine!\n");
        exit(EXIT_FAILURE);
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);


    std::list<Address> l;

    l.push_back(Address(b.entry, false, Address_type::Call));

    uint64_t addr = b.entry;
    size_t size = b.size;
    const uint8_t *code = &b.data[addr];

    cs_insn *insn = cs_malloc(handle);

    while (cs_disasm_iter(handle, &code, &size, &addr, insn)) {
        if (cs_insn_group(handle, insn, CS_GRP_CALL)) {
            detail = insn->detail;
            if (detail->x86.op_count == 1 && detail->x86.operands[0].type == X86_OP_IMM)
                if ((uint64_t)detail->x86.operands[0].imm < size)
                    l.push_back(Address(detail->x86.operands[0].imm, false, Address_type::Call));
        }
        if (cs_insn_group(handle, insn, CS_GRP_JUMP)) {
            detail = insn->detail;
            if (detail->x86.op_count == 1 && detail->x86.operands[0].type == X86_OP_IMM)
                if ((uint64_t)detail->x86.operands[0].imm < size)
                    l.push_back(Address(detail->x86.operands[0].imm, false, Address_type::Jump));
        }
    }

    cs_free(insn, 1);
    cs_close(&handle);

    l.sort(cmp_addr);
    l.unique(equ_addr);

    return l;
}

static bool check_call(const std::list<Address> &l, const uint64_t data)
{
    for (const auto& i : l) {
        if (i.type == Address_type::Call)
            if (i.value == data)
                return true;
    }
    return false;
}

static void check_jump(std::list<Address> &l, const uint64_t data)
{
    for (auto& i : l) {
        if (i.type == Address_type::Jump)
            if (i.value == data)
                if (!i.visited) {
                    i.visited = true;
                    printf("\nL_0x%lx:\n", data);
                }
    }
}

void rt_disasm(const Binary &b, uint64_t addr, Address &a, std::list<Address> &addr_list)
{
    csh handle = 0;

    uint8_t r_ah = 0xff;
    a.visited = true;

    if (cs_open(CS_ARCH_X86, CS_MODE_16, &handle) != CS_ERR_OK) {
        fprintf(stderr, "ERROR: Failed to initialize engine!\n");
        exit(EXIT_FAILURE);
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);

    size_t size = b.size;

    if (addr > (size + b.entry)) {
        cs_close(&handle);
        return;
    }

    const uint8_t *code = &b.data[addr];

    cs_insn *insn = cs_malloc(handle);

    if (addr == b.entry) {
        printf(".start:\n");

        while (cs_disasm_iter(handle, &code, &size, &addr, insn)) {
            if (get_reg_ah(*insn) != 0xff)
                r_ah = get_reg_ah(*insn);

            if (insn->id == X86_INS_INT) {
                print_comment(*insn, r_ah);
                if (check_call(addr_list, addr) || cs_insn_group(handle, insn, CS_GRP_RET) ||
                    cs_insn_group(handle, insn, CS_GRP_IRET))
                    break;
            } else {
                print_insn(*insn);
                check_jump(addr_list, addr);

                if (check_call(addr_list, addr) || cs_insn_group(handle, insn, CS_GRP_RET) ||
                    cs_insn_group(handle, insn, CS_GRP_IRET))
                    break;
            }
        }
    } else {
        printf("\n\nproc_0x%lx:\n", addr);

        while (cs_disasm_iter(handle, &code, &size, &addr, insn)) {
            if (get_reg_ah(*insn) != 0xff)
                r_ah = get_reg_ah(*insn);

            if (insn->id == X86_INS_INT) {
                print_comment(*insn, r_ah);
                if (check_call(addr_list, addr) || cs_insn_group(handle, insn, CS_GRP_RET) ||
                    cs_insn_group(handle, insn, CS_GRP_IRET))
                    break;
            } else {
                print_insn(*insn);
                check_jump(addr_list, addr);

                if (check_call(addr_list, addr) || cs_insn_group(handle, insn, CS_GRP_RET) ||
                    cs_insn_group(handle, insn, CS_GRP_IRET))
                    break;
            }
        }

    }

    cs_free(insn, 1);
    cs_close(&handle);
}

void ls_disasm(const Binary &b)
{
    csh handle = 0;

    if (cs_open(CS_ARCH_X86, CS_MODE_16, &handle) != CS_ERR_OK) {
        fprintf(stderr, "ERROR: Failed to initialize engine!\n");
        exit(EXIT_FAILURE);
    }

    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);

    printf(".start:\n");


    uint64_t addr = b.entry;
    size_t size = b.size;
    const uint8_t *code = &b.data[b.entry];

    cs_insn *insn = cs_malloc(handle);

    while (cs_disasm_iter(handle, &code, &size, &addr, insn))
        print_insn(*insn);

    cs_free(insn, 1);
    cs_close(&handle);
}

