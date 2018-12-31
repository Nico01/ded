#include <iomanip>
#include <sstream>
#include <cinttypes>
#include <fmt/printf.h>

#include "insnfmt.h"

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


static std::string get_opcodes_str(const cs_insn insn)
{
    std::stringstream ss;

    for (auto i = 0; i < insn.size; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<uint16_t>(insn.bytes[i]) << " ";

    return ss.str();
}

void print_insn(const cs_insn insn)
{
    std::string opcodes = get_opcodes_str(insn);

    printf("0x%06" PRIx64 ":\t %-20s\t%s  %s\n", insn.address, opcodes.c_str(), insn.mnemonic, insn.op_str);
}

bool print_insn_r(const cs_insn insn, const uint8_t r_ah)
{
    auto f = [&i = insn](const std::string s)
    {
        printf("0x%06" PRIx64 ":\t %-20s\t%s  %s %s", i.address, get_opcodes_str(i).c_str(), i.mnemonic, i.op_str, s.c_str());
    };

    if (insn.id == X86_INS_INT) {
        switch (insn.detail->x86.operands[0].imm) {
        case 0x21:
            switch (r_ah) {
            case 0xff:
                f("\n");
                return false;
            case 0x4c:
                f(fmt::sprintf("; %s\n========\n", int21h[r_ah]));
                return true;
            default:
                f(fmt::sprintf("; %s\n", int21h[r_ah]));
                return false;
            }
        case 0x20:
            f("; exit()\n========\n");
            return true;
        default:
            f("\n");
            return false;
        }
    }

    f("\n");
    return false;
}

void print_label(const Analyzer::Address &a)
{
    auto f = [&z = a]()
    {
        printf("xref: [ ");
        for (auto& x: z.xref)
            printf("'0x%lx, %s' ", x.address, x.istr.c_str());
        printf("]\n");
    };

    switch (a.type) {
    case Analyzer::Address_type::Start:
        printf("; .start:\n");
        break;
    case Analyzer::Address_type::Call:
        printf("\n\n; sub_0x%06lx ~ ", a.value);
        f();
        break;
    case Analyzer::Address_type::Jump:
    case Analyzer::Address_type::JmpX:
        printf("\n; loc_0x%06lx ~ ", a.value);
        f();
        break;
    default:
        break;
    }
}
