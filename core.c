#include "core.h"

#include <capstone/capstone.h>
#include <inttypes.h>

char *int21h[] = {
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

static list *list_init(uint64_t data, bool is_proc)
{
    list *l = malloc(sizeof(list));

    if (l != NULL) {
        l->next = NULL;
        l->value = data;
        l->visited = false;
        if (is_proc)
            l->is_proc = true;
    }

    return l;
}

static void list_add(list *node, uint64_t data, bool is_proc)
{
    list *l = node;

    while (l->next != NULL)
        l = l->next;

    l->next = list_init(data, is_proc);
}

static void list_remove_duplicates(list *node)
{
    list *c1, *c2, *dup;
    c1 = node;

    while (c1 != NULL && c1->next != NULL) {
        c2 = c1;

        while (c2->next != NULL) {
            if (c1->value == c2->next->value) {
                dup = c2->next;
                c2->next = c2->next->next;
                free(dup);
            } else
                c2 = c2->next;
        }
        c1 = c1->next;
    }
}

static bool list_cmp_addr(list *node, uint64_t data)
{
    while (node) {
        if (node->value == data)
            return true;

        node = node->next;
    }
    return false;
}

static list *get_node(list *node, uint64_t data)
{
    while (node) {
        if (node->value == data)
            return node;

        node = node->next;
    }
    return NULL;
}

void list_free(list *node)
{
    list *tmp;

    while (node) {
        tmp = node;
        node = node->next;
        free(tmp);
    }
}

MZ_Hdr *read_mz_header(FILE *fp)
{
    MZ_Hdr *mz_hdr = malloc(sizeof(MZ_Hdr));

    if (fseek(fp, 0, SEEK_SET) != 0) {
        free(mz_hdr);
        return NULL;
    }

    if (fread(mz_hdr, sizeof(MZ_Hdr), 1, fp) != 1) {
        free(mz_hdr);
        return NULL;
    }

    if (mz_hdr->signature != 0x5a4D && mz_hdr->signature != 0x4D5a) {
        free(mz_hdr);
        return NULL;
    }

    return mz_hdr;
}

void disp_header(MZ_Hdr *mz_hdr)
{
    printf("DOS Header:\n");
    printf("Magic number                    0x%x\n", mz_hdr->signature);
    printf("Bytes in last pages             0x%x\n", mz_hdr->bytes_in_last_block);
    printf("Pages in file                   0x%x\n", mz_hdr->blocks_in_file);
    printf("Relocations                     0x%x\n", mz_hdr->num_relocs);
    printf("Size of header                  0x%x\n", mz_hdr->header_paragraphs);
    printf("Minimum extra paragraphs        0x%x\n", mz_hdr->min_extra_paragraphs);
    printf("Maximum extra paragraphs        0x%x\n", mz_hdr->max_extra_paragraphs);
    printf("Initial ss:sp                   0x%x:0x%x\n", mz_hdr->ss, mz_hdr->sp);
    printf("Checksum                        0x%x\n", mz_hdr->checksum);
    printf("Initial cs:ip                   0x%x:0x%x\n", mz_hdr->cs, mz_hdr->ip);
    printf("Address of relocation table     0x%x\n", mz_hdr->reloc_table_offset);
    printf("Overlay number                  0x%x\n\n", mz_hdr->overlay_number);
}

uint64_t get_entry(MZ_Hdr *mz_hdr) { return (mz_hdr->header_paragraphs * 16); }

size_t get_exe_size(MZ_Hdr *mz_hdr)
{
    size_t size = mz_hdr->blocks_in_file * 512 - (mz_hdr->header_paragraphs * 16);
    if (mz_hdr->bytes_in_last_block)
        size -= (512 - mz_hdr->bytes_in_last_block);

    return size;
}

char *get_opcodes(cs_insn insn)
{
    uint8_t len = (2 * insn.size) + 1;
    char opstr[32];
    char *opptr = opstr;

    for (int i = 0; i < insn.size; i++) {
        opptr += snprintf(opptr, len, "%02x ", insn.bytes[i]);
    }

    *(opptr + 1) = '\0';
    char *opcodes = strdup(opstr);

    return opcodes;
}

uint8_t get_reg_ah(cs_insn insn)
{
    cs_detail *detail = insn.detail;
    uint8_t reg_ah = 0xff;

    if (detail->x86.op_count == 2) {
        if (detail->x86.operands[0].type == X86_OP_REG &&
            detail->x86.operands[1].type == X86_OP_IMM) {
            if (detail->x86.operands[0].reg == X86_REG_AH)
                reg_ah = detail->x86.operands[1].imm;

            if (detail->x86.operands[0].reg == X86_REG_AX)
                reg_ah = detail->x86.operands[1].imm >> 8;

            return reg_ah;
        }
    }
    return reg_ah;
}

bool is_int21h(cs_insn insn)
{
    cs_detail *detail = insn.detail;

    if (detail->x86.operands[0].imm == 0x21) {
        return true;
    }

    return false;
}

bool is_int20h(cs_insn insn)
{
    cs_detail *detail = insn.detail;

    if (detail->x86.operands[0].imm == 0x20) {
        return true;
    }

    return false;
}

list *search_addr(uint64_t addr, size_t size, uint8_t *buffer, addr_type mode)
{
    csh handle;
    cs_insn *insn;
    cs_detail *detail;

    list *l = NULL;

    if (mode == CALL_ADDR)
        l = list_init(addr, true);
    else
        l = list_init(0, false);

    if (cs_open(CS_ARCH_X86, CS_MODE_16, &handle) != CS_ERR_OK) {
        fprintf(stderr, "ERROR: Failed to initialize engine!\n");
        exit(EXIT_FAILURE);
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);

    for (size_t i = 0; i < size; i++) {
        const uint8_t *code = &buffer[i + addr];
        insn = cs_malloc(handle);

        if (mode == CALL_ADDR) {
            while (cs_disasm_iter(handle, &code, &size, &addr, insn)) {
                if (cs_insn_group(handle, insn, CS_GRP_CALL)) {
                    detail = insn->detail;
                    if (detail->x86.op_count == 1 && detail->x86.operands[0].type == X86_OP_IMM)
                        if ((uint64_t)detail->x86.operands[0].imm < size)
                            list_add(l, detail->x86.operands[0].imm, true);
                }
            }
        } else {
            while (cs_disasm_iter(handle, &code, &size, &addr, insn)) {
                if (cs_insn_group(handle, insn, CS_GRP_JUMP)) {
                    detail = insn->detail;
                    if (detail->x86.op_count == 1 && detail->x86.operands[0].type == X86_OP_IMM)
                        if ((uint64_t)detail->x86.operands[0].imm < size)
                            list_add(l, detail->x86.operands[0].imm, false);
                }
            }
        }

        cs_free(insn, 1);
    }

    cs_close(&handle);

    list_remove_duplicates(l);

    return l;
}

static void check_jump(list *node, uint64_t data)
{
    if (list_cmp_addr(node, data)) {
        list *l = get_node(node, data);

        if (!l->visited) {
            l->visited = true;

            if (!l->is_proc)
                printf("\nL_0x%lx:\n", data);
        }
    }
}

void rt_disasm(uint64_t entry, uint64_t addr, size_t size, uint8_t *buffer, list *call, list *jump)
{
    csh handle = 0;
    cs_insn *insn;

    uint8_t r_ah = 0xff;
    call->visited = true;

    if (cs_open(CS_ARCH_X86, CS_MODE_16, &handle) != CS_ERR_OK) {
        fprintf(stderr, "ERROR: Failed to initialize engine!\n");
        exit(EXIT_FAILURE);
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);

    if (addr > (size + entry))
        goto end;

    if (addr == entry) {
        printf(".start:\n");

        for (size_t i = 0; i < size; i++) {
            const uint8_t *code = &buffer[i + addr];
            insn = cs_malloc(handle);

            while (cs_disasm_iter(handle, &code, &size, &addr, insn)) {
                char *opcodes = get_opcodes(*insn);

                if (get_reg_ah(*insn) != 0xff)
                    r_ah = get_reg_ah(*insn);

                if (insn->id == X86_INS_INT && is_int21h(*insn) && r_ah != 0xff) {
                    printf("0x%06" PRIx64 ":\t %-20s\t%s  %s ; %s\n", insn->address, opcodes,
                           insn->mnemonic, insn->op_str, int21h[r_ah]);
                    free(opcodes);

                    if (r_ah == 0x4c)
                        printf("========\n");

                    check_jump(jump, addr);

                    if (list_cmp_addr(call, addr) || cs_insn_group(handle, insn, CS_GRP_RET) ||
                        cs_insn_group(handle, insn, CS_GRP_IRET))
                        goto end;
                } else {
                    printf("0x%06" PRIx64 ":\t %-20s\t%s  %s\n", insn->address, opcodes,
                           insn->mnemonic, insn->op_str);
                    free(opcodes);

                    if (is_int20h(*insn))
                        printf("========\n");

                    check_jump(jump, addr);

                    if (list_cmp_addr(call, addr) || cs_insn_group(handle, insn, CS_GRP_RET) ||
                        cs_insn_group(handle, insn, CS_GRP_IRET))
                        goto end;
                }
            }
            cs_free(insn, 1);
        }
    } else {
        printf("\n\nproc_0x%lx:\n", addr);

        for (size_t i = 0; i < size; i++) {
            const uint8_t *code = &buffer[i + addr];
            insn = cs_malloc(handle);

            while (cs_disasm_iter(handle, &code, &size, &addr, insn)) {
                char *opcodes = get_opcodes(*insn);
                if (get_reg_ah(*insn) != 0xff)
                    r_ah = get_reg_ah(*insn);

                if (insn->id == X86_INS_INT && is_int21h(*insn) && r_ah != 0xff) {
                    printf("0x%06" PRIx64 ":\t %-20s\t%s  %s ; %s\n", insn->address, opcodes,
                           insn->mnemonic, insn->op_str, int21h[r_ah]);
                    free(opcodes);

                    check_jump(jump, addr);

                    if (cs_insn_group(handle, insn, CS_GRP_RET) ||
                        cs_insn_group(handle, insn, CS_GRP_IRET))
                        goto end;
                } else {
                    printf("0x%06" PRIx64 ":\t %-20s\t%s  %s\n", insn->address, opcodes,
                           insn->mnemonic, insn->op_str);
                    free(opcodes);

                    check_jump(jump, addr);

                    if (cs_insn_group(handle, insn, CS_GRP_RET) ||
                        cs_insn_group(handle, insn, CS_GRP_IRET))
                        goto end;
                }
            }
            cs_free(insn, 1);
        }
    }

end:
    cs_close(&handle);
}

void ls_disasm(uint64_t addr, size_t size, uint8_t *buffer)
{
    csh handle = 0;
    cs_insn *insn;

    if (cs_open(CS_ARCH_X86, CS_MODE_16, &handle) != CS_ERR_OK) {
        fprintf(stderr, "ERROR: Failed to initialize engine!\n");
        exit(EXIT_FAILURE);
    }

    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);

    printf(".start:\n");

    for (size_t i = 0; i < size; i++) {
        const uint8_t *code = &buffer[i + addr];
        insn = cs_malloc(handle);

        while (cs_disasm_iter(handle, &code, &size, &addr, insn)) {
            char *opcodes = get_opcodes(*insn);
            printf("0x%06" PRIx64 ":\t %-20s\t%s  %s\n", insn->address, opcodes, insn->mnemonic,
                   insn->op_str);
            free(opcodes);
        }
        cs_free(insn, 1);
    }
    cs_close(&handle);
}
