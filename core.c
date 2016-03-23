#include "core.h"

#include <capstone/capstone.h>
#include <inttypes.h>

static list *list_init(uint64_t data)
{
    list *l = malloc(sizeof(list));

    if (l != NULL) {
        l->next = NULL;
        l->value = data;
    }

    return l;
}

static void list_add(list *node, uint64_t data)
{
    list *l = node;

    while (l->next != NULL)
        l = l->next;

    l->next = list_init(data);
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


uint64_t get_entry(MZ_Hdr *mz_hdr)
{
    return (mz_hdr->header_paragraphs * 16);
}

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
    char opstr[16];
    char *opptr = opstr;

    for (int i = 0; i < insn.size; i++) {
        opptr += snprintf(opptr, len, "%02x ", insn.bytes[i]);
    }

    *(opptr + 1) = '\0';
    char *opcodes = strdup(opstr);

    return opcodes;
}

list *search_call(uint64_t addr, size_t size, uint8_t *buffer)
{
    csh handle;
    cs_insn *insn;
    cs_detail *detail;
    const uint8_t *code = NULL;

    list *proc_addr = list_init(addr);

    if (cs_open(CS_ARCH_X86, CS_MODE_16, &handle) != CS_ERR_OK) {
        printf("ERROR: Failed to initialize engine!\n");
        exit(EXIT_FAILURE);
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);

    for (uint64_t i = addr; i < size; i++) {
        code = &buffer[i];
        insn = cs_malloc(handle);

        while (cs_disasm_iter(handle, &code, &size, &addr, insn)) {
            if (insn->id == X86_INS_CALL) {
                detail = insn->detail;
                if (detail->x86.operands[0].type == X86_OP_IMM)
                    list_add(proc_addr, detail->x86.operands[0].imm);
            }
        }
        cs_free(insn, 1);
    }

    cs_close(&handle);

    list_remove_duplicates(proc_addr);

    return proc_addr;
}

list *search_jump(uint64_t addr, size_t size, uint8_t *buffer)
{
    csh handle;
    cs_insn *insn;
    cs_detail *detail;
    const uint8_t *code = NULL;

    list *labl_addr = list_init(0);

    if (cs_open(CS_ARCH_X86, CS_MODE_16, &handle) != CS_ERR_OK) {
        printf("ERROR: Failed to initialize engine!\n");
        exit(EXIT_FAILURE);
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);

    for (uint64_t i = addr; i < size; i++) {
        code = &buffer[i];
        insn = cs_malloc(handle);

        while (cs_disasm_iter(handle, &code, &size, &addr, insn)) {
            if (cs_insn_group(handle, insn, CS_GRP_JUMP)) {
                detail = insn->detail;
                if (detail->x86.operands[0].type == X86_OP_IMM)
                    list_add(labl_addr, detail->x86.operands[0].imm);
            }
        }
        cs_free(insn, 1);
    }

    cs_close(&handle);

    list_remove_duplicates(labl_addr);

    return labl_addr;
}

void rt_disasm(uint64_t entry, uint64_t addr, size_t size, uint8_t *buffer, list *call, list *jump)
{
    csh handle = 0;
    cs_insn *insn;
    const uint8_t *code = NULL;

    if (cs_open(CS_ARCH_X86, CS_MODE_16, &handle) != CS_ERR_OK) {
        printf("ERROR: Failed to initialize engine!\n");
        exit(EXIT_FAILURE);
    }

    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);

    while (jump) {
        if (addr == entry) {
            printf(".start\n");

            for (uint64_t i = addr; i < size; i++) {
                code = &buffer[i];
                insn = cs_malloc(handle);

                while (cs_disasm_iter(handle, &code, &size, &addr, insn)) {
                    char *opcodes = get_opcodes(*insn);
                    printf("0x%06" PRIx64 ":\t %-20s\t%s  %s\n", insn->address, opcodes, insn->mnemonic, insn->op_str);
                    free(opcodes);

                    if (list_cmp_addr(jump, addr))
                        printf("\nlabel_0x%lx\n", addr);

                    if (list_cmp_addr(call, addr))
                        goto end;
                }
                cs_free(insn, 1);
            }
        } else {
            printf("\n\nproc_0x%lx\n", addr);

            for (uint64_t i = addr; i < size; i++) {
                code = &buffer[i];
                insn = cs_malloc(handle);

                while (cs_disasm_iter(handle, &code, &size, &addr, insn)) {
                    char *opcodes = get_opcodes(*insn);
                    printf("0x%06" PRIx64 ":\t %-20s\t%s  %s\n", insn->address, opcodes, insn->mnemonic, insn->op_str);
                    free(opcodes);

                    if (list_cmp_addr(jump, addr))
                        printf("\nlabel_0x%lx\n", addr);

                    if (insn->id == X86_INS_RET)
                        goto end;
                }
                cs_free(insn, 1);
            }

            jump = jump->next;
        }
    }

end:
    cs_close(&handle);
}

void ls_disasm(uint64_t addr, size_t size, uint8_t *buffer)
{
    csh handle = 0;
    cs_insn *insn;
    const uint8_t *code = NULL;

    if (cs_open(CS_ARCH_X86, CS_MODE_16, &handle) != CS_ERR_OK) {
        printf("ERROR: Failed to initialize engine!\n");
        exit(EXIT_FAILURE);
    }

    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);

    printf(".start\n");

    for (uint64_t i = addr; i < size; i++) {
        code = &buffer[i];
        insn = cs_malloc(handle);

        while (cs_disasm_iter(handle, &code, &size, &addr, insn)) {
            char *opcodes = get_opcodes(*insn);
            printf("0x%06" PRIx64 ":\t %-20s\t%s  %s\n", insn->address, opcodes, insn->mnemonic, insn->op_str);
            free(opcodes);
        }
        cs_free(insn, 1);
    }
    cs_close(&handle);
}
