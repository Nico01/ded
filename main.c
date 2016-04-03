// DOS Executable Disassembler

#include "core.h"
#include <getopt.h>

typedef struct {
    char *filename;
    bool mz;
    bool recursive;
    bool hdr;
} Options;

static uint8_t rtd(FILE *fp, size_t size, uint8_t *buffer, Options opts);
static uint8_t lsd(FILE *fp, size_t size, uint8_t *buffer, Options opts);

static void usage(char *filename)
{
    fprintf(stderr,
            "\nUsage: %s <option> -f <file>\n"
            "\n\tOptions:\n"
            "\n\t-H    display this information\n"
            "\n\t-e    disassemble DOS MZ 16 bits executable\n"
            "\n\t-h    if -e display the DOS MZ header\n"
            "\n\t-r    disassemble file using recursive traversal algorithm (experimental)\n"
            "\n\t-f    input file\n\n"
            "\n\tNote:"
            "\n\tif no flags are given the input file is treated as a headerless 16 bits\n"
            "\texecutable (.COM) and the linear sweep algorithm is used.\n\n",
            filename);

    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
    FILE *fp;
    int c;

    Options opts = (Options){.filename = NULL, .recursive = false, .mz = false };

    if (argc < 2) {
        usage(argv[0]);
    }

    while ((c = getopt(argc, argv, "Hehrf:")) != -1) {
        switch (c) {
        case 'H':
            usage(argv[0]);
            break;
        case 'e':
            opts.mz = true;
            break;
        case 'h':
            opts.hdr = true;
            break;
        case 'r':
            opts.recursive = true;
            break;
        case 'f':
            opts.filename = optarg;
            break;
        default:
            usage(argv[0]);
        }
    }

    if (opts.filename == NULL) {
        fprintf(stderr, "Invalid file name\n");
        usage(argv[0]);
    }

    if ((fp = fopen(opts.filename, "rb")) == NULL) {
        perror("Error");
        exit(EXIT_FAILURE);
    }

    fseek(fp, 0, SEEK_END);
    size_t size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (size == 0) {
        fprintf(stderr, "%s: File size %zu\n", opts.filename, size);
        goto end2;
    }

    uint8_t *buffer = malloc(size * sizeof(uint8_t));
    fread(buffer, size, 1, fp);

    if (opts.recursive) {
        uint8_t err = rtd(fp, size, buffer, opts);
        if (err != 0)
            goto end;
    } else {
        uint8_t err = lsd(fp, size, buffer, opts);
        if (err != 0)
            goto end;
    }

end:
    free(buffer);
end2:
    fclose(fp);

    return 0;
}

static uint8_t rtd(FILE *fp, size_t size, uint8_t *buffer, Options opts)
{
    if (opts.mz) {
        MZ_Hdr *mz_hdr = read_mz_header(fp);

        if (mz_hdr == NULL) {
            fprintf(stderr, "%s: File format not recognized\n", opts.filename);
            return 1;
        }

        uint64_t exe_entry = get_entry(mz_hdr);

        if (exe_entry > size)
            exe_entry = 0x1c;

        if (opts.hdr)
            disp_header(mz_hdr);

        list *proc_addr = search_addr(exe_entry, get_exe_size(mz_hdr), buffer, CALL_ADDR);
        list *labl_addr = search_addr(exe_entry, get_exe_size(mz_hdr), buffer, JUMP_ADDR);

        while (proc_addr) {
            if (!proc_addr->visited && proc_addr->value < size)
                rt_disasm(exe_entry, proc_addr->value, get_exe_size(mz_hdr), buffer, proc_addr,
                          labl_addr);
            proc_addr = proc_addr->next;
        }

        list_free(proc_addr);
        list_free(labl_addr);
    } else {
        list *proc_addr = search_addr(0, size, buffer, CALL_ADDR);
        list *labl_addr = search_addr(0, size, buffer, JUMP_ADDR);

        while (proc_addr) {
            if (!proc_addr->visited && proc_addr->value < size)
                rt_disasm(0, proc_addr->value, size, buffer, proc_addr, labl_addr);
            proc_addr = proc_addr->next;
        }

        list_free(proc_addr);
        list_free(labl_addr);
    }

    return 0;
}

static uint8_t lsd(FILE *fp, size_t size, uint8_t *buffer, Options opts)
{
    if (opts.mz) {
        MZ_Hdr *mz_hdr = read_mz_header(fp);

        if (mz_hdr == NULL) {
            fprintf(stderr, "%s: File format not recognized\n", opts.filename);
            return 1;
        }

        uint64_t exe_entry = get_entry(mz_hdr);

        if (exe_entry > size)
            exe_entry = 0x1c;

        if (opts.hdr)
            disp_header(mz_hdr);

        ls_disasm(exe_entry, get_exe_size(mz_hdr), buffer);

    } else {
        ls_disasm(0, size, buffer);
    }

    return 0;
}
