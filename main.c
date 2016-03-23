// DOS Executable Disassembler

#include "core.h"

#include <ctype.h>
#include <getopt.h>

void usage(char *filename)
{
    fprintf(stderr, "\nUsage: %s <option> -f <file>\n"
                    "\n\tOptions:\n"
                    "\n\t-h    display this information\n"
                    "\n\t-e    disassemble DOS MZ 16 bits executable\n"
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
    int opt;
    char *filename = NULL;
    bool recursive = false, mz = false;

    if ( argc < 2 ) {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    while ((opt = getopt(argc, argv, "herf:")) != -1) {
        switch (opt) {
        case 'h':
            usage(argv[0]);
            break;
        case 'e':
            mz = true;
            break;
        case 'r':
            recursive = true;
            break;
        case 'f':
            filename = optarg;
            break;
        default:
            usage(argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if (filename == NULL) {
        printf("Invalid file name\n");
        exit(EXIT_FAILURE);
    }

    if ((fp = fopen(filename, "rb")) == NULL) {
        perror("Error");
        exit(EXIT_FAILURE);
    }

    fseek(fp, 0, SEEK_END);
    size_t size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (size == 0) {
        printf("%s: File size %zu\n", filename, size);
        exit(EXIT_FAILURE);
    }

    uint8_t *buffer = malloc(size * sizeof(uint8_t));
    fread(buffer, size, 1, fp);

    if (recursive) {
        if (mz) {
            MZ_Hdr *mz_hdr = read_mz_header(fp);

            if (mz_hdr == NULL) {
                printf("%s: File format not recognized\n", filename);
                exit(EXIT_FAILURE);
            }

            disp_header(mz_hdr);

            list *proc_addr = search_call(get_entry(mz_hdr), get_exe_size(mz_hdr), buffer);
            list *labl_addr = search_jump(get_entry(mz_hdr), get_exe_size(mz_hdr), buffer);

            while (proc_addr) {
                rt_disasm(get_entry(mz_hdr), proc_addr->value, get_exe_size(mz_hdr), buffer, proc_addr,
                       labl_addr);
                proc_addr = proc_addr->next;
            }
        } else {
            list *proc_addr = search_call(0, size, buffer);
            list *labl_addr = search_jump(0, size, buffer);

            while (proc_addr) {
                rt_disasm(0, proc_addr->value, size, buffer, proc_addr, labl_addr);
                proc_addr = proc_addr->next;
            }
        }
    } else {
        if (mz) {
            MZ_Hdr *mz_hdr = read_mz_header(fp);

            if (mz_hdr == NULL) {
                printf("%s: File format not recognized\n", filename);
                exit(EXIT_FAILURE);
            }

            disp_header(mz_hdr);
            ls_disasm(get_entry(mz_hdr), get_exe_size(mz_hdr), buffer);

        } else {
            ls_disasm(0, size, buffer);
        }
    }

    fclose(fp);
    free(buffer);

    return 0;
}
