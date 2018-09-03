#include "utils.h"

// Modified version of http://grapsus.net/blog/post/Hexadecimal-dump-in-C
void hexdump(const uint8_t *data, uint64_t address, size_t size)
{
    printf("\n; Data:\n");

    for (uint64_t i = 0; i < size + ((size % 16) ? (16 - size % 16) : 0); i++) {
        /* print offset */
        if (i % 16 == 0) {
            printf(";0x%06lx: ", i + address);
        }

        /* print hex data */
        if (i < size) {
            printf("%02x ", 0xFF & data[i]);
        }
        else /* end of block, just aligning for ASCII dump */
        {
            printf("   ");
        }

        /* print ASCII dump */
        if (i % 16 == (16 - 1)) {
            printf("| ");
            for (uint64_t j = i - (16 - 1); j <= i; j++) {
                if (j >= size) /* end of block, not really printing */
                {
                    putchar(' ');
                }
                else if (isprint(data[j])) /* printable char */
                {
                    putchar(0xFF & data[j]);
                }
                else /* other char */
                {
                    putchar('.');
                }
            }
            printf(" |\n");
        }
    }
}

void Gap::fill_gap(const Binary& b)
{
    if (this->next_addr <= this->last_addr || this->next_addr == b.entry)
        return;

    size_t s = this->next_addr - this->last_addr;

    if ( s > 1) {
        const uint8_t *data = &b.data.at(this->last_addr);
        hexdump(data, this->last_addr, s);
    }
}
