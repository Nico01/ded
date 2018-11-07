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

void print_addr_list(const std::map<uint64_t, Analyzer::Address>& l, uint64_t last_vaddr)
{
    fprintf(stderr, "\n\n; Statistics: Address list size %zu\n\n", l.size());

    int a = 0, b = 0, c = 0;

    auto f = [](const Analyzer::Address& l)
    {
        fprintf(stderr, ";\t \t ~ xref: {\n;\t\t\t");
        for (auto& x: l.xref)
            fprintf(stderr, "'0x%lx, %s' ", x.address, x.istr.c_str());
        fprintf(stderr, "\n;\t\t}\n\n");
    };

    for (auto& [addr, val] : l) {
        if (addr > last_vaddr)
            continue;

        switch (val.type) {
        case Analyzer::Address_type::Start:
            fprintf(stderr, ";\t 0x%06lx: Start function (entry point )\n", addr);
            break;
        case Analyzer::Address_type::Call:
            fprintf(stderr, ";\t 0x%06lx: function                  \t(visited: %s)\n",
                addr, val.visited ? "true" : "false");
            f(val);
            a += (val.visited ? 1 : 0);
            break;
        case Analyzer::Address_type::Jump:
            fprintf(stderr, ";\t 0x%06lx: branch address            \t(visited: %s)\n",
                addr, val.visited ? "true" : "false");
            f(val);
            b += (val.visited ? 1 : 0);
            break;
        case Analyzer::Address_type::JmpX:
            fprintf(stderr, ";\t 0x%06lx: conditional branch address\t(visited: %s)\n",
                addr, val.visited ? "true" : "false");
            f(val);
            c += (val.visited ? 1 : 0);
            break;
        default:
            break;
        }
    }
    fprintf(stderr, "\n; Reached: %d function - %d branch address - %d conditional branch address\n\n", a + 1, b, c);
}
