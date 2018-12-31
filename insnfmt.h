#ifndef DED_INSN_FMT_H
#define DED_INSN_FMT_H

#include <capstone/capstone.h>
#include "analyzer.h"

void print_insn(const cs_insn insn);
bool print_insn_r(const cs_insn insn, const uint8_t r_ah);
void print_label(const Analyzer::Address &a);

#endif // DED_INSN_FMT_H
