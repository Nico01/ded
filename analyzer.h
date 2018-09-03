/* analyzer.h
 *
 * Copyright 2018 Nico01 <nicola.onorata@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef DED_ANALYZER_H
#define DED_ANALYZER_H

#include <map>
#include <vector>

#include "binary.h"
#include "disassembler.h"

namespace Analyzer {

enum class Address_type { Nccf, Start, Call, Jump, JmpX, Undef };

struct XRef {
    uint64_t address;
    uint32_t insn_id;
    std::string istr;

    XRef(uint64_t addr, uint32_t id, std::string s)
		: address(addr), insn_id(id), istr(s){}
};

struct Address {
    uint64_t value;
    bool visited;
    Address_type type;
    std::vector<XRef> xref;

	Address(const uint64_t a, bool b, Address_type t)
		: value(a), visited(b), type(t){}
};

std::map<uint64_t, Analyzer::Address> analyze(const Binary& b, Disasm::Disassembler& d);


struct BB { // Basic Block
    uint64_t s_addr; //Entry
    uint64_t e_addr; //Exit
    std::vector<Disasm::Instruction> insn;
};

} // Analyzer

#endif //DED_ANALYZER_H
