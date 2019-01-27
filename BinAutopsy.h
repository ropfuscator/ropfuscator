// ==============================================================================
//   BINARY AUTOPSY
//   part of the ROPfuscator project
// ==============================================================================
// This module extracts useful features from a given binary. We call it
// "autopsy" because we have to analyse an already compiled program, dissecting
// it in many sections and extracting as many features as possible.
//
// More in detail, the module is able to extract:
//      - data about ELF sections
//      - symbols from the .dynsym section
//      - microgadgets from executable section
//
// Microgadgets are a subset of what are commonly known as ROP Gadgets, with the
// only difference that we grab only the ones composed by a single instruction
// before the ret, e.g.:
//        mov eax, ebx
//        ret
//
// This module offers also a set of methods to look for a specific microgadget
// among the ones discovered and a lately described "exchange path" analyser.
//

#ifndef BINAUTOPSY_H
#define BINAUTOPSY_H

#include <bfd.h>
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <string>
#include <vector>

namespace std {

struct Symbol {
  char *Label;
  char *Version;
  char *SymVerDirective;
  uint64_t Address;

  Symbol(string label, string version, uint64_t address);

  char *getSymVerDirective();
};

struct Section {
  string Label;
  uint64_t Address, Length;

  Section(string label, uint64_t address, uint64_t length);
};

struct Microgadget {
  cs_insn *Instr;

  // debug
  string asmInstr;

  Microgadget(cs_insn *instr, string asmInstr);
  uint64_t getAddress() const;
  x86_insn getID() const;
  cs_x86_op getOp(int i) const;
  uint8_t getNumOp() const;
};

class BinaryAutopsy {
public:
  static uint8_t ret[];
  vector<Symbol> Symbols;
  vector<Section> Sections;
  vector<Microgadget> Microgadgets;
  char *BinaryPath;
  bfd *BfdHandle;

  BinaryAutopsy(string path);

  void getSections();
  void getDynamicSymbols();
  Symbol *getRandomSymbol();
  void extractGadgets();
  Microgadget *gadgetLookup(string asmInstr);
};

} // namespace std

#endif