#include "llvm/MC/MCInst.h"
#include <string>

#ifndef MICROGADGET_H
#define MICROGADGET_H

enum class GadgetType {
  UNDEFINED,
  INIT,
  XCHG,
  COPY,
  LOAD,
  LOAD_1,
  STORE,
  JMP,
  ADD,
  ADD_1,
  SUB,
  SUB_1,
  AND,
  AND_1,
  OR,
  OR_1,
  XOR,
  XOR_1,
  CMOVE,
  CMOVB,
};

// Microgadget - represents a single x86 instruction that precedes a RET.
struct Microgadget {
  // Type - gives basic semantic information about the instruction
  GadgetType Type;

  unsigned short reg1;
  unsigned short reg2;

  // Instr - LLVM MCInst data structure of disassembled gadget
  const std::vector<llvm::MCInst> Instr;

  // gadget address(es)
  std::vector<uint64_t> addresses;

  // debug
  std::string asmInstr;

  // Constructor
  Microgadget(const llvm::MCInst *instr, int count, uint64_t address,
              std::string asmInstr)
      : Instr(instr, instr + count), asmInstr(asmInstr) {
    addresses.push_back(address);
  }
};

#endif