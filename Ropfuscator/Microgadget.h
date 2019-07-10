#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <string>

#ifndef MICROGADGET_H
#define MICROGADGET_H

enum GadgetClass_t {
  REG_INIT,
  REG_RESET,
  REG_LOAD,
  REG_STORE,
  REG_XCHG,
  UNDEFINED
};

// Microgadget - represents a single x86 instruction that precedes a RET.
struct Microgadget {
  // Instr - pointer to a capstone-engine data structure that contains details
  // on the overall semantics of the instruction, along with address, opcode,
  // etc.
  const cs_insn *Instr;

  // Class - gives basic semantic information about the instruction
  GadgetClass_t Class;

  // debug
  std::string asmInstr;

  // Constructor
  Microgadget(cs_insn *instr, std::string asmInstr)
      : Instr(instr), asmInstr(asmInstr){};

  // getAddress - returns the offset relative to the analysed binary file.
  uint64_t getAddress() const { return Instr[0].address; }

  // getID - returns the instruction opcode.
  x86_insn getID() const {
    // Returns the ID (opcode)
    return static_cast<x86_insn>(Instr[0].id);
  }

  // getOp - returns the i-th instruction operand.
  cs_x86_op getOp(int i) const {
    // Returns the i-th operand
    return Instr[0].detail->x86.operands[i];
  }

  // getNumOp - returns the total number of operands of the instruction
  uint8_t getNumOp() const {
    // Returns the number of operands
    return Instr[0].detail->x86.op_count;
  }
};

#endif