//#include "../X86ROPUtils.h"
#include "BinAutopsy.h"
#include "Microgadget.h"
#include "Symbol.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/CodeGen/MachineBasicBlock.h"

#ifndef CHAINELEM_H
#define CHAINELEM_H

// Generic element to be put in the chain.
struct ChainElem {

  enum class Type { GADGET, IMM_VALUE, IMM_GLOBAL, JMP_BLOCK, JMP_FALLTHROUGH };

  // type - it can be a GADGET or an IMMEDIATE value. We need to specify the
  // type because we will use different strategies during the creation of
  // machine instructions to push elements of the chain onto the stack.
  Type type;

  union {
    // global - global symbol address
    const llvm::GlobalValue *global;
    // pointer to a microgadget
    const Microgadget *microgadget;
    // jump target MBB
    llvm::MachineBasicBlock *jmptarget;
  };
  // value - immediate value
  int64_t value;

  // Factory method (type: GADGET)
  static ChainElem fromGadget(const Microgadget *gadget) {
    ChainElem e;
    e.type = Type::GADGET;
    e.microgadget = gadget;
    return e;
  }

  // Factory method (type: IMM_VALUE)
  static ChainElem fromImmediate(int64_t value) {
    ChainElem e;
    e.type = Type::IMM_VALUE;
    e.value = value;
    return e;
  }

  // Factory method (type: IMM_GLOBAL)
  static ChainElem fromGlobal(const llvm::GlobalValue *global, int64_t offset) {
    ChainElem e;
    e.type = Type::IMM_GLOBAL;
    e.global = global;
    e.value = offset;
    return e;
  }

  // Factory method (type: JMP_BLOCK)
  static ChainElem fromJmpTarget(llvm::MachineBasicBlock *jmptarget) {
    ChainElem e;
    e.type = Type::JMP_BLOCK;
    e.jmptarget = jmptarget;
    return e;
  }

  // Factory method (type: JMP_FALLTHROUGH)
  static ChainElem createJmpFallthrough() {
    ChainElem e;
    e.type = Type::JMP_FALLTHROUGH;
    return e;
  }

  friend bool operator==(ChainElem const &A, ChainElem const &B) {
    if (A.type != B.type)
      return false;

    if (A.type == Type::GADGET)
      return (A.microgadget == B.microgadget);
    else
      return (A.value == B.value);
  }

  void debugPrint() const {
    switch (type) {
    case Type::GADGET:
      llvm::dbgs() << "GADGET    : " << microgadget->asmInstr << "\n";
      break;
    case Type::IMM_VALUE:
      llvm::dbgs() << "IMM_VALUE : " << value << "\n";
      break;
    case Type::IMM_GLOBAL:
      llvm::dbgs() << "IMM_GLOBAL: " << *global << " + " << value << "\n";
      break;
    case Type::JMP_BLOCK:
      llvm::dbgs() << "JMP_BLOCK : " << jmptarget->getNumber() << "\n";
      break;
    case Type::JMP_FALLTHROUGH:
      llvm::dbgs() << "JMP_FALLTHROUGH\n";
      break;
    }
  }
};

#endif