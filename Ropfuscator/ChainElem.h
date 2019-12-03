//#include "../X86ROPUtils.h"
#include "BinAutopsy.h"
#include "Microgadget.h"
#include "Symbol.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/GlobalValue.h"

#ifndef CHAINELEM_H
#define CHAINELEM_H

// Generic element to be put in the chain.
struct ChainElem {

  enum class Type { GADGET, IMM_VALUE, IMM_GLOBAL };

  // type - it can be a GADGET or an IMMEDIATE value. We need to specify the
  // type because we will use different strategies during the creation of
  // machine instructions to push elements of the chain onto the stack.
  Type type;

  union {
    // global - global symbol address
    const llvm::GlobalValue *global;
    // pointer to a microgadget
    const Microgadget *microgadget;
  };
  // value - immediate value
  int64_t value;

  // Constructor (type: GADGET)
  explicit ChainElem(Microgadget *gadget) {
    this->type = Type::GADGET;
    this->microgadget = gadget;
  }

  // Constructor (type: IMM_VALUE)
  explicit ChainElem(int64_t value) {
    this->type = Type::IMM_VALUE;
    this->value = value;
  }

  // Constructor (type: IMM_GLOBAL)
  ChainElem(const llvm::GlobalValue *global, int64_t offset) {
    this->type = Type::IMM_GLOBAL;
    this->global = global;
    this->value = offset;
  }

  friend bool operator==(ChainElem const &A, ChainElem const &B) {
    if (A.type != B.type)
      return false;

    if (A.type == Type::GADGET)
      return (A.microgadget == B.microgadget);
    else
      return (A.value == B.value);
  }
};

#endif