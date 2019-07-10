//#include "../X86ROPUtils.h"
#include "BinAutopsy.h"
#include "Microgadget.h"
#include "Symbol.h"

#ifndef CHAINELEM_H
#define CHAINELEM_H

enum type_t { GADGET, IMMEDIATE };

// Generic element to be put in the chain.
struct ChainElem {
  // type - it can be a GADGET or an IMMEDIATE value. We need to specify the
  // type because we will use different strategies during the creation of
  // machine instructions to push elements of the chain onto the stack.
  type_t type;

  union {
    // value - immediate value
    int64_t value;

    // pointer to a microgadget
    const Microgadget *microgadget;
  };

  // Constructor (type: GADGET)
  ChainElem(Microgadget *gadget) {
    this->type = GADGET;
    this->microgadget = gadget;
  }

  // Constructor (type: IMMEDIATE)
  ChainElem(int64_t value) {
    this->type = IMMEDIATE;
    this->value = value;
  }
};

#endif