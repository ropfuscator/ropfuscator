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

  // s - pointer to a symbol.
  // We bind symbols to chain elements because, if we'd do that to actual
  // microgadgets, it would be fairly easy to predict which gadget is referenced
  // with a symbol, since during the chain execution very few gadgets are
  // executed.
  Symbol *symbol;

  // Constructor (type: GADGET)
  ChainElem(Microgadget *gadget) {
    this->microgadget = gadget;
    this->type = GADGET;
    // this->symbol = ROPChain::BA->getRandomSymbol();
  }

  // Constructor (type: IMMEDIATE)
  ChainElem(int64_t value) : value(value) { type = IMMEDIATE; }

  // getRelativeAddress - returns the gadget address relative to the symbol it
  // is anchored to.
  uint64_t getRelativeAddress() {
    return microgadget->getAddress() - symbol->Address;
  }
};

#endif