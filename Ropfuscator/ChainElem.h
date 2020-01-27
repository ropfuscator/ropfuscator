#include "Microgadget.h"
#include "Symbol.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/CodeGen/MachineBasicBlock.h"

#ifndef CHAINELEM_H
#define CHAINELEM_H

// Generic element to be put in the chain.
struct ChainElem {

  enum class Type { GADGET, IMM_VALUE, IMM_GLOBAL, JMP_BLOCK, JMP_FALLTHROUGH, ESP_PUSH, ESP_OFFSET };

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
    // id for ESP_PUSH and ESP_OFFSET
    int esp_id;
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

  // Factory method (type: ESP_PUSH)
  static ChainElem createStackPointerPush() {
    static int esp_id = 0;
    ChainElem e;
    e.type = Type::ESP_PUSH;
    e.esp_id = ++esp_id;
    return e;
  }

  // Factory method (type: ESP_OFFSET)
  static ChainElem createStackPointerOffset(int64_t value, int esp_id) {
    ChainElem e;
    e.type = Type::ESP_OFFSET;
    e.value = value;
    e.esp_id = esp_id;
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

  template <typename OstreamT>
  void debugPrint(OstreamT &os) const {
    switch (type) {
    case Type::GADGET:
      os << "GADGET    : " << microgadget->asmInstr << "\n";
      break;
    case Type::IMM_VALUE:
      os << "IMM_VALUE : " << value << "\n";
      break;
    case Type::IMM_GLOBAL:
      os << "IMM_GLOBAL: " << *global << " + " << value << "\n";
      break;
    case Type::JMP_BLOCK:
      os << "JMP_BLOCK : " << jmptarget->getNumber() << "\n";
      break;
    case Type::JMP_FALLTHROUGH:
      os << "JMP_FALLTHROUGH\n";
      break;
    case Type::ESP_PUSH:
      os << "ESP_PUSH  : id=" << esp_id << "\n";
      break;
    case Type::ESP_OFFSET:
      os << "ESP_OFFSET: " << value << ", id=" << esp_id << "\n";
      break;
    }
  }
};

#endif