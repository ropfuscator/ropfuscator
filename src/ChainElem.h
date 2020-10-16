#include "Debug.h"
#include "Microgadget.h"
#include "Symbol.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/IR/GlobalValue.h"

#ifndef CHAINELEM_H
#define CHAINELEM_H

namespace ropf {

// Generic element to be put in the chain.
struct ChainElem {
  enum class Type {
    GADGET,
    IMM_VALUE,
    IMM_GLOBAL,
    JMP_BLOCK,
    JMP_FALLTHROUGH,
    ESP_PUSH,
    ESP_OFFSET
  };

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

    switch (A.type) {
    case Type::GADGET:
      return A.microgadget == B.microgadget;
    case Type::IMM_VALUE:
      return A.value == B.value;
    case Type::IMM_GLOBAL:
      return A.global == B.global && A.value == B.value;
    case Type::JMP_BLOCK:
      return A.jmptarget == B.jmptarget;
    case Type::JMP_FALLTHROUGH:
      return true;
    case Type::ESP_PUSH:
      return A.esp_id == B.esp_id;
    case Type::ESP_OFFSET:
      return A.esp_id == B.esp_id && A.value == B.value;
    }
    return false;
  }

  friend std::ostream &operator<<(std::ostream &os, const ChainElem &e) {
    e.debugPrint(os);
    return os;
  }

  void debugPrint(std::ostream &os) const {
    switch (type) {
    case Type::GADGET:
      fmt::print(os, "GADGET\t:{}\n", microgadget->asmInstr);
      break;
    case Type::IMM_VALUE:
      fmt::print(os, "IMM_VALUE\t:{}\n", value);
      break;
    case Type::IMM_GLOBAL:
      fmt::print(os, "IMM_GLOBAL:\t:{} + {}\n", *global, value);
      break;
    case Type::JMP_BLOCK:
      fmt::print(os, "JMP_BLOCK\t:{}\n", jmptarget->getNumber());
      break;
    case Type::JMP_FALLTHROUGH:
      fmt::print(os, "JMP_FALLTHROUGH\n");
      break;
    case Type::ESP_PUSH:
      fmt::print(os, "ESP_PUSH\t:id={}\n", esp_id);
      break;
    case Type::ESP_OFFSET:
      fmt::print(os, "ESP_OFFSET\t:{}, id={}\n", value, esp_id);
      break;
    }
  }
};

} // namespace ropf

#endif
