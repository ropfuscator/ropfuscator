#include "OpaqueConstruct.h"
#include "../X86TargetMachine.h"
#include "CapstoneLLVMAdpt.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"

using namespace llvm;

OpaqueConstruct::~OpaqueConstruct() {}

#define DECL_REG_LOCATION(R)                                                   \
  const OpaqueStorage OpaqueStorage::R(OpaqueStorage::Type::REG, X86_REG_##R, 0)
#define DECL_STACK_LOCATION(I)                                                 \
  const OpaqueStorage OpaqueStorage::STACK_##I(OpaqueStorage::Type::STACK,     \
                                               X86_REG_INVALID, I)
DECL_REG_LOCATION(EAX);
DECL_REG_LOCATION(ECX);
DECL_REG_LOCATION(EDX);
DECL_REG_LOCATION(EBX);
DECL_STACK_LOCATION(0);
DECL_STACK_LOCATION(4);
DECL_STACK_LOCATION(8);
DECL_STACK_LOCATION(12);

class OpaqueConstant32 : public OpaqueConstruct {
public:
  OpaqueState getInput() const override {
    return OpaqueState(); // empty
  }
  OpaqueState getOutput() const override {
    OpaqueState state;
    state.emplace_back(returnStorage(),
                       OpaqueValue::createConstant(returnValue()));
    return state;
  }
  virtual OpaqueStorage returnStorage() const = 0;
  virtual uint32_t returnValue() const = 0;
};

// stub (mock) implementation of opaque constant,
// which just moves the constant into the register/stack.
class MovConstant32 : public OpaqueConstant32 {
public:
  MovConstant32(const OpaqueStorage &target, uint32_t value)
      : target(target), value(value) {}
  void compile(MachineBasicBlock &block,
               MachineBasicBlock::iterator position) const {
    const auto *TII = block.getParent()->getTarget().getMCInstrInfo();
    switch (target.type) {
    case OpaqueStorage::Type::REG:
      BuildMI(block, position, nullptr, TII->get(X86::MOV32ri))
          .addReg(convertToLLVMReg(target.reg))
          .addImm(value);
      break;
    case OpaqueStorage::Type::STACK:
      BuildMI(block, position, nullptr, TII->get(X86::MOV32mi))
          .addReg(X86::ESP)
          .addImm(1)
          .addReg(0)
          .addImm(target.stackOffset)
          .addReg(0)
          .addImm(value);
      break;
    }
  }
  OpaqueStorage returnStorage() const { return target; }
  uint32_t returnValue() const { return value; }
  std::vector<x86_reg> getClobberedRegs() const {
    return std::vector<x86_reg>(); // none
  }

private:
  OpaqueStorage target;
  uint32_t value;
};

std::shared_ptr<OpaqueConstruct> OpaqueConstructFactory::createOpaqueConstant32(
    const OpaqueStorage &target, uint32_t value, const std::string &algorithm) {
  if (algorithm == "mov") {
    return std::shared_ptr<OpaqueConstruct>(new MovConstant32(target, value));
  } else {
    return std::shared_ptr<OpaqueConstruct>();
  }
}
