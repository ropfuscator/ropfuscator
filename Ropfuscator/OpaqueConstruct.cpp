#include "OpaqueConstruct.h"
#include "../X86TargetMachine.h"
#include "X86AssembleHelper.h"

using namespace llvm;

OpaqueConstruct::~OpaqueConstruct() {}

#define DECL_REG_LOCATION(R)                                                   \
  const OpaqueStorage OpaqueStorage::R(OpaqueStorage::Type::REG, X86::R, 0)
#define DECL_STACK_LOCATION(I)                                                 \
  const OpaqueStorage OpaqueStorage::STACK_##I(OpaqueStorage::Type::STACK,     \
                                               X86::NoRegister, I)
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
    return {}; // empty
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
  void compile(X86AssembleHelper &as, int stackOffset) const override {
    switch (target.type) {
    case OpaqueStorage::Type::REG:
      as.mov(as.reg(target.reg), as.imm(value));
      break;
    case OpaqueStorage::Type::STACK:
      as.mov(as.mem(X86::ESP, target.stackOffset + stackOffset), as.imm(value));
      break;
    }
  }
  OpaqueStorage returnStorage() const override { return target; }
  uint32_t returnValue() const override { return value; }
  std::vector<llvm_reg_t> getClobberedRegs() const override { return {}; }

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
