#include "OpaqueConstruct.h"
#include "Debug.h"
#include "InstrStegano.h"
#include "MathUtil.h"
#include "X86AssembleHelper.h"
#include "X86TargetMachine.h"
#include <algorithm>

namespace ropf {

using namespace llvm;

OpaqueConstruct::~OpaqueConstruct() {}

#define DECL_REG_LOCATION(R)                                                   \
  const OpaqueStorage OpaqueStorage::R(OpaqueStorage::Type::REG, X86::R, 0)
#define DECL_STACK_LOCATION(I)                                                 \
  const OpaqueStorage OpaqueStorage::STACK_##I(OpaqueStorage::Type::STACK,     \
                                               X86::NoRegister,                \
                                               I)
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

namespace { // implementation details

// ============================================================
// symbolic (random) value implementation

void moveConstant(X86AssembleHelper &as,
                  StackState &       stack,
                  unsigned int       targetReg,
                  uint32_t           value,
                  size_t             size) {
  // targetReg := resultValue
  if (stack.stack_mangled && !stack.constant_location.empty()) {
    std::vector<int> stackOffsets;
    uint32_t         addend;
    // pick up random constants saved in stack
    std::sample(stack.constant_location.begin(),
                stack.constant_location.end(),
                std::back_inserter(stackOffsets),
                size,
                math::Random::engine());
    // compute difference
    addend = value;
    for (int offset : stackOffsets) {
      addend -= stack.saved_values.find(offset)->second.value;
    }
    std::shuffle(stackOffsets.begin(),
                 stackOffsets.end(),
                 math::Random::engine());
    as.mov(as.reg(targetReg), as.imm(addend));
    for (int offset : stackOffsets) {
      as.add(as.reg(targetReg), as.mem(X86::ESP, offset - stack.stack_offset));
    }
  } else {
    as.mov(as.reg(targetReg), as.imm(value));
  }
}

void moveMixedRegs(X86AssembleHelper &              as,
                   StackState &                     stack,
                   unsigned int                     targetReg,
                   const std::vector<unsigned int> &regs) {
  // targetReg := targetReg + sum(regs)
  if (stack.stack_mangled && !stack.constant_location.empty()) {
    std::vector<int>                        stackOffsets;
    uint32_t                                addend = math::Random::rand();
    decltype(stack.regs_location)::iterator it, end = stack.regs_location.end();
    if ((it = stack.regs_location.find(targetReg)) != end) {
      stackOffsets.push_back(it->second);
    } else {
      std::sample(stack.constant_location.begin(),
                  stack.constant_location.end(),
                  std::back_inserter(stackOffsets),
                  1,
                  math::Random::engine());
    }
    for (auto reg : regs) {
      if ((it = stack.regs_location.find(reg)) != end) {
        stackOffsets.push_back(it->second);
      } else {
        std::sample(stack.constant_location.begin(),
                    stack.constant_location.end(),
                    std::back_inserter(stackOffsets),
                    1,
                    math::Random::engine());
      }
    }
    std::shuffle(stackOffsets.begin(),
                 stackOffsets.end(),
                 math::Random::engine());
    as.mov(as.reg(targetReg), as.imm(addend));
    for (int offset : stackOffsets) {
      as.add(as.reg(targetReg), as.mem(X86::ESP, offset - stack.stack_offset));
    }
  } else {
    decltype(stack.regs_location)::iterator it, end = stack.regs_location.end();
    if ((it = stack.regs_location.find(targetReg)) != end) {
      // register may be clobbered (saved in stack)
      as.mov(as.reg(targetReg),
             as.mem(X86::ESP, it->second - stack.stack_offset));
    }
    for (auto reg : regs) {
      if ((it = stack.regs_location.find(reg)) != end) {
        // register may be clobbered (saved in stack)
        as.add(as.reg(targetReg),
               as.mem(X86::ESP, it->second - stack.stack_offset));
      } else {
        as.add(as.reg(targetReg), as.reg(reg));
      }
    }
  }
}

class RuntimeValueGenerator {
public:
  virtual void compile(X86AssembleHelper &            as,
                       StackState &                   stack,
                       const std::vector<llvm_reg_t> &targetRegs,
                       const std::vector<llvm_reg_t> &sourceRegs) const = 0;
  virtual ~RuntimeValueGenerator() = default;
};

class ConstantRuntimeValueGenerator : RuntimeValueGenerator {
public:
  void compile(X86AssembleHelper &            as,
               StackState &                   stack,
               const std::vector<llvm_reg_t> &targetRegs,
               const std::vector<llvm_reg_t> &sourceRegs) const override {
    for (llvm_reg_t target : targetRegs) {
      moveConstant(as,
                   stack,
                   target,
                   math::Random::rand(),
                   sourceRegs.size() / targetRegs.size());
    }
  }
  static RuntimeValueGenerator *create() {
    return new ConstantRuntimeValueGenerator();
  }
};

class AddRegRuntimeValueGenerator : RuntimeValueGenerator {
public:
  void compile(X86AssembleHelper &            as,
               StackState &                   stack,
               const std::vector<llvm_reg_t> &targetRegs,
               const std::vector<llvm_reg_t> &sourceRegs) const override {
    if (targetRegs.size() > 1) {
      size_t n  = sourceRegs.size() / targetRegs.size();
      auto   it = sourceRegs.begin();
      for (llvm_reg_t target : targetRegs) {
        std::vector<llvm_reg_t> regs(it, it + n);
        moveMixedRegs(as, stack, target, regs);
        it += n;
      }
    } else if (targetRegs.size() == 0) {
      moveMixedRegs(as, stack, targetRegs[0], sourceRegs);
    }
  }
  static RuntimeValueGenerator *create() {
    return new AddRegRuntimeValueGenerator();
  }
};

class RdtscRuntimeValueGenerator : RuntimeValueGenerator {
public:
  void compile(X86AssembleHelper &            as,
               StackState &                   stack,
               const std::vector<llvm_reg_t> &targetRegs,
               const std::vector<llvm_reg_t> &sourceRegs) const override {
    if (targetRegs.size() == 1) {
      llvm_reg_t reg = targetRegs[0];
      if (reg != X86::EAX) {
        as.xchg(as.reg(X86::EAX), as.reg(reg));
      }
      as.push(as.reg(X86::RDX));
      as.rdtsc();
      as.pop(as.reg(X86::RDX));
      if (reg != X86::EAX) {
        as.xchg(as.reg(X86::EAX), as.reg(reg));
      }
    } else if (targetRegs.size() == 2 &&
               ((targetRegs[0] == X86::EAX && targetRegs[1] == X86::EDX) ||
                (targetRegs[0] == X86::RDX && targetRegs[1] == X86::RAX))) {
      as.rdtsc();
    } else if (targetRegs.size() > 1) {
      unsigned int reg = targetRegs[0];
      compile(as, stack, {reg}, sourceRegs);
      for (unsigned int target : targetRegs) {
        if (reg != target) {
          as.mov(as.reg(target), as.reg(reg));
        }
      }
    }
  }
  static RuntimeValueGenerator *create() {
    return new RdtscRuntimeValueGenerator();
  }
};

class RdtscRandomGeneratorOC : public OpaqueConstruct {
public:
  static OpaqueConstruct *create() { return new RdtscRandomGeneratorOC(); }
  void compile(X86AssembleHelper &as, StackState &stack) const override {
    as.rdtsc();
  }
  void compileStegano(X86AssembleHelper &        as,
                      StackState &               stack,
                      const SteganoInstructions &instrs) const override {
    // not used as of now, so just use default implementation
    compile(as, stack);
    InstrSteganoProcessor stegano;
    stegano.insert(instrs, as, stack, {}, 0, 0);
  }
  size_t      opaquePredicateCount() const override { return 0; }
  OpaqueState getInput() const override { return {}; }
  OpaqueState getOutput() const override {
    return {{OpaqueStorage::EAX, OpaqueValue::createAny()}};
  }
  std::vector<llvm_reg_t> getClobberedRegs() const override {
    return {X86::EAX, X86::EDX};
  }
};

class NegativeStackRandomGeneratorOC : public OpaqueConstruct {
public:
  static OpaqueConstruct *create() {
    return new NegativeStackRandomGeneratorOC();
  }
  void compile(X86AssembleHelper &as, StackState &stack) const override {
    int offset = -4 * math::Random::range32(2u, 32u);
    as.mov(as.reg(X86::EAX), as.mem(X86::ESP, offset));
  }
  void compileStegano(X86AssembleHelper &        as,
                      StackState &               stack,
                      const SteganoInstructions &instrs) const override {
    // not used as of now, so just use default implementation
    compile(as, stack);
    InstrSteganoProcessor stegano;
    stegano.insert(instrs, as, stack, {}, 0, 0);
  }
  size_t      opaquePredicateCount() const override { return 0; }
  OpaqueState getInput() const override { return {}; }
  OpaqueState getOutput() const override {
    return {{OpaqueStorage::EAX, OpaqueValue::createAny()}};
  }
  std::vector<llvm_reg_t> getClobberedRegs() const override {
    return {X86::EAX};
  }
};

class AddRegRandomGeneratorOC : public OpaqueConstruct {
public:
  static OpaqueConstruct *create() { return new AddRegRandomGeneratorOC(); }
  void compile(X86AssembleHelper &as, StackState &stack) const override {
    moveMixedRegs(as,
                  stack,
                  X86::EAX,
                  {X86::EBX, X86::ECX, X86::EDX, X86::ESI, X86::EDI});
  }
  void compileStegano(X86AssembleHelper &        as,
                      StackState &               stack,
                      const SteganoInstructions &instrs) const override {
    // not used as of now, so just use default implementation
    compile(as, stack);
    InstrSteganoProcessor stegano;
    stegano.insert(instrs, as, stack, {}, 0, 0);
  }
  size_t      opaquePredicateCount() const override { return 0; }
  OpaqueState getInput() const override { return {}; }
  OpaqueState getOutput() const override {
    return {{OpaqueStorage::EAX, OpaqueValue::createAny()}};
  }
  std::vector<llvm_reg_t> getClobberedRegs() const override {
    return {X86::EAX, X86::EFLAGS};
  }
};

// ============================================================
// basic opaque constant implementation

// stub (mock) implementation of opaque constant,
// which just moves the constant into the register/stack.
class MovConstant32 : public OpaqueConstant32 {
public:
  MovConstant32(const OpaqueStorage &target, uint32_t value)
      : target(target), value(value) {}

  static OpaqueConstruct *create(const OpaqueStorage &                  target,
                                 uint32_t                               value,
                                 std::shared_ptr<RuntimeValueGenerator> rvg,
                                 bool contextualOpEnabled) {
    return new MovConstant32(target, value);
  }

  void compile(X86AssembleHelper &as, StackState &stack) const override {
    switch (target.type) {
    case OpaqueStorage::Type::REG:
      as.mov(as.reg(target.reg), as.imm(value));
      break;
    case OpaqueStorage::Type::STACK:
      as.mov(as.mem(X86::ESP, target.stackOffset), as.imm(value));
      break;
    }
  }

  void compileStegano(X86AssembleHelper &        as,
                      StackState &               stack,
                      const SteganoInstructions &instrs) const override {
    // TODO: interleave
    compile(as, stack);
    InstrSteganoProcessor stegano;
    stegano.insert(instrs, as, stack, {}, 0, 0);
  }

  OpaqueStorage returnStorage() const override { return target; }

  uint32_t returnValue() const override { return value; }

  std::vector<llvm_reg_t> getClobberedRegs() const override {
    if (target.type == OpaqueStorage::Type::REG) {
      return {target.reg};
    }
    return {};
  }

  size_t opaquePredicateCount() const override { return 1; }

private:
  OpaqueStorage target;
  uint32_t      value;
};

// This opaque predicate executes the following code:
//   edx:eax = eax(input1) * edx(input2);
//   dl := edx == compvalue[63:32]
//   al := eax == compvalue[31:0]
//   al := al & dl
// or
//   edx:eax = eax(input1) * edx(input2);
//   dl := edx != compvalue[63:32]
//   al := eax != compvalue[31:0]
//   al := al | dl
class MultiplyCompareOpaquePredicate : public OpaqueConstruct {
  // Contextual OP
  MultiplyCompareOpaquePredicate(uint32_t input1,
                                 uint32_t input2,
                                 uint64_t compvalue,
                                 bool     negate)
      : compvalue(compvalue), negate(negate), isInvariantOp(false) {
    inputState.emplace_back(OpaqueStorage::EAX,
                            OpaqueValue::createConstant(input1));
    inputState.emplace_back(OpaqueStorage::EDX,
                            OpaqueValue::createConstant(input2));
    uint64_t multvalue = (uint64_t)input1 * input2;
    bool     al        = negate ^ (multvalue == compvalue);
    bool     dl        = negate ^ ((multvalue >> 32) == (compvalue >> 32));
    outputState.emplace_back(
        OpaqueStorage::EAX,
        OpaqueValue::createConstant((multvalue & 0xffffff00) + (al ? 1 : 0)));
    outputState.emplace_back(
        OpaqueStorage::EDX,
        OpaqueValue::createConstant(((multvalue >> 32) & 0xffffff00) +
                                    (dl ? 1 : 0)));
  }

  // Invariant OP
  MultiplyCompareOpaquePredicate(uint64_t compvalue, bool negate)
      : compvalue(compvalue), negate(negate), isInvariantOp(true) {
    inputState.emplace_back(OpaqueStorage::EAX, OpaqueValue::createAny());
    inputState.emplace_back(OpaqueStorage::EDX, OpaqueValue::createAny());
    outputState.emplace_back(OpaqueStorage::EAX, OpaqueValue::createAny());
    outputState.emplace_back(OpaqueStorage::EDX, OpaqueValue::createAny());
  }

public:
  OpaqueState getInput() const override { return inputState; }
  OpaqueState getOutput() const override { return outputState; }
  bool        isInvariant() const { return isInvariantOp; }

  void compile(X86AssembleHelper &as, StackState &stack) const override {
    as.mul(as.reg(X86::EDX)); // edx:eax = eax * edx
    as.cmp(as.reg(X86::EAX), as.imm(compvalue & 0xffffffff));
    if (negate) {
      as.setne(as.reg(X86::AL));
      as.cmp(as.reg(X86::EDX), as.imm((compvalue >> 32) & 0xffffffff));
      as.setne(as.reg(X86::DL));
      as.lor8(as.reg(X86::AL), as.reg(X86::DL));
    } else {
      as.sete(as.reg(X86::AL));
      as.cmp(as.reg(X86::EDX), as.imm((compvalue >> 32) & 0xffffffff));
      as.sete(as.reg(X86::DL));
      as.land8(as.reg(X86::AL), as.reg(X86::DL));
    }
  }

  void compileStegano(X86AssembleHelper &        as,
                      StackState &               stack,
                      const SteganoInstructions &instrs) const override {
    as.mul(as.reg(X86::EDX)); // edx:eax = eax * edx
    InstrSteganoProcessor stegano;
    const OpaqueValue *   eax = inputState.find(OpaqueStorage::EAX);
    const OpaqueValue *   edx = inputState.find(OpaqueStorage::EDX);
    if (eax->type == OpaqueValue::Type::CONSTANT &&
        edx->type == OpaqueValue::Type::CONSTANT) {
      uint64_t mult_result =
          (uint64_t)eax->values[0] * (uint64_t)edx->values[0];
      if (math::Random::bit()) {
        stegano.insert(instrs,
                       as,
                       stack,
                       {},
                       X86::EDX,
                       (uint32_t)(mult_result >> 32));
      } else {
        stegano.insert(instrs, as, stack, {}, X86::EAX, (uint32_t)mult_result);
      }
    } else {
      stegano.insert(instrs, as, stack, {}, 0, 0);
    }
    as.cmp(as.reg(X86::EAX), as.imm(compvalue & 0xffffffff));
    if (negate) {
      as.setne(as.reg(X86::AL));
      as.cmp(as.reg(X86::EDX), as.imm((compvalue >> 32) & 0xffffffff));
      as.setne(as.reg(X86::DL));
      as.lor8(as.reg(X86::AL), as.reg(X86::DL));
    } else {
      as.sete(as.reg(X86::AL));
      as.cmp(as.reg(X86::EDX), as.imm((compvalue >> 32) & 0xffffffff));
      as.sete(as.reg(X86::DL));
      as.land8(as.reg(X86::AL), as.reg(X86::DL));
    }
  }

  size_t opaquePredicateCount() const override { return 1; }

  std::vector<llvm_reg_t> getClobberedRegs() const override {
    return {X86::EAX, X86::EDX, X86::EFLAGS};
  }

  // Invariant OP: for all input, generate constant
  static std::shared_ptr<MultiplyCompareOpaquePredicate>
  createRandomInvariant(bool output) {
    uint64_t z = math::PrimeNumberGenerator::getPrime64();
    return std::shared_ptr<MultiplyCompareOpaquePredicate>(
        new MultiplyCompareOpaquePredicate(z, output));
  }

  // Contextual OP: almost invariant but has different output for some input
  static std::shared_ptr<MultiplyCompareOpaquePredicate>
  createRandomContextual(bool output) {
    uint32_t x      = math::PrimeNumberGenerator::getPrime32();
    uint32_t y      = math::PrimeNumberGenerator::getPrime32();
    uint64_t z      = (uint64_t)x * y;
    bool     negate = math::Random::bit();
    output ^= negate;
    if (!output) {
      uint64_t v;
      do {
        v = (uint64_t)math::PrimeNumberGenerator::getPrime32() *
            math::PrimeNumberGenerator::getPrime32();
      } while (z == v);
      z = v;
    }
    return std::shared_ptr<MultiplyCompareOpaquePredicate>(
        new MultiplyCompareOpaquePredicate(x, y, z, negate));
  }

  // Randomly generate contextual or invariant OP
  static std::shared_ptr<MultiplyCompareOpaquePredicate>
  createRandom(bool output) {
    return math::Random::bit() ? createRandomContextual(output)
                               : createRandomInvariant(output);
  }

private:
  uint64_t    compvalue;
  bool        negate;
  bool        isInvariantOp;
  OpaqueState inputState, outputState;
};

class MultiplyCompareBasedOpaqueConstant : public OpaqueConstant32 {
  std::vector<std::shared_ptr<MultiplyCompareOpaquePredicate>> predicates;
  const OpaqueStorage &                                        target;
  uint32_t                                                     value;
  std::shared_ptr<RuntimeValueGenerator>                       rvg;

public:
  MultiplyCompareBasedOpaqueConstant(const OpaqueStorage &target,
                                     uint32_t             value,
                                     std::shared_ptr<RuntimeValueGenerator> rvg,
                                     bool contextualOpEnabled)
      : target(target), value(value), rvg(rvg) {
    for (int i = 31; i >= 0; i--) {
      bool v = 1 & (value >> i);
      predicates.push_back(
          contextualOpEnabled
              ? MultiplyCompareOpaquePredicate::createRandom(v)
              : MultiplyCompareOpaquePredicate::createRandomInvariant(v));
    }
  }

  static OpaqueConstruct *create(const OpaqueStorage &                  target,
                                 uint32_t                               value,
                                 std::shared_ptr<RuntimeValueGenerator> rvg,
                                 bool contextualOpEnabled) {
    return new MultiplyCompareBasedOpaqueConstant(target,
                                                  value,
                                                  rvg,
                                                  contextualOpEnabled);
  }

  OpaqueStorage returnStorage() const override { return target; }

  uint32_t returnValue() const override { return value; }

  std::vector<llvm_reg_t> getClobberedRegs() const override {
    return {X86::EAX, X86::ECX, X86::EDX, X86::EFLAGS};
  }

  void compile(X86AssembleHelper &as, StackState &stack) const override {
    // as.inlineasm(fmt::format("# MULTCOMP BEGIN 0x{:x}", returnValue()));
    for (auto &p : predicates) {
      // initialise inputs (eax, edx)
      if (p->isInvariant()) {
        compileRandom(as, stack);
      } else {
        uint32_t in_eax = *p->getInput().findValue(OpaqueStorage::EAX);
        uint32_t in_edx = *p->getInput().findValue(OpaqueStorage::EDX);
        compileConstant(as, stack, in_eax, in_edx);
      }
      // multiply and compare
      p->compile(as, stack);
      // accumulate the result in ecx
      as.shl(as.reg(X86::ECX));
      as.lor8(as.reg(X86::CL), as.reg(X86::AL));
    }
    switch (target.type) {
    case OpaqueStorage::Type::REG:
      if (target.reg != X86::ECX)
        as.mov(as.reg(target.reg), as.reg(X86::ECX));
      break;
    case OpaqueStorage::Type::STACK:
      as.mov(as.mem(X86::ESP, target.stackOffset), as.reg(X86::ECX));
      break;
    }
    // as.inlineasm(fmt::format("# MULTCOMP END 0x{:x}", returnValue()));
  }

  void compileStegano(X86AssembleHelper &        as,
                      StackState &               stack,
                      const SteganoInstructions &instrs) const override {
    // as.inlineasm(fmt::format("# MULTCOMP BEGIN 0x{:x}", returnValue()));
    std::vector<SteganoInstructions> steglist;
    instrs.expandWithDummy(predicates.size())
        .split(predicates.size(), steglist);
    for (size_t i = 0; i < steglist.size(); i++) {
      auto &p = predicates[i];
      // initialise inputs (eax, edx)
      if (p->isInvariant()) {
        compileRandom(as, stack);
      } else {
        uint32_t in_eax = *p->getInput().findValue(OpaqueStorage::EAX);
        uint32_t in_edx = *p->getInput().findValue(OpaqueStorage::EDX);
        compileConstant(as, stack, in_eax, in_edx);
      }
      // multiply and compare
      p->compileStegano(as, stack, steglist[i]);
      // accumulate the result in ecx
      as.shl(as.reg(X86::ECX));
      as.lor8(as.reg(X86::CL), as.reg(X86::AL));
    }
    switch (target.type) {
    case OpaqueStorage::Type::REG:
      if (target.reg != X86::ECX)
        as.mov(as.reg(target.reg), as.reg(X86::ECX));
      break;
    case OpaqueStorage::Type::STACK:
      as.mov(as.mem(X86::ESP, target.stackOffset), as.reg(X86::ECX));
      break;
    }
    // as.inlineasm(fmt::format("# MULTCOMP END 0x{:x}", returnValue()));
  }

  size_t opaquePredicateCount() const override { return predicates.size(); }

private:
  void compileConstant(X86AssembleHelper &as,
                       StackState &       stack,
                       uint32_t           eax,
                       uint32_t           edx) const {
    moveConstant(as, stack, X86::EAX, eax, 3);
    moveConstant(as, stack, X86::EDX, edx, 3);
  }
  void compileRandom(X86AssembleHelper &as, StackState &stack) const {
    rvg->compile(as,
                 stack,
                 {X86::EAX, X86::EDX},
                 {X86::ECX, X86::ESI, X86::EBX, X86::EDI});
    // moveMixedRegs(as, stack, X86::EAX, {X86::ECX, X86::ESI});
    // moveMixedRegs(as, stack, X86::EDX, {X86::EBX, X86::EDI});
  }
}; // namespace

struct R3SATVar {
  uint8_t index : 7;
  bool    neg   : 1;
};

struct R3SATClause {
  std::array<R3SATVar, 3>                        vars;
  template <typename UINT> std::pair<UINT, UINT> toMask() const {
    std::pair<UINT, UINT> mask = {0, 0};
    for (int i = 0; i < 3; i++) {
      (vars[i].neg ? mask.second : mask.first) |= (UINT)1 << vars[i].index;
    }
    return mask;
  }
};

template <typename UINT>
class Random3SATOpaquePredicateBase : public OpaqueConstruct {
protected:
  Random3SATOpaquePredicateBase(bool negate, bool isInvariantOp)
      : negate(negate), isInvariantOp(isInvariantOp) {}

public:
  OpaqueState getInput() const override { return inputState; }
  OpaqueState getOutput() const override { return outputState; }
  bool        isInvariant() const { return isInvariantOp; }

protected:
  void genClauses(const UINT *avoid, int nclauses) {
    for (int k = 0; k < nclauses; k++) {
      UINT        maskbits[2];
      R3SATClause clause;
      do {
        maskbits[0] = maskbits[1] = 0;
        for (int bits = 0; bits < 3;) {
          R3SATVar var = {
              (uint8_t)math::Random::range32(0, sizeof(UINT) * 8 - 1),
              math::Random::bit()};
          UINT mask = (UINT)1 << var.index;
          if ((maskbits[0] & mask) | (maskbits[1] & mask))
            continue;
          maskbits[var.neg] |= mask;
          clause.vars[bits] = var;
          bits++;
        }
      } while (avoid &&
               ((maskbits[0] & *avoid) | (maskbits[1] & ~*avoid)) == 0);
      clauses.emplace_back(clause);
    }
  }

  bool                     negate;
  bool                     isInvariantOp;
  std::vector<R3SATClause> clauses;
  OpaqueState              inputState, outputState;
};

class Random3SAT32OpaquePredicate
    : public Random3SATOpaquePredicateBase<uint32_t> {
  // Contextual OP 1
  Random3SAT32OpaquePredicate(uint32_t input,
                              bool     negate,
                              int      nclauses = 32 * 6)
      : Random3SATOpaquePredicateBase(negate, false) {
    // input = edx, output = lsb of eax
    inputState.emplace_back(OpaqueStorage::EDX,
                            OpaqueValue::createConstant(input));
    genClauses(&input, nclauses);
  }

  // Contextual OP 2
  Random3SAT32OpaquePredicate(uint32_t input1,
                              uint32_t input2,
                              bool     negate,
                              int      nclauses = 32 * 6)
      : Random3SATOpaquePredicateBase(negate, false) {
    // input = edx, output = lsb of eax
    inputState.emplace_back(OpaqueStorage::EDX,
                            OpaqueValue::createConstant(input1));
    genClauses(&input2, nclauses);
  }

  // Invariant OP
  Random3SAT32OpaquePredicate(bool negate, int nclauses = 32 * 6)
      : Random3SATOpaquePredicateBase(negate, true) {
    // input = edx, output = lsb of eax
    inputState.emplace_back(OpaqueStorage::EDX, OpaqueValue::createAny());
    genClauses(nullptr, nclauses);
  }

  static void compileSharedCode(X86AssembleHelper &as, bool negate) {
    // Input: esi - pointer to clause data
    // InOut: al - set result in LSB of al
    // Clobber: bx, ecx, edx, edi, esi
    auto reg_ptr   = as.reg(X86::ESI);
    auto reg_input = as.reg(X86::EDX);
    auto reg_info  = as.reg(X86::ECX);
    auto reg_mask  = as.reg(X86::EDI);
    auto l0        = as.label();
    auto l2        = as.label();

    // asm                  # asm (negate)
    //   or    al, 0x01     #   and   al, 0xfe
    //   mov   edi, 1
    // .L0:
    //   mov   bl, al
    //   and   bl, 0xfe     #   or    bl, 0x01
    //   mov   ecx, [esi]
    //   test  ecx, ecx
    //   je    .L2
    // === repeat 3 times ===
    //   test  cl, 0x80
    //   je    .L1
    //   not   edx
    // .L1:
    //   rol   edi, cl
    //   test  edx, edi
    //   setne bh
    //                      #   not   bh
    //   or    bl, bh       #   and   bl, bh
    //   shr   ecx, 8
    // === repeat end ===
    //   and   al, bl       #   or    al, bl
    //   add   esi, 3
    //   jmp   .L0
    // .L2:
    if (negate) {
      as.land8(as.reg(X86::AL), as.imm(0xfe));
    } else {
      as.lor8(as.reg(X86::AL), as.imm(0x01));
    }
    as.mov(reg_mask, as.imm(1));
    as.putLabel(l0);
    as.mov8(as.reg(X86::BL), as.reg(X86::AL));
    if (negate) {
      as.lor8(as.reg(X86::BL), as.imm(0x01));
    } else {
      as.land8(as.reg(X86::BL), as.imm(0xfe));
    }
    as.mov(reg_info, as.mem(X86::ESI));
    as.test(reg_info, reg_info);
    as.je(l2);
    for (int i = 0; i < 3; i++) {
      auto l1 = as.label();
      as.test8(as.reg(X86::CL), as.imm(0x80));
      as.je(l1);
      as.lnot(reg_input);
      as.putLabel(l1);
      as.rol_cl(reg_mask);
      as.test(reg_input, reg_mask);
      as.setne(as.reg(X86::BH));
      if (negate) {
        as.lnot8(as.reg(X86::BH));
        as.land8(as.reg(X86::BL), as.reg(X86::BH));
      } else {
        as.lor8(as.reg(X86::BL), as.reg(X86::BH));
      }
      if (i != 2) {
        as.shr(as.reg(X86::ECX), as.imm(8));
      }
    }
    if (negate) {
      as.lor8(as.reg(X86::AL), as.reg(X86::BL));
    } else {
      as.land8(as.reg(X86::AL), as.reg(X86::BL));
    }
    as.add(reg_ptr, as.imm(3));
    as.jmp(l0);
    as.putLabel(l2);
  }

public:
  void compile(X86AssembleHelper &as, StackState &stack) const override {
    std::vector<uint8_t> clausedata;
    R3SATVar             current = {0, 0};
    for (auto clause : clauses) {
      for (auto var : clause.vars) {
        uint8_t info = (var.index - current.index + 32) % 32;
        if (var.neg ^ current.neg) {
          info |= 0x80;
        }
        current = var;
        clausedata.push_back(info);
      }
    }
    for (int i = 0; i < 4; i++) {
      clausedata.push_back(0);
    }
    auto gv_clausedata = as.createData(clausedata.data(), clausedata.size());
    as.mov(as.reg(X86::ESI), gv_clausedata);
    compileSharedCode(as, negate);
  }

  void compileStegano(X86AssembleHelper &        as,
                      StackState &               stack,
                      const SteganoInstructions &instrs) const override {
    // TODO: interleave
    compile(as, stack);
    InstrSteganoProcessor stegano;
    stegano.insert(instrs, as, stack, {}, 0, 0);
  }

  size_t opaquePredicateCount() const override { return 1; }

  std::vector<llvm_reg_t> getClobberedRegs() const override {
    return {X86::EAX,
            X86::EBX,
            X86::ECX,
            X86::EDX,
            X86::EDI,
            X86::ESI,
            X86::EFLAGS};
  }

  // Invariant OP: for all input, generate constant
  static std::shared_ptr<Random3SAT32OpaquePredicate>
  createRandomInvariant(bool output) {
    return std::shared_ptr<Random3SAT32OpaquePredicate>(
        new Random3SAT32OpaquePredicate(output));
  }

  // Contextual OP: almost invariant but has different output for some input
  static std::shared_ptr<Random3SAT32OpaquePredicate>
  createRandomContextual(bool output) {
    uint32_t input = math::Random::range32(0, UINT32_MAX);
    return std::shared_ptr<Random3SAT32OpaquePredicate>(
        new Random3SAT32OpaquePredicate(input, !output));
  }

  // Contextual OP: almost invariant but has different output for some input
  static std::shared_ptr<Random3SAT32OpaquePredicate>
  createRandomContextual2(bool output) {
    uint32_t input1 = math::Random::range32(0, UINT32_MAX);
    uint32_t input2 = math::Random::range32(0, UINT32_MAX);
    while (input1 == input2) {
      input2 = math::Random::range32(0, UINT32_MAX);
    }
    return std::shared_ptr<Random3SAT32OpaquePredicate>(
        new Random3SAT32OpaquePredicate(input1, input2, output));
  }

  // Randomly generate contextual or invariant OP
  static std::shared_ptr<Random3SAT32OpaquePredicate>
  createRandom(bool output) {
    switch (math::Random::range32(0, 2)) {
    case 0: return createRandomContextual(output);
    case 1: return createRandomContextual2(output);
    default: return createRandomInvariant(output);
    }
  }
};

class Random3SAT32OpaqueConstant : public OpaqueConstant32 {
  std::vector<std::shared_ptr<Random3SAT32OpaquePredicate>> predicates;
  const OpaqueStorage &                                     target;
  uint32_t                                                  value;
  std::shared_ptr<RuntimeValueGenerator>                    rvg;

public:
  Random3SAT32OpaqueConstant(const OpaqueStorage &                  target,
                             uint32_t                               value,
                             std::shared_ptr<RuntimeValueGenerator> rvg,
                             bool contextualOpEnabled)
      : target(target), value(value), rvg(rvg) {
    for (int i = 31; i >= 0; i--) {
      bool v = 1 & (value >> i);
      predicates.push_back(
          contextualOpEnabled
              ? Random3SAT32OpaquePredicate::createRandom(v)
              : Random3SAT32OpaquePredicate::createRandomInvariant(v));
    }
  }

  static OpaqueConstruct *create(const OpaqueStorage &                  target,
                                 uint32_t                               value,
                                 std::shared_ptr<RuntimeValueGenerator> rvg,
                                 bool contextualOpEnabled) {
    return new Random3SAT32OpaqueConstant(target,
                                          value,
                                          rvg,
                                          contextualOpEnabled);
  }

  OpaqueStorage returnStorage() const override { return target; }

  uint32_t returnValue() const override { return value; }

  std::vector<llvm_reg_t> getClobberedRegs() const override {
    return {X86::EAX,
            X86::EBX,
            X86::ECX,
            X86::EDX,
            X86::EDI,
            X86::ESI,
            X86::EFLAGS};
  }

  void compile(X86AssembleHelper &as, StackState &stack) const override {
    // as.inlineasm(fmt::format("# R3SAT BEGIN 0x{:x}", returnValue()));
    for (auto &p : predicates) {
      // initialise input (edx)
      if (p->isInvariant()) {
        compileRandom(as, stack);
      } else {
        uint32_t in_edx = *p->getInput().findValue(OpaqueStorage::EDX);
        compileConstant(as, stack, in_edx);
      }
      // accumulate the result in eax
      as.shl(as.reg(X86::EAX));
      // compute opaque predicate (set LSB in eax)
      p->compile(as, stack);
    }
    switch (target.type) {
    case OpaqueStorage::Type::REG:
      if (target.reg != X86::EAX)
        as.mov(as.reg(target.reg), as.reg(X86::EAX));
      break;
    case OpaqueStorage::Type::STACK:
      as.mov(as.mem(X86::ESP, target.stackOffset), as.reg(X86::EAX));
      break;
    }
    // as.inlineasm(fmt::format("# R3SAT END 0x{:x}", returnValue()));
  }

  void compileStegano(X86AssembleHelper &        as,
                      StackState &               stack,
                      const SteganoInstructions &instrs) const override {
    // as.inlineasm(fmt::format("# R3SAT BEGIN 0x{:x}", returnValue()));
    std::vector<SteganoInstructions> steglist;
    instrs.expandWithDummy(predicates.size())
        .split(predicates.size(), steglist);
    for (size_t i = 0; i < predicates.size(); i++) {
      auto &p = predicates[i];
      // initialise input (edx)
      if (p->isInvariant()) {
        compileRandom(as, stack);
      } else {
        uint32_t in_edx = *p->getInput().findValue(OpaqueStorage::EDX);
        compileConstant(as, stack, in_edx);
      }
      // accumulate the result in eax
      as.shl(as.reg(X86::EAX));
      // compute opaque predicate (set LSB in eax)
      p->compileStegano(as, stack, steglist[i]);
    }
    switch (target.type) {
    case OpaqueStorage::Type::REG:
      if (target.reg != X86::EAX)
        as.mov(as.reg(target.reg), as.reg(X86::EAX));
      break;
    case OpaqueStorage::Type::STACK:
      as.mov(as.mem(X86::ESP, target.stackOffset), as.reg(X86::EAX));
      break;
    }
    // as.inlineasm(fmt::format("# R3SAT END 0x{:x}", returnValue()));
  }

  size_t opaquePredicateCount() const override { return predicates.size(); }

private:
  void compileConstant(X86AssembleHelper &as,
                       StackState &       stack,
                       uint32_t           value) const {
    moveConstant(as, stack, X86::EDX, value, 6);
  }
  void compileRandom(X86AssembleHelper &as, StackState &stack) const {
    // moveMixedRegs(as, stack, X86::EDX,
    //               {X86::EAX, X86::EBX, X86::ECX, X86::EDI, X86::ESI});
    rvg->compile(as,
                 stack,
                 {X86::EDX},
                 {X86::EAX, X86::EBX, X86::ECX, X86::EDI, X86::ESI});
  }
};

// ============================================================
// selector implementation
// selector will select a value from a set of values, based on random input

class MovRandomSelectorOC : public OpaqueConstruct {
public:
  MovRandomSelectorOC(const OpaqueStorage &        target,
                      const std::vector<uint32_t> &values)
      : target(target), values(values) {
    std::random_shuffle(this->values.begin(), this->values.end());
  }
  static OpaqueConstruct *create(const OpaqueStorage &        target,
                                 const std::vector<uint32_t> &values) {
    return new MovRandomSelectorOC(target, values);
  }

  void compile(X86AssembleHelper &as, StackState &stack) const override {
    unsigned int targetreg =
        target.type == OpaqueStorage::Type::REG ? target.reg : X86::EAX;
    unsigned int tmpreg    = target.reg == X86::EAX ? X86::EDX : X86::EAX;
    auto         endLabel  = as.label();
    bool         labelUsed = false;
    compileAux(as,
               as.reg(targetreg),
               as.reg(tmpreg),
               endLabel,
               0,
               values.size(),
               1,
               labelUsed);
    if (labelUsed)
      as.putLabel(endLabel);
    if (target.type == OpaqueStorage::Type::STACK) {
      as.mov(as.mem(X86::ESP, target.stackOffset), as.reg(targetreg));
    }
  }

  void compileStegano(X86AssembleHelper &        as,
                      StackState &               stack,
                      const SteganoInstructions &instrs) const override {
    // not used as of now, so just use default implementation
    compile(as, stack);
    InstrSteganoProcessor stegano;
    stegano.insert(instrs, as, stack, {}, 0, 0);
  }
  size_t opaquePredicateCount() const override { return 0; }

  OpaqueState getInput() const override {
    return {{OpaqueStorage::EAX, OpaqueValue::createAny()}};
  }
  OpaqueState getOutput() const override {
    return {{OpaqueStorage::EAX, OpaqueValue::createConstant(values)}};
  }
  std::vector<llvm_reg_t> getClobberedRegs() const override {
    return {X86::EAX, X86::EDX};
  }

private:
  OpaqueStorage         target;
  std::vector<uint32_t> values;

  void compileAux(X86AssembleHelper &             as,
                  const X86AssembleHelper::Reg &  target,
                  const X86AssembleHelper::Reg &  tmpreg,
                  const X86AssembleHelper::Label &endLabel,
                  uint32_t                        m,
                  uint32_t                        n,
                  uint32_t                        flag,
                  bool &                          labelUsed) const {
    if (n == 1) {
      as.mov(target, as.imm(values[m]));
      if (m + n != values.size()) {
        as.jmp(endLabel);
        labelUsed = true;
      }
    } else if (n == 2) {
      as.test(as.reg(X86::EAX), as.imm(flag));
      as.mov(target, as.imm(values[0]));
      as.mov(tmpreg, as.imm(values[1]));
      as.cmove(target, tmpreg);
      if (m + n != values.size()) {
        as.jmp(endLabel);
        labelUsed = true;
      }
    } else {
      int  n2    = n / 2;
      auto label = as.label();
      as.test(as.reg(X86::EAX), as.imm(flag));
      as.je(label);
      compileAux(as, target, tmpreg, endLabel, m, n2, flag << 1, labelUsed);
      as.putLabel(label);
      compileAux(as,
                 target,
                 tmpreg,
                 endLabel,
                 m + n2,
                 n - n2,
                 flag << 1,
                 labelUsed);
    }
  }
};

// ============================================================
// composer implementation
// composer will connect multiple opaque constructs

class ComposedOpaqueConstruct : public OpaqueConstruct {
  std::vector<std::shared_ptr<OpaqueConstruct>> functions;

public:
  ComposedOpaqueConstruct(
      std::initializer_list<std::shared_ptr<OpaqueConstruct>> functions)
      : functions(functions) {
    std::reverse(this->functions.begin(), this->functions.end());
  }

  void compile(X86AssembleHelper &as, StackState &stack) const override {
    for (auto &func : functions) {
      func->compile(as, stack);
    }
  }

  void compileStegano(X86AssembleHelper &        as,
                      StackState &               stack,
                      const SteganoInstructions &instrs) const override {
    if (instrs.instrs.empty()) {
      compile(as, stack);
    } else {
      size_t insertionPoints =
          std::count_if(functions.begin(), functions.end(), [](auto &func) {
            return func->opaquePredicateCount() > 0;
          });
      if (insertionPoints == 1) {
        for (auto &func : functions) {
          if (func->opaquePredicateCount()) {
            func->compileStegano(as, stack, instrs);
          } else {
            func->compile(as, stack);
          }
        }
      } else if (insertionPoints == 0 || insertionPoints == functions.size()) {
        std::vector<SteganoInstructions> list;
        instrs.expandWithDummy(functions.size()).split(functions.size(), list);
        for (size_t i = 0; i < functions.size(); i++) {
          functions[i]->compileStegano(as, stack, list[i]);
        }
      } else {
        std::vector<SteganoInstructions> list;
        instrs.expandWithDummy(insertionPoints).split(insertionPoints, list);
        size_t j = 0;
        for (auto &func : functions) {
          if (func->opaquePredicateCount()) {
            func->compileStegano(as, stack, list[j++]);
          } else {
            func->compile(as, stack);
          }
        }
      }
    }
  }

  size_t opaquePredicateCount() const override {
    size_t count = 0;
    for (auto &f : functions) {
      count += f->opaquePredicateCount();
    }
    return count;
  }

  OpaqueState getInput() const override {
    return functions.size() > 0 ? functions[0]->getInput() : OpaqueState();
  }
  OpaqueState getOutput() const override {
    return functions.size() > 0 ? functions[functions.size() - 1]->getOutput()
                                : OpaqueState();
  }
  std::vector<llvm_reg_t> getClobberedRegs() const override {
    std::set<llvm_reg_t> regs;
    for (auto func : functions) {
      auto clobbered = func->getClobberedRegs();
      regs.insert(clobbered.begin(), clobbered.end());
    }
    return std::vector<llvm_reg_t>(regs.begin(), regs.end());
  }
};

// ============================================================
// value adjuster implementation

// This class will convert input values to output values,
// without leaking input/output values themselves.
// All input / output values should be distinct and have same length.
//
// case n=1:
//   just use XOR to convert value.
//   y1 = x1 ^ V   where V = x1 ^ y1
// case n=2:
//   using multiplication and addition (with optional shift) to convert value.
//   y1 = (x1 >> S) * V + U
//   y2 = (x2 >> S) * V + U
//     where V = (y2 - y1) * (Inv(x2 >> S - x1 >> S) mod 2**32)
//           U = y1 - (x1 >> S) * V
//     (Note: modular inverse may not exist for (x2-x1) when x2-x1 is even,
//            so we try S = 0..31 to find )
// case n>2:
//   not implemented. maybe matrix-modulo-inverse based implementation?
class ValueAdjustingOpaqueConstruct : public OpaqueConstruct {
public:
  ValueAdjustingOpaqueConstruct(const OpaqueStorage &        target,
                                const std::vector<uint32_t> &inputvalues,
                                const std::vector<uint32_t> &outputvalues)
      : target(target), inputvalues(inputvalues), outputvalues(outputvalues) {
    assert(inputvalues.size() == outputvalues.size());
    std::sort(this->inputvalues.begin(), this->inputvalues.end());
    std::random_shuffle(this->outputvalues.begin(), this->outputvalues.end());
  }

  void compile(X86AssembleHelper &as, StackState &stack) const override {
    auto endLabel     = as.label();
    bool endLabelUsed = false;
    switch (target.type) {
    case OpaqueStorage::Type::REG:
      compileAux(as, 0, inputvalues.size(), target.reg, endLabelUsed, endLabel);
      if (endLabelUsed)
        as.putLabel(endLabel);
      break;
    case OpaqueStorage::Type::STACK:
      auto stackref = as.mem(X86::ESP, target.stackOffset);
      as.mov(as.reg(X86::EAX), stackref);
      compileAux(as, 0, inputvalues.size(), X86::EAX, endLabelUsed, endLabel);
      if (endLabelUsed)
        as.putLabel(endLabel);
      as.mov(stackref, as.reg(X86::EAX));
      break;
    }
  }

  void compileStegano(X86AssembleHelper &        as,
                      StackState &               stack,
                      const SteganoInstructions &instrs) const override {
    // not used as of now, so just use default implementation
    compile(as, stack);
    InstrSteganoProcessor stegano;
    stegano.insert(instrs, as, stack, {}, 0, 0);
  }

  size_t opaquePredicateCount() const override { return 0; }

  OpaqueState getInput() const override {
    return {{target, OpaqueValue::createConstant(inputvalues)}};
  }
  OpaqueState getOutput() const override {
    return {{target, OpaqueValue::createConstant(outputvalues)}};
  }
  std::vector<llvm_reg_t> getClobberedRegs() const override {
    switch (inputvalues.size()) {
    case 1:
      if (target.type == OpaqueStorage::Type::STACK)
        return {X86::EAX, X86::EFLAGS};
      return {X86::EFLAGS};
    case 2: return {X86::EAX, X86::EDX, X86::EFLAGS};
    default: return {X86::EAX, X86::ECX, X86::EDX, X86::EFLAGS};
    }
  }

private:
  OpaqueStorage         target;
  std::vector<uint32_t> inputvalues;
  std::vector<uint32_t> outputvalues;

  void compileAux(X86AssembleHelper &             as,
                  uint32_t                        pos,
                  uint32_t                        N,
                  unsigned int                    targetreg,
                  bool &                          endLabelUsed,
                  const X86AssembleHelper::Label &endLabel) const {
    if (N == 1) {
      uint32_t xorval = inputvalues[pos] ^ outputvalues[pos];
      as.lxor(as.reg(targetreg), as.imm(xorval));
    } else {
      std::vector<uint32_t> params;
      uint32_t              shift;
      if (computeParams(pos, N, params, shift)) {
        // tmpreg1: used in N>2, tmpreg2: used in N>3
        unsigned int tmpreg1 = targetreg == X86::EDX ? X86::EAX : X86::EDX;
        unsigned int tmpreg2 = targetreg == X86::ECX ? X86::EAX : X86::ECX;
        if (shift > 0)
          as.shr(as.reg(targetreg), as.imm(shift));
        for (uint32_t i = 0; i + 2 < N; i++) {
          if (i == 0) {
            as.imul(as.reg(tmpreg1), as.reg(targetreg), as.imm(params[i]));
          } else {
            as.imul(as.reg(tmpreg2), as.reg(targetreg), as.imm(params[i]));
            as.add(as.reg(tmpreg1), as.reg(tmpreg2));
          }
          as.shr(as.reg(targetreg), as.imm(1));
        }
        as.imul(as.reg(targetreg), as.imm(params[N - 2]));
        as.add(as.reg(targetreg), as.imm(params[N - 1]));
        if (N > 2) {
          as.add(as.reg(targetreg), as.reg(tmpreg1));
        }
      } else {
        // cannot find matrix inverse; we should split the input-output map
        // and compile each case
        assert(N >= 3);
        uint32_t n2 = (N + 1) / 2;
        assert(inputvalues[pos + n2 - 1] < inputvalues[pos + n2]);
        uint32_t mid    = math::Random::range32(inputvalues[pos + n2 - 1] + 1,
                                             inputvalues[pos + n2]);
        auto     label1 = as.label();
        // test if input < mid
        as.cmp(as.reg(targetreg), as.imm(mid));
        as.jb(label1);
        // case input >= mid:
        compileAux(as, pos + n2, N - n2, targetreg, endLabelUsed, endLabel);
        as.jmp(endLabel);
        endLabelUsed = true;
        // case input < mid:
        as.putLabel(label1);
        compileAux(as, pos, n2, targetreg, endLabelUsed, endLabel);
      }
    }
  }

  // compute parameters such that:
  // ForAll j: output[j] ==
  //  Sum_i<-{0..N-2} { params[i]*(input[j]>>(shift+i)) } + params[N-1]
  bool computeParams(uint32_t               pos,
                     uint32_t               N,
                     std::vector<uint32_t> &params,
                     uint32_t &             shift) const {
    math::Matrix mat(N, N);
    for (uint32_t s = 0; s + N < 32 + 2; s++) {
      for (uint32_t i = 0; i < N; i++) {
        for (uint32_t j = 0; j < N - 1; j++) {
          mat.at(i, j) = inputvalues[pos + i] >> (s + j);
        }
        mat.at(i, N - 1) = 1;
      }
      math::Matrix invmat = mat.view().inverse_mod(0x100000000ULL);
      if (invmat.width() > 0) {
        math::Matrix output(1, N);
        for (uint32_t i = 0; i < N; i++) {
          output.at(i, 0) = outputvalues[pos + i];
        }
        math::Matrix p = invmat * output;
        for (uint32_t i = 0; i < N; i++) {
          params.push_back((uint32_t)p.at(i, 0));
        }
        shift = s;
        return true;
      }
    }
    return false;
  }
};

// ============================================================
// factories

template <typename Result, typename... Args>
using oc_factory = Result *(*)(Args...);

std::map<std::string,
         oc_factory<OpaqueConstruct,
                    const OpaqueStorage &,
                    uint32_t,
                    std::shared_ptr<RuntimeValueGenerator>,
                    bool>>
    constant_factories = {
        {OPAQUE_CONSTANT_ALGORITHM_MOV, MovConstant32::create},
        {OPAQUE_CONSTANT_ALGORITHM_MULTCOMP,
         MultiplyCompareBasedOpaqueConstant::create},
        {OPAQUE_CONSTANT_ALGORITHM_R3SAT32, Random3SAT32OpaqueConstant::create},
};

std::map<std::string, oc_factory<RuntimeValueGenerator>>
    runtimevaluegen_factories = {
        {OPAQUE_RANDOM_ALGORITHM_ADDREG, AddRegRuntimeValueGenerator::create},
        {OPAQUE_RANDOM_ALGORITHM_RDTSC, RdtscRuntimeValueGenerator::create},
        {OPAQUE_RANDOM_ALGORITHM_CONSTANT,
         ConstantRuntimeValueGenerator::create},
};

std::map<std::string, oc_factory<OpaqueConstruct>> random_factories = {
    {OPAQUE_RANDOM_ALGORITHM_ADDREG, AddRegRandomGeneratorOC::create},
    {OPAQUE_RANDOM_ALGORITHM_RDTSC, RdtscRandomGeneratorOC::create},
    {OPAQUE_RANDOM_ALGORITHM_NEGSTK, NegativeStackRandomGeneratorOC::create},
};

std::map<std::string,
         oc_factory<OpaqueConstruct,
                    const OpaqueStorage &,
                    const std::vector<uint32_t> &>>
    selector_factories = {
        {OPAQUE_SELECTOR_ALGORITHM_MOV, MovRandomSelectorOC::create},
};

template <typename Result, typename... Args>
Result *
callFactory(const std::map<std::string, oc_factory<Result, Args...>> &factories,
            const std::string &                                       key,
            Args &&...args) {
  auto it = factories.find(key);
  return it == factories.end() ? nullptr
                               : it->second(std::forward<Args>(args)...);
}

} // namespace

// ============================================================

std::shared_ptr<OpaqueConstruct> OpaqueConstructFactory::createOpaqueConstant32(
    const OpaqueStorage &target,
    uint32_t             value,
    const std::string &  algorithm,
    const std::string &  inputAlgorithm,
    bool                 contextualOpEnabled) {
  std::shared_ptr<RuntimeValueGenerator> rvg {
      callFactory(runtimevaluegen_factories, inputAlgorithm)};
  if (!rvg) {
    dbg_fmt("Warning: unknown opaque input generation algorithm: {}\n",
            inputAlgorithm);
    rvg.reset(AddRegRuntimeValueGenerator::create());
  }
  std::shared_ptr<OpaqueConstruct> oc {
      callFactory(constant_factories,
                  algorithm,
                  target,
                  std::move(value),
                  std::move(rvg),
                  std::move(contextualOpEnabled))};
  if (!oc) {
    dbg_fmt("Warning: unknown opaque predicate algorithm: {}\n", algorithm);
    oc.reset(MovConstant32::create(target, value, rvg, contextualOpEnabled));
  }
  return oc;
}

std::shared_ptr<OpaqueConstruct> OpaqueConstructFactory::createOpaqueConstant32(
    const OpaqueStorage &target,
    const std::string &  algorithm,
    const std::string &  inputAlgorithm,
    bool                 contextualOpEnabled) {
  uint32_t value = math::Random::rand();
  return createOpaqueConstant32(target,
                                value,
                                algorithm,
                                inputAlgorithm,
                                contextualOpEnabled);
}

std::shared_ptr<OpaqueConstruct>
OpaqueConstructFactory::createBranchingOpaqueConstant32(
    const OpaqueStorage &        target,
    const std::vector<uint32_t> &values,
    const std::string &          algorithm) {
  std::string random_algo   = OPAQUE_RANDOM_ALGORITHM_ADDREG,
              selector_algo = OPAQUE_SELECTOR_ALGORITHM_MOV;
  size_t pos                = algorithm.find("+");
  if (pos != std::string::npos) {
    random_algo   = algorithm.substr(0, pos);
    selector_algo = algorithm.substr(pos + 1);
  } else {
    dbg_fmt("Warning: unknown opaque predicate algorithm: {}\n", algorithm);
    // use default algorithm anyway
  }
  std::shared_ptr<OpaqueConstruct> randomOC, selectorOC;
  // random generator
  if (OpaqueConstruct *p = callFactory(random_factories, random_algo)) {
    randomOC.reset(p);
  } else {
    dbg_fmt("Warning: unknown random algorithm: {}\n", random_algo);
    // use default algorithm anyway
    randomOC.reset(AddRegRandomGeneratorOC::create());
  }
  // selector
  if (OpaqueConstruct *oc =
          callFactory(selector_factories, selector_algo, target, values)) {
    selectorOC.reset(oc);
  } else {
    dbg_fmt("Warning: unknown selector algorithm: {}\n", selector_algo);
    // use default algorithm anyway
    selectorOC.reset(MovRandomSelectorOC::create(target, values));
  }
  return compose(selectorOC, randomOC);
}

std::shared_ptr<OpaqueConstruct>
OpaqueConstructFactory::createBranchingOpaqueConstant32(
    const OpaqueStorage &target,
    size_t               n_choices,
    const std::string &  algorithm) {
  std::set<uint32_t> values;
  while (values.size() < n_choices) {
    values.insert(math::Random::rand());
  }
  std::vector<uint32_t> values_v(values.begin(), values.end());
  return createBranchingOpaqueConstant32(target, values_v, algorithm);
}

std::shared_ptr<OpaqueConstruct>
OpaqueConstructFactory::compose(std::shared_ptr<OpaqueConstruct> f,
                                std::shared_ptr<OpaqueConstruct> g) {
  return std::shared_ptr<OpaqueConstruct>(new ComposedOpaqueConstruct({f, g}));
}

std::shared_ptr<OpaqueConstruct> OpaqueConstructFactory::createValueAdjustor(
    const OpaqueStorage &        target,
    const std::vector<uint32_t> &inputvalues,
    const std::vector<uint32_t> &outputvalues) {
  return std::shared_ptr<OpaqueConstruct>(
      new ValueAdjustingOpaqueConstruct(target, inputvalues, outputvalues));
}

} // namespace ropf
