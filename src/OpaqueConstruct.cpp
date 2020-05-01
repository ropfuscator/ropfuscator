#include "OpaqueConstruct.h"
#include "Debug.h"
#include "MathUtil.h"
#include "X86AssembleHelper.h"
#include "X86TargetMachine.h"
#include <algorithm>
#include <random>

namespace ropf {

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

namespace { // implementation details

// ============================================================
// basic opaque constant implementation

// stub (mock) implementation of opaque constant,
// which just moves the constant into the register/stack.
class MovConstant32 : public OpaqueConstant32 {
public:
  MovConstant32(const OpaqueStorage &target, uint32_t value)
      : target(target), value(value) {}

  static OpaqueConstruct *create(const OpaqueStorage &target, uint32_t value) {
    return new MovConstant32(target, value);
  }

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

class MultiplyCompareOpaquePredicate : public OpaqueConstruct {
public:
  MultiplyCompareOpaquePredicate(uint32_t input1, uint32_t input2,
                                 uint64_t compvalue)
      : compvalue(compvalue) {
    inputState.emplace_back(OpaqueStorage::EAX,
                            OpaqueValue::createConstant(input1));
    inputState.emplace_back(OpaqueStorage::EDX,
                            OpaqueValue::createConstant(input2));
    uint64_t multvalue = (uint64_t)input1 * input2;
    bool al = multvalue == compvalue;
    bool dl = (multvalue >> 32) == (compvalue >> 32);
    outputState.emplace_back(
        OpaqueStorage::EAX,
        OpaqueValue::createConstant((multvalue & 0xffffff00) + (al ? 1 : 0)));
    outputState.emplace_back(
        OpaqueStorage::EDX,
        OpaqueValue::createConstant(((multvalue >> 32) & 0xffffff00) +
                                    (dl ? 1 : 0)));
  }

  OpaqueState getInput() const override { return inputState; }
  OpaqueState getOutput() const override { return outputState; }

  void compile(X86AssembleHelper &as, int stackOffset) const override {
    as.mul(as.reg(X86::EDX)); // edx:eax = eax * edx
    as.cmp(as.reg(X86::EAX), as.imm(compvalue & 0xffffffff));
    as.sete(as.reg(X86::AL));
    as.cmp(as.reg(X86::EDX), as.imm((compvalue >> 32) & 0xffffffff));
    as.sete(as.reg(X86::DL));
    as.land8(as.reg(X86::AL), as.reg(X86::DL));
  }

  std::vector<llvm_reg_t> getClobberedRegs() const override {
    return {X86::EAX, X86::EDX, X86::EFLAGS};
  }

  static std::shared_ptr<MultiplyCompareOpaquePredicate>
  createRandom(bool output) {
    uint32_t x = math::PrimeNumberGenerator::getPrime32();
    uint32_t y = math::PrimeNumberGenerator::getPrime32();
    uint64_t z = (uint64_t)x * y;
    if (!output) {
      uint64_t v;
      do {
        v = (uint64_t)math::PrimeNumberGenerator::getPrime32() *
            math::PrimeNumberGenerator::getPrime32();
      } while (z == v);
      z = v;
    }
    return std::shared_ptr<MultiplyCompareOpaquePredicate>(
        new MultiplyCompareOpaquePredicate(x, y, z));
  }

private:
  uint64_t compvalue;
  OpaqueState inputState, outputState;
};

class MultiplyCompareBasedOpaqueConstant : public OpaqueConstant32 {
  std::vector<std::shared_ptr<MultiplyCompareOpaquePredicate>> predicates;
  const OpaqueStorage &target;
  uint32_t value;

public:
  MultiplyCompareBasedOpaqueConstant(const OpaqueStorage &target,
                                     uint32_t value)
      : target(target), value(value) {
    for (int i = 31; i >= 0; i--) {
      bool v = 1 & (value >> i);
      predicates.push_back(MultiplyCompareOpaquePredicate::createRandom(v));
    }
  }

  static OpaqueConstruct *create(const OpaqueStorage &target, uint32_t value) {
    return new MultiplyCompareBasedOpaqueConstant(target, value);
  }

  OpaqueStorage returnStorage() const override { return target; }

  uint32_t returnValue() const override { return value; }

  std::vector<llvm_reg_t> getClobberedRegs() const override {
    return {X86::EAX, X86::ECX, X86::EDX, X86::EFLAGS};
  }

  void compile(X86AssembleHelper &as, int stackOffset) const override {
    uint32_t out_eax = 0;
    uint32_t out_edx = 0;
    for (auto &p : predicates) {
      uint32_t in_eax = *p->getInput().findValue(OpaqueStorage::EAX);
      uint32_t in_edx = *p->getInput().findValue(OpaqueStorage::EDX);
      if (out_eax == 0) {
        as.mov(as.reg(X86::EAX), as.imm(in_eax));
        as.mov(as.reg(X86::EDX), as.imm(in_edx));
      } else {
        as.lxor(as.reg(X86::EAX), as.imm(in_eax ^ out_eax));
        as.lxor(as.reg(X86::EDX), as.imm(in_edx ^ out_edx));
      }
      p->compile(as, stackOffset);
      as.shl(as.reg(X86::ECX));
      as.lor8(as.reg(X86::CL), as.reg(X86::AL));
      out_eax = *p->getOutput().findValue(OpaqueStorage::EAX);
      out_edx = *p->getOutput().findValue(OpaqueStorage::EDX);
    }
    switch (target.type) {
    case OpaqueStorage::Type::REG:
      if (target.reg != X86::ECX)
        as.mov(as.reg(target.reg), as.reg(X86::ECX));
      break;
    case OpaqueStorage::Type::STACK:
      as.mov(as.mem(X86::ESP, target.stackOffset + stackOffset),
             as.reg(X86::ECX));
      break;
    }
  }
};

// ============================================================
// symbolic (random) value implementation

class RdtscRandomGeneratorOC : public OpaqueConstruct {
public:
  static OpaqueConstruct *create() { return new RdtscRandomGeneratorOC(); }
  void compile(X86AssembleHelper &as, int stackOffset) const override {
    as.rdtsc();
  }
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
  void compile(X86AssembleHelper &as, int stackOffset) const override {
    int offset = -4 * math::Random::range32(2u, 32u);
    as.mov(as.reg(X86::EAX), as.mem(X86::ESP, offset));
  }
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
  void compile(X86AssembleHelper &as, int stackOffset) const override {
    for (auto reg : {X86::EBX, X86::ECX, X86::EDX, X86::ESI, X86::EDI})
      as.add(as.reg(X86::EAX), as.reg(reg));
  }
  OpaqueState getInput() const override { return {}; }
  OpaqueState getOutput() const override {
    return {{OpaqueStorage::EAX, OpaqueValue::createAny()}};
  }
  std::vector<llvm_reg_t> getClobberedRegs() const override {
    return {X86::EAX, X86::EFLAGS};
  }
};

// ============================================================
// selector implementation
// selector will select a value from a set of values, based on random input

class MovRandomSelectorOC : public OpaqueConstruct {
public:
  MovRandomSelectorOC(const OpaqueStorage &target,
                      const std::vector<uint32_t> &values)
      : target(target), values(values) {
    std::random_shuffle(this->values.begin(), this->values.end());
  }
  static OpaqueConstruct *create(const OpaqueStorage &target,
                                 const std::vector<uint32_t> &values) {
    return new MovRandomSelectorOC(target, values);
  }

  void compile(X86AssembleHelper &as, int stackOffset) const override {
    unsigned int targetreg =
        target.type == OpaqueStorage::Type::REG ? target.reg : X86::EAX;
    unsigned int tmpreg = target.reg == X86::EAX ? X86::EDX : X86::EAX;
    auto endLabel = as.label();
    bool labelUsed = false;
    compileAux(as, as.reg(targetreg), as.reg(tmpreg), endLabel, 0,
               values.size(), 1, labelUsed);
    if (labelUsed)
      as.putLabel(endLabel);
    if (target.type == OpaqueStorage::Type::STACK) {
      as.mov(as.mem(X86::ESP, target.stackOffset + stackOffset),
             as.reg(targetreg));
    }
  }

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
  OpaqueStorage target;
  std::vector<uint32_t> values;

  void compileAux(X86AssembleHelper &as, const X86AssembleHelper::Reg &target,
                  const X86AssembleHelper::Reg &tmpreg,
                  const X86AssembleHelper::Label &endLabel, uint32_t m,
                  uint32_t n, uint32_t flag, bool &labelUsed) const {
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
      int n2 = n / 2;
      auto label = as.label();
      as.test(as.reg(X86::EAX), as.imm(flag));
      as.je(label);
      compileAux(as, target, tmpreg, endLabel, m, n2, flag << 1, labelUsed);
      as.putLabel(label);
      compileAux(as, target, tmpreg, endLabel, m + n2, n - n2, flag << 1,
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

  void compile(X86AssembleHelper &as, int stackOffset) const override {
    for (auto func : functions) {
      func->compile(as, stackOffset);
    }
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
  ValueAdjustingOpaqueConstruct(const OpaqueStorage &target,
                                const std::vector<uint32_t> &inputvalues,
                                const std::vector<uint32_t> &outputvalues)
      : target(target), inputvalues(inputvalues), outputvalues(outputvalues) {
    assert(inputvalues.size() == outputvalues.size());
    std::sort(this->inputvalues.begin(), this->inputvalues.end());
    std::random_shuffle(this->outputvalues.begin(), this->outputvalues.end());
  }

  void compile(X86AssembleHelper &as, int stackOffset) const override {
    auto endLabel = as.label();
    bool endLabelUsed = false;
    switch (target.type) {
    case OpaqueStorage::Type::REG:
      compileAux(as, 0, inputvalues.size(), target.reg, endLabelUsed, endLabel);
      if (endLabelUsed)
        as.putLabel(endLabel);
      break;
    case OpaqueStorage::Type::STACK:
      auto stackref = as.mem(X86::ESP, target.stackOffset + stackOffset);
      as.mov(as.reg(X86::EAX), stackref);
      compileAux(as, 0, inputvalues.size(), X86::EAX, endLabelUsed, endLabel);
      if (endLabelUsed)
        as.putLabel(endLabel);
      as.mov(stackref, as.reg(X86::EAX));
      break;
    }
  }

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
    case 2:
      return {X86::EAX, X86::EDX, X86::EFLAGS};
    default:
      return {X86::EAX, X86::ECX, X86::EDX, X86::EFLAGS};
    }
  }

private:
  OpaqueStorage target;
  std::vector<uint32_t> inputvalues;
  std::vector<uint32_t> outputvalues;

  void compileAux(X86AssembleHelper &as, uint32_t pos, uint32_t N,
                  unsigned int targetreg, bool &endLabelUsed,
                  const X86AssembleHelper::Label &endLabel) const {
    if (N == 1) {
      uint32_t xorval = inputvalues[pos] ^ outputvalues[pos];
      as.lxor(as.reg(targetreg), as.imm(xorval));
    } else {
      std::vector<uint32_t> params;
      uint32_t shift;
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
        uint32_t mid = math::Random::range32(inputvalues[pos + n2 - 1],
                                             inputvalues[pos + n2]);
        auto label1 = as.label();
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
  bool computeParams(uint32_t pos, uint32_t N, std::vector<uint32_t> &params,
                     uint32_t &shift) const {
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

template <typename... Args> using oc_factory = OpaqueConstruct *(*)(Args...);

std::map<std::string, oc_factory<const OpaqueStorage &, uint32_t>>
    constant_factories = {
        {OPAQUE_CONSTANT_ALGORITHM_MOV, MovConstant32::create},
        {OPAQUE_CONSTANT_ALGORITHM_MULTCOMP,
         MultiplyCompareBasedOpaqueConstant::create},
};

std::map<std::string, oc_factory<>> random_factories = {
    {OPAQUE_RANDOM_ALGORITHM_ADDREG, AddRegRandomGeneratorOC::create},
    {OPAQUE_RANDOM_ALGORITHM_RDTSC, RdtscRandomGeneratorOC::create},
    {OPAQUE_RANDOM_ALGORITHM_NEGSTK, NegativeStackRandomGeneratorOC::create},
};

std::map<std::string,
         oc_factory<const OpaqueStorage &, const std::vector<uint32_t> &>>
    selector_factories = {
        {OPAQUE_SELECTOR_ALGORITHM_MOV, MovRandomSelectorOC::create},
};

template <typename... Args>
OpaqueConstruct *
call_factory(const std::map<std::string, oc_factory<Args...>> &factories,
             const std::string &key, Args &&... args) {
  auto it = factories.find(key);
  return it == factories.end() ? nullptr
                               : it->second(std::forward<Args>(args)...);
}

} // namespace

// ============================================================

std::shared_ptr<OpaqueConstruct> OpaqueConstructFactory::createOpaqueConstant32(
    const OpaqueStorage &target, uint32_t value, const std::string &algorithm) {
  if (OpaqueConstruct *oc = call_factory(constant_factories, algorithm, target,
                                         std::move(value))) {
    return std::shared_ptr<OpaqueConstruct>(oc);
  } else {
    dbg_fmt("Warning: unknown opaque predicate algorithm: {}\n", algorithm);
    return std::shared_ptr<OpaqueConstruct>(
        MovConstant32::create(target, value));
  }
}

std::shared_ptr<OpaqueConstruct>
OpaqueConstructFactory::createOpaqueConstant32(const OpaqueStorage &target,
                                               const std::string &algorithm) {
  uint32_t value = math::Random::rand();
  return createOpaqueConstant32(target, value, algorithm);
}

std::shared_ptr<OpaqueConstruct>
OpaqueConstructFactory::createBranchingOpaqueConstant32(
    const OpaqueStorage &target, const std::vector<uint32_t> &values,
    const std::string &algorithm) {
  std::string random_algo = OPAQUE_RANDOM_ALGORITHM_ADDREG,
              selector_algo = OPAQUE_SELECTOR_ALGORITHM_MOV;
  size_t pos = algorithm.find("+");
  if (pos != std::string::npos) {
    random_algo = algorithm.substr(0, pos);
    selector_algo = algorithm.substr(pos + 1);
  } else {
    dbg_fmt("Warning: unknown opaque predicate algorithm: {}\n", algorithm);
    // use default algorithm anyway
  }
  std::shared_ptr<OpaqueConstruct> randomOC, selectorOC;
  // random generator
  if (OpaqueConstruct *p = call_factory(random_factories, random_algo)) {
    randomOC.reset(p);
  } else {
    dbg_fmt("Warning: unknown random algorithm: {}\n", random_algo);
    // use default algorithm anyway
    randomOC.reset(AddRegRandomGeneratorOC::create());
  }
  // selector
  if (OpaqueConstruct *oc =
          call_factory(selector_factories, selector_algo, target, values)) {
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
    const OpaqueStorage &target, size_t n_choices,
    const std::string &algorithm) {
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
    const OpaqueStorage &target, const std::vector<uint32_t> &inputvalues,
    const std::vector<uint32_t> &outputvalues) {
  return std::shared_ptr<OpaqueConstruct>(
      new ValueAdjustingOpaqueConstruct(target, inputvalues, outputvalues));
}

} // namespace ropf
