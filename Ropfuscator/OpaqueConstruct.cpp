#include "OpaqueConstruct.h"
#include "../X86TargetMachine.h"
#include "Debug.h"
#include "X86AssembleHelper.h"
#include <algorithm>
#include <random>

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

template <typename RandomGenerator> class PrimeNumberGenerator {
public:
  RandomGenerator rng;
  std::uniform_int_distribution<uint32_t> dist32;
  std::uniform_int_distribution<uint64_t> dist64;

  uint32_t getRandom32() { return dist32(rng); }
  uint64_t getRandom64() { return dist64(rng); }

  bool isPrime32(uint32_t n) {
    if (n < 40) {
      for (uint32_t x : {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37}) {
        if (n == x) {
          return true;
        }
      }
      return false;
    }
    if (n % 2 == 0 || n % 3 == 0) {
      return false;
    }
    for (uint32_t x : {5, 7, 11, 13, 17, 19, 23, 29, 31}) {
      if (n % x == 0) {
        return false;
      }
    }
    // Miller-Rabin test
    uint32_t d = n - 1;
    int r = 0;
    while (d % 2 == 0) {
      d >>= 1;
      r++;
    }
    for (uint32_t a : {2, 7, 61}) {
      uint32_t x = modpow32(a, d, n);
      if (x == 1 || x == n - 1) {
        goto CONTINUE;
      }
      for (int j = 0; j < r; j++) {
        x = (uint32_t)((uint64_t)x * x % n);
        if (x == n - 1) {
          goto CONTINUE;
        }
      }
      return false;
    CONTINUE:;
    }
    return true;
  }

  bool isPrime64(uint64_t n) { // caution: very slow!
    if (n < 40) {
      for (uint32_t x : {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37}) {
        if (n == x) {
          return true;
        }
      }
      return false;
    }
    if (n % 2 == 0 || n % 3 == 0) {
      return false;
    }
    for (uint32_t x : {5, 7, 11, 13, 17, 19, 23, 29, 31}) {
      if (n % x == 0) {
        return false;
      }
    }
    // Miller-Rabin test
    uint64_t d = n - 1;
    int r = 0;
    while (d % 2 == 0) {
      d >>= 1;
      r++;
    }
    for (uint64_t a : {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37}) {
      uint64_t x = modpow64(a, d, n);
      if (x == 1 || x == n - 1) {
        goto CONTINUE;
      }
      for (int j = 0; j < r; j++) {
        x = mulmod64(x, x, n);
        if (x == n - 1) {
          goto CONTINUE;
        }
      }
      return false;
    CONTINUE:;
    }
    return true;
  }

  static uint32_t modpow32(uint32_t base, uint32_t exponent, uint32_t modulus) {
    uint64_t n = 1;
    for (uint32_t mask = 0x80000000; mask != 0; mask >>= 1) {
      n = n * n % modulus;
      if (exponent & mask) {
        n = n * base % modulus;
      }
    }
    return static_cast<uint32_t>(n);
  }

  static uint64_t mulmod64(uint64_t a, uint64_t b, uint64_t modulus) {
    if (a == 1)
      return b % modulus;
    if (b == 1)
      return a % modulus;
    if (a < 0x100000000ULL && b < 0x100000000ULL) {
      return a * b % modulus;
    }
    // n < modulus
    uint64_t result = 0;
    uint64_t n = b;
    for (uint64_t x = a; x > 0; x >>= 1) {
      if (x % 2 != 0) {
        // result = (result + n) % modulus;
        result += (n >= modulus - result) ? n - modulus : n;
      }
      // n = n * 2 % modulus;
      n += (n >= modulus - n) ? n - modulus : n;
    }
    return result;
  }

  static uint64_t modpow64(uint64_t base, uint64_t exponent, uint64_t modulus) {
    uint64_t n = 1;
    if (base >= modulus) {
      base %= modulus;
    }
    for (uint64_t mask = 0x8000000000000000ULL; mask != 0; mask >>= 1) {
      n = mulmod64(n, n, modulus);
      if (exponent & mask) {
        n = mulmod64(n, base, modulus);
      }
    }
    return n;
  }

public:
  PrimeNumberGenerator(RandomGenerator rng)
      : rng(rng), dist32(0x80000000, 0xffffffff),
        dist64(0x8000000000000000ULL, 0xffffffffffffffffULL) {}
  PrimeNumberGenerator()
      : rng(), dist32(0x80000000, 0xffffffff),
        dist64(0x8000000000000000ULL, 0xffffffffffffffffULL) {}
  uint32_t getPrime32() {
    for (;;) {
      uint32_t v = getRandom32();
      if (isPrime32(v)) {
        return v;
      }
    }
  }
  uint64_t getPrime64() { // caution: very slow!
    for (;;) {
      uint64_t v = getRandom64();
      if (isPrime64(v)) {
        return v;
      }
    }
  }
};

class MultiplyCompareOpaquePredicate : public OpaqueConstruct {
public:
  MultiplyCompareOpaquePredicate(uint32_t input1, uint32_t input2,
                                 uint64_t compvalue)
      : input1(input1), input2(input2), compvalue(compvalue) {
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
    uint32_t x = rng.getPrime32();
    uint32_t y = rng.getPrime32();
    uint64_t z = (uint64_t)x * y;
    if (!output) {
      uint64_t v;
      do {
        v = (uint64_t)rng.getPrime32() * rng.getPrime32();
      } while (z == v);
      z = v;
    }
    return std::shared_ptr<MultiplyCompareOpaquePredicate>(
        new MultiplyCompareOpaquePredicate(x, y, z));
  }

private:
  static PrimeNumberGenerator<std::default_random_engine> rng;

  uint32_t input1, input2;
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

static std::default_random_engine rand_device;
PrimeNumberGenerator<std::default_random_engine>
    MultiplyCompareOpaquePredicate::rng;

std::shared_ptr<OpaqueConstruct> OpaqueConstructFactory::createOpaqueConstant32(
    const OpaqueStorage &target, uint32_t value, const std::string &algorithm) {
  if (algorithm == "mov") {
    return std::shared_ptr<OpaqueConstruct>(new MovConstant32(target, value));
  }
  if (algorithm == "multcomp") {
    return std::shared_ptr<OpaqueConstruct>(
        new MultiplyCompareBasedOpaqueConstant(target, value));
  }

  return std::shared_ptr<OpaqueConstruct>();
}

class RdtscRandomGeneratorOC : public OpaqueConstruct {
public:
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

class AddRegRandomGeneratorOC : public OpaqueConstruct {
public:
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

class MovRandomSelectorOC : public OpaqueConstruct {
public:
  MovRandomSelectorOC(const OpaqueStorage &target,
                      const std::vector<uint32_t> &values)
      : target(target), values(values) {
    std::random_shuffle(this->values.begin(), this->values.end());
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
                  const X86AssembleHelper::ExternalLabel &endLabel, int m,
                  int n, uint32_t flag, bool &labelUsed) const {
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

std::shared_ptr<OpaqueConstruct>
OpaqueConstructFactory::createOpaqueConstant32(const OpaqueStorage &target,
                                               const std::string &algorithm) {
  uint32_t value = rand_device();
  return createOpaqueConstant32(target, value, algorithm);
}

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

std::shared_ptr<OpaqueConstruct>
OpaqueConstructFactory::compose(std::shared_ptr<OpaqueConstruct> f,
                                std::shared_ptr<OpaqueConstruct> g) {
  uint32_t value = rand_device();
  return std::shared_ptr<OpaqueConstruct>(new ComposedOpaqueConstruct({f, g}));
}

std::shared_ptr<OpaqueConstruct>
OpaqueConstructFactory::createBranchingOpaqueConstant32(
    const OpaqueStorage &target, const std::vector<uint32_t> &values,
    const std::string &algorithm) {
  std::string random_algo = "addreg", selector_algo = "mov";
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
  if (random_algo == "addreg") {
    randomOC.reset(new AddRegRandomGeneratorOC());
  } else if (random_algo == "rdtsc") {
    randomOC.reset(new RdtscRandomGeneratorOC());
  } else {
    dbg_fmt("Warning: unknown random algorithm: {}\n", random_algo);
    // use default algorithm anyway
    randomOC.reset(new AddRegRandomGeneratorOC());
  }
  // selector
  if (selector_algo == "mov") {
    selectorOC.reset(new MovRandomSelectorOC(target, values));
  } else {
    dbg_fmt("Warning: unknown selector algorithm: {}\n", selector_algo);
    // use default algorithm anyway
    selectorOC.reset(new MovRandomSelectorOC(target, values));
  }
  return compose(selectorOC, randomOC);
}

std::shared_ptr<OpaqueConstruct>
OpaqueConstructFactory::createBranchingOpaqueConstant32(
    const OpaqueStorage &target, size_t n_choices,
    const std::string &algorithm) {
  std::set<uint32_t> values;
  while (values.size() < n_choices) {
    values.insert(rand_device());
  }
  std::vector<uint32_t> values_v(values.begin(), values.end());
  return createBranchingOpaqueConstant32(target, values_v, algorithm);
}

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
  }

  void compile(X86AssembleHelper &as, int stackOffset) const override {
    if (inputvalues.size() == 1) {
      uint32_t xorval = inputvalues[0] ^ outputvalues[0];
      switch (target.type) {
      case OpaqueStorage::Type::REG:
        as.lxor(as.reg(target.reg), as.imm(xorval));
        break;
      case OpaqueStorage::Type::STACK:
        auto stackref = as.mem(X86::ESP, target.stackOffset + stackOffset);
        as.lxor(stackref, as.imm(xorval));
        break;
      }
    } else if (inputvalues.size() == 2) {
      uint32_t x1 = inputvalues[0];
      uint32_t x2 = inputvalues[1];
      uint32_t y1 = outputvalues[0];
      uint32_t y2 = outputvalues[1];
      if (x1 == x2)
        abort();
      uint32_t shift = 0;
      // while x2>>shift - x1>>shift is even, increase shift amount
      // since even numbers do not have a modular inverse (mod 2^32)
      while (((x2 >> shift) - (x1 >> shift)) % 2 == 0) {
        shift++;
      }
      // assert(((x2 >> shift) - (x1 >> shift)) % 2 != 0);
      // now x2>>shift - x1>>shift is odd, and has a modular inverse
      uint32_t v = modinv((x2 >> shift) - (x1 >> shift), 0x100000000ULL);
      v *= y2 - y1;
      uint32_t u = y1 - (x1 >> shift) * v;
      // assert((x1 >> shift) * v + u == y1 && (x2 >> shift) * v + u == y2);
      switch (target.type) {
      case OpaqueStorage::Type::REG:
        if (shift > 0)
          as.shr(as.reg(target.reg), as.imm(shift));
        as.imul(as.reg(target.reg), as.imm(v));
        as.add(as.reg(target.reg), as.imm(u));
        break;
      case OpaqueStorage::Type::STACK:
        auto stackref = as.mem(X86::ESP, target.stackOffset + stackOffset);
        as.mov(as.reg(X86::EAX), stackref);
        if (shift > 0)
          as.shr(as.reg(X86::EAX), as.imm(shift));
        as.imul(as.reg(X86::EAX), as.imm(v));
        as.add(as.reg(X86::EAX), as.imm(u));
        as.mov(stackref, as.reg(X86::EAX));
        break;
      }
    } else {
      dbg_fmt("Not implemented: adjusting values of n>2\n");
      exit(1);
    }
  }

  OpaqueState getInput() const override {
    return {{target, OpaqueValue::createConstant(inputvalues)}};
  }
  OpaqueState getOutput() const override {
    return {{target, OpaqueValue::createConstant(outputvalues)}};
  }
  std::vector<llvm_reg_t> getClobberedRegs() const override {
    return {X86::EAX, X86::EDX, X86::EFLAGS};
  }

private:
  OpaqueStorage target;
  std::vector<uint32_t> inputvalues;
  std::vector<uint32_t> outputvalues;

  static void egcd(uint64_t a, uint64_t m, uint64_t &g, uint64_t &x,
                   uint64_t &y) {
    if (a == 0) {
      g = m;
      x = 0;
      y = 1;
    } else {
      egcd(m % a, a, g, y, x);
      x -= (m / a) * y;
    }
  }
  static uint64_t modinv(uint64_t a, uint64_t m) {
    uint64_t g, x, y;
    egcd(a, m, g, x, y);
    return g == 1 ? x % m : 0;
  }
};

std::shared_ptr<OpaqueConstruct> OpaqueConstructFactory::createValueAdjustor(
    const OpaqueStorage &target, const std::vector<uint32_t> &inputvalues,
    const std::vector<uint32_t> &outputvalues) {
  return std::shared_ptr<OpaqueConstruct>(
      new ValueAdjustingOpaqueConstruct(target, inputvalues, outputvalues));
}
