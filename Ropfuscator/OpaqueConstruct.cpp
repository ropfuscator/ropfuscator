#include "OpaqueConstruct.h"
#include "../X86TargetMachine.h"
#include "X86AssembleHelper.h"
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

std::shared_ptr<OpaqueConstruct>
OpaqueConstructFactory::createOpaqueConstant32(const OpaqueStorage &target,
                                               const std::string &algorithm) {
  uint32_t value = rand_device();
  return createOpaqueConstant32(target, value, algorithm);
}
