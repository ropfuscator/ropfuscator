#include "OpaqueConstruct.h"
#include "../X86TargetMachine.h"
#include "Debug.h"
#include "X86AssembleHelper.h"
#include <algorithm>
#include <random>

using namespace llvm;

namespace {

class Math {

  static std::random_device rdev;
  static std::default_random_engine reng;
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

public:
  static uint64_t modinv(uint64_t a, uint64_t m) {
    uint64_t g, x, y;
    egcd(a, m, g, x, y);
    return g == 1 ? x % m : 0;
  }
  static uint64_t randrange(uint64_t x, uint64_t y) {
    std::uniform_int_distribution<uint64_t> dist(x, y);
    return dist(reng);
  }
  static uint32_t randrange(uint32_t x, uint32_t y) {
    std::uniform_int_distribution<uint32_t> dist(x, y);
    return dist(reng);
  }
};

std::random_device Math::rdev;
std::default_random_engine Math::reng(Math::rdev());

class Matrix {
  unsigned int M, N;
  std::vector<uint64_t> data;

public:
  class View {
    Matrix &matrix;
    unsigned int offX, offY, M, N;

  public:
    View(Matrix &matrix, unsigned int offX, unsigned int offY, unsigned int M,
         unsigned int N)
        : matrix(matrix), offX(offX), offY(offY), M(M), N(N) {}
    uint64_t &at(unsigned int y, unsigned int x) {
      return matrix.at(y + offY, x + offX);
    }
    uint64_t at(unsigned int y, unsigned int x) const {
      return matrix.at(y + offY, x + offX);
    }
    uint64_t &operator[](const std::pair<unsigned int, unsigned int> &index) {
      return at(index.first, index.second);
    }
    uint64_t
    operator[](const std::pair<unsigned int, unsigned int> &index) const {
      return at(index.first, index.second);
    }
    unsigned int width() const { return M; }
    unsigned int height() const { return N; }
    View &operator=(const View &other) {
      assert(width() == other.width() && height() == other.height());
      for (unsigned int i = 0; i < height(); i++) {
        for (unsigned int j = 0; j < width(); j++) {
          at(i, j) = other.at(i, j);
        }
      }
      return *this;
    }
    View &operator=(const Matrix &other) {
      return *this = const_cast<Matrix &>(other).view();
    }
    template <typename UnaOp> Matrix op(UnaOp op) const {
      Matrix result(width(), height());
      for (unsigned int i = 0; i < height(); i++) {
        for (unsigned int j = 0; j < width(); j++) {
          result.at(i, j) = op(at(i, j));
        }
      }
      return result;
    }
    template <typename BinOp> Matrix op(const View &other, BinOp op) const {
      assert(width() == other.width() && height() == other.height());
      Matrix result(width(), height());
      for (unsigned int i = 0; i < height(); i++) {
        for (unsigned int j = 0; j < width(); j++) {
          result.at(i, j) = op(at(i, j), other.at(i, j));
        }
      }
      return result;
    }
    Matrix mult(const View &other) const {
      assert(width() == other.height());
      Matrix result(other.width(), height());
      for (unsigned int i = 0; i < height(); i++) {
        for (unsigned int j = 0; j < other.width(); j++) {
          for (unsigned int k = 0; k < width(); k++) {
            result.at(i, j) += at(i, k) * other.at(k, j);
          }
        }
      }
      return result;
    }
    Matrix operator*(const View &other) const { return mult(other); }
    Matrix operator*(const Matrix &other) const {
      return *this * const_cast<Matrix &>(other).view();
    }
    Matrix operator+(const View &other) const {
      return op(other, std::plus<uint64_t>());
    }
    Matrix operator+(const Matrix &other) const {
      return *this + const_cast<Matrix &>(other).view();
    }
    Matrix operator-(const View &other) const {
      return op(other, std::minus<uint64_t>());
    }
    Matrix operator-(const Matrix &other) const {
      return *this - const_cast<Matrix &>(other).view();
    }
    Matrix operator-() const { return op(std::negate<uint64_t>()); }
    Matrix inverse_mod(uint64_t modulus) const {
      assert(M == N);
      Matrix result(N, N);
      if (N == 0) {
        return result;
      } else if (N == 1) {
        uint64_t inv = Math::modinv(at(0, 0), modulus);
        if (inv == 0) {
          return Matrix(0, 0); // failure
        }
        result.at(0, 0) = inv;
        return result;
      } else if (N == 2) {
        uint64_t det = at(0, 0) * at(1, 1) - at(0, 1) * at(1, 0);
        uint64_t invdet = Math::modinv(det, modulus);
        if (invdet == 0) {
          return Matrix(0, 0); // failure
        }
        result.at(0, 0) = uint64_t(invdet * at(1, 1)) % modulus;
        result.at(0, 1) = uint64_t(invdet * -at(0, 1)) % modulus;
        result.at(1, 0) = uint64_t(invdet * -at(1, 0)) % modulus;
        result.at(1, 1) = uint64_t(invdet * at(0, 0)) % modulus;
        return result;
      } else {
        unsigned int n1 = (N + 1) / 2;
        unsigned int n2 = N - n1;
        // split matrix
        View A = view(0, 0, n1, n1);
        View B = view(n1, 0, n2, n1);
        View C = view(0, n1, n1, n2);
        View D = view(n1, n1, n2, n2);
        Matrix InvA = A.inverse_mod(modulus);
        if (InvA.width() == 0) {
          return Matrix(0, 0); // failure
        }
        Matrix F = D - C * InvA * B;
        Matrix InvF = F.view().inverse_mod(modulus);
        if (InvF.width() == 0) {
          return Matrix(0, 0); // failure
        }
        Matrix G = InvA * B * InvF;
        Matrix H = C * InvA;
        result.view(0, 0, n1, n1) = InvA + G * H;
        result.view(n1, 0, n2, n1) = -G;
        result.view(0, n1, n1, n2) = -InvF * H;
        result.view(n1, n1, n2, n2) = InvF;
        for (unsigned int i = 0; i < N; i++) {
          for (unsigned int j = 0; j < N; j++) {
            result.at(i, j) %= modulus;
          }
        }
        return result;
      }
    }
    View view(unsigned int offX, unsigned int offY, unsigned int m,
              unsigned int n) const {
      assert(offX >= 0 && offY >= 0 && m >= 0 && n >= 0 && m + offX <= M &&
             n + offY <= N);
      return View(matrix, this->offX + offX, this->offY + offY, m, n);
    }
  };
  Matrix(unsigned int M, unsigned int N) : M(M), N(N), data(M * N) {}
  uint64_t &at(unsigned int y, unsigned int x) {
    assert(x < M && y < N);
    return data[x + y * M];
  }
  uint64_t at(unsigned int y, unsigned int x) const {
    assert(x < M && y < N);
    return data[x + y * M];
  }
  unsigned int width() { return M; }
  unsigned int height() { return N; }
  View view() { return View(*this, 0, 0, M, N); }
  View view(unsigned int offX, unsigned int offY, unsigned int m,
            unsigned int n) {
    assert(offX >= 0 && offY >= 0 && m >= 0 && n >= 0 && m + offX <= M &&
           n + offY <= N);
    return View(*this, offX, offY, m, n);
  }
  Matrix operator+(const View &other) const {
    return const_cast<Matrix &>(*this).view() + other;
  }
  Matrix operator+(const Matrix &other) const {
    return const_cast<Matrix &>(*this).view() + other;
  }
  Matrix operator-(const View &other) const {
    return const_cast<Matrix &>(*this).view() - other;
  }
  Matrix operator-(const Matrix &other) const {
    return const_cast<Matrix &>(*this).view() - other;
  }
  Matrix operator*(const View &other) const {
    return const_cast<Matrix &>(*this).view() * other;
  }
  Matrix operator*(const Matrix &other) const {
    return const_cast<Matrix &>(*this).view() * other;
  }
  Matrix operator-() const { return -const_cast<Matrix &>(*this).view(); }
};

} // namespace

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
  if (algorithm == OPAQUE_CONSTANT_ALGORITHM_MOV) {
    return std::shared_ptr<OpaqueConstruct>(new MovConstant32(target, value));
  }
  if (algorithm == OPAQUE_CONSTANT_ALGORITHM_MULTCOMP) {
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

class NegativeStackRandomGeneratorOC : public OpaqueConstruct {
public:
  void compile(X86AssembleHelper &as, int stackOffset) const override {
    int offset = -4 * Math::randrange(2u, 32u);
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
  } else if (random_algo == "negativestack") {
    randomOC.reset(new NegativeStackRandomGeneratorOC());
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
        uint32_t mid =
            Math::randrange(inputvalues[pos + n2 - 1], inputvalues[pos + n2]);
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
    Matrix mat(N, N);
    for (uint32_t s = 0; s + N < 32 + 2; s++) {
      for (uint32_t i = 0; i < N; i++) {
        for (uint32_t j = 0; j < N - 1; j++) {
          mat.at(i, j) = inputvalues[pos + i] >> (s + j);
        }
        mat.at(i, N - 1) = 1;
      }
      Matrix invmat = mat.view().inverse_mod(0x100000000ULL);
      if (invmat.width() > 0) {
        Matrix output(1, N);
        for (uint32_t i = 0; i < N; i++) {
          output.at(i, 0) = outputvalues[pos + i];
        }
        Matrix p = invmat * output;
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

std::shared_ptr<OpaqueConstruct> OpaqueConstructFactory::createValueAdjustor(
    const OpaqueStorage &target, const std::vector<uint32_t> &inputvalues,
    const std::vector<uint32_t> &outputvalues) {
  return std::shared_ptr<OpaqueConstruct>(
      new ValueAdjustingOpaqueConstruct(target, inputvalues, outputvalues));
}
