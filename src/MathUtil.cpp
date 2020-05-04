#include <cstdint>
#include <random>

#include "MathUtil.h"

namespace ropf::math {

namespace {

std::random_device rdev;
std::default_random_engine reng;

void egcd(uint64_t a, uint64_t m, uint64_t &g, uint64_t &x, uint64_t &y) {
  if (a == 0) {
    g = m;
    x = 0;
    y = 1;
  } else {
    egcd(m % a, a, g, y, x);
    x -= (m / a) * y;
  }
}

} // namespace

uint32_t Random::range32(uint32_t x, uint32_t y) {
  std::uniform_int_distribution<uint32_t> dist(x, y);
  return dist(reng);
}

uint64_t Random::range64(uint64_t x, uint64_t y) {
  std::uniform_int_distribution<uint64_t> dist(x, y);
  return dist(reng);
}

uint32_t Random::rand() { return reng(); }

bool Random::bit() { return range32(0, 1) != 0; }

std::default_random_engine Random::engine() { return reng; }

uint64_t modinv(uint64_t a, uint64_t m) {
  uint64_t g, x, y;
  egcd(a, m, g, x, y);
  return g == 1 ? x % m : 0;
}

namespace {
class PrimeNumberGeneratorImpl {
  friend class math::PrimeNumberGenerator;
  static uint32_t getRandom32() {
    return (Random::range32(0x40000000UL, 0x7fffffffUL) << 1) | 1;
  }
  static uint64_t getRandom64() {
    return (Random::range64(0x4000000000000000ULL, 0x7fffffffffffffffULL)
            << 1) |
           1;
  }

  static bool isPrime32(uint32_t n) {
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

  static bool isPrime64(uint64_t n) { // caution: very slow!
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
#if (defined(__GNUC__) || defined(__clang__)) && defined(__x86_64__)
    uint64_t rax, rdx;
    asm("mulq %3\n\t"
        "divq %4"
        : "=a"(rax), "=&d"(rdx)
        : "a"(a), "rm"(b), "rm"(modulus)
        : "cc");
    return rdx;
#elif defined(__SIZEOF_INT128__)
    return (__uint128_t)a * b % modulus;
#else
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
#endif
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
};
} // namespace

uint32_t PrimeNumberGenerator::getPrime32() {
  for (;;) {
    uint32_t v = PrimeNumberGeneratorImpl::getRandom32();
    if (PrimeNumberGeneratorImpl::isPrime32(v)) {
      return v;
    }
  }
}
uint64_t PrimeNumberGenerator::getPrime64() { // caution: very slow!
  for (;;) {
    uint64_t v = PrimeNumberGeneratorImpl::getRandom64();
    if (PrimeNumberGeneratorImpl::isPrime64(v)) {
      return v;
    }
  }
}

} // namespace ropf::math
