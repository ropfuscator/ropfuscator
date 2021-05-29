#include <cstdint>
#include <random>

#include "MathUtil.h"

namespace ropf::math {

namespace {

std::random_device         rdev;
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

template <typename UIntT> struct Divisor {};

template <> struct Divisor<uint32_t> {
  uint32_t d0;
#ifdef __SIZEOF_INT128__
  uint64_t d1;
  Divisor(uint64_t dividend) {
    d0 = dividend;
    d1 = 1 + ((uint64_t)-1) / dividend;
  }
#else
  uint32_t d1, d2;
  Divisor(uint64_t dividend) {
    d0         = dividend;
    uint64_t d = 1 + ((uint64_t)-1) / dividend;
    d0         = d >> 32;
    d1         = d;
  }
#endif
       operator uint32_t() const { return d0; }
  void divmod(uint64_t x, uint64_t &quo, uint64_t &rem) const {
    uint64_t result;
#ifdef __SIZEOF_INT128__
    result = ((__uint128_t)d1 * x) >> 64;
#else
    if (x >> 32) {
      uint64_t x1 = x >> 32;
      uint64_t x2 = (uint32_t)x;
      // (x1x2 * d1d2) >> 64
      // x1d1 + (x1d2 + x2d1) >> 32 + x2d2 >> 64
      int      overflow = 0;
      uint64_t v0, v = (x2 * d2) >> 32;
      v0 = x2 * d1;
      v += v0;
      if (v < v0)
        overflow++;
      v0 = x1 * d2;
      v += v0;
      if (v < v0)
        overflow++;
      v >>= 32;
      result = x1 * d1 + v + overflow;
    } else {
      uint64_t v2 = x * d1;
      v2 += (v1 >> 32);
      result = v2 >> 32;
    }
#endif
    uint64_t r = x - result * d0;
    while (r >> 32) {
      r += d0;
      result--;
    }
    while (r >= d0) {
      r -= d0;
      result++;
    }
    quo = result;
    rem = r;
  }
};

uint64_t operator/(uint64_t x, const Divisor<uint32_t> &d) {
  uint64_t quo, rem;
  d.divmod(x, quo, rem);
  return quo;
}
uint64_t operator%(uint64_t x, const Divisor<uint32_t> &d) {
  uint64_t quo, rem;
  d.divmod(x, quo, rem);
  return rem;
}

#ifdef __SIZEOF_INT128__

template <> struct Divisor<uint64_t> {
  uint64_t d0, d1, d2;
  Divisor(uint64_t dividend) {
    // assert(dividend > 1);
    d0            = dividend;
    __uint128_t d = 1 + ((__uint128_t)-1) / dividend;
    d1            = d >> 64;
    d2            = d;
  }
       operator uint64_t() const { return d0; }
  void divmod(__uint128_t x, __uint128_t &quo, __uint128_t &rem) const {
    __uint128_t result;
    if (x >> 64) {
      __uint128_t x1 = x >> 64;
      __uint128_t x2 = (uint64_t)x;
      // (x1x2 * d1d2) >> 128
      // x1d1 + (x1d2 + x2d1) >> 64 + x2d2 >> 128
      int         overflow = 0;
      __uint128_t v0, v = (x2 * d2) >> 64;
      v0 = x2 * d1;
      v += v0;
      if (v < v0)
        overflow++;
      v0 = x1 * d2;
      v += v0;
      if (v < v0)
        overflow++;
      v >>= 64;
      result = x1 * d1 + v + overflow;
    } else {
      __uint128_t v1 = x * d2;
      __uint128_t v2 = x * d1;
      v2 += (v1 >> 64);
      result = v2 >> 64;
    }
    __uint128_t r = x - result * d0;
    while (r >> 64) {
      r += d0;
      result--;
    }
    while (r >= d0) {
      r -= d0;
      result++;
    }
    quo = result;
    rem = r;
  }
};

__uint128_t operator/(__uint128_t x, const Divisor<uint64_t> &d) {
  __uint128_t quo, rem;
  d.divmod(x, quo, rem);
  return quo;
}
__uint128_t operator%(__uint128_t x, const Divisor<uint64_t> &d) {
  __uint128_t quo, rem;
  d.divmod(x, quo, rem);
  return rem;
}

#else

template <> struct Divisor<uint64_t> {
  uint64_t d0;
  Divisor(uint64_t dividend) { d0 = dividend; }
  operator uint64_t() const { return d0; }
};

#endif

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

  template <typename ModT>
  static uint32_t mulmod(uint32_t a, uint32_t b, const ModT &modulus) {
    return (uint64_t)a * b % modulus;
  }

  template <typename ModT>
  static uint64_t mulmod(uint64_t a, uint64_t b, const ModT &modulus) {
#if defined(__SIZEOF_INT128__)
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

  template <typename UIntT, typename ModT>
  static UIntT modpow(UIntT base, UIntT exponent, const ModT &modulus) {
    UIntT n = 1;
    for (; exponent; exponent >>= 1) {
      if (exponent & 1) {
        n = mulmod(n, base, modulus);
      }
      base = mulmod(base, base, modulus);
    }
    return n;
  }

  static constexpr const uint16_t prime_base_32[256] = {
#include "detail/primetestdata32.h"
  };
  static constexpr const uint16_t prime_base_64[16384] = {
#include "detail/primetestdata64.h"
  };
  static constexpr const uint16_t prime_base_64_2[8] =
      {15, 135, 13, 60, 15, 117, 65, 29};

  template <typename UIntT, typename ModT>
  static bool
  millerRabinTest(UIntT n, UIntT d, int r, UIntT base, const ModT &n_mod) {
    UIntT x = modpow(base, d, n_mod);
    if (x == 1 || x == n - 1) {
      return true;
    }
    for (int j = 0; j < r; j++) {
      x = mulmod(x, x, n_mod);
      if (x == n - 1) {
        return true;
      }
    }
    return false;
  }

  template <typename UIntT> static bool isPrime(UIntT n) {
    if (n < 40) {
      for (UIntT x : {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37}) {
        if (n == x) {
          return true;
        }
      }
      return false;
    }
    if (n % 2 == 0 || n % 3 == 0) {
      return false;
    }
    for (UIntT x : {5, 7, 11, 13, 17, 19, 23, 29, 31}) {
      if (n % x == 0) {
        return false;
      }
    }
    if (n < 37 * 37) {
      return true;
    }
    // Miller-Rabin test
    UIntT d = n - 1;
    int   r = 0;
    while ((d & 0x1) == 0) {
      d >>= 1;
      r++;
    }
    Divisor<UIntT> divisor(n);
    if constexpr (sizeof(UIntT) <= 4) {
      // < 2**32
      uint32_t hash = (uint32_t)n * 0xad625b89u;
      UIntT    base = prime_base_32[hash >> 24];
      return millerRabinTest(n, d, r, base, divisor);
    } else {
      if (n >> 32) {
        // >= 2**32
        UIntT base = 2;
        if (!millerRabinTest(n, d, r, base, divisor)) {
          return false;
        }
        uint32_t hash = (uint32_t)n * 0xad625b89u;
        base          = prime_base_64[hash >> 18];
        if (!millerRabinTest(n, d, r, base, divisor)) {
          return false;
        }
        if (n >> 49) {
          base = prime_base_64_2[base >> 13];
          if (!millerRabinTest(n, d, r, base, divisor)) {
            return false;
          }
        }
        return true;
      } else {
        // < 2**32
        uint32_t hash = (uint32_t)n * 0xad625b89u;
        UIntT    base = prime_base_32[hash >> 24];
        return millerRabinTest(n, d, r, base, divisor);
      }
      return true;
    }
  }
};
} // namespace

uint32_t PrimeNumberGenerator::getPrime32() {
  for (;;) {
    uint32_t v = PrimeNumberGeneratorImpl::getRandom32();
    if (PrimeNumberGeneratorImpl::isPrime<uint32_t>(v)) {
      return v;
    }
  }
}
uint64_t PrimeNumberGenerator::getPrime64() { // caution: very slow!
  for (;;) {
    uint64_t v = PrimeNumberGeneratorImpl::getRandom64();
    if (PrimeNumberGeneratorImpl::isPrime<uint64_t>(v)) {
      return v;
    }
  }
}

} // namespace ropf::math
