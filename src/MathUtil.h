#ifndef ROPF_MATHUTIL_H
#define ROPF_MATHUTIL_H

#include <cassert>
#include <cstdint>
#include <functional>
#include <random>
#include <vector>

namespace ropf::math {

class Random {
public:
  static uint32_t                   range32(uint32_t x, uint32_t y);
  static uint64_t                   range64(uint64_t x, uint64_t y);
  static uint32_t                   rand();
  static bool                       bit();
  static std::default_random_engine engine();
};

class PrimeNumberGenerator {
public:
  static uint32_t getPrime32();
  static uint64_t getPrime64();
};

uint64_t modinv(uint64_t a, uint64_t m);

class Matrix {
  unsigned int          M, N;
  std::vector<uint64_t> data;

public:
  class View {
    Matrix &     matrix;
    unsigned int offX, offY, M, N;

  public:
    View(Matrix &     matrix,
         unsigned int offX,
         unsigned int offY,
         unsigned int M,
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
    View &       operator=(const View &other) {
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
        uint64_t inv = modinv(at(0, 0), modulus);
        if (inv == 0) {
          return Matrix(0, 0); // failure
        }
        result.at(0, 0) = inv;
        return result;
      } else if (N == 2) {
        uint64_t det    = at(0, 0) * at(1, 1) - at(0, 1) * at(1, 0);
        uint64_t invdet = modinv(det, modulus);
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
        View   A    = view(0, 0, n1, n1);
        View   B    = view(n1, 0, n2, n1);
        View   C    = view(0, n1, n1, n2);
        View   D    = view(n1, n1, n2, n2);
        Matrix InvA = A.inverse_mod(modulus);
        if (InvA.width() == 0) {
          return Matrix(0, 0); // failure
        }
        Matrix F    = D - C * InvA * B;
        Matrix InvF = F.view().inverse_mod(modulus);
        if (InvF.width() == 0) {
          return Matrix(0, 0); // failure
        }
        Matrix G                    = InvA * B * InvF;
        Matrix H                    = C * InvA;
        result.view(0, 0, n1, n1)   = InvA + G * H;
        result.view(n1, 0, n2, n1)  = -G;
        result.view(0, n1, n1, n2)  = -InvF * H;
        result.view(n1, n1, n2, n2) = InvF;
        for (unsigned int i = 0; i < N; i++) {
          for (unsigned int j = 0; j < N; j++) {
            result.at(i, j) %= modulus;
          }
        }
        return result;
      }
    }
    View view(unsigned int offX,
              unsigned int offY,
              unsigned int m,
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
  View         view() { return View(*this, 0, 0, M, N); }
  View
  view(unsigned int offX, unsigned int offY, unsigned int m, unsigned int n) {
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

} // namespace ropf::math

#endif
