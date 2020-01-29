#ifndef OPAQUECONSTRUCT_H
#define OPAQUECONSTRUCT_H

#include <cstdint>
#include <memory>

#include "llvm/CodeGen/MachineBasicBlock.h"
#include <capstone/capstone.h>

/// Represents input/output register (or stack) location of opaque constructs.
struct OpaqueStorage {
  /// location type
  enum class Type {
    /// represents register.
    REG,
    /// represents stack location with offset.
    STACK
  };
  Type type;
  union {
    /// when type == REG, contains the register (capstone)
    x86_reg reg;
    /// when type == STACK, contains the stack offset
    int stackOffset;
  };
};

// forward declaration
struct OpaqueValue;

/// Opaque predicate input/output condition
typedef std::vector<std::pair<OpaqueStorage, OpaqueValue>> OpaqueState;

/// Abstract value for opaque predicate input/output
struct OpaqueValue {
  // With contextual opaque predicates, compute output from input
  using compute_fun_type = OpaqueValue (*)(const OpaqueState &);
  /// Represents value type.
  enum class Type {
    /// when used in input, "input value should be specific value"
    /// when used in output, "output value is constant"
    CONSTANT,
    /// when used in input, "any value is accepted";
    /// when used in output, "may be any value"
    ANY,
    /// used only in output. Output is computed from input
    CONTEXTUAL
  };
  const Type type;
  union {
    /// when type == CONSTANT, contains the constant value
    uint64_t value;
    /// when type == CONTEXTUAL, contains the compute function
    compute_fun_type compute;
  };
  /// create a value with type == ANY.
  static OpaqueValue createAny() { return OpaqueValue(Type::ANY, 0, nullptr); }
  /// create a value with type == CONSTANT.
  /// @param value the constant value
  static OpaqueValue createConstant(uint64_t value) {
    return OpaqueValue(Type::CONSTANT, value, nullptr);
  }
  /// create a value with type == CONTEXTUAL.
  /// @param compute pointer to a function which computes the value from input
  static OpaqueValue createContextual(compute_fun_type compute) {
    return OpaqueValue(Type::CONTEXTUAL, 0, compute);
  }

private:
  OpaqueValue(Type type, uint64_t value, compute_fun_type compute)
      : type(type) {
    if (type == Type::CONSTANT)
      this->value = value;
    if (type == Type::CONTEXTUAL)
      this->compute = compute;
  }
};

/// Opaque construct (opaque predicate, opaque constant) API.
class OpaqueConstruct {
public:
  /// get input constraints.
  virtual OpaqueState getInput() const = 0;
  /// get output constraints.
  virtual OpaqueState getOutput() const = 0;
  /// get clobbered registers, including flag registers.
  /// it is the responsibility of invoker to save the registers.
  virtual std::vector<x86_reg> getClobberedRegs() const = 0;
  /// generate x86 code which implements the opaque construct.
  /// @param block the basic block into which the code is generated
  /// @param position the insertion point of the code
  virtual void compile(llvm::MachineBasicBlock &block,
                       llvm::MachineBasicBlock::iterator position) const = 0;
  /// virtual destructor
  virtual ~OpaqueConstruct();
};

/// Factory methods for opaque constructs.
class OpaqueConstructFactory {
public:
  /// create a 32-bit opaque constant with specified algorithm.
  /// @param target target location into which the value is stored
  /// @param value the value to be stored
  static std::shared_ptr<OpaqueConstruct>
  createOpaqueConstant32(const OpaqueStorage &target, uint32_t value,
                         const std::string &algorithm = "mov");
};

#if 0
class OpaqueConstructManipulator {
public:
  static bool isComposable(const OpaqueConstruct &f, const OpaqueConstruct &g);
  static std::shared_ptr<OpaqueConstruct>
  compose(std::shared_ptr<OpaqueConstruct> f,
          std::shared_ptr<OpaqueConstruct> g);
};
#endif

#endif
