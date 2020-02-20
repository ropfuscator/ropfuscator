#ifndef OPAQUECONSTRUCT_H
#define OPAQUECONSTRUCT_H

#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

typedef unsigned int llvm_reg_t;
class X86AssembleHelper;

/// Represents input/output register (or stack) location of opaque constructs.
struct OpaqueStorage {
  /// location type
  enum class Type {
    /// represents register.
    REG,
    /// represents stack location with offset.
    STACK
  };

  const Type type;

  union {
    /// when type == REG, contains the register (LLVM)
    llvm_reg_t reg;
    /// when type == STACK, contains the stack offset
    int stackOffset;
  };

  static const OpaqueStorage EAX, ECX, EDX, EBX;
  static const OpaqueStorage STACK_0, STACK_4, STACK_8, STACK_12;

  bool operator==(const OpaqueStorage &other) const {
    if (this == &other)
      return true;
    if (type == Type::REG)
      return other.type == Type::REG && reg == other.reg;
    else if (type == Type::STACK)
      return other.type == Type::STACK && stackOffset == other.stackOffset;
    return false;
  }

private:
  OpaqueStorage(Type type, llvm_reg_t reg, int stackOffset) : type(type) {
    if (type == Type::REG)
      this->reg = reg;
    else if (type == Type::STACK)
      this->stackOffset = stackOffset;
  }
};

// forward declaration
struct OpaqueState;

/// Abstract value for opaque predicate input/output
struct OpaqueValue {
  // With contextual opaque predicates, compute output from input
  using compute_fun_type = OpaqueValue (*)(const OpaqueState &);

  /// Represents value type.
  enum class Type {
    /// when used in input, "input value should be specific value"
    /// when used in output, "output value is constant"
    CONSTANT,
    CONSTANT_MULTIPLE,
    /// when used in input, "any value is accepted";
    /// when used in output, "may be any value"
    ANY,
    /// used only in output. Output is computed from input
    CONTEXTUAL
  };

  const Type type;

  /// when type == CONSTANT | CONSTANT_MULTIPLE, contains the constant value(s)
  std::vector<uint32_t> values;
  /// when type == CONTEXTUAL, contains the compute function
  compute_fun_type compute;

  /// create a value with type == ANY.
  static OpaqueValue createAny() { return OpaqueValue(Type::ANY, {}, nullptr); }

  /// create a value with type == CONSTANT.
  /// @param value the constant value
  static OpaqueValue createConstant(uint32_t value) {
    return OpaqueValue(Type::CONSTANT, {value}, nullptr);
  }

  /// create a value with type == CONSTANT_VALUES.
  /// @param values the constant value
  static OpaqueValue createConstant(const std::vector<uint32_t> &values) {
    return OpaqueValue(Type::CONSTANT_MULTIPLE, values, nullptr);
  }

  /// create a value with type == CONTEXTUAL.
  /// @param compute pointer to a function which computes the value from input
  static OpaqueValue createContextual(compute_fun_type compute) {
    return OpaqueValue(Type::CONTEXTUAL, {}, compute);
  }

private:
  OpaqueValue(Type type, const std::vector<uint32_t> &values,
              compute_fun_type compute)
      : type(type), values(values), compute(compute) {}
};

/// Opaque predicate input/output condition
struct OpaqueState {
  std::vector<std::pair<OpaqueStorage, OpaqueValue>> state;
  OpaqueValue find(OpaqueStorage);
  uint64_t findConcrete(OpaqueStorage);
  OpaqueState(std::initializer_list<std::pair<OpaqueStorage, OpaqueValue>> l)
      : state(l) {}
  OpaqueState() = default;
  void emplace_back(const OpaqueStorage &storage, const OpaqueValue &value) {
    state.emplace_back(storage, value);
  }
  const OpaqueValue *find(const OpaqueStorage &key) const {
    for (auto &p : state) {
      if (p.first == key) {
        return &p.second;
      }
    }
    return nullptr;
  }
  const std::vector<uint32_t> *findValues(const OpaqueStorage &key) const {
    auto *p = find(key);
    if (p && (p->type == OpaqueValue::Type::CONSTANT ||
              p->type == OpaqueValue::Type::CONSTANT_MULTIPLE)) {
      return &p->values;
    }
    return nullptr;
  }
  const uint32_t *findValue(const OpaqueStorage &key) const {
    auto *p = findValues(key);
    return p ? p->data() : nullptr;
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
  virtual std::vector<llvm_reg_t> getClobberedRegs() const = 0;
  /// generate x86 code which implements the opaque construct.
  /// @param as assembler to generate instruction
  /// @param stackOffset offset to store/retrieve data into/from stack
  virtual void compile(X86AssembleHelper &as, int stackOffset) const = 0;
  /// virtual destructor
  virtual ~OpaqueConstruct();
};

/// Factory methods for opaque constructs.
class OpaqueConstructFactory {
public:
  /// create a 32-bit opaque constant with specified algorithm.
  /// @param target target location into which the value is stored
  /// @param value the value to be stored
  /// @param algorithm opaque constant algorithm (default: "mov")
  static std::shared_ptr<OpaqueConstruct>
  createOpaqueConstant32(const OpaqueStorage &target, uint32_t value,
                         const std::string &algorithm = "mov");

  /// create a 32-bit opaque constant with random result value.
  /// @param target target location into which the value is stored
  /// @param algorithm opaque constant algorithm (default: "mov")
  static std::shared_ptr<OpaqueConstruct>
  createOpaqueConstant32(const OpaqueStorage &target,
                         const std::string &algorithm = "mov");

  /// create a 32-bit opaque constant with specified algorithm.
  /// @param target target location into which the value is stored
  /// @param values the values to be stored
  /// @param algorithm opaque constant algorithm, in the form of
  ///  "randomgenerator+selector" (default: addreg+mov)
  static std::shared_ptr<OpaqueConstruct>
  createBranchingOpaqueConstant32(const OpaqueStorage &target,
                                  const std::vector<uint32_t> &values,
                                  const std::string &algorithm = "addreg+mov");

  /// create a 32-bit opaque constant with specified algorithm.
  /// @param target target location into which the value is stored
  /// @param n_choices the number of random values
  /// @param algorithm opaque constant algorithm, in the form of
  ///  "randomgenerator+selector" (default: addreg+mov)
  static std::shared_ptr<OpaqueConstruct>
  createBranchingOpaqueConstant32(const OpaqueStorage &target, size_t n_choices,
                                  const std::string &algorithm = "addreg+mov");

  static std::shared_ptr<OpaqueConstruct>
  createValueAdjustor(const OpaqueStorage &target,
                      const std::vector<uint32_t> &inputvalues,
                      const std::vector<uint32_t> &outputvalues);

  static std::shared_ptr<OpaqueConstruct>
  compose(std::shared_ptr<OpaqueConstruct> f,
          std::shared_ptr<OpaqueConstruct> g);
};

#endif
