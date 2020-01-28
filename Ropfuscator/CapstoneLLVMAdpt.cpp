#include "CapstoneLLVMAdpt.h"
#include "../X86TargetMachine.h"
#include <assert.h>
#include <array>

bool areEqualOps(const cs_x86_op &op0, const cs_x86_op &op1) {
  if (op0.type != op1.type)
    return false;

  switch (op0.type) {
  case X86_OP_REG:
    return (op0.reg == op1.reg);
  case X86_OP_MEM: {
    if (op0.mem.segment != op1.mem.segment)
      return false;
    if (op0.mem.base != op1.mem.base)
      return false;
    if (op0.mem.index != op1.mem.index)
      return false;
    if (op0.mem.scale != op1.mem.scale)
      return false;
    return (op0.mem.disp == op1.mem.disp);
  }
  case X86_OP_IMM:
    return (op0.imm == op1.imm);
  default: {
    assert(false && "trying to compare invalid operands!");
    return false;
  }
  }
}

x86_reg extractReg(const cs_x86_op op) {
  if (op.type == X86_OP_REG)
    return op.reg;
  else
    return (x86_reg)op.mem.base;
}

cs_x86_op opCreate(x86_op_type type, unsigned int value) {
  cs_x86_op op;
  op.type = type;

  switch (type) {
  case X86_OP_REG: {
    op.reg = (x86_reg)value;
    break;
  }
  case X86_OP_IMM: {
    op.imm = (uint64_t)value;
    break;
  }
  case X86_OP_MEM: {
    x86_op_mem mem;
    op.mem = mem;
    op.mem.base = (x86_reg)value;
    break;
  }
  default:
    assert(false && "Invalid operand type");
  }

  return op;
}

namespace {
struct RegMap {
  struct Entry {
    unsigned int llvmreg;
    x86_reg capstonereg;
  };
  std::array<unsigned int, X86_REG_ENDING> capstone_to_llvm;
  std::array<x86_reg, llvm::X86::NUM_TARGET_REGS> llvm_to_capstone;
  static const Entry mappingTable[233];
  RegMap() {
    capstone_to_llvm.fill(llvm::X86::NoRegister);
    llvm_to_capstone.fill(X86_REG_INVALID);
    for (auto &entry : mappingTable) {
      capstone_to_llvm[entry.capstonereg] = entry.llvmreg;
      llvm_to_capstone[entry.llvmreg] = entry.capstonereg;
    }
  }
} static const regmap;
#define R(N)                                                                   \
  { llvm::X86::N, X86_REG_##N }
#define R_0_to_7(N)                                                            \
  R(N##0), R(N##1), R(N##2), R(N##3), R(N##4), R(N##5), R(N##6), R(N##7)
#define R_8_to_15(N)                                                           \
  R(N##8), R(N##9), R(N##10), R(N##11), R(N##12), R(N##13), R(N##14), R(N##15)
#define R_16_to_23(N)                                                          \
  R(N##16), R(N##17), R(N##18), R(N##19), R(N##20), R(N##21), R(N##22), R(N##23)
#define R_24_to_31(N)                                                          \
  R(N##24), R(N##25), R(N##26), R(N##27), R(N##28), R(N##29), R(N##30), R(N##31)
const RegMap::Entry RegMap::mappingTable[] = {
    // 8bit general purpose
    R(AL), R(AH), R(CL), R(CH), R(DL), R(DH), R(BL), R(BH), R(SPL), R(BPL),
    R(SIL), R(DIL),
    // 16bit general purpose
    R(AX), R(CX), R(DX), R(BX), R(SP), R(BP), R(SI), R(DI),
    // 16bit segment
    R(CS), R(DS), R(SS), R(ES), R(FS), R(GS),
    // 16bit special / x87
    R(IP), R(FPSW),
    // 32bit general purpose
    R(EAX), R(ECX), R(EDX), R(EBX), R(ESP), R(EBP), R(ESI), R(EDI),
    // 32bit special
    R(EIP), R(EIZ), R(EFLAGS),
    // control/debug register
    R_0_to_7(CR), R_8_to_15(CR), R_0_to_7(DR),
    // x86_64 8bit
    R(R8B), R(R9B), R(R10B), R(R11B), R(R12B), R(R13B), R(R14B), R(R15B),
    // x86_64 16bit
    R(R8W), R(R9W), R(R10W), R(R11W), R(R12W), R(R13W), R(R14W), R(R15W),
    // x86_64 32bit
    R(R8D), R(R9D), R(R10D), R(R11D), R(R12D), R(R13D), R(R14D), R(R15D),
    // x86_64 64bit
    R(RAX), R(RCX), R(RDX), R(RBX), R(RSP), R(RBP), R(RSI), R(RDI), R(RIP),
    R(RIZ), R(R8), R(R9), R(R10), R(R11), R(R12), R(R13), R(R14), R(R15),
    // floating point, MMX
    R_0_to_7(FP), R_0_to_7(ST), R_0_to_7(MM),
    // SSE
    R_0_to_7(XMM), R_8_to_15(XMM), R_16_to_23(XMM), R_24_to_31(XMM),
    // AVX
    R_0_to_7(YMM), R_8_to_15(YMM), R_16_to_23(YMM), R_24_to_31(YMM),
    R_0_to_7(ZMM), R_8_to_15(ZMM), R_16_to_23(ZMM), R_24_to_31(ZMM),
    R_0_to_7(K)};
} // namespace

x86_reg convertToCapstoneReg(unsigned int reg) {
  return reg < regmap.llvm_to_capstone.size() ? regmap.llvm_to_capstone[reg] : X86_REG_INVALID;
}

unsigned int convertToLLVMReg(x86_reg reg) {
  return reg < regmap.capstone_to_llvm.size() ? regmap.capstone_to_llvm[reg] : llvm::X86::NoRegister;
}
