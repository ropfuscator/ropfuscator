#include "CapstoneLLVMAdpt.h"
#include "../X86TargetMachine.h"
#include <assert.h>

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

x86_reg convertToCapstoneReg(unsigned int reg) {
  switch (reg) {
    using namespace llvm;
  case X86::AL:
    return X86_REG_AL;
  case X86::CL:
    return X86_REG_CL;
  case X86::DL:
    return X86_REG_DL;
  case X86::AH:
    return X86_REG_AH;
  case X86::CH:
    return X86_REG_CH;
  case X86::DH:
    return X86_REG_DH;
  case X86::BL:
    return X86_REG_BL;
  case X86::BH:
    return X86_REG_BH;
  case X86::SIL:
    return X86_REG_SIL;
  case X86::DIL:
    return X86_REG_DIL;
  case X86::BPL:
    return X86_REG_BPL;
  case X86::SPL:
    return X86_REG_SPL;
  case X86::R8B:
    return X86_REG_R8B;
  case X86::R9B:
    return X86_REG_R9B;
  case X86::R10B:
    return X86_REG_R10B;
  case X86::R11B:
    return X86_REG_R11B;
  case X86::R14B:
    return X86_REG_R14B;
  case X86::R15B:
    return X86_REG_R15B;
  case X86::R12B:
    return X86_REG_R12B;
  case X86::R13B:
    return X86_REG_R13B;
  case X86::AX:
    return X86_REG_AX;
  case X86::CX:
    return X86_REG_CX;
  case X86::DX:
    return X86_REG_DX;
  case X86::SI:
    return X86_REG_SI;
  case X86::DI:
    return X86_REG_DI;
  case X86::BX:
    return X86_REG_BX;
  case X86::BP:
    return X86_REG_BP;
  case X86::SP:
    return X86_REG_SP;
  case X86::R8W:
    return X86_REG_R8W;
  case X86::R9W:
    return X86_REG_R9W;
  case X86::R10W:
    return X86_REG_R10W;
  case X86::R11W:
    return X86_REG_R11W;
  case X86::R14W:
    return X86_REG_R14W;
  case X86::R15W:
    return X86_REG_R15W;
  case X86::R12W:
    return X86_REG_R12W;
  case X86::R13W:
    return X86_REG_R13W;
  case X86::EAX:
    return X86_REG_EAX;
  case X86::ECX:
    return X86_REG_ECX;
  case X86::EDX:
    return X86_REG_EDX;
  case X86::ESI:
    return X86_REG_ESI;
  case X86::EDI:
    return X86_REG_EDI;
  case X86::EBX:
    return X86_REG_EBX;
  case X86::EBP:
    return X86_REG_EBP;
  case X86::ESP:
    return X86_REG_ESP;
  case X86::R8D:
    return X86_REG_R8D;
  case X86::R9D:
    return X86_REG_R9D;
  case X86::R10D:
    return X86_REG_R10D;
  case X86::R11D:
    return X86_REG_R11D;
  case X86::R14D:
    return X86_REG_R14D;
  case X86::R15D:
    return X86_REG_R15D;
  case X86::R12D:
    return X86_REG_R12D;
  case X86::R13D:
    return X86_REG_R13D;
  case X86::RAX:
    return X86_REG_RAX;
  case X86::RCX:
    return X86_REG_RCX;
  case X86::RDX:
    return X86_REG_RDX;
  case X86::RSI:
    return X86_REG_RSI;
  case X86::RDI:
    return X86_REG_RDI;
  case X86::R8:
    return X86_REG_R8;
  case X86::R9:
    return X86_REG_R9;
  case X86::R10:
    return X86_REG_R10;
  case X86::R11:
    return X86_REG_R11;
  case X86::RBX:
    return X86_REG_RBX;
  case X86::R14:
    return X86_REG_R14;
  case X86::R15:
    return X86_REG_R15;
  case X86::R12:
    return X86_REG_R12;
  case X86::R13:
    return X86_REG_R13;
  case X86::RBP:
    return X86_REG_RBP;
  case X86::RSP:
    return X86_REG_RSP;
  case X86::RIP:
    return X86_REG_RIP;
  case X86::CS:
    return X86_REG_CS;
  case X86::DS:
    return X86_REG_DS;
  case X86::SS:
    return X86_REG_SS;
  case X86::ES:
    return X86_REG_ES;
  case X86::FS:
    return X86_REG_FS;
  case X86::GS:
    return X86_REG_GS;
  default:
    assert(false && "Tried to translate an unsupported register!");
    exit(1);
  }
}
