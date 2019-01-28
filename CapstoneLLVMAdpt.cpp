#include "CapstoneLLVMAdpt.h"
#include <assert.h>

cs_x86_op opCreate(x86_op_type type, unsigned int value) {
  cs_x86_op op;
  op.type = type;

  switch (type) {
  case X86_OP_REG: {
    op.reg = static_cast<x86_reg>(value);
    break;
  }
  case X86_OP_IMM: {
    op.imm = static_cast<uint64_t>(value);
    break;
  }
  case X86_OP_MEM: {
    x86_op_mem mem;
    op.mem = mem;
    op.mem.base = static_cast<x86_reg>(value);
    break;
  }
  default:
    assert(false && "Invalid operand type");
  }

  return op;
}

bool opValid(cs_x86_op op) { return op.type != 0; }

bool opCompare(cs_x86_op a, cs_x86_op b) {
  if (a.type == b.type) {
    switch (a.type) {
    case X86_OP_REG:
      return a.reg == b.reg;
    case X86_OP_IMM:
      return a.imm == b.imm;

    // For MEM operands, we look only at the base address, since displacement
    // and other stuff cannot be useful for our purpose
    case X86_OP_MEM:
      return a.mem.base == b.mem.base;

    default:
      assert(false && "Trying to compare invalid or floating point operands "
                      "(not supported)");
    }
  }
  return false;
}
