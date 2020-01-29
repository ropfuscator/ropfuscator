#ifndef X86ASSEMBLEHELPER_H
#define X86ASSEMBLEHELPER_H

#include "../X86TargetMachine.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"

namespace llvm {
class GlobalValue;
}

class X86AssembleHelper {
public:
  typedef unsigned int llvm_reg_t;
  struct Imm {
    uint64_t imm;
    void add(llvm::MachineInstrBuilder &builder) const { builder.addImm(imm); }
  };
  struct ImmGlobal {
    const llvm::GlobalValue *global;
    int64_t offset;
    void add(llvm::MachineInstrBuilder &builder) const {
      builder.addGlobalAddress(global, offset);
    }
  };
  struct Reg {
    llvm_reg_t reg;
    void add(llvm::MachineInstrBuilder &builder) const { builder.addReg(reg); }
  };
  struct Mem {
    llvm_reg_t reg;
    int scale;
    llvm_reg_t index;
    int offset;
    llvm_reg_t seg;
    void add(llvm::MachineInstrBuilder &builder) const {
      builder.addReg(reg).addImm(scale).addReg(index).addImm(offset).addReg(
          seg);
    }
  };
  X86AssembleHelper(llvm::MachineBasicBlock &block,
                    llvm::MachineBasicBlock::iterator position)
      : block(block), position(position),
        TII(block.getParent()->getTarget().getMCInstrInfo()) {}

  // --- operand builder ---
  Imm imm(uint64_t value) const { return {value}; }
  ImmGlobal imm(const llvm::GlobalValue *global, int64_t offset) const {
    return {global, offset};
  }
  Reg reg(llvm_reg_t r) const { return {r}; }
  Mem mem(llvm_reg_t r, int ofs = 0, llvm_reg_t idx = llvm::X86::NoRegister,
          int scale = 1, llvm_reg_t segment = llvm::X86::NoRegister) const {
    return {r, scale, idx, ofs, segment};
  }
  // --- instruction builder ---
  void mov(Reg r, Imm i) const { _instr(llvm::X86::MOV32ri, r, i); }
  void mov(Reg r, ImmGlobal i) const { _instr(llvm::X86::MOV32ri, r, i); }
  void mov(Mem m, Imm i) const { _instr(llvm::X86::MOV32mi, m, i); }
  void mov(Mem m, ImmGlobal i) const { _instr(llvm::X86::MOV32mi, m, i); }
  void add(Reg r, Imm i) const { _instr(llvm::X86::ADD32ri, r, i); }
  void add(Reg r, ImmGlobal i) const { _instr(llvm::X86::ADD32ri, r, i); }
  void add(Mem m, Imm i) const { _instr(llvm::X86::ADD32mi, m, i); }
  void add(Mem m, ImmGlobal i) const { _instr(llvm::X86::ADD32mi, m, i); }
  void push(Reg r) const { _instr(llvm::X86::PUSH32r, r); }
  void pop(Reg r) const { _instr(llvm::X86::POP32r, r); }
  void pushf() const { _instr(llvm::X86::PUSHF32); }
  void popf() const { _instr(llvm::X86::POPF32); }
  void inlineasm(const char *str) const {
    BuildMI(block, position, nullptr, TII->get(llvm::TargetOpcode::INLINEASM))
        .addExternalSymbol(str)
        .addImm(0);
  }

private:
  void _instr(unsigned int opcode) const {
    BuildMI(block, position, nullptr, TII->get(opcode));
  }
  template <typename T1> void _instr(unsigned int opcode, T1 operand1) const {
    auto builder = BuildMI(block, position, nullptr, TII->get(opcode));
    operand1.add(builder);
  }
  template <typename T1, typename T2>
  void _instr(unsigned int opcode, T1 operand1, T2 operand2) const {
    auto builder = BuildMI(block, position, nullptr, TII->get(opcode));
    operand1.add(builder);
    operand2.add(builder);
  }
  llvm::MachineBasicBlock &block;
  llvm::MachineBasicBlock::iterator position;
  const llvm::MCInstrInfo *TII;
};

#endif
