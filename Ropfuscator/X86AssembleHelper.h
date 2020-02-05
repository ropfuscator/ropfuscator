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

  struct ExternalLabel {
    const std::string label;

    void add(llvm::MachineInstrBuilder &builder) const {
      auto external_symbol =
          builder.getInstr()->getMF()->createExternalSymbolName(label);

      builder.addExternalSymbol(external_symbol);
    }
  };

  struct BasicBlockRef {
    llvm::MachineBasicBlock *label;

    void add(llvm::MachineInstrBuilder &builder) const {
      builder.addMBB(label);
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
  ExternalLabel label(const std::string label) const { return {label}; }
  BasicBlockRef label(llvm::MachineBasicBlock *label) const { return {label}; }

  // --- instruction builder ---
  void mov(Reg r, Imm i) const { _instr(llvm::X86::MOV32ri, r, i); }
  void mov(Reg r, ImmGlobal i) const { _instr(llvm::X86::MOV32ri, r, i); }
  void mov(Mem m, Imm i) const { _instr(llvm::X86::MOV32mi, m, i); }
  void mov(Mem m, ImmGlobal i) const { _instr(llvm::X86::MOV32mi, m, i); }
  void add(Reg r, Imm i) const { _instr(llvm::X86::ADD32ri, r, i); }
  void add(Reg r, ImmGlobal i) const { _instr(llvm::X86::ADD32ri, r, i); }
  void add(Mem m, Imm i) const { _instr(llvm::X86::ADD32mi, m, i); }
  void add(Mem m, ImmGlobal i) const { _instr(llvm::X86::ADD32mi, m, i); }
  void add(Mem m, ExternalLabel i) const { _instr(llvm::X86::ADD32mi, m, i); }
  void push(Reg r) const { _instr(llvm::X86::PUSH32r, r); }
  void push(Imm i) const { _instr(llvm::X86::PUSHi32, i); }
  void push(ImmGlobal i) const { _instr(llvm::X86::PUSHi32, i); }
  void push(ExternalLabel i) const { _instr(llvm::X86::PUSHi32, i); }
  void push(BasicBlockRef l) const { _instr(llvm::X86::PUSHi32, l); }
  void pop(Reg r) const { _instr(llvm::X86::POP32r, r); }
  void pushf() const { _instr(llvm::X86::PUSHF32); }
  void popf() const { _instr(llvm::X86::POPF32); }
  void ret() const { _instr(llvm::X86::RETL); }
  void call(ExternalLabel l) const { _instr(llvm::X86::CALLpcrel32, l); }
  void jmp(ExternalLabel l) const { _instr(llvm::X86::JMP_1, l); }
  void jmp(BasicBlockRef l) const { _instr(llvm::X86::JMP_1, l); }
  void lea(Reg r, Mem m) const {
    auto builder =
        BuildMI(block, position, nullptr, TII->get(llvm::X86::LEA32r), r.reg);
    m.add(builder);
  }
  void inlineasm(std::string str) const {
    auto external_symbol = block.getParent()->createExternalSymbolName(str);

    BuildMI(block, position, nullptr, TII->get(llvm::TargetOpcode::INLINEASM))
        .addExternalSymbol(external_symbol)
        .addImm(0);
  }

private:
  llvm::MachineBasicBlock &block;
  llvm::MachineBasicBlock::iterator position;
  const llvm::MCInstrInfo *TII;

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
};

#endif
