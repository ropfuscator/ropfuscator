#ifndef X86ASSEMBLEHELPER_H
#define X86ASSEMBLEHELPER_H

#include "X86TargetMachine.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/MC/MCContext.h"
#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <map>
#include <string>

namespace llvm {
class GlobalValue;
}

namespace ropf {

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

  struct Label {
    llvm::MCSymbol *symbol;

    void add(llvm::MachineInstrBuilder &builder) const {
      builder.addSym(symbol);
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
      : block(block), position(position), ctx(block.getParent()->getContext()),
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
  Label label() const { return label(_newLabelName()); }
  Label label(const std::string label) const {
    return {ctx.getOrCreateSymbol(label)};
  }
  ImmGlobal addOffset(Label label, int64_t offset) const {
    return imm(_createGV(label.symbol->getName()), offset);
  }

  // --- instruction builder ---
  void mov(Reg r1, Reg r2) const { _instr(llvm::X86::MOV32rr, r1, r2); }
  void mov(Reg r, Imm i) const { _instr(llvm::X86::MOV32ri, r, i); }
  void mov(Reg r, ImmGlobal i) const { _instr(llvm::X86::MOV32ri, r, i); }
  void mov(Reg r, Mem m) const { _instr(llvm::X86::MOV32rm, r, m); }
  void mov(Mem m, Reg r) const { _instr(llvm::X86::MOV32mr, m, r); }
  void mov(Mem m, Imm i) const { _instr(llvm::X86::MOV32mi, m, i); }
  void mov(Mem m, ImmGlobal i) const { _instr(llvm::X86::MOV32mi, m, i); }
  void add(Reg r1, Reg r2) const { _instrd(llvm::X86::ADD32rr, r1, r2); }
  void add(Reg r, Imm i) const { _instr(llvm::X86::ADD32ri, r, i); }
  void add(Reg r, ImmGlobal i) const { _instr(llvm::X86::ADD32ri, r, i); }
  void add(Reg r, Label i) const { _instr(llvm::X86::ADD32ri, r, i); }
  void add(Reg r, Mem m) const { _instrd(llvm::X86::ADD32rm, r, m); }
  void add(Mem m, Reg r) const { _instr(llvm::X86::ADD32mr, m, r); }
  void add(Mem m, Imm i) const { _instr(llvm::X86::ADD32mi, m, i); }
  void add(Mem m, ImmGlobal i) const { _instr(llvm::X86::ADD32mi, m, i); }
  void add(Mem m, Label i) const { _instr(llvm::X86::ADD32mi, m, i); }
  void imul(Reg r) const { _instr(llvm::X86::IMUL32r, r); }
  void imul(Reg r, Imm i) const { _instrd(llvm::X86::IMUL32rri, r, i); }
  void imul(Reg r1, Reg r2, Imm i) const {
    _instrd0(llvm::X86::IMUL32rri, r1, r2, i);
  }
  void mul(Reg r) const { _instr(llvm::X86::MUL32r, r); }
  void cmp(Reg r, Imm i) const { _instr(llvm::X86::CMP32ri, r, i); }
  void cmp(Reg r1, Reg r2) const { _instr(llvm::X86::CMP32rr, r1, r2); }
  void movzx(Reg r1, Reg r2) const { _instr(llvm::X86::MOVZX32rr8, r1, r2); }
  void land(Reg r1, Reg r2) const { _instrd(llvm::X86::AND32rr, r1, r2); }
  void land(Reg r, Imm i) const { _instrd(llvm::X86::AND32ri, r, i); }
  void land8(Reg r1, Reg r2) const { _instrd(llvm::X86::AND8rr, r1, r2); }
  void test(Reg r1, Reg r2) const { _instr(llvm::X86::TEST32rr, r1, r2); }
  void test(Reg r, Imm i) const { _instr(llvm::X86::TEST32ri, r, i); }
  void lor(Reg r1, Reg r2) const { _instrd(llvm::X86::OR32rr, r1, r2); }
  void lor8(Reg r1, Reg r2) const { _instrd(llvm::X86::OR8rr, r1, r2); }
  void lxor(Reg r1, Reg r2) const { _instrd(llvm::X86::XOR32rr, r1, r2); }
  void lxor(Reg r, Imm i) const { _instrd(llvm::X86::XOR32ri, r, i); }
  void lxor(Mem m, Imm i) const { _instr(llvm::X86::XOR32mi, m, i); }
  void lnot(Reg r) const { _instr(llvm::X86::NOT32r, r); }
  void shl(Reg r) const { _instr(llvm::X86::SHL32r1, r); }
  void shl(Reg r, Imm i) const { _instrd(llvm::X86::SHL32ri, r, i); }
  void shr(Reg r) const { _instr(llvm::X86::SHR32r1, r); }
  void shr(Reg r, Imm i) const { _instrd(llvm::X86::SHR32ri, r, i); }
  void push(Reg r) const { _instr(llvm::X86::PUSH32r, r); }
  void push(Imm i) const { _instr(llvm::X86::PUSHi32, i); }
  void push(ImmGlobal i) const { _instr(llvm::X86::PUSHi32, i); }
  void push(Label i) const { _instr(llvm::X86::PUSHi32, i); }
  void pop(Reg r) const { _instr(llvm::X86::POP32r, r); }
  void pushf() const { _instr(llvm::X86::PUSHF32); }
  void popf() const { _instr(llvm::X86::POPF32); }
  void ret() const { _instr(llvm::X86::RETL); }
  void rdtsc() const { _instr(llvm::X86::RDTSC); }
  void call(Label l) const { _instr(llvm::X86::CALLpcrel32, l); }
  void jmp(Label l) const { _instr(llvm::X86::JMP_1, l); }

#if LLVM_VERSION_MAJOR >= 9
  void cmove(Reg r1, Reg r2) const {
    _instrd(llvm::X86::CMOV32rr, r1, r2, imm(llvm::X86::COND_E));
  }
  void sete(Reg r) const {
    _instr(llvm::X86::SETCCr, r, imm(llvm::X86::COND_E));
  }
  void setne(Reg r) const {
    _instr(llvm::X86::SETCCr, r, imm(llvm::X86::COND_NE));
  }
  void je(Label l) const {
    _instr(llvm::X86::JCC_1, l, imm(llvm::X86::COND_E));
  }
  void ja(Label l) const {
    _instr(llvm::X86::JCC_1, l, imm(llvm::X86::COND_A));
  }
  void jb(Label l) const {
    _instr(llvm::X86::JCC_1, l, imm(llvm::X86::COND_B));
  }
#else
  void cmove(Reg r1, Reg r2) const { _instrd(llvm::X86::CMOVE32rr, r1, r2); }
  void sete(Reg r) const { _instr(llvm::X86::SETEr, r); }
  void setne(Reg r) const { _instr(llvm::X86::SETNEr, r); }
  void je(Label l) const { _instr(llvm::X86::JE_1, l); }
  void ja(Label l) const { _instr(llvm::X86::JA_1, l); }
  void jb(Label l) const { _instr(llvm::X86::JB_1, l); }
#endif

  void lea(Reg r, Mem m) const {
    auto builder =
        BuildMI(block, position, nullptr, TII->get(llvm::X86::LEA32r), r.reg);
    m.add(builder);
  }
  // Don't use this function unless really necessary;
  // LLVM will create assembly parser for each inline assembly code,
  // which will heavily slow down the build process.
  void inlineasm(std::string str) const {
    auto external_symbol = block.getParent()->createExternalSymbolName(str);

    BuildMI(block, position, nullptr, TII->get(llvm::TargetOpcode::INLINEASM))
        .addExternalSymbol(external_symbol)
        .addImm(0);
  }
  void putLabel(Label label) { _instr(llvm::TargetOpcode::GC_LABEL, label); }

private:
  llvm::MachineBasicBlock &block;
  llvm::MachineBasicBlock::iterator position;
  llvm::MCContext &ctx;
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

  template <typename T2>
  void _instrd(unsigned int opcode, Reg operand1, T2 operand2) const {
    auto builder =
        BuildMI(block, position, nullptr, TII->get(opcode), operand1.reg);
    operand1.add(builder);
    operand2.add(builder);
  }

  template <typename T2, typename T3>
  void _instrd(unsigned int opcode, Reg operand1, T2 operand2,
               T3 operand3) const {
    auto builder =
        BuildMI(block, position, nullptr, TII->get(opcode), operand1.reg);
    operand1.add(builder);
    operand2.add(builder);
    operand3.add(builder);
  }

  template <typename T2, typename T3>
  void _instrd0(unsigned int opcode, Reg operand1, T2 operand2,
                T3 operand3) const {
    auto builder =
        BuildMI(block, position, nullptr, TII->get(opcode), operand1.reg);
    operand2.add(builder);
    operand3.add(builder);
  }

  static std::string _newLabelName() {
    static int n = 0;
    return ".Ltmp_ropfuscator_" + std::to_string(++n);
  }

  llvm::GlobalValue *_createGV(std::string name) const {
    auto *module = const_cast<llvm::Module *>(
        block.getParent()->getFunction().getParent());
    auto *gv = module->getGlobalVariable(name, true);
    if (!gv) {
      auto *voidT = llvm::Type::getVoidTy(module->getContext());
      gv = new llvm::GlobalVariable(*module, voidT, true,
                                    llvm::GlobalValue::ExternalLinkage, nullptr,
                                    name);
    }
    return gv;
  }
};

struct StackState {
  std::map<unsigned int, int> saved_regs;
  int stack_offset;
};

} // namespace ropf

#endif
