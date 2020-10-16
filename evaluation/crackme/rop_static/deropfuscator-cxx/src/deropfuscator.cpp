#include <iostream>
#include <map>
#include <memory>
#include <utility>
#include <vector>

#include <capstone/capstone.h>
#include <capstone/x86.h>

#include "asmanalysis.hpp"
#include "elfanalysis.hpp"

// usage: deropfuscator <Ropfuscated-ELF-file>
//
// analyse a ropfuscated elf file, decode the ROP chain
// into a flat instructions, and write modified ELF file
// in <original-elf-file>.derop file.
//
// this version is compatible with:
// ropfuscator @ fb184bd232fe1931d9dc8cb1282f87c3d9303d17

using namespace ELFIO;

static const char *libc_filename = "/lib/i386-linux-gnu/libc.so.6";

static int debug_level = 2;

struct StackEntry {
  virtual ~StackEntry() {}
  virtual void add(uint32_t value) = 0;
  virtual std::string to_string() const = 0;
};

struct StackEntryExternal : StackEntry {
  symbol_name symbol;
  int32_t offset;
  void add(uint32_t x) override { offset += x; }
  StackEntryExternal(const symbol_name &symbol, uint32_t offset)
      : symbol(symbol), offset(offset) {}
  std::string to_string() const {
    char buf[64] = {0};
    if (offset != 0) {
      snprintf(buf, sizeof(buf), " %+d", offset);
    }
    return symbol.first + "@" + symbol.second + buf;
  }
};

struct StackEntryLocalAddr : StackEntry {
  uint32_t addr;
  void add(uint32_t x) override { addr += x; }
  StackEntryLocalAddr(uint32_t addr) : addr(addr) {}
  std::string to_string() const {
    char buf[64];
    snprintf(buf, sizeof(buf), "address @ 0x%x", addr);
    return buf;
  }
};

struct StackEntryImmediate : StackEntry {
  uint32_t value;
  void add(uint32_t x) override { value += x; }
  StackEntryImmediate(uint32_t value) : value(value) {}
  std::string to_string() const {
    char buf[64];
    snprintf(buf, sizeof(buf), "0x%x", value);
    return buf;
  }
};

struct StackEntryReg : StackEntry {
  x86_reg reg;
  std::string regname;
  uint32_t addend;
  void add(uint32_t x) override { addend += x; }
  StackEntryReg(x86_reg reg, const std::string &regname)
      : reg(reg), regname(regname), addend(0) {}
  std::string to_string() const {
    char buf[64];
    snprintf(buf, sizeof(buf), "%s %+d", regname.c_str(), addend);
    return buf;
  }
};

struct StackEmulator {
  std::vector<std::shared_ptr<StackEntry>> stack;
  uint32_t addr_begin, addr_end;
  int stack_pointer;
  bool ret_insn;
  bool errored;

  StackEmulator() { reset(); }

  void reset() {
    stack.clear();
    addr_begin = 0;
    addr_end = 0;
    stack_pointer = 0;
    ret_insn = false;
    errored = false;
  }

  void exec_insn(const cs_insn &insn, ElfAnalysis &exe) {
    const cs_x86 &x86insn = insn.detail->x86;
    std::string mnemonic = insn.mnemonic;
    std::string opstr = insn.op_str;
    const cs_x86_op &op0 = x86insn.operands[0], &op1 = x86insn.operands[1];
    if (addr_begin == 0) {
      addr_begin = insn.address;
    }
    switch (insn.id) {
    case X86_INS_PUSH: {
      switch (op0.type) {
      case X86_OP_IMM:
        if (x86insn.opcode[0] == 0x68) {
          uint32_t rtype;
          symbol_name sym;
          uint64_t addr = insn.address + 1;
          if (exe.find_reloc_at(addr, rtype, sym)) {
            switch (rtype) {
            case R_386_32:
              push(new StackEntryExternal(sym, op0.imm));
              break;
            case R_386_RELATIVE:
              push(new StackEntryLocalAddr(op0.imm));
              break;
            case R_386_NONE:
              push(new StackEntryImmediate(op0.imm));
              break;
            default:
              errored = true;
              break;
            }
            break;
          }
        }
        push(new StackEntryImmediate(op0.imm));
        break;
      case X86_OP_REG:
        if (op0.reg == X86_REG_ESP) {
          StackEntryReg *entry = new StackEntryReg(op0.reg, insn.op_str);
          entry->add(-4 * stack_pointer);
          push(entry);
        } else {
          push(new StackEntryReg(op0.reg, insn.op_str));
        }
        break;
      default:
        errored = true;
        break;
      }
      break;
    }
    case X86_INS_PUSHFD: {
      push(new StackEntryReg(X86_REG_EFLAGS, "eflags"));
      break;
    }
    case X86_INS_ADD: {
      if (op0.type == X86_OP_MEM && op0.mem.base == X86_REG_ESP &&
          op0.mem.disp == 0 && op1.type == X86_OP_IMM) {
        // add [esp], imm
        if (std::shared_ptr<StackEntry> entry = top()) {
          entry->add(op1.imm);
        }
      } else if (op0.type == X86_OP_REG && op0.reg == X86_REG_ESP &&
                 op1.type == X86_OP_IMM && op1.imm % 4 == 0) {
        // add esp, imm
        add_esp(op1.imm);
      } else {
        errored = true;
      }
      break;
    }
    case X86_INS_LEA: {
      const cs_x86_op &op0 = x86insn.operands[0], &op1 = x86insn.operands[1];
      if (op0.type == X86_OP_REG && op0.reg == X86_REG_ESP &&
          op1.type == X86_OP_MEM && op1.mem.base == X86_REG_ESP &&
          op1.mem.index == X86_REG_INVALID) {
        // lea esp, [esp + imm]
        add_esp(op1.mem.disp);
      } else {
        errored = true;
      }
      break;
    }
    case X86_INS_POP:
    case X86_INS_POPFD: {
      pop();
      break;
    }
    case X86_INS_RET: {
      pop();
      ++stack_pointer;
      ret_insn = true;
      addr_end = insn.address + insn.size;
      break;
    }
    default: {
      errored = true;
      break;
    }
    }
  }

private:
  void push(StackEntry *entry) {
    if (stack.size() == stack_pointer) {
      stack.emplace_back(entry);
      stack_pointer++;
    } else {
      stack[stack_pointer++] = std::shared_ptr<StackEntry>(entry);
    }
  }
  std::shared_ptr<StackEntry> top() {
    if (stack_pointer == 0) {
      errored = true;
      return nullptr;
    }
    return stack[stack_pointer - 1];
  }
  std::shared_ptr<StackEntry> pop() {
    if (stack_pointer == 0) {
      errored = true;
      return nullptr;
    }
    return stack[--stack_pointer];
  }
  void add_esp(int32_t imm) {
    if (imm > 0) {
      for (int i = 0; i < imm / 4; i++)
        pop();
    } else {
      for (int i = 0; i < imm / -4; i++)
        push(new StackEntryImmediate(0));
    }
  }
};

struct RelocTable {
  std::vector<uint32_t> relative;
  std::vector<std::pair<uint32_t, symbol_name>> symbol;
  std::vector<std::pair<uint32_t, symbol_name>> symbol_pcrel;
};

struct LinearCode {

  struct Instr {
    x86_insn oper;
    int operands_count;
    cs_x86_op operands[4];
    std::string oper_str;
    std::string operands_str;
    uint8_t bytes[16];
    std::shared_ptr<symbol_name> reloc_symbol;
    int len;
    Instr(const cs_insn &insn)
        : oper((x86_insn)insn.id), operands_count(insn.detail->x86.op_count),
          oper_str(insn.mnemonic), operands_str(insn.op_str), len(insn.size) {
      std::copy(insn.detail->x86.operands, insn.detail->x86.operands + 4,
                operands);
      std::copy(insn.bytes, insn.bytes + 16, bytes);
    }
    Instr() = default;
    Instr(const Instr &) = default;
  };

  std::vector<Instr> code;

  // assemble
  void assemble(uint8_t *buf, RelocTable &reloc, const StackEmulator &stack) {
    static std::map<x86_reg, int> reg_map = {
        {X86_REG_EAX, 0}, {X86_REG_ECX, 1}, {X86_REG_EDX, 2}, {X86_REG_EBX, 3},
        {X86_REG_ESP, 4}, {X86_REG_EBP, 5}, {X86_REG_ESI, 6}, {X86_REG_EDI, 7}};
    static std::map<x86_insn, int> jcc_map = {
        {X86_INS_JO, 0}, {X86_INS_JNO, 1}, {X86_INS_JB, 2},  {X86_INS_JAE, 3},
        {X86_INS_JE, 4}, {X86_INS_JNE, 5}, {X86_INS_JBE, 6}, {X86_INS_JA, 7}};
    uint32_t addr_begin = stack.addr_begin;
    uint32_t addr_end = stack.addr_end;
    uint32_t addr = addr_begin;
    for (Instr &instr : code) {
      if (instr.len == 0) {
        if (instr.oper == X86_INS_MOV && instr.operands_count == 2 &&
            instr.operands[0].type == X86_OP_REG &&
            instr.operands[1].type == X86_OP_IMM) {
          // mov reg, imm
          auto it = reg_map.find(instr.operands[0].reg);
          if (it != reg_map.end()) {
            instr.len = 5;
            instr.bytes[0] = 0xb8 + it->second;
            *(uint32_t *)&instr.bytes[1] = (uint32_t)instr.operands[1].imm;
          }
        } else if (instr.oper == X86_INS_LEA && instr.operands_count == 2 &&
                   instr.operands[0].type == X86_OP_REG &&
                   instr.operands[1].type == X86_OP_MEM &&
                   instr.operands[1].mem.base == 0 &&
                   instr.operands[1].mem.index == 0 &&
                   instr.operands[1].mem.segment == 0) {
          // lea reg, [disp]
          auto it = reg_map.find(instr.operands[0].reg);
          if (it != reg_map.end()) {
            instr.len = 6;
            instr.bytes[0] = 0x8d;
            instr.bytes[1] = 0x05 | (it->second << 3);
            *(uint32_t *)&instr.bytes[2] = (uint32_t)instr.operands[1].mem.disp;
            if (instr.reloc_symbol) {
              reloc.symbol.emplace_back(addr + 2, *instr.reloc_symbol);
            } else {
              reloc.relative.emplace_back(addr + 2);
            }
          }
        } else if (instr.oper == X86_INS_LEA && instr.operands_count == 2 &&
                   instr.operands[0].type == X86_OP_REG &&
                   instr.operands[1].type == X86_OP_MEM &&
                   instr.operands[1].mem.index == 0 &&
                   instr.operands[1].mem.segment == 0 && !instr.reloc_symbol) {
          // lea reg, [reg+disp]
          auto it1 = reg_map.find(instr.operands[0].reg);
          auto it2 = reg_map.find((x86_reg)instr.operands[1].mem.base);
          if (it1 != reg_map.end() && it2 != reg_map.end()) {
            int32_t disp = (int32_t)instr.operands[1].mem.disp;
            int pos = 0;
            instr.bytes[pos++] = 0x8d;
            if (disp == 0) {
              instr.bytes[pos++] = 0x00 | (it1->second << 3) | (it2->second);
            } else if (disp >= -128 && disp < 128) {
              instr.bytes[pos++] = 0x40 | (it1->second << 3) | (it2->second);
            } else {
              instr.bytes[pos++] = 0x80 | (it1->second << 3) | (it2->second);
            }
            if (instr.operands[1].mem.base == X86_REG_ESP) {
              instr.bytes[pos++] = 0x24;
            }
            if (disp == 0) {
              // no extra bytes
            } else if (disp >= -128 && disp < 128) {
              instr.bytes[pos++] = (uint8_t)disp;
            } else {
              instr.bytes[pos] = (uint32_t)instr.operands[1].mem.disp;
              pos += 4;
            }
            instr.len = pos;
          }
        } else if (instr.oper == X86_INS_JMP && instr.operands_count == 1 &&
                   instr.operands[0].type == X86_OP_IMM &&
                   !instr.reloc_symbol) {
          // jmp imm
          instr.len = 5;
          instr.bytes[0] = 0xe9;
          uint32_t target = (uint32_t)instr.operands[0].imm;
          *(uint32_t *)&instr.bytes[1] = target - (addr + instr.len);
        } else if (instr.oper == X86_INS_CALL && instr.operands_count == 1 &&
                   instr.operands[0].type == X86_OP_IMM) {
          // call imm
          instr.len = 5;
          instr.bytes[0] = 0xe8;
          if (instr.reloc_symbol) {
            *(uint32_t *)&instr.bytes[1] = (uint32_t)-4;
            reloc.symbol_pcrel.emplace_back(addr + instr.len - 4,
                                            *instr.reloc_symbol);
          } else {
            uint32_t target = (uint32_t)instr.operands[0].imm;
            *(uint32_t *)&instr.bytes[1] = target - (addr + instr.len);
          }
        } else if (instr.oper == X86_INS_CALL && instr.operands_count == 1 &&
                   instr.operands[0].type == X86_OP_REG) {
          // call reg
          auto it = reg_map.find(instr.operands[0].reg);
          if (it != reg_map.end()) {
            instr.len = 2;
            instr.bytes[0] = 0xff;
            instr.bytes[1] = 0xd0 | it->second;
          }
        } else if (instr.oper == X86_INS_JMP && instr.operands_count == 1 &&
                   instr.operands[0].type == X86_OP_REG) {
          // jmp reg
          auto it = reg_map.find(instr.operands[0].reg);
          if (it != reg_map.end()) {
            instr.len = 2;
            instr.bytes[0] = 0xff;
            instr.bytes[1] = 0xe0 | it->second;
          }
        } else if ((instr.oper == X86_INS_JE || instr.oper == X86_INS_JNE ||
                    instr.oper == X86_INS_JB || instr.oper == X86_INS_JAE) &&
                   instr.operands_count == 1 &&
                   instr.operands[0].type == X86_OP_IMM &&
                   !instr.reloc_symbol) {
          // jcc imm
          auto it = jcc_map.find(instr.oper);
          if (it != jcc_map.end()) {
            instr.len = 6;
            instr.bytes[0] = 0x0f;
            instr.bytes[1] = 0x80 | it->second;
            uint32_t target = (uint32_t)instr.operands[0].imm;
            *(uint32_t *)&instr.bytes[2] = target - (addr + instr.len);
          }
        } else if (instr.oper == X86_INS_PUSH && instr.operands_count == 1 &&
                   instr.operands[0].type == X86_OP_REG) {
          // push reg
          auto it = reg_map.find(instr.operands[0].reg);
          if (it != reg_map.end()) {
            instr.len = 1;
            instr.bytes[0] = 0x50 | it->second;
          }
        } else if (instr.oper == X86_INS_PUSHFD) {
          // pushf
          instr.len = 1;
          instr.bytes[0] = 0x9c;
        } else if (instr.oper == X86_INS_NOP) {
          // nop
          instr.len = 1;
          instr.bytes[0] = 0x90;
        } else if (instr.oper == X86_INS_RET) {
          // ret
          instr.len = 1;
          instr.bytes[0] = 0xc3;
        } else {
          std::cout << "[NOTIMPL]\t" << instr.oper_str << "\t"
                    << instr.operands_str << std::endl;
        }
      }
      if (addr + instr.len > addr_end) {
        std::cout << "[WARNING] deobfuscated code does not fit into binary"
                  << std::endl;
        std::cout << instr.len << std::endl;
        std::cout << instr.oper_str << instr.operands_str << std::endl;
        std::cout << std::hex << stack.addr_begin << std::endl;
        std::cout << std::hex << stack.addr_end << std::endl;
        return;
      }
      std::memcpy(buf + (addr - addr_begin), instr.bytes, instr.len);
      addr += instr.len;
    }
    if (addr < addr_end) {
      std::memset(buf + (addr - addr_begin), '\x90', addr_end - addr);
    }
  }

  // peep hole optimisation
  void optimise(const StackEmulator &stack) {
    if (code.size() == 0) {
      return;
    }

    // lea reg1, ...; lea reg2, ...; cmove reg1, reg2; jmp reg1
    if (code.size() >= 4 && (code[code.size() - 2].oper == X86_INS_CMOVE ||
                             code[code.size() - 2].oper == X86_INS_CMOVB)) {
      Instr &inst1 = code[code.size() - 4];
      Instr &inst2 = code[code.size() - 3];
      Instr &inst3 = code[code.size() - 2];
      Instr &inst4 = code[code.size() - 1];
      if (inst1.oper == X86_INS_LEA && inst2.oper == X86_INS_LEA &&
          inst4.oper == X86_INS_JMP && !inst1.reloc_symbol &&
          !inst2.reloc_symbol) {
        auto lea1_dst = inst1.operands[0];
        auto lea1_src = inst1.operands[1];
        auto lea2_dst = inst2.operands[0];
        auto lea2_src = inst2.operands[1];
        auto cmov_dst = inst3.operands[0];
        auto cmov_src = inst3.operands[1];
        auto jmp_tgt = inst4.operands[0];
        if (lea1_dst.type == X86_OP_REG && lea1_src.type == X86_OP_MEM &&
            lea2_dst.type == X86_OP_REG && lea2_src.type == X86_OP_MEM &&
            cmov_dst.type == X86_OP_REG && cmov_src.type == X86_OP_REG &&
            jmp_tgt.type == X86_OP_REG && cmov_dst.reg == jmp_tgt.reg &&
            lea1_src.mem.base == 0 && lea1_src.mem.index == 0 &&
            lea1_src.mem.segment == 0 && lea2_src.mem.base == 0 &&
            lea2_src.mem.index == 0 && lea2_src.mem.segment == 0) {
          x86_insn jcc_insn = X86_INS_INVALID;
          std::string jcc_str;
          if (cmov_dst.reg == lea1_dst.reg && cmov_src.reg == lea2_dst.reg) {
            if (inst3.oper == X86_INS_CMOVE) {
              jcc_insn = X86_INS_JNE;
              jcc_str = "jne";
            } else if (inst3.oper == X86_INS_CMOVB) {
              jcc_insn = X86_INS_JAE;
              jcc_str = "jae";
            }
          } else if (cmov_src.reg == lea1_dst.reg &&
                     cmov_dst.reg == lea2_dst.reg) {
            if (inst3.oper == X86_INS_CMOVE) {
              jcc_insn = X86_INS_JE;
              jcc_str = "je";
            } else if (inst3.oper == X86_INS_CMOVB) {
              jcc_insn = X86_INS_JB;
              jcc_str = "jb";
            }
          }
          if (jcc_insn != X86_INS_INVALID) {
            std::string target = inst1.operands_str;
            target = target.substr(0, target.rfind("]"));
            target = target.substr(target.rfind("[") + 1);
            Instr jcc_inst;
            jcc_inst.oper = jcc_insn;
            jcc_inst.oper_str = jcc_str;
            jcc_inst.operands_count = 1;
            jcc_inst.operands_str = target;
            jcc_inst.operands[0].type = X86_OP_IMM;
            jcc_inst.operands[0].imm = lea1_src.mem.disp;
            jcc_inst.len = 0;
            target = inst2.operands_str;
            target = target.substr(0, target.rfind("]"));
            target = target.substr(target.rfind("[") + 1);
            Instr jmp_inst;
            jmp_inst.oper = X86_INS_JMP;
            jmp_inst.oper_str = "jmp";
            jmp_inst.operands_count = 1;
            jmp_inst.operands_str = target;
            jmp_inst.operands[0].type = X86_OP_IMM;
            jmp_inst.operands[0].imm = lea2_src.mem.disp;
            jmp_inst.len = 0;
            code.resize(code.size() - 4);
            code.push_back(jcc_inst);
            code.push_back(jmp_inst);
          }
        }
      }
    }

    // jmp next-addr -> remove
    if (code.size() >= 1) {
      Instr &lastinst = code[code.size() - 1];
      if (lastinst.oper == X86_INS_JMP) {
        auto operand0 = lastinst.operands[0];
        if (operand0.type == X86_OP_IMM && operand0.imm == stack.addr_end) {
          // jump to next block
          code.resize(code.size() - 1);
        }
      }
    }

    // lea reg, ...; call reg -> call ...
    for (int i = 0; i < 2 && i + 2 <= code.size(); i++) {
      Instr &inst1 = code[code.size() - i - 2];
      Instr &inst2 = code[code.size() - i - 1];
      if (inst1.oper == X86_INS_LEA && inst2.oper == X86_INS_CALL) {
        auto lea_dst = inst1.operands[0];
        auto lea_src = inst1.operands[1];
        auto call_op = inst2.operands[0];
        if (lea_dst.type == X86_OP_REG && call_op.type == X86_OP_REG &&
            lea_src.type == X86_OP_MEM && lea_src.mem.base == 0 &&
            lea_src.mem.index == 0 && lea_src.mem.segment == 0 &&
            lea_dst.reg == call_op.reg) {
          Instr inst = inst2;
          inst.len = 0;
          inst.reloc_symbol = inst1.reloc_symbol;
          inst.operands[0].type = X86_OP_IMM;
          inst.operands[0].imm = lea_src.mem.disp;
          std::string callee = inst1.operands_str;
          callee = callee.substr(0, callee.rfind("]"));
          callee = callee.substr(callee.rfind("[") + 1);
          inst.operands_str = callee;
          code.erase(code.end() - (i + 2), code.end() - i);
          code.insert(code.end() - i, inst);
        }
      }
    }
  }
};

int main(int argc, char **argv) {
  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << " <elffile> [<libcfile>]" << std::endl;
    return 1;
  }
  if (argc > 2) {
    libc_filename = argv[2];
  }

  ElfAnalysis obfexe, libc;
  obfexe.debug = false;
  libc.debug = false;

  if (!obfexe.load(argv[1])) {
    std::cerr << "ELF load error: " << argv[1] << std::endl;
    return 1;
  }

  if (!libc.load(libc_filename)) {
    std::cerr << "ELF load error: " << libc_filename << std::endl;
    return 1;
  }

  if (debug_level >= 1)
    std::cout << "================= analysing " << argv[1] << std::endl;
  obfexe.analyse();

  if (debug_level >= 1)
    std::cout << "================= analysing " << libc_filename << std::endl;
  libc.analyse();

  AsmAnalysis analysis(CS_ARCH_X86, CS_MODE_32);
  analysis.set_option(CS_OPT_DETAIL, CS_OPT_ON);

  // added reloc
  RelocTable reloctable;
  // removed reloc
  std::vector<int> removed_relocs;

  // find symbols
  std::vector<int> chain_symbol_indices;
  for (const auto &kv : obfexe.symtab.name_to_index) {
    size_t pos = kv.first.rfind("chain_");
    if (pos != std::string::npos) {
      if (kv.first.rfind("resume_", 0) == std::string::npos) {
        chain_symbol_indices.push_back(kv.second);
      }
    }
  }

  ElfModifier modifier(obfexe);

  std::vector<bool> leading_byte(256);
  for (uint8_t b : {0x8d, 0x68, 0x6a}) {
    // lea esp, [esp+...] or push
    leading_byte[b] = true;
  }
  std::vector<std::unique_ptr<StackEntry>> stack;

  std::vector<StackEmulator> ropchains;

  // stage 1: analyse instructions in obfuscated code
  // and extract rop chains in stack
  for (auto *sec : obfexe.elf.sections) {
    auto sectname = sec->get_name();
    if (sectname.rfind(".text", 0) == 0) {
      uint32_t addr_begin = (uint32_t)sec->get_address();
      uint32_t addr_end = addr_begin + (uint32_t)sec->get_size();
      uint32_t addr = addr_begin;
      const void *code = obfexe.find_code_at(addr_begin);
      StackEmulator emulator;
      for (const auto &insn :
           analysis.disassembler(code, addr_end - addr, addr)) {
        // std::cout << insn.address << std::endl;
        // std::cout << insn.size << std::endl;
        // std::cout << insn.mnemonic << std::endl;
        emulator.exec_insn(insn, obfexe);
        if (emulator.errored) {
          emulator.reset();
          continue;
        } else if (emulator.ret_insn) {
          ropchains.push_back(emulator);
          emulator.reset();
          continue;
        }
      }
    }
  }

  for (StackEmulator &ropchain : ropchains) {
    // stage 2: analyse rop chains and get linear instructions
    if (debug_level >= 1)
      std::cout << std::hex << "================= deobfuscating chain @ 0x"
                << ropchain.addr_begin << " - 0x" << ropchain.addr_end
                << std::dec << std::endl;
    LinearCode linearcode;
    enum { GADGET, POP, JMP } state = GADGET;
    x86_reg reg = X86_REG_INVALID;
    std::string regname = "";
    std::vector<std::shared_ptr<StackEntry>> stack(
        ropchain.stack.rend() - ropchain.stack_pointer, ropchain.stack.rend());
    for (auto &entry : stack) {
      if (debug_level >= 3)
        std::cout << " [stack] " << entry->to_string() << std::endl;
      if (state == POP) {
        LinearCode::Instr insn;
        insn.len = 0;
        insn.oper = X86_INS_MOV;
        insn.oper_str = "mov";
        insn.operands_str = regname + ", ";
        insn.operands[0].type = X86_OP_REG;
        insn.operands[0].reg = reg;
        insn.operands_count = 2;
        if (auto *immentry = dynamic_cast<StackEntryImmediate *>(entry.get())) {
          insn.operands_str += std::to_string(immentry->value);
          insn.operands[1].type = X86_OP_IMM;
          insn.operands[1].imm = immentry->value;
        } else if (auto *regentry =
                       dynamic_cast<StackEntryReg *>(entry.get())) {
          if (regentry->addend == 0) {
            insn.operands_str += regentry->regname;
            insn.operands[1].type = X86_OP_REG;
            insn.operands[1].reg = regentry->reg;
          } else {
            std::string addendstr = std::to_string((int32_t)regentry->addend);
            if (addendstr[0] != '-') {
              addendstr = "+" + addendstr;
            }
            insn.oper = X86_INS_LEA;
            insn.oper_str = "lea";
            insn.operands_str +=
                "dword ptr [" + regentry->regname + addendstr + "]";
            insn.operands[1].type = X86_OP_MEM;
            insn.operands[1].mem = {0, regentry->reg, 0, 0, regentry->addend};
          }
        } else if (auto *addrentry =
                       dynamic_cast<StackEntryLocalAddr *>(entry.get())) {
          char addr_operand_buf[16];
          snprintf(addr_operand_buf, sizeof(addr_operand_buf), "[0x%x]",
                   addrentry->addr);
          insn.oper = X86_INS_LEA;
          insn.oper_str = "lea";
          insn.operands_str += "dword ptr ";
          insn.operands_str += addr_operand_buf;
          insn.operands[1].type = X86_OP_MEM;
          insn.operands[1].mem = {0, 0, 0, 0, addrentry->addr};
        } else if (auto *addrentry =
                       dynamic_cast<StackEntryExternal *>(entry.get())) {
          insn.oper = X86_INS_LEA;
          insn.oper_str = "lea";
          insn.operands_str += "dword ptr [" + addrentry->symbol.first + "@@" +
                               addrentry->symbol.second + "]";
          insn.operands[1].type = X86_OP_MEM;
          insn.operands[1].mem = {0, 0, 0, 0, 0};
          insn.reloc_symbol.reset(new symbol_name(addrentry->symbol));
        } else {
          insn.operands_str += "???";
          insn.operands[1].type = X86_OP_IMM;
          insn.operands[1].imm = 0;
        }
        linearcode.code.push_back(insn);
        state = GADGET;
        continue;
      }
      if (state == JMP) {
        // The stack is not really a rop chain
        if (auto *regentry = dynamic_cast<StackEntryReg *>(entry.get())) {
          LinearCode::Instr insn;
          insn.len = 0;
          if (regentry->reg == X86_REG_EFLAGS) {
            insn.oper = X86_INS_PUSHFD;
            insn.oper_str = "pushf";
            insn.operands_count = 0;
          } else {
            insn.oper = X86_INS_PUSH;
            insn.oper_str = "push";
            insn.operands_str = regentry->regname;
            insn.operands[0].type = X86_OP_REG;
            insn.operands[0].reg = regentry->reg;
            insn.operands_count = 1;
          }
          linearcode.code.insert(linearcode.code.begin(), insn);
        }
        continue;
      }
      if (auto *gadget = dynamic_cast<StackEntryExternal *>(entry.get())) {
        auto it = libc.dynsym.namever_to_index.find(gadget->symbol);
        if (it != libc.dynsym.namever_to_index.end()) {
          uint32_t addr =
              (uint32_t)libc.dynsym.index_to_addr[it->second] + gadget->offset;

          if (debug_level >= 3)
            std::cout << std::hex << "   [gadget] 0x" << addr << std::dec
                      << std::endl;

          const void *code = libc.find_code_at(addr);
          bool gadget_end = false;
          for (const auto &insn : analysis.disassembler(code, 10, addr)) {
            if (debug_level >= 3)
              std::cout << "\t" << insn.mnemonic << "\t" << insn.op_str
                        << std::endl;
            switch (insn.id) {
            case X86_INS_RET:
            case X86_INS_JMP:
              gadget_end = true;
              break;
            case X86_INS_POP:
              state = POP;
              reg = insn.detail->x86.operands[0].reg;
              regname = insn.op_str;
              break;
            case X86_INS_PUSH:
              if (&entry == &stack[stack.size() - 1]) {
                // end
                if (insn.detail->x86.operands[0].type == X86_OP_REG) {
                  LinearCode::Instr instr(insn);
                  instr.len = 0;
                  instr.oper = X86_INS_JMP;
                  instr.oper_str = "jmp";
                  linearcode.code.push_back(instr);
                }
                state = JMP;
              } else {
                if (insn.detail->x86.operands[0].type == X86_OP_REG) {
                  LinearCode::Instr instr(insn);
                  instr.len = 0;
                  instr.oper = X86_INS_CALL;
                  instr.oper_str = "call";
                  linearcode.code.push_back(instr);
                }
              }
              break;
            default:
              linearcode.code.push_back(LinearCode::Instr(insn));
              break;
            }
            if (gadget_end) {
              break;
            }
          }
        } else {
          if (debug_level >= 1)
            std::cout << " [WARNING] symbol not found: " << gadget->symbol.first
                      << "@@" << gadget->symbol.second << std::endl;
        }
      } else if (auto *addrentry =
                     dynamic_cast<StackEntryLocalAddr *>(entry.get())) {
        char addr_operand_buf[16];
        snprintf(addr_operand_buf, sizeof(addr_operand_buf), "0x%x",
                 addrentry->addr);
        LinearCode::Instr instr;
        instr.len = 0;
        instr.oper = X86_INS_JMP;
        instr.oper_str = "jmp";
        instr.operands_str = addr_operand_buf;
        instr.operands_count = 1;
        instr.operands[0].type = X86_OP_IMM;
        instr.operands[0].imm = addrentry->addr;
        linearcode.code.push_back(instr);
        state = JMP;
      }
    }
    if (state != JMP) {
      LinearCode::Instr instr;
      instr.len = 0;
      instr.oper = X86_INS_RET;
      instr.oper_str = "ret";
      instr.operands_count = 0;
      linearcode.code.push_back(instr);
    }
    // optimise
    linearcode.optimise(ropchain);
    if (debug_level >= 1) {
      std::cout << " [recovered instructions]" << std::endl;
      for (auto &inst : linearcode.code) {
        std::cout << "\t" << inst.oper_str << "\t" << inst.operands_str
                  << std::endl;
      }
    }

    // stage 3: rewrite binary instructions
    uint8_t *codeptr =
        (uint8_t *)modifier.get_modifiable_memory(ropchain.addr_begin);
    if (codeptr) {
      linearcode.assemble(codeptr, reloctable, ropchain);
    }

    // step 4: determine relocations to be removed
    {
      auto &m = obfexe.reldyn.addr_to_index;
      for (auto it1 = m.lower_bound(ropchain.addr_begin),
                it2 = m.upper_bound(ropchain.addr_end);
           it1 != it2; ++it1) {
        removed_relocs.push_back(it1->second);
      }
    }
  }

  // step 5: add/remove relocations
  {
    std::sort(removed_relocs.begin(), removed_relocs.end());
    section *sec = obfexe.elf.sections[".rel.dyn"];
    int relative_relocs = 0;
    int total_relocs = 0;
    if (sec) {
      const char *orig_data = sec->get_data();
      std::vector<char> data(sec->get_size());
      int entry_size = sec->get_entry_size();
      int n = sec->get_size() / entry_size;
      removed_relocs.push_back(n); // sentinel
      int i = 0;
      // add relocs (R_386_RELATIVE)
      for (uint32_t addr : reloctable.relative) {
        Elf32_Rel reloc;
        reloc.r_info = ELF32_R_INFO(0, R_386_RELATIVE);
        reloc.r_offset = addr;
        relative_relocs++;
        std::memcpy(&data[entry_size * i++], &reloc, entry_size);
      }
      // copy relocs (except for removed ones)
      for (int j = 0, k = 0; j < n; j++) {
        if (removed_relocs[k] == j) {
          k++;
        } else {
          Elf32_Rel &reloc = (Elf32_Rel &)orig_data[entry_size * j];
          if (ELF32_R_TYPE(reloc.r_info) == R_386_RELATIVE) {
            relative_relocs++;
          }
          std::memcpy(&data[entry_size * i++], &reloc, entry_size);
        }
      }
      // add relocs (R_386_32)
      for (auto &entry : reloctable.symbol) {
        Elf32_Rel reloc;
        auto it = obfexe.dynsym.namever_to_index.find(entry.second);
        if (it != obfexe.dynsym.namever_to_index.end()) {
          reloc.r_info = ELF32_R_INFO(it->second, R_386_32);
          reloc.r_offset = entry.first;
          std::memcpy(&data[entry_size * i++], &reloc, entry_size);
        }
      }
      // add relocs (R_386_PC32)
      for (auto &entry : reloctable.symbol_pcrel) {
        Elf32_Rel reloc;
        auto it = obfexe.dynsym.namever_to_index.find(entry.second);
        if (it != obfexe.dynsym.namever_to_index.end()) {
          reloc.r_info = ELF32_R_INFO(it->second, R_386_PC32);
          reloc.r_offset = entry.first;
          std::memcpy(&data[entry_size * i++], &reloc, entry_size);
        }
      }
      total_relocs = i;
      // write back relocation section
      sec->set_data(&data[0], data.size());
    }

    // modify RELSZ and RELCOUNT in .dynamic
    sec = obfexe.elf.sections[".dynamic"];
    if (sec) {
      const char *orig_data = sec->get_data();
      std::vector<char> data(sec->get_size());
      std::memcpy(&data[0], orig_data, sec->get_size());
      int entry_size = sec->get_entry_size();
      int n = sec->get_size() / entry_size;
      for (int i = 0; i < n; i++) {
        Elf32_Dyn &dyn = (Elf32_Dyn &)data[entry_size * i];
        if (dyn.d_tag == DT_RELSZ) {
          dyn.d_un.d_val = sizeof(Elf32_Rel) * total_relocs;
        }
        if (dyn.d_tag == 0x6ffffffa) { // DT_RELCOUNT
          dyn.d_un.d_val = relative_relocs;
        }
      }
      // write back dynamic section
      sec->set_data(&data[0], data.size());
    }
  }

  // write code changes
  modifier.commit_modifications();

  // finally, save the deobfuscated binary
  std::string savedfile = argv[1] + std::string(".derop");
  if (debug_level >= 1)
    std::cout << "================= saving " << savedfile << std::endl;
  obfexe.elf.save(savedfile);

  return 0;
}
