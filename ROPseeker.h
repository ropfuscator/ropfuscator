//
// ROPseeker engine aims to find gadgets within a given binary.
//
#define PACKAGE "ropfuscator" /* see https://bugs.gentoo.org/428728 */

#include "SymExtractor.h"
#include <bfd.h>
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <dirent.h>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <vector>

// Max bytes before the RET to be examined (RET included!)
#define MAXDEPTH 4
using namespace std;

struct Gadget;

string POSSIBLE_LIBC_FOLDERS[] = {"/lib", "/usr/lib", "/usr/local/lib"};

vector<Gadget> gadgets;

struct Gadget {
  cs_insn *instructions;

  // debug
  string asmInstr;

  Gadget(cs_insn *instructions, string asmInstr)
      : instructions(instructions), asmInstr(asmInstr){};

  uint64_t getAddress() const { return instructions[0].address; }

  uint64_t getRelativeAddess(Symbol *s) const {
    // Returns the address relative to a given symbol
    uint64_t absAddress = getAddress();
    return absAddress - s->address;
  }

  x86_insn getID() const {
    // Returns the ID (opcode)
    return static_cast<x86_insn>(instructions[0].id);
  }

  cs_x86_op getOp(int i) const {
    // Returns the i-th operand
    return instructions[0].detail->x86.operands[i];
  }

  uint8_t getNumOp() const {
    // Returns the number of operands
    return instructions[0].detail->x86.op_count;
  }
};

// TODO: plz improve me
bool recurseLibcDir(const char *path, string &libcPath, uint current_depth) {
  DIR *dir;
  struct dirent *entry;

  if (!current_depth) {
    return false;
  }

  dir = opendir(path);

  if (dir == NULL)
    return false;

  // searching for libc in regular files only
  while ((entry = readdir(dir)) != NULL) {
    if (!strcmp(entry->d_name, "libc.so.6")) {
      libcPath += path;
      libcPath += "/";
      libcPath += entry->d_name;

      // llvm::dbgs() << "libc found here: " << libcPath << "\n";

      return true;
    }
  }

  // could not find libc, recursing into directories
  dir = opendir(path);

  if (dir == NULL)
    return false;

  while ((entry = readdir(dir)) != NULL) {
    // must be a dir and not "." or ".."
    if (entry->d_type == DT_DIR && strcmp(entry->d_name, ".") &&
        strcmp(entry->d_name, "..")) {

      // constructing path to dir
      string newpath = std::string();

      newpath += path;
      newpath += "/";
      newpath += entry->d_name;

      // llvm::dbgs() << "recursing into: " << newpath << "\n";

      // recurse into dir
      if (recurseLibcDir(newpath.c_str(), libcPath, current_depth - 1))
        return true;
    }
  }

  return false;
}

// TODO: plz improve me
bool getLibcPath(string &libcPath) {
  uint maxrecursedepth = 3;

  libcPath.clear();

  for (auto &folder : POSSIBLE_LIBC_FOLDERS) {
    if (recurseLibcDir(folder.c_str(), libcPath, maxrecursedepth))
      return true;
  }
  return false;
}

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
      assert(1 == 2 && "Trying to compare invalid or floating point operands "
                       "(not supported)");
    }
  }
  return false;
}

Gadget *gadgetLookup(string asmInstr) {
  // Legacy: lookup by asm_instr string
  if (gadgets.size() > 0) {
    for (auto &gadget : gadgets) {
      if (gadget.asmInstr.compare(asmInstr) == 0)
        return &gadget;
    }
  }
  return nullptr;
}

Gadget *gadgetLookup(x86_insn insn, cs_x86_op op0, cs_x86_op op1) {
  if (gadgets.size() > 0) {
    for (auto &gadget : gadgets) {

      // Search by OpCode
      if (gadget.getID() == insn) {
        // We don't reason about the number of operands, since it is possible to
        // assume that instructions with the same opcode have also the same
        // number of operands

        // Search by operand
        if (opCompare(gadget.getOp(0), op0) &&
            opCompare(gadget.getOp(1), op1)) {
          return &gadget;
        }
      }
    }
  }
  return nullptr;
}

cs_x86_op opCreate(x86_op_type type, uint value) {
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
    assert(1 == 2 && "Invalid operand type");
  }

  return op;
}

vector<Gadget> extractGadgets() {
  const uint8_t ret[] = "\xc3";
  string libcPath;

  // capstone stuff
  csh handle;
  cs_insn *instructions;

  srand(time(NULL));

  assert(getLibcPath(libcPath));

  // bfd
  bfd *bfd_h;
  initBfd(libcPath, bfd_h);
  assert(bfd_check_format(bfd_h, bfd_object) &&
         "Given file does not look like a valid ELF file");

  // Gets executable sections from the library file
  getSections(&(*bfd_h));

  // Get symbols from .dynsym table, to use them for symbol hooking
  getDynamicSymbols(&(*bfd_h));
  llvm::dbgs() << "[*] Found " << symbols.size() << " symbols\n";

  assert((cs_open(CS_ARCH_X86, CS_MODE_32, &handle) == CS_ERR_OK) &&
         "Unable to initialise capstone-engine");
  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
  llvm::dbgs() << "[*] Looking for gadgets in " << libcPath << "\n";

  ifstream input_file(libcPath, ios::binary);
  assert(input_file.good() && "Unable to find libc!");

  // Get input size
  input_file.seekg(0, ios::end);
  streamoff input_size = input_file.tellg();
  llvm::dbgs() << "[*] Scanning the whole binary (" << input_size
               << " bytes) ...\n";

  // Read the whole file
  input_file.seekg(0, ios::beg);
  uint8_t *buf = new uint8_t[input_size];
  input_file.read(reinterpret_cast<char *>(buf), input_size);

  for (auto &s : sections) {
    llvm::dbgs() << "[*] Searching gadgets in section " + s.name + " ... ";
    int cnt = 0;

    // Scan for RET instructions
    for (uint64_t i = s.address; i < static_cast<uint64_t>(s.address + s.size);
         i++) {

      if (buf[i] == *ret) {
        // llvm::dbgs() << "    ret @ " << i;
        size_t offset = i + 1;
        uint8_t *cur_pos = buf + offset;

        // Iteratively try to decode starting from (MAXDEPTH to 0)
        // instructions before the actual RET
        for (int depth = MAXDEPTH; depth >= 0; depth--) {

          size_t count = cs_disasm(handle, cur_pos - depth, depth,
                                   offset - depth, depth, &instructions);

          // Valid gadgets must have two instructions, and the
          // last one must be a RET
          if (count == 2 && instructions[count - 1].id == X86_INS_RET) {

            // Each gadget is identified with its mnemonic
            // and operators (ugly but straightforward :P)
            string asm_instr;
            for (size_t j = 0; j < count - 1; j++) {
              asm_instr += instructions[j].mnemonic;
              asm_instr += " ";
              asm_instr += instructions[j].op_str;
              asm_instr += ";";
            }

            if (gadgetLookup(asm_instr) == nullptr) {
              gadgets.push_back(Gadget(instructions, asm_instr));
              // llvm::dbgs() << "Added gadget: " << asm_instr << "\n";
              cnt++;
            }
          }
        }
      }
    }
    llvm::dbgs() << cnt << " found!\n";
  }
  free(buf);
  input_file.close();

  llvm::dbgs() << "[*] Found " << gadgets.size() << " unique microgadgets!\n";

  /*for (auto const &gadget : gadgets) {
    llvm::dbgs() << "0x" << gadget.address << ":   \t" << gadget.asmInstr
                 << "\n";
  }*/

  return gadgets;
}
