// ==============================================================================
//   X86 ROP Utils
//   part of the ROPfuscator project
// ==============================================================================
// This is the main module of the whole project.
// It provides high-level reasoning about the actual ROP chain creation by
// mapping each instruction, given as input, to a series of microgadgets that
// have the very same semantic.
// It is also responsible to inject the newly built ROP chain and remove the
// instructions that have been replaced.

#include "Ropfuscator/BinAutopsy.h"
#include "Ropfuscator/ChainElem.h"
#include "Ropfuscator/LivenessAnalysis.h"
#include "X86.h"
#include "X86InstrBuilder.h"
#include "X86TargetMachine.h"
#include <tuple>

#ifndef X86ROPUTILS_H
#define X86ROPUTILS_H

#define CHAIN_LABEL_LEN 16

#if __GNUC__
#if __x86_64__ || __ppc64__
#define ARCH_64
const std::string POSSIBLE_LIBC_FOLDERS[] = {"/lib32", "/usr/lib32",
                                             "/usr/local/lib32"};
#else
#define ARCH_32
const std::string POSSIBLE_LIBC_FOLDERS[] = {"/lib", "/usr/lib",
                                             "/usr/local/lib"};
#endif
#endif

typedef std::vector<ChainElem> ROPChain;

using namespace std;
using namespace llvm;

// Keeps track of all the instructions to be replaced with the obfuscated
// ones. Handles the injection of auxiliary machine code to guarantee the
// correct chain execution and to resume the non-obfuscated code execution
// afterwards.
class ROPEngine {
  ROPChain chain;

  bool handleAddSubIncDec(MachineInstr *, std::vector<x86_reg> &scratchRegs);
  bool handleMov32rm(MachineInstr *, std::vector<x86_reg> &scratchRegs);
  bool handleMov32mr(MachineInstr *, std::vector<x86_reg> &scratchRegs);
  void addToInstrMap(MachineInstr *, ChainElem);

public:
  // BA - shared instance of Binary Autopsy.
  static BinaryAutopsy *BA;

  // instruction mapping between MachineInstrs and their gadget counterpart
  map<MachineInstr *, vector<ChainElem>> instrMap;

  // Constructor
  ROPEngine();

  ROPChain ropify(llvm::MachineInstr &MI, std::vector<x86_reg> &scratchRegs);

  // addImmToReg - adds an immediate value (stored into a scratch register) to
  // the given register.
  bool addImmToReg(MachineInstr *MI, x86_reg reg, int immediate,
                   vector<x86_reg> const &scratchRegs);

  // computeAddress - finds the correct set of gadgets such that:
  // the value in "inputReg" is copied in a scratch register, incremented by the
  // value of "displacement", and placed in any register that can be exchanged
  // with "outputReg".
  // The return value is the actual register in which the computed value is
  // saved. This is useful to whom calls this method, in order to create an
  // exchange chain to move the results onto another register.
  x86_reg computeAddress(MachineInstr *MI, x86_reg inputReg, int displacement,
                         x86_reg outputReg, vector<x86_reg> scratchRegs);

  // Xchg - Concatenates a series of XCHG gadget in order to exchange reg a with
  // reg b.
  int Xchg(MachineInstr *, x86_reg a, x86_reg b);

  // DoubleXchg - Concatenates a series of XCHG gadget in order to exchange reg
  // a with reg b, and c with d. This method helps to prevent two exchange
  // chains that have the same operands to undo each other.
  void DoubleXchg(MachineInstr *, x86_reg a, x86_reg b, x86_reg c, x86_reg d);

  void undoXchgs(MachineInstr *MI);
  x86_reg getEffectiveReg(x86_reg reg);
};

#endif