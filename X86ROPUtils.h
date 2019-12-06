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

enum class ROPChainStatus {
  OK = 0, // chain generated without error
  ERR_NOT_IMPLEMENTED, // unknown instruction
  ERR_NO_REGISTER_AVAILABLE, // enough registers are not available
  ERR_NO_GADGETS_AVAILABLE, // no gadgets are available
  ERR_UNSUPPORTED, // known instruction, but not supported for some reason
  ERR_UNSUPPORTED_STACKPOINTER, // not supported as it uses/modifies stack pointer
  COUNT
};

using namespace std;
using namespace llvm;

bool getLibraryPath(std::string &libraryPath);

// Keeps track of all the instructions to be replaced with the obfuscated
// ones. Handles the injection of auxiliary machine code to guarantee the
// correct chain execution and to resume the non-obfuscated code execution
// afterwards.
class ROPEngine {
  ROPChain chain;

  ROPChainStatus handleAddSubIncDecRI(MachineInstr *, std::vector<x86_reg> &scratchRegs);
  ROPChainStatus handleAddSubRR(MachineInstr *, std::vector<x86_reg> &scratchRegs);
  ROPChainStatus handleLea32r(MachineInstr *, std::vector<x86_reg> &scratchRegs);
  ROPChainStatus handleMov32rm(MachineInstr *, std::vector<x86_reg> &scratchRegs);
  ROPChainStatus handleMov32mr(MachineInstr *, std::vector<x86_reg> &scratchRegs);
  ROPChainStatus handleMov32mi(MachineInstr *, std::vector<x86_reg> &scratchRegs);
  ROPChainStatus handleMov32rr(MachineInstr *, std::vector<x86_reg> &scratchRegs);
  ROPChainStatus handleCmp32mi(MachineInstr *, std::vector<x86_reg> &scratchRegs);
  ROPChainStatus handleCmp32ri(MachineInstr *, std::vector<x86_reg> &scratchRegs);
  ROPChainStatus addSubImmToReg(MachineInstr *MI, x86_reg reg, bool isSub, int immediate,
                      std::vector<x86_reg> const &scratchRegs);

public:
  // Constructor
  ROPEngine();

  ROPChainStatus ropify(llvm::MachineInstr &MI, std::vector<x86_reg> &scratchRegs,
                        bool &flagIsModifiedInInstr, ROPChain &resultChain);
  ROPChain undoXchgs(MachineInstr *MI);
  void mergeChains(ROPChain &chain1, const ROPChain &chain2);

  // Reiteratively removes adjacent pairs of equal xchg gadgets to reduce the
  // chain size. Indeed, two consecutive equal xchg gadgets undo each other's
  // effects.
  void removeDuplicates(ROPChain &chain);
};

// Generates inline assembly labels that are used in the prologue and epilogue
// of each ROP chain
void generateChainLabels(char **chainLabel, char **chainLabelC,
                         char **resumeLabel, char **resumeLabelC,
                         StringRef funcName, int chainID);

#endif