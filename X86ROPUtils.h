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
#include "Ropfuscator/XchgGraph.h"
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

enum class FlagSaveMode {
  NOT_SAVED,
  SAVE_BEFORE_EXEC,
  SAVE_AFTER_EXEC
};

class ROPChain {
public:
  std::vector<ChainElem> chain;
  ChainElem *successor; // jump target at the end of chain
  FlagSaveMode flagSave;
  bool hasNormalInstr;
  bool hasConditionalJump;
  bool hasUnconditionalJump;

  std::vector<ChainElem>::iterator begin() { return chain.begin(); }
  std::vector<ChainElem>::const_iterator begin() const { return chain.begin(); }
  std::vector<ChainElem>::iterator end() { return chain.end(); }
  std::vector<ChainElem>::const_iterator end() const { return chain.end(); }
  std::vector<ChainElem>::reverse_iterator rbegin() { return chain.rbegin(); }
  std::vector<ChainElem>::const_reverse_iterator rbegin() const {
    return chain.rbegin();
  }
  std::vector<ChainElem>::reverse_iterator rend() { return chain.rend(); }
  std::vector<ChainElem>::const_reverse_iterator rend() const {
    return chain.rend();
  }
  size_t size() const { return chain.size(); }
  void emplace_back(const ChainElem &elem) { chain.emplace_back(elem); }
  bool valid() { return !chain.empty() || successor; }
  ROPChain &append(const ROPChain &other) {
    chain.insert(chain.end(), other.begin(), other.end());
    return *this;
  }
  void append(std::initializer_list<std::reference_wrapper<const ROPChain>> list) {
    for (const ROPChain &c : list) append(c);
  }
  bool canMerge(const ROPChain &other);
  void merge(const ROPChain &other);
  void clear() {
    chain.clear();
    successor = nullptr;
    flagSave = FlagSaveMode::NOT_SAVED;
    hasNormalInstr = false;
    hasConditionalJump = false;
    hasUnconditionalJump = false;
  }
  // Reiteratively removes adjacent pairs of equal xchg gadgets to reduce the
  // chain size. Indeed, two consecutive equal xchg gadgets undo each other's
  // effects.
  void removeDuplicates();
  ROPChain() { clear(); }
};

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
  XchgState state;

  ROPChainStatus handleArithmeticRI(MachineInstr *, std::vector<x86_reg> &scratchRegs);
  ROPChainStatus handleArithmeticRR(MachineInstr *, std::vector<x86_reg> &scratchRegs);
  ROPChainStatus handleArithmeticRM(MachineInstr *, std::vector<x86_reg> &scratchRegs);
  ROPChainStatus handleXor32RR(MachineInstr *, std::vector<x86_reg> &scratchRegs);
  ROPChainStatus handleLea32r(MachineInstr *, std::vector<x86_reg> &scratchRegs);
  ROPChainStatus handleMov32rm(MachineInstr *, std::vector<x86_reg> &scratchRegs);
  ROPChainStatus handleMov32mr(MachineInstr *, std::vector<x86_reg> &scratchRegs);
  ROPChainStatus handleMov32mi(MachineInstr *, std::vector<x86_reg> &scratchRegs);
  ROPChainStatus handleMov32rr(MachineInstr *, std::vector<x86_reg> &scratchRegs);
  ROPChainStatus handleCmp32mi(MachineInstr *, std::vector<x86_reg> &scratchRegs);
  ROPChainStatus handleCmp32ri(MachineInstr *, std::vector<x86_reg> &scratchRegs);
  ROPChainStatus handleCmp32rm(MachineInstr *, std::vector<x86_reg> &scratchRegs);
  ROPChainStatus handleJmp1(MachineInstr *, std::vector<x86_reg> &scratchRegs);
  ROPChainStatus handleJcc1(MachineInstr *, std::vector<x86_reg> &scratchRegs);
  ROPChainStatus handleCall(MachineInstr *, std::vector<x86_reg> &scratchRegs);
  ROPChainStatus handleCallReg(MachineInstr *, std::vector<x86_reg> &scratchRegs);
  bool convertOperandToChainPushImm(const MachineOperand &operand, ChainElem &result);

public:
  // Constructor
  ROPEngine();

  ROPChainStatus ropify(llvm::MachineInstr &MI, std::vector<x86_reg> &scratchRegs,
                        bool shouldFlagSaved, ROPChain &resultChain);
  ROPChain undoXchgs(MachineInstr *MI);
  void mergeChains(ROPChain &chain1, const ROPChain &chain2);

};

// Generates inline assembly labels that are used in the prologue and epilogue
// of each ROP chain
void generateChainLabels(char **chainLabel, char **chainLabelC,
                         char **resumeLabel, char **resumeLabelC,
                         StringRef funcName, int chainID);

#endif