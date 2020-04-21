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

#ifndef ROPENGINE_H
#define ROPENGINE_H

#include "ChainElem.h"
#include "LivenessAnalysis.h"
#include "XchgGraph.h"
#include "llvm/CodeGen/MachineInstr.h"
#include <string>
#include <tuple>
#include <vector>

// forward declaration
class BinaryAutopsy;

enum class FlagSaveMode { NOT_SAVED, SAVE_BEFORE_EXEC, SAVE_AFTER_EXEC };

class ROPChain {
public:
  std::vector<ChainElem> chain;
  ChainElem *successor; // jump target at the end of chain
  FlagSaveMode flagSave;
  bool hasNormalInstr, hasConditionalJump, hasUnconditionalJump;

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
  OK = 0,                    // chain generated without error
  ERR_NOT_IMPLEMENTED,       // unknown instruction
  ERR_NO_REGISTER_AVAILABLE, // enough registers are not available
  ERR_NO_GADGETS_AVAILABLE,  // no gadgets are available
  ERR_UNSUPPORTED, // known instruction, but not supported for some reason
  ERR_UNSUPPORTED_STACKPOINTER, // not supported as it uses/modifies stack
                                // pointer
  COUNT
};

// Keeps track of all the instructions to be replaced with the obfuscated
// ones. Handles the injection of auxiliary machine code to guarantee the
// correct chain execution and to resume the non-obfuscated code execution
// afterwards.
class ROPEngine {
  ROPChain chain;
  XchgState state;
  const BinaryAutopsy &BA;

  ROPChainStatus handleArithmeticRI(llvm::MachineInstr *,
                                    std::vector<unsigned int> &scratchRegs);
  ROPChainStatus handleArithmeticRR(llvm::MachineInstr *,
                                    std::vector<unsigned int> &scratchRegs);
  ROPChainStatus handleArithmeticRM(llvm::MachineInstr *,
                                    std::vector<unsigned int> &scratchRegs);
  ROPChainStatus handleXor32RR(llvm::MachineInstr *,
                               std::vector<unsigned int> &scratchRegs);
  ROPChainStatus handleLea32r(llvm::MachineInstr *,
                              std::vector<unsigned int> &scratchRegs);
  ROPChainStatus handleMov32rm(llvm::MachineInstr *,
                               std::vector<unsigned int> &scratchRegs);
  ROPChainStatus handleMov32mr(llvm::MachineInstr *,
                               std::vector<unsigned int> &scratchRegs);
  ROPChainStatus handleMov32mi(llvm::MachineInstr *,
                               std::vector<unsigned int> &scratchRegs);
  ROPChainStatus handleMov32rr(llvm::MachineInstr *,
                               std::vector<unsigned int> &scratchRegs);
  ROPChainStatus handleMov32ri(llvm::MachineInstr *,
                               std::vector<unsigned int> &scratchRegs);
  ROPChainStatus handleCmp32mi(llvm::MachineInstr *,
                               std::vector<unsigned int> &scratchRegs);
  ROPChainStatus handleCmp32rr(llvm::MachineInstr *,
                               std::vector<unsigned int> &scratchRegs);
  ROPChainStatus handleCmp32ri(llvm::MachineInstr *,
                               std::vector<unsigned int> &scratchRegs);
  ROPChainStatus handleCmp32rm(llvm::MachineInstr *,
                               std::vector<unsigned int> &scratchRegs);
  ROPChainStatus handleJmp1(llvm::MachineInstr *,
                            std::vector<unsigned int> &scratchRegs);
  ROPChainStatus handleJcc1(llvm::MachineInstr *,
                            std::vector<unsigned int> &scratchRegs);
  ROPChainStatus handleCall(llvm::MachineInstr *,
                            std::vector<unsigned int> &scratchRegs);
  ROPChainStatus handleCallReg(llvm::MachineInstr *,
                               std::vector<unsigned int> &scratchRegs);
  bool convertOperandToChainPushImm(const llvm::MachineOperand &operand,
                                    ChainElem &result);

public:
  // Constructor
  ROPEngine(const BinaryAutopsy &BA);

  ROPChainStatus ropify(llvm::MachineInstr &MI,
                        std::vector<unsigned int> &scratchRegs,
                        bool shouldFlagSaved, ROPChain &resultChain);

  void mergeChains(ROPChain &chain1, const ROPChain &chain2);
};

// Generates inline assembly labels that are used in the prologue and epilogue
// of each ROP chain
#endif