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

#include "../X86.h"
#include "../X86InstrBuilder.h"
#include "../X86TargetMachine.h"
#include "BinAutopsy.h"
#include "LivenessAnalysis.h"
#include <tuple>

#ifndef X86ROPUTILS_H
#define X86ROPUTILS_H

enum type_t { GADGET, IMMEDIATE };

struct Stats {
  int processed;
  int replaced;

  Stats() : processed(0), replaced(0){};
};

// Generic element to be put in the chain.
struct ChainElem {
  // type - it can be a GADGET or an IMMEDIATE value. We need to specify the
  // type because we will use different strategies during the creation of
  // machine instructions to push elements of the chain onto the stack.
  type_t type;

  union {
    // value - immediate value
    int64_t value;

    // r - pointer to a microgadget
    const Microgadget *r;
  };

  // s - pointer to a symbol.
  // We bind symbols to chain elements because, if we'd do that to actual
  // microgadgets, it would be fairly easy to predict which gadget is referenced
  // with a symbol, since during the chain execution very few gadgets are
  // executed.
  Symbol *s;

  // Constructor (type: GADGET)
  ChainElem(Microgadget *g);

  // Constructor (type: IMMEDIATE)
  ChainElem(int64_t value);

  // getRelativeAddress - returns the gadget address relative to the symbol it
  // is anchored to.
  uint64_t getRelativeAddress();
};

// Keeps track of all the instructions to be replaced with the obfuscated
// ones. Handles the injection of auxiliary machine code to guarantee the
// correct chain execution and to resume the non-obfuscated code execution
// afterwards.
class ROPChain {
  // globalChainID - just an incremental ID number for all the chains that will
  // be created.
  static int globalChainID;

  // chainID - chain number.
  int chainID;

  // finalized - this flag tells if the chain has to be closed. This happens
  // when an unsupported instruction is encountered: the chain is closed, the
  // unsupported instruction remains untouched, and possibly a new chain is
  // created as soon as a supported instruction is processed.
  bool finalized = false;

  // instructionsToDelete - keeps track of all the instructions that we want to
  // replace with obfuscated ones
  std::vector<llvm::MachineInstr *> instructionsToDelete;

  // chain - holds all the elements of the ROP chain
  std::vector<ChainElem> chain;

public:
  // Labels for inline asm instructions ("C" = colon)
  char chainLabel[16];    // chain_X
  char chainLabel_C[16];  // chain_X:
  char resumeLabel[16];   // resume_X
  char resumeLabel_C[16]; // resume_X:

  // Injection location within the program code
  llvm::MachineBasicBlock *MBB;
  llvm::MachineFunction *MF;
  llvm::MachineInstr *injectionPoint;
  llvm::MCInstrInfo const *TII;

  // SRT - holds data about the available registers that can be used as scratch
  // registers (see LivenessAnalysis).
  ScratchRegTracker &SRT;

  // addInstruction - wrapper method: if a correct binding can be found between
  // the original instruction and some gadgets, the original instruction is put
  // in a vector. We keep track of all the instructions to remove in order to
  // defer the actual deletion to the moment in which we'll inject the ROP
  // Chain. We do this because currently MI is just an iterator
  int addInstruction(llvm::MachineInstr &MI);

  int mapBindings(llvm::MachineInstr &MI);
  void inject();
  void loadEffectiveAddress(int64_t displacement);

  // addImmToReg - adds an immediate value (stored into a scratch register) to
  // the given register.
  x86_reg addImmToReg(x86_reg reg, int immediate,
                      std::vector<x86_reg> scratchRegs);

  // computeAddress - finds the correct set of gadgets such that:
  // the value in "inputReg" is copied in a scratch register, incremented by the
  // value of "displacement", and placed in any register that can be exchanged
  // with "outputReg".
  // The return value is the actual register in which the computed value is
  // saved. This is useful to whom calls this method, in order to create an
  // exchange chain to move the results onto another register.
  x86_reg computeAddress(x86_reg inputReg, int displacement, x86_reg outputReg,
                         std::vector<x86_reg> scratchRegs);

  // pickSuitableGadget -  Among a set of RR gadgets, picks the one that has:
  // 1. as dst operand the register we supply, or at least one that is
  // exchangeable
  // 2. as src operand a register that is at least indirectly initialisable via
  // a scratch register.
  std::tuple<Microgadget *, x86_reg, x86_reg>
  pickSuitableGadget(std::vector<Microgadget *> &RR, x86_reg o_dst,
                     llvm::MachineInstr &MI);

  static BinaryAutopsy *BA;

  // Helper methods
  bool isFinalized();
  void finalize();
  bool isEmpty();

  // Xchg - Helper method. Adds a series of XCHG gadgets to the chain.
  int Xchg(x86_reg a, x86_reg b);
  void DoubleXchg(x86_reg a, x86_reg b, x86_reg c, x86_reg d);

  ROPChain(llvm::MachineBasicBlock &MBB, llvm::MachineInstr &injectionPoint,
           ScratchRegTracker &SRT)
      : MBB(&MBB), injectionPoint(&injectionPoint), SRT(SRT) {
    MF = MBB.getParent();
    TII = MF->getTarget().getMCInstrInfo();
    chainID = globalChainID++;

    // Creates all the labels
    sprintf(chainLabel, ".chain_%d", chainID);
    sprintf(chainLabel_C, ".chain_%d:", chainID);
    sprintf(resumeLabel, ".resume_%d", chainID);
    sprintf(resumeLabel_C, ".resume_%d:", chainID);
  }

  ~ROPChain() { globalChainID--; }
};

#endif