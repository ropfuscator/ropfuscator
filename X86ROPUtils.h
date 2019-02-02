//
// Created by Daniele Ferla on 22/10/2018.
//

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

struct ChainElem {
  // Element to be pushed onto the stack (gadget or immediate value)
  // Each ChainElem is associated with a specific symbol: by doing this, we can
  // avoid to associate one gadget with always the same symbol
  type_t type;
  union {
    int64_t value;
    const Microgadget *r;
  };
  Symbol *s;

  ChainElem(Microgadget *g);

  ChainElem(int64_t value);

  uint64_t getRelativeAddress();
};

class ROPChain {
  // Keeps track of all the instructions to be replaced with the obfuscated
  // ones. Handles the injection of auxiliary machine code to guarantee the
  // correct chain execution and to resume the non-obfuscated code execution
  // afterwards.

  // IDs
  static int globalChainID;
  int chainID;

  // A finalized chain can't get gadgets anymore
  bool finalized = false;

  // Input instructions that we want to replace with obfuscated ones
  std::vector<llvm::MachineInstr *> instructionsToDelete;

  // Gadgets to be pushed onto the stack during the injection phase
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
  std::tuple<Microgadget *, x86_reg, x86_reg>

  // pickSuitableGadget -  Among a set of RR gadgets, picks the one that has:
  // 1. as dst operand the register we supply, or at least one that is
  // exchangeable
  // 2. as src operand a register that is at least indirectly initialisable via
  // a scratch register.
  pickSuitableGadget(std::vector<Microgadget> &RR, x86_reg o_dst,
                     llvm::MachineInstr &MI);

  static BinaryAutopsy *BA;

  // Helper methods
  bool isFinalized();
  void finalize();
  bool isEmpty();

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