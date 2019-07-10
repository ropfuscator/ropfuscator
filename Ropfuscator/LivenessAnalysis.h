// ==============================================================================
//   LIVENESS ANALYSIS
//   part of the ROPfuscator project
// ==============================================================================
// This module tracks the availability of spare registers to be used as scratch
// registers during the ROP chain execution.
//
// Since we have to replace arbitrary instructions with a set of microgadgets,
// the only way to reproduce the same semantic of the input instruction is to
// chain many different microgadgets one after another.
// While this is not a problem when dealing with simple instructions, things get
// a little bit harder when it comes to compute temporary values, such
// immediates or memory offsets.
// In these cases, we have to use a register to momentary store such values.
// Obviously we cannot choose a random one, otherwise we could corrupt some
// useful data that would have been used by the next instructions in the basic
// block.
//
// For this reason we perform a data-flow analysis here: we keep track of all
// the registers that are available before each single instruction has been
// executed.

#ifndef LIVENESSANALYSIS_H
#define LIVENESSANALYSIS_H

#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <map>
#include <vector>

// ScratchRegTracker - tracks the availability of scratch registers with
// single-instruction granularity.
class ScratchRegTracker {
private:
  // regs - maps each instruction with an array of available scratch registers.
  std::map<llvm::MachineInstr *, std::vector<x86_reg>> regs;

  // MBB - pointer to the basic block on which the analysis is performed.
  llvm::MachineBasicBlock &MBB;

  // addInstr - adds a new MachineInstr entry on the map, with an empty vector.
  void addInstr(llvm::MachineInstr &MI);

  // addReg - adds a new scratch register.
  void addReg(llvm::MachineInstr &MI, int reg);

  // performLivenessAnalysis - performs the data-flow analysis and fills the map
  // above.
  void performLivenessAnalysis();

  // findRegs - just a backend search function that returns a pointer to the
  // array of available registers.
  std::vector<x86_reg> *findRegs(llvm::MachineInstr &MI);

public:
  // Constructor
  ScratchRegTracker(llvm::MachineBasicBlock &MBB);

  // getRegs - returns an array of all the scratch registers available before
  // the given instruction.
  std::vector<x86_reg> *getRegs(llvm::MachineInstr &MI);

  // getReg - returns a scratch register.
  x86_reg getReg(llvm::MachineInstr &MI);

  // count - returns the number of available scratch registers.
  int count(llvm::MachineInstr &MI);
};

#endif