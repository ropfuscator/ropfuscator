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
#include <map>
#include <vector>

// ScratchRegMap - associative map to bind a specific MachineInstr to a list of
// available scratch registers
typedef std::map<llvm::MachineInstr *, std::vector<unsigned int>> ScratchRegMap;

void addReg(llvm::MachineInstr &MI, int reg, ScratchRegMap &regs);

ScratchRegMap performLivenessAnalysis(llvm::MachineBasicBlock &MBB);

#endif