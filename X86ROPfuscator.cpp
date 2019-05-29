// ==============================================================================
//   X86 ROPFUSCATOR
//   part of the ROPfuscator project
// ==============================================================================
// This module is simply the frontend of ROPfuscator for LLVM.
// It also provides statics about the processed functions.
//

#include "RopfuscatorDebug.h"
#include "RopfuscatorLivenessAnalysis.h"
#include "X86.h"
#include "X86InstrBuilder.h"
#include "X86MachineFunctionInfo.h"
#include "X86ROPUtils.h"
#include "X86RegisterInfo.h"
#include "X86Subtarget.h"
#include "X86TargetMachine.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include <cmath>
#include <map>
#include <sstream>
#include <string>
#include <utility>

#define X86_ROPFUSCATOR_PASS_NAME "x86-ropfuscator"
#define X86_ROPFUSCATOR_PASS_DESC "Obfuscate machine code through ROP chains"

using namespace llvm;

namespace {
class X86ROPfuscator : public MachineFunctionPass {
public:
  static char ID;

  X86ROPfuscator() : MachineFunctionPass(ID) {
    initializeX86ROPfuscatorPass(*PassRegistry::getPassRegistry());
  }

  StringRef getPassName() const override { return X86_ROPFUSCATOR_PASS_NAME; }
  bool runOnMachineFunction(MachineFunction &MF) override;
};

char X86ROPfuscator::ID = 0;
} // namespace

FunctionPass *llvm::createX86ROPfuscatorPass() { return new X86ROPfuscator(); }

bool X86ROPfuscator::runOnMachineFunction(MachineFunction &MF) {
  Stats stats = Stats();
  StringRef const funcName = MF.getName();

  DEBUG_WITH_TYPE(
      PROCESSED_INSTR,
      dbgs() << fmt::format("Processing function: {}\n", funcName.str()));

  for (MachineBasicBlock &MBB : MF) {
    std::vector<ROPChain *> ropChains;

    auto scratchRegTracker = ScratchRegTracker(MBB);

    for (MachineInstr &MI : MBB) {
      if (MI.isDebugInstr())
        continue;
      if (MI.getFlag(MachineInstr::FrameSetup) ||
          MI.getFlag(MachineInstr::FrameDestroy))
        continue;

      stats.processed++;

      if (ropChains.empty() || ropChains.back()->isFinalized()) {
        // Since we are forced to do the actual injection only when the whole
        // Machine Basic Block has been processed, we have to pass the
        // MachineInstr by value, because it is an iterator and, at some
        // point, it will be invalidated.
        auto *ropChain = new ROPChain(MBB, MI, scratchRegTracker);
        ropChains.push_back(ropChain);
      }

      ROPChain *lastChain = ropChains.back();

      if (lastChain->addInstruction(MI)) {
        DEBUG_WITH_TYPE(
            PROCESSED_INSTR,
            dbgs() << fmt::format("{}[✓ {:^14}]{} {}\n", COLOR_GREEN,
                                  lastChain->chainLabel, COLOR_RESET, MI));
        stats.replaced++;
      } else {
        // An error means that the current instruction isn't supported, hence
        // the chain is finalized. When a new supported instruction will be
        // processed, another chain will be created. This essentially means
        // that a chain is split every time an un-replaceable instruction is
        // encountered.

        DEBUG_WITH_TYPE(PROCESSED_INSTR,
                        dbgs() << fmt::format("{}[✗ {:^14}]{} {}\n", COLOR_RED,
                                              "Unsupported", COLOR_RESET, MI));

        if (lastChain->isEmpty()) {
          // The last created chain is pointless at this point, since it's
          // empty.
          delete lastChain;
          ropChains.pop_back();
        } else
          lastChain->finalize();
      }
    }

    // IMPORTANT: the injection must occur only after that the entire Machine
    // Basic Block has been run through, otherwise an exception is thrown. For
    // this reason, we use a vector in which we put all the chains to be
    // injected only at this point.
    for (ROPChain *rc : ropChains)
      rc->inject();
  }

  DEBUG_WITH_TYPE(
      OBF_STATS,
      dbgs() << fmt::format("{}: {}/{} ({}%) instructions obfuscated.\n",
                            funcName.str(), stats.replaced, stats.processed,
                            stats.replaced * 100 / stats.processed));

  // the MachineFunction has been modified
  return true;
}

INITIALIZE_PASS(X86ROPfuscator, X86_ROPFUSCATOR_PASS_NAME,
                X86_ROPFUSCATOR_PASS_DESC, false, false)