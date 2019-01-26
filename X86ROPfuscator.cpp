//===-- X86ROPfuscationPass.cpp - ROP Obfuscation Prototype pass
//---------------------------===//
//
// Written by Daniele Ferla.
//
//===----------------------------------------------------------------------===//
//
// This file implements an obfuscating transformation prototype
// as a MachineFunctionPass.
//
//===----------------------------------------------------------------------===//
#include "../X86.h"
#include "../X86InstrBuilder.h"
#include "../X86MachineFunctionInfo.h"
#include "../X86RegisterInfo.h"
#include "../X86Subtarget.h"
#include "../X86TargetMachine.h"
#include "LivenessAnalysis.h"
#include "X86ROPUtils.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include <cmath>
#include <map>
#include <sstream>
#include <string>
#include <utility>

using namespace llvm;

namespace {
struct X86ROPfuscationPass : public MachineFunctionPass {
  static char ID;

  X86ROPfuscationPass() : MachineFunctionPass(ID) {}

  bool runOnMachineFunction(MachineFunction &MF);
};

char X86ROPfuscationPass::ID = 0;
} // namespace

FunctionPass *llvm::createX86ROPfuscationPass() {
  return new X86ROPfuscationPass();
}

bool X86ROPfuscationPass::runOnMachineFunction(MachineFunction &MF) {

  Stats stats = Stats();
  StringRef const funcName = MF.getName();
  dbgs() << "\n[*] Processing function: " << funcName << "\n";

  for (MachineBasicBlock &MBB : MF) {
    std::vector<ROPChain *> ropChains;

    registerLivenessAnalysis(MBB);

    for (MachineInstr &MI : MBB) {
      if (!(MI.getFlag(MachineInstr::FrameSetup) ||
            MI.getFlag(MachineInstr::FrameDestroy))) {

        dbgs() << "\n* " << MI;
        while (int r = deadRegs.getScratchRegister(MI))
          dbgs() << "live: " << r << "\n";

        stats.processed++;

        if (ropChains.empty() || ropChains.back()->isFinalized()) {
          /* Since we are forced to do the actual injection only when the whole
           * Machine Basic Block has been processed, we have to pass the
           * MachineInstr by value, because it is an iterator and, at some
           * point, it will be invalidated. */
          ROPChain *ropChain = new ROPChain(MBB, MI);
          ropChains.push_back(ropChain);
        }

        ROPChain *lastChain = ropChains.back();

        int err = lastChain->addInstruction(MI);
        if (err) {
          /* An error means that the current instruction isn't supported, hence
           * the chain is finalized. When a new supported instruction will be
           * processed, another chain will be created. This essentially means
           * that a chain is split every time an un-replaceable instruction is
           * encountered. */
          // dbgs() << "\033[31;2m    ✗  Unsupported instruction\033[0m\n";
          if (lastChain->isEmpty()) {
            /* The last created chain is pointless at this point, since it's
             * empty. */
            delete lastChain;
            ropChains.pop_back();
          } else
            lastChain->finalize();
        } else {
          // dbgs() << "\033[32m    ✓  Replaced\033[0m\n";
          stats.replaced++;
        }
      }
    }

    /* IMPORTANT: the injection must occur only after that the entire Machine
     * Basic Block has been run through, otherwise an exception is thrown. For
     * this reason, we use a vector in which we put all the chains to be
     * injected only at this point. */
    for (ROPChain *rc : ropChains) {
      dbgs() << " >  Injecting ROP Chain: " << rc->chainLabel << "\n";
      rc->inject();
    }
  }

  dbgs() << "\n--------------------------------------------\n";
  dbgs() << " \033[1mSTATISTICS for function \033[4m" << funcName
         << "\033[24m:\n";
  dbgs() << "   Total instr.:\t" << stats.processed << "\n";
  dbgs() << "   Replaced:\t\t" << stats.replaced << " ("
         << (stats.replaced * 100) / stats.processed << "%)\033[0m";
  dbgs() << "\n--------------------------------------------\n";

  // the MachineFunction has been modified
  return true;
}
