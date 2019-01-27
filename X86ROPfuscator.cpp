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
#include "BinAutopsy.h"
#include "LivenessAnalysis.h"
//#include "X86ROPUtils.h"
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

static cl::opt<std::string> BinaryPath(
    "lib", cl::desc("path to the library from which gadgets must be extracted"),
    cl::NotHidden, cl::Optional, cl::ValueRequired);

namespace {
struct X86ROPfuscationPass : public MachineFunctionPass {
  static char ID;

  X86ROPfuscationPass() : MachineFunctionPass(ID) {
    StringRef binPath = StringRef(BinaryPath.getValue());
    if (binPath.empty()) {
      dbgs() << "[*] No 'lib' argument supplied. Using LIBC\n";
      binPath = "/lib/i386-linux-gnu/libc.so.6";
    }

    std::BinaryAutopsy BinAutopsy =
        std::BinaryAutopsy(binPath).extractGadgets();
  }
  bool doInitialization(Module &M);
  bool runOnMachineFunction(MachineFunction &MF);
};

char X86ROPfuscationPass::ID = 0;
} // namespace

FunctionPass *llvm::createX86ROPfuscationPass() {
  BinAutopsy.extractGadgets();
  return new X86ROPfuscationPass();
}

bool X86ROPfuscationPass::doInitialization(Module &M) { return false; }

bool X86ROPfuscationPass::runOnMachineFunction(MachineFunction &MF) {

  return true;
}
