// ==============================================================================
//   X86 ROPFUSCATOR
//   part of the ROPfuscator project
// ==============================================================================
// This module is simply the frontend of ROPfuscator for LLVM.
//

#include "ROPfuscatorConfig.h"
#include "ROPfuscatorCore.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/Pass.h"
#include "llvm/PassSupport.h"
#include "llvm/Support/CommandLine.h"
#include <memory>

#define X86_ROPFUSCATOR_PASS_NAME "x86-ropfuscator"
#define X86_ROPFUSCATOR_PASS_DESC "Obfuscate machine code through ROP chains"

namespace llvm {
// ROPfuscator Machine Pass
void initializeX86ROPfuscatorPass(PassRegistry &);
FunctionPass *createX86ROPfuscatorPass();
} // namespace llvm

using namespace llvm;

// ----------------------------------------------------------------
//  COMMAND LINE ARGUMENTS
// ----------------------------------------------------------------
static cl::opt<bool>
    ROPfPassDisabled("fno-ropfuscator",
                     cl::desc("Disable code obfuscation via ROP chains"));

static cl::opt<std::string> RopfuscatorConfigFile(
    "ropfuscator-config",
    cl::desc("Specify a configuration file path for obfuscation"),
    cl::NotHidden, cl::Optional, cl::ValueRequired);

// ----------------------------------------------------------------

namespace {
class X86ROPfuscator : public MachineFunctionPass {
public:
  static char ID;

  X86ROPfuscator() : MachineFunctionPass(ID), ropfuscator(nullptr) {
    initializeX86ROPfuscatorPass(*PassRegistry::getPassRegistry());
  }

  virtual ~X86ROPfuscator() override {}

  StringRef getPassName() const override { return X86_ROPFUSCATOR_PASS_NAME; }

  bool runOnMachineFunction(MachineFunction &MF) override {
    if (ropfuscator) {
      ropfuscator->obfuscateFunction(MF);
      return true;
    }

    return false;
  }

  bool doInitialization(Module &module) override {
    if (ROPfPassDisabled) {
      return false;
    }

    ROPfuscatorConfig config;

    if (!RopfuscatorConfigFile.empty()) {
      config.loadFromFile(RopfuscatorConfigFile);
    }

    ropfuscator = new ROPfuscatorCore(module, config);

    return true;
  }

  bool doFinalization(Module &) override {
    if (ropfuscator) {
      delete ropfuscator;
      ropfuscator = nullptr;
    }

    return true;
  }

private:
  ROPfuscatorCore *ropfuscator;
};

char X86ROPfuscator::ID = 0;
} // namespace

FunctionPass *llvm::createX86ROPfuscatorPass() { return new X86ROPfuscator(); }

INITIALIZE_PASS(X86ROPfuscator, X86_ROPFUSCATOR_PASS_NAME,
                X86_ROPFUSCATOR_PASS_DESC, false, false)
