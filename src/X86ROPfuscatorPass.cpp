// ==============================================================================
//   X86 ROPFUSCATOR
//   part of the ROPfuscator project
// ==============================================================================
// This module is simply the frontend of ROPfuscator for LLVM.
//

#include "Debug.h"
#include "ROPfuscatorConfig.h"
#include "ROPfuscatorCore.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/Pass.h"
#include "llvm/PassSupport.h"
#include "llvm/Support/CommandLine.h"
#include "../../X86Subtarget.h"
#include <memory>

#define X86_ROPFUSCATOR_PASS_NAME "x86-ropfuscator"
#define X86_ROPFUSCATOR_PASS_DESC "Obfuscate machine code through ROP chains"

namespace llvm {
// ROPfuscator Machine Pass
void          initializeX86ROPfuscatorPass(PassRegistry &);
FunctionPass *createX86ROPfuscatorPass();
} // namespace llvm

using namespace llvm;

namespace ropf {
namespace {

// ----------------------------------------------------------------
//  COMMAND LINE ARGUMENTS
// ----------------------------------------------------------------
cl::opt<bool> RopfuscatorPassDisabled(
    "fno-ropfuscator",
    cl::desc("Disable code obfuscation via ROP chains"));

cl::opt<std::string> RopfuscatorConfigFile(
    "ropfuscator-config",
    cl::desc("Specify a configuration file path for obfuscation"),
    cl::NotHidden,
    cl::Optional,
    cl::ValueRequired);

cl::opt<std::string> RopfuscatorGadgetLibrary(
    "ropfuscator-library",
    cl::desc("Specify a library to extract gadgets from"),
    cl::NotHidden,
    cl::Optional,
    cl::ValueRequired);

// ----------------------------------------------------------------

class X86ROPfuscator : public MachineFunctionPass {
public:
  static char ID;

  X86ROPfuscator() : MachineFunctionPass(ID), ropfuscator(nullptr) {
    initializeX86ROPfuscatorPass(*PassRegistry::getPassRegistry());
  }

  virtual ~X86ROPfuscator() override {}

  StringRef getPassName() const override { return X86_ROPFUSCATOR_PASS_NAME; }

  bool runOnMachineFunction(MachineFunction &MF) override {
    if (!MF.getSubtarget<X86Subtarget>().is32Bit()) {
      return false;
    }

    if (ropfuscator) {
      ropfuscator->obfuscateFunction(MF);
      return true;
    }

    return false;
  }

  bool doInitialization(Module &module) override {
    if (RopfuscatorPassDisabled) {
      dbg_fmt("[*] ROPfuscator disabled by command-line flag.");
      return false;
    }

    ROPfuscatorConfig config;

    if (!RopfuscatorConfigFile.empty()) {
      config.loadFromFile(RopfuscatorConfigFile);
    }

    if (!config.globalConfig.obfuscationEnabled) {
      dbg_fmt("[*] ROPfuscator disabled in configuration file.\n");
      return false;
    }

    if (RopfuscatorGadgetLibrary.empty() &&
        config.globalConfig.libraryPath.empty()) {
      dbg_fmt("[-] Library not defined. Disabling ROPfuscator.\n");
      return false;
    }
    // assign library from command-line if library has not been
    // set in the configuration file
    if (!RopfuscatorGadgetLibrary.empty() &&
        config.globalConfig.libraryPath.empty()) {
      config.globalConfig.libraryPath = RopfuscatorGadgetLibrary;
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
} // namespace ropf

using ropf::X86ROPfuscator;

FunctionPass *llvm::createX86ROPfuscatorPass() { return new X86ROPfuscator(); }

INITIALIZE_PASS(X86ROPfuscator,
                X86_ROPFUSCATOR_PASS_NAME,
                X86_ROPFUSCATOR_PASS_DESC,
                false,
                false)
