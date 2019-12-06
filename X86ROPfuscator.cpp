// ==============================================================================
//   X86 ROPFUSCATOR
//   part of the ROPfuscator project
// ==============================================================================
// This module is simply the frontend of ROPfuscator for LLVM.
// It also provides statics about the processed functions.
//

#include "Ropfuscator/BinAutopsy.h"
#include "Ropfuscator/Debug.h"
#include "Ropfuscator/LivenessAnalysis.h"
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

#define ROPFUSCATOR_INSTRUCTION_STAT

#ifdef ROPFUSCATOR_INSTRUCTION_STAT
struct ROPChainStatEntry {
  static const int entry_size = static_cast<int>(ROPChainStatus::COUNT);
  int data[entry_size];
  int &operator[](ROPChainStatus status) {
    return data[static_cast<int>(status)];
  }
  int operator[](ROPChainStatus status) const {
    return data[static_cast<int>(status)];
  }
  int total() const {
    return std::accumulate(&data[0], &data[entry_size], 0);
  }
  ROPChainStatEntry() {
    memset(data, 0, sizeof(data));
  }
  friend llvm::raw_ostream &operator<<(llvm::raw_ostream &os, const ROPChainStatEntry &entry) {
    os << "stat:ropfuscated " << entry[ROPChainStatus::OK]
       << " / total " << entry.total() << " ["
       << " not-implemented: " << entry[ROPChainStatus::ERR_NOT_IMPLEMENTED]
       << " no-register: " << entry[ROPChainStatus::ERR_NO_REGISTER_AVAILABLE]
       << " no-gadget: " << entry[ROPChainStatus::ERR_NO_GADGETS_AVAILABLE]
       << " unsupported: " << entry[ROPChainStatus::ERR_UNSUPPORTED]
       << " unsupported-esp: " << entry[ROPChainStatus::ERR_UNSUPPORTED_STACKPOINTER]
       << " ]";
    return os;
  }
};
#endif

using namespace llvm;

// ----------------------------------------------------------------
//  COMMAND LINE ARGUMENTS
// ----------------------------------------------------------------
static cl::opt<bool>
    ROPfPassDisabled("fno-ropfuscator",
                     cl::desc("Disable code obfuscation via ROP chains"));

static cl::opt<bool> OpaquePredicatesEnabled(
    "fopaque-predicates",
    cl::desc("Enable the injection of opaque predicates"));

// ----------------------------------------------------------------

namespace {
class X86ROPfuscator : public MachineFunctionPass {
public:
  static char ID;

  X86ROPfuscator() : MachineFunctionPass(ID) {
    initializeX86ROPfuscatorPass(*PassRegistry::getPassRegistry());
  }

  StringRef getPassName() const override { return X86_ROPFUSCATOR_PASS_NAME; }
  bool runOnMachineFunction(MachineFunction &MF) override;

private:
  void insertROPChain(MachineFunction &MF, const ROPChain &chain,
                      MachineBasicBlock &MBB, MachineInstr &MI,
                      const TargetInstrInfo *TII, BinaryAutopsy *BA,
                      int chainID, bool shouldFlagSaved,
                      bool isFlagModifiedInInstr);
};

char X86ROPfuscator::ID = 0;
} // namespace

FunctionPass *llvm::createX86ROPfuscatorPass() { return new X86ROPfuscator(); }

// ----------------------------------------------------------------

void X86ROPfuscator::insertROPChain(MachineFunction &MF, const ROPChain &chain,
                                    MachineBasicBlock &MBB, MachineInstr &MI,
                                    const TargetInstrInfo *TII,
                                    BinaryAutopsy *BA, int chainID,
                                    bool shouldFlagSaved,
                                    bool isFlagModifiedInInstr) {

  char *chainLabel, *chainLabelC, *resumeLabel, *resumeLabelC;
  // EMIT PROLOGUE
  generateChainLabels(&chainLabel, &chainLabelC, &resumeLabel, &resumeLabelC,
                      MF.getName(), chainID);

  if (shouldFlagSaved) {
    // save eflags
    if (isFlagModifiedInInstr) {
      // If the obfuscated instruction will modify flags,
      // the flags should be restored after ROP chain is constructed
      // and just before the ROP chain is executed.
      // flag is saved at the top of the stack

      // lea esp, [esp-4*(N+1)]   # where N = chain size
      BuildMI(MBB, MI, nullptr, TII->get(X86::LEA32r), X86::ESP)
          .addReg(X86::ESP)
          .addImm(1)
          .addReg(0)
          .addImm(-4 * (chain.size() + 1))
          .addReg(0);
      // pushf (EFLAGS register backup)
      BuildMI(MBB, MI, nullptr, TII->get(X86::PUSHF32));

      // lea esp, [esp+4*(N+2)]   # where N = chain size
      BuildMI(MBB, MI, nullptr, TII->get(X86::LEA32r), X86::ESP)
          .addReg(X86::ESP)
          .addImm(1)
          .addReg(0)
          .addImm(4 * (chain.size() + 2))
          .addReg(0);
    } else {
      // If the obfuscated instruction will NOT modify flags,
      // (and if the chain execution might modify the flags,)
      // the flags should be restored after the ROP chain is executed.
      // flag is saved at the bottom of the stack
      // pushf (EFLAGS register backup)
      BuildMI(MBB, MI, nullptr, TII->get(X86::PUSHF32));
    }
  }
  // call funcName_chain_X
  BuildMI(MBB, MI, nullptr, TII->get(X86::CALLpcrel32))
      .addExternalSymbol(chainLabel);
  // jmp resume_funcName_chain_X
  BuildMI(MBB, MI, nullptr, TII->get(X86::JMP_1))
      .addExternalSymbol(resumeLabel);
  // funcName_chain_X:
  BuildMI(MBB, MI, nullptr, TII->get(TargetOpcode::INLINEASM))
      .addExternalSymbol(chainLabelC)
      .addImm(0);

  // ROP Chain
  // Pushes each chain element on the stack in reverse order
  for (auto elem = chain.rbegin(); elem != chain.rend(); ++elem) {
    switch (elem->type) {

    case ChainElem::Type::IMM_VALUE: {
      // Push the immediate value onto the stack //
      // push $imm
      BuildMI(MBB, MI, nullptr, TII->get(X86::PUSHi32)).addImm(elem->value);
      break;
    }

    case ChainElem::Type::IMM_GLOBAL: {
      // Push the global symbol onto the stack
      // push global_symbol
      BuildMI(MBB, MI, nullptr, TII->get(X86::PUSHi32))
          .addGlobalAddress(elem->global, elem->value);
      break;
    }

    case ChainElem::Type::GADGET: {
      if (OpaquePredicatesEnabled) {
        // call $opaquePredicate
        BuildMI(MBB, MI, nullptr, TII->get(X86::CALLpcrel32))
            .addExternalSymbol("opaquePredicate");

        // je $wrong_target
        BuildMI(MBB, MI, nullptr, TII->get(X86::JNE_1))
            .addExternalSymbol(chainLabel);
      }

      // Get a random symbol to reference this gadget in memory
      Symbol *sym = BA->getRandomSymbol();
      uint64_t relativeAddr = elem->microgadget->getAddress() - sym->Address;

      // .symver directive: necessary to prevent aliasing when more
      // symbols have the same name. We do this exclusively when the
      // symbol Version is not "Base" (i.e., it is the only one
      // available).
      if (strcmp(sym->Version, "Base") != 0) {
        BuildMI(MBB, MI, nullptr, TII->get(TargetOpcode::INLINEASM))
            .addExternalSymbol(sym->getSymVerDirective())
            .addImm(0);
      }

      // push $symbol
      BuildMI(MBB, MI, nullptr, TII->get(X86::PUSHi32))
          .addExternalSymbol(sym->Label);

      // add [esp], $offset
      addDirectMem(BuildMI(MBB, MI, nullptr, TII->get(X86::ADD32mi)), X86::ESP)
          .addImm(relativeAddr);
      break;
    }
    }
  }

  // EMIT EPILOGUE
  // restore eflags, if eflags should be restored BEFORE chain execution
  if (shouldFlagSaved && isFlagModifiedInInstr) {
    // lea esp, [esp-4]
    BuildMI(MBB, MI, nullptr, TII->get(X86::LEA32r), X86::ESP)
        .addReg(X86::ESP)
        .addImm(1)
        .addReg(0)
        .addImm(-4)
        .addReg(0);
    // popf (EFLAGS register restore)
    BuildMI(MBB, MI, nullptr, TII->get(X86::POPF32));
  }
  // ret
  BuildMI(MBB, MI, nullptr, TII->get(X86::RETL));
  // resume_funcName_chain_X:
  BuildMI(MBB, MI, nullptr, TII->get(TargetOpcode::INLINEASM))
      .addExternalSymbol(resumeLabelC)
      .addImm(0);
  // restore eflags, if eflags should be restored AFTER chain execution
  if (shouldFlagSaved && !isFlagModifiedInInstr) {
    // popf (EFLAGS register restore)
    BuildMI(MBB, MI, nullptr, TII->get(X86::POPF32));
  }
}

bool X86ROPfuscator::runOnMachineFunction(MachineFunction &MF) {
  // disable ROPfuscator is -fno-ropfuscator flag is passed
  if (ROPfPassDisabled)
    return false;

  // create a new singleton instance of Binary Autopsy
  std::string libraryPath;
  getLibraryPath(libraryPath);
  BinaryAutopsy *BA = BinaryAutopsy::getInstance(libraryPath);
  BA->analyseUsedSymbols(MF.getFunction().getParent());

  // stats
  int processed = 0, obfuscated = 0;
  StringRef const funcName = MF.getName();

  // ASM labels for each ROP chain
  int chainID = 0;
  char *chainLabel, *chainLabelC, *resumeLabel, *resumeLabelC;

  // original instructions that have been successfully ROPified and that will be
  // removed at the end
  std::vector<MachineInstr *> instrToDelete;

  // description of the target ISA (used to generate new instructions, below)
  X86InstrInfo const *TII = MF.getSubtarget<X86Subtarget>().getInstrInfo();

#ifdef ROPFUSCATOR_INSTRUCTION_STAT
  static std::map<unsigned, ROPChainStatEntry> instr_stat;
#endif

  for (MachineBasicBlock &MBB : MF) {
    // perform register liveness analysis to get a list of registers that can be
    // safely clobbered to compute temporary data
    ScratchRegMap MBBScratchRegs = performLivenessAnalysis(MBB);

    for (auto it = MBB.begin(), it_end = MBB.end(); it != it_end; ++it) {
      MachineInstr &MI = *it;

      if (MI.isDebugInstr())
        continue;

      DEBUG_WITH_TYPE(PROCESSED_INSTR, dbgs() << "    " << MI);
      processed++;

      // get the list of scratch registers available for this instruction
      std::vector<x86_reg> MIScratchRegs = MBBScratchRegs.find(&MI)->second;

      // Do this instruction and/or following instructions
      // use current flags (i.e. affected by current flags)?
      bool shouldFlagSaved = !TII->isSafeToClobberEFLAGS(MBB, it);
      // Does this instruction modify (define/kill) flags?
      bool isFlagModifiedInInstr = false;
      // Example instruction sequence describing how these booleans are set:
      //   mov eax, 1    # false, false
      //   add eax, 1    # false, true
      //   cmp eax, ebx  # false, true
      //   mov ecx, 1    # true,  false (caution!)
      //   mov edx, 2    # true,  false (caution!)
      //   je .Local1    # true,  false
      //   add eax, ebx  # false, true
      //   adc ecx, edx  # true,  true
      //   adc ecx, 1    # true,  true

      ROPChain result;
      ROPChainStatus status =
          ROPEngine().ropify(MI, MIScratchRegs, isFlagModifiedInInstr, result);

#ifdef ROPFUSCATOR_INSTRUCTION_STAT
      instr_stat[MI.getOpcode()][status]++;
#endif

      if (status != ROPChainStatus::OK) {
        // unable to obfuscate
        DEBUG_WITH_TYPE(
            PROCESSED_INSTR,
            dbgs() << "\033[31;2m    ✗  Unsupported instruction\033[0m\n");

        continue;
      } else {
        // add current instruction in the To-Delete list
        instrToDelete.push_back(&MI);
        insertROPChain(MF, result, MBB, MI, TII, BA, chainID, shouldFlagSaved,
                       isFlagModifiedInInstr);

        // successfully obfuscated
        DEBUG_WITH_TYPE(PROCESSED_INSTR,
                        dbgs() << "\033[32m    ✓  Replaced\033[0m\n");
        chainID++;
        obfuscated++;
      }
    }

    // delete old vanilla instructions only after we finished to iterate through
    // the basic block
    for (auto &MI : instrToDelete)
      MI->eraseFromParent();

    instrToDelete.clear();
  }

  // print obfuscation stats for this function
  DEBUG_WITH_TYPE(OBF_STATS, dbgs() << "   " << funcName << ":  \t"
                                    << obfuscated << "/" << processed << " ("
                                    << (obfuscated * 100) / processed
                                    << "%) instructions obfuscated\n");
#ifdef ROPFUSCATOR_INSTRUCTION_STAT
  for (auto &kv : instr_stat) {
    DEBUG_WITH_TYPE(OBF_STATS, dbgs() << kv.first << " = " << TII->getName(kv.first)
                                      << " : " << kv.second << "\n");
  }
#endif
  // the MachineFunction has been modified
  return true;
}

INITIALIZE_PASS(X86ROPfuscator, X86_ROPFUSCATOR_PASS_NAME,
                X86_ROPFUSCATOR_PASS_DESC, false, false)