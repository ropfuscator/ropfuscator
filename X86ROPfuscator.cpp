// ==============================================================================
//   X86 ROPFUSCATOR
//   part of the ROPfuscator project
// ==============================================================================
// This module is simply the frontend of ROPfuscator for LLVM.
// It also provides statics about the processed functions.
//

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
};

char X86ROPfuscator::ID = 0;
} // namespace

FunctionPass *llvm::createX86ROPfuscatorPass() { return new X86ROPfuscator(); }

// Generates inline assembly labels that are used in the prologue and epilogue
// of each ROP chain
void generateChainLabels(char **chainLabel, char **chainLabelC,
                         char **resumeLabel, char **resumeLabelC,
                         StringRef funcName, int chainID);

bool X86ROPfuscator::runOnMachineFunction(MachineFunction &MF) {
  // disable ROPfuscator is -fno-ropfuscator flag is passed
  if (ROPfPassDisabled)
    return false;

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
  MCInstrInfo const *TII = MF.getTarget().getMCInstrInfo();

  for (MachineBasicBlock &MBB : MF) {
    // perform register liveness analysis to get a list of registers that can be
    // safely clobbered to compute temporary data
    // TODO: ScratchRegTracker as simple function which returns the hash map
    auto SRT = ScratchRegTracker(MBB);

    ROPChain chain;
    for (MachineInstr &MI : MBB) {
      if (MI.isDebugInstr())
        continue;

      DEBUG_WITH_TYPE(PROCESSED_INSTR, dbgs() << "    " << MI);
      processed++;

      auto ropeng = ROPEngine();
      ROPChain result = ropeng.ropify(MI, *SRT.getRegs(MI));
      if (result.empty()) {
        // unable to obfuscate
        DEBUG_WITH_TYPE(
            PROCESSED_INSTR,
            dbgs() << "\033[31;2m    ✗  Unsupported instruction\033[0m\n");

        // ROP chain injection is deferred until an unsupported instruction is
        // encountered
        if (chain.size() > 0) {
          // EMIT PROLOGUE
          generateChainLabels(&chainLabel, &chainLabelC, &resumeLabel,
                              &resumeLabelC, funcName, chainID);

          // pushf (EFLAGS register backup)
          BuildMI(MBB, MI, nullptr, TII->get(X86::PUSHF32));
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

            case IMMEDIATE: {
              // Push the immediate value onto the stack //
              // push $imm
              BuildMI(MBB, MI, nullptr, TII->get(X86::PUSHi32))
                  .addImm(elem->value);
              break;
            }

            case GADGET: {
              if (OpaquePredicatesEnabled) {
                // call $opaquePredicate
                BuildMI(MBB, MI, nullptr, TII->get(X86::CALLpcrel32))
                    .addExternalSymbol("opaquePredicate");

                // je $wrong_target
                BuildMI(MBB, MI, nullptr, TII->get(X86::JNE_1))
                    .addExternalSymbol(chainLabel);
              }

              // Get a random symbol to reference this gadget in memory
              Symbol *sym = ropeng.BA->getRandomSymbol();
              uint64_t relativeAddr =
                  elem->microgadget->getAddress() - sym->Address;

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
              addDirectMem(BuildMI(MBB, MI, nullptr, TII->get(X86::ADD32mi)),
                           X86::ESP)
                  .addImm(relativeAddr);
              break;
            }
            }
          }

          // EMIT EPILOGUE
          // ret
          BuildMI(MBB, MI, nullptr, TII->get(X86::RETL));
          // resume_funcName_chain_X:
          BuildMI(MBB, MI, nullptr, TII->get(TargetOpcode::INLINEASM))
              .addExternalSymbol(resumeLabelC)
              .addImm(0);
          // popf (EFLAGS register restore)
          BuildMI(MBB, MI, nullptr, TII->get(X86::POPF32));

          chainID++;
          chain.clear();
        }
        // skip to the next instruction
        else
          continue;

      } else {
        // successfully obfuscated
        DEBUG_WITH_TYPE(PROCESSED_INSTR,
                        dbgs() << "\033[32m    ✓  Replaced\033[0m\n");

        // append the obtained chain (result) to the existing one (chain)
        chain.insert(chain.end(), result.begin(), result.end());
        obfuscated++;
        // add current instruction in the To-Delete list
        instrToDelete.push_back(&MI);
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

  // the MachineFunction has been modified
  return true;
}

void generateChainLabels(char **chainLabel, char **chainLabelC,
                         char **resumeLabel, char **resumeLabelC,
                         StringRef funcName, int chainID) {
  using namespace std;
  string funcName_s = funcName.str();
  string chainLabel_s = funcName_s + "_chain_" + to_string(chainID);
  string chainLabelC_s = funcName_s + "_chain_" + to_string(chainID) + ":";
  string resumeLabel_s =
      "resume_" + funcName_s + "_chain_" + to_string(chainID);
  string resumeLabelC_s =
      "resume_" + funcName_s + "_chain_" + to_string(chainID) + ":";

  // we need to allocate these strings on the heap, since they will be
  // used by AsmPrinter *after* runOnMachineFunction() has returned!
  *chainLabel = new char[chainLabel_s.size() + 1];
  *chainLabelC = new char[chainLabelC_s.size() + 1];
  *resumeLabel = new char[resumeLabel_s.size() + 1];
  *resumeLabelC = new char[resumeLabelC_s.size() + 1];

  strcpy(*chainLabel, chainLabel_s.c_str());
  strcpy(*chainLabelC, chainLabelC_s.c_str());
  strcpy(*resumeLabel, resumeLabel_s.c_str());
  strcpy(*resumeLabelC, resumeLabelC_s.c_str());
}

//   DEBUG_WITH_TYPE(PROCESSED_INSTR,
//                   dbgs() << "Processing function: " << funcName.str() <<
//                   "\n");

//   for (MachineBasicBlock &MBB : MF) {
//     std::vector<ROPChain *> ropChains;

//     auto scratchRegTracker = ScratchRegTracker(MBB);

//     for (MachineInstr &MI : MBB) {
//       if (MI.isDebugInstr())
//         continue;
//       if (MI.getFlag(MachineInstr::FrameSetup) ||
//           MI.getFlag(MachineInstr::FrameDestroy))
//         continue;

//       stats.processed++;

//       if (ropChains.empty() || ropChains.back()->isFinalized()) {
//         // Since we are forced to do the actual injection only when the whole
//         // Machine Basic Block has been processed, we have to pass the
//         // MachineInstr by value, because it is an iterator and, at some
//         // point, it will be invalidated.
//         auto *ropChain = new ROPChain(MBB, MI, scratchRegTracker);
//         ropChains.push_back(ropChain);
//       }

//       ROPChain *lastChain = ropChains.back();

//       if (lastChain->addInstruction(MI)) {
//         // DEBUG_WITH_TYPE(PROCESSED_INSTR, dbgs() << "✓ " <<  MI));

//         // DEBUG_WITH_TYPE(ROPCHAIN, dbgs() << "[ROPChain "<<
//         // lastChain->chainLabel << "]",
//         //                                                 ));
//         // for (auto &g : lastChain->instrMap[&MI]) {
//         //   if (g.type == GADGET)
//         //     DEBUG_WITH_TYPE(ROPCHAIN,
//         //                     dbgs() << fmt::format("\t\t{:#018x}: {}\n", 0,
//         // g.microgadget->asmInstr));
//         //   else
//         //     DEBUG_WITH_TYPE(ROPCHAIN, dbgs()
//         //                                   << fmt::format("\t{:^18}:
//         {:#x}\n",
//         //                                                  "Immediate",
//         //                                                  g.value));
//         // }
//         stats.replaced++;
//       } else {
//         // An error means that the current instruction isn't supported, hence
//         // the chain is finalized. When a new supported instruction will be
//         // processed, another chain will be created. This essentially means
//         // that a chain is split every time an un-replaceable instruction is
//         // encountered.

//         DEBUG_WITH_TYPE(PROCESSED_INSTR, dbgs() << "✗ " << MI);

//         if (lastChain->isEmpty()) {
//           // The last created chain is pointless at this point, since it's
//           // empty.
//           delete lastChain;
//           ropChains.pop_back();
//         } else
//           lastChain->finalize();
//       }
//     }

//     // IMPORTANT: the injection must occur only after that the entire Machine
//     // Basic Block has been run through, otherwise an exception is thrown.
//     For
//     // this reason, we use a vector in which we put all the chains to be
//     // injected only at this point.
//     for (ROPChain *rc : ropChains)
//       rc->inject();
//   }

//   // DEBUG_WITH_TYPE(
//   //     OBF_STATS,
//   //     dbgs() << "{}: {}/{} ({}%) instructions obfuscated.\n",
//   //                           funcName.str(), stats.replaced,
//   stats.processed,
//   //                           stats.replaced * 100 / stats.processed));

//   // the MachineFunction has been modified
//   return true;
// }

INITIALIZE_PASS(X86ROPfuscator, X86_ROPFUSCATOR_PASS_NAME,
                X86_ROPFUSCATOR_PASS_DESC, false, false)