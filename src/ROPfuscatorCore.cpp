// ==============================================================================
//   X86 ROPFUSCATOR
//   part of the ROPfuscator project
// ==============================================================================
// This module is simply the frontend of ROPfuscator for LLVM.
// It also provides statics about the processed functions.
//

#include "ROPfuscatorCore.h"
#include "BinAutopsy.h"
#include "Debug.h"
#include "LivenessAnalysis.h"
#include "OpaqueConstruct.h"
#include "ROPEngine.h"
#include "ROPfuscatorConfig.h"
#include "X86.h"
#include "X86AssembleHelper.h"
#include "X86MachineFunctionInfo.h"
#include "X86RegisterInfo.h"
#include "X86Subtarget.h"
#include "X86TargetMachine.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include <cmath>
#include <map>
#include <sstream>
#include <string>
#include <utility>

using namespace llvm;

#if __GNUC__
#if __x86_64__ || __ppc64__
#define ARCH_64
const std::string POSSIBLE_LIBC_FOLDERS[] = {"/lib32", "/usr/lib32",
                                             "/usr/local/lib32"};
#else
#define ARCH_32
const std::string POSSIBLE_LIBC_FOLDERS[] = {"/lib", "/usr/lib",
                                             "/usr/local/lib"};
#endif
#endif

const bool obfuscateImmediateOperand = true;

void generateChainLabels(std::string &chainLabel, std::string &resumeLabel,
                         StringRef funcName, int chainID) {
  chainLabel = fmt::format("{}_chain_{}", funcName.str(), chainID);
  resumeLabel = fmt::format("resume_{}", chainLabel);

  // replacing $ with _
  std::replace(chainLabel.begin(), chainLabel.end(), '$', '_');
}

#ifdef ROPFUSCATOR_INSTRUCTION_STAT
struct ROPfuscatorCore::ROPChainStatEntry {
  static const int entry_size = static_cast<int>(ROPChainStatus::COUNT);
  int data[entry_size];

  int &operator[](ROPChainStatus status) {
    return data[static_cast<int>(status)];
  }

  int operator[](ROPChainStatus status) const {
    return data[static_cast<int>(status)];
  }

  int total() const { return std::accumulate(&data[0], &data[entry_size], 0); }

  ROPChainStatEntry() { memset(data, 0, sizeof(data)); }

  static constexpr const char *DEBUG_FMT_NORMAL =
      "stat: ropfuscated {0} / total {6}\n[not-implemented: {1} | "
      "no-register: {2} | no-gadget: {3} "
      "| unsupported: {4} | unsupported-esp: {5}]";
  static constexpr const char *DEBUG_FMT_SIMPLE =
      "{0}\t{1}\t{2}\t{3}\t{4}\t{5}\t{6}";

  std::ostream &print_to(std::ostream &os, const char *fmt) const {
    const ROPChainStatEntry &entry = *this;
    fmt::print(os, fmt, entry[ROPChainStatus::OK],
               entry[ROPChainStatus::ERR_NOT_IMPLEMENTED],
               entry[ROPChainStatus::ERR_NO_REGISTER_AVAILABLE],
               entry[ROPChainStatus::ERR_NO_GADGETS_AVAILABLE],
               entry[ROPChainStatus::ERR_UNSUPPORTED],
               entry[ROPChainStatus::ERR_UNSUPPORTED_STACKPOINTER],
               entry.total());
    return os;
  }

  friend std::ostream &operator<<(std::ostream &os,
                                  const ROPChainStatEntry &entry) {
    return entry.print_to(os, DEBUG_FMT_NORMAL);
  }

  std::string to_string(const char *fmt) const {
    std::stringstream ss;
    print_to(ss, fmt);
    return ss.str();
  }

  static std::string header_string(const char *fmt) {
    return fmt::format(fmt, "ropfuscated", "not-implemented", "no-register",
                       "no-gadget", "unsupported", "unsupported-esp", "total");
  }
};
#endif

static bool findLibcRecursive(const llvm::Twine &path, std::string &libraryPath,
                              int current_depth) {
  if (current_depth == 0) {
    return false;
  }

  std::error_code ec;
  auto dir_it = llvm::sys::fs::directory_iterator(path, ec);
  auto dir_end = llvm::sys::fs::directory_iterator();

  // searching for libc in regular files only
  while (!ec && dir_it != dir_end) {
    auto st = dir_it->status();
    if (st && st->type() == llvm::sys::fs::file_type::regular_file &&
        llvm::sys::path::filename(dir_it->path()) == "libc.so.6") {
      libraryPath = dir_it->path();
      // dbg_fmt("libc found here: {}\n", libraryPath);

      return true;
    }
    dir_it.increment(ec);
  }

  // could not find libc, recursing into directories
  dir_it = llvm::sys::fs::directory_iterator(path, ec);

  while (!ec && dir_it != dir_end) {
    auto st = dir_it->status();
    if (st && st->type() == llvm::sys::fs::file_type::directory_file) {
      // recurse into dir
      // dbg_fmt("recursing into: {}\n", dir_it->path());
      if (findLibcRecursive(dir_it->path(), libraryPath, current_depth - 1))
        return true;
    }
    dir_it.increment(ec);
  }

  return false;
}

static std::string findLibcPath() {
  std::string libraryPath;
  int maxrecursedepth = 3;

  for (auto &folder : POSSIBLE_LIBC_FOLDERS) {
    if (findLibcRecursive(folder, libraryPath, maxrecursedepth)) {
      dbg_fmt("[*] Using library path: {}\n", libraryPath);
      return libraryPath;
    }
  }

  return "";
}

// ----------------------------------------------------------------

ROPfuscatorCore::ROPfuscatorCore(llvm::Module &module,
                                 const ROPfuscatorConfig &config)
    : config(config), BA(nullptr), TII(nullptr) {}

ROPfuscatorCore::~ROPfuscatorCore() {
#ifdef ROPFUSCATOR_INSTRUCTION_STAT
  if (config.globalConfig.printInstrStat) {
    dbg_fmt(
        "{}\t{}\t{}\n", "op-id", "op-name",
        ROPChainStatEntry::header_string(ROPChainStatEntry::DEBUG_FMT_SIMPLE));
    for (auto &kv : instr_stat) {
      dbg_fmt("{}\t{}\t{}\n", kv.first, TII->getName(kv.first),
              kv.second.to_string(ROPChainStatEntry::DEBUG_FMT_SIMPLE));
    }
  }
#endif
}

void ROPfuscatorCore::insertROPChain(const ROPChain &chain,
                                     MachineBasicBlock &MBB, MachineInstr &MI,
                                     int chainID,
                                     const ObfuscationParameter &param) {
  std::string chainLabel, resumeLabel;
  auto as = X86AssembleHelper(MBB, MI.getIterator());

  generateChainLabels(chainLabel, resumeLabel, MBB.getParent()->getName(),
                      chainID);

  bool isLastInstrInBlock = MI.getNextNode() == nullptr;
  bool resumeLabelRequired = false;
  std::map<int, int> espOffsetMap;
  int espoffset = 0;

  // stack layout:
  // 1. saved-regs (and flags, if FlagSaveMode == SAVE_BEFORE_EXEC)
  // 2. ROP chain
  // 3. flags (if FlagSaveMode == SAVE_AFTER_EXEC)
  // 4. return addr (if jump instruction is not ropfuscated)

  std::set<unsigned int> savedRegs;
  savedRegs.insert(X86::EFLAGS); // flags are modified generally
  // generate opaque constants before insert
  std::vector<std::shared_ptr<OpaqueConstruct>> opaqueConstants;
  if (param.opaquePredicateEnabled) {
    savedRegs.insert(X86::EAX); // OpaqueConstant will be stored in EAX

    for (auto &elem : chain) {
      switch (elem.type) {
      case ChainElem::Type::GADGET:
        if (elem.microgadget->addresses.size() > 1 &&
            param.opaqueBranchDivergenceEnabled) {
          savedRegs.insert(X86::ECX); // ValueAdjustor will clobber ECX
          savedRegs.insert(X86::EDX); // ValueAdjustor will clobber EDX
          auto opaqueConstant =
              OpaqueConstructFactory::createBranchingOpaqueConstant32(
                  OpaqueStorage::EAX,
                  std::min((size_t)param.opaqueBranchDivergenceMaxBranches,
                           elem.microgadget->addresses.size()),
                  param.opaqueBranchDivergenceAlgorithm);
          opaqueConstants.push_back(opaqueConstant);
          auto clobbered = opaqueConstant->getClobberedRegs();
          savedRegs.insert(clobbered.begin(), clobbered.end());
        } else {
          auto opaqueConstant = OpaqueConstructFactory::createOpaqueConstant32(
              OpaqueStorage::EAX, param.opaqueConstantAlgorithm);
          opaqueConstants.push_back(opaqueConstant);
          auto clobbered = opaqueConstant->getClobberedRegs();
          savedRegs.insert(clobbered.begin(), clobbered.end());
        }
        break;
      case ChainElem::Type::IMM_VALUE:
      case ChainElem::Type::IMM_GLOBAL:
        if (obfuscateImmediateOperand) {
          auto opaqueConstant = OpaqueConstructFactory::createOpaqueConstant32(
              OpaqueStorage::EAX, param.opaqueConstantAlgorithm);
          opaqueConstants.push_back(opaqueConstant);
          auto clobbered = opaqueConstant->getClobberedRegs();
          savedRegs.insert(clobbered.begin(), clobbered.end());
        }
        break;
      default:
        break;
      }
    }
  }

  // EMIT PROLOGUE

  // save registers (and flags if necessary) on top of the stack
  int regSavedOffset = 4 * (chain.size() + 1);
  if (chain.hasUnconditionalJump || chain.hasConditionalJump)
    regSavedOffset -= 4;
  if (chain.flagSave == FlagSaveMode::SAVE_AFTER_EXEC)
    regSavedOffset += 4;
  if (chain.flagSave == FlagSaveMode::SAVE_BEFORE_EXEC) {
    savedRegs.insert(X86::EFLAGS);
  } else {
    savedRegs.erase(X86::EFLAGS);
  }
  if (!savedRegs.empty()) {
    // lea esp, [esp-4*(N+1)]   # where N = chain size
    as.lea(as.reg(X86::ESP), as.mem(X86::ESP, -regSavedOffset));
    // save registers (and flags)
    for (auto it = savedRegs.begin(); it != savedRegs.end(); ++it) {
      if (*it == X86::EFLAGS) {
        as.pushf();
      } else {
        as.push(as.reg(*it));
      }
    }
    // lea esp, [esp+4*(N+1+M)]
    // where N = chain size, M = num of saved registers
    as.lea(as.reg(X86::ESP),
           as.mem(X86::ESP, regSavedOffset + 4 * savedRegs.size()));
  }

  if (chain.flagSave == FlagSaveMode::SAVE_AFTER_EXEC) {
    assert(!chain.hasUnconditionalJump || !chain.hasConditionalJump);

    // If the obfuscated instruction will NOT modify flags,
    // (and if the chain execution might modify the flags,)
    // the flags should be restored after the ROP chain is executed.
    // flag is saved at the bottom of the stack
    // pushf (EFLAGS register backup)
    as.pushf();
    espoffset -= 4;
  }

  auto asChainLabel = as.label(chainLabel);
  auto asResumeLabel = as.label(resumeLabel);
  if (chain.hasUnconditionalJump || chain.hasConditionalJump) {
    // jmp funcName_chain_X
    // (omitted since it would be redundant)
  } else {
    // call funcName_chain_X
    as.call(asChainLabel);
    // jmp resume_funcName_chain_X
    as.jmp(asResumeLabel);
    resumeLabelRequired = true;
    espoffset -= 4;
  }

  // funcName_chain_X:
  as.putLabel(asChainLabel);

  // ROP Chain
  // Pushes each chain element on the stack in reverse order
  for (auto elem = chain.rbegin(); elem != chain.rend(); ++elem) {
    switch (elem->type) {

    case ChainElem::Type::IMM_VALUE: {
      // Push the immediate value onto the stack
      if (param.opaquePredicateEnabled && obfuscateImmediateOperand) {
        auto opaqueConstant = opaqueConstants.back();
        opaqueConstants.pop_back();
        uint32_t value =
            *opaqueConstant->getOutput().findValue(OpaqueStorage::EAX);
        // compute opaque constant to eax
        opaqueConstant->compile(as, 0);
        // adjust eax to be the constant
        uint32_t diff = elem->value - value;
        as.add(as.reg(X86::EAX), as.imm(diff));
        // push eax
        as.push(as.reg(X86::EAX));
      } else {
        // push $imm
        as.push(as.imm(elem->value));
      }
      break;
    }

    case ChainElem::Type::IMM_GLOBAL: {
      // Push the global symbol onto the stack
      if (param.opaquePredicateEnabled && obfuscateImmediateOperand) {
        auto opaqueConstant = opaqueConstants.back();
        opaqueConstants.pop_back();
        uint32_t value =
            *opaqueConstant->getOutput().findValue(OpaqueStorage::EAX);
        // compute opaque constant to eax
        opaqueConstant->compile(as, 0);
        // adjust eax to be the constant
        uint32_t diff = elem->value - value;
        as.add(as.reg(X86::EAX), as.imm(elem->global, diff));
        // push eax
        as.push(as.reg(X86::EAX));
      } else {
        // push global_symbol
        as.push(as.imm(elem->global, elem->value));
      }
      break;
    }

    case ChainElem::Type::GADGET: {
      // Get a random symbol to reference this gadget in memory
      const Symbol *sym = BA->getRandomSymbol();
      // Choose a random address in the gadget
      const std::vector<uint64_t> &addresses = elem->microgadget->addresses;
      std::vector<uint32_t> offsets;
      if (addresses.size() > 1 && param.opaqueBranchDivergenceEnabled) {
        // take 2 addresses randomly
        std::vector<int> indices(addresses.size());
        for (size_t i = 0; i < addresses.size(); i++) {
          indices[i] = i;
        }
        while (offsets.size() <
               std::min((size_t)param.opaqueBranchDivergenceMaxBranches,
                        addresses.size())) {
          int n = rand() % indices.size();
          int index = indices[n];
          indices.erase(indices.begin() + n);
          offsets.push_back(addresses[index] - sym->Address);
        }
      } else {
        offsets.push_back(addresses[rand() % addresses.size()] - sym->Address);
      }

      // .symver directive: necessary to prevent aliasing when more
      // symbols have the same name. We do this exclusively when the
      // symbol Version is not "Base" (i.e., it is the only one
      // available).
      if (!sym->isUsed && sym->Version != "Base") {
        as.inlineasm(sym->getSymverDirective());
        sym->isUsed = true;
      }

      // push $symbol
      as.push(as.label(sym->Label));
      if (param.opaquePredicateEnabled) {
        auto opaqueConstant = opaqueConstants.back();
        opaqueConstants.pop_back();
        auto output = opaqueConstant->getOutput();
        auto &opaqueValues = *output.findValues(OpaqueStorage::EAX);
        auto adjuster = OpaqueConstructFactory::createValueAdjustor(
            OpaqueStorage::EAX, opaqueValues, offsets);
        // compute opaque constant to eax
        opaqueConstant->compile(as, 0);
        // adjust eax to be relativeAddr
        adjuster->compile(as, 0);
        // add [esp], eax
        as.add(as.mem(X86::ESP), as.reg(X86::EAX));
      } else {
        // add [esp], $offset
        as.add(as.mem(X86::ESP), as.imm(offsets[0]));
      }
      break;
    }

    case ChainElem::Type::JMP_BLOCK: {
      // push label
      MachineBasicBlock *targetMBB = elem->jmptarget;
      as.push(as.label(targetMBB));
      MBB.addSuccessorWithoutProb(targetMBB);
      break;
    }

    case ChainElem::Type::JMP_FALLTHROUGH: {
      // push label
      if (isLastInstrInBlock) {
        MachineBasicBlock *targetMBB = nullptr;
        for (auto it = MBB.succ_begin(); it != MBB.succ_end(); ++it) {
          if (MBB.isLayoutSuccessor(*it)) {
            targetMBB = *it;
            break;
          }
        }
        if (!targetMBB) {
          // call or conditional jump at the end of function:
          // probably calling "no-return" functions like exit()
          // so we just put dummy return address here
          as.push(as.imm(0));
        } else {
          as.push(as.label(targetMBB));
        }
      } else {
        as.push(as.label(resumeLabel));
        resumeLabelRequired = true;
      }
      break;
    }

    case ChainElem::Type::ESP_PUSH: {
      // push esp
      as.push(as.reg(X86::ESP));
      espOffsetMap[elem->esp_id] = espoffset;
      break;
    }

    case ChainElem::Type::ESP_OFFSET: {
      // push $(imm - espoffset)
      auto it = espOffsetMap.find(elem->esp_id);
      if (it == espOffsetMap.end()) {
        dbg_fmt("Internal error: ESP_OFFSET should precede corresponding "
                "ESP_PUSH\n");
        exit(1);
      }
      int64_t value = elem->value - it->second;
      as.push(as.imm(value));
      break;
    }
    }

    espoffset -= 4;
  }

  // EMIT EPILOGUE
  // restore registers (and flags)
  if (!savedRegs.empty()) {
    // lea esp, [esp-4*N]   # where N = num of saved registers
    as.lea(as.reg(X86::ESP), as.mem(X86::ESP, -4 * savedRegs.size()));
    // restore registers (and flags)
    for (auto it = savedRegs.rbegin(); it != savedRegs.rend(); ++it) {
      if (*it == X86::EFLAGS) {
        as.popf();
      } else {
        as.pop(as.reg(*it));
      }
    }
  }

  // ret
  as.ret();

  // resume_funcName_chain_X:
  if (resumeLabelRequired) {
    // If the label is inserted when ROP chain terminates with jump,
    // AsmPrinter::isBlockOnlyReachableByFallthrough() doesn't work correctly
    as.putLabel(asResumeLabel);
  }

  // restore eflags, if eflags should be restored AFTER chain execution
  if (chain.flagSave == FlagSaveMode::SAVE_AFTER_EXEC) {
    // popf (EFLAGS register restore)
    as.popf();
  }
}

void ROPfuscatorCore::obfuscateFunction(MachineFunction &MF) {
  // create a new singleton instance of Binary Autopsy
  if (BA == nullptr) {
    if (config.globalConfig.libraryPath.empty()) {
      config.globalConfig.libraryPath = findLibcPath();
    }
    BA = BinaryAutopsy::getInstance(config.globalConfig, MF);
  }

  if (TII == nullptr) {
    // description of the target ISA (used to generate new instructions, below)
    const X86Subtarget &target = MF.getSubtarget<X86Subtarget>();

    if (target.is64Bit()) {
      dbg_fmt("Error: currently ROPfuscator only works for 32bit.\n");
      exit(1);
    }

    TII = target.getInstrInfo();
  }

  std::string funcName = MF.getName().str();
  ObfuscationParameter param = config.getParameter(funcName);
  if (!param.obfuscationEnabled) {
    return;
  }

  // stats
  int processed = 0, obfuscated = 0;

  // ASM labels for each ROP chain
  int chainID = 0;

  // original instructions that have been successfully ROPified and that will be
  // removed at the end
  std::vector<MachineInstr *> instrToDelete;

  for (MachineBasicBlock &MBB : MF) {
    // perform register liveness analysis to get a list of registers that can be
    // safely clobbered to compute temporary data
    ScratchRegMap MBBScratchRegs = performLivenessAnalysis(MBB);

    ROPChain chain0; // merged chain
    MachineInstr *prevMI = nullptr;
    for (auto it = MBB.begin(), it_end = MBB.end(); it != it_end; ++it) {
      MachineInstr &MI = *it;

      if (MI.isDebugInstr())
        continue;

      DEBUG_WITH_TYPE(PROCESSED_INSTR, dbg_fmt("    {}", MI));
      processed++;

      // get the list of scratch registers available for this instruction
      std::vector<unsigned int> MIScratchRegs =
          MBBScratchRegs.find(&MI)->second;

      // Do this instruction and/or following instructions
      // use current flags (i.e. affected by current flags)?
      bool shouldFlagSaved = !TII->isSafeToClobberEFLAGS(MBB, it);
      // Does this instruction modify (define/kill) flags?
      // bool isFlagModifiedInInstr = false;
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
          ROPEngine(*BA).ropify(MI, MIScratchRegs, shouldFlagSaved, result);

      bool isJump = result.hasConditionalJump || result.hasUnconditionalJump;
      if (isJump && result.flagSave == FlagSaveMode::SAVE_AFTER_EXEC) {
        // when flag should be saved after resume, jmp instruction cannot be
        // ROPified
        status = ROPChainStatus::ERR_UNSUPPORTED;
      }

#ifdef ROPFUSCATOR_INSTRUCTION_STAT
      instr_stat[MI.getOpcode()][status]++;
#endif

      if (status != ROPChainStatus::OK) {
        DEBUG_WITH_TYPE(PROCESSED_INSTR,
                        dbg_fmt("{}\t✗ Unsupported instruction{}\n", COLOR_RED,
                                COLOR_RESET));

        if (chain0.valid()) {
          insertROPChain(chain0, MBB, *prevMI, chainID++, param);
          chain0.clear();
        }
        continue;
      }
      // add current instruction in the To-Delete list
      instrToDelete.push_back(&MI);

      if (chain0.canMerge(result)) {
        chain0.merge(result);
      } else {
        if (chain0.valid()) {
          insertROPChain(chain0, MBB, *prevMI, chainID++, param);
          chain0.clear();
        }
        chain0 = std::move(result);
      }
      prevMI = &MI;

      DEBUG_WITH_TYPE(PROCESSED_INSTR,
                      dbg_fmt("{}\t✓ Replaced{}\n", COLOR_GREEN, COLOR_RESET));

      obfuscated++;
    }

    if (chain0.valid()) {
      insertROPChain(chain0, MBB, *prevMI, chainID++, param);
      chain0.clear();
    }

    // delete old vanilla instructions only after we finished to iterate through
    // the basic block
    for (auto &MI : instrToDelete)
      MI->eraseFromParent();

    instrToDelete.clear();
  }

  // print obfuscation stats for this function
  DEBUG_WITH_TYPE(OBF_STATS,
                  dbg_fmt("{}: {}/{} ({}%) instructions obfuscated\n", funcName,
                          obfuscated, processed,
                          (obfuscated * 100) / processed));
}
