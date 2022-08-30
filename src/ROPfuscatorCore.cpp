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
#include "MathUtil.h"
#include "OpaqueConstruct.h"
#include "ROPEngine.h"
#include "ROPfuscatorConfig.h"
#include "Utils.h"
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
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <utility>

using namespace llvm;

namespace ropf {

struct ROPfuscatorCore::ROPChainStatEntry {
  static const int entry_size = static_cast<int>(ROPChainStatus::COUNT);
  int              data[entry_size];

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
      "| unsupported: {4} | unsupported-esp: {5} | debug-instr: {6}]";
  static constexpr const char *DEBUG_FMT_SIMPLE =
      "{0:^13}\t{1:^13}\t{2:^13}\t{3:^13}\t{4:^13}\t{5:^13}\t{6:^13}\t{7:^13}";

  std::ostream &printTo(std::ostream &os, const char *fmt) const {
    const ROPChainStatEntry &entry = *this;
    fmt::print(os,
               fmt,
               entry[ROPChainStatus::OK],
               entry[ROPChainStatus::ERR_NOT_IMPLEMENTED],
               entry[ROPChainStatus::ERR_NO_REGISTER_AVAILABLE],
               entry[ROPChainStatus::ERR_NO_GADGETS_AVAILABLE],
               entry[ROPChainStatus::ERR_UNSUPPORTED],
               entry[ROPChainStatus::ERR_UNSUPPORTED_STACKPOINTER],
               entry[ROPChainStatus::ERR_DEBUG_INSTRUCTION],
               entry.total());
    return os;
  }

  friend std::ostream &operator<<(std::ostream            &os,
                                  const ROPChainStatEntry &entry) {
    return entry.printTo(os, DEBUG_FMT_NORMAL);
  }

  std::string toString(const char *fmt) const {
    std::stringstream ss;
    printTo(ss, fmt);
    return ss.str();
  }

  static std::string headerString(const char *fmt) {
    return fmt::format(fmt,
                       "ropfuscated",
                       "not-implemented",
                       "no-register",
                       "no-gadget",
                       "unsupported",
                       "unsupported-esp",
                       "debug-instr",
                       "total");
  }
};

// ----------------------------------------------------------------

namespace {

// Lowered ROP Chain
// These classes represent more lower level of machine code than ROP chain
// and directly output machine code.

// base class
struct ROPChainPushInst {
  std::shared_ptr<OpaqueConstruct> opaqueConstant;
  virtual void compile(X86AssembleHelper &, StackState &) = 0;
  virtual ~ROPChainPushInst()                             = default;
};

// immediate (immediate operand, etc)
struct PUSH_IMM : public ROPChainPushInst {
  int64_t value;
  explicit PUSH_IMM(int64_t value) : value(value) {}
  virtual void compile(X86AssembleHelper &as, StackState &stack) override {
    if (opaqueConstant) {
      uint32_t opaque =
          *opaqueConstant->getOutput().findValue(OpaqueStorage::EAX);

      opaqueConstant->compile(as, stack);

      // adjust eax to be the constant
      uint32_t diff = value - opaque;
      as.add(as.reg(X86::EAX), as.imm(diff));
      // push eax
      as.push(as.reg(X86::EAX));
    } else {
      // push $imm
      as.push(as.imm(value));
    }
  }
  virtual ~PUSH_IMM() = default;
};

// global variable (immediate operand, etc)
struct PUSH_GV : public ROPChainPushInst {
  const llvm::GlobalValue *gv;
  int64_t                  offset;
  PUSH_GV(const llvm::GlobalValue *gv, int64_t offset)
      : gv(gv), offset(offset) {}
  virtual void compile(X86AssembleHelper &as, StackState &stack) override {
    if (opaqueConstant) {
      uint32_t opaque =
          *opaqueConstant->getOutput().findValue(OpaqueStorage::EAX);

      opaqueConstant->compile(as, stack);

      // adjust eax to be the constant
      uint32_t diff = offset - opaque;
      as.add(as.reg(X86::EAX), as.imm(gv, diff));
      // push eax
      as.push(as.reg(X86::EAX));
    } else {
      // push global_symbol
      as.push(as.imm(gv, offset));
    }
  }
  virtual ~PUSH_GV() = default;
};

// gadget with single or multiple addresses
struct PUSH_GADGET : public ROPChainPushInst {
  const Symbol *anchor;
  uint32_t      offset;
  explicit PUSH_GADGET(const Symbol *anchor, uint32_t offset)
      : anchor(anchor), offset(offset) {}
  virtual void compile(X86AssembleHelper &as, StackState &stack) override {
    if (opaqueConstant) {
      auto opaqueValues =
          *opaqueConstant->getOutput().findValues(OpaqueStorage::EAX);

      opaqueConstant->compile(as, stack);

      // add eax, $symbol
      as.add(as.reg(X86::EAX), as.label(anchor->Label));
      // push eax
      as.push(as.reg(X86::EAX));
    } else {
      // push $symbol+offset
      as.push(as.addOffset(as.label(anchor->Label), offset));
    }
  }
  virtual ~PUSH_GADGET() = default;
};

// local label
struct PUSH_LABEL : public ROPChainPushInst {
  X86AssembleHelper::Label label;
  explicit PUSH_LABEL(const X86AssembleHelper::Label &label) : label(label) {}
  virtual void compile(X86AssembleHelper &as, StackState &stack) override {
    if (opaqueConstant) {
      uint32_t value =
          *opaqueConstant->getOutput().findValue(OpaqueStorage::EAX);

      opaqueConstant->compile(as, stack);

      // adjust eax to jump target address
      as.add(as.reg(X86::EAX), as.addOffset(label, -value));
      // push eax
      as.push(as.reg(X86::EAX));
    } else {
      // push label
      as.push(label);
    }
  }
  virtual ~PUSH_LABEL() = default;
};

// push esp
struct PUSH_ESP : public ROPChainPushInst {
  virtual void compile(X86AssembleHelper &as, StackState &stack) override {
    as.push(as.reg(X86::ESP));
  }
  virtual ~PUSH_ESP() = default;
};

// push eflags
struct PUSH_EFLAGS : public ROPChainPushInst {
  virtual void compile(X86AssembleHelper &as, StackState &stack) override {
    as.pushf();
  }
  virtual ~PUSH_EFLAGS() = default;
};

void generateChainLabels(std::string &chainLabel,
                         std::string &resumeLabel,
                         StringRef    funcName,
                         int          chainID) {
  chainLabel  = fmt::format("{}_chain_{}", funcName.str(), chainID);
  resumeLabel = fmt::format("resume_{}", chainLabel);

  // replacing $ with _
  std::replace(chainLabel.begin(), chainLabel.end(), '$', '_');
}

void putLabelInMBB(MachineBasicBlock &MBB, X86AssembleHelper::Label label) {
  X86AssembleHelper as(MBB, MBB.begin());
  as.putLabel(label);
}

} // namespace

class ChainElementSelector {
  unsigned int                       percentage;
  const std::vector<ChainElem::Type> elemTypes;
  size_t                             current, total;

public:
  ChainElementSelector(unsigned int                        percentage,
                       const std::vector<ChainElem::Type> &elemTypes)
      : percentage(percentage), elemTypes(elemTypes) {}

  void setPercentage(unsigned int newPercentage) {
    if (percentage != newPercentage) {
      current = total = 0;
    }
    percentage = newPercentage;
  }

  void select(const ROPChain &chain, std::vector<unsigned int> &outVector) {
    std::default_random_engine &rng = math::Random::engine();
    size_t                      chainElemsToObfuscate;
    std::vector<size_t>         buf;

    // saving the indices of all the chain elements of a specific type.
    // we will decide the ones to keep later
    for (size_t i = 0; i < chain.size(); i++) {
      for (auto elem : elemTypes) {
        if (elem == chain.chain[i].type) {
          buf.emplace_back(i);
        }
      }
    }

    if (!buf.size()) {
      return;
    }

    total += buf.size();

    chainElemsToObfuscate = total * percentage / 100 - current;
    current += chainElemsToObfuscate;

    if (!chainElemsToObfuscate) {
      return;
    }

    if (buf.size() == chainElemsToObfuscate) {
      copy(buf.begin(), buf.end(), back_inserter(outVector));
      return;
    }

    // select N indices to be obfuscated (preserve the order)
    std::sample(buf.begin(),
                buf.end(),
                std::back_inserter(outVector),
                chainElemsToObfuscate,
                rng);
  }
};

ROPfuscatorCore::ROPfuscatorCore(llvm::Module            &module,
                                 const ROPfuscatorConfig &config)
    : config(config), BA(nullptr), TII(nullptr),
      sourceFileName(module.getSourceFileName()) {
  total_chain_elems = 0;
  total_func_count  = 0;
  curr_func_count   = 0;

  // the filename might contain slashes, replacing them to dashes
  std::replace(sourceFileName.begin(), sourceFileName.end(), '/', '-');

  for (auto &f : module.getFunctionList()) {
    if (!f.empty()) {
      total_func_count++;
    }
  }

  if (config.globalConfig.rng_seed) {
    math::Random::engine().seed(config.globalConfig.rng_seed);
  }

  if (config.globalConfig.writeInstrStat) {
    auto          logfile = fmt::format("{}-{}",
                               ROPFUSCATOR_OBFUSCATION_STATISTICS_FILE_HEAD,
                               sourceFileName);
    std::ofstream f(logfile, std::ios_base::app);
    f.seekp(0, std::ios::end);

    // if the file is empty, write header and total instructions
    if (!f.tellp()) {
      dbg_fmt("[*] Writing header in {}\n", logfile);

      f << fmt::format(
          "{:^15}\t{}\n",
          "OPCODE",
          ROPChainStatEntry::headerString(ROPChainStatEntry::DEBUG_FMT_SIMPLE));

      f.flush();
      f.close();
    } else {
      dbg_fmt("[*] {} exists already!\n", logfile);
    }
  }

  gadgetAddressSelector =
      new ChainElementSelector(0, {ChainElem::Type::GADGET});
  immediateSelector = new ChainElementSelector(
      0,
      {ChainElem::Type::IMM_VALUE, ChainElem::Type::IMM_GLOBAL});
  branchTargetSelector = new ChainElementSelector(
      0,
      {ChainElem::Type::JMP_BLOCK, ChainElem::Type::JMP_FALLTHROUGH});
}

ROPfuscatorCore::~ROPfuscatorCore() {
  if (config.globalConfig.writeInstrStat) {
    auto logfile = fmt::format("{}-{}",
                               ROPFUSCATOR_OBFUSCATION_STATISTICS_FILE_HEAD,
                               sourceFileName);
    dbg_fmt("[*] Writing coverage information in {}\n", logfile);
    std::ofstream f(logfile, std::ios_base::app);

    for (auto &kv : instr_stat)
      f << fmt::format("{:^15}\t{}\n",
                       TII->getName(kv.first),
                       kv.second.toString(ROPChainStatEntry::DEBUG_FMT_SIMPLE));

    // this can happen as MachineFunction.getInstructionCount()
    // does not take in account some opcodes such as GC_LABEL
    if (module_total_instructions != processed_instructions) {
      dbg_fmt("[!] Instruction count mismatch: module instructions: {} | "
              "processed instructions: {}\n",
              module_total_instructions,
              processed_instructions);
    }

    f.flush();
    f.close();
  }

  if (config.globalConfig.printInstrStat) {
    for (auto &kv : instr_stat) {
      dbg_fmt("{:^7}\t{:^15}\t{}\n",
              kv.first,
              TII->getName(kv.first),
              kv.second.toString(ROPChainStatEntry::DEBUG_FMT_SIMPLE));
    }

    dbg_fmt("============================================================\n");
    dbg_fmt("Total ROP chain elements: {}\n", total_chain_elems);
  }

  delete gadgetAddressSelector;
  delete immediateSelector;
  delete branchTargetSelector;

  assert(module_total_instructions == processed_instructions);
}

void ROPfuscatorCore::insertROPChain(ROPChain                   &chain,
                                     MachineBasicBlock          &MBB,
                                     MachineInstr               &MI,
                                     int                         chainID,
                                     const ObfuscationParameter &param) {
  X86AssembleHelper           as = X86AssembleHelper(MBB, MI.getIterator());
  bool                        isLastInstrInBlock  = MI.getNextNode() == nullptr;
  bool                        resumeLabelRequired = false;
  std::map<int, int>          espOffsetMap;
  int                         espoffset = 0;
  std::vector<const Symbol *> versionedSymbols;
  std::vector<unsigned>       gadgetsIdxToObfuscate, immediatesIdxToObfuscate,
      branchIdxToObfuscate;

  total_chain_elems += chain.size();

  // stack layout:
  // (A) if FlagSaveMode == SAVE_AFTER_EXEC:
  // 1. saved-regs
  // 2. ROP chain
  // 3. flags
  // 4. return addr
  //
  // (B) if FlagSaveMode == SAVE_BEFORE_EXEC or NOT_SAVED:
  // 1. saved-regs (and flags)
  // 2. ROP chain
  // 3. return address

  if (chain.hasUnconditionalJump || chain.hasConditionalJump) {
    // continuation of the ROP chain (resume address) is already on the chain
  } else {
    // push resume address on the chain
    chain.emplace_back(ChainElem::createJmpFallthrough());
  }

  X86AssembleHelper::Label asChainLabel, asResumeLabel;
  if (config.globalConfig.useChainLabel) {
    std::string chainLabel, resumeLabel;
    generateChainLabels(chainLabel,
                        resumeLabel,
                        MBB.getParent()->getName(),
                        chainID);
    asChainLabel  = as.label(chainLabel);
    asResumeLabel = as.label(resumeLabel);
  } else {
    asChainLabel  = as.label();
    asResumeLabel = as.label();
  }

  // Convert ROP chain to push instructions
  std::vector<std::shared_ptr<ROPChainPushInst>> pushchain;

  if (chain.flagSave == FlagSaveMode::SAVE_AFTER_EXEC) {
    assert(!chain.hasUnconditionalJump || !chain.hasConditionalJump);

    // If the obfuscated instruction will NOT modify flags,
    // (and if the chain execution might modify the flags,)
    // the flags should be restored after the ROP chain is executed.
    // flag is saved at the bottom of the stack
    // pushf (EFLAGS register backup)
    ROPChainPushInst *push = new PUSH_EFLAGS();
    pushchain.emplace_back(push);
    // modify isLastInstrInBlock flag, since we will emit popf instruction later
    isLastInstrInBlock = false;
    espoffset -= 4;
  }

  // reversing the chain as we are going to push the values in reverse
  // order on the stack
  std::reverse(chain.begin(), chain.end());

  // handle obfuscation of gadget addresses
  if (param.opaqueGadgetAddressesEnabled) {
    gadgetAddressSelector->select(chain, gadgetsIdxToObfuscate);
  }

  // handle obfuscation of immediate operands
  if (param.opaqueImmediateOperandsEnabled) {
    immediateSelector->select(chain, immediatesIdxToObfuscate);
  }

  // handle obfuscation of branch operations
  if (param.opaqueBranchTargetsEnabled) {
    branchTargetSelector->select(chain, branchIdxToObfuscate);
  }

  size_t idx = 0;
  // Pushes each chain element on the stack in reverse order
  for (auto elem : chain) {
    switch (elem.type) {
    case ChainElem::Type::IMM_VALUE: {
      // Push the immediate value onto the stack
      ROPChainPushInst *push = new PUSH_IMM(elem.value);

      if (param.opaquePredicatesEnabled &&
          param.opaqueImmediateOperandsEnabled &&
          contains(immediatesIdxToObfuscate, idx)) {
        push->opaqueConstant = OpaqueConstructFactory::createOpaqueConstant32(
            OpaqueStorage::EAX,
            param.opaqueConstantsAlgorithm,
            param.opaqueInputGenAlgorithm,
            param.contextualOpaquePredicatesEnabled);
      }

      pushchain.emplace_back(push);
      break;
    }

    case ChainElem::Type::IMM_GLOBAL: {
      // Push the global symbol onto the stack
      ROPChainPushInst *push = new PUSH_GV(elem.global, elem.value);

      if (param.opaquePredicatesEnabled &&
          param.opaqueImmediateOperandsEnabled &&
          contains(immediatesIdxToObfuscate, idx)) {
        // we have to limit value range, so that
        // linker will not complain about integer overflow in relocation
        uint32_t value = elem.value - math::Random::range32(0x1000, 0x10000000);
        push->opaqueConstant = OpaqueConstructFactory::createOpaqueConstant32(
            OpaqueStorage::EAX,
            value,
            param.opaqueConstantsAlgorithm,
            param.opaqueInputGenAlgorithm,
            param.contextualOpaquePredicatesEnabled);
      }

      pushchain.emplace_back(push);
      break;
    }

    case ChainElem::Type::GADGET: {
      // Get a random symbol to reference this gadget in memory
      const Symbol                *sym       = BA->getRandomSymbol();
      // Choose a random address in the gadget
      const std::vector<uint64_t> &addresses = elem.microgadget->addresses;
      std::vector<uint32_t>        offsets;

      // pick address randomly
      std::sample(addresses.begin(),
                  addresses.end(),
                  std::back_inserter(offsets),
                  1,
                  math::Random::engine());

      for (auto &offset : offsets) {
        offset -= sym->Address;
      }

      // .symver directive: necessary to prevent aliasing when more
      // symbols have the same name. We do this exclusively when the
      // symbol Version is not "Base" (i.e., it is the only one
      // available).
      if (!sym->isUsed && sym->Version != "Base") {
        versionedSymbols.push_back(sym);
        sym->isUsed = true;
      }

      ROPChainPushInst *push = new PUSH_GADGET(sym, offsets[0]);

      // if we should obfuscate the addresses and the current
      // index has been selected to be obfuscated
      if (param.opaquePredicatesEnabled && param.opaqueGadgetAddressesEnabled &&
          contains(gadgetsIdxToObfuscate, idx)) {
        std::shared_ptr<OpaqueConstruct> opaqueConstant;

        opaqueConstant = OpaqueConstructFactory::createOpaqueConstant32(
            OpaqueStorage::EAX,
            param.opaqueConstantsAlgorithm,
            param.opaqueInputGenAlgorithm,
            param.contextualOpaquePredicatesEnabled);

        auto opaqueValues =
            *opaqueConstant->getOutput().findValues(OpaqueStorage::EAX);
        auto adjuster =
            OpaqueConstructFactory::createValueAdjustor(OpaqueStorage::EAX,
                                                        opaqueValues,
                                                        offsets);
        push->opaqueConstant =
            OpaqueConstructFactory::compose(adjuster, opaqueConstant);
      }

      pushchain.emplace_back(push);
      break;
    }

    case ChainElem::Type::JMP_BLOCK: {
      MachineBasicBlock *targetMBB = elem.jmptarget;
      MBB.addSuccessorWithoutProb(targetMBB);
      auto targetLabel = as.label();
      putLabelInMBB(*targetMBB, targetLabel);

      ROPChainPushInst *push = new PUSH_LABEL(targetLabel);
      if (param.opaquePredicatesEnabled && param.opaqueBranchTargetsEnabled &&
          contains(branchIdxToObfuscate, idx)) {
        // we have to limit value range, so that
        // linker will not complain about integer overflow in relocation
        uint32_t value       = -math::Random::range32(0x1000, 0x10000000);
        push->opaqueConstant = OpaqueConstructFactory::createOpaqueConstant32(
            OpaqueStorage::EAX,
            value,
            param.opaqueConstantsAlgorithm,
            param.opaqueInputGenAlgorithm,
            param.contextualOpaquePredicatesEnabled);
      }
      pushchain.emplace_back(push);
      break;
    }

    case ChainElem::Type::JMP_FALLTHROUGH: {
      // push label
      X86AssembleHelper::Label targetLabel = {nullptr};
      if (isLastInstrInBlock) {
        for (auto it = MBB.succ_begin(); it != MBB.succ_end(); ++it) {
          if (MBB.isLayoutSuccessor(*it)) {
            auto *targetMBB = *it;
            targetLabel     = asResumeLabel;
            putLabelInMBB(*targetMBB, targetLabel);
            break;
          }
        }
      } else {
        targetLabel         = asResumeLabel;
        resumeLabelRequired = true;
      }
      if (targetLabel.symbol) {
        ROPChainPushInst *push = new PUSH_LABEL(targetLabel);
        if (param.opaquePredicatesEnabled && param.opaqueBranchTargetsEnabled &&
            contains(branchIdxToObfuscate, idx)) {
          // we have to limit value range, so that
          // linker will not complain about integer overflow in relocation
          uint32_t value       = -math::Random::range32(0x1000, 0x10000000);
          push->opaqueConstant = OpaqueConstructFactory::createOpaqueConstant32(
              OpaqueStorage::EAX,
              value,
              param.opaqueConstantsAlgorithm,
              param.opaqueInputGenAlgorithm,
              param.contextualOpaquePredicatesEnabled);
        }
        pushchain.emplace_back(push);
      } else {
        // call or conditional jump at the end of function:
        // probably calling "no-return" functions like exit()
        // so we just put dummy return address here
        auto dummyLabel = as.label();
        as.putLabel(dummyLabel);
        ROPChainPushInst *push = new PUSH_LABEL(dummyLabel);
        pushchain.emplace_back(push);
      }
      break;
    }

    case ChainElem::Type::ESP_PUSH: {
      // push esp
      ROPChainPushInst *push = new PUSH_ESP();
      pushchain.emplace_back(push);
      espOffsetMap[elem.esp_id] = espoffset;
      break;
    }

    case ChainElem::Type::ESP_OFFSET: {
      // push $(imm - espoffset)
      auto it = espOffsetMap.find(elem.esp_id);
      if (it == espOffsetMap.end()) {
        dbg_fmt("Internal error: ESP_OFFSET should precede corresponding "
                "ESP_PUSH\n");
        exit(1);
      }
      ROPChainPushInst *push = new PUSH_IMM(elem.value - it->second);
      pushchain.emplace_back(push);
      break;
    }
    }

    espoffset -= 4;
    idx++;
  }

  // EMIT PROLOGUE

  // symbol version directives
  if (!versionedSymbols.empty()) {
    std::stringstream ss;
    for (auto *sym : versionedSymbols) {
      if (ss.tellp() > 0) {
        ss << "\n";
      }
      ss << sym->getSymverDirective();
    }
    as.inlineasm(ss.str());
  }

  // save registers (and flags if necessary) on top of the stack
  std::set<unsigned int> savedRegs;
  StackState             stackState;

  // compute clobbered registers
  if (param.opaquePredicatesEnabled) {
    for (auto &push : pushchain) {
      if (auto &op = push->opaqueConstant) {
        auto clobbered = op->getClobberedRegs();
        savedRegs.insert(clobbered.begin(), clobbered.end());
      }
    }
  }
  if (chain.flagSave == FlagSaveMode::SAVE_BEFORE_EXEC) {
    savedRegs.insert(X86::EFLAGS);
  } else {
    savedRegs.erase(X86::EFLAGS);
  }
  std::vector<unsigned int> stackRegLayout;
  if (!savedRegs.empty()) {
    // lea esp, [esp-4*(N+1)]   # where N = chain size
    as.lea(as.reg(X86::ESP), as.mem(X86::ESP, espoffset));
    // save registers (and flags)
    int offset = 0;
    stackRegLayout.insert(stackRegLayout.begin(),
                          savedRegs.begin(),
                          savedRegs.end());
    if (param.opaqueSavedStackValuesEnabled) {
      stackRegLayout.resize(2 * savedRegs.size(), X86::NoRegister);
      std::shuffle(stackRegLayout.begin() + 1,
                   stackRegLayout.end(),
                   math::Random::engine());
      stackState.stack_mangled = true;
    }
    for (auto reg : stackRegLayout) {
      offset -= 4;
      if (reg == X86::NoRegister) {
        uint32_t value = math::Random::rand();
        as.push(as.imm(value));
        stackState.addConst(value, espoffset + offset);
      } else {
        if (reg == X86::EFLAGS) {
          as.pushf();
        } else {
          as.push(as.reg(reg));
        }
        stackState.addReg(reg, espoffset + offset);
      }
    }
    // lea esp, [esp+4*(N+1+M)]
    // where N = chain size, M = num of saved registers
    as.lea(as.reg(X86::ESP), as.mem(X86::ESP, -(offset + espoffset)));
  }

  // funcName_chain_X:
  as.putLabel(asChainLabel);

  // emit rop chain
  stackState.stack_offset = 0;
  for (auto &push : pushchain) {
    push->compile(as, stackState);
    stackState.stack_offset -= 4;
  }

  // EMIT EPILOGUE
  // restore registers (and flags)
  if (!stackRegLayout.empty()) {
    // lea esp, [esp-4*N]   # where N = num of saved registers
    as.lea(as.reg(X86::ESP), as.mem(X86::ESP, -4 * stackRegLayout.size()));
    // restore registers (and flags)
    int popCount = 0;
    for (auto it = stackRegLayout.rbegin(); it != stackRegLayout.rend(); ++it) {
      popCount++;
      if (*it != X86::NoRegister) {
        while (popCount > 0) {
          popCount--;
          if (*it == X86::EFLAGS) {
            if (popCount > 0) {
              as.add(as.reg(X86::ESP), as.imm(popCount * 4));
              popCount = 0;
            }
            as.popf();
          } else {
            as.pop(as.reg(*it));
          }
        }
      }
    }
  }

  if (chain.callee) {
    // Insert dummy call instruction (not actually output in assembly file)
    // to convince that this includes function call in later analysis.
    // Currently, EHStreamer::computeCallSiteTable will use this information
    // to generate correct call site information for C++ exception handling.
    as.dummyCall(chain.callee);
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

  // restoring the order of the chain
  std::reverse(chain.begin(), chain.end());
}

void ROPfuscatorCore::obfuscateFunction(MachineFunction &MF) {
  std::string          funcName = MF.getName().str();
  ObfuscationParameter param    = config.getParameter(funcName);

  if (!param.obfuscationEnabled) {
    if (config.globalConfig.showProgress) {
      dbg_fmt("[*] skipping    [{2:4d}/{1:4d}] {0}...\n",
              funcName,
              total_func_count,
              curr_func_count);
    }

    return;
  }

  curr_func_count++;
  module_total_instructions += MF.getInstructionCount();

  // create a new singleton instance of Binary Autopsy
  if (BA == nullptr) {
    if (config.globalConfig.linkedLibraries.empty()) {
      for (std::string libname : {"libgcc_s.so.1",
                                  "libpthread.so.0",
                                  "libm.so.6",
                                  "libstdc++.so.6"}) {
        std::string path = findLibraryPath(libname);
        if (!path.empty()) {
          config.globalConfig.linkedLibraries.push_back(path);
          dbg_fmt("[*] Avoiding gadgets from: {}\n", path);
        }
      }
    }

    BA = BinaryAutopsy::getInstance(config.globalConfig, MF);
  }

  if (TII == nullptr) {
    // description of the target ISA (used to generate new instructions, below)
    TII = MF.getSubtarget<X86Subtarget>().getInstrInfo();
  }

  if (config.globalConfig.showProgress) {
    dbg_fmt("[*] obfuscating [{2:4d}/{1:4d}] {0}...\n",
            funcName,
            total_func_count,
            curr_func_count);
  }

  // stats
  size_t obfuscated                      = 0;
  size_t processed_function_instructions = 0;

  // ASM labels for each ROP chain
  int chainID = 0;

  gadgetAddressSelector->setPercentage(
      param.gadgetAddressesObfuscationPercentage);
  immediateSelector->setPercentage(param.opaqueImmediateOperandsPercentage);
  branchTargetSelector->setPercentage(param.opaqueBranchTargetsPercentage);

  // original instructions that have been successfully ROPified and that will be
  // removed at the end
  std::vector<MachineInstr *> instrToDelete;

  for (MachineBasicBlock &MBB : MF) {
    // perform register liveness analysis to get a list of registers that can be
    // safely clobbered to compute temporary data
    ScratchRegMap MBBScratchRegs = performLivenessAnalysis(MBB);

    ROPChain      chain0; // merged chain
    MachineInstr *prevMI = nullptr;
    for (auto it = MBB.begin(), it_end = MBB.end(); it != it_end; ++it) {
      MachineInstr &MI = *it;

      // MachineFunction.getInstructionCount() does not take in account
      // GC_LABEL hence we adapt to match LLVM's instruction count
      if (MI.getOpcode() != llvm::TargetOpcode::GC_LABEL) {
        processed_instructions++;
        processed_function_instructions++;
      }

      if (MI.isDebugInstr()) {
        instr_stat[MI.getOpcode()][ROPChainStatus::ERR_DEBUG_INSTRUCTION]++;
        continue;
      }

      DEBUG_WITH_TYPE(PROCESSED_INSTR, dbg_fmt("    {}", MI));

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

      ROPChain       result;
      ROPChainStatus status =
          ROPEngine(*BA).ropify(MI, MIScratchRegs, shouldFlagSaved, result);

      bool isJump = result.hasConditionalJump || result.hasUnconditionalJump;
      if (isJump && result.flagSave == FlagSaveMode::SAVE_AFTER_EXEC) {
        // when flag should be saved after resume, jmp instruction cannot be
        // ROPified
        status = ROPChainStatus::ERR_UNSUPPORTED;
      }

      instr_stat[MI.getOpcode()][status]++;

      if (status != ROPChainStatus::OK) {
        DEBUG_WITH_TYPE(PROCESSED_INSTR,
                        dbg_fmt("{}\t✗ Unsupported instruction{}\n",
                                COLOR_RED,
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
    for (auto &MI : instrToDelete) {
      MI->eraseFromParent();
    }

    instrToDelete.clear();
  }

  // print obfuscation stats for this function
  DEBUG_WITH_TYPE(
      OBF_STATS,
      dbg_fmt("{}: {}/{} ({}%) instructions obfuscated\n",
              funcName,
              obfuscated,
              processed_function_instructions,
              (obfuscated * 100) / processed_function_instructions));
}

} // namespace ropf
