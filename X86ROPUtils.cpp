#include "X86ROPUtils.h"
#include "Ropfuscator/CapstoneLLVMAdpt.h"
#include "Ropfuscator/Debug.h"
#include "Ropfuscator/Symbol.h"
#include "llvm/CodeGen/MachineFunction.h"
#include <dirent.h>

using namespace llvm;

static cl::opt<std::string> CustomLibraryPath(
    "use-custom-lib",
    cl::desc("Specify a custom library which gadget must be extracted from"),
    cl::NotHidden, cl::Optional, cl::ValueRequired);

// TODO: plz improve me
bool recurseLibcDir(const char *path, std::string &libraryPath,
                    uint current_depth) {
  DIR *dir;
  struct dirent *entry;

  if (!current_depth) {
    return false;
  }

  dir = opendir(path);

  if (dir == nullptr)
    return false;

  // searching for libc in regular files only
  while ((entry = readdir(dir)) != nullptr) {
    if (!strcmp(entry->d_name, "libc.so.6")) {
      libraryPath += path;
      libraryPath += "/";
      libraryPath += entry->d_name;

      // llvm::dbgs() << "libc found here: " << libraryPath << "\n";

      return true;
    }
  }

  // could not find libc, recursing into directories
  dir = opendir(path);

  if (dir == nullptr)
    return false;

  while ((entry = readdir(dir))) {
    // must be a dir and not "." or ".."
    if (entry->d_type == DT_DIR && strcmp(entry->d_name, ".") &&
        strcmp(entry->d_name, "..")) {

      // constructing path to dir
      std::string newpath = std::string();

      newpath += path;
      newpath += "/";
      newpath += entry->d_name;

      // llvm::dbgs() << "recursing into: " << newpath << "\n";

      // recurse into dir
      if (recurseLibcDir(newpath.c_str(), libraryPath, current_depth - 1))
        return true;
    }
  }

  return false;
}

// TODO: plz improve me
bool getLibraryPath(std::string &libraryPath) {
  if (!CustomLibraryPath.empty()) {
    libraryPath = CustomLibraryPath.getValue();
    dbgs() << "[*] Using custom library path: " << libraryPath << "\n";
    return true;
  }

  uint maxrecursedepth = 3;
  libraryPath.clear();

  for (auto &folder : POSSIBLE_LIBC_FOLDERS) {
    if (recurseLibcDir(folder.c_str(), libraryPath, maxrecursedepth)) {
      dbgs() << "[*] Using library path: " << libraryPath << "\n";
      return true;
    }
  }
  return false;
}

// ------------------------------------------------------------------------
// ROP Chain
// ------------------------------------------------------------------------

ROPEngine::ROPEngine() {}

x86_reg ROPEngine::getEffectiveReg(x86_reg reg) {
  BinaryAutopsy *BA = BinaryAutopsy::getInstance();
  return static_cast<x86_reg>(BA->xgraph.searchLogicalReg(reg));
}

int ROPEngine::Xchg(MachineInstr *MI, x86_reg a, x86_reg b) {
  BinaryAutopsy *BA = BinaryAutopsy::getInstance();
  // avoid in case of equal registers
  if (a == b) {
    DEBUG_WITH_TYPE(XCHG_CHAIN, dbgs() << "[XchgChain]\tavoiding exchanging "
                                       << a << " with " << b << " (equal)\n");
    return 0;
  }

  DEBUG_WITH_TYPE(XCHG_CHAIN, dbgs() << "[XchgChain]\texchanging " << a
                                     << " with " << b << "\n");

  auto xchgPath = BA->getXchgPath(a, b);
  for (auto &a : xchgPath) {
    DEBUG_WITH_TYPE(XCHG_CHAIN, dbgs()
                                    << "[XchgChain]\t" << a->asmInstr << "\n");
    chain.emplace_back(ChainElem(a));
    addToInstrMap(MI, ChainElem(a));
  }

  DEBUG_WITH_TYPE(XCHG_CHAIN, dbgs() << "[XchgChain]\t"
                                     << "performed " << xchgPath.size()
                                     << " exchanges\n\n");
  return xchgPath.size();
}

ROPChain ROPEngine::undoXchgs(MachineInstr *MI) {
  BinaryAutopsy *BA = BinaryAutopsy::getInstance();
  ROPChain result;

  // TODO: merge code with Xchg
  auto xchgPath = BA->undoXchgs();
  for (auto &a : xchgPath)
    llvm::dbgs() << "-> " << a->asmInstr << "\n";
  llvm::dbgs() << "undo xchgs: " << xchgPath.size() << "\n";
  int iter = 0;
  for (auto it = xchgPath.begin(); it != xchgPath.end(); it++) {
    llvm::dbgs() << "\t " << iter << "\n";
    // Skip equal and consecutive xchg gadgets
    // if (it != xchgPath.end() && *(it + 1) == *it) {
    //   ++it;
    //   continue;
    // }
    result.emplace_back(ChainElem(*it));
    addToInstrMap(MI, ChainElem(*it));
    iter++;
  }
  return result;
}

bool ROPEngine::addImmToReg(MachineInstr *MI, x86_reg reg, int immediate,
                            std::vector<x86_reg> const &scratchRegs) {
  BinaryAutopsy *BA = BinaryAutopsy::getInstance();
  ROPChain init, add, reorder;

  for (auto &scratchReg : scratchRegs) {
    init = BA->findGadgetPrimitive("init", scratchReg);
    add = BA->findGadgetPrimitive("add", reg, scratchReg);
    reorder = undoXchgs(MI);

    if (init.empty() || add.empty()) {
      BA->xgraph.reorderRegisters(); // xchg graph rollback
      continue;
    }
    init.emplace_back(ChainElem(immediate));
    chain.insert(chain.end(), init.begin(), init.end());
    chain.insert(chain.end(), add.begin(), add.end());
    chain.insert(chain.end(), reorder.begin(), reorder.end());

    return true;
  }

  return false;
}

x86_reg ROPEngine::computeAddress(MachineInstr *MI, x86_reg inputReg,
                                  int displacement, x86_reg outputReg,
                                  std::vector<x86_reg> scratchRegs) {

  addImmToReg(MI, outputReg, displacement, scratchRegs);
}

bool ROPEngine::handleAddSubIncDec(MachineInstr *MI,
                                   std::vector<x86_reg> &scratchRegs) {
  unsigned opcode = MI->getOpcode();

  int imm;
  x86_reg dest_reg;

  // no scratch registers are available -> abort.
  if (scratchRegs.empty())
    return false;

  switch (opcode) {
  case X86::ADD32ri8:
  case X86::ADD32ri: {
    if (!MI->getOperand(2).isImm())
      return false;

    imm = MI->getOperand(2).getImm();

    break;
  }
  case X86::SUB32ri8:
  case X86::SUB32ri: {
    if (!MI->getOperand(2).isImm())
      return false;

    imm = -MI->getOperand(2).getImm();

    break;
  }
  case X86::INC32r: {
    imm = 1;
    break;
  }
  case X86::DEC32r: {
    imm = -1;
    break;
  }
  default:
    return false;
  }

  dest_reg = convertToCapstoneReg(MI->getOperand(0).getReg());

  return addImmToReg(MI, dest_reg, imm, scratchRegs);
}

bool ROPEngine::handleMov32rm(MachineInstr *MI,
                              std::vector<x86_reg> &scratchRegs) {
  BinaryAutopsy *BA = BinaryAutopsy::getInstance();
  ROPChain init, add, load, xchg, reorder;

  // Preliminary checks
  if (scratchRegs.size() < 1 || // there isn't at least 1 scratch register
      (MI->getOperand(0).getReg() == 0 // instruction uses a segment register
       || MI->getOperand(1).getReg() == 0))
    return false;

  // extract operands
  x86_reg dst = convertToCapstoneReg(MI->getOperand(0).getReg());
  x86_reg src = convertToCapstoneReg(MI->getOperand(1).getReg());

  unsigned displacement;
  if (MI->getOperand(4).isImm()) // is an immediate and not a symbol
    displacement = MI->getOperand(4).getImm();
  else
    return false;

  for (auto &scratchReg : scratchRegs) {
    init = BA->findGadgetPrimitive("init", scratchReg);
    add = BA->findGadgetPrimitive("add", scratchReg, src);
    load = BA->findGadgetPrimitive("load_1", scratchReg, scratchReg);

    reorder = undoXchgs(MI);
    xchg = BA->exchangeRegs(dst, scratchReg);
    BA->xgraph.reorderRegisters(); // otherwise the last xchg would be undone by
                                   // the next obfuscated instruction

    if (init.empty() || add.empty() || load.empty() || xchg.empty()) {
      BA->xgraph.reorderRegisters(); // xchg graph rollback
      continue;
    }

    init.emplace_back(ChainElem(displacement));
    chain.insert(chain.end(), init.begin(), init.end());
    chain.insert(chain.end(), add.begin(), add.end());
    chain.insert(chain.end(), load.begin(), load.end());
    chain.insert(chain.end(), reorder.begin(), reorder.end());
    chain.insert(chain.end(), xchg.begin(), xchg.end());

    return true;
  }

  return false;
}

bool ROPEngine::handleMov32mr(MachineInstr *MI,
                              std::vector<x86_reg> &scratchRegs) {
  BinaryAutopsy *BA = BinaryAutopsy::getInstance();
  ROPChain init, add, store, reorder;

  // Preliminary checks
  if (scratchRegs.size() < 1 || // there isn't at least 1 scratch register
      (MI->getOperand(0).getReg() == 0 // instruction uses a segment register
       || MI->getOperand(5).getReg() == 0))
    return false;

  // extract operands
  x86_reg dst = convertToCapstoneReg(MI->getOperand(0).getReg());
  x86_reg src = convertToCapstoneReg(MI->getOperand(5).getReg());

  unsigned displacement;
  if (MI->getOperand(3).isImm()) // is an immediate and not a symbol
    displacement = MI->getOperand(3).getImm();
  else
    return false;

  for (auto &scratchReg : scratchRegs) {
    init = BA->findGadgetPrimitive("init", scratchReg);
    add = BA->findGadgetPrimitive("add", scratchReg, dst);
    store = BA->findGadgetPrimitive("store", scratchReg, src);

    reorder = undoXchgs(MI);

    if (init.empty() || add.empty() || store.empty()) {
      BA->xgraph.reorderRegisters(); // xchg graph rollback
      continue;
    }

    init.emplace_back(ChainElem(displacement));
    chain.insert(chain.end(), init.begin(), init.end());
    chain.insert(chain.end(), add.begin(), add.end());
    chain.insert(chain.end(), store.begin(), store.end());
    chain.insert(chain.end(), reorder.begin(), reorder.end());

    return true;
  }

  return false;
}

ROPChain ROPEngine::ropify(MachineInstr &MI,
                           std::vector<x86_reg> &scratchRegs) {
  // if ESP is one of the operands of MI -> abort
  for (unsigned int i = 0; i < MI.getNumOperands(); i++) {
    if (MI.getOperand(i).isReg() && MI.getOperand(i).getReg() == X86::ESP)
      return chain;
  }

  DEBUG_WITH_TYPE(LIVENESS_ANALYSIS,
                  dbgs() << "[LivenessAnalysis] avail. scratch registers:\t");

  for (auto &a : scratchRegs) {
    DEBUG_WITH_TYPE(LIVENESS_ANALYSIS, dbgs() << a << " ");
  }
  DEBUG_WITH_TYPE(LIVENESS_ANALYSIS, dbgs() << "\n");

  switch (MI.getOpcode()) {
  // case X86::ADD32ri8:
  // case X86::ADD32ri:
  // case X86::SUB32ri8:
  // case X86::SUB32ri:
  // case X86::INC32r:
  // case X86::DEC32r: {
  //   if (!handleAddSubIncDec(&MI, scratchRegs))
  //     return chain;
  //   break;
  // }
  // case X86::MOV32rm: {
  //   if (!handleMov32rm(&MI, scratchRegs)) {
  //     return chain;
  //   }
  //   break;
  // }
  case X86::MOV32mr: {
    if (!handleMov32mr(&MI, scratchRegs)) {
      return chain;
    }
    break;
  }
  default:
    return chain;
  }

  return chain;
}

void ROPEngine::addToInstrMap(MachineInstr *MI, ChainElem CE) {
  // TODO: this won't be valid once the MI * gets invalidated after an erase().
  instrMap[MI].emplace_back(CE);
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