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

ROPChainStatus ROPEngine::addSubImmToReg(MachineInstr *MI, x86_reg reg,
                               bool isSub, int immediate,
                               std::vector<x86_reg> const &scratchRegs) {
  BinaryAutopsy *BA = BinaryAutopsy::getInstance();
  ROPChain init, addsub, reorder;

  for (auto &scratchReg : scratchRegs) {
    init = BA->findGadgetPrimitive("init", scratchReg);
    addsub = BA->findGadgetPrimitive(isSub ? "sub" : "add", reg, scratchReg);
    reorder = BA->undoXchgs();

    if (init.empty() || addsub.empty()) {
      BA->xgraph.reorderRegisters(); // xchg graph rollback
      continue;
    }
    init.emplace_back(ChainElem(immediate));
    chain.insert(chain.end(), init.begin(), init.end());
    chain.insert(chain.end(), addsub.begin(), addsub.end());
    chain.insert(chain.end(), reorder.begin(), reorder.end());

    return ROPChainStatus::OK;
  }

  return ROPChainStatus::ERR_NO_GADGETS_AVAILABLE;
}

ROPChainStatus ROPEngine::handleAddSubIncDec(MachineInstr *MI,
                                   std::vector<x86_reg> &scratchRegs) {
  unsigned opcode = MI->getOpcode();

  bool isSub;
  int imm;
  x86_reg dest_reg;

  // no scratch registers are available -> abort.
  if (scratchRegs.empty())
    return ROPChainStatus::ERR_NO_REGISTER_AVAILABLE;

  switch (opcode) {
  case X86::ADD32ri8:
  case X86::ADD32ri: {
    if (!MI->getOperand(2).isImm())
      return ROPChainStatus::ERR_UNSUPPORTED;

    isSub = false;
    imm = MI->getOperand(2).getImm();

    break;
  }
  case X86::SUB32ri8:
  case X86::SUB32ri: {
    if (!MI->getOperand(2).isImm())
      return ROPChainStatus::ERR_UNSUPPORTED;

    isSub = true;
    imm = MI->getOperand(2).getImm();

    break;
  }
  case X86::INC32r: {
    isSub = false;
    imm = 1;
    break;
  }
  case X86::DEC32r: {
    isSub = true;
    imm = 1;
    break;
  }
  default:
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  dest_reg = convertToCapstoneReg(MI->getOperand(0).getReg());

  return addSubImmToReg(MI, dest_reg, isSub, imm, scratchRegs);
}

ROPChainStatus ROPEngine::handleMov32rm(MachineInstr *MI,
                              std::vector<x86_reg> &scratchRegs) {
  BinaryAutopsy *BA = BinaryAutopsy::getInstance();
  ROPChain init, add, load, xchg, reorder;

  // Preliminary checks
  if (scratchRegs.size() < 1) // there isn't at least 1 scratch register
    return ROPChainStatus::ERR_NO_REGISTER_AVAILABLE;

  if (MI->getOperand(0).getReg() == 0 // instruction uses a segment register
       || MI->getOperand(1).getReg() == 0)
    return ROPChainStatus::ERR_UNSUPPORTED;

  // skip scaled-index addressing mode since we cannot handle them
  //      mov     orig_0, [orig_1 + scale_2 * orig_3 + disp_4]
  if (MI->getOperand(3).isReg() && MI->getOperand(3).getReg() != 0)
    return ROPChainStatus::ERR_UNSUPPORTED;

  // extract operands
  x86_reg dst = convertToCapstoneReg(MI->getOperand(0).getReg());
  x86_reg src = convertToCapstoneReg(MI->getOperand(1).getReg());

  unsigned displacement;
  if (MI->getOperand(4).isImm()) // is an immediate and not a symbol
    displacement = MI->getOperand(4).getImm();
  else
    return ROPChainStatus::ERR_UNSUPPORTED;

  for (auto &scratchReg : scratchRegs) {
    init = BA->findGadgetPrimitive("init", scratchReg);
    add = BA->findGadgetPrimitive("add", scratchReg, src);
    load = BA->findGadgetPrimitive("load_1", scratchReg, scratchReg);

    reorder = BA->undoXchgs();
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

    return ROPChainStatus::OK;
  }

  return ROPChainStatus::ERR_NO_GADGETS_AVAILABLE;
}

ROPChainStatus ROPEngine::handleMov32mr(MachineInstr *MI,
                              std::vector<x86_reg> &scratchRegs) {
  BinaryAutopsy *BA = BinaryAutopsy::getInstance();
  ROPChain init, add, store, reorder;

  // Preliminary checks
  if (scratchRegs.size() < 1) // there isn't at least 1 scratch register
    return ROPChainStatus::ERR_NO_REGISTER_AVAILABLE;

  if (MI->getOperand(0).getReg() == 0 // instruction uses a segment register
       || MI->getOperand(5).getReg() == 0)
    return ROPChainStatus::ERR_UNSUPPORTED;

  // skip scaled-index addressing mode since we cannot handle them
  //      mov     [orig_0 + scale_1 * orig_2 + disp_3], orig_5
  if (MI->getOperand(2).isReg() && MI->getOperand(2).getReg() != 0)
    return ROPChainStatus::ERR_UNSUPPORTED;

  // extract operands
  x86_reg dst = convertToCapstoneReg(MI->getOperand(0).getReg());
  x86_reg src = convertToCapstoneReg(MI->getOperand(5).getReg());

  unsigned displacement;
  if (MI->getOperand(3).isImm()) // is an immediate and not a symbol
    displacement = MI->getOperand(3).getImm();
  else
    return ROPChainStatus::ERR_UNSUPPORTED;

  for (auto &scratchReg : scratchRegs) {
    init = BA->findGadgetPrimitive("init", scratchReg);
    add = BA->findGadgetPrimitive("add", scratchReg, dst);
    store = BA->findGadgetPrimitive("store", scratchReg, src);

    reorder = BA->undoXchgs();

    if (init.empty() || add.empty() || store.empty()) {
      BA->xgraph.reorderRegisters(); // xchg graph rollback
      continue;
    }

    init.emplace_back(ChainElem(displacement));
    chain.insert(chain.end(), init.begin(), init.end());
    chain.insert(chain.end(), add.begin(), add.end());
    chain.insert(chain.end(), store.begin(), store.end());
    chain.insert(chain.end(), reorder.begin(), reorder.end());

    return ROPChainStatus::OK;
  }

  return ROPChainStatus::ERR_NO_GADGETS_AVAILABLE;
}

ROPChainStatus ROPEngine::handleMov32mi(MachineInstr *MI,
                              std::vector<x86_reg> &scratchRegs) {
  BinaryAutopsy *BA = BinaryAutopsy::getInstance();
  ROPChain initImm, initOfs, add, store, reorder;

  // Preliminary checks
  if (scratchRegs.size() < 2) // there isn't at least 2 scratch register
    return ROPChainStatus::ERR_NO_REGISTER_AVAILABLE;

  if (MI->getOperand(0).getReg() == 0) // instruction uses a segment register
    return ROPChainStatus::ERR_UNSUPPORTED;

  // skip scaled-index addressing mode since we cannot handle them
  //      mov     [orig_0 + scale_1 * orig_2 + disp_3], orig_5
  if (MI->getOperand(2).isReg() && MI->getOperand(2).getReg() != 0)
    return ROPChainStatus::ERR_UNSUPPORTED;

  // extract operands
  x86_reg dst = convertToCapstoneReg(MI->getOperand(0).getReg());
  unsigned int imm = (unsigned int)MI->getOperand(5).getImm();

  unsigned displacement;
  if (MI->getOperand(3).isImm()) // is an immediate and not a symbol
    displacement = MI->getOperand(3).getImm();
  else
    return ROPChainStatus::ERR_UNSUPPORTED;

  for (auto &scratchReg1 : scratchRegs) {
    for (auto &scratchReg2 : scratchRegs) {
      if (scratchReg1 == scratchReg2)
        continue;
      initImm = BA->findGadgetPrimitive("init", scratchReg2);
      initOfs = BA->findGadgetPrimitive("init", scratchReg1);
      add = BA->findGadgetPrimitive("add", scratchReg1, dst);
      store = BA->findGadgetPrimitive("store", scratchReg1, scratchReg2);

      reorder = BA->undoXchgs();

      if (initImm.empty() || initOfs.empty() || add.empty() || store.empty()) {
        BA->xgraph.reorderRegisters(); // xchg graph rollback
        continue;
      }

      initImm.emplace_back(ChainElem(imm));
      initOfs.emplace_back(ChainElem(displacement));
      chain.insert(chain.end(), initImm.begin(), initImm.end());
      chain.insert(chain.end(), initOfs.begin(), initOfs.end());
      chain.insert(chain.end(), add.begin(), add.end());
      chain.insert(chain.end(), store.begin(), store.end());
      chain.insert(chain.end(), reorder.begin(), reorder.end());

      return ROPChainStatus::OK;
    }
  }

  return ROPChainStatus::ERR_NO_GADGETS_AVAILABLE;
}

ROPChainStatus ROPEngine::handleMov32rr(MachineInstr *MI,
                              std::vector<x86_reg> &scratchRegs) {
  BinaryAutopsy *BA = BinaryAutopsy::getInstance();
  ROPChain store, reorder;

  if (MI->getOperand(0).getReg() == 0 || MI->getOperand(1).getReg() == 0)
    return ROPChainStatus::ERR_UNSUPPORTED;

  // extract operands
  x86_reg dst = convertToCapstoneReg(MI->getOperand(0).getReg());
  x86_reg src = convertToCapstoneReg(MI->getOperand(1).getReg());

  store = BA->findGadgetPrimitive("copy", dst, src);
  reorder = BA->undoXchgs();

  if (store.empty())
    return ROPChainStatus::ERR_NO_GADGETS_AVAILABLE;

  chain.insert(chain.end(), store.begin(), store.end());
  chain.insert(chain.end(), reorder.begin(), reorder.end());

  return ROPChainStatus::OK;
}

ROPChainStatus ROPEngine::handleCmp32mi(MachineInstr *MI,
                              std::vector<x86_reg> &scratchRegs) {
  BinaryAutopsy *BA = BinaryAutopsy::getInstance();
  ROPChain initImm, initOfs, add, load, sub, reorder;

  // Preliminary checks
  if (scratchRegs.size() < 2) // there isn't at least 2 scratch register
    return ROPChainStatus::ERR_NO_REGISTER_AVAILABLE;

  if (MI->getOperand(0).getReg() == 0) // instruction uses a segment register
    return ROPChainStatus::ERR_UNSUPPORTED;

  // skip scaled-index addressing mode since we cannot handle them
  //      cmp     [orig_0 + scale_1 * orig_2 + disp_3], orig_5
  if (MI->getOperand(2).isReg() && MI->getOperand(2).getReg() != 0
      || MI->getOperand(4).isReg() && MI->getOperand(4).getReg() != 0)
    return ROPChainStatus::ERR_UNSUPPORTED;

  // extract operands
  x86_reg dst = convertToCapstoneReg(MI->getOperand(0).getReg());
  unsigned int imm = (unsigned int)MI->getOperand(5).getImm();

  unsigned displacement;
  if (MI->getOperand(3).isImm()) // is an immediate and not a symbol
    displacement = MI->getOperand(3).getImm();
  else
    return ROPChainStatus::ERR_UNSUPPORTED;

  for (auto &scratchReg1 : scratchRegs) {
    for (auto &scratchReg2 : scratchRegs) {
      if (scratchReg1 == scratchReg2)
        continue;
      initImm = BA->findGadgetPrimitive("init", scratchReg2);
      initOfs = BA->findGadgetPrimitive("init", scratchReg1);
      add = BA->findGadgetPrimitive("add", scratchReg1, dst);
      load = BA->findGadgetPrimitive("load_1", scratchReg1);
      sub = BA->findGadgetPrimitive("sub", scratchReg1, scratchReg2);

      reorder = BA->undoXchgs();

      if (initImm.empty() || initOfs.empty() || add.empty() || load.empty() || sub.empty()) {
        BA->xgraph.reorderRegisters(); // xchg graph rollback
        continue;
      }

      initImm.emplace_back(ChainElem(imm));
      initOfs.emplace_back(ChainElem(displacement));
      chain.insert(chain.end(), initImm.begin(), initImm.end());
      chain.insert(chain.end(), initOfs.begin(), initOfs.end());
      chain.insert(chain.end(), add.begin(), add.end());
      chain.insert(chain.end(), load.begin(), load.end());
      chain.insert(chain.end(), sub.begin(), sub.end());
      chain.insert(chain.end(), reorder.begin(), reorder.end());

      return ROPChainStatus::OK;
    }
  }

  return ROPChainStatus::ERR_NO_GADGETS_AVAILABLE;
}

ROPChainStatus ROPEngine::handleCmp32ri(MachineInstr *MI,
                              std::vector<x86_reg> &scratchRegs) {
  BinaryAutopsy *BA = BinaryAutopsy::getInstance();
  ROPChain init, copy, sub, reorder;

  // Preliminary checks
  if (scratchRegs.size() < 2) // there isn't at least 2 scratch register
    return ROPChainStatus::ERR_NO_REGISTER_AVAILABLE;

  if (MI->getOperand(0).getReg() == 0 || !MI->getOperand(1).isImm())
    return ROPChainStatus::ERR_UNSUPPORTED;

  // extract operands
  x86_reg reg = convertToCapstoneReg(MI->getOperand(0).getReg());
  unsigned int imm = (unsigned int)MI->getOperand(1).getImm();

  for (auto &scratchReg1 : scratchRegs) {
    for (auto &scratchReg2 : scratchRegs) {
      if (scratchReg1 == scratchReg2)
        continue;
      init = BA->findGadgetPrimitive("init", scratchReg2);
      copy = BA->findGadgetPrimitive("copy", scratchReg1, reg);
      sub = BA->findGadgetPrimitive("sub", scratchReg1, scratchReg2);

      reorder = BA->undoXchgs();

      if (init.empty() || copy.empty() || sub.empty()) {
        BA->xgraph.reorderRegisters(); // xchg graph rollback
        continue;
      }

      init.emplace_back(ChainElem(imm));
      chain.insert(chain.end(), init.begin(), init.end());
      chain.insert(chain.end(), copy.begin(), copy.end());
      chain.insert(chain.end(), sub.begin(), sub.end());
      chain.insert(chain.end(), reorder.begin(), reorder.end());

      return ROPChainStatus::OK;
    }
  }

  return ROPChainStatus::ERR_NO_GADGETS_AVAILABLE;
}

ROPChainStatus ROPEngine::ropify(MachineInstr &MI, std::vector<x86_reg> &scratchRegs,
                           bool &flagIsModifiedInInstr, ROPChain &resultChain) {
  // if ESP is one of the operands of MI -> abort
  for (unsigned int i = 0; i < MI.getNumOperands(); i++) {
    if (MI.getOperand(i).isReg() && MI.getOperand(i).getReg() == X86::ESP)
      return ROPChainStatus::ERR_UNSUPPORTED_STACKPOINTER;
  }

  DEBUG_WITH_TYPE(LIVENESS_ANALYSIS,
                  dbgs() << "[LivenessAnalysis] avail. scratch registers:\t");

  for (auto &a : scratchRegs) {
    DEBUG_WITH_TYPE(LIVENESS_ANALYSIS, dbgs() << a << " ");
  }
  DEBUG_WITH_TYPE(LIVENESS_ANALYSIS, dbgs() << "\n");

  ROPChainStatus status;
  switch (MI.getOpcode()) {
  case X86::ADD32ri8:
  case X86::ADD32ri:
  case X86::SUB32ri8:
  case X86::SUB32ri:
  case X86::INC32r:
  case X86::DEC32r: {
    status = handleAddSubIncDec(&MI, scratchRegs);
    flagIsModifiedInInstr = true;
    break;
  }
  case X86::CMP32mi:
  case X86::CMP32mi8:
    status = handleCmp32mi(&MI, scratchRegs);
    flagIsModifiedInInstr = true;
    break;
  case X86::CMP32ri:
  case X86::CMP32ri8:
    status = handleCmp32ri(&MI, scratchRegs);
    flagIsModifiedInInstr = true;
    break;
  case X86::MOV32rm: {
    status = handleMov32rm(&MI, scratchRegs);
    flagIsModifiedInInstr = false;
    break;
  }
  case X86::MOV32mr: {
    status = handleMov32mr(&MI, scratchRegs);
    flagIsModifiedInInstr = false;
    break;
  }
  case X86::MOV32mi:
    status = handleMov32mi(&MI, scratchRegs);
    flagIsModifiedInInstr = false;
    break;
  case X86::MOV32rr:
    status = handleMov32rr(&MI, scratchRegs);
    flagIsModifiedInInstr = false;
    break;
  default:
    return ROPChainStatus::ERR_NOT_IMPLEMENTED;
  }

  removeDuplicates(chain);
  resultChain = std::move(chain);
  return status;
}

void ROPEngine::removeDuplicates(ROPChain &chain) {
  bool duplicates;

  do {
    duplicates = false;
    if (chain.size() < 2)
      break;

    for (auto it = chain.begin() + 1; it != chain.end();) {
      // equal microgadgets, but only if they're both XCHG instructions
      if (*it == *(it - 1) && it->type == GADGET &&
          it->microgadget->getID() == X86_INS_XCHG) {
        it = chain.erase(it - 1);
        it = chain.erase(it);
        duplicates = true;
      }
      if (it != chain.end())
        ++it;
      else
        break;
    }

  } while (duplicates);
}

void generateChainLabels(char **chainLabel, char **chainLabelC,
                         char **resumeLabel, char **resumeLabelC,
                         StringRef funcName, int chainID) {
  using namespace std;
  string funcName_s = funcName.str();
  string chainLabel_s = funcName_s + "_chain_" + to_string(chainID);
  std::replace(chainLabel_s.begin(), chainLabel_s.end(), '$', '_');
  string chainLabelC_s = chainLabel_s + ":";
  string resumeLabel_s = "resume_" + chainLabel_s;
  string resumeLabelC_s = resumeLabel_s + ":";

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