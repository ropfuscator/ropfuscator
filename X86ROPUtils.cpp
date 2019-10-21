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

void ROPEngine::undoXchgs(MachineInstr *MI) {
  BinaryAutopsy *BA = BinaryAutopsy::getInstance();
  // TODO: merge code with Xchg
  auto xchgPath = BA->undoXchgs();
  llvm::dbgs() << "undo xchgs: " << xchgPath.size() << "\n";
  int iter = 0;
  for (auto it = xchgPath.begin(); it != xchgPath.end(); it++) {
    llvm::dbgs() << "\t " << iter << "\n";
    // Skip equal and consecutive xchg gadgets
    if (it != xchgPath.end() && *(it + 1) == *it) {
      ++it;
      continue;
    }
    chain.emplace_back(ChainElem(*it));
    addToInstrMap(MI, ChainElem(*it));
    iter++;
  }
}

bool ROPEngine::addImmToReg(MachineInstr *MI, x86_reg reg, int immediate,
                            std::vector<x86_reg> const &scratchRegs) {
  BinaryAutopsy *BA = BinaryAutopsy::getInstance();

  for (auto &scratchReg : scratchRegs) {
    ROPChain init =
        BA->findGadgetPrimitive("init", getEffectiveReg(scratchReg));
    ROPChain add =
        BA->findGadgetPrimitive("add", reg, getEffectiveReg(scratchReg));

    if (init.empty() || add.empty()) {
      BA->xgraph.reorderRegisters(); // xchg graph rollback
      continue;
    }
    init.emplace_back(ChainElem(immediate));
    chain.insert(chain.end(), init.begin(), init.end());
    chain.insert(chain.end(), add.begin(), add.end());

    undoXchgs(MI);
    return true;
  }

  return false;
  /*
    Microgadget *pop, *add;
    x86_reg pop_0, add_0, add_1;
    x86_reg scratch = X86_REG_INVALID;

    // pop    pop_0
    // add    add_0, add_1

    bool combinationFound = false;

    for (auto &p : BA->gadgetLookup(X86_INS_POP, X86_OP_REG)) {
      if (combinationFound)
        break;
      pop_0 = p->getOp(0).reg;
      // dbgs() << p->asmInstr << "\n";

      for (auto &a : BA->gadgetLookup(X86_INS_ADD, X86_OP_REG, X86_OP_REG)) {
        if (combinationFound)
          break;
        add_0 = a->getOp(0).reg;
        add_1 = a->getOp(1).reg;
        // dbgs() << a->asmInstr << "\n";

        // REQ #1: src and dst operands cannot be the same
        if (add_0 == add_1)
          continue;

        // REQ #2: add_0 must be at least exchangeable with reg
        if (!BA->areExchangeable(reg, add_0))
          continue;

        // REQ #3: pop_0 (where we put the immediate) must be at least
        // exchangeable with add_1 (the src operand)
        if (!BA->areExchangeable(pop_0, add_1))
          continue;

        // REQ #4: pop_0 must be at least exchangeable with a scratch register
        // that must be different from reg.
        for (auto &sr : scratchRegs) {
          if (sr == reg)
            continue;
          if (BA->areExchangeable(sr, pop_0)) {
            scratch = sr;

            // if all these requirements are met, the whole gadget combination
            // is saved.
            add = a;
            pop = p;

            combinationFound = true;
            break;
          }
        }
      }
    }

    if (!combinationFound)
      return false;

    // dbgs() << "[*] Chosen gadgets: \n";
    // dbgs() << pop->asmInstr << "\n" << add->asmInstr << "\n";
    // dbgs() << "[*] Scratch reg: " << scratch << "\n";

    // Okay, now it's time to build the chain!

    // POP
    Xchg(MI, getEffectiveReg(scratch), pop_0);

    chain.emplace_back(ChainElem(pop));
    // dbgs() << pop->asmInstr << "\n"
    //<< "imm: " << immediate;
    chain.emplace_back(immediate);

    addToInstrMap(MI, ChainElem(pop));
    addToInstrMap(MI, ChainElem(immediate));

    // ADD
    Xchg(MI, getEffectiveReg(reg), add_0);
    Xchg(MI, getEffectiveReg(scratch), add_1);

    chain.emplace_back(ChainElem(add));
    addToInstrMap(MI, ChainElem(add));

    // dbgs() << add->asmInstr << "\n";
    undoXchgs(MI);*/
}

x86_reg ROPEngine::computeAddress(MachineInstr *MI, x86_reg inputReg,
                                  int displacement, x86_reg outputReg,
                                  std::vector<x86_reg> scratchRegs) {

  addImmToReg(MI, outputReg, displacement, scratchRegs);

  /*
  llvm::dbgs() << "eax: " << X86_REG_EAX << ", ebp: " << X86_REG_EBP
               << ", ecx: " << X86_REG_ECX << ", edx: " << X86_REG_EDX
               << ", edi:" << X86_REG_EDI << ", esi: " << X86_REG_ESI << "\n";
  Microgadget *mov, *pop, *add;
  x86_reg mov_0, mov_1, pop_0, add_0, add_1;

  x86_reg scratchR1 = X86_REG_INVALID;
  x86_reg scratchR2 = X86_REG_INVALID;

  // To successfully compute the address, we need a compatible set of gadgets
  // like this (parametrising the operands):
  //    mov     mov_0, mov_1
  //    pop     pop_0
  //    add     add_0, add_1
  //
  // In order to be suitable, this set of gadgets must meet several
  // requirements, i.e. constraints on the operands of each instruction, that
  // are checked in the inner for cycle.

  // We have to find a valid combination given three sets of gadgets for mov,
  // pop and add instructions, and with only register operands.
  bool combinationFound = false;

  for (auto &m : BA->findAllGadgets(X86_INS_MOV, X86_OP_REG, X86_OP_REG)) {
    if (combinationFound)
      break;
    mov_0 = m->getOp(0).reg;
    mov_1 = m->getOp(1).reg;

    for (auto &p : BA->findAllGadgets(X86_INS_POP, X86_OP_REG)) {
      if (combinationFound)
        break;
      pop_0 = p->getOp(0).reg;

      for (auto &a : BA->findAllGadgets(X86_INS_ADD, X86_OP_REG, X86_OP_REG)) {
        if (combinationFound)
          break;
        add_0 = a->getOp(0).reg;
        add_1 = a->getOp(1).reg;

        // REQ #1: src and dst operands cannot be the same
        if (add_0 == add_1)
          continue;

        // REQ #2: mov_0, add_0 and outputReg must belong to the same exchange
        // path (i.e. they are exchangeable)
        if (!BA->areExchangeable(mov_0, add_0, outputReg))
          continue;

        // REQ #3: pop_0, add_1 must belong to the same exchange path
        if (!BA->areExchangeable(pop_0, add_1))
          continue;

        // REQ #4: mov_1, inputReg must belong to the same exchange path
        if (!BA->areExchangeable(mov_1, inputReg))
          continue;

        // REQ #5: mov_0 and pop_0 must be different, because we need the two
        // operands (base address and displacement) in different registers.
        if (mov_0 == pop_0)
          continue;

        // REQ #6: mov_0 and pop_0 must be exchangeable with two different
        // scratch registers.
        for (auto &sr1 : scratchRegs) {
          if (combinationFound)
            break;

          for (auto &sr2 : scratchRegs) {
            if (sr1 == sr2)
              continue;
            if (BA->areExchangeable(sr1, mov_0) &&
                BA->areExchangeable(sr2, pop_0)) {
              scratchR1 = sr1;
              scratchR2 = sr2;

              // if all these requirements are met, the whole gadget combination
              // is saved.
              add = a;
              pop = p;
              mov = m;

              combinationFound = true;
              break;
            }
          }
        }
      }
    }
  }

  if (combinationFound) {

    dbgs() << "[*] Chosen gadgets: \n\t";
    dbgs() << mov->asmInstr << "\n\t" << pop->asmInstr << "\n\t"
           << add->asmInstr << "\n\t";
    dbgs() << "[*] Scratch regs: " << scratchR1 << ", " << scratchR2 << "\n";

    //
    //
    // MOV
    dbgs() << "MOV\tSR1:" << getEffectiveReg(scratchR1)
           << ", SR2:" << getEffectiveReg(scratchR2) << "\n";
    BA->xgraph.printAll();

    Xchg(MI, getEffectiveReg(scratchR1), mov_0);
    Xchg(MI, getEffectiveReg(inputReg), mov_1);

    chain.emplace_back(ChainElem(mov));
    addToInstrMap(MI, ChainElem(mov));

    //
    //
    // POP

    dbgs() << "ADD\tSR1:" << getEffectiveReg(scratchR1)
           << ", SR2:" << getEffectiveReg(scratchR2) << "\n";
    BA->xgraph.printAll();

    Xchg(MI, getEffectiveReg(scratchR2), pop_0);

    chain.emplace_back(ChainElem(pop));
    addToInstrMap(MI, ChainElem(pop));
    chain.emplace_back(displacement);
    addToInstrMap(MI, ChainElem(displacement));

    //
    //
    // ADD

    dbgs() << "ADD\tSR1:" << getEffectiveReg(scratchR1)
           << ", SR2:" << getEffectiveReg(scratchR2) << "\n";
    BA->xgraph.printAll();

    Xchg(MI, getEffectiveReg(scratchR1), add_0);
    Xchg(MI, getEffectiveReg(scratchR2), add_1);

    chain.emplace_back(ChainElem(add));
    addToInstrMap(MI, ChainElem(add));

    // dbgs() << add->asmInstr << "\n";
  }

  // return the register where the computed address is saved. It is the LOGICAL
  // register, so whoever will use it, has to find the EFFECTIVE register that
  // holds it.
  return scratchR1;*/
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
    llvm::dbgs() << "*******\ninit: " << scratchReg << "("
                 << getEffectiveReg(scratchReg) << "), " << displacement
                 << "\n";
    ROPChain init =
        BA->findGadgetPrimitive("init", getEffectiveReg(scratchReg));
    for (auto &a : init) {
      if (a.type == GADGET)
        llvm::dbgs() << a.microgadget->asmInstr << "\n";
    }
    if (init.empty()) {
      llvm::dbgs() << "*******\nInvalid ROP Chain: rolling back...\n";
      BA->xgraph.reorderRegisters(); // xchg graph rollback
      continue;
    }

    llvm::dbgs() << "*******\nadd: " << scratchReg << "("
                 << getEffectiveReg(scratchReg) << "), " << src << " ("
                 << getEffectiveReg(src) << ")\n";
    ROPChain add = BA->findGadgetPrimitive("add", getEffectiveReg(scratchReg),
                                           getEffectiveReg(src));
    for (auto &a : add) {
      llvm::dbgs() << a.microgadget->asmInstr << "\n";
    }
    if (add.empty()) {
      llvm::dbgs() << "*******\nInvalid ROP Chain: rolling back...\n";
      BA->xgraph.reorderRegisters(); // xchg graph rollback
      continue;
    }

    llvm::dbgs() << "*******\nload: " << dst << " (" << getEffectiveReg(dst)
                 << "), " << scratchReg << "(" << getEffectiveReg(scratchReg)
                 << ")\n";
    ROPChain load = BA->findGadgetPrimitive("load_1", getEffectiveReg(dst),
                                            getEffectiveReg(scratchReg));
    for (auto &a : load) {
      llvm::dbgs() << a.microgadget->asmInstr << "\n";
    }

    if (load.empty()) {
      llvm::dbgs() << "*******\nInvalid ROP Chain: rolling back...\n";
      BA->xgraph.reorderRegisters(); // xchg graph rollback
      continue;
    }
    init.emplace_back(ChainElem(displacement));
    chain.insert(chain.end(), init.begin(), init.end());
    chain.insert(chain.end(), add.begin(), add.end());
    chain.insert(chain.end(), load.begin(), load.end());

    undoXchgs(MI);

    llvm::dbgs() << "[*] Final ropchain:\n";
    for (auto &g : chain)
      if (g.type == GADGET)
        llvm::dbgs() << g.microgadget->asmInstr << "\n";
    llvm::dbgs() << "\n";
    return true;
  }

  return false;

  /*
  // We will replace this instruction with its register-register variant,
  // like this (parametrising the operands):
  //      mov     mov_0, [mov_1]

  for (auto &m : BA->findAllGadgets(X86_INS_MOV, X86_OP_REG, X86_OP_MEM)) {
    mov_0 = m->getOp(0).reg;
    mov_1 = static_cast<x86_reg>(m->getOp(1).mem.base);
    int mov_disp = m->getOp(1).mem.disp;

    // if the two dst operands aren't connected, skip the gadget
    if (!BA->areExchangeable(orig_0, mov_0))
      continue;

    // Of course, we do need to put in "mov_1" the value of "orig_1 + disp".
    // To do this, we call the computeAddress function passing the following
    // parameters:
    //    - orig_1: input register, that is the register where the base
    //    memory address is located
    //    - orig_disp - mov_disp: difference of the displacement of the
    //    original instruction and the gadget; we do this in order to
    //    compensate the displacement that may be embedded in the gadget
    //    (e.g. mov reg1, [reg2 + 0x50])
    //    - mov_1: output register, namely the register in which we'd prefer
    //    to retrieve the result; if this is not possible, the result is
    //    placed in a register that is at least reachable via a series of
    //    xchg gadgets
    //    - scratchRegs: a list of scratch registers that can be clobbered
    auto res =
        computeAddress(MI, orig_1, orig_disp - mov_disp, mov_1, scratchRegs);

    if (res != X86_REG_INVALID) {
      address = res;
      mov = m;
      break;
    }
  }

  if (address == X86_REG_INVALID)
    return false;

  /*dbgs() << "Results returned in: " << address << "\n";
  dbgs() << "[*] Chosen gadgets: \n";
  dbgs() << mov->asmInstr << "\n\n";

  // -----------

  dbgs() << "MOV32MR. Results in " << address << " ("
         << getEffectiveReg(address) << ")\n";
  dbgs() << "mov_0: " << mov_0 << " (" << getEffectiveReg(mov_0)
         << "), mov_1:" << mov_1 << " (" << getEffectiveReg(mov_1)
         << "), orig_0: " << orig_0 << " (" << getEffectiveReg(orig_0) << ")\n";

  Xchg(MI, getEffectiveReg(orig_0), mov_0);
  Xchg(MI, getEffectiveReg(address), mov_1);

  chain.emplace_back(ChainElem(mov));
  addToInstrMap(MI, ChainElem(mov));

  // dbgs() << mov->asmInstr << "\n";
  undoXchgs(MI);
  return true;*/
}

bool ROPEngine::handleMov32mr(MachineInstr *MI,
                              std::vector<x86_reg> &scratchRegs) {
  BinaryAutopsy *BA = BinaryAutopsy::getInstance();
  x86_reg orig_0, orig_1, mov_0, mov_1, address = X86_REG_INVALID;
  int orig_disp;
  Microgadget *mov;

  // NOTE: for more comments, please check the case MOV32rm: we adopt the
  // very same strategies.

  // no scratch registers are available, or the dst operand is ESP
  // (we are unable to modify it since we are using microgadgets) -> abort.
  if (scratchRegs.size() < 2)
    return false;

  // sometimes mov instructions have operands that use segment registers, and
  // we just cannot handle them
  if (MI->getOperand(0).getReg() == 0 || MI->getOperand(5).getReg() == 0)
    return false;

  // dump all the useful operands from the MachineInstr we are processing:
  //      mov     [orig_0 + disp], orig_1
  orig_0 = convertToCapstoneReg(MI->getOperand(0).getReg()); // dst
  orig_1 = convertToCapstoneReg(MI->getOperand(5).getReg()); // src

  if (!MI->getOperand(3).isImm())
    return false;

  orig_disp = MI->getOperand(3).getImm(); // displacement

  for (auto &m : BA->findAllGadgets(X86_INS_MOV, X86_OP_MEM, X86_OP_REG)) {
    // dbgs() << m->asmInstr << "\n";
    //      mov     [mov_0], mov_1
    mov_0 = static_cast<x86_reg>(m->getOp(0).mem.base);
    mov_1 = m->getOp(1).reg;
    int mov_disp = m->getOp(0).mem.disp;

    // if the two src operands aren't connected, skip the gadget
    if (!BA->areExchangeable(orig_1, mov_1))
      continue;

    auto res =
        computeAddress(MI, orig_0, orig_disp - mov_disp, mov_0, scratchRegs);

    if (res != X86_REG_INVALID) {
      address = res;
      mov = m;
      break;
    }
  }

  if (address == X86_REG_INVALID)
    return false;

  dbgs() << "Results returned in: " << address << "\n";
  dbgs() << "[*] Chosen gadget: \n";
  dbgs() << mov->asmInstr << "\n\n";

  dbgs() << "MOV32MR. Results in " << address << " ("
         << getEffectiveReg(address) << ")\n";

  Xchg(MI, getEffectiveReg(orig_1), mov_1);
  Xchg(MI, getEffectiveReg(address), mov_0);

  chain.emplace_back(ChainElem(mov));
  addToInstrMap(MI, ChainElem(mov));

  dbgs() << mov->asmInstr << "\n";
  undoXchgs(MI);
  return true;
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
  case X86::MOV32rm: {
    if (!handleMov32rm(&MI, scratchRegs)) {
      return chain;
    }
    break;
  }
  // case X86::MOV32mr: {
  //   if (!handleMov32mr(&MI, scratchRegs)) {
  //     return chain;
  //   }
  //   break;
  // }
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