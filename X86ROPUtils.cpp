#include "X86ROPUtils.h"
#include "RopfuscatorCapstoneLLVMAdpt.h"
#include "RopfuscatorDebug.h"
#include "llvm/CodeGen/MachineFunction.h"
#include <dirent.h>
#include <fmt/format.h>
#include <fmt/ostream.h>

using namespace llvm;

static cl::opt<bool> OpaquePredicatesEnabled(
    "fopaque-predicates",
    cl::desc("Enable the injection of opaque predicates"));

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
    return true;
  }

  uint maxrecursedepth = 3;
  libraryPath.clear();

  for (auto &folder : POSSIBLE_LIBC_FOLDERS) {
    if (recurseLibcDir(folder.c_str(), libraryPath, maxrecursedepth))
      return true;
  }
  return false;
}

// ------------------------------------------------------------------------
// Chain Element
// ------------------------------------------------------------------------

ChainElem::ChainElem(Microgadget *gadget) {
  this->microgadget = gadget;
  this->type = GADGET;
  this->symbol = ROPChain::BA->getRandomSymbol();
}

ChainElem::ChainElem(int64_t value) : value(value) { type = IMMEDIATE; }

uint64_t ChainElem::getRelativeAddress() {
  return microgadget->getAddress() - symbol->Address;
}

// ------------------------------------------------------------------------
// ROP Chain
// ------------------------------------------------------------------------

int ROPChain::globalChainID = 0;

std::string libraryPath;
bool libraryFound = getLibraryPath(libraryPath);

BinaryAutopsy *ROPChain::BA = BinaryAutopsy::getInstance(libraryPath);

ROPChain::ROPChain(MachineBasicBlock &MBB, MachineInstr &injectionPoint,
                   ScratchRegTracker &SRT)
    : MBB(&MBB), injectionPoint(injectionPoint), SRT(SRT) {
  MF = MBB.getParent();
  TII = MF->getTarget().getMCInstrInfo();
  chainID = globalChainID++;

  // Creates all the labels
  sprintf(chainLabel, ".chain_%d", chainID);
  sprintf(chainLabel_C, ".chain_%d:", chainID);
  sprintf(resumeLabel, ".resume_%d", chainID);
  sprintf(resumeLabel_C, ".resume_%d:", chainID);
}

ROPChain::~ROPChain() { globalChainID--; }

void ROPChain::inject() {
  // dbgs() << "injecting " << chain.size() << " gadgets!\n";
  // PROLOGUE: saves the EIP value before executing the ROP chain

  // pushf (EFLAGS register backup): important because the opaque predicate
  // validation, and in general all the operations performed during the rop
  // chain execution, may alter the flags. If that happens, subsequent
  // conditional jumps may act in an unpredictable way!
  BuildMI(*MBB, injectionPoint, nullptr, TII->get(X86::PUSHF32));
  // call chain_X
  BuildMI(*MBB, injectionPoint, nullptr, TII->get(X86::CALLpcrel32))
      .addExternalSymbol(chainLabel);
  // jmp resume_X
  BuildMI(*MBB, injectionPoint, nullptr, TII->get(X86::JMP_1))
      .addExternalSymbol(resumeLabel);
  // chain_X:
  BuildMI(*MBB, injectionPoint, nullptr, TII->get(TargetOpcode::INLINEASM))
      .addExternalSymbol(chainLabel_C)
      .addImm(0);

  // Pushes each gadget onto the stack in reverse order
  for (auto e = chain.rbegin(); e != chain.rend(); ++e) {
    switch (e->type) {

    case IMMEDIATE: {
      // Push the immediate value onto the stack //
      // push $imm
      BuildMI(*MBB, injectionPoint, nullptr, TII->get(X86::PUSHi32))
          .addImm(e->value);
      break;
    }

    case GADGET: {
      // Push a random symbol that, when resolved by the dynamic linker, will be
      // used as base address; then add the offset to point a specific
      // gadget
      if (OpaquePredicatesEnabled) {
        // call $opaquePredicate
        BuildMI(*MBB, injectionPoint, nullptr, TII->get(X86::CALLpcrel32))
            .addExternalSymbol("opaquePredicate");

        // je $wrong_target
        BuildMI(*MBB, injectionPoint, nullptr, TII->get(X86::JNE_1))
            .addExternalSymbol(chainLabel);
      }

      // .symver directive: necessary to prevent aliasing when more
      // symbols have the same name. We do this exclusively when the symbol
      // Version is not "Base" (i.e., it is the only one available).
      if (strcmp(e->symbol->Version, "Base") != 0) {
        BuildMI(*MBB, injectionPoint, nullptr,
                TII->get(TargetOpcode::INLINEASM))
            .addExternalSymbol(e->symbol->getSymVerDirective())
            .addImm(0);
      }

      // push $symbol
      BuildMI(*MBB, injectionPoint, nullptr, TII->get(X86::PUSHi32))
          .addExternalSymbol(e->symbol->Label);

      // add [esp], $offset
      addDirectMem(
          BuildMI(*MBB, injectionPoint, nullptr, TII->get(X86::ADD32mi)),
          X86::ESP)
          .addImm(e->getRelativeAddress());
      break;
    }
    }
  }
  // EPILOGUE Emits the `ret` instruction which will trigger the chain
  // execution, and a label to resume the normal execution flow when the chain
  // has finished.
  // ret
  BuildMI(*MBB, injectionPoint, nullptr, TII->get(X86::RETL));
  // resume_X:
  BuildMI(*MBB, injectionPoint, nullptr, TII->get(TargetOpcode::INLINEASM))
      .addExternalSymbol(resumeLabel_C)
      .addImm(0);
  // popf (EFLAGS register restore)
  BuildMI(*MBB, injectionPoint, nullptr, TII->get(X86::POPF32));

  // Deletes the initial instructions
  for (MachineInstr *MI : instructionsToDelete) {
    instrMap.erase(MI);
    MI->eraseFromParent();
  }
}

bool ROPChain::addInstruction(MachineInstr &MI) {
  bool ok;

  assert(!finalized && "Attempt to modify a finalized chain!");

  ok = mapBindings(MI);

  if (ok)
    instructionsToDelete.push_back(&MI);

  return ok;
}

int ROPChain::Xchg(MachineInstr *MI, x86_reg a, x86_reg b) {
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

void ROPChain::DoubleXchg(MachineInstr *MI, x86_reg a, x86_reg b, x86_reg c,
                          x86_reg d) {
  Xchg(MI, a, b);

  // just a fancy way to check if the two pairs of operands are the same,
  // regardless of their order.
  if (((std::min(a, b) == std::min(c, d)) &&
       (std::max(a, b) == std::max(c, d)))) {

    DEBUG_WITH_TYPE(XCHG_CHAIN, dbgs() << "[XchgChain]\t"
                                       << "avoiding double-xchg between " << c
                                       << " and " << d << "\n");
  } else {
    Xchg(MI, c, d);
  }
}

bool ROPChain::addImmToReg(MachineInstr *MI, x86_reg reg, int immediate,
                           std::vector<x86_reg> const &scratchRegs) {
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
      if (!BA->checkXchgPath(reg, add_0))
        continue;

      // REQ #3: pop_0 (where we put the immediate) must be at least
      // exchangeable with add_1 (the src operand)
      if (!BA->checkXchgPath(pop_0, add_1))
        continue;

      // REQ #4: pop_0 must be at least exchangeable with a scratch register
      // that must be different from reg.
      for (auto &sr : scratchRegs) {
        if (sr == reg)
          continue;
        if (BA->checkXchgPath(sr, pop_0)) {
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
  Xchg(MI, scratch, pop_0);

  chain.emplace_back(ChainElem(pop));
  // dbgs() << pop->asmInstr << "\n"
  //<< "imm: " << immediate;
  chain.emplace_back(immediate);

  addToInstrMap(MI, ChainElem(pop));
  addToInstrMap(MI, ChainElem(immediate));

  Xchg(MI, pop_0, scratch);

  // ADD
  DoubleXchg(MI, reg, add_0, scratch, add_1);

  chain.emplace_back(ChainElem(add));
  addToInstrMap(MI, ChainElem(add));

  // dbgs() << add->asmInstr << "\n";

  DoubleXchg(MI, add_1, scratch, add_0, reg);

  return true;
}

x86_reg ROPChain::computeAddress(MachineInstr *MI, x86_reg inputReg,
                                 int displacement, x86_reg outputReg,
                                 std::vector<x86_reg> scratchRegs) {

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

  for (auto &m : BA->gadgetLookup(X86_INS_MOV, X86_OP_REG, X86_OP_REG)) {
    if (combinationFound)
      break;
    mov_0 = m->getOp(0).reg;
    mov_1 = m->getOp(1).reg;

    for (auto &p : BA->gadgetLookup(X86_INS_POP, X86_OP_REG)) {
      if (combinationFound)
        break;
      pop_0 = p->getOp(0).reg;

      for (auto &a : BA->gadgetLookup(X86_INS_ADD, X86_OP_REG, X86_OP_REG)) {
        if (combinationFound)
          break;
        add_0 = a->getOp(0).reg;
        add_1 = a->getOp(1).reg;

        // REQ #1: src and dst operands cannot be the same
        if (add_0 == add_1)
          continue;

        // REQ #2: mov_0, add_0 and outputReg must belong to the same exchange
        // path (i.e. they are exchangeable)
        if (!BA->checkXchgPath(mov_0, add_0, outputReg))
          continue;

        // REQ #3: pop_0, add_1 must belong to the same exchange path
        if (!BA->checkXchgPath(pop_0, add_1))
          continue;

        // REQ #4: mov_1, inputReg must belong to the same exchange path
        if (!BA->checkXchgPath(mov_1, inputReg))
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
            if (BA->checkXchgPath(sr1, mov_0) &&
                BA->checkXchgPath(sr2, pop_0)) {
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

    /*dbgs() << "[*] Chosen gadgets: \n";
    dbgs() << mov->asmInstr << "\n"
           << pop->asmInstr << "\n"
           << add->asmInstr << "\n";
    dbgs() << "[*] Scratch regs: " << scratchR1 << ", " << scratchR2 << "\n";
*/
    // Okay, now it's time to build the chain!

    // MOV
    DoubleXchg(MI, scratchR1, mov_0, inputReg, mov_1);

    chain.emplace_back(ChainElem(mov));
    addToInstrMap(MI, ChainElem(mov));

    // dbgs() << mov->asmInstr << "\n";

    DoubleXchg(MI, mov_1, inputReg, mov_0, scratchR1);

    // POP
    Xchg(MI, scratchR2, pop_0);

    chain.emplace_back(ChainElem(pop));
    addToInstrMap(MI, ChainElem(pop));

    // dbgs() << pop->asmInstr << "\n"
    //       << "displacement: " << displacement;
    chain.emplace_back(displacement);
    addToInstrMap(MI, ChainElem(displacement));

    Xchg(MI, pop_0, scratchR2);

    // ADD
    DoubleXchg(MI, scratchR1, add_0, scratchR2, add_1);

    chain.emplace_back(ChainElem(add));
    addToInstrMap(MI, ChainElem(add));

    // dbgs() << add->asmInstr << "\n";

    DoubleXchg(MI, add_1, scratchR2, add_0, scratchR1);
  }

  return scratchR1;
}

bool ROPChain::handleAddSubIncDec(MachineInstr *MI) {
  unsigned opcode = MI->getOpcode();
  auto const scratchRegs = *SRT.getRegs(*MI);
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

bool ROPChain::handleMov32rm(MachineInstr *MI) {
  auto scratchRegs = *SRT.getRegs(*MI);
  x86_reg orig_0, orig_1, mov_0, mov_1, address = X86_REG_INVALID;
  int orig_disp;
  Microgadget *mov;

  // no scratch registers are available, or the dst operand is ESP (we are
  // unable to modify it since we are using microgadgets) -> abort.
  if (scratchRegs.size() < 2)
    return false;

  // sometimes mov instructions have operands that use segment registers, and
  // we just cannot handle them
  if (MI->getOperand(0).getReg() == 0 || MI->getOperand(1).getReg() == 0)
    return false;

  // dump all the useful operands from the MachineInstr we are processing:
  //      mov     orig_0, [orig_1 + disp]
  orig_0 = convertToCapstoneReg(MI->getOperand(0).getReg()); // dst
  orig_1 = convertToCapstoneReg(MI->getOperand(1).getReg()); // src

  if (!MI->getOperand(4).isImm())
    return false;

  orig_disp = MI->getOperand(4).getImm(); // displacement

  // We will replace this instruction with its register-register variant,
  // like this (parametrising the operands):
  //      mov     mov_0, [mov_1]

  for (auto &m : BA->gadgetLookup(X86_INS_MOV, X86_OP_REG, X86_OP_MEM)) {
    mov_0 = m->getOp(0).reg;
    mov_1 = static_cast<x86_reg>(m->getOp(1).mem.base);
    int mov_disp = m->getOp(1).mem.disp;

    // if the two dst operands aren't connected, skip the gadget
    if (!BA->checkXchgPath(orig_0, mov_0))
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
*/
  // -----------

  DoubleXchg(MI, orig_0, mov_0, address, mov_1);

  chain.emplace_back(ChainElem(mov));
  addToInstrMap(MI, ChainElem(mov));

  // dbgs() << mov->asmInstr << "\n";

  DoubleXchg(MI, mov_1, address, mov_0, orig_0);

  return true;
}

bool ROPChain::handleMov32mr(MachineInstr *MI) {
  auto scratchRegs = *SRT.getRegs(*MI);
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

  for (auto &m : BA->gadgetLookup(X86_INS_MOV, X86_OP_MEM, X86_OP_REG)) {
    // dbgs() << m->asmInstr << "\n";
    //      mov     [mov_0], mov_1
    mov_0 = static_cast<x86_reg>(m->getOp(0).mem.base);
    mov_1 = m->getOp(1).reg;
    int mov_disp = m->getOp(0).mem.disp;

    // if the two src operands aren't connected, skip the gadget
    if (!BA->checkXchgPath(orig_1, mov_1))
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

  /*
  dbgs() << "Results returned in: " << address << "\n";
  dbgs() << "[*] Chosen gadgets: \n";
  dbgs() << mov->asmInstr << "\n\n";
  */

  DoubleXchg(MI, address, mov_0, orig_1, mov_1);

  chain.emplace_back(ChainElem(mov));
  addToInstrMap(MI, ChainElem(mov));

  // dbgs() << mov->asmInstr << "\n";

  DoubleXchg(MI, mov_1, orig_1, mov_0, address);

  return true;
}

bool ROPChain::mapBindings(MachineInstr &MI) {
  // if ESP is one of the operands of MI -> abort
  for (unsigned int i = 0; i < MI.getNumOperands(); i++) {
    if (MI.getOperand(i).isReg() && MI.getOperand(i).getReg() == X86::ESP)
      return false;
  }

  DEBUG_WITH_TYPE(
      LIVENESS_ANALYSIS,
      dbgs() << fmt::format("[LivenessAnalysis] avail. scratch registers:\t"));

  for (auto &a : *SRT.getRegs(MI)) {
    DEBUG_WITH_TYPE(LIVENESS_ANALYSIS, dbgs() << a << " ");
  }
  DEBUG_WITH_TYPE(LIVENESS_ANALYSIS, dbgs() << "\n");

  switch (MI.getOpcode()) {
  case X86::ADD32ri8:
  case X86::ADD32ri:
  case X86::SUB32ri8:
  case X86::SUB32ri:
  case X86::INC32r:
  case X86::DEC32r: {
    if (!handleAddSubIncDec(&MI))
      return false;
    break;
  }
  case X86::MOV32rm: {
    if (!handleMov32rm(&MI)) {
      return false;
    }
    break;
  }
  case X86::MOV32mr: {
    if (!handleMov32mr(&MI)) {
      return false;
    }
    break;
  }
  default:
    return false;
  }

  return true;
}

void ROPChain::addToInstrMap(MachineInstr *MI, ChainElem CE) {
  // TODO: this won't be valid once the MI * gets invalidated after an erase().
  instrMap[MI].emplace_back(CE);
}

void ROPChain::finalize() { finalized = true; }

bool ROPChain::isFinalized() { return finalized; }

bool ROPChain::isEmpty() { return chain.empty(); }
