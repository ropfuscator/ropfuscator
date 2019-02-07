#include "X86ROPUtils.h"
#include "CapstoneLLVMAdpt.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/Support/Debug.h"

using namespace llvm;

// ------------------------------------------------------------------------
// Chain Element
// ------------------------------------------------------------------------

ChainElem::ChainElem(Microgadget *g) {
  // dbgs() << "\t ChainElem: gadget @ " << *r << "\n";
  r = g;

  type = GADGET;
  s = ROPChain::BA->getRandomSymbol();
};

ChainElem::ChainElem(int64_t value) : value(value) { type = IMMEDIATE; }

uint64_t ChainElem::getRelativeAddress() {
  return r->getAddress() - s->Address;
}

// ------------------------------------------------------------------------
// ROP Chain
// ------------------------------------------------------------------------

int ROPChain::globalChainID = 0;

BinaryAutopsy *ROPChain::BA = BinaryAutopsy::getInstance(
    // "examples/step1_add/libwebkitgtk-3.0.so.0.22.17");
    //"/home/user/llvm-build/examples/step1_add/libnaive.so");
    "/lib/i386-linux-gnu/libc.so.6");

void ROPChain::inject() {
  dbgs() << "injecting " << chain.size() << " gadgets!\n";
  // PROLOGUE: saves the EIP value before executing the ROP chain
  // pushf (EFLAGS register backup)
  // BuildMI(*MBB, injectionPoint, nullptr, TII->get(X86::PUSHF32));
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
      // dbgs() << "Processing gadget: " << e->r->asmInstr << "\n";
      // call $opaquePredicate
      /*BuildMI(*MBB, injectionPoint, nullptr, TII->get(X86::CALLpcrel32))
          .addExternalSymbol("opaquePredicate");*/

      // je $wrong_target
      // BuildMI(*MBB, injectionPoint, nullptr, TII->get(X86::JNE_1))
      //    .addExternalSymbol(chainLabel);
      // .symver directive: necessary to prevent aliasing when more
      // symbols have the same name. We do this exclusively when the symbol
      // Version is not "Base" (i.e., it is the only one available).
      if (strcmp(e->s->Version, "Base") != 0) {
        BuildMI(*MBB, injectionPoint, nullptr,
                TII->get(TargetOpcode::INLINEASM))
            .addExternalSymbol(e->s->getSymVerDirective())
            .addImm(0);
      }

      // TODO: push+add in one single instruction (via inline ASM)
      // push $symbol
      BuildMI(*MBB, injectionPoint, nullptr, TII->get(X86::PUSHi32))
          .addExternalSymbol(e->s->Label);

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
  // BuildMI(*MBB, injectionPoint, nullptr, TII->get(X86::POPF32));

  // Deletes the initial instructions
  for (MachineInstr *MI : instructionsToDelete) {
    MI->eraseFromParent();
  }
}

int ROPChain::addInstruction(MachineInstr &MI) {
  assert(!finalized && "Attempt to modify a finalized chain!");
  int err = mapBindings(MI);

  if (!err) {
    instructionsToDelete.push_back(&MI);
  }

  return err;
}

void ROPChain::Xchg(x86_reg a, x86_reg b) {
  for (auto &a : BA->getXchgPath(a, b)) {
    dbgs() << "\t" << a->asmInstr << "\n";
    chain.emplace_back(ChainElem(a));
  }
}

std::tuple<Microgadget *, x86_reg, x86_reg>
ROPChain::pickSuitableGadget(std::vector<Microgadget *> &RR, x86_reg o_dst,
                             MachineInstr &MI) {
  std::tuple<Microgadget *, x86_reg, x86_reg> xchgDirective;

  for (auto &g : RR) {

    x86_reg g_dst = g->getOp(0).reg; // gadget dst operand
    x86_reg g_src = g->getOp(1).reg; // gadget src operand

    // same src and dst operands -> skip
    if (g_src == g_dst)
      continue;

    // dst operands of original instr. and RR gadget don't belong to a
    // feasible exchange path -> skip
    if (!BA->checkXchgPath(o_dst, g_dst))
      continue;

    // now we have to check whether the src operand of the RR gadget can be
    // directly or indirectly initialisable via a scratch register
    for (auto &initialisableReg : BA->getInitialisableRegs()) {
      for (auto &scratchReg : *SRT.getRegs(MI)) {

        // convert LLVM register enum (e.g. X86::EAX) in capstone
        // (X86_REG_EAX);
        if (BA->checkXchgPath(g_src, initialisableReg, scratchReg)) {
          xchgDirective = std::make_tuple(g, initialisableReg, scratchReg);
          return xchgDirective;
        }
      }
    }
  }
  return xchgDirective;
}

x86_reg ROPChain::computeAddress(x86_reg inputReg, int displacement,
                                 x86_reg outputReg,
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

        // REQ #1: mov_0, add_0 and outputReg must belong to the same exchange
        // path (i.e. they are exchangeable)
        if (!BA->checkXchgPath(mov_0, add_0, outputReg))
          continue;

        // REQ #2: pop_0, add_1 must belong to the same exchange path
        if (!BA->checkXchgPath(pop_0, add_1))
          continue;

        // REQ #3: mov_1, inputReg must belong to the same exchange path
        if (!BA->checkXchgPath(mov_1, inputReg))
          continue;

        // REQ #4: mov_0 and pop_0 must be different, because we need the two
        // operands (base address and displacement) in different registers.
        if (mov_0 == pop_0)
          continue;

        // REQ #5: mov_0 and pop_0 must be exchangeable with two different
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

    dbgs() << "[*] Chosen gadgets: \n";
    dbgs() << mov->asmInstr << "\n"
           << pop->asmInstr << "\n"
           << add->asmInstr << "\n";
    dbgs() << "[*] Scratch regs: " << scratchR1 << ", " << scratchR2 << "\n";

    // Okay, now it's time to build the chain!

    // MOV
    Xchg(scratchR1, mov_0);
    Xchg(inputReg, mov_1);

    chain.emplace_back(ChainElem(mov));
    dbgs() << mov->asmInstr << "\n";

    Xchg(mov_1, inputReg);
    Xchg(mov_0, scratchR1);

    // POP
    Xchg(scratchR2, pop_0);

    chain.emplace_back(ChainElem(pop));
    dbgs() << pop->asmInstr << "\n"
           << "displacement: " << displacement;
    chain.push_back(displacement);

    Xchg(pop_0, scratchR2);

    // ADD
    Xchg(scratchR1, add_0);
    Xchg(scratchR2, add_1);

    chain.emplace_back(ChainElem(add));
    dbgs() << add->asmInstr << "\n";

    Xchg(add_1, scratchR2);
    Xchg(add_0, scratchR1);
  }

  return scratchR1;
}

int ROPChain::mapBindings(MachineInstr &MI) {
  // if ESP is one of the operands of MI -> abort
  for (unsigned int i = 0; i < MI.getNumOperands(); i++) {
    if (MI.getOperand(i).isReg() && MI.getOperand(i).getReg() == X86::ESP)
      return 1;
  }
  for (auto &a : *SRT.getRegs(MI))
    dbgs() << "scratch: " << a << " \n";
  unsigned opcode = MI.getOpcode();
  switch (opcode) {
  case X86::ADD32ri8:
  case X86::ADD32ri: {
    return 1;

    // no scratch registers are available, or the dst operand is ESP (we are
    // unable to modify it since we are using microgadgets) -> abort.
    auto scratchRegs = *SRT.getRegs(MI);
    if (scratchRegs.size() < 2)
      return 1;

    // searches an ADD instruction with register-register flavour; if nothing
    // is found -> abort
    auto RR = BA->gadgetLookup(X86_INS_ADD, X86_OP_REG, X86_OP_REG);
    if (RR.size() == 0)
      return 1;

    // original instr. dst operand
    x86_reg o_dst = convertToCapstoneReg(MI.getOperand(0).getReg());

    // iterate through all the RR gadgets until a suitable one is found
    std::tuple<Microgadget *, x86_reg, x86_reg> suitable =
        pickSuitableGadget(RR, o_dst, MI);
    Microgadget *picked = std::get<0>(suitable);
    x86_reg init = std::get<1>(suitable);
    x86_reg scratch = std::get<2>(suitable);
    if (picked == nullptr)
      return 1;

    dbgs() << "found the right gadget: " << std::get<0>(suitable)->asmInstr
           << "\n";
    dbgs() << "scratch reg: " << scratch << ", init reg: " << init << "\n";

    // Step 1: initialise the register

    // reserve the scratch register by popping it
    // SRT.popReg(MI, scratch);

    // build xchg path (scratch -> init)
    // dbgs() << "\nscratch -> init\n";
    std::vector<Microgadget *> tmp = BA->getXchgPath(scratch, init);
    for (auto &a : tmp) {
      // dbgs() << a->asmInstr << "\n";
      chain.emplace_back(ChainElem(a));
    }

    // now the contents of init are in scratch and viceversa, so we can pop
    // init
    Microgadget *regInit = BA->gadgetLookup(X86_INS_POP, init).front();
    chain.emplace_back(ChainElem(regInit));
    chain.push_back(MI.getOperand(2).getImm());

    // build xchg path (scratch <- init)
    // dbgs() << "\ninit -> scratch\n";
    tmp = BA->getXchgPath(init, scratch);
    for (auto &a : tmp) {
      // dbgs() << a->asmInstr << "\n";
      chain.emplace_back(ChainElem(a));
    }

    // Step 2: at this point we have indirectly initialised the scratch
    // register. Now it is time to exchange registers again in order to match
    // the operands of the RR instruction.

    //  build xchg path (o_dst -> g_dst)
    // dbgs() << "\no_dst -> g_dst\n";
    tmp = BA->getXchgPath(o_dst, picked->getOp(0).reg);
    for (auto &a : tmp) {
      // dbgs() << a->asmInstr << "\n";
      chain.emplace_back(ChainElem(a));
    }

    // build xchg path (scratch -> g_src)
    // dbgs() << "\nscratch -> g_src\n";
    tmp = BA->getXchgPath(scratch, picked->getOp(1).reg);
    for (auto &a : tmp) {
      // dbgs() << a->asmInstr << "\n";
      chain.emplace_back(ChainElem(a));
    }

    // rr instruction
    chain.emplace_back(ChainElem(picked));
    // dbgs() << picked->asmInstr;

    // build xchg path (scratch <- g_src)
    // dbgs() << "\nscratch <- g_src\n";
    tmp = BA->getXchgPath(picked->getOp(1).reg, scratch);
    for (auto &a : tmp) {
      // dbgs() << a->asmInstr << "\n";
      chain.emplace_back(ChainElem(a));
    }

    //  build xchg path (o_dst <- g_dst)
    // dbgs() << "\no_dst <- g_dst\n";
    tmp = BA->getXchgPath(picked->getOp(0).reg, o_dst);
    for (auto &a : tmp) {
      // dbgs() << a->asmInstr << "\n";
      chain.emplace_back(ChainElem(a));
    }

    return 0;
  }
  case X86::MOV32rm: {
    // no scratch registers are available, or the dst operand is ESP (we are
    // unable to modify it since we are using microgadgets) -> abort.
    auto scratchRegs = *SRT.getRegs(MI);
    if (scratchRegs.size() < 2)
      return 1;

    // dump all the useful operands from the MachineInstr we are processing:
    //      mov     orig_0, [orig_1 + disp]
    x86_reg orig_0 = convertToCapstoneReg(MI.getOperand(0).getReg()); // dst
    x86_reg orig_1 = convertToCapstoneReg(MI.getOperand(1).getReg()); // src
    int orig_disp = MI.getOperand(4).getImm(); // displacement

    // We will replace this instruction with its register-register variant,
    // like this (parametrising the operands):
    //      mov     mov_0, [mov_1]

    x86_reg mov_0, mov_1;
    x86_reg address = X86_REG_INVALID;
    Microgadget *mov;

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
      //    compensate the displacement that may be embedded in the gadget (e.g.
      //    mov reg1, [reg2 + 0x50])
      //    - mov_1: output register, namely the register in which we'd prefer
      //    to retrieve the result; if this is not possible, the result is
      //    placed in a register that is at least reachable via a series of xchg
      //    gadgets
      //    - scratchRegs: a list of scratch registers that can be clobbered
      auto res =
          computeAddress(orig_1, orig_disp - mov_disp, mov_1, scratchRegs);

      if (res != X86_REG_INVALID) {
        address = res;
        mov = m;
        break;
      }
    }

    if (address == X86_REG_INVALID)
      return 1;

    dbgs() << "Results returned in: " << address << "\n";
    dbgs() << "[*] Chosen gadgets: \n";
    dbgs() << mov->asmInstr << "\n\n";

    // -----------

    Xchg(orig_0, mov_0);
    Xchg(address, mov_1);

    chain.emplace_back(ChainElem(mov));
    dbgs() << mov->asmInstr << "\n";

    Xchg(mov_0, orig_0);

    return 0;
  }
  case X86::MOV32mr: {
    // NOTE: for more comments, please check the case MOV32rm: we adopt the very
    // same strategies.

    // no scratch registers are available, or the dst operand is ESP
    // (we are unable to modify it since we are using microgadgets) -> abort.
    auto scratchRegs = *SRT.getRegs(MI);
    if (scratchRegs.size() < 2)
      return 1;

    // dump all the useful operands from the MachineInstr we are processing:
    //      mov     [orig_0 + disp], orig_1
    x86_reg orig_0 = convertToCapstoneReg(MI.getOperand(0).getReg()); // dst
    x86_reg orig_1 = convertToCapstoneReg(MI.getOperand(5).getReg()); // src
    int orig_disp = MI.getOperand(3).getImm(); // displacement

    x86_reg mov_0, mov_1;
    x86_reg address = X86_REG_INVALID;
    Microgadget *mov;

    for (auto &m : BA->gadgetLookup(X86_INS_MOV, X86_OP_MEM, X86_OP_REG)) {
      //      mov     [mov_0], mov_1
      mov_0 = static_cast<x86_reg>(m->getOp(0).mem.base);
      mov_1 = m->getOp(1).reg;
      int mov_disp = m->getOp(0).mem.disp;

      // if the two src operands aren't connected, skip the gadget
      if (!BA->checkXchgPath(orig_1, mov_1))
        continue;

      auto res =
          computeAddress(orig_0, orig_disp - mov_disp, mov_0, scratchRegs);

      if (res != X86_REG_INVALID) {
        address = res;
        mov = m;
        break;
      }
    }

    if (address == X86_REG_INVALID)
      return 1;

    dbgs() << "Results returned in: " << address << "\n";
    dbgs() << "[*] Chosen gadgets: \n";
    dbgs() << mov->asmInstr << "\n\n";

    // -----------

    Xchg(address, mov_0);
    Xchg(orig_1, mov_1);

    chain.emplace_back(ChainElem(mov));
    dbgs() << mov->asmInstr << "\n";

    Xchg(mov_1, orig_1);

    return 0;
  }
  default:
    return 1;
  }
}

void ROPChain::finalize() { finalized = true; }

bool ROPChain::isFinalized() { return finalized; }

bool ROPChain::isEmpty() { return chain.empty(); }
