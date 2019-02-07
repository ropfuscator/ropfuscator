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

std::tuple<Microgadget *, x86_reg, x86_reg>
ROPChain::pickSuitableGadgetMem(std::vector<Microgadget *> &RR, x86_reg o_dst,
                                MachineInstr &MI) {
  std::tuple<Microgadget *, x86_reg, x86_reg> xchgDirective;
  /*
    for (auto &g : RR) {

      x86_reg g_dst = g->getOp(0).reg; // gadget dst operand
      x86_reg g_src =
          static_cast<x86_reg>(g->getOp(1).mem.base; // gadget src operand

      // same src and dst operands -> skip
      // if (g_src == g_dst)
      //  continue;

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
          x86_reg capScratchReg = convertToCapstoneReg(scratchReg);
          if (BA->checkXchgPath(g_src, initialisableReg, capScratchReg)) {
            xchgDirective = std::make_tuple(g, initialisableReg, capScratchReg);
            return xchgDirective;
          }
        }
      }
    }*/
  return xchgDirective;
}

x86_reg ROPChain::computeAddress(x86_reg inputReg, int displacement,
                                 x86_reg outputReg, MachineInstr &MI) {
  std::vector<ChainElem> retVect;
  std::vector<Microgadget *> tmp;

  auto movRR_v = BA->gadgetLookup(X86_INS_MOV, X86_OP_REG, X86_OP_REG);
  auto popR_v = BA->gadgetLookup(X86_INS_POP, X86_OP_REG);
  auto addRR_v = BA->gadgetLookup(X86_INS_ADD, X86_OP_REG, X86_OP_REG);

  Microgadget *picked_movRR, *picked_popR, *picked_addRR;
  x86_reg scratchr1 = X86_REG_INVALID;
  x86_reg scratchr2 = X86_REG_INVALID;

  // mov REG1, inputSrc
  // pop REG2
  // add REG1, REG2
  // REG1 must be exchangeable with outputSrc
  for (auto &movRR : movRR_v) {
    for (auto &popR : popR_v) {
      for (auto &addRR : addRR_v) {
        // check exchangeability between related operands
        if ((!BA->checkXchgPath(outputReg, addRR->getOp(0).reg,
                                movRR->getOp(0).reg)) ||
            !BA->checkXchgPath(addRR->getOp(1).reg, popR->getOp(0).reg) ||
            !BA->checkXchgPath(movRR->getOp(1).reg, inputReg) ||
            movRR->getOp(0).reg == popR->getOp(0).reg)
          continue;

        for (auto &sr1 : *SRT.getRegs(MI)) {
          for (auto &sr2 : *SRT.getRegs(MI)) {
            if (sr1 == sr2)
              continue;
            if (BA->checkXchgPath(sr1, movRR->getOp(0).reg) &&
                BA->checkXchgPath(sr2, popR->getOp(0).reg)) {
              scratchr1 = sr1;
              scratchr2 = sr2;

              // pick the whole gadget combination
              picked_addRR = addRR;
              picked_popR = popR;
              picked_movRR = movRR;
            }
          }
        }
      }
    }
  }

  // if scratchr1 hasn't been set, then no any other pointer has, so the search
  // for a suitable gadget-set failed.
  if (scratchr1) {

    dbgs() << "[*] Chosen gadgets: \n";
    dbgs() << picked_movRR->asmInstr << "\n"
           << picked_popR->asmInstr << "\n"
           << picked_addRR->asmInstr << "\n";
    dbgs() << "[*] Scratch regs: " << scratchr1 << ", " << scratchr2 << "\n";

    // Okay, now it's time to build the chain!

    // ---------

    Xchg(scratchr1, picked_movRR->getOp(0).reg);
    Xchg(inputReg, picked_movRR->getOp(1).reg);

    chain.emplace_back(ChainElem(picked_movRR));
    dbgs() << picked_movRR->asmInstr << "\n";

    Xchg(picked_movRR->getOp(1).reg, inputReg);
    Xchg(picked_movRR->getOp(0).reg, scratchr1);

    // ----------
    Xchg(scratchr2, picked_popR->getOp(0).reg);

    chain.emplace_back(ChainElem(picked_popR));
    dbgs() << picked_popR->asmInstr << "\n";
    dbgs() << "displacement: " << displacement;
    chain.push_back(displacement);

    Xchg(picked_popR->getOp(0).reg, scratchr2);
    // ------------
    Xchg(scratchr1, picked_addRR->getOp(0).reg);
    Xchg(scratchr2, picked_addRR->getOp(1).reg);

    chain.emplace_back(ChainElem(picked_addRR));
    dbgs() << picked_addRR->asmInstr << "\n";

    Xchg(picked_addRR->getOp(1).reg, scratchr2);
    Xchg(picked_addRR->getOp(0).reg, scratchr1);
  }

  return scratchr1;
}

int ROPChain::mapBindings(MachineInstr &MI) {
  // if ESP is one of the operands of MI -> abort
  for (unsigned int i = 0; i < MI.getNumOperands(); i++) {
    if (MI.getOperand(i).isReg() && MI.getOperand(i).getReg() == X86::ESP)
      return 1;
  }

  unsigned opcode = MI.getOpcode();
  switch (opcode) {
  case X86::ADD32ri8:
  case X86::ADD32ri: {
    return 1;

    // no scratch registers are available, or the dst operand is ESP (we are
    // unable to modify it since we are using microgadgets) -> abort.
    if (SRT.count(MI) < 1)
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
    if (SRT.count(MI) < 2)
      return 1;

    // original instr src operand
    x86_reg o_src = convertToCapstoneReg(MI.getOperand(1).getReg());
    // original instr dst operand
    x86_reg o_dst = convertToCapstoneReg(MI.getOperand(0).getReg());

    auto movRM_v = BA->gadgetLookup(X86_INS_MOV, X86_OP_REG, X86_OP_MEM);

    x86_reg computedAddrReg;
    Microgadget *picked_movRM;

    for (auto &movRM : movRM_v) {
      x86_reg outputReg = static_cast<x86_reg>(movRM->getOp(1).mem.base);
      uint64_t displacement =
          MI.getOperand(4).getImm() - movRM->getOp(1).mem.disp;

      auto res = computeAddress(o_src, displacement, outputReg, MI);
      if (res != X86_REG_INVALID) {
        computedAddrReg = res;
        picked_movRM = movRM;
        break;
      }
    }

    dbgs() << "Results returned in: " << computedAddrReg << "\n";
    dbgs() << "[*] Chosen gadgets: \n";
    dbgs() << picked_movRM->asmInstr << "\n\n";

    // -----------

    Xchg(o_dst, picked_movRM->getOp(0).reg);

    Xchg(computedAddrReg,
         static_cast<x86_reg>(picked_movRM->getOp(1).mem.base));

    chain.emplace_back(ChainElem(picked_movRM));
    dbgs() << picked_movRM->asmInstr << "\n";

    /* tmp =
     BA->getXchgPath(static_cast<x86_reg>(picked_movRM->getOp(1).mem.base),
                           scratchr1);
     for (auto &a : tmp) {
       dbgs() << a->asmInstr << "\n";
       chain.emplace_back(ChainElem(a));
     }*/

    Xchg(picked_movRM->getOp(0).reg, o_dst);

    return 0;
  }
  case X86::MOV32mr: {

    // no scratch registers are available, or the dst operand is ESP (we are
    // unable to modify it since we are using microgadgets) -> abort.
    if (SRT.count(MI) < 2)
      return 1;

    // original instr src operand
    x86_reg o_src = convertToCapstoneReg(MI.getOperand(5).getReg());
    // original instr dst operand
    x86_reg o_dst = convertToCapstoneReg(MI.getOperand(0).getReg());

    auto movMR_v = BA->gadgetLookup(X86_INS_MOV, X86_OP_MEM, X86_OP_REG);

    x86_reg computedAddrReg;
    Microgadget *picked_movMR;

    for (auto &movMR : movMR_v) {
      if (!BA->checkXchgPath(o_src, movMR->getOp(1).reg))
        continue;
      x86_reg outputReg = static_cast<x86_reg>(movMR->getOp(0).mem.base);
      uint64_t displacement =
          MI.getOperand(3).getImm() - movMR->getOp(0).mem.disp;

      auto res = computeAddress(o_dst, displacement, outputReg, MI);
      if (res != X86_REG_INVALID) {
        computedAddrReg = res;
        picked_movMR = movMR;
        break;
      }
    }

    dbgs() << "Results returned in: " << computedAddrReg << "\n";
    dbgs() << "[*] Chosen gadgets: \n";
    dbgs() << picked_movMR->asmInstr << "\n\n";

    // -----------

    Xchg(computedAddrReg,
         static_cast<x86_reg>(picked_movMR->getOp(0).mem.base));

    Xchg(o_src, picked_movMR->getOp(1).reg);

    chain.emplace_back(ChainElem(picked_movMR));
    dbgs() << picked_movMR->asmInstr << "\n";

    /* tmp =
     BA->getXchgPath(static_cast<x86_reg>(picked_movMR->getOp(1).mem.base),
                           scratchr1);
     for (auto &a : tmp) {
       dbgs() << a->asmInstr << "\n";
       chain.emplace_back(ChainElem(a));
     }*/

    Xchg(picked_movMR->getOp(1).reg, o_src);

    return 0;
  }
  default:
    return 1;
  }
}

void ROPChain::finalize() { finalized = true; }

bool ROPChain::isFinalized() { return finalized; }

bool ROPChain::isEmpty() { return chain.empty(); }
