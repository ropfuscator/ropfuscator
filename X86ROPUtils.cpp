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
    "examples/step1_add/libwebkitgtk-3.0.so.0.22.17");
// "/home/user/llvm-build/examples/step1_add/libnaive.so");

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

int ROPChain::mapBindings(MachineInstr &MI) {
  // if ESP is one of the operands of MI -> abort
  for (unsigned int i = 0; i < MI.getNumOperands(); i++) {
    if (MI.getOperand(i).isReg() && MI.getOperand(i).getReg() == X86::ESP)
      return 1;
  }

  /*void pane1() {
    for (auto &initialisableReg : BA->getInitialisableRegs()) {
      for (auto &scratchReg : *SRT.getRegs(MI)) {
        for (auto &movRR :
             BA->gadgetLookup(X86_INS_MOV, X86_OP_REG, X86_OP_REG)) {
          for (auto &popR : BA->gadgetLookup(X86_INS_POP, X86_OP_REG)) {
            for (auto &addRR :
                 BA->gadgetLookup(X86_INS_ADD, X86_OP_REG, X86_OP_REG)) {
              for (auto &movMR :
                   BA->gadgetLookup(X86_INS_MOV, X86_OP_REG, X86_OP_MEM)) {
                // mov REG1, o_src
                if (!BA->checkXchgPath(movRR->getOp(1).reg, o_src))
                  continue;

                if (!BA->checkXchgPath(movRR->getOp(0).reg, initialisableReg,
                                       scratchReg))
                  continue;

                if (!BA->checkXchgPath(
                        movRR->getOp(0).reg, addRR->getOp(0).reg,
                        static_cast<x86_reg>(movMR->getOp(1).mem.base)))
                  continue;
                if (!BA->checkXchgPath(popR->getOp(0).reg, addRR->getOp(1).reg))
                  continue;

                dbgs() << "\n[*] Found first gadget combination!\n";
                dbgs() << movRR->asmInstr << "\n"
                       << popR->asmInstr << "\n"
                       << addRR->asmInstr << "\n"
                       << movRR->asmInstr << "\n";
              }
            }
          }
        }
      }
    }
  }*/

  unsigned opcode = MI.getOpcode();
  switch (opcode) {
  case X86::ADD32ri8:
  case X86::ADD32ri: {

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
    for (auto &a : *SRT.getRegs(MI))
      dbgs() << "scratch reg: " << a << "\n";

    // no scratch registers are available, or the dst operand is ESP (we are
    // unable to modify it since we are using microgadgets) -> abort.
    if (SRT.count(MI) < 2)
      return 1;

    // original instr src operand
    x86_reg o_src = convertToCapstoneReg(MI.getOperand(1).getReg());
    // original instr dst operand
    x86_reg o_dst = convertToCapstoneReg(MI.getOperand(0).getReg());

    auto movRR_v = BA->gadgetLookup(X86_INS_MOV, X86_OP_REG, X86_OP_REG);
    auto popR_v = BA->gadgetLookup(X86_INS_POP, X86_OP_REG);
    auto addRR_v = BA->gadgetLookup(X86_INS_ADD, X86_OP_REG, X86_OP_REG);
    auto movRM_v = BA->gadgetLookup(X86_INS_MOV, X86_OP_REG, X86_OP_MEM);

    Microgadget *picked_movRR, *picked_popR, *picked_addRR, *picked_movRM;
    x86_reg scratchr1, scratchr2;

    for (auto &movRR : movRR_v) {
      for (auto &popR : popR_v) {
        for (auto &addRR : addRR_v) {
          for (auto &movRM : movRM_v) {
            // check exchangeability between related operands
            if ((!BA->checkXchgPath(
                    static_cast<x86_reg>(movRM->getOp(1).mem.base),
                    addRR->getOp(0).reg, movRR->getOp(0).reg)) ||
                !BA->checkXchgPath(addRR->getOp(1).reg, popR->getOp(0).reg) ||
                !BA->checkXchgPath(movRR->getOp(1).reg, o_src) ||
                !BA->checkXchgPath(movRM->getOp(0).reg, o_dst) ||
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
                  picked_movRM = movRM;
                  picked_addRR = addRR;
                  picked_popR = popR;
                  picked_movRR = movRR;
                }
              }
            }
          }
        }
      }
    }

    dbgs() << "[*] Chosen gadgets: \n";
    dbgs() << picked_movRR->asmInstr << "\n"
           << picked_popR->asmInstr << "\n"
           << picked_addRR->asmInstr << "\n"
           << picked_movRM->asmInstr << "\n";
    dbgs() << "[*] Scratch regs: " << scratchr1 << ", " << scratchr2 << "\n";

    // Okay, now it's time to build the chain!

    // ---------
    std::vector<Microgadget *> tmp;
    tmp = BA->getXchgPath(scratchr1, picked_movRR->getOp(0).reg);
    for (auto &a : tmp) {
      dbgs() << a->asmInstr << "\n";
      chain.emplace_back(ChainElem(a));
    }

    tmp = BA->getXchgPath(o_src, picked_movRR->getOp(1).reg);
    for (auto &a : tmp) {
      dbgs() << a->asmInstr << "\n";
      chain.emplace_back(ChainElem(a));
    }

    chain.emplace_back(ChainElem(picked_movRR));
    dbgs() << picked_movRR->asmInstr << "\n";

    tmp = BA->getXchgPath(picked_movRR->getOp(1).reg, o_src);
    for (auto &a : tmp) {
      dbgs() << a->asmInstr << "\n";
      chain.emplace_back(ChainElem(a));
    }

    tmp = BA->getXchgPath(picked_movRR->getOp(0).reg, scratchr1);
    for (auto &a : tmp) {
      dbgs() << a->asmInstr << "\n";
      chain.emplace_back(ChainElem(a));
    }

    // ----------
    tmp = BA->getXchgPath(scratchr2, picked_popR->getOp(0).reg);
    for (auto &a : tmp) {
      dbgs() << a->asmInstr << "\n";
      chain.emplace_back(ChainElem(a));
    }

    chain.emplace_back(ChainElem(picked_popR));
    dbgs() << picked_popR->asmInstr << "\n";
    dbgs() << "original disp: " << MI.getOperand(4).getImm()
           << "\ngadget disp: " << picked_movRM->getOp(1).mem.disp << "\n";
    dbgs() << "computed disp: "
           << MI.getOperand(4).getImm() - picked_movRM->getOp(1).mem.disp
           << "\n";
    chain.push_back(MI.getOperand(4).getImm() -
                    picked_movRM->getOp(1).mem.disp);

    tmp = BA->getXchgPath(picked_popR->getOp(0).reg, scratchr2);
    for (auto &a : tmp) {
      dbgs() << a->asmInstr << "\n";
      chain.emplace_back(ChainElem(a));
    }

    // ------------
    tmp = BA->getXchgPath(scratchr1, picked_addRR->getOp(0).reg);
    for (auto &a : tmp) {
      dbgs() << a->asmInstr << "\n";
      chain.emplace_back(ChainElem(a));
    }

    tmp = BA->getXchgPath(scratchr2, picked_addRR->getOp(1).reg);
    for (auto &a : tmp) {
      dbgs() << a->asmInstr << "\n";
      chain.emplace_back(ChainElem(a));
    }

    chain.emplace_back(ChainElem(picked_addRR));
    dbgs() << picked_addRR->asmInstr << "\n";

    tmp = BA->getXchgPath(picked_addRR->getOp(1).reg, scratchr2);
    for (auto &a : tmp) {
      dbgs() << a->asmInstr << "\n";
      chain.emplace_back(ChainElem(a));
    }

    tmp = BA->getXchgPath(picked_addRR->getOp(0).reg, scratchr1);
    for (auto &a : tmp) {
      dbgs() << a->asmInstr << "\n";
      chain.emplace_back(ChainElem(a));
    }

    // -----------
    tmp = BA->getXchgPath(o_dst, picked_movRM->getOp(0).reg);
    for (auto &a : tmp) {
      dbgs() << a->asmInstr << "\n";
      chain.emplace_back(ChainElem(a));
    }

    tmp = BA->getXchgPath(
        scratchr1, static_cast<x86_reg>(picked_movRM->getOp(1).mem.base));
    for (auto &a : tmp) {
      dbgs() << a->asmInstr << "\n";
      chain.emplace_back(ChainElem(a));
    }

    chain.emplace_back(ChainElem(picked_movRM));
    dbgs() << picked_movRM->asmInstr << "\n";

    /* tmp =
     BA->getXchgPath(static_cast<x86_reg>(picked_movRM->getOp(1).mem.base),
                           scratchr1);
     for (auto &a : tmp) {
       dbgs() << a->asmInstr << "\n";
       chain.emplace_back(ChainElem(a));
     }*/

    tmp = BA->getXchgPath(picked_movRM->getOp(0).reg, o_dst);
    for (auto &a : tmp) {
      dbgs() << a->asmInstr << "\n";
      chain.emplace_back(ChainElem(a));
    }
    return 0;
  }
  case X86::MOV32mr: {
    return 1;
    // no scratch registers are available, or the dst operand is ESP (we are
    // unable to modify it since we are using microgadgets) -> abort.
    if (SRT.count(MI) < 2)
      return 1;

    // original instr src operand
    x86_reg o_src = convertToCapstoneReg(MI.getOperand(5).getReg());
    // original instr dst operand
    x86_reg o_dst = convertToCapstoneReg(MI.getOperand(0).getReg());

    auto movRR_v = BA->gadgetLookup(X86_INS_MOV, X86_OP_REG, X86_OP_REG);
    auto popR_v = BA->gadgetLookup(X86_INS_POP, X86_OP_REG);
    auto addRR_v = BA->gadgetLookup(X86_INS_ADD, X86_OP_REG, X86_OP_REG);
    auto movMR_v = BA->gadgetLookup(X86_INS_MOV, X86_OP_MEM, X86_OP_REG);

    Microgadget *picked_movRR, *picked_popR, *picked_addRR, *picked_movMR;
    x86_reg scratchr1, scratchr2;

    for (auto &movRR : movRR_v) {
      for (auto &popR : popR_v) {
        for (auto &addRR : addRR_v) {
          for (auto &movMR : movMR_v) {
            // check exchangeability between related operands
            if ((!BA->checkXchgPath(
                    static_cast<x86_reg>(movMR->getOp(1).mem.base),
                    addRR->getOp(0).reg, movRR->getOp(0).reg)) ||
                !BA->checkXchgPath(addRR->getOp(1).reg, popR->getOp(0).reg) ||
                !BA->checkXchgPath(movRR->getOp(1).reg, o_src) ||
                !BA->checkXchgPath(movMR->getOp(0).reg, o_dst) ||
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
                  picked_movMR = movMR;
                  picked_addRR = addRR;
                  picked_popR = popR;
                  picked_movRR = movRR;
                }
              }
            }
          }
        }
      }
    }

    dbgs() << "[*] Chosen gadgets: \n";
    dbgs() << picked_movRR->asmInstr << "\n"
           << picked_popR->asmInstr << "\n"
           << picked_addRR->asmInstr << "\n"
           << picked_movMR->asmInstr << "\n";
    dbgs() << "[*] Scratch regs: " << scratchr1 << ", " << scratchr2 << "\n";

    // Okay, now it's time to build the chain!

    // ---------
    std::vector<Microgadget *> tmp;
    tmp = BA->getXchgPath(scratchr1, picked_movRR->getOp(0).reg);
    for (auto &a : tmp) {
      dbgs() << a->asmInstr << "\n";
      chain.emplace_back(ChainElem(a));
    }

    tmp = BA->getXchgPath(o_src, picked_movRR->getOp(1).reg);
    for (auto &a : tmp) {
      dbgs() << a->asmInstr << "\n";
      chain.emplace_back(ChainElem(a));
    }

    chain.emplace_back(ChainElem(picked_movRR));
    dbgs() << picked_movRR->asmInstr << "\n";

    tmp = BA->getXchgPath(picked_movRR->getOp(1).reg, o_src);
    for (auto &a : tmp) {
      dbgs() << a->asmInstr << "\n";
      chain.emplace_back(ChainElem(a));
    }

    tmp = BA->getXchgPath(picked_movRR->getOp(0).reg, scratchr1);
    for (auto &a : tmp) {
      dbgs() << a->asmInstr << "\n";
      chain.emplace_back(ChainElem(a));
    }

    // ----------
    tmp = BA->getXchgPath(scratchr2, picked_popR->getOp(0).reg);
    for (auto &a : tmp) {
      dbgs() << a->asmInstr << "\n";
      chain.emplace_back(ChainElem(a));
    }

    chain.emplace_back(ChainElem(picked_popR));
    dbgs() << picked_popR->asmInstr << "\n";
    dbgs() << "original disp: " << MI.getOperand(4).getImm()
           << "\ngadget disp: " << picked_movMR->getOp(1).mem.disp << "\n";
    dbgs() << "computed disp: "
           << MI.getOperand(4).getImm() - picked_movMR->getOp(1).mem.disp
           << "\n";
    chain.push_back(MI.getOperand(4).getImm() -
                    picked_movMR->getOp(1).mem.disp);

    tmp = BA->getXchgPath(picked_popR->getOp(0).reg, scratchr2);
    for (auto &a : tmp) {
      dbgs() << a->asmInstr << "\n";
      chain.emplace_back(ChainElem(a));
    }

    // ------------
    tmp = BA->getXchgPath(scratchr1, picked_addRR->getOp(0).reg);
    for (auto &a : tmp) {
      dbgs() << a->asmInstr << "\n";
      chain.emplace_back(ChainElem(a));
    }

    tmp = BA->getXchgPath(scratchr2, picked_addRR->getOp(1).reg);
    for (auto &a : tmp) {
      dbgs() << a->asmInstr << "\n";
      chain.emplace_back(ChainElem(a));
    }

    chain.emplace_back(ChainElem(picked_addRR));
    dbgs() << picked_addRR->asmInstr << "\n";

    tmp = BA->getXchgPath(picked_addRR->getOp(1).reg, scratchr2);
    for (auto &a : tmp) {
      dbgs() << a->asmInstr << "\n";
      chain.emplace_back(ChainElem(a));
    }

    tmp = BA->getXchgPath(picked_addRR->getOp(0).reg, scratchr1);
    for (auto &a : tmp) {
      dbgs() << a->asmInstr << "\n";
      chain.emplace_back(ChainElem(a));
    }

    // -----------
    tmp = BA->getXchgPath(o_dst, picked_movMR->getOp(0).reg);
    for (auto &a : tmp) {
      dbgs() << a->asmInstr << "\n";
      chain.emplace_back(ChainElem(a));
    }

    tmp = BA->getXchgPath(
        scratchr1, static_cast<x86_reg>(picked_movMR->getOp(1).mem.base));
    for (auto &a : tmp) {
      dbgs() << a->asmInstr << "\n";
      chain.emplace_back(ChainElem(a));
    }

    chain.emplace_back(ChainElem(picked_movMR));
    dbgs() << picked_movMR->asmInstr << "\n";

    /* tmp =
     BA->getXchgPath(static_cast<x86_reg>(picked_movMR->getOp(1).mem.base),
                           scratchr1);
     for (auto &a : tmp) {
       dbgs() << a->asmInstr << "\n";
       chain.emplace_back(ChainElem(a));
     }*/

    tmp = BA->getXchgPath(picked_movMR->getOp(0).reg, o_dst);
    for (auto &a : tmp) {
      dbgs() << a->asmInstr << "\n";
      chain.emplace_back(ChainElem(a));
    }
    return 0;
  }
  default:
    return 1;
  }
}

void ROPChain::finalize() { finalized = true; }

bool ROPChain::isFinalized() { return finalized; }

bool ROPChain::isEmpty() { return chain.empty(); }
