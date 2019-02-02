#include "X86ROPUtils.h"
#include "CapstoneLLVMAdpt.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/Support/Debug.h"

using namespace llvm;

// ------------------------------------------------------------------------
// Chain Element
// ------------------------------------------------------------------------

ChainElem::ChainElem(Microgadget &g) {
  r = &g;
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

BinaryAutopsy *ROPChain::BA =
    BinaryAutopsy::getInstance("/lib/i386-linux-gnu/libc.so.6");

void ROPChain::inject() {
  dbgs() << "injecting " << chain.size() << " gadgets!\n";
  // PROLOGUE: saves the EIP value before executing the ROP chain
  // pushf (EFLAGS register backup)
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
      // Push a random symbol that, when resolved by the dynamic linker, willbe
      // used as base address; then add the offset to point a specific
      // gadget
      dbgs() << "Processing gadget: " << e->r->asmInstr << "\n";
      // call $opaquePredicate
      BuildMI(*MBB, injectionPoint, nullptr, TII->get(X86::CALLpcrel32))
          .addExternalSymbol("opaquePredicate");

      // je $wrong_target
      BuildMI(*MBB, injectionPoint, nullptr, TII->get(X86::JNE_1))
          .addExternalSymbol(chainLabel);
      dbgs() << "Writing symver\n";
      // .symver directive: necessary to prevent aliasing when more
      // symbols have the same name
      BuildMI(*MBB, injectionPoint, nullptr, TII->get(TargetOpcode::INLINEASM))
          .addExternalSymbol(e->s->getSymVerDirective())
          .addImm(0);

      // TODO: push+add in one single instruction (via inline ASM)
      dbgs() << "Writing symbol\n";
      // push $symbol
      BuildMI(*MBB, injectionPoint, nullptr, TII->get(X86::PUSHi32))
          .addExternalSymbol(e->s->Label);

      // add [esp], $offset
      dbgs() << "Writing offset\n";
      addDirectMem(
          BuildMI(*MBB, injectionPoint, nullptr, TII->get(X86::ADD32mi)),
          X86::ESP)
          .addImm(e->getRelativeAddress());
      dbgs() << "\n\npanyny\n";
      break;
    }
    }
  }
  dbgs() << "pane paazzo\n";
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
ROPChain::pickSuitableGadget(std::vector<Microgadget> &RR, x86_reg o_dst,
                             MachineInstr &MI) {
  std::tuple<Microgadget *, x86_reg, x86_reg> xchgDirective;

  for (Microgadget &g : RR) {

    x86_reg g_dst = g.getOp(0).reg; // gadget dst operand
    x86_reg g_src = g.getOp(1).reg; // gadget src operand
    if (g_dst == X86_REG_EAX && g_src == X86_REG_ECX)
      continue;
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
        x86_reg capScratchReg = convertToCapstoneReg(scratchReg);
        if (BA->checkXchgPath(g_src, initialisableReg, capScratchReg)) {
          xchgDirective = std::make_tuple(&g, initialisableReg, capScratchReg);
          return xchgDirective;
        }
      }
    }
  }
  return xchgDirective;
}

int ROPChain::mapBindings(MachineInstr &MI) {
  unsigned opcode = MI.getOpcode();
  switch (opcode) {
  case X86::ADD32ri8:
  case X86::ADD32ri: {

    // no scratch registers are available, or the dst operand is ESP (we are
    // unable to modify it since we are using microgadgets) -> abort.
    if (SRT.count(MI) < 1 || MI.getOperand(0).getReg() == X86::ESP)
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

    dbgs() << "found the right gadget: " << std::get<0>(suitable)->asmInstr
           << "\n";
    dbgs() << "scratch reg: " << scratch << ", init reg: " << init << "\n";

    // Step 1: initialise the register
    // In the worst case, we have to exchange the initialisable register with
    // the scratch register. Initialise that register. Exchange back again, then
    // exchange scratch register and instruction src operand.

    // reserve the scratch register by popping it
    // TODO: DO I REALLY NEED TO DO THIS?
    SRT.popReg(MI, scratch);

    std::vector<Microgadget> tmp = BA->getXchgPath(init, scratch);
    if (tmp.size() == 0)
      dbgs() << "no xchg required between scratch and init\n";
    else
      dbgs() << tmp.size() << " xchg to perform:\n";
    for (auto &a : tmp) {
      dbgs() << "x -> " << a.asmInstr << "\n";
      chain.push_back(ChainElem(a));
    }

    // here scratch = initilisable
    Microgadget regInit = BA->gadgetLookup(X86_INS_POP, scratch).front();

    // exchange back
    tmp = BA->getXchgPath(scratch, init);
    if (tmp.size() == 0)
      dbgs() << "no xchg required between init and scratch\n";

    for (auto &a : tmp)
      dbgs() << "x -> " << a.asmInstr << "\n";

    // exchange dst gadget op
    tmp = BA->getXchgPath(o_dst, picked->getOp(0).reg);
    if (tmp.size() == 0)
      dbgs() << "no xchg required between original dst and gadget dst\n";

    for (auto &a : tmp)
      dbgs() << "x -> " << a.asmInstr << "\n";

    // exchange src gadget op
    tmp = BA->getXchgPath(scratch, picked->getOp(1).reg);
    if (tmp.size() == 0)
      dbgs() << "no xchg required between the loaded scratch register and "
                "gadget src\n";

    for (auto &a : tmp)
      dbgs() << "x -> " << a.asmInstr << "\n";
    return 0;
  }
  }
}

void ROPChain::finalize() { finalized = true; }

bool ROPChain::isFinalized() { return finalized; }

bool ROPChain::isEmpty() { return chain.empty(); }
