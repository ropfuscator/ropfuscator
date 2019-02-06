#include "X86ROPUtils.h"
#include "CapstoneLLVMAdpt.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/Support/Debug.h"
#include <z3++.h>

// mk_or() belongs to the Z3 C++ API, but for some reason it is not possible to
// call it from the library. Reporting it here.
using namespace z3;
inline expr mk_or(expr_vector const &args) {
  array<Z3_ast> _args(args);
  Z3_ast r = Z3_mk_or(args.ctx(), _args.size(), _args.ptr());
  args.check_error();
  return expr(args.ctx(), r);
}

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

BinaryAutopsy *ROPChain::BA =
    BinaryAutopsy::getInstance("/lib/i386-linux-gnu/libc.so.6");
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
              for (auto &movRM :
                   BA->gadgetLookup(X86_INS_MOV, X86_OP_REG, X86_OP_MEM)) {
                // mov REG1, o_src
                if (!BA->checkXchgPath(movRR->getOp(1).reg, o_src))
                  continue;

                if (!BA->checkXchgPath(movRR->getOp(0).reg, initialisableReg,
                                       scratchReg))
                  continue;

                if (!BA->checkXchgPath(
                        movRR->getOp(0).reg, addRR->getOp(0).reg,
                        static_cast<x86_reg>(movRM->getOp(1).mem.base)))
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

    // searches an ADD instruction with register-register flavour; if nothing
    // is found -> abort
    auto movRR = BA->gadgetLookup(X86_INS_MOV, X86_OP_REG, X86_OP_REG);
    auto popR = BA->gadgetLookup(X86_INS_POP, X86_OP_REG);
    auto addRR = BA->gadgetLookup(X86_INS_ADD, X86_OP_REG, X86_OP_REG);
    auto movRM = BA->gadgetLookup(X86_INS_MOV, X86_OP_REG, X86_OP_MEM);

    using namespace z3;
    // setting up z3
    context c;
    expr r1 = c.int_const("r1");
    expr r2 = c.int_const("r2");
    expr r3 = c.int_const("r3");
    expr r4 = c.int_const("r4");
    expr r5 = c.int_const("r5");
    expr r6 = c.int_const("r6");
    expr r7 = c.int_const("r7");

    expr_vector g1(c);
    expr_vector g2(c);
    expr_vector g3(c);
    expr_vector g4(c);

    solver s(c);

    // rules for MOV32rm:
    //    mov r1, r2
    //    pop r3
    //    add r4, r5
    //    mov r6, [r7]
    // r1, r4 and r7 must be the same register, or at least reacheable
    // r3, r5 another register
    s.add(r1 == r4); // REG1
    s.add(r4 == r7);
    s.add(r3 == r5); // REG2
    s.add(r1 != r3);

    using namespace llvm;

    // mov
    for (auto &g : movRR) {
      dbgs() << "[MovRR] " << g->asmInstr << "\n";
      x86_reg op0 = g->getOp(0).reg;
      x86_reg op1 = g->getOp(1).reg;

      expr_vector reachableFromOp0(c);
      for (auto &r : BA->getReachableRegs(op0))
        reachableFromOp0.push_back(r1 == r);

      expr_vector reachableFromOp1(c);
      for (auto &r : BA->getReachableRegs(op1))
        reachableFromOp1.push_back(r2 == r);

      g1.push_back(mk_or(reachableFromOp0) && mk_or(reachableFromOp1));
    }
    std::cout << mk_or(g1) << "\n";
    s.add(mk_or(g1));

    // pop
    for (auto &g : popR) {
      dbgs() << "[popR] " << g->asmInstr << "\n";
      x86_reg op0 = g->getOp(0).reg;

      expr_vector reachableFromOp0(c);
      for (auto &r : BA->getReachableRegs(op0))
        reachableFromOp0.push_back(r3 == r);

      g2.push_back(mk_or(reachableFromOp0));
    }
    std::cout << mk_or(g2) << "\n";
    s.add(mk_or(g2));

    // add
    for (auto &g : addRR) {
      dbgs() << "[addRR] " << g->asmInstr << "\n";
      x86_reg op0 = g->getOp(0).reg;
      x86_reg op1 = g->getOp(1).reg;

      expr_vector reachableFromOp0(c);
      for (auto &r : BA->getReachableRegs(op0))
        reachableFromOp0.push_back(r4 == r);

      expr_vector reachableFromOp1(c);
      for (auto &r : BA->getReachableRegs(op1))
        reachableFromOp1.push_back(r5 == r);

      g3.push_back(mk_or(reachableFromOp0) && mk_or(reachableFromOp1));
    }
    std::cout << mk_or(g3) << "\n";
    s.add(mk_or(g3));

    // movRM
    for (auto &g : movRM) {
      dbgs() << "[movRM] " << g->asmInstr << "\n";
      x86_reg op0 = g->getOp(0).reg;
      x86_reg op1 = static_cast<x86_reg>(g->getOp(1).mem.base);

      // TODO: REMOVE JUST DEBUG
      if (op1 == X86_REG_EAX)
        continue;

      // for o_dst rules are much tighter
      expr_vector reachableFromOp0(c);
      if (BA->checkXchgPath(op0, o_dst)) {
        for (auto &r : BA->getReachableRegs(op0))
          reachableFromOp0.push_back(r6 == r);
      }

      expr_vector reachableFromOp1(c);
      for (auto &r : BA->getReachableRegs(op1))
        reachableFromOp1.push_back(r7 == r);

      g4.push_back(mk_or(reachableFromOp0) && mk_or(reachableFromOp1));
    }
    std::cout << mk_or(g4) << "\n";
    s.add(mk_or(g4));

    s.check();

    model smt_model = s.get_model();
    std::cout << smt_model << "\n";

    x86_reg movRR_op1 =
        smt_model.get_const_interp(smt_model[1]).get_numeral_int();

    /* std::vector<Microgadget *> tmp = BA->getXchgPath(scratch, init);
     for (auto &a : tmp) {
       // dbgs() << a->asmInstr << "\n";
       chain.emplace_back(ChainElem(a));
     }*/

    // popR
    /*
    for (auto &g : popR) {
      dbgs() << "[popR] " << g->asmInstr << "\n";
      x86_reg op0 = g->getOp(0).reg;

      // op0: check if is a scratch register, or at least can be exchange
    with a
      // scratch register: if yes we add it to the constraints.
      for (auto &sr : *SRT.getRegs(MI)) {
        x86_reg sr_cap = convertToCapstoneReg(sr);
        // dbgs() << "scratch reg: " << sr_cap << "\n";

        if (BA->checkXchgPath(op0, sr_cap)) {
          dbgs() << "\t(r3) " << op0
                 << " can be exchanged with scratch register " << sr_cap
                 << "\n";
          using namespace z3;
          args3.push_back(r3 == op0);
        }
      }
    }

    for (auto &g : addRR) {
      dbgs() << "[addRR] " << g->asmInstr << "\n";
      x86_reg op0 = g->getOp(0).reg;
      x86_reg op1 = g->getOp(1).reg;

      // op0: check if is a scratch register, or at least can be exchange
    with a
      // scratch register: if yes we add it to the constraints.
      for (auto &sr : *SRT.getRegs(MI)) {
        x86_reg sr_cap = convertToCapstoneReg(sr);
        // dbgs() << "scratch reg: " << sr_cap << "\n";

        if (BA->checkXchgPath(op0, sr_cap)) {
          dbgs() << "\t(r4) " << op0
                 << " can be exchanged with scratch register " << sr_cap
                 << "\n";
          using namespace z3;
          args4.push_back(r4 == op0);
        }
      }

      // op1: must be equal or at least exchangeable with o_src
      if (BA->checkXchgPath(op1, o_src)) {
        dbgs() << "\t(r5) " << op1 << " can be exchanged with scratch
    register "
               << o_src << "\n";
        using namespace z3;
        args5.push_back(r5 == op1);
      }
    }

    //    std::cout << z3::mk_or(args1) << "\n";
    using namespace z3;
    std::cout << mk_or(args1) << "\n";
    std::cout << mk_or(args2) << "\n";
    std::cout << mk_or(args3) << "\n";
    std::cout << mk_or(args4) << "\n";
    std::cout << mk_or(args5) << "\n";

    s.add(mk_or(args1));
    s.add(mk_or(args2));
    s.add(mk_or(args3));
    s.add(mk_or(args4));
    s.add(mk_or(args5));

    s.check();
    model m = s.get_model();
    std::cout << m << "\n";*/
    /*
        for (auto &a : movRR)
          dbgs() << a->asmInstr << "\n";

        if (RR.size() == 0)
          return 1;
        // for (auto &a : RR)
        //  dbgs() << "-> " << a.asmInstr << "\n";
        // original instr. dst operand
        x86_reg o_dst = convertToCapstoneReg(MI.getOperand(0).getReg());

        // iterate through all the RR gadgets until a suitable one is found
        std::tuple<Microgadget *, x86_reg, x86_reg> suitable =
            pickSuitableGadgetMem(RR, o_dst, MI);
        Microgadget *picked = std::get<0>(suitable);
        x86_reg init = std::get<1>(suitable);
        x86_reg scratch = std::get<2>(suitable);

        if (picked == nullptr)
          return 1;

        dbgs() << "found the right gadget: " <<
       std::get<0>(suitable)->asmInstr
               << "\n";
        dbgs() << "scratch reg: " << scratch << ", init reg: " << init <<
       "\n"; return 1;
        // Step 1: initialise the register

        // reserve the scratch register by popping it
        SRT.popReg(MI, scratch);

        // build xchg path (scratch -> init)
        dbgs() << "\nscratch -> init\n";
        std::vector<Microgadget *> tmp = BA->getXchgPath(scratch, init);
        for (auto &a : tmp) {
          dbgs() << a->asmInstr << "\n";
          chain.emplace_back(ChainElem(a));
        }

        // now the contents of init are in scratch and viceversa, so we can
       pop
        // init
        Microgadget *regInit = BA->gadgetLookup(X86_INS_POP, init).front();
        chain.emplace_back(ChainElem(regInit));
        chain.push_back(MI.getOperand(2).getImm());

        // build xchg path (scratch <- init)
        dbgs() << "\ninit -> scratch\n";
        tmp = BA->getXchgPath(init, scratch);
        for (auto &a : tmp) {
          dbgs() << a->asmInstr << "\n";
          chain.emplace_back(ChainElem(a));
        }

        // Step 2: at this point we have indirectly initialised the scratch
        // register. Now it is time to exchange registers again in order to
       match
        // the operands of the RR instruction.

        //  build xchg path (o_dst -> g_dst)
        dbgs() << "\no_dst -> g_dst\n";
        tmp = BA->getXchgPath(o_dst, picked->getOp(0).reg);
        for (auto &a : tmp) {
          dbgs() << a->asmInstr << "\n";
          chain.emplace_back(ChainElem(a));
        }

        // build xchg path (scratch -> g_src)
        dbgs() << "\nscratch -> g_src\n";
        tmp = BA->getXchgPath(scratch, picked->getOp(1).reg);
        for (auto &a : tmp) {
          dbgs() << a->asmInstr << "\n";
          chain.emplace_back(ChainElem(a));
        }

        // rr instruction
        chain.emplace_back(ChainElem(picked));
        dbgs() << picked->asmInstr;

        // build xchg path (scratch <- g_src)
        dbgs() << "\nscratch <- g_src\n";
        tmp = BA->getXchgPath(picked->getOp(1).reg, scratch);
        for (auto &a : tmp) {
          dbgs() << a->asmInstr << "\n";
          chain.emplace_back(ChainElem(a));
        }

        //  build xchg path (o_dst <- g_dst)
        dbgs() << "\no_dst <- g_dst\n";
        tmp = BA->getXchgPath(picked->getOp(0).reg, o_dst);
        for (auto &a : tmp) {
          dbgs() << a->asmInstr << "\n";
          chain.emplace_back(ChainElem(a));
        }
    */
    return 0;
  }
  default:
    return 1;
  }
}

void ROPChain::finalize() { finalized = true; }

bool ROPChain::isFinalized() { return finalized; }

bool ROPChain::isEmpty() { return chain.empty(); }
