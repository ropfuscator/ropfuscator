//
// Created by Daniele Ferla on 22/10/2018.
//

#include "../X86.h"
#include "../X86InstrBuilder.h"
#include "../X86MachineFunctionInfo.h"
#include "../X86RegisterInfo.h"
#include "../X86Subtarget.h"
#include "../X86TargetMachine.h"
//#include "ROPseeker.h"
#include "BinAutopsy.h"
#include "CapstoneLLVMAdpt.h"
#include "LivenessAnalysis.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include <iostream>
#include <stdio.h>
#include <string>
#include <sys/time.h>
#include <tuple>

using namespace llvm;
enum type_t { GADGET, IMMEDIATE };

// struct ChainElem;

struct Stats {
  int processed;
  int replaced;

  Stats() : processed(0), replaced(0){};
};

class ROPChain {
  // Keeps track of all the instructions to be replaced with the obfuscated
  // ones. Handles the injection of auxiliary machine code to guarantee the
  // correct chain execution and to resume the non-obfuscated code execution
  // afterwards.

  // IDs
  static int globalChainID;
  int chainID;

  // A finalized chain can't get gadgets anymore
  bool finalized = false;

  // Input instructions that we want to replace with obfuscated ones
  std::vector<MachineInstr *> instructionsToDelete;

  // Gadgets to be pushed onto the stack during the injection phase
  // std::vector<ChainElem> chain;

  static BinaryAutopsy *BA;

public:
  // Labels for inline asm instructions ("C" = colon)
  char chainLabel[16];    // chain_X
  char chainLabel_C[16];  // chain_X:
  char resumeLabel[16];   // resume_X
  char resumeLabel_C[16]; // resume_X:

  // Injection location within the program code
  MachineBasicBlock *MBB;
  MachineFunction *MF;
  MachineInstr *injectionPoint;
  MCInstrInfo const *TII;
  ScratchRegTracker &SRT;

  // Methods
  int addInstruction(MachineInstr &MI);
  int mapBindings(MachineInstr &MI);
  void inject();
  void loadEffectiveAddress(int64_t displacement);
  std::tuple<Microgadget *, x86_reg, x86_reg>
  pickSuitableGadget(std::vector<Microgadget> &RR, x86_reg o_dst,
                     MachineInstr &MI);

  // Helper methods
  bool isFinalized();
  void finalize();
  bool isEmpty();

  ROPChain(MachineBasicBlock &MBB, MachineInstr &injectionPoint,
           ScratchRegTracker &SRT)
      : MBB(&MBB), injectionPoint(&injectionPoint), SRT(SRT) {
    MF = MBB.getParent();
    TII = MF->getTarget().getMCInstrInfo();
    chainID = globalChainID++;

    // Creates all the labels
    sprintf(chainLabel, ".chain_%d", chainID);
    sprintf(chainLabel_C, ".chain_%d:", chainID);
    sprintf(resumeLabel, ".resume_%d", chainID);
    sprintf(resumeLabel_C, ".resume_%d:", chainID);
  }

  ~ROPChain() { globalChainID--; }
};

BinaryAutopsy *ROPChain::BA =
    BinaryAutopsy::getInstance("/lib/i386-linux-gnu/libc.so.6");
/*
std::BinaryAutopsy *init() {
  static cl::opt<std::string> BinaryPath(
      "lib",
      cl::desc("path to the library from which gadgets must be extracted"),
      cl::NotHidden, cl::Optional, cl::ValueRequired);
  StringRef binPath = StringRef(BinaryPath.getValue());
  if (binPath.empty()) {
    dbgs() << "[*] No 'lib' argument supplied. Using LIBC\n";
    binPath = "/lib/i386-linux-gnu/libc.so.6";
  }

  std::BinaryAutopsy *BA = std::BinaryAutopsy::getInstance(binPath);
  BA->extractGadgets();
  return BA;
}*/
/*
struct ChainElem {
  // Element to be pushed onto the stack (gadget or immediate value)
  // Each ChainElem is associated with a specific symbol: by doing this, we
can
  // avoid to associate one gadget with always the same symbol
  type_t type;
  union {
    int64_t value;
    const Gadget *r;
  };
  Symbol *s;

  ChainElem(std::string asmInstr) {
    type = GADGET;

    r = gadgetLookup(asmInstr);
    assert(r != nullptr && "Unable to find the requested gadget");

    s = getRandomSymbol();
  };

  ChainElem(Gadget *r) : r(r) {
    type = GADGET;
    s = getRandomSymbol();
  };

  ChainElem(int64_t value) : value(value) { type = IMMEDIATE; }

  uint64_t getRelativeAddress() { return r->getAddress() - s->address; }
};
*/

int ROPChain::globalChainID = 0;

void ROPChain::inject() {
  /*gadgetLookup(X86_INS_XOR, opCreate(X86_OP_REG, X86_REG_EAX),
               opCreate(X86_OP_REG, X86_REG_EAX));

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

      // call $opaquePredicate
      BuildMI(*MBB, injectionPoint, nullptr, TII->get(X86::CALLpcrel32))
          .addExternalSymbol("opaquePredicate");

      // je $wrong_target
      BuildMI(*MBB, injectionPoint, nullptr, TII->get(X86::JNE_1))
          .addExternalSymbol(chainLabel);

      // .symver directive: necessary to prevent aliasing when more symbols
      // have the same name
      BuildMI(*MBB, injectionPoint, nullptr, TII->get(TargetOpcode::INLINEASM))
          .addExternalSymbol(e->s->getSymVerDirective())
          .addImm(0);

      // TODO: push+add in one single instruction (via inline ASM)

      // push $symbol
      BuildMI(*MBB, injectionPoint, nullptr, TII->get(X86::PUSHi32))
          .addExternalSymbol(e->s->name);

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
    MI->eraseFromParent();
  }*/
}

int ROPChain::addInstruction(MachineInstr &MI) {
  // Wrapper method: if a correct binding can be found between the original
  // instruction and some gadgets, the original instruction is put in a
  // vector. We keep track of all the instructions to remove in order to defer
  // the actual deletion to the moment in which we'll inject the ROP Chain. We
  // do this because currently MI is just an iterator

  assert(!finalized && "Attempt to modify a finalized chain!");
  int err = mapBindings(MI);

  if (!err) {
    instructionsToDelete.push_back(&MI);
  }

  return err;
}

// Among a set of RR gadgets, picks the one that has:
// 1. as dst operand the register we supply, or at least one that is
// exchangeable
// 2. as src operand a register that is at least indirectly initialisable via
// a scratch register.
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
    for (auto &a : tmp)
      dbgs() << "x -> " << a.asmInstr << "\n";

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

    // exchange dst gadget op
    tmp = BA->getXchgPath(scratch, picked->getOp(1).reg);
    if (tmp.size() == 0)
      dbgs() << "no xchg required between the loaded scratch register and "
                "gadget src\n";

    for (auto &a : tmp)
      dbgs() << "x -> " << a.asmInstr << "\n";
  }

    /*
        if (MI.getOperand(0).getReg() == X86::EAX) {
          chain.push_back(ChainElem("pop ecx;"));
          chain.push_back(MI.getOperand(2).getImm());
          chain.push_back(ChainElem("add eax, ecx;"));
          return 0;
        } else
          return 1;*/
  /*case X86::SUB32ri8:
  case X86::SUB32ri:
    return 1;
    if (MI.getOperand(0).getReg() == X86::EAX) {
      chain.push_back(ChainElem("pop ecx;"));
      chain.push_back(ChainElem(-MI.getOperand(2).getImm()));
      chain.push_back(ChainElem("add eax, ecx;"));
      return 0;
    } else
      return 1;
  case X86::MOV32ri:
    if (MI.getOperand(0).getReg() == X86::EAX) {
      auto g = gadgetLookup(X86_INS_POP, opCreate(X86_OP_REG, X86_REG_EAX));
      if (g) {
        chain.push_back(ChainElem(g));
        chain.push_back(ChainElem(MI.getOperand(2).getImm()));
        return 0;
      }
    }
    return 1;
  case X86::MOV32rm:
    return 1;
    // mov eax, dword ptr [ebp - $displacement]
    if (MI.getOperand(0).getReg() == X86::EAX &&
        MI.getOperand(1).getReg() == X86::EBP) {
      loadEffectiveAddress(MI.getOperand(4).getImm());
      chain.push_back(ChainElem("mov eax, dword ptr [edx];"));
      return 0;
    } else
      return 1;
  case X86::MOV32mr:
    return 1;
    // mov dword ptr [ebp - $displacement], eax
    if (MI.getOperand(0).getReg() == X86::EBP &&
        MI.getOperand(5).getReg() == X86::EAX) {
      loadEffectiveAddress(MI.getOperand(3).getImm());
      chain.push_back(ChainElem("mov dword ptr [edx], eax;"));
      return 0;
    } else
      return 1;*/
  default:
    return 1;
  }
}

void ROPChain::loadEffectiveAddress(int64_t displacement) {
  /* Loads the effective address of a memory reference of type [ebp +
   * $displacement] in EDX */
  // EAX <- EBP
  /*
  chain.push_back(ChainElem("xchg eax, ebp;"));
  chain.push_back(ChainElem("xchg eax, edx;"));
  chain.push_back(ChainElem("mov eax, edx;"));
  chain.push_back(ChainElem("xchg eax, ebp;"));
  chain.push_back(ChainElem("xchg eax, edx;"));
  // EAX = EAX + $displacement
  chain.push_back(ChainElem("pop ecx;"));
  chain.push_back(ChainElem(displacement));
  chain.push_back(ChainElem("add eax, ecx;"));
  // EDX <- EAX
  chain.push_back(ChainElem("xchg eax, edx;"));*/
}

void ROPChain::finalize() { finalized = true; }

bool ROPChain::isFinalized() { return finalized; }

bool ROPChain::isEmpty() { return true; } // chain.empty(); }
