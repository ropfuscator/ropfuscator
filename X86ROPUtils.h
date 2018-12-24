//
// Created by Daniele Ferla on 22/10/2018.
//

#include "../X86.h"
#include "../X86InstrBuilder.h"
#include "../X86MachineFunctionInfo.h"
#include "../X86RegisterInfo.h"
#include "../X86Subtarget.h"
#include "../X86TargetMachine.h"
#include "ROPseeker.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include <stdio.h>
#include <string>
#include <sys/time.h>

using namespace llvm;
enum type_t { GADGET, IMMEDIATE };

struct ChainElem;

struct Stats {
  int processed;
  int replaced;

  Stats() : processed(0), replaced(0){};
};

class ROPChain {
  /* Keeps track of all the instructions to be replaced with the obfuscated
   * ones. Handles the injection of auxiliary machine code to guarantee the
   * correct chain execution and to resume the non-obfuscated code execution
   * afterwards. */

  // IDs
  static int globalChainID;
  int chainID;

  // A finalized chain can't get gadgets anymore
  bool finalized = false;

  // Input instructions that we want to replace with obfuscated ones
  std::vector<MachineInstr *> instructionsToDelete;

  // Gadgets to be pushed onto the stack during the injection phase
  std::vector<ChainElem> chain;

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

  // Methods
  int addInstruction(MachineInstr &MI);
  int mapBindings(MachineInstr &MI);
  void inject();
  void loadEffectiveAddress(int64_t displacement);

  // Helper methods
  bool isFinalized();
  void finalize();
  bool isEmpty();

  typedef std::map<std::string, Gadget *> ropmap;
  static ropmap libc_microgadgets;

  ROPChain(MachineBasicBlock &MBB, MachineInstr &injectionPoint)
      : MBB(&MBB), injectionPoint(&injectionPoint) {
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

struct ChainElem {
  /* Element to be pushed onto the stack. It could be either a gadget
   * or an immediate value */
  type_t type;
  int64_t value;
  const char* symbolName;
  const char* symVerDirective;

  ChainElem(std::string asmInstr) {
    type = GADGET;

    Gadget* r = ROPChain::libc_microgadgets[asmInstr];
    assert(r != nullptr &&
           "Unable to find specified asm instruction in the gadget library!");

    uint64_t address = r->address;

    Symbol *s = getRandomSymbol();
    value = address - s->address;

    symbolName = s->name.c_str();
    symVerDirective = s->symVer.c_str();
  };

  ChainElem(int64_t value) : value(value) { type = IMMEDIATE; }
};

ROPChain::ropmap ROPChain::libc_microgadgets = findGadgets();

int ROPChain::globalChainID = 0;

void ROPChain::inject() {
  /* PROLOGUE: saves the EIP value before executing the ROP chain */
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


  /* Pushes each gadget onto the stack in reverse order */
  for (auto elem = chain.rbegin(); elem != chain.rend(); ++elem) {
    switch (elem->type) {

      case IMMEDIATE: {
      /* Push the immediate value onto the stack */
      // push $imm
      BuildMI(*MBB, injectionPoint, nullptr, TII->get(X86::PUSHi32))
          .addImm(elem->value); break;
      }

      case GADGET: {
      /* Push a random symbol that, when resolved by the dynamic linker,
       * will be used as base address; then add the offset to point a specific gadget */

      // .symver directive: necessary to prevent aliasing when more symbols have the same name
      BuildMI(*MBB, injectionPoint, nullptr, TII->get(TargetOpcode::INLINEASM))
                .addExternalSymbol(elem->symVerDirective)
                .addImm(0);
      // push $symbol
      BuildMI(*MBB, injectionPoint, nullptr, TII->get(X86::PUSHi32))
          .addExternalSymbol(elem->symbolName);
      // add [esp], $offset
      addDirectMem(
          BuildMI(*MBB, injectionPoint, nullptr, TII->get(X86::ADD32mi)),
          X86::ESP)
          .addImm(elem->value); break;
      }
    }
  }

  /* EPILOGUE
  Emits the `ret` instruction which will trigger the chain execution, and a
  label to resume the normal execution flow when the chain has finished. */
  // ret
  BuildMI(*MBB, injectionPoint, nullptr, TII->get(X86::RETL));
  // resume_X:
  BuildMI(*MBB, injectionPoint, nullptr, TII->get(TargetOpcode::INLINEASM))
      .addExternalSymbol(resumeLabel_C)
      .addImm(0);

  /* Deletes the initial instructions */
  for (MachineInstr *MI : instructionsToDelete) {
    MI->eraseFromParent();
  }
}

int ROPChain::addInstruction(MachineInstr &MI) {
  /* Wrapper method: if a correct binding can be found between the original
   * instruction and some gadgets, the original instruction is put in a vector.
   * We keep track of all the instructions to remove in order to defer the
   * actual deletion to the moment in which we'll inject the ROP Chain. We do
   * this because currently MI is just an iterator */
  assert(!finalized && "Attempt to modify a finalized chain!");
  int err = mapBindings(MI);

  if (!err) {
    instructionsToDelete.push_back(&MI);
  }

  return err;
}

int ROPChain::mapBindings(MachineInstr &MI) {
  /* Given a specific MachineInstr it tries to find a series of gadgets that
   * can replace the input instruction maintaining the same semantics.
   * In general we use registers as following:
   *    - EAX: accumulator, storage of computed values
   *    - EBX: pointer to the libc base address
   *    - ECX: storage of immediate values
   *    - EDX: storage of memory addresses */

  unsigned opcode = MI.getOpcode();
  switch (opcode) {
  case X86::ADD32ri8:
  case X86::ADD32ri:
    if (MI.getOperand(0).getReg() == X86::EAX) {
      chain.push_back(ChainElem("pop ecx;"));
      chain.push_back(MI.getOperand(2).getImm());
      chain.push_back(ChainElem("add eax, ecx;"));
      return 0;
    } else
      return 1;
  case X86::SUB32ri8:
  case X86::SUB32ri:
    if (MI.getOperand(0).getReg() == X86::EAX) {
      chain.push_back(ChainElem("pop ecx;"));
      chain.push_back(ChainElem(-MI.getOperand(2).getImm()));
      chain.push_back(ChainElem("add eax, ecx;"));
      return 0;
    } else
      return 1;
  case X86::MOV32ri:
    if (MI.getOperand(0).getReg() == X86::EAX) {
      chain.push_back(ChainElem("pop eax;"));
      chain.push_back(ChainElem(MI.getOperand(2).getImm()));
      return 0;
    } else
      return 1;
  case X86::MOV32rm:
    // mov eax, dword ptr [ebp - $displacement]
    if (MI.getOperand(0).getReg() == X86::EAX &&
        MI.getOperand(1).getReg() == X86::EBP) {
      loadEffectiveAddress(MI.getOperand(4).getImm());
      chain.push_back(ChainElem("mov eax, dword ptr [edx];"));
      return 0;
    } else
      return 1;
  case X86::MOV32mr:
    // mov dword ptr [ebp - $displacement], eax
    if (MI.getOperand(0).getReg() == X86::EBP &&
        MI.getOperand(5).getReg() == X86::EAX) {
      loadEffectiveAddress(MI.getOperand(3).getImm());
      chain.push_back(ChainElem("mov dword ptr [edx], eax;"));
      return 0;
    } else
      return 1;
  default:
    return 1;
  }
}

void ROPChain::loadEffectiveAddress(int64_t displacement) {
  /* Loads the effective address of a memory reference of type [ebp +
   * $displacement] in EDX */
  // EAX <- EBP
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
  chain.push_back(ChainElem("xchg eax, edx;"));
}

void ROPChain::finalize() { finalized = true; }

bool ROPChain::isFinalized() { return finalized; }

bool ROPChain::isEmpty() { return chain.empty(); }
