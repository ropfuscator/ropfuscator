#include "RopfuscatorLivenessAnalysis.h"
#include "RopfuscatorCapstoneLLVMAdpt.h"
#include "RopfuscatorDebug.h"
#include "X86.h"
#include "X86Subtarget.h"
#include "llvm/CodeGen/LivePhysRegs.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <map>

using namespace llvm;

ScratchRegTracker::ScratchRegTracker(MachineBasicBlock &MBB) : MBB(MBB) {
  performLivenessAnalysis();
}

void ScratchRegTracker::addInstr(MachineInstr &MI) {
  std::vector<x86_reg> emptyVect;
  regs.insert(std::make_pair(&MI, emptyVect));
  return;
}

void ScratchRegTracker::addReg(MachineInstr &MI, int reg) {
  auto it = regs.find(&MI);
  // IMPORTANT: Here the register representation is converted from LLVM to
  // capstone and stored in the map.
  if (it != regs.end()) {
    it->second.push_back(convertToCapstoneReg(reg));
  } else
    assert(false && "No matching MachineInstr found in regs map!");
  return;
}

std::vector<x86_reg> *ScratchRegTracker::findRegs(MachineInstr &MI) {
  auto it = regs.find(&MI);
  if (it != regs.end()) {
    // std::vector<x86_reg> *tmp = &it->second;
    return &it->second;
  }
  assert(false && "No vector");
}

x86_reg ScratchRegTracker::getReg(MachineInstr &MI) {
  std::vector<x86_reg> *tmp = findRegs(MI);
  if (tmp)
    return tmp->back();
  return X86_REG_INVALID;
}

std::vector<x86_reg> *ScratchRegTracker::getRegs(MachineInstr &MI) {
  std::vector<x86_reg> *tmp = findRegs(MI);
  if (tmp)
    return tmp;
  return nullptr;
}

int ScratchRegTracker::count(MachineInstr &MI) {
  std::vector<x86_reg> *tmp = findRegs(MI);
  if (tmp)
    return tmp->size();
  return 0;
}

void ScratchRegTracker::performLivenessAnalysis() {
  const MachineFunction *MF = MBB.getParent();
  const TargetRegisterInfo &TRI = *MF->getSubtarget().getRegisterInfo();
  const MachineRegisterInfo &MRI = MF->getRegInfo();
  LivePhysRegs LiveRegs(TRI);
  LiveRegs.addLiveIns(MBB);

  for (auto I = MBB.begin(); I != MBB.end(); ++I) {
    MachineInstr *MI = &*I;
    addInstr(*MI);
    for (unsigned reg : X86::GR32RegClass) {
      if (LiveRegs.available(MRI, reg)) {
        addReg(*MI, reg);
      }
    }
    SmallVector<std::pair<unsigned, const MachineOperand *>, 2> Clobbers;
    LiveRegs.stepForward(*MI, Clobbers);
  }

  DEBUG_WITH_TYPE(LIVENESS_ANALYSIS,
                  dbgs() << "[LivenessAnalysis]\tRegister liveness analysis "
                            "performed on basic block "
                         << MBB.getNumber() << "\n");
}