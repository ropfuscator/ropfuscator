#include "LivenessAnalysis.h"
#include "../X86.h"
#include "../X86Subtarget.h"
#include "CapstoneLLVMAdpt.h"
#include "Debug.h"
#include "llvm/CodeGen/LivePhysRegs.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <map>

using namespace llvm;
using namespace std;

void addReg(MachineInstr &MI, int reg,
            map<MachineInstr *, vector<x86_reg>> &regs) {
  auto it = regs.find(&MI);

  // IMPORTANT: Here the register representation is converted from LLVM to
  // capstone and stored in the map.
  if (it != regs.end()) {
    it->second.push_back(convertToCapstoneReg(reg));
  } else
    assert(false && "No matching MachineInstr found in regs map!");

  return;
}

map<MachineInstr *, vector<x86_reg>>
performLivenessAnalysis(MachineBasicBlock &MBB) {
  map<MachineInstr *, vector<x86_reg>> regs;
  vector<x86_reg> emptyVect;

  const MachineFunction *MF = MBB.getParent();
  const TargetRegisterInfo &TRI = *MF->getSubtarget().getRegisterInfo();
  const MachineRegisterInfo &MRI = MF->getRegInfo();
  LivePhysRegs LiveRegs(TRI);
  LiveRegs.addLiveIns(MBB);

  for (auto I = MBB.begin(); I != MBB.end(); ++I) {
    MachineInstr *MI = &*I;
    regs.insert(std::make_pair(MI, emptyVect));

    for (unsigned reg : X86::GR32RegClass) {
      if (LiveRegs.available(MRI, reg)) {
        addReg(*MI, reg, regs);
      }
    }

    SmallVector<pair<unsigned, const MachineOperand *>, 2> Clobbers;

    LiveRegs.stepForward(*MI, Clobbers);
  }

  string msg = fmt::format("[LivenessAnalysis]\tRegister liveness analysis "
                           "performed on basic block {}\n",
                           MBB.getNumber());
  DEBUG_WITH_TYPE(LIVENESS_ANALYSIS, dbgs() << msg);

  return regs;
}