//
// LivenessAnalysis
// Analyses the liveness of physical registers in order to get an unused
// (dead/killed) register when we have the need of a scratch register
//

#include "../X86.h"
#include "../X86InstrBuilder.h"
#include "../X86MachineFunctionInfo.h"
#include "../X86RegisterInfo.h"
#include "../X86Subtarget.h"
#include "../X86TargetMachine.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include <cmath>
#include <map>
#include <sstream>
#include <string>
#include <utility>

using namespace llvm;

struct DeadRegs {
  // Keeps track of available registers when a specific MachineInstr is given
  std::map<MachineInstr *, std::vector<int>> r;

  void setScratchRegister(MachineInstr &MI, int reg) {
    auto it = r.find(&MI);
    if (it != r.end()) {
      it->second.push_back(reg);
    } else {
      std::vector<int> tmp;
      tmp.push_back(reg);
      r.insert(std::make_pair(&MI, tmp));
    }
  }

  int getScratchRegister(MachineInstr &MI) {
    auto it = r.find(&MI);
    if (it != r.end()) {
      std::vector<int> *tmp = &it->second;
      if (tmp->size() > 0) {
        int retval = tmp->back();
        tmp->pop_back();
        return retval;
      }
    }
    return NULL;
  }
};

DeadRegs deadRegs;

void registerLivenessAnalysis(MachineBasicBlock &MBB) {
  const MachineFunction *MF = MBB.getParent();
  const TargetRegisterInfo &TRI = *MF->getSubtarget().getRegisterInfo();
  const MachineRegisterInfo &MRI = MF->getRegInfo();
  LivePhysRegs LiveRegs(TRI);
  LiveRegs.addLiveOuts(MBB);

  // Data-flow analysis is performed starting from the end of each basic block,
  // iterating each instruction backwards to find USEs and DEFs of each physical
  // register
  for (auto I = MBB.rbegin(); I != MBB.rend(); ++I) {
    MachineInstr *MI = &*I;

    for (unsigned reg : X86::GR32RegClass) {
      if (LiveRegs.available(MRI, reg)) {
        deadRegs.setScratchRegister(*MI, reg);
      }
    }

    LiveRegs.stepBackward(*MI);
  }

  dbgs() << "[*] Register liveness analysis performed on basic block "
         << MBB.getNumber() << "\n";
}