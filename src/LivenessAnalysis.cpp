#include "LivenessAnalysis.h"
#include "Debug.h"
#include "X86.h"
#include "X86Subtarget.h"
#include "llvm/CodeGen/LivePhysRegs.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include <map>

namespace ropf {

using namespace llvm;
using namespace std;

#if LLVM_VERSION_MAJOR >= 8
typedef MCPhysReg reg_type;
#else
typedef unsigned int reg_type;
#endif

void addReg(MachineInstr &                             MI,
            int                                        reg,
            map<MachineInstr *, vector<unsigned int>> &regs) {
  auto it = regs.find(&MI);

  if (it == regs.end()) {
    assert(false && "No matching MachineInstr found in regs map!");
  }

  it->second.push_back(reg);

  return;
}

map<MachineInstr *, vector<unsigned int>>
performLivenessAnalysis(MachineBasicBlock &MBB) {
  map<MachineInstr *, vector<unsigned int>> regs;
  vector<unsigned int>                      emptyVect;

  const MachineFunction *    MF  = MBB.getParent();
  const TargetRegisterInfo & TRI = *MF->getSubtarget().getRegisterInfo();
  const MachineRegisterInfo &MRI = MF->getRegInfo();
  LivePhysRegs               LiveRegs(TRI);
  LiveRegs.addLiveIns(MBB);

  for (auto I = MBB.begin(); I != MBB.end(); ++I) {
    MachineInstr *MI = &*I;
    regs.insert(std::make_pair(MI, emptyVect));

    for (unsigned reg : X86::GR32RegClass) {
      if (LiveRegs.available(MRI, reg)) {
        addReg(*MI, reg, regs);
      }
    }

    SmallVector<pair<reg_type, const MachineOperand *>, 2> Clobbers;

    LiveRegs.stepForward(*MI, Clobbers);
  }

  DEBUG_WITH_TYPE(LIVENESS_ANALYSIS,
                  dbg_fmt("[LivenessAnalysis]\tRegister liveness analysis "
                          "performed on basic block {}\n",
                          MBB.getNumber()));

  return regs;
}

} // namespace ropf
