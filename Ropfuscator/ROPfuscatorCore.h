// ==============================================================================
//   X86 ROPFUSCATOR
//   part of the ROPfuscator project
// ==============================================================================
// This module is simply the frontend of ROPfuscator for LLVM.
// It also provides statics about the processed functions.
//

#ifndef ROPFUSCATORCORE_H
#define ROPFUSCATORCORE_H

// To generate instruction coverage, define this
#define ROPFUSCATOR_INSTRUCTION_STAT

#ifdef ROPFUSCATOR_INSTRUCTION_STAT
#include <map>
#endif

// forward declaration
class BinaryAutopsy;
class ROPChain;
namespace llvm {
class MachineFunction;
class MachineBasicBlock;
class MachineInstr;
class X86InstrInfo;
} // namespace llvm

class ROPfuscatorCore {
public:
  ROPfuscatorCore();
  ~ROPfuscatorCore();
  void obfuscateFunction(llvm::MachineFunction &MF);

  bool opaquePredicateEnabled;

private:
  BinaryAutopsy *BA;
  const llvm::X86InstrInfo *TII;

#ifdef ROPFUSCATOR_INSTRUCTION_STAT
  struct ROPChainStatEntry;
  std::map<unsigned, ROPChainStatEntry> instr_stat;
#endif

  void insertROPChain(const ROPChain &chain, llvm::MachineBasicBlock &MBB,
                      llvm::MachineInstr &MI, int chainID);
};

#endif
