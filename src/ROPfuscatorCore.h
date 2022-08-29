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
#define ROPFUSCATOR_OBFUSCATION_STATISTICS_FILE_HEAD                           \
  "ropfuscator_obfuscation_stats"
#include <map>
#endif

#include "ChainElem.h"
#include "ROPfuscatorConfig.h"

// forward declaration
namespace llvm {
class MachineFunction;
class MachineBasicBlock;
class MachineInstr;
class Module;
class X86InstrInfo;
} // namespace llvm

namespace ropf {

class BinaryAutopsy;
class ROPChain;
class ChainElementSelector;

class ROPfuscatorCore {
public:
  explicit ROPfuscatorCore(llvm::Module            &module,
                           const ROPfuscatorConfig &config);
  ~ROPfuscatorCore();
  void obfuscateFunction(llvm::MachineFunction &MF);

private:
  ROPfuscatorConfig         config;
  BinaryAutopsy            *BA;
  const llvm::X86InstrInfo *TII;
  ChainElementSelector     *gadgetAddressSelector;
  ChainElementSelector     *immediateSelector;
  ChainElementSelector     *branchTargetSelector;
  std::string               sourceFileName;

#ifdef ROPFUSCATOR_INSTRUCTION_STAT
  struct ROPChainStatEntry;
  std::map<unsigned, ROPChainStatEntry> instr_stat;
  size_t                                total_chain_elems;
  size_t                                total_instructions;
#endif
  // for progress report
  size_t total_func_count, curr_func_count;

  // Randomly reduces the number of specific type(s) of chain elements to the
  // specified percentage. The indices of the chain elements are saved into
  // outVector.
  void reduceChainElemTypeToPercentage(ROPChain                    &chain,
                                       unsigned int                 percentage,
                                       std::vector<ChainElem::Type> elemTypes,
                                       std::vector<unsigned>       &outVector);

  void insertROPChain(ROPChain                   &chain,
                      llvm::MachineBasicBlock    &MBB,
                      llvm::MachineInstr         &MI,
                      int                         chainID,
                      const ObfuscationParameter &param);
};

} // namespace ropf

#endif
