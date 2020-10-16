// ==============================================================================
//   BINARY AUTOPSY
//   part of the ROPfuscator project
// ==============================================================================
// This module extracts useful features from a given binary. We call it
// "autopsy" because we have to analyse an already compiled program, dissecting
// it in many sections and extracting as many features as possible.
//
// More in detail, the module is able to extract:
//      - data about ELF sections
//      - symbols from the .dynsym section
//      - microgadgets from executable sections
//
// Microgadgets are a subset of what are commonly known as ROP Gadgets, with the
// only difference that we grab only the ones composed by a single instruction
// before the ret, e.g.:
//        mov eax, ebx
//        ret
//
// This module offers also a set of helper methods to search for a specific
// microgadget or verify the exchangeability of its operands.

#ifndef BINAUTOPSY_H
#define BINAUTOPSY_H

#include "ChainElem.h"
#include "Microgadget.h"
#include "ROPEngine.h"
#include "ROPfuscatorConfig.h"
#include "Section.h"
#include "Symbol.h"
#include "X86Subtarget.h"
#include "XchgGraph.h"
#include "llvm/IR/Module.h"
#include "llvm/MC/MCContext.h"
#include "llvm/Target/TargetMachine.h"
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace ropf {

// Max bytes before the RET to be examined (RET included!)
// see BinaryAutopsy::extractGadgets()
#define MAXDEPTH 4

// forward declaration
class ROPChain;
class ELFParser;

// BinaryAutopsy - dumps all the data needed by ROPfuscator.
// It provides also methods to look for specific gadgets and performs
// operand exchangeability analyses.
// This class has been designed as singleton to simplify the interaction with
// the ROPChain class. Indeed, we don't want to analyse the same file every time
// that a new ROPChain is instanciated.
class BinaryAutopsy {
private:
  // Singleton
  static BinaryAutopsy *instance;
  BinaryAutopsy(const GlobalConfig &config, const llvm::Module &module,
                const llvm::TargetMachine &target, llvm::MCContext &context);
  BinaryAutopsy() = delete;
  BinaryAutopsy(const BinaryAutopsy &) = delete;
  ~BinaryAutopsy();

  const llvm::Module &module;
  const llvm::TargetMachine &target;
  llvm::MCContext &context;
  const GlobalConfig &config;

public:
  // XchgGraph instance
  XchgGraph xgraph;

  // Symbols - results from dumpDynamicSymbols() are placed here
  std::vector<Symbol> Symbols;

  // Sections - results from dumpSections() are placed here
  std::vector<Section> Sections;
  // Segments - results from dumpSegments() are placed here
  std::vector<Section> Segments;

  // GadgetPrimitives - results from dumpGadgets() are placed here
  std::map<GadgetType, std::vector<std::shared_ptr<Microgadget>>>
      GadgetPrimitives;

  // elf - a handle to analyse ELF file. Used by dumpSections() and
  // dumpDynamicSymbols()
  std::unique_ptr<ELFParser> elf;

  // otherlibs - handles to other ELF libraries.
  std::vector<std::unique_ptr<ELFParser>> otherLibs;

  bool isModuleSymbolAnalysed;

  // getInstance - returns an instance of this singleton class
  static BinaryAutopsy *getInstance(const GlobalConfig &config,
                                    llvm::MachineFunction &MF);

  // -----------------------------------------------------------------------------
  //  ANALYSES
  // -----------------------------------------------------------------------------

private:
  // dissect - dumps all the data and performs every analysis.
  void dissect(ELFParser *);

  // dumpSections - parses the ELF header to obtain a list of
  // sections that contain executable code, from which the symbol and gadget
  // extraction will take place.
  void dumpSections(const ELFParser *, std::vector<Section> &) const;

  void dumpSegments(const ELFParser *, std::vector<Section> &) const;

  // dumpDynamicSymbols - extracts symbols from the .dynsym section. It takes
  // into account only function symbols with global scope and used in executable
  // sections.
  void dumpDynamicSymbols(const ELFParser *, std::vector<Symbol> &,
                          bool safeOnly) const;

  // isSafeSymbol - return true if symbols are "safe" to be used
  // in gadget addressing
  bool isSafeSymbol(const Symbol &) const;

  // dumpGadgets - extracts every microgadget (i.e., single instructions
  // before a RET) that can be found in executable sections. Each instruction is
  // decoded with LLVM disassembler engine.
  void dumpGadgets(const ELFParser *,
                   std::vector<std::shared_ptr<Microgadget>> &) const;

  // buildXchgGraph - creates a new instance of xgraph and feeds it with all the
  // XCHG gadgets that have been found.
  void buildXchgGraph();

  // register gadget in GadgetPrimitives with some filters.
  void addGadget(std::shared_ptr<Microgadget> gadget);

  // analyseUsedSymbols - traverse the module and register the symbol names
  // with forbidden list
  void analyseUsedSymbols();

public:
  // -----------------------------------------------------------------------------
  //  HELPER METHODS
  // -----------------------------------------------------------------------------

  // getRandomSymbol - returns a random symbol. This is used to reference each
  // gadget in the ROP chain as sum of a random symbol address and the gadget
  // offset from it.
  const Symbol *getRandomSymbol() const;

  // findGadget - set of overloaded methods to look for a specific gadget in
  // the set of the ones that have been previously discovered.
  // const Microgadget *findGadget(std::string asmInstr) const;

  const Microgadget *findGadget(GadgetType type, unsigned int op0,
                                unsigned int op1 = llvm::X86::NoRegister) const;

  ROPChain findGadgetPrimitive(XchgState &state, GadgetType type,
                               unsigned int reg1,
                               unsigned int reg2 = llvm::X86::NoRegister) const;

  // areExchangeable - uses XChgGraph to check whether two (or more
  // registers) can be mutually exchanged.
  bool areExchangeable(unsigned int a, unsigned int b) const;

  // getXchgPath - returns a vector of XCHG gadgets in order to exchange the
  // given two registers.
  ROPChain exchangeRegs(XchgState &state, unsigned int reg1,
                        unsigned int reg2) const;

  ROPChain undoXchgs(XchgState &state) const;

  unsigned int getEffectiveReg(const XchgState &state, unsigned int reg) const;

  void debugPrintGadgets() const;

private:
  // Takes a path from the XchgGraph and build a ROP Chains with the right
  // Xchg microgadgets
  ROPChain buildXchgChain(XchgPath const &path) const;
};

} // namespace ropf

#endif
