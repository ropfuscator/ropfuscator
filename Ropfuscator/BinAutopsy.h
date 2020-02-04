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

#define PACKAGE "ropfuscator" /* see https://bugs.gentoo.org/428728 */

#include "ChainElem.h"
#include "Microgadget.h"
#include "ROPEngine.h"
#include "Section.h"
#include "Symbol.h"
#include "XchgGraph.h"
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <map>
#include <string>
#include <vector>

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
  explicit BinaryAutopsy(std::string path);
  BinaryAutopsy() = delete;
  BinaryAutopsy(const BinaryAutopsy &) = delete;
  ~BinaryAutopsy();

public:
  // XchgGraph instance
  XchgGraph xgraph;

  // Symbols - results from dumpDynamicSymbols() are placed here
  std::vector<Symbol> Symbols;

  // Sections - results from dumpSections() are placed here
  std::vector<Section> Sections;
  // Segments - results from dumpSegments() are placed here
  std::vector<Section> Segments;

  // Microgadgets - results from dumpGadgets() are placed here
  std::vector<Microgadget> Microgadgets;

  std::map<std::string, std::vector<Microgadget>> GadgetPrimitives;

  // elf - an handle to analyse ELF file. Used by dumpSections() and
  // dumpDynamicSymbols()
  std::unique_ptr<ELFParser> elf;

  bool isModuleSymbolAnalysed;

  // getInstance - returns an instance of this singleton class
  static BinaryAutopsy *getInstance(std::string path);
  static BinaryAutopsy *getInstance();

  // -----------------------------------------------------------------------------
  //  ANALYSES
  // -----------------------------------------------------------------------------

private:
  // dissect - dumps all the data and performs every analysis.
  void dissect();

  // dumpSections - parses the ELF header to obtain a list of
  // sections that contain executable code, from which the symbol and gadget
  // extraction will take place.
  void dumpSections();
  void dumpSegments();

  // dumpDynamicSymbols - extracts symbols from the .dynsym section. It takes
  // into account only function symbols with global scope and used in executable
  // sections.
  void dumpDynamicSymbols();

  // dumpGadgets - extracts every microgadget (i.e., single instructions
  // before a RET) that can be found in executable sections. Each instruction is
  // decoded using capstone-engine.
  void dumpGadgets();

  // buildXchgGraph - creates a new instance of xgraph and feeds it with all the
  // XCHG gadgets that have been found.
  void buildXchgGraph();

  // applyGadgetFilters - removes problematic gadgets from the set of discovered
  // ones, basing on the defined filters.
  void applyGadgetFilters();

public:
  // analyseUsedSymbols - traverse the module and register the symbol names
  // with forbidden list
  void analyseUsedSymbols(const llvm::Module *module);

  // -----------------------------------------------------------------------------
  //  HELPER METHODS
  // -----------------------------------------------------------------------------

  // getRandomSymbol - returns a random symbol. This is used to reference each
  // gadget in the ROP chain as sum of a random symbol address and the gadget
  // offset from it.
  const Symbol *getRandomSymbol() const;

  // gadgetLookup - set of overloaded methods to look for a specific gadget in
  // the set of the ones that have been previously discovered.
  const Microgadget *findGadget(std::string asmInstr) const;
  const Microgadget *findGadget(x86_insn insn, x86_reg op0,
                                x86_reg op1 = X86_REG_INVALID) const;

  std::vector<const Microgadget *>
  findAllGadgets(x86_insn insn, x86_op_type op0,
                 x86_op_type op1 = x86_op_type()) const;
  std::vector<const Microgadget *>
  findAllGadgets(x86_insn insn, x86_reg op0,
                 x86_reg op1 = X86_REG_INVALID) const;
  std::vector<const Microgadget *> findAllGadgets(GadgetClass_t Class) const;

  ROPChain findGadgetPrimitive(XchgState &state, std::string type, x86_reg op0,
                               x86_reg op1 = X86_REG_INVALID) const;
                               
  // areExchangeable - uses XChgGraph to check whether two (or more
  // registers) can be mutually exchanged.
  bool areExchangeable(x86_reg a, x86_reg b) const;

  // getXchgPath - returns a vector of XCHG gadgets in order to exchange the
  // given two registers.
  ROPChain exchangeRegs(XchgState &state, x86_reg reg0, x86_reg reg1) const;
  ROPChain undoXchgs(XchgState &state) const;
  x86_reg getEffectiveReg(const XchgState &state, x86_reg reg) const;

private:
  // Takes a path from the XchgGraph and build a ROP Chains with the right
  // Xchg microgadgets
  ROPChain buildXchgChain(XchgPath const &path) const;
};

#endif