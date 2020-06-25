#ifndef INSTRSTEGANO_H
#define INSTRSTEGANO_H

#include "ChainElem.h"
#include <cstdint>
#include <memory>
#include <vector>

namespace ropf {

struct Microgadget;
class ROPChain;
class X86AssembleHelper;
struct StackState;

struct SteganoInstr {
  const Microgadget *gadget;
  std::shared_ptr<ChainElem> poppedValue;
  bool isDummy() const { return gadget == nullptr; }
  static const SteganoInstr DUMMY;
  SteganoInstr(const Microgadget *gadget, const ChainElem &poppedValue)
      : gadget(gadget), poppedValue(new ChainElem(poppedValue)) {}
  SteganoInstr(const Microgadget *gadget) : gadget(gadget), poppedValue() {}
};

struct SteganoInstructions {
  std::vector<SteganoInstr> instrs;
  void split(size_t count, std::vector<SteganoInstructions> &instrs) const;
  SteganoInstructions expandWithDummy(size_t newsize) const;
};

struct SteganoStrategy {
  bool enabled;
  // ratio of ROP gadgets which is interleaved into opaque constructs
  double hidingRatio;
};

class InstrSteganoProcessor {
public:
  InstrSteganoProcessor() {}
  size_t convertROPChainToStegano(ROPChain &chain, SteganoInstructions &instrs,
                                  size_t maxElem);
  void insert(const SteganoInstructions &instrs, X86AssembleHelper &as,
              StackState &stack, const std::vector<unsigned int> &tempRegs,
              unsigned int opaqueReg, uint32_t opaqueValue) {
    for (const SteganoInstr &instr : instrs.instrs) {
      if (instr.isDummy()) {
        insertDummy(as, stack, tempRegs, opaqueReg, opaqueValue);
      } else {
        insertGadget(instr.gadget, instr.poppedValue.get(), as, stack, tempRegs,
                     opaqueReg, opaqueValue);
      }
    }
  }
  void insertDummy(X86AssembleHelper &as, StackState &stack,
                   const std::vector<unsigned int> &tempRegs,
                   unsigned int opaqueReg, uint32_t opaqueValue);
  void insertGadget(const Microgadget *gadget, const ChainElem *poppedValue,
                    X86AssembleHelper &as, StackState &stack,
                    const std::vector<unsigned int> &tempRegs,
                    unsigned int opaqueReg, uint32_t opaqueValue);
};

} // namespace ropf

#endif // INSTRSTEGANO_H
