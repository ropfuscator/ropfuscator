#include "InstrStegano.h"
#include "ChainElem.h"
#include "Debug.h"
#include "MathUtil.h"
#include "ROPEngine.h"
#include "X86AssembleHelper.h"

#include "X86.h"

namespace ropf {

namespace X86 = llvm::X86;

const SteganoInstr SteganoInstr::DUMMY = {nullptr};

void SteganoInstructions::split(
    size_t count, std::vector<SteganoInstructions> &result) const {
  if (count == 0) {
    return;
  }
  size_t n = instrs.size() / count;
  std::vector<size_t> num_elements;
  for (size_t i = 0; i < count; i++) {
    num_elements.push_back(n);
  }
  for (size_t i = n * count; i < instrs.size(); i++) {
    num_elements[math::Random::range32(0, (uint32_t)count)]++;
  }
  auto it = instrs.begin();
  for (size_t i = 0; i < count; i++) {
    result.push_back({});
    std::copy_n(it, num_elements[i], std::back_inserter(result.back().instrs));
    it += num_elements[i];
  }
}

SteganoInstructions SteganoInstructions::expandWithDummy(size_t newsize) const {
  if (newsize <= instrs.size()) {
    return *this;
  }
  std::vector<bool> orig_indices(newsize);
  for (size_t i = 0; i < instrs.size(); i++) {
    orig_indices[i] = true;
  }
  std::shuffle(orig_indices.begin(), orig_indices.end(),
               math::Random::engine());
  SteganoInstructions result;
  result.instrs.reserve(newsize);
  auto it = instrs.begin();
  for (bool b : orig_indices) {
    result.instrs.push_back(b ? *it++ : SteganoInstr::DUMMY);
  }
  return result;
}

void InstrSteganoProcessor::insertDummy(
    X86AssembleHelper &as, StackState &stack,
    const std::vector<unsigned int> &tempRegs, unsigned int opaqueReg,
    uint32_t opaqueValue) {
  if (stack.constant_location.size() == 0) {
    // do not insert
    return;
  }
  // as.inlineasm("# dummy");
  int stack_offset = stack.constant_location[math::Random::range32(
      0, stack.constant_location.size())];
  // mutate constant value saved in stack
  if (opaqueReg == 0 || math::Random::bit()) {
    opaqueValue = math::Random::rand();
    as.add(as.mem(X86::ESP, stack_offset - stack.stack_offset),
           as.imm(opaqueValue));
  } else {
    as.add(as.mem(X86::ESP, stack_offset - stack.stack_offset),
           as.reg(opaqueReg));
  }
  stack.saved_values[stack_offset].value += opaqueValue;
}

size_t InstrSteganoProcessor::convertROPChainToStegano(
    ROPChain &chain, SteganoInstructions &instrs, size_t maxElem) {
  if (chain.size() == 0) {
    return 0;
  }
  size_t i;
  maxElem = std::min(maxElem, chain.size() - 1);
  for (i = 0; i < maxElem; i++) {
    const ChainElem &elem = chain.chain[i];
    bool supported = false;
    bool popNext = false;
    if (elem.type != ChainElem::Type::GADGET) {
      break;
    }
    const Microgadget *gadget = elem.microgadget;
    switch (gadget->Type) {
    case GadgetType::INIT:
      popNext = true;
      supported = true;
      break;
    default:
      break;
    }
    if (!supported || (popNext && i + 1 >= maxElem)) {
      break;
    }
    if (popNext) {
      ChainElem &elem = chain.chain[i + 1];
      if (elem.type != ChainElem::Type::IMM_VALUE)
        break;
      instrs.instrs.emplace_back(gadget, elem);
      i++;
    } else {
      instrs.instrs.emplace_back(gadget);
    }
  };
  chain.chain.erase(chain.chain.begin(), chain.chain.begin() + i);
  return i;
}

void InstrSteganoProcessor::insertGadget(
    const Microgadget *gadget, const ChainElem *poppedValue,
    X86AssembleHelper &as, StackState &stack,
    const std::vector<unsigned int> &tempRegs, unsigned int opaqueReg,
    uint32_t opaqueValue) {
  // as.inlineasm("# stegano instr");
  // find actual location where reg1 and reg2 are stored
  bool reg1_stack = false;
  bool reg2_stack = false;
  int reg1_offset = 0;
  int reg2_offset = 0;
  auto it_end = stack.regs_location.end();
  if (gadget->reg1) {
    auto it = stack.regs_location.find(gadget->reg1);
    if (it != it_end) {
      reg1_stack = true;
      reg1_offset = it->second - stack.stack_offset;
    }
  }
  if (gadget->reg2) {
    auto it = stack.regs_location.find(gadget->reg2);
    if (it != it_end) {
      reg2_stack = true;
      reg2_offset = it->second - stack.stack_offset;
    }
  }
  switch (gadget->Type) {
  case GadgetType::INIT:
    if (poppedValue == nullptr) {
      dbg_fmt("Impl error: poppedValue == null\n");
      return;
    }
    if (reg1_stack) {
      if (opaqueReg == 0) {
        opaqueValue = math::Random::rand();
        as.mov(as.mem(X86::ESP, reg1_offset), as.imm(opaqueValue));
      } else {
        as.mov(as.mem(X86::ESP, reg1_offset), as.reg(opaqueReg));
      }
      switch (poppedValue->type) {
      case ChainElem::Type::IMM_VALUE:
        as.add(as.mem(X86::ESP, reg1_offset),
               as.imm(poppedValue->value - opaqueValue));
        break;
      case ChainElem::Type::IMM_GLOBAL:
        dbg_fmt("Impl error: unsupported popped value\n");
        as.add(as.mem(X86::ESP, reg1_offset),
               as.imm(poppedValue->global, -opaqueValue));
        break;
      default:
        dbg_fmt("Impl error: unsupported popped value\n");
        return;
      }
    } else {
      if (opaqueReg == 0) {
        opaqueValue = math::Random::rand();
        as.mov(as.reg(gadget->reg1), as.imm(opaqueValue));
      } else {
        as.mov(as.reg(gadget->reg1), as.reg(opaqueReg));
      }
      switch (poppedValue->type) {
      case ChainElem::Type::IMM_VALUE:
        as.add(as.reg(gadget->reg1), as.imm(poppedValue->value - opaqueValue));
        break;
      case ChainElem::Type::IMM_GLOBAL:
        dbg_fmt("Impl error: unsupported popped value\n");
        as.add(as.reg(gadget->reg1), as.imm(poppedValue->global, -opaqueValue));
        break;
      default:
        dbg_fmt("Impl error: unsupported popped value\n");
        return;
      }
    }
    break;
  case GadgetType::XCHG:
  case GadgetType::COPY:
  case GadgetType::LOAD:
  case GadgetType::LOAD_1:
  case GadgetType::STORE:
  case GadgetType::ADD:
  case GadgetType::ADD_1:
  case GadgetType::SUB:
  case GadgetType::SUB_1:
  case GadgetType::AND:
  case GadgetType::AND_1:
  case GadgetType::OR:
  case GadgetType::OR_1:
  case GadgetType::XOR:
  case GadgetType::XOR_1:
  case GadgetType::CMOVE:
  case GadgetType::CMOVB:
    dbg_fmt("Impl error: not implemented\n");
    return;
  default:
    dbg_fmt("Impl error: unexpected case\n");
    return;
  }
}

} // namespace ropf
