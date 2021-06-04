#include "InstrStegano.h"
#include "ChainElem.h"
#include "Debug.h"
#include "MathUtil.h"
#include "ROPEngine.h"
#include "X86AssembleHelper.h"

#include "llvm/CodeGen/MachineBasicBlock.h"

namespace ropf {

namespace X86 = llvm::X86;

const SteganoInstr SteganoInstr::DUMMY = {nullptr};

void SteganoInstructions::split(
    size_t                            count,
    std::vector<SteganoInstructions> &result) const {
  if (count == 0) {
    return;
  }
  size_t              n = instrs.size() / count;
  std::vector<size_t> num_elements;
  for (size_t i = 0; i < count; i++) {
    num_elements.push_back(n);
  }
  for (size_t i = n * count; i < instrs.size(); i++) {
    num_elements[math::Random::range32(0, (uint32_t)count - 1)]++;
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
  std::shuffle(orig_indices.begin(),
               orig_indices.end(),
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
    X86AssembleHelper &              as,
    StackState &                     stack,
    const std::vector<unsigned int> &tempRegs,
    unsigned int                     opaqueReg,
    uint32_t                         opaqueValue) {
  if (stack.constant_location.size() == 0) {
    // do not insert
    return;
  }
  // as.inlineasm("# dummy");
  int stack_offset = stack.constant_location[math::Random::range32(
      0,
      stack.constant_location.size() - 1)];
  // mutate constant value saved in stack
  if (opaqueReg == 0 || math::Random::bit()) {
    opaqueValue = math::Random::rand();
    as.add(as.mem(X86::ESP, stack_offset - stack.stack_offset),
           as.imm(opaqueValue));
    stack.saved_values[stack_offset].value =
        (uint32_t)(opaqueValue + stack.saved_values[stack_offset].value);
  } else {
    uint32_t value = math::Random::rand();
    as.mov(as.mem(X86::ESP, stack_offset - stack.stack_offset),
           as.reg(opaqueReg));
    as.add(as.mem(X86::ESP, stack_offset - stack.stack_offset), as.imm(value));
    stack.saved_values[stack_offset].value = (uint32_t)(opaqueValue + value);
  }
}

size_t
InstrSteganoProcessor::convertROPChainToStegano(ROPChain &           chain,
                                                SteganoInstructions &instrs,
                                                size_t               maxElem) {
  if (chain.size() == 0) {
    return 0;
  }
  size_t i;
  maxElem = std::min(maxElem, chain.size() - 1);
  for (i = 0; i < maxElem; i++) {
    const ChainElem &elem      = chain.chain[i];
    bool             supported = false;
    bool             popNext   = false;
    if (elem.type != ChainElem::Type::GADGET) {
      break;
    }
    const Microgadget *gadget = elem.microgadget;
    switch (gadget->Type) {
    case GadgetType::MOV:
      popNext   = true;
      supported = true;
      break;
    case GadgetType::XCHG:
    case GadgetType::COPY:
    case GadgetType::LOAD:
    case GadgetType::LOAD_1: supported = true; break;
    default: break;
    }
    if (!supported || (popNext && i + 1 >= maxElem)) {
      break;
    }
    if (popNext) {
      ChainElem &elem = chain.chain[i + 1];
      if (elem.type != ChainElem::Type::IMM_VALUE &&
          elem.type != ChainElem::Type::IMM_GLOBAL &&
          elem.type != ChainElem::Type::JMP_BLOCK) {
        break;
      }
      instrs.instrs.emplace_back(gadget, elem);
      i++;
    } else {
      instrs.instrs.emplace_back(gadget);
    }
  }

  chain.chain.erase(chain.chain.begin(), chain.chain.begin() + i);
  // dbg_fmt("stegano {} / {}\n", i, chain.chain.size() + i);
  return i;
}

void InstrSteganoProcessor::insertGadget(
    const Microgadget *              gadget,
    const ChainElem *                poppedValue,
    X86AssembleHelper &              as,
    StackState &                     stack,
    const std::vector<unsigned int> &tempRegs,
    unsigned int                     opaqueReg,
    uint32_t                         opaqueValue) {
  // as.inlineasm("# stegano instr");
  // find actual location where reg1 and reg2 are stored
  MemLoc x = MemLoc::find(gadget->reg1, stack);
  MemLoc y = MemLoc::find(gadget->reg2, stack);
  switch (gadget->Type) {
  case GadgetType::MOV:
    // reg1 := poppedValue
    insertMov(x, poppedValue, as, stack, opaqueReg, opaqueValue);
    break;
  case GadgetType::XCHG:
    // xchg reg1, reg2
    insertXchg(x, y, as, stack);
    break;
  case GadgetType::COPY:
    // mov reg1, reg2
    insertMov(x, y, as, stack);
    break;
  case GadgetType::LOAD:
    // mov reg1, [reg2]
    insertLoad(x, y, as, stack);
    break;
  case GadgetType::LOAD_1:
    // mov reg1, [reg1]
    insertLoad(x, as, stack);
    break;
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
  case GadgetType::CMOVB: dbg_fmt("Impl error: not implemented\n"); return;
  default: dbg_fmt("Impl error: unexpected case\n"); return;
  }
}

InstrSteganoProcessor::MemLoc
InstrSteganoProcessor::MemLoc::find(unsigned int reg, const StackState &stack) {
  if (reg == 0) {
    return {0, 0};
  }

  auto it = stack.regs_location.find(reg);

  if (it != stack.regs_location.end()) {
    return {0, it->second - stack.stack_offset};
  }

  return {reg, 0};
}

void InstrSteganoProcessor::insertXchg(const MemLoc &     x,
                                       const MemLoc &     y,
                                       X86AssembleHelper &as,
                                       StackState &       stack) {
  if (x.isStack()) {
    if (y.isStack()) {
      as.xchg(as.reg(X86::EAX), as.mem(X86::ESP, x.stackOffset));
      as.xchg(as.reg(X86::EAX), as.mem(X86::ESP, y.stackOffset));
      as.xchg(as.reg(X86::EAX), as.mem(X86::ESP, x.stackOffset));
    } else {
      as.xchg(as.reg(y.reg), as.mem(X86::ESP, x.stackOffset));
    }
  } else {
    if (y.isStack()) {
      as.xchg(as.reg(x.reg), as.mem(X86::ESP, x.stackOffset));
    } else {
      as.xchg(as.reg(x.reg), as.reg(y.reg));
    }
  }
}

void InstrSteganoProcessor::insertMov(const MemLoc &     dst,
                                      const MemLoc &     src,
                                      X86AssembleHelper &as,
                                      StackState &       stack) {
  if (src.isStack()) {
    if (dst.isStack()) {
      as.xchg(as.reg(X86::EAX), as.mem(X86::ESP, src.stackOffset));
      as.mov(as.mem(X86::ESP, dst.stackOffset), as.reg(X86::EAX));
      as.xchg(as.reg(X86::EAX), as.mem(X86::ESP, src.stackOffset));
    } else {
      as.mov(as.reg(dst.reg), as.mem(X86::ESP, src.stackOffset));
    }
  } else {
    if (dst.isStack()) {
      as.mov(as.mem(X86::ESP, dst.stackOffset), as.reg(src.reg));
    } else {
      as.mov(as.reg(dst.reg), as.reg(src.reg));
    }
  }
}

namespace {

template <typename DstLoc>
void insertMovImpl(const DstLoc &     dstloc,
                   const ChainElem *  poppedValue,
                   X86AssembleHelper &as,
                   StackState &       stack,
                   unsigned int       opaqueReg,
                   uint32_t           opaqueValue) {
  switch (poppedValue->type) {
  case ChainElem::Type::IMM_VALUE:
    if (opaqueReg == 0) {
      opaqueValue = math::Random::rand();
      as.mov(dstloc, as.imm(opaqueValue));
    } else {
      as.mov(dstloc, as.reg(opaqueReg));
    }

    as.add(dstloc, as.imm(poppedValue->value - opaqueValue));
    break;
  case ChainElem::Type::IMM_GLOBAL: {
    uint32_t addend;

    if (opaqueReg == 0) {
      addend      = math::Random::range32(0x1000, 0x10000000);
      opaqueValue = poppedValue->value - addend;
      as.mov(dstloc, as.imm(opaqueValue));
    } else {
      as.mov(dstloc, as.reg(opaqueReg));
      addend = poppedValue->value - opaqueValue;

      if (addend > 0x10000000) {
        addend = math::Random::range32(0x1000, 0x10000000);
        as.lxor(
            dstloc,
            as.imm((uint32_t)((poppedValue->value - addend) ^ opaqueValue)));
      }
    }

    as.add(dstloc, as.imm(poppedValue->global, addend));
    break;
  }
  case ChainElem::Type::JMP_BLOCK: {
    uint32_t addend;

    if (opaqueReg == 0) {
      addend      = math::Random::range32(0x1000, 0x10000000);
      opaqueValue = -addend;

      as.mov(dstloc, as.imm(opaqueValue));
    } else {
      as.mov(dstloc, as.reg(opaqueReg));
      addend = -opaqueValue;

      if (addend > 0x10000000) {
        addend = math::Random::range32(0x1000, 0x10000000);
        as.lxor(dstloc, as.imm((uint32_t)((-addend) ^ opaqueValue)));
      }
    }

    llvm::MachineBasicBlock *targetMBB   = poppedValue->jmptarget;
    auto                     targetLabel = as.label();
    X86AssembleHelper        as0(*targetMBB, targetMBB->begin());

    as0.putLabel(targetLabel);
    as.add(dstloc, as.addOffset(targetLabel, addend));

    break;
  }
  default: dbg_fmt("Impl error: unsupported popped value\n"); break;
  }
}

} // namespace

void InstrSteganoProcessor::insertMov(const MemLoc &     dst,
                                      const ChainElem *  poppedValue,
                                      X86AssembleHelper &as,
                                      StackState &       stack,
                                      unsigned int       opaqueReg,
                                      uint32_t           opaqueValue) {
  if (poppedValue == nullptr) {
    dbg_fmt("Impl error: poppedValue == null\n");
    return;
  }

  if (dst.isStack()) {
    // reg1 is saved in [esp+reg1_offset]
    // [esp+reg1_offset] = opaqueValue;
    // [esp+reg1_offset] += poppedValue - opaqueValue;
    insertMovImpl(as.mem(X86::ESP, dst.stackOffset),
                  poppedValue,
                  as,
                  stack,
                  opaqueReg,
                  opaqueValue);
  } else {
    // reg1 is stored as it is
    // reg1 = opaqueValue;
    // reg1 += poppedValue - opaqueValue;
    insertMovImpl(as.reg(dst.reg),
                  poppedValue,
                  as,
                  stack,
                  opaqueReg,
                  opaqueValue);
  }
}

void InstrSteganoProcessor::insertLoad(const MemLoc &     dst,
                                       const MemLoc &     addr,
                                       X86AssembleHelper &as,
                                       StackState &       stack) {
  if (addr.isStack()) {
    if (dst.isStack()) {
      // xchg tmp, dst
      // mov tmp, addr
      // mov tmp, [eax]
      // xchg tmp, dst
      auto tmpreg = X86::EAX;
      as.xchg(as.reg(tmpreg), as.mem(X86::ESP, dst.stackOffset));
      as.mov(as.reg(tmpreg), as.mem(X86::ESP, addr.stackOffset));
      as.mov(as.reg(tmpreg), as.mem(tmpreg));
      as.xchg(as.reg(tmpreg), as.mem(X86::ESP, dst.stackOffset));
    } else {
      as.mov(as.reg(dst.reg), as.mem(X86::ESP, addr.stackOffset));
      as.mov(as.reg(dst.reg), as.mem(dst.reg));
    }
  } else {
    if (dst.isStack()) {
      // xchg tmp, dst
      // mov tmp, [addr]
      // xchg tmp, dst
      auto tmpreg = addr.reg != X86::EAX ? X86::EAX : X86::ECX;
      as.xchg(as.reg(tmpreg), as.mem(X86::ESP, dst.stackOffset));
      as.mov(as.reg(tmpreg), as.mem(addr.reg));
      as.xchg(as.reg(tmpreg), as.mem(X86::ESP, dst.stackOffset));
    } else {
      as.mov(as.reg(dst.reg), as.mem(addr.reg));
    }
  }
}

void InstrSteganoProcessor::insertLoad(const MemLoc &     dst,
                                       X86AssembleHelper &as,
                                       StackState &       stack) {
  if (dst.isStack()) {
    // xchg tmp, dst
    // mov tmp, [tmp]
    // xchg tmp, dst
    auto tmpreg = X86::EAX;
    as.xchg(as.reg(tmpreg), as.mem(X86::ESP, dst.stackOffset));
    as.mov(as.reg(tmpreg), as.mem(tmpreg));
    as.xchg(as.reg(tmpreg), as.mem(X86::ESP, dst.stackOffset));
  } else {
    as.mov(as.reg(dst.reg), as.mem(dst.reg));
  }
}

} // namespace ropf
