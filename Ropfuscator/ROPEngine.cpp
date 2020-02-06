#include "ROPEngine.h"
#include "CapstoneLLVMAdpt.h"
#include "Debug.h"
#include "Symbol.h"
#include "llvm/CodeGen/MachineFunction.h"

using std::string;
using namespace llvm;

class ROPChainBuilder {
  struct ReorderTag {};

  struct VirtualInstr {
    const char *type;
    x86_reg reg1, reg2;
    ChainElem immediate;

    VirtualInstr(const char *type, x86_reg reg1, x86_reg reg2)
        : type(type), reg1(reg1), reg2(reg2) {}

    VirtualInstr(const ChainElem &immediate)
        : type(nullptr), immediate(immediate) {}

    VirtualInstr(ReorderTag) : type("#reorder") {}

    bool isReorder() const { return type && strcmp(type, "#reorder") == 0; }
  };

  const BinaryAutopsy *BA;
  const std::vector<x86_reg> &scratchRegs;
  std::vector<VirtualInstr> vchain;
  size_t numScratchRegs;

public:
  bool normalInstrFlag, jumpInstrFlag, conditionalJumpInstrFlag;

  ROPChainBuilder &append(const char *type, x86_reg reg1,
                          x86_reg reg2 = X86_REG_INVALID) {
    vchain.emplace_back(type, reg1, reg2);
    numScratchRegs = std::max((int)numScratchRegs, -reg1);
    numScratchRegs = std::max((int)numScratchRegs, -reg2);
    return *this;
  }

  ROPChainBuilder &append(const ChainElem &immediate) {
    vchain.emplace_back(immediate);
    return *this;
  }

  ROPChainBuilder &reorder() {
    vchain.emplace_back(ReorderTag());
    return *this;
  }

  explicit ROPChainBuilder(const std::vector<x86_reg> &scratchRegs)
      : BA(BinaryAutopsy::getInstance()), scratchRegs(scratchRegs), vchain(),
        numScratchRegs(0), normalInstrFlag(false), jumpInstrFlag(false),
        conditionalJumpInstrFlag(false) {}

  ROPChainStatus build(XchgState &state, ROPChain &result) const {
    std::vector<x86_reg> regList;

    if (numScratchRegs > scratchRegs.size())
      return ROPChainStatus::ERR_NO_REGISTER_AVAILABLE;

    regList.reserve(numScratchRegs);

    return buildAux(state, result, regList);
  }

private:
  ROPChainStatus buildAux(XchgState &state, ROPChain &result,
                          std::vector<x86_reg> &regList) const {
    if (regList.size() < numScratchRegs) {
      for (x86_reg r : scratchRegs) {
        if (std::find(regList.begin(), regList.end(), r) == regList.end()) {
          regList.push_back(r);

          ROPChainStatus status = buildAux(state, result, regList);
          regList.pop_back();

          if (status == ROPChainStatus::OK) {
            return status;
          }
        }
      }
      return ROPChainStatus::ERR_NO_GADGETS_AVAILABLE;
    }

    std::vector<ROPChain> chains;
    XchgState state0(state);

    for (const VirtualInstr &vi : vchain) {
      if (vi.isReorder()) {
        ROPChain chain = BA->undoXchgs(state0);
        chains.push_back(chain);
      } else if (vi.type) {
        x86_reg reg1 = vi.reg1 >= 0 ? vi.reg1 : regList[-vi.reg1 - 1];
        x86_reg reg2 = vi.reg2 >= 0 ? vi.reg2 : regList[-vi.reg2 - 1];

        if (!isNoop(vi.type, reg1, reg2)) {
          ROPChain chain = BA->findGadgetPrimitive(state0, vi.type, reg1, reg2);

          if (!chain.valid())
            return ROPChainStatus::ERR_NO_GADGETS_AVAILABLE;

          chains.push_back(chain);
        }
      } else {
        if (chains.empty())
          chains.emplace_back();

        chains.back().emplace_back(vi.immediate);
      }
    }

    for (const ROPChain &chain : chains) {
      result.append(chain);
    }

    state = state0;

    if (normalInstrFlag)
      result.hasNormalInstr = true;

    if (jumpInstrFlag)
      result.hasUnconditionalJump = true;

    if (conditionalJumpInstrFlag)
      result.hasConditionalJump = true;

    return ROPChainStatus::OK;
  }

  static bool isNoop(const char *type, x86_reg reg1, x86_reg reg2) {
    if (strcmp(type, "copy") == 0 && reg1 == reg2)
      return true;

    return false;
  }
};

static const x86_reg SCRATCH_1 = (x86_reg)-1;
static const x86_reg SCRATCH_2 = (x86_reg)-2;

// ------------------------------------------------------------------------
// ROP Chain
// ------------------------------------------------------------------------

bool ROPChain::canMerge(const ROPChain &other) {
  if (!valid())
    return true;

  // unconditional jump will terminate rop chain
  if (hasUnconditionalJump)
    return false;

  // conditional jump will terminate rop chain,
  // except for following unconditional jump
  if (hasConditionalJump && other.hasNormalInstr)
    return false;

  if (hasConditionalJump && other.hasConditionalJump)
    return false;

  // otherwise, test if flag save mode is compatible
  //             NOT_SAVED SAVE_BEFORE SAVE_AFTER (other)
  // NOT_SAVED   compat    incompat    incompat
  // SAVE_BEFORE compat    incompat    incompat
  // SAVE_AFTER  incompat  incompat    incompat
  // (this)
  return other.flagSave == FlagSaveMode::NOT_SAVED &&
         (flagSave == FlagSaveMode::NOT_SAVED ||
          flagSave == FlagSaveMode::SAVE_BEFORE_EXEC);
}

void ROPChain::merge(const ROPChain &other) {
  if (!valid()) {
    *this = other;
    return;
  }

  append(other);
  removeDuplicates();
  hasNormalInstr |= other.hasNormalInstr;
  hasConditionalJump |= other.hasConditionalJump;
  hasUnconditionalJump |= other.hasUnconditionalJump;

  // handle conditional jump + unconditional jmp chain
  if (other.successor && !successor) {
    for (auto it = rbegin(); it != rend(); ++it) {
      if (*it == *other.successor) {
        successor = &*it;
        break;
      }
    }

    bool conditionalJumpFound = false;

    for (auto it = begin(); it != end();) {
      if (it->type == ChainElem::Type::JMP_FALLTHROUGH) {
        *it = *successor;
        conditionalJumpFound = true;
      } else if (conditionalJumpFound && *successor == *it) {
        it = chain.erase(it);
        continue;
      }
      ++it;
    }
  }
}

ROPEngine::ROPEngine() {}

bool ROPEngine::convertOperandToChainPushImm(const MachineOperand &operand,
                                             ChainElem &result) {
  if (operand.isImm()) {
    result = ChainElem::fromImmediate(operand.getImm());
    return true;
  } else if (operand.isGlobal()) {
    result = ChainElem::fromGlobal(operand.getGlobal(), operand.getOffset());
    return true;
  }

  return false;
}

ROPChainStatus
ROPEngine::handleArithmeticRI(MachineInstr *MI,
                              std::vector<x86_reg> &scratchRegs) {
  const char *gadget_type;
  int imm;

  switch (MI->getOpcode()) {
  case X86::ADD32ri8:
  case X86::ADD32ri: {
    if (!MI->getOperand(2).isImm())
      return ROPChainStatus::ERR_UNSUPPORTED;

    gadget_type = "add";
    imm = MI->getOperand(2).getImm();
    break;
  }
  case X86::SUB32ri8:
  case X86::SUB32ri: {
    if (!MI->getOperand(2).isImm())
      return ROPChainStatus::ERR_UNSUPPORTED;

    gadget_type = "sub";
    imm = MI->getOperand(2).getImm();
    break;
  }
  case X86::AND32ri8:
  case X86::AND32ri: {
    if (!MI->getOperand(2).isImm())
      return ROPChainStatus::ERR_UNSUPPORTED;

    gadget_type = "and";
    imm = MI->getOperand(2).getImm();
    break;
  }
  case X86::INC32r: {
    gadget_type = "add";
    imm = 1;
    break;
  }
  case X86::DEC32r: {
    gadget_type = "sub";
    imm = 1;
    break;
  }
  default:
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  x86_reg dest_reg = convertToCapstoneReg(MI->getOperand(0).getReg());
  ROPChainBuilder builder(scratchRegs);

  builder.append("init", SCRATCH_1).append(ChainElem::fromImmediate(imm));
  builder.append(gadget_type, dest_reg, SCRATCH_1);
  builder.reorder();
  builder.normalInstrFlag = true;

  return builder.build(state, chain);
}

ROPChainStatus
ROPEngine::handleArithmeticRR(MachineInstr *MI,
                              std::vector<x86_reg> &scratchRegs) {
  // extract operands
  x86_reg dst = convertToCapstoneReg(MI->getOperand(0).getReg());
  x86_reg src1 = convertToCapstoneReg(MI->getOperand(1).getReg());
  x86_reg src2 = convertToCapstoneReg(MI->getOperand(2).getReg());

  if (dst != src1)
    return ROPChainStatus::ERR_UNSUPPORTED;

  const char *gadget_type;

  switch (MI->getOpcode()) {
  case X86::ADD32rr:
    gadget_type = (src1 == src2) ? "add_1" : "add";
    break;
  case X86::SUB32rr:
    gadget_type = (src1 == src2) ? "sub_1" : "sub";
    break;
  case X86::AND32rr:
    gadget_type = (src1 == src2) ? "and_1" : "and";
    break;
  default:
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  ROPChainBuilder builder(scratchRegs);

  builder.append(gadget_type, dst, src2);
  builder.reorder();
  builder.normalInstrFlag = true;

  return builder.build(state, chain);
}

ROPChainStatus
ROPEngine::handleArithmeticRM(MachineInstr *MI,
                              std::vector<x86_reg> &scratchRegs) {
  const char *gadget_type;

  switch (MI->getOpcode()) {
  case X86::ADD32rm:
    gadget_type = "add";
    break;
  case X86::SUB32rm:
    gadget_type = "sub";
    break;
  case X86::AND32rm:
    gadget_type = "and";
    break;
  default:
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  if (MI->getOperand(0).getReg() == 0 || MI->getOperand(2).getReg() == 0)
    return ROPChainStatus::ERR_UNSUPPORTED;

  // skip scaled-index addressing mode since we cannot handle them
  //      xxx     orig_0/1, [orig_2 + scale_3 * orig_4 + disp_5]
  if (MI->getOperand(3).isReg() && MI->getOperand(3).getReg() != 0)
    return ROPChainStatus::ERR_UNSUPPORTED;

  // extract operands
  x86_reg dst = convertToCapstoneReg(MI->getOperand(0).getReg());
  x86_reg src = convertToCapstoneReg(MI->getOperand(2).getReg());

  ChainElem disp_elem;
  if (!convertOperandToChainPushImm(MI->getOperand(5), disp_elem))
    return ROPChainStatus::ERR_UNSUPPORTED;

  ROPChainBuilder builder(scratchRegs);

  builder.append("init", SCRATCH_1).append(disp_elem);
  builder.append("add", SCRATCH_1, src);
  builder.append("load_1", SCRATCH_1);
  builder.append(gadget_type, dst, SCRATCH_1);
  builder.reorder();
  builder.normalInstrFlag = true;

  return builder.build(state, chain);
}

ROPChainStatus ROPEngine::handleXor32RR(MachineInstr *MI,
                                        std::vector<x86_reg> &scratchRegs) {
  // extract operands
  x86_reg dst = convertToCapstoneReg(MI->getOperand(0).getReg());
  x86_reg src1 = convertToCapstoneReg(MI->getOperand(1).getReg());
  x86_reg src2 = convertToCapstoneReg(MI->getOperand(2).getReg());

  // only handle xor eax, eax which is widely used and gadgets are often found
  if (dst != src1 || dst != src2)
    return ROPChainStatus::ERR_UNSUPPORTED;

  ROPChainBuilder builder(scratchRegs);

  builder.append("xor_1", dst);
  builder.reorder();
  builder.normalInstrFlag = true;

  return builder.build(state, chain);
}

ROPChainStatus ROPEngine::handleLea32r(MachineInstr *MI,
                                       std::vector<x86_reg> &scratchRegs) {
  unsigned int op_dst = MI->getOperand(0).getReg();
  unsigned int op_reg1 = MI->getOperand(1).getReg();
  // int64_t op_scale = MI->getOperand(2).getImm();
  unsigned int op_reg2 = MI->getOperand(3).getReg();
  llvm::MachineOperand op_disp = MI->getOperand(4);
  unsigned int op_segment = MI->getOperand(5).getReg();

  // lea op_dst, op_segment:[op_reg1 + op_scale * op_reg2 + op_disp]
  if (op_dst == 0 || op_segment != 0)
    return ROPChainStatus::ERR_UNSUPPORTED;

  // skip scaled-index addressing mode
  if (op_reg2 != 0)
    return ROPChainStatus::ERR_UNSUPPORTED;

  x86_reg dst = convertToCapstoneReg(op_dst);
  ChainElem disp_elem;

  if (!convertOperandToChainPushImm(op_disp, disp_elem))
    return ROPChainStatus::ERR_UNSUPPORTED;

  ROPChainBuilder builder(scratchRegs);

  if (op_reg1 == 0) {
    // lea dst, [disp]
    // -> mov dst, disp
    builder.append("init", dst).append(disp_elem);
  } else {
    // lea dst, [src + disp]
    x86_reg src = convertToCapstoneReg(op_reg1);

    if (src != dst) {
      // -> mov dst, disp; add dst, src
      builder.append("init", dst).append(disp_elem);
      builder.append("add", dst, src);
    } else {
      // -> mov scratch, disp; add dst, scratch
      builder.append("init", SCRATCH_1).append(disp_elem);
      builder.append("add", dst, SCRATCH_1);
    }
  }

  builder.reorder();
  builder.normalInstrFlag = true;

  return builder.build(state, chain);
}

ROPChainStatus ROPEngine::handleMov32rm(MachineInstr *MI,
                                        std::vector<x86_reg> &scratchRegs) {
  // instruction uses a segment register
  if (MI->getOperand(0).getReg() == 0 || MI->getOperand(1).getReg() == 0)
    return ROPChainStatus::ERR_UNSUPPORTED;

  // skip scaled-index addressing mode since we cannot handle them
  //      mov     orig_0, [orig_1 + scale_2 * orig_3 + disp_4]
  if (MI->getOperand(3).isReg() && MI->getOperand(3).getReg() != 0)
    return ROPChainStatus::ERR_UNSUPPORTED;

  // extract operands
  x86_reg dst = convertToCapstoneReg(MI->getOperand(0).getReg());
  x86_reg src = convertToCapstoneReg(MI->getOperand(1).getReg());
  ChainElem disp_elem;

  if (!convertOperandToChainPushImm(MI->getOperand(4), disp_elem))
    return ROPChainStatus::ERR_UNSUPPORTED;

  ROPChainBuilder builder(scratchRegs);

  builder.append("init", SCRATCH_1).append(disp_elem);
  builder.append("add", SCRATCH_1, src);
  builder.append("load_1", SCRATCH_1);
  builder.append("copy", dst, SCRATCH_1);
  builder.reorder();
  builder.normalInstrFlag = true;

  return builder.build(state, chain);
}

ROPChainStatus ROPEngine::handleMov32mr(MachineInstr *MI,
                                        std::vector<x86_reg> &scratchRegs) {
  // instruction uses a segment register
  if (MI->getOperand(0).getReg() == 0 || MI->getOperand(5).getReg() == 0)
    return ROPChainStatus::ERR_UNSUPPORTED;

  // skip scaled-index addressing mode since we cannot handle them
  //      mov     [orig_0 + scale_1 * orig_2 + disp_3], orig_5
  if (MI->getOperand(2).isReg() && MI->getOperand(2).getReg() != 0)
    return ROPChainStatus::ERR_UNSUPPORTED;

  // extract operands
  x86_reg dst = convertToCapstoneReg(MI->getOperand(0).getReg());
  x86_reg src = convertToCapstoneReg(MI->getOperand(5).getReg());
  ChainElem disp_elem;

  if (!convertOperandToChainPushImm(MI->getOperand(3), disp_elem))
    return ROPChainStatus::ERR_UNSUPPORTED;

  if (src == X86_REG_ESP)
    return ROPChainStatus::ERR_UNSUPPORTED;

  if (dst == X86_REG_ESP) {
    if (disp_elem.type != ChainElem::Type::IMM_VALUE || disp_elem.value < 0)
      return ROPChainStatus::ERR_UNSUPPORTED;

    ROPChainBuilder builder(scratchRegs);
    ChainElem esp_elem = ChainElem::createStackPointerPush();

    disp_elem =
        ChainElem::createStackPointerOffset(disp_elem.value, esp_elem.esp_id);
    builder.append("init", SCRATCH_1).append(disp_elem);
    builder.append("init", SCRATCH_2).append(esp_elem);
    builder.append("add", SCRATCH_1, SCRATCH_2);
    builder.append("store", SCRATCH_1, src);
    builder.reorder();
    builder.normalInstrFlag = true;

    return builder.build(state, chain);
  }

  ROPChainBuilder builder(scratchRegs);

  builder.append("init", SCRATCH_1).append(disp_elem);
  builder.append("add", SCRATCH_1, dst);
  builder.append("store", SCRATCH_1, src);
  builder.reorder();
  builder.normalInstrFlag = true;

  return builder.build(state, chain);
}

ROPChainStatus ROPEngine::handleMov32mi(MachineInstr *MI,
                                        std::vector<x86_reg> &scratchRegs) {
  // instruction uses a segment register
  if (MI->getOperand(0).getReg() == 0)
    return ROPChainStatus::ERR_UNSUPPORTED;

  // skip scaled-index addressing mode since we cannot handle them
  //      mov     [orig_0 + scale_1 * orig_2 + disp_3], orig_5
  if (MI->getOperand(2).isReg() && MI->getOperand(2).getReg() != 0)
    return ROPChainStatus::ERR_UNSUPPORTED;

  ChainElem imm_elem;

  if (!convertOperandToChainPushImm(MI->getOperand(5), imm_elem))
    return ROPChainStatus::ERR_UNSUPPORTED;

  // extract operands
  x86_reg dst = convertToCapstoneReg(MI->getOperand(0).getReg());

  ChainElem disp_elem;

  if (!convertOperandToChainPushImm(MI->getOperand(3), disp_elem))
    return ROPChainStatus::ERR_UNSUPPORTED;

  if (dst == X86_REG_ESP) {
    if (disp_elem.type != ChainElem::Type::IMM_VALUE || disp_elem.value < 0)
      return ROPChainStatus::ERR_UNSUPPORTED;

    ROPChainBuilder builder(scratchRegs);
    ChainElem esp_elem = ChainElem::createStackPointerPush();

    disp_elem =
        ChainElem::createStackPointerOffset(disp_elem.value, esp_elem.esp_id);
    builder.append("init", SCRATCH_1).append(disp_elem);
    builder.append("init", SCRATCH_2).append(esp_elem);
    builder.append("add", SCRATCH_1, SCRATCH_2);
    builder.append("init", SCRATCH_2).append(imm_elem);
    builder.append("store", SCRATCH_1, SCRATCH_2);
    builder.reorder();
    builder.normalInstrFlag = true;

    return builder.build(state, chain);
  }

  ROPChainBuilder builder(scratchRegs);

  builder.append("init", SCRATCH_2).append(imm_elem);
  builder.append("init", SCRATCH_1).append(disp_elem);
  builder.append("add", SCRATCH_1, dst);
  builder.append("store", SCRATCH_1, SCRATCH_2);
  builder.reorder();
  builder.normalInstrFlag = true;

  return builder.build(state, chain);
}

ROPChainStatus ROPEngine::handleMov32rr(MachineInstr *MI,
                                        std::vector<x86_reg> &scratchRegs) {
  if (MI->getOperand(0).getReg() == 0 || MI->getOperand(1).getReg() == 0)
    return ROPChainStatus::ERR_UNSUPPORTED;

  // extract operands
  x86_reg dst = convertToCapstoneReg(MI->getOperand(0).getReg());
  x86_reg src = convertToCapstoneReg(MI->getOperand(1).getReg());

  ROPChainBuilder builder(scratchRegs);

  builder.append("copy", dst, src);
  builder.reorder();
  builder.normalInstrFlag = true;

  return builder.build(state, chain);
}

ROPChainStatus ROPEngine::handleCmp32mi(MachineInstr *MI,
                                        std::vector<x86_reg> &scratchRegs) {
  // skip scaled-index addressing mode since we cannot handle them
  //      cmp     [orig_0 + scale_1 * orig_2 + disp_3], orig_5
  if ((MI->getOperand(2).isReg() && MI->getOperand(2).getReg() != 0) ||
      (MI->getOperand(4).isReg() && MI->getOperand(4).getReg() != 0))
    return ROPChainStatus::ERR_UNSUPPORTED;

  // extract operands
  if (MI->getOperand(0).getReg() == 0) // instruction uses a segment register
    return ROPChainStatus::ERR_UNSUPPORTED;

  x86_reg dst = convertToCapstoneReg(MI->getOperand(0).getReg());
  ChainElem imm_elem;

  if (!convertOperandToChainPushImm(MI->getOperand(5), imm_elem))
    return ROPChainStatus::ERR_UNSUPPORTED;

  ChainElem disp_elem;

  if (!convertOperandToChainPushImm(MI->getOperand(3), disp_elem))
    return ROPChainStatus::ERR_UNSUPPORTED;

  ROPChainBuilder builder(scratchRegs);

  builder.append("init", SCRATCH_2).append(imm_elem);
  builder.append("init", SCRATCH_1).append(disp_elem);
  builder.append("add", SCRATCH_1, dst);
  builder.append("load_1", SCRATCH_1);
  builder.append("sub", SCRATCH_1, SCRATCH_2);
  builder.reorder();
  builder.normalInstrFlag = true;

  return builder.build(state, chain);
}

ROPChainStatus ROPEngine::handleCmp32ri(MachineInstr *MI,
                                        std::vector<x86_reg> &scratchRegs) {
  // extract operands
  if (MI->getOperand(0).getReg() == 0)
    return ROPChainStatus::ERR_UNSUPPORTED;

  x86_reg reg = convertToCapstoneReg(MI->getOperand(0).getReg());
  ChainElem imm_elem;

  if (!convertOperandToChainPushImm(MI->getOperand(1), imm_elem))
    return ROPChainStatus::ERR_UNSUPPORTED;

  ROPChainBuilder builder(scratchRegs);

  builder.append("init", SCRATCH_2).append(imm_elem);
  builder.append("copy", SCRATCH_1, reg);
  builder.append("sub", SCRATCH_1, SCRATCH_2);
  builder.reorder();
  builder.normalInstrFlag = true;

  return builder.build(state, chain);
}

ROPChainStatus ROPEngine::handleCmp32rm(MachineInstr *MI,
                                        std::vector<x86_reg> &scratchRegs) {
  if (MI->getOperand(0).getReg() == 0 // instruction uses a segment register
      || MI->getOperand(1).getReg() == 0)
    return ROPChainStatus::ERR_UNSUPPORTED;

  // skip scaled-index addressing mode since we cannot handle them
  //      xxx     orig_0, [orig_1 + scale_2 * orig_3 + disp_4]
  if (MI->getOperand(3).isReg() && MI->getOperand(3).getReg() != 0)
    return ROPChainStatus::ERR_UNSUPPORTED;

  // extract operands
  x86_reg dst = convertToCapstoneReg(MI->getOperand(0).getReg());
  x86_reg src = convertToCapstoneReg(MI->getOperand(1).getReg());
  ChainElem disp_elem;

  if (!convertOperandToChainPushImm(MI->getOperand(4), disp_elem))
    return ROPChainStatus::ERR_UNSUPPORTED;

  ROPChainBuilder builder(scratchRegs);

  builder.append("init", SCRATCH_1).append(disp_elem);
  builder.append("add", SCRATCH_1, src);
  builder.append("load_1", SCRATCH_1);
  builder.append("copy", SCRATCH_2, dst);
  builder.append("sub", SCRATCH_2, SCRATCH_1);
  builder.reorder();
  builder.normalInstrFlag = true;

  return builder.build(state, chain);
}

ROPChainStatus ROPEngine::handleJmp1(MachineInstr *MI,
                                     std::vector<x86_reg> &scratchRegs) {
  if (!MI->getOperand(0).isMBB()) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  chain.emplace_back(ChainElem::fromJmpTarget(MI->getOperand(0).getMBB()));
  chain.hasUnconditionalJump = true;
  chain.successor = &chain.chain.back();

  return ROPChainStatus::OK;
}

ROPChainStatus ROPEngine::handleJcc1(MachineInstr *MI,
                                     std::vector<x86_reg> &scratchRegs) {
  // Jcc1 ROPification strategy:
  //   pop reg1
  //   ...target1...
  //   pop reg2
  //   ...target2...
  //   cmov?? reg1, reg2
  //   (xchg reg2)
  //   jmp reg1  # xchg is not allowed

  if (!MI->getOperand(0).isMBB())
    return ROPChainStatus::ERR_UNSUPPORTED;

  const char *cmov_type;
  bool reverse;

  switch (MI->getOpcode()) {
  case X86::JE_1:
    cmov_type = "cmove";
    reverse = false;
    break;
  case X86::JNE_1:
    cmov_type = "cmove";
    reverse = true;
    break;
  case X86::JB_1:
    cmov_type = "cmovb";
    reverse = false;
    break;
  case X86::JAE_1:
    cmov_type = "cmovb";
    reverse = true;
    break;
  default:
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  ROPChainBuilder builder(scratchRegs);

  builder.append("init", reverse ? SCRATCH_1 : SCRATCH_2)
      .append(ChainElem::fromJmpTarget(MI->getOperand(0).getMBB()));
  builder.append("init", reverse ? SCRATCH_2 : SCRATCH_1)
      .append(ChainElem::createJmpFallthrough());
  builder.append(cmov_type, SCRATCH_1, SCRATCH_2);
  builder.reorder();
  builder.append("jmp", SCRATCH_1);
  builder.conditionalJumpInstrFlag = true;

  return builder.build(state, chain);
}

ROPChainStatus ROPEngine::handleCall(MachineInstr *MI,
                                     std::vector<x86_reg> &scratchRegs) {
  //   pop reg1
  //   [callee]
  //   jmp reg1
  //   [return addr]

  ChainElem callee_elem;
  if (!convertOperandToChainPushImm(MI->getOperand(0), callee_elem))
    return ROPChainStatus::ERR_UNSUPPORTED;

  ROPChainBuilder builder(scratchRegs);

  builder.append("init", SCRATCH_1).append(callee_elem);
  builder.reorder();
  builder.append("jmp", SCRATCH_1);
  builder.append(ChainElem::createJmpFallthrough());
  builder.jumpInstrFlag = true;

  return builder.build(state, chain);
}

ROPChainStatus ROPEngine::handleCallReg(MachineInstr *MI,
                                        std::vector<x86_reg> &scratchRegs) {
  //   jmp reg
  //   [return addr]

  if (!MI->getOperand(0).isReg() || MI->getOperand(0).getReg() == 0)
    return ROPChainStatus::ERR_UNSUPPORTED;

  x86_reg reg = convertToCapstoneReg(MI->getOperand(0).getReg());
  ROPChainBuilder builder(scratchRegs);

  builder.append("jmp", reg);
  builder.append(ChainElem::createJmpFallthrough());
  builder.jumpInstrFlag = true;

  return builder.build(state, chain);
}

ROPChainStatus ROPEngine::ropify(MachineInstr &MI,
                                 std::vector<x86_reg> &scratchRegs,
                                 bool shouldFlagSaved, ROPChain &resultChain) {
  if (MI.getOpcode() != X86::CALLpcrel32 && MI.getOpcode() != X86::CALL32r &&
      MI.getOpcode() != X86::MOV32mr && MI.getOpcode() != X86::MOV32mi) {
    // if ESP is one of the operands of MI -> abort
    for (unsigned int i = 0; i < MI.getNumOperands(); i++) {
      if (MI.getOperand(i).isReg() && MI.getOperand(i).getReg() == X86::ESP)
        return ROPChainStatus::ERR_UNSUPPORTED_STACKPOINTER;
    }
  }

  DEBUG_WITH_TYPE(LIVENESS_ANALYSIS,
                  dbg_fmt("[LivenessAnalysis] Available scratch registers:\t"));
  for (auto &reg : scratchRegs) {
    DEBUG_WITH_TYPE(LIVENESS_ANALYSIS, dbg_fmt("{} ", reg));
    (void)reg; // suppress unused warning
  }
  DEBUG_WITH_TYPE(LIVENESS_ANALYSIS, dbg_fmt("\n"));

  ROPChainStatus status;
  FlagSaveMode flagSave;

  switch (MI.getOpcode()) {
  case X86::ADD32ri8:
  case X86::ADD32ri:
  case X86::SUB32ri8:
  case X86::SUB32ri:
  case X86::AND32ri8:
  case X86::AND32ri:
  case X86::INC32r:
  case X86::DEC32r: {
    status = handleArithmeticRI(&MI, scratchRegs);
    flagSave = FlagSaveMode::SAVE_BEFORE_EXEC;
    break;
  }
  case X86::ADD32rr:
  case X86::SUB32rr:
  case X86::AND32rr:
    status = handleArithmeticRR(&MI, scratchRegs);
    flagSave = FlagSaveMode::SAVE_BEFORE_EXEC;
    break;
  case X86::ADD32rm:
  case X86::SUB32rm:
  case X86::AND32rm:
    status = handleArithmeticRM(&MI, scratchRegs);
    flagSave = FlagSaveMode::SAVE_BEFORE_EXEC;
    break;
  case X86::XOR32rr:
    status = handleXor32RR(&MI, scratchRegs);
    flagSave = FlagSaveMode::SAVE_BEFORE_EXEC;
    break;
  case X86::CMP32mi:
  case X86::CMP32mi8:
    status = handleCmp32mi(&MI, scratchRegs);
    flagSave = FlagSaveMode::SAVE_BEFORE_EXEC;
    break;
  case X86::CMP32ri:
  case X86::CMP32ri8:
    status = handleCmp32ri(&MI, scratchRegs);
    flagSave = FlagSaveMode::SAVE_BEFORE_EXEC;
    break;
  case X86::CMP32rm:
    status = handleCmp32rm(&MI, scratchRegs);
    flagSave = FlagSaveMode::SAVE_BEFORE_EXEC;
    break;
  case X86::LEA32r:
    status = handleLea32r(&MI, scratchRegs);
    flagSave = FlagSaveMode::SAVE_AFTER_EXEC;
    break;
  case X86::MOV32rm: {
    status = handleMov32rm(&MI, scratchRegs);
    flagSave = FlagSaveMode::SAVE_AFTER_EXEC;
    break;
  }
  case X86::MOV32mr: {
    status = handleMov32mr(&MI, scratchRegs);
    flagSave = FlagSaveMode::SAVE_AFTER_EXEC;
    break;
  }
  case X86::MOV32mi:
    status = handleMov32mi(&MI, scratchRegs);
    flagSave = FlagSaveMode::SAVE_AFTER_EXEC;
    break;
  case X86::MOV32rr:
    status = handleMov32rr(&MI, scratchRegs);
    flagSave = FlagSaveMode::SAVE_AFTER_EXEC;
    break;
  case X86::JMP_1:
    status = handleJmp1(&MI, scratchRegs);
    flagSave = FlagSaveMode::SAVE_BEFORE_EXEC;
    break;
  case X86::JE_1:
  case X86::JNE_1:
  case X86::JB_1:
  case X86::JAE_1:
    status = handleJcc1(&MI, scratchRegs);
    flagSave = FlagSaveMode::SAVE_BEFORE_EXEC;
    break;
  case X86::CALLpcrel32:
    status = handleCall(&MI, scratchRegs);
    flagSave = FlagSaveMode::SAVE_BEFORE_EXEC;
    break;
  case X86::CALL32r:
    status = handleCallReg(&MI, scratchRegs);
    flagSave = FlagSaveMode::SAVE_BEFORE_EXEC;
    break;
  default:
    return ROPChainStatus::ERR_NOT_IMPLEMENTED;
  }

  if (status == ROPChainStatus::OK) {
    chain.flagSave = shouldFlagSaved ? flagSave : FlagSaveMode::NOT_SAVED;
    chain.removeDuplicates();
    resultChain = std::move(chain);
  }

  return status;
}

void ROPChain::removeDuplicates() {
  bool duplicates;

  do {
    duplicates = false;

    if (chain.size() < 2)
      break;

    for (auto it = chain.begin() + 1; it != chain.end();) {
      // equal microgadgets, but only if they're both XCHG instructions
      if (*it == *(it - 1) && it->type == ChainElem::Type::GADGET &&
          it->microgadget->getID() == X86_INS_XCHG) {
        it = chain.erase(it - 1);
        it = chain.erase(it);
        duplicates = true;
      }

      if (it != chain.end())
        ++it;
      else
        break;
    }
  } while (duplicates);
}

void generateChainLabels(string &chainLabel, string &resumeLabel,
                         StringRef funcName, int chainID) {
  chainLabel = fmt::format("{}_chain_{}", funcName.str(), chainID);
  resumeLabel = fmt::format("resume_{}", chainLabel);

  // replacing $ with _
  std::replace(chainLabel.begin(), chainLabel.end(), '$', '_');
}