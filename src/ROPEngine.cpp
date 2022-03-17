#include "ROPEngine.h"
#include "BinAutopsy.h"
#include "Debug.h"
#include "Microgadget.h"
#include "Symbol.h"
#include "X86.h"
#include "X86InstrBuilder.h"
#include "X86TargetMachine.h"
#include "llvm/CodeGen/MachineFunction.h"

using std::string;
using namespace llvm;

#if LLVM_VERSION_MAJOR < 10
using Register = unsigned int;
#endif

namespace ropf {

class ROPChainBuilder {
  struct ReorderTag {};

  struct VirtualInstr {
    GadgetType type;
    int        reg1, reg2;
    ChainElem  immediate;

    VirtualInstr(GadgetType type, int reg1, int reg2)
        : type(type), reg1(reg1), reg2(reg2) {}

    VirtualInstr(const ChainElem &immediate)
        : type(GadgetType::UNDEFINED), immediate(immediate) {}

    VirtualInstr(ReorderTag) : type((GadgetType)-1) {}

    bool isReorder() const { return type == (GadgetType)-1; }
    bool isImmediate() const { return type == GadgetType::UNDEFINED; }
  };

  const BinaryAutopsy             &BA;
  const std::vector<unsigned int> &scratchRegs;
  std::vector<VirtualInstr>        vchain;
  size_t                           numScratchRegs;

public:
  bool normalInstrFlag, jumpInstrFlag, conditionalJumpInstrFlag;

  ROPChainBuilder &
  append(GadgetType type, int reg1, int reg2 = X86::NoRegister) {
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

  explicit ROPChainBuilder(const BinaryAutopsy             &BA,
                           const std::vector<unsigned int> &scratchRegs)
      : BA(BA), scratchRegs(scratchRegs), vchain(), numScratchRegs(0),
        normalInstrFlag(false), jumpInstrFlag(false),
        conditionalJumpInstrFlag(false) {}

  ROPChainStatus build(XchgState &state, ROPChain &result) const {
    std::vector<int> regList;

    if (numScratchRegs > scratchRegs.size()) {
      return ROPChainStatus::ERR_NO_REGISTER_AVAILABLE;
    }

    regList.reserve(numScratchRegs);

    return buildAux(state, result, regList);
  }

private:
  ROPChainStatus buildAux(XchgState        &state,
                          ROPChain         &result,
                          std::vector<int> &regList) const {
    if (regList.size() < numScratchRegs) {
      for (unsigned int r : scratchRegs) {
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
    XchgState             state0(state);

    for (const VirtualInstr &vi : vchain) {
      if (vi.isReorder()) {
        ROPChain chain = BA.undoXchgs(state0);
        chains.push_back(chain);
      } else if (vi.isImmediate()) {
        if (chains.empty()) {
          chains.emplace_back();
        }

        chains.back().emplace_back(vi.immediate);
      } else {
        int reg1 = vi.reg1 >= 0 ? vi.reg1 : regList[-vi.reg1 - 1];
        int reg2 = vi.reg2 >= 0 ? vi.reg2 : regList[-vi.reg2 - 1];

        if (!isNoop(vi.type, reg1, reg2)) {
          ROPChain chain = BA.findGadgetPrimitive(state0, vi.type, reg1, reg2);

          if (!chain.valid()) {
            return ROPChainStatus::ERR_NO_GADGETS_AVAILABLE;
          }

          chains.push_back(chain);
        }
      }
    }

    for (const ROPChain &chain : chains) {
      result.append(chain);
    }

    state = state0;

    if (normalInstrFlag) {
      result.hasNormalInstr = true;
    }

    if (jumpInstrFlag) {
      result.hasUnconditionalJump = true;
    }

    if (conditionalJumpInstrFlag) {
      result.hasConditionalJump = true;
    }

    return ROPChainStatus::OK;
  }

  static bool isNoop(GadgetType type, int reg1, int reg2) {
    if (type == GadgetType::COPY && reg1 == reg2) {
      return true;
    }

    return false;
  }
};

namespace {
const int SCRATCH_1 = -1;
const int SCRATCH_2 = -2;
} // namespace

// ------------------------------------------------------------------------
// ROP Chain
// ------------------------------------------------------------------------

bool ROPChain::canMerge(const ROPChain &other) {
  if (!valid()) {
    return true;
  }

  // unconditional jump will terminate rop chain
  if (hasUnconditionalJump) {
    return false;
  }

  // conditional jump will terminate rop chain,
  // except for following unconditional jump
  if (hasConditionalJump && other.hasNormalInstr) {
    return false;
  }

  if (hasConditionalJump && other.hasConditionalJump) {
    return false;
  }

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
  if (!callee) {
    callee = other.callee;
  }

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
        *it                  = *successor;
        conditionalJumpFound = true;
      } else if (conditionalJumpFound && *successor == *it) {
        it = chain.erase(it);
        continue;
      }
      ++it;
    }
  }
}

ROPEngine::ROPEngine(const BinaryAutopsy &BA) : BA(BA) {}

bool ROPEngine::convertOperandToChainPushImm(const MachineOperand &operand,
                                             ChainElem            &result) {
  if (operand.isImm()) {
    result = ChainElem::fromImmediate(operand.getImm());
    return true;
  }

  if (operand.isGlobal()) {
    result = ChainElem::fromGlobal(operand.getGlobal(), operand.getOffset());
    return true;
  }

  return false;
}

ROPChainStatus
ROPEngine::handleArithmeticRI(MachineInstr              *MI,
                              std::vector<unsigned int> &scratchRegs) {
  GadgetType gadget_type;
  int        imm;

  switch (MI->getOpcode()) {
  case X86::ADD32ri8:
  case X86::ADD32ri: {
    if (!MI->getOperand(2).isImm()) {
      return ROPChainStatus::ERR_UNSUPPORTED;
    }

    gadget_type = GadgetType::ADD;
    imm         = MI->getOperand(2).getImm();
    break;
  }
  case X86::SUB32ri8:
  case X86::SUB32ri: {
    if (!MI->getOperand(2).isImm()) {
      return ROPChainStatus::ERR_UNSUPPORTED;
    }

    gadget_type = GadgetType::SUB;
    imm         = MI->getOperand(2).getImm();
    break;
  }
  case X86::AND32ri8:
  case X86::AND32ri: {
    if (!MI->getOperand(2).isImm()) {
      return ROPChainStatus::ERR_UNSUPPORTED;
    }

    gadget_type = GadgetType::AND;
    imm         = MI->getOperand(2).getImm();
    break;
  }
  case X86::INC32r: {
    gadget_type = GadgetType::ADD;
    imm         = 1;
    break;
  }
  case X86::DEC32r: {
    gadget_type = GadgetType::SUB;
    imm         = 1;
    break;
  }
  default: return ROPChainStatus::ERR_UNSUPPORTED;
  }

  Register        dest_reg = MI->getOperand(0).getReg();
  ROPChainBuilder builder(BA, scratchRegs);

  builder.append(GadgetType::MOV, SCRATCH_1)
      .append(ChainElem::fromImmediate(imm));
  builder.append(gadget_type, dest_reg, SCRATCH_1);
  builder.reorder();
  builder.normalInstrFlag = true;

  return builder.build(state, chain);
}

ROPChainStatus
ROPEngine::handleArithmeticRR(MachineInstr              *MI,
                              std::vector<unsigned int> &scratchRegs) {
  // extract operands
  Register dst  = MI->getOperand(0).getReg();
  Register src1 = MI->getOperand(1).getReg();
  Register src2 = MI->getOperand(2).getReg();

  if (dst != src1) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  GadgetType gadget_type;

  switch (MI->getOpcode()) {
  case X86::ADD32rr:
  case X86::ADD32rr_DB:
    gadget_type = (src1 == src2) ? GadgetType::ADD_1 : GadgetType::ADD;
    break;
  case X86::SUB32rr:
    gadget_type = (src1 == src2) ? GadgetType::SUB_1 : GadgetType::SUB;
    break;
  case X86::AND32rr:
    gadget_type = (src1 == src2) ? GadgetType::AND_1 : GadgetType::AND;
    break;
  default: return ROPChainStatus::ERR_UNSUPPORTED;
  }

  ROPChainBuilder builder(BA, scratchRegs);

  builder.append(gadget_type, dst, src2);
  builder.reorder();
  builder.normalInstrFlag = true;

  return builder.build(state, chain);
}

ROPChainStatus
ROPEngine::handleArithmeticRM(MachineInstr              *MI,
                              std::vector<unsigned int> &scratchRegs) {
  GadgetType gadget_type;

  switch (MI->getOpcode()) {
  case X86::ADD32rm: gadget_type = GadgetType::ADD; break;
  case X86::SUB32rm: gadget_type = GadgetType::SUB; break;
  case X86::AND32rm: gadget_type = GadgetType::AND; break;
  default: return ROPChainStatus::ERR_UNSUPPORTED;
  }

  if (MI->getOperand(0).getReg() == X86::NoRegister) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  // skip scaled-index addressing mode since we cannot handle them
  //      xxx     orig_0/1, [orig_2 + scale_3 * orig_4 + disp_5]
  if (MI->getOperand(4).isReg() &&
      MI->getOperand(4).getReg() != X86::NoRegister) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  // extract operands
  Register dst = MI->getOperand(0).getReg();
  Register src = MI->getOperand(2).getReg(); // may be NoRegister

  ChainElem disp_elem;
  if (!convertOperandToChainPushImm(MI->getOperand(5), disp_elem)) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  ROPChainBuilder builder(BA, scratchRegs);

  builder.append(GadgetType::MOV, SCRATCH_1).append(disp_elem);
  if (src != X86::NoRegister) {
    builder.append(GadgetType::ADD, SCRATCH_1, src);
  }
  builder.append(GadgetType::LOAD_1, SCRATCH_1);
  builder.append(gadget_type, dst, SCRATCH_1);
  builder.reorder();
  builder.normalInstrFlag = true;

  return builder.build(state, chain);
}

ROPChainStatus
ROPEngine::handleXor32RR(MachineInstr              *MI,
                         std::vector<unsigned int> &scratchRegs) {
  // extract operands
  Register dst  = MI->getOperand(0).getReg();
  Register src1 = MI->getOperand(1).getReg();
  Register src2 = MI->getOperand(2).getReg();

  // only handle xor eax, eax which is widely used and gadgets are often found
  if (dst != src1 || dst != src2) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  ROPChainBuilder builder(BA, scratchRegs);

  builder.append(GadgetType::XOR_1, dst);
  builder.reorder();
  builder.normalInstrFlag = true;

  return builder.build(state, chain);
}

ROPChainStatus ROPEngine::handleLea32r(MachineInstr              *MI,
                                       std::vector<unsigned int> &scratchRegs) {
  Register                    dst        = MI->getOperand(0).getReg();
  Register                    src        = MI->getOperand(1).getReg();
  // int64_t op_scale = MI->getOperand(2).getImm();
  Register                    indexReg   = MI->getOperand(3).getReg();
  const llvm::MachineOperand &op_disp    = MI->getOperand(4);
  Register                    segmentReg = MI->getOperand(5).getReg();

  // lea op_dst, op_segment:[op_reg1 + op_scale * op_reg2 + op_disp]
  // skip scaled-index addressing mode
  if (dst == X86::NoRegister || segmentReg != X86::NoRegister ||
      indexReg != X86::NoRegister) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  ChainElem disp_elem;

  if (!convertOperandToChainPushImm(op_disp, disp_elem)) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  ROPChainBuilder builder(BA, scratchRegs);

  if (src == X86::NoRegister) {
    // lea dst, [disp]
    // -> mov dst, disp
    builder.append(GadgetType::MOV, dst).append(disp_elem);
  } else {
    // lea dst, [src + disp]

    if (src != dst) {
      // -> mov dst, disp; add dst, src
      builder.append(GadgetType::MOV, dst).append(disp_elem);
      builder.append(GadgetType::ADD, dst, src);
    } else {
      // -> mov scratch, disp; add dst, scratch
      builder.append(GadgetType::MOV, SCRATCH_1).append(disp_elem);
      builder.append(GadgetType::ADD, dst, SCRATCH_1);
    }
  }

  builder.reorder();
  builder.normalInstrFlag = true;

  return builder.build(state, chain);
}

ROPChainStatus
ROPEngine::handleMov32rm(MachineInstr              *MI,
                         std::vector<unsigned int> &scratchRegs) {
  if (MI->getOperand(0).getReg() == X86::NoRegister) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  // skip scaled-index addressing mode since we cannot handle them
  //      mov     orig_0, [orig_1 + scale_2 * orig_3 + disp_4]
  if (MI->getOperand(3).isReg() &&
      MI->getOperand(3).getReg() != X86::NoRegister) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }
  // instruction uses a segment register
  if (MI->getOperand(5).isReg() &&
      MI->getOperand(5).getReg() != X86::NoRegister) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  // extract operands
  Register  dst = MI->getOperand(0).getReg();
  Register  src = MI->getOperand(1).getReg(); // may be NoRegister
  ChainElem disp_elem;

  if (!convertOperandToChainPushImm(MI->getOperand(4), disp_elem)) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  ROPChainBuilder builder(BA, scratchRegs);

  builder.append(GadgetType::MOV, SCRATCH_1).append(disp_elem);
  if (src != X86::NoRegister) {
    builder.append(GadgetType::ADD, SCRATCH_1, src);
  }
  builder.append(GadgetType::LOAD_1, SCRATCH_1);
  builder.append(GadgetType::COPY, dst, SCRATCH_1);
  builder.reorder();
  builder.normalInstrFlag = true;

  return builder.build(state, chain);
}

ROPChainStatus
ROPEngine::handleMov32mr(MachineInstr              *MI,
                         std::vector<unsigned int> &scratchRegs) {
  if (MI->getOperand(5).getReg() == X86::NoRegister) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  // skip scaled-index addressing mode since we cannot handle them
  //      mov     [orig_0 + scale_1 * orig_2 + disp_3], orig_5
  if (MI->getOperand(2).isReg() &&
      MI->getOperand(2).getReg() != X86::NoRegister) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }
  // instruction uses a segment register
  if (MI->getOperand(4).isReg() &&
      MI->getOperand(4).getReg() != X86::NoRegister) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  // extract operands
  Register  dst = MI->getOperand(0).getReg(); // may be NoRegister
  Register  src = MI->getOperand(5).getReg();
  ChainElem disp_elem;

  if (!convertOperandToChainPushImm(MI->getOperand(3), disp_elem)) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  if (src == X86::ESP) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  if (dst == X86::ESP) {
    if (disp_elem.type != ChainElem::Type::IMM_VALUE || disp_elem.value < 0) {
      return ROPChainStatus::ERR_UNSUPPORTED;
    }

    ROPChainBuilder builder(BA, scratchRegs);
    ChainElem       esp_elem = ChainElem::createStackPointerPush();

    disp_elem =
        ChainElem::createStackPointerOffset(disp_elem.value, esp_elem.esp_id);
    builder.append(GadgetType::MOV, SCRATCH_1).append(disp_elem);
    builder.append(GadgetType::MOV, SCRATCH_2).append(esp_elem);
    builder.append(GadgetType::ADD, SCRATCH_1, SCRATCH_2);
    builder.append(GadgetType::STORE, SCRATCH_1, src);
    builder.reorder();
    builder.normalInstrFlag = true;

    return builder.build(state, chain);
  }

  ROPChainBuilder builder(BA, scratchRegs);

  builder.append(GadgetType::MOV, SCRATCH_1).append(disp_elem);
  if (dst != X86::NoRegister) {
    builder.append(GadgetType::ADD, SCRATCH_1, dst);
  }
  builder.append(GadgetType::STORE, SCRATCH_1, src);
  builder.reorder();
  builder.normalInstrFlag = true;

  return builder.build(state, chain);
}

ROPChainStatus
ROPEngine::handleMov32mi(MachineInstr              *MI,
                         std::vector<unsigned int> &scratchRegs) {
  // skip scaled-index addressing mode since we cannot handle them
  //      mov     [orig_0 + scale_1 * orig_2 + disp_3], orig_5
  if (MI->getOperand(2).isReg() &&
      MI->getOperand(2).getReg() != X86::NoRegister) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }
  // instruction uses a segment register
  if (MI->getOperand(4).isReg() &&
      MI->getOperand(4).getReg() != X86::NoRegister) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  ChainElem imm_elem;

  if (!convertOperandToChainPushImm(MI->getOperand(5), imm_elem)) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  // extract operands
  Register dst = MI->getOperand(0).getReg(); // may be NoRegister

  ChainElem disp_elem;

  if (!convertOperandToChainPushImm(MI->getOperand(3), disp_elem)) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  if (dst == X86::ESP) {
    if (disp_elem.type != ChainElem::Type::IMM_VALUE || disp_elem.value < 0) {
      return ROPChainStatus::ERR_UNSUPPORTED;
    }

    ROPChainBuilder builder(BA, scratchRegs);
    ChainElem       esp_elem = ChainElem::createStackPointerPush();

    disp_elem =
        ChainElem::createStackPointerOffset(disp_elem.value, esp_elem.esp_id);
    builder.append(GadgetType::MOV, SCRATCH_1).append(disp_elem);
    builder.append(GadgetType::MOV, SCRATCH_2).append(esp_elem);
    builder.append(GadgetType::ADD, SCRATCH_1, SCRATCH_2);
    builder.append(GadgetType::MOV, SCRATCH_2).append(imm_elem);
    builder.append(GadgetType::STORE, SCRATCH_1, SCRATCH_2);
    builder.reorder();
    builder.normalInstrFlag = true;

    return builder.build(state, chain);
  }

  ROPChainBuilder builder(BA, scratchRegs);

  builder.append(GadgetType::MOV, SCRATCH_2).append(imm_elem);
  builder.append(GadgetType::MOV, SCRATCH_1).append(disp_elem);
  if (dst != X86::NoRegister) {
    builder.append(GadgetType::ADD, SCRATCH_1, dst);
  }
  builder.append(GadgetType::STORE, SCRATCH_1, SCRATCH_2);
  builder.reorder();
  builder.normalInstrFlag = true;

  return builder.build(state, chain);
}

ROPChainStatus
ROPEngine::handleMov32rr(MachineInstr              *MI,
                         std::vector<unsigned int> &scratchRegs) {
  if (MI->getOperand(0).getReg() == 0 || MI->getOperand(1).getReg() == 0) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  // extract operands
  Register dst = MI->getOperand(0).getReg();
  Register src = MI->getOperand(1).getReg();

  ROPChainBuilder builder(BA, scratchRegs);

  builder.append(GadgetType::COPY, dst, src);
  builder.reorder();
  builder.normalInstrFlag = true;

  return builder.build(state, chain);
}

ROPChainStatus
ROPEngine::handleMov32ri(MachineInstr              *MI,
                         std::vector<unsigned int> &scratchRegs) {
  if (MI->getOperand(0).getReg() == 0 || MI->getOperand(1).getReg() == 0) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  // extract operands
  Register  dst = MI->getOperand(0).getReg();
  ChainElem imm_elem;

  if (!convertOperandToChainPushImm(MI->getOperand(1), imm_elem)) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  ROPChainBuilder builder(BA, scratchRegs);

  builder.append(GadgetType::MOV, dst).append(imm_elem);
  builder.reorder();
  builder.normalInstrFlag = true;

  return builder.build(state, chain);
}

ROPChainStatus
ROPEngine::handleCmp32mi(MachineInstr              *MI,
                         std::vector<unsigned int> &scratchRegs) {
  // skip scaled-index addressing mode since we cannot handle them
  //      cmp     [orig_0 + scale_1 * orig_2 + disp_3], orig_5
  if ((MI->getOperand(2).isReg() &&
       MI->getOperand(2).getReg() != X86::NoRegister) ||
      (MI->getOperand(4).isReg() &&
       MI->getOperand(4).getReg() != X86::NoRegister)) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  // extract operands
  Register  dst = MI->getOperand(0).getReg(); // may be NoRegister
  ChainElem imm_elem;

  if (!convertOperandToChainPushImm(MI->getOperand(5), imm_elem)) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  ChainElem disp_elem;

  if (!convertOperandToChainPushImm(MI->getOperand(3), disp_elem)) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  ROPChainBuilder builder(BA, scratchRegs);

  builder.append(GadgetType::MOV, SCRATCH_2).append(imm_elem);
  builder.append(GadgetType::MOV, SCRATCH_1).append(disp_elem);
  if (dst != X86::NoRegister) {
    builder.append(GadgetType::ADD, SCRATCH_1, dst);
  }
  builder.append(GadgetType::LOAD_1, SCRATCH_1);
  builder.append(GadgetType::SUB, SCRATCH_1, SCRATCH_2);
  builder.reorder();
  builder.normalInstrFlag = true;

  return builder.build(state, chain);
}

ROPChainStatus
ROPEngine::handleCmp32rr(MachineInstr              *MI,
                         std::vector<unsigned int> &scratchRegs) {
  // extract operands
  if (MI->getOperand(0).getReg() == 0) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  Register reg1 = MI->getOperand(0).getReg();
  Register reg2 = MI->getOperand(1).getReg();

  ROPChainBuilder builder(BA, scratchRegs);

  builder.append(GadgetType::COPY, SCRATCH_1, reg1);
  builder.append(GadgetType::SUB, SCRATCH_1, reg2);
  builder.reorder();
  builder.normalInstrFlag = true;

  return builder.build(state, chain);
}

ROPChainStatus
ROPEngine::handleCmp32ri(MachineInstr              *MI,
                         std::vector<unsigned int> &scratchRegs) {
  // extract operands
  if (MI->getOperand(0).getReg() == 0) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  Register  reg = MI->getOperand(0).getReg();
  ChainElem imm_elem;

  if (!convertOperandToChainPushImm(MI->getOperand(1), imm_elem)) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  ROPChainBuilder builder(BA, scratchRegs);

  builder.append(GadgetType::MOV, SCRATCH_2).append(imm_elem);
  builder.append(GadgetType::COPY, SCRATCH_1, reg);
  builder.append(GadgetType::SUB, SCRATCH_1, SCRATCH_2);
  builder.reorder();
  builder.normalInstrFlag = true;

  return builder.build(state, chain);
}

ROPChainStatus
ROPEngine::handleCmp32rm(MachineInstr              *MI,
                         std::vector<unsigned int> &scratchRegs) {
  if (MI->getOperand(0).getReg() == X86::NoRegister) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  // skip scaled-index addressing mode since we cannot handle them
  //      xxx     orig_0, [orig_1 + scale_2 * orig_3 + disp_4]
  if ((MI->getOperand(3).isReg() &&
       MI->getOperand(3).getReg() != X86::NoRegister) ||
      (MI->getOperand(5).isReg() &&
       MI->getOperand(5).getReg() != X86::NoRegister)) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  // extract operands
  Register  dst = MI->getOperand(0).getReg();
  Register  src = MI->getOperand(1).getReg(); // may be NoRegister
  ChainElem disp_elem;

  if (!convertOperandToChainPushImm(MI->getOperand(4), disp_elem)) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  ROPChainBuilder builder(BA, scratchRegs);

  builder.append(GadgetType::MOV, SCRATCH_1).append(disp_elem);
  if (src != X86::NoRegister) {
    builder.append(GadgetType::ADD, SCRATCH_1, src);
  }
  builder.append(GadgetType::LOAD_1, SCRATCH_1);
  builder.append(GadgetType::COPY, SCRATCH_2, dst);
  builder.append(GadgetType::SUB, SCRATCH_2, SCRATCH_1);
  builder.reorder();
  builder.normalInstrFlag = true;

  return builder.build(state, chain);
}

ROPChainStatus ROPEngine::handleJmp1(MachineInstr              *MI,
                                     std::vector<unsigned int> &scratchRegs) {
  if (!MI->getOperand(0).isMBB()) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  chain.emplace_back(ChainElem::fromJmpTarget(MI->getOperand(0).getMBB()));
  chain.hasUnconditionalJump = true;
  chain.successor            = &chain.chain.back();

  return ROPChainStatus::OK;
}

ROPChainStatus ROPEngine::handleJcc1(MachineInstr              *MI,
                                     std::vector<unsigned int> &scratchRegs) {
  // Jcc1 ROPification strategy:
  //   pop reg1
  //   ...target1...
  //   pop reg2
  //   ...target2...
  //   cmov?? reg1, reg2
  //   (xchg reg2)
  //   jmp reg1  # xchg is not allowed

  if (!MI->getOperand(0).isMBB()) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  GadgetType cmov_type;
  bool       reverse;

#if LLVM_VERSION_MAJOR >= 9
  switch (MI->getOperand(1).getImm()) {
  case X86::COND_E:
    cmov_type = GadgetType::CMOVE;
    reverse   = false;
    break;
  case X86::COND_NE:
    cmov_type = GadgetType::CMOVE;
    reverse   = true;
    break;
  case X86::COND_B:
    cmov_type = GadgetType::CMOVB;
    reverse   = false;
    break;
  case X86::COND_AE:
    cmov_type = GadgetType::CMOVB;
    reverse   = true;
    break;
  default: return ROPChainStatus::ERR_UNSUPPORTED;
  }
#else
  switch (MI->getOpcode()) {
  case X86::JE_1:
    cmov_type = GadgetType::CMOVE;
    reverse   = false;
    break;
  case X86::JNE_1:
    cmov_type = GadgetType::CMOVE;
    reverse   = true;
    break;
  case X86::JB_1:
    cmov_type = GadgetType::CMOVB;
    reverse   = false;
    break;
  case X86::JAE_1:
    cmov_type = GadgetType::CMOVB;
    reverse   = true;
    break;
  default: return ROPChainStatus::ERR_UNSUPPORTED;
  }
#endif

  ROPChainBuilder builder(BA, scratchRegs);

  builder.append(GadgetType::MOV, reverse ? SCRATCH_1 : SCRATCH_2)
      .append(ChainElem::fromJmpTarget(MI->getOperand(0).getMBB()));
  builder.append(GadgetType::MOV, reverse ? SCRATCH_2 : SCRATCH_1)
      .append(ChainElem::createJmpFallthrough());
  builder.append(cmov_type, SCRATCH_1, SCRATCH_2);
  builder.reorder();
  builder.append(GadgetType::JMP, SCRATCH_1);
  builder.conditionalJumpInstrFlag = true;

  return builder.build(state, chain);
}

ROPChainStatus ROPEngine::handleCall(MachineInstr              *MI,
                                     std::vector<unsigned int> &scratchRegs) {
  //   pop reg1
  //   [callee]
  //   jmp reg1
  //   [return addr]

  ChainElem callee_elem;
  if (!convertOperandToChainPushImm(MI->getOperand(0), callee_elem)) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  ROPChainBuilder builder(BA, scratchRegs);

  builder.append(callee_elem);
  builder.append(ChainElem::createJmpFallthrough());
  builder.jumpInstrFlag = true;

  ROPChainStatus rv = builder.build(state, chain);
  if (rv == ROPChainStatus::OK &&
      callee_elem.type == ChainElem::Type::IMM_GLOBAL) {
    chain.callee = callee_elem.global;
  }
  return rv;
}

ROPChainStatus
ROPEngine::handleCallReg(MachineInstr              *MI,
                         std::vector<unsigned int> &scratchRegs) {
  //   jmp reg
  //   [return addr]

  if (!MI->getOperand(0).isReg() || MI->getOperand(0).getReg() == 0) {
    return ROPChainStatus::ERR_UNSUPPORTED;
  }

  Register        reg = MI->getOperand(0).getReg();
  ROPChainBuilder builder(BA, scratchRegs);

  builder.append(GadgetType::JMP, reg);
  builder.append(ChainElem::createJmpFallthrough());
  builder.jumpInstrFlag = true;

  return builder.build(state, chain);
}

ROPChainStatus ROPEngine::ropify(MachineInstr              &MI,
                                 std::vector<unsigned int> &scratchRegs,
                                 bool                       shouldFlagSaved,
                                 ROPChain                  &resultChain) {
  if (MI.getOpcode() != X86::CALLpcrel32 && MI.getOpcode() != X86::CALL32r &&
      MI.getOpcode() != X86::MOV32mr && MI.getOpcode() != X86::MOV32mi) {
    // if ESP is one of the operands of MI -> abort
    for (unsigned int i = 0; i < MI.getNumOperands(); i++) {
      if (MI.getOperand(i).isReg() && MI.getOperand(i).getReg() == X86::ESP) {
        return ROPChainStatus::ERR_UNSUPPORTED_STACKPOINTER;
      }
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
  FlagSaveMode   flagSave;

  switch (MI.getOpcode()) {
  case X86::ADD32ri8:
  case X86::ADD32ri:
  case X86::SUB32ri8:
  case X86::SUB32ri:
  case X86::AND32ri8:
  case X86::AND32ri:
  case X86::INC32r:
  case X86::DEC32r: {
    status   = handleArithmeticRI(&MI, scratchRegs);
    flagSave = FlagSaveMode::SAVE_BEFORE_EXEC;
    break;
  }
  case X86::ADD32rr:
  case X86::SUB32rr:
  case X86::AND32rr:
  case X86::ADD32rr_DB:
    status   = handleArithmeticRR(&MI, scratchRegs);
    flagSave = FlagSaveMode::SAVE_BEFORE_EXEC;
    break;
  case X86::ADD32rm:
  case X86::SUB32rm:
  case X86::AND32rm:
    status   = handleArithmeticRM(&MI, scratchRegs);
    flagSave = FlagSaveMode::SAVE_BEFORE_EXEC;
    break;
  case X86::XOR32rr:
    status   = handleXor32RR(&MI, scratchRegs);
    flagSave = FlagSaveMode::SAVE_BEFORE_EXEC;
    break;
  case X86::CMP32mi:
  case X86::CMP32mi8:
    status   = handleCmp32mi(&MI, scratchRegs);
    flagSave = FlagSaveMode::SAVE_BEFORE_EXEC;
    break;
  case X86::CMP32rr:
    status   = handleCmp32rr(&MI, scratchRegs);
    flagSave = FlagSaveMode::SAVE_BEFORE_EXEC;
    break;
  case X86::CMP32ri:
  case X86::CMP32ri8:
    status   = handleCmp32ri(&MI, scratchRegs);
    flagSave = FlagSaveMode::SAVE_BEFORE_EXEC;
    break;
  case X86::CMP32rm:
    status   = handleCmp32rm(&MI, scratchRegs);
    flagSave = FlagSaveMode::SAVE_BEFORE_EXEC;
    break;
  case X86::LEA32r:
    status   = handleLea32r(&MI, scratchRegs);
    flagSave = FlagSaveMode::SAVE_AFTER_EXEC;
    break;
  case X86::MOV32rm:
    status   = handleMov32rm(&MI, scratchRegs);
    flagSave = FlagSaveMode::SAVE_AFTER_EXEC;
    break;
  case X86::MOV32mr:
    status   = handleMov32mr(&MI, scratchRegs);
    flagSave = FlagSaveMode::SAVE_AFTER_EXEC;
    break;
  case X86::MOV32mi:
    status   = handleMov32mi(&MI, scratchRegs);
    flagSave = FlagSaveMode::SAVE_AFTER_EXEC;
    break;
  case X86::MOV32rr:
    status   = handleMov32rr(&MI, scratchRegs);
    flagSave = FlagSaveMode::SAVE_AFTER_EXEC;
    break;
  case X86::MOV32ri:
    status   = handleMov32ri(&MI, scratchRegs);
    flagSave = FlagSaveMode::SAVE_AFTER_EXEC;
    break;
  case X86::JMP_1:
    status   = handleJmp1(&MI, scratchRegs);
    flagSave = FlagSaveMode::SAVE_BEFORE_EXEC;
    break;
#if LLVM_VERSION_MAJOR >= 9
  case X86::JCC_1:
#else
  case X86::JE_1:
  case X86::JNE_1:
  case X86::JB_1:
  case X86::JAE_1:
#endif
    status   = handleJcc1(&MI, scratchRegs);
    flagSave = FlagSaveMode::SAVE_BEFORE_EXEC;
    break;
  case X86::CALLpcrel32:
    status   = handleCall(&MI, scratchRegs);
    flagSave = FlagSaveMode::SAVE_BEFORE_EXEC;
    break;
  case X86::CALL32r:
    status   = handleCallReg(&MI, scratchRegs);
    flagSave = FlagSaveMode::SAVE_BEFORE_EXEC;
    break;
  default: return ROPChainStatus::ERR_NOT_IMPLEMENTED;
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

    if (chain.size() < 2) {
      break;
    }

    for (auto it = chain.begin() + 1; it != chain.end();) {
      // equal microgadgets, but only if they're both XCHG instructions
      if (*it == *(it - 1) && it->type == ChainElem::Type::GADGET &&
          it->microgadget->Type == GadgetType::XCHG) {
        it         = chain.erase(it - 1);
        it         = chain.erase(it);
        duplicates = true;
      }

      if (it != chain.end()) {
        ++it;
      } else {
        break;
      }
    }
  } while (duplicates);
}

} // namespace ropf
