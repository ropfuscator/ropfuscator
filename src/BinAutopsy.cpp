// ==============================================================================
//   BINARY AUTOPSY
//   part of the ROPfuscator project
// ==============================================================================

#include "BinAutopsy.h"
#include "ChainElem.h"
#include "Debug.h"
#include "ROPEngine.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDisassembler/MCDisassembler.h"
#include "llvm/Object/ELF.h"
#include "llvm/Support/TargetRegistry.h"

#if LLVM_VERSION_MAJOR >= 9
#include "MCTargetDesc/X86IntelInstPrinter.h"
#else
#include "InstPrinter/X86IntelInstPrinter.h"
#endif

#include <assert.h>
#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <fstream>
#include <sstream>
#include <stdlib.h>
#include <string.h>
#include <time.h>

using namespace llvm;
using llvm::object::ELF32LE;
using llvm::object::ELF32LEFile;

namespace ropf {

class ELFParser {
public:
  ELFParser(const std::string &path) : path(path) {
    std::ifstream f(path, std::ios::binary);

    if (!f.good()) {
      dbg_fmt("Given file {} does not exist or is invalid", path);
      exit(1);
    }

    // dbg_fmt("Analysing {}\n", path);

    f.seekg(0, std::ios::end);

    size_t size = f.tellg();

    f.seekg(0, std::ios::beg);
    buf.resize(size);
    f.read(&buf[0], size);
    f.close();

    auto elf_opt = ELF32LEFile::create(StringRef(&buf[0], size));

    if (!elf_opt) {
      dbg_fmt("ELF file error: {}: {}\n", path, elf_opt.takeError());
      exit(1);
    }

    this->elf.reset(new ELF32LEFile(*elf_opt));

    parseSections();
    parseVerdefs();
  }

  const uint8_t *base() const { return elf->base(); }
  size_t size() const { return elf->getBufSize(); }

  std::vector<ELF32LE::Phdr> getCodeSegments() const {
    std::vector<ELF32LE::Phdr> rv;

    if (auto segments = elf->program_headers()) {
      // iterate through segments
      for (auto &seg : *segments) {
        // check if it is loadable segment and executable
        if (seg.p_type == ELF_PT_LOAD && (seg.p_flags & ELF_PF_X)) {
          rv.push_back(seg);
        }
      }
    }

    return rv;
  }

  std::vector<ELF32LE::Shdr> getCodeSections() const {
    std::vector<ELF32LE::Shdr> rv;
    if (auto sections = elf->sections()) {
      for (auto &section : *sections) {
        if (section.sh_type == ELF_SHT_PROGBITS &&
            (section.sh_flags & ELF_SHF_EXECINSTR)) {
          rv.push_back(section);
        }
      }
    }
    return rv;
  }

  std::string getSectionName(const ELF32LE::Shdr &section) const {
    if (auto sectname_opt = elf->getSectionName(&section)) {
      return sectname_opt->str();
    }

    return "<unnamed>";
  }

  ArrayRef<ELF32LE::Sym> getDynamicSymbols() const {
    auto symbols = elf->symbols(dynsym);

    if (symbols)
      return *symbols;

    return ArrayRef<ELF32LE::Sym>();
  }

  Expected<StringRef> getSymbolName(const ELF32LE::Sym &sym) const {
    return sym.getName(dynstrtab);
  }

  bool isGlobalOrWeakFunction(const ELF32LE::Sym &sym) const {
    return sym.getType() == ELF_STT_FUNC &&
           (sym.getBinding() == ELF_STB_GLOBAL ||
            sym.getBinding() == ELF_STB_WEAK);
  }

  std::string getSymbolVersion(int symindex) const {
    auto versyms = elf->getSectionContentsAsArray<uint16_t>(versym);

    if (!versyms)
      return "";

    uint16_t value = (*versyms)[symindex];

    if (value == ELF_VER_NDX_LOCAL || value == ELF_VER_NDX_GLOBAL ||
        value >= ELF_VER_NDX_LORESERVE)
      return "";

    value &= 0x7fff;

    if (value >= verdefs.size())
      return "";

    return verdefs[value];
  }

  std::string getPath() const { return path; }

private:
  struct Verdef {
    uint16_t vd_version;
    uint16_t vd_flags;
    uint16_t vd_ndx;
    uint16_t vd_cnt;
    uint32_t vd_hash;
    uint32_t vd_aux;
    uint32_t vd_next;
  };
  struct Verdef_aux {
    uint32_t vda_name;
    uint32_t vda_next;
  };

  // ELF constants

  // SHT_PROGBITS: code section loaded into memory
  static const int ELF_SHT_PROGBITS = 1;
  // SHT_DYNSYM: dynamic symbol table
  static const int ELF_SHT_DYNSYM = 11;
  // SHT_GNU_verdef: symbol version definition
  static const int ELF_SHT_GNU_verdef = 0x6ffffffd;
  // SHT_GNU_versym: symbol version information
  static const int ELF_SHT_GNU_versym = 0x6fffffff;
  // SHF_EXECINSTR: executable flag of section
  static const int ELF_SHF_EXECINSTR = 0x4;
  // PT_LOAD: code segment loaded into memory
  static const int ELF_PT_LOAD = 1;
  // PF_X: executable flag of segment
  static const int ELF_PF_X = 0x01;
  // symbol type: function
  static const int ELF_STT_FUNC = 2;
  // symbol binding: global
  static const int ELF_STB_GLOBAL = 1;
  // symbol binding: weak
  static const int ELF_STB_WEAK = 2;
  // version table index: local
  static const int ELF_VER_NDX_LOCAL = 0;
  // version table index: global
  static const int ELF_VER_NDX_GLOBAL = 1;
  // version table index: max value + 1
  static const int ELF_VER_NDX_LORESERVE = 0xff00;

  std::string path;
  std::unique_ptr<ELF32LEFile> elf;
  std::vector<char> buf;
  const ELF32LE::Shdr *dynsym;
  const ELF32LE::Shdr *verdef;
  const ELF32LE::Shdr *versym;
  StringRef dynstrtab;
  std::vector<std::string> verdefs;

  void parseSections() {
    // identify dynsym, verdef, versym sections
    if (auto sections = elf->sections()) {
      for (auto &section : *sections) {
        if (section.sh_type == ELF_SHT_DYNSYM) {
          dynsym = &section;
        } else if (section.sh_type == ELF_SHT_GNU_verdef) {
          verdef = &section;
        } else if (section.sh_type == ELF_SHT_GNU_versym) {
          versym = &section;
        }
      }
    }

    if (dynsym) {
      if (auto dynstr_opt = elf->getStringTableForSymtab(*dynsym)) {
        dynstrtab = *dynstr_opt;
      }
    }
  }

  void parseVerdefs() {
    std::map<uint16_t, const char *> verdefmap;

    if (!verdef)
      return;

    auto data_opt = elf->getSectionContents(verdef);

    if (!data_opt)
      return;

    const uint8_t *data = data_opt->data();
    size_t size = data_opt->size();
    uint16_t max_index = 0;

    // iterate over Verdef entries
    for (unsigned int pos = 0; pos < size;) {
      const Verdef *entry = reinterpret_cast<const Verdef *>(&data[pos]);

      if (max_index < entry->vd_ndx)
        max_index = entry->vd_ndx;

      if (entry->vd_cnt > 0) {
        // only take the first Verdef_aux entry
        const Verdef_aux *aux =
            reinterpret_cast<const Verdef_aux *>(&data[pos + entry->vd_aux]);

        if (aux->vda_name < dynstrtab.size())
          verdefmap.emplace(entry->vd_ndx, &dynstrtab.data()[aux->vda_name]);
      }

      if (entry->vd_next == 0)
        break;

      pos += entry->vd_next;
    }

    verdefs.resize(max_index + 1);

    for (auto &entry : verdefmap) {
      verdefs[entry.first] = entry.second;
    }
  }
};

BinaryAutopsy::BinaryAutopsy(const GlobalConfig &config, const Module &module,
                             const TargetMachine &target, MCContext &context)
    : module(module), target(target), context(context), config(config),
      elf(new ELFParser(config.libraryPath)) {
  // Seeds the PRNG (we'll use it in getRandomSymbol());
  for (const std::string &libPath : config.linkedLibraries) {
    otherLibs.emplace_back(new ELFParser(libPath));
  }
  srand(time(nullptr));
  isModuleSymbolAnalysed = false;

  dissect(elf.get());
  analyseUsedSymbols();
}

BinaryAutopsy::~BinaryAutopsy() {}

void BinaryAutopsy::dissect(ELFParser *elf) {
  dumpSections(elf, Sections);
  dumpSegments(elf, Segments);
  dumpDynamicSymbols(elf, Symbols, true);

  std::vector<std::shared_ptr<Microgadget>> gadgets;
  dumpGadgets(elf, gadgets);
  for (auto gadget : gadgets) {
    addGadget(gadget);
  }
  buildXchgGraph();
}

BinaryAutopsy *BinaryAutopsy::instance = 0;

BinaryAutopsy *BinaryAutopsy::getInstance(const GlobalConfig &config,
                                          llvm::MachineFunction &MF) {
  if (instance == nullptr) {
    instance = new BinaryAutopsy(config, *MF.getFunction().getParent(),
                                 MF.getTarget(), MF.getContext());
  }

  return instance;
}

void BinaryAutopsy::dumpSegments(const ELFParser *elf,
                                 std::vector<Section> &segments) const {
  for (auto &seg : elf->getCodeSegments()) {
    segments.push_back(
        Section("<unnamed-segment>", seg.p_offset, seg.p_filesz));
  }
}

void BinaryAutopsy::dumpSections(const ELFParser *elf,
                                 std::vector<Section> &sections) const {
  DEBUG_WITH_TYPE(SECTIONS,
                  dbg_fmt("[SECTIONS]\tLooking for CODE sections... \n"));
  // Iterates through only the sections that contain executable code
  for (auto &section : elf->getCodeSections()) {
    std::string sectname = elf->getSectionName(section);

    sections.push_back(Section(sectname, section.sh_addr, section.sh_size));

    DEBUG_WITH_TYPE(SECTIONS,
                    dbg_fmt("[SECTIONS]\tFound section {}\n", sectname));
  }
}

void BinaryAutopsy::dumpDynamicSymbols(const ELFParser *elf,
                                       std::vector<Symbol> &Symbols,
                                       bool safeOnly) const {
  // dbg_fmt("[*] Scanning for symbols... \n");
  auto symbols = elf->getDynamicSymbols();
  std::set<std::string> symbolNames;

  // Scan for all the symbols
  for (size_t i = 0; i < symbols.size(); i++) {
    const ELF32LE::Sym &sym = symbols[i];

    // Consider only function symbols with global scope
    if (elf->isGlobalOrWeakFunction(sym) && sym.isDefined()) {
      auto name_opt = elf->getSymbolName(sym);

      if (!name_opt) {
        continue;
      }

      std::string symbolName = name_opt->str();
      uint64_t addr = sym.getValue();

      // Get version string to avoid symbol aliasing
      std::string versionString = elf->getSymbolVersion(i);

      // we cannot use multiple versions of the same symbol,
      // so we detect duplicate.
      if (symbolNames.find(symbolName) == symbolNames.end()) {
        symbolNames.insert(symbolName);
        Symbol sym(symbolName, versionString, addr);
        if (!safeOnly || isSafeSymbol(sym))
          Symbols.emplace_back(sym);
      } else {
        // multi-versioned symbol
        if (safeOnly && config.avoidMultiversionSymbol) {
          for (auto it = Symbols.begin(); it != Symbols.end(); ++it) {
            if (it->Label == symbolName) {
              Symbols.erase(it);
              break;
            }
          }
        }
      }
    }
  }
}

bool BinaryAutopsy::isSafeSymbol(const Symbol &symbol) const {
  // those two symbols are very often subject to aliasing (they can be found
  // in many different libraries loaded in memory), so better avoiding them!
  if (symbol.Label == "_init" || symbol.Label == "_fini")
    return false;

  // functions with name prefixed with "_dl" is possibly created
  // by dynamic linkers, so we aviod them
  if (symbol.Label.rfind("_dl", 0) != std::string::npos)
    return false;

  return true;
}

void BinaryAutopsy::analyseUsedSymbols() {
  isModuleSymbolAnalysed = true;
  std::set<std::string> names;

  for (const auto &f : module.getFunctionList()) {
    names.insert(f.getName().str());
  }

  for (const auto &g : module.getGlobalList()) {
    names.insert(g.getName().str());
  }

  for (auto &lib : otherLibs) {
    std::vector<Symbol> symbols;
    dumpDynamicSymbols(lib.get(), symbols, false);
    for (auto &sym : symbols) {
      names.insert(sym.Label);
    }
  }

  for (auto it = Symbols.begin(); it != Symbols.end();) {
    if (names.find(it->Label) != names.end()) {
      it = Symbols.erase(it);
    } else {
      ++it;
    }
  }
}

const Symbol *BinaryAutopsy::getRandomSymbol() const {
  unsigned long i = rand() % Symbols.size();

  return &(Symbols.at(i));
}

extern "C" void LLVMInitializeX86Disassembler();

class DisassemblerHelper {
  MCDisassembler *disasm;
  X86IntelInstPrinter *printer;
  ArrayRef<uint8_t> data;

public:
  DisassemblerHelper(const TargetMachine &target, MCContext &context,
                     const ELFParser &elf) {
    LLVMInitializeX86Disassembler();
    disasm = target.getTarget().createMCDisassembler(
        *target.getMCSubtargetInfo(), context);
    printer = new X86IntelInstPrinter(*target.getMCAsmInfo(),
                                      *target.getMCInstrInfo(),
                                      *target.getMCRegisterInfo());
    data = ArrayRef<uint8_t>(elf.base(), elf.size());
  }

  ~DisassemblerHelper() { delete printer; }

  void disassemble(uint64_t address, size_t &size, MCInst *result,
                   size_t &count) {
    size_t i = 0;
    size_t pos = 0;
    uint64_t readsize = 0;
    for (i = 0, pos = 0; i < count && pos < size; i++, pos += readsize) {
#if LLVM_VERSION_MAJOR >= 10
      auto status = disasm->getInstruction(
          result[i], readsize, data.slice(address + pos, size - pos),
          address + pos, llvm::nulls());
#else
      auto status = disasm->getInstruction(
          result[i], readsize, data.slice(address + pos, size - pos),
          address + pos, llvm::nulls(), llvm::nulls());
#endif
      if (status != MCDisassembler::DecodeStatus::Success) {
        // disassemble error
        count = 0;
        size = 0;
        return;
      }
    }
    count = i;
    size = pos;
  }

  std::string formatInstr(const MCInst &instr) {
    std::string result;
    raw_string_ostream os(result);
#if LLVM_VERSION_MAJOR >= 10
    printer->printInstruction(&instr, 0, os);
#else
    printer->printInstruction(&instr, os);
#endif
    os.flush();
    if (!result.empty() && result[0] == '\t') {
      result = result.substr(1);
    }
    return result;
  }
};

void BinaryAutopsy::dumpGadgets(
    const ELFParser *elf,
    std::vector<std::shared_ptr<Microgadget>> &gadgets) const {
  DisassemblerHelper disasm(target, context, *elf);

  // map to check duplication
  std::map<std::string, std::shared_ptr<Microgadget>> gadgetMap;

  const uint8_t *buf = elf->base();

  for (auto &s : (config.searchSegmentForGadget ? Segments : Sections)) {
    int cnt = 0;

    // Scan for RET instructions
    for (uint64_t i = s.Address; i < (uint64_t)(s.Address + s.Length); i++) {
      if (buf[i] == (uint8_t)'\xc3') { // ret
        size_t offset = i + 1;
        const uint8_t *cur_pos = buf + offset;

        // Iteratively try to decode starting from MAXDEPTH to 1
        // bytes before the actual RET
        for (int depth = MAXDEPTH; depth > 0; depth--) {

          // Capstone sometimes ignores repeat prefix (0xF2, 0xF3)
          // in disassembled output. We do not need gadget prefixed
          // with repeat, so we avoid them
          uint8_t firstbyte = *(cur_pos - depth);
          if (firstbyte == 0xf2 || firstbyte == 0xf3)
            continue;

          uint64_t addr = offset - depth;

          MCInst instructions[2];
          size_t count = 2;
          size_t size = depth;
          disasm.disassemble(addr, size, instructions, count);

          // Valid gadgets must have two instructions, and the
          // last one must be a RET
          if (count == 2 && instructions[1].getOpcode() == X86::RETL &&
              // exclude PREFIX RET
              instructions[0].getOpcode() != X86::DATA16_PREFIX &&
              instructions[0].getOpcode() != X86::LOCK_PREFIX &&
              instructions[0].getOpcode() != X86::REP_PREFIX &&
              instructions[0].getOpcode() != X86::REPNE_PREFIX) {
            // Each gadget is identified with its mnemonic
            // and operators (ugly but straightforward :P)
            std::string asm_instr = disasm.formatInstr(instructions[0]);

            auto it = gadgetMap.find(asm_instr);
            if (it != gadgetMap.end()) {
              it->second->addresses.push_back(addr);
            } else {
              std::shared_ptr<Microgadget> gadget(
                  new Microgadget(instructions, count, addr, asm_instr));
              gadgets.push_back(gadget);
              gadgetMap.emplace(asm_instr, gadget);

              cnt++;
            }
          }
        }
      }
    }

    // scan for indirect jmp instructions
    for (uint64_t addr = s.Address; addr < (uint64_t)(s.Address + s.Length) - 1;
         addr++) {

      if (buf[addr] == 0xff && buf[addr + 1] >= 0xe0 && buf[addr + 1] < 0xe8) {
        MCInst inst;
        size_t count = 1;
        size_t size = 2;
        disasm.disassemble(addr, size, &inst, count);
        // Valid gadgets must have just one instruction of JMP register
        if (count == 1 && inst.getOpcode() == X86::JMP32r) {
          std::string asm_instr = disasm.formatInstr(inst);

          auto it = gadgetMap.find(asm_instr);
          if (it != gadgetMap.end()) {
            it->second->addresses.push_back(addr);
          } else {
            std::shared_ptr<Microgadget> gadget(
                new Microgadget(&inst, 1, addr, asm_instr));
            gadgets.push_back(gadget);
            gadgetMap.emplace(asm_instr, gadget);

            cnt++;
          }
        }
      }
    }
    // dbg_fmt("{} found!\n", cnt);
  }
}

const Microgadget *BinaryAutopsy::findGadget(GadgetType type, unsigned int reg1,
                                             unsigned int reg2) const {
  auto it = GadgetPrimitives.find(GadgetType::XCHG);
  if (it == GadgetPrimitives.end() || it->second.empty()) {
    return nullptr;
  }

  for (auto &g : it->second) {
    if (g->reg1 == reg1 && g->reg2 == reg2) {
      return g.get();
    }
  }
  return nullptr;
}

void BinaryAutopsy::buildXchgGraph() {
  DEBUG_WITH_TYPE(XCHG_GRAPH,
                  dbg_fmt("[XchgGraph] Building the exchange graph...\n"));

  xgraph = XchgGraph();

  // search for all the "xchg reg, reg" gadgets
  auto it = GadgetPrimitives.find(GadgetType::XCHG);
  if (it == GadgetPrimitives.end() || it->second.empty()) {
    DEBUG_WITH_TYPE(
        XCHG_GRAPH,
        dbg_fmt("[XchgGraph]\t"
                "[!] Unable to build graph: no xchg gadgets found\n"));

    return;
  }

  for (auto &g : it->second) {
    auto edge_a = g->reg1;
    auto edge_b = g->reg2;

    xgraph.addEdge(edge_a, edge_b);

    DEBUG_WITH_TYPE(XCHG_GRAPH, dbg_fmt("[XchgGraph]\tAdded new edge: {}, {}\n",
                                        edge_a, edge_b));
  }
}

void BinaryAutopsy::addGadget(std::shared_ptr<Microgadget> gadget) {
  // Categorise the gadgets in primitives
  const MCInst &inst = gadget->Instr[0];

  bool espUsed = false;
  // gadgets with ESP as operand, since we cannot deal with the
  // stack pointer using just microgadgets.
  for (unsigned int i = 0; i < inst.getNumOperands(); i++) {
    const auto &operand = inst.getOperand(i);
    if (operand.isReg() && operand.getReg() == X86::ESP) {
      espUsed = true;
    }
  }
  if (espUsed) {
    return;
  }

  switch (inst.getOpcode()) {
  // pop REG: init
  case X86::POP32r:
  case X86::POP32rmr: {
    gadget->reg1 = inst.getOperand(0).getReg();
    gadget->reg2 = X86::NoRegister;
    gadget->Type = GadgetType::INIT;
    GadgetPrimitives[GadgetType::INIT].push_back(gadget);
    break;
  }
  // add REG1, REG2: add
  case X86::ADD32rr: {
    gadget->reg1 = inst.getOperand(1).getReg();
    gadget->reg2 = inst.getOperand(2).getReg();
    if (gadget->reg1 != gadget->reg2) {
      gadget->Type = GadgetType::ADD;
      GadgetPrimitives[GadgetType::ADD].push_back(gadget);
    } else {
      gadget->Type = GadgetType::ADD_1;
      GadgetPrimitives[GadgetType::ADD_1].push_back(gadget);
    }
    break;
  }
  // sub REG1, REG2: sub
  case X86::SUB32rr: {
    gadget->reg1 = inst.getOperand(1).getReg();
    gadget->reg2 = inst.getOperand(2).getReg();
    if (gadget->reg1 != gadget->reg2) {
      gadget->Type = GadgetType::SUB;
      GadgetPrimitives[GadgetType::SUB].push_back(gadget);
    } else {
      gadget->Type = GadgetType::SUB_1;
      GadgetPrimitives[GadgetType::SUB_1].push_back(gadget);
    }
    break;
  }
  // and REG1, REG2: and
  case X86::AND32rr: {
    gadget->reg1 = inst.getOperand(1).getReg();
    gadget->reg2 = inst.getOperand(2).getReg();
    if (gadget->reg1 != gadget->reg2) {
      gadget->Type = GadgetType::AND;
      GadgetPrimitives[GadgetType::AND].push_back(gadget);
    } else {
      gadget->Type = GadgetType::AND_1;
      GadgetPrimitives[GadgetType::AND_1].push_back(gadget);
    }
    break;
  }
  // xor REG1, REG2: xor_1, xor_2
  case X86::XOR32rr: {
    gadget->reg1 = inst.getOperand(1).getReg();
    gadget->reg2 = inst.getOperand(2).getReg();
    if (gadget->reg1 != gadget->reg2) {
      gadget->Type = GadgetType::XOR;
      GadgetPrimitives[GadgetType::XOR].push_back(gadget);
    } else {
      gadget->Type = GadgetType::XOR_1;
      GadgetPrimitives[GadgetType::XOR_1].push_back(gadget);
    }
    break;
  }
  // mov REG1, REG2: copy
  case X86::MOV32rr: {
    gadget->reg1 = inst.getOperand(0).getReg();
    gadget->reg2 = inst.getOperand(1).getReg();
    if (gadget->reg1 != gadget->reg2) {
      gadget->Type = GadgetType::COPY;
      GadgetPrimitives[GadgetType::COPY].push_back(gadget);
    }
    break;
  }
  // mov REG, MEM: load
  case X86::MOV32rm: {
    // mov reg0, reg5:[reg1 + imm_scale2 * reg3 + imm_disp4]
    bool hasScaleReg = inst.getOperand(3).isReg() &&
                       inst.getOperand(3).getReg() != X86::NoRegister;
    bool hasSegmentReg = inst.getOperand(5).isReg() &&
                         inst.getOperand(5).getReg() != X86::NoRegister;
    bool hasDisplacement =
        !inst.getOperand(4).isImm() || inst.getOperand(4).getImm() != 0;
    if (hasScaleReg || hasSegmentReg || hasDisplacement) {
      break;
    }
    gadget->reg1 = inst.getOperand(0).getReg();
    gadget->reg2 = inst.getOperand(1).getReg();
    if (gadget->reg1 != gadget->reg2) {
      gadget->Type = GadgetType::LOAD;
      GadgetPrimitives[GadgetType::LOAD].push_back(gadget);
    } else {
      gadget->Type = GadgetType::LOAD_1;
      GadgetPrimitives[GadgetType::LOAD_1].push_back(gadget);
    }
    break;
  }
  // mov MEM, REG: store
  case X86::MOV32mr: {
    // mov reg4:[reg0 + imm_scale1 * reg2 + imm_disp3], reg5
    bool hasScaleReg = inst.getOperand(2).isReg() &&
                       inst.getOperand(2).getReg() != X86::NoRegister;
    bool hasSegmentReg = inst.getOperand(4).isReg() &&
                         inst.getOperand(4).getReg() != X86::NoRegister;
    bool hasDisplacement =
        !inst.getOperand(3).isImm() || inst.getOperand(3).getImm() != 0;
    if (hasScaleReg || hasSegmentReg || hasDisplacement) {
      break;
    }
    gadget->reg1 = inst.getOperand(0).getReg();
    gadget->reg2 = inst.getOperand(5).getReg();
    if (gadget->reg1 != gadget->reg2) {
      gadget->Type = GadgetType::STORE;
      GadgetPrimitives[GadgetType::STORE].push_back(gadget);
    }
    // mov [eax], eax is useless in most cases so we just ignore it
    break;
  }
  // xchg eax, REG2: xchg
  case X86::XCHG32ar: {
    gadget->reg1 = X86::EAX;
    gadget->reg2 = inst.getOperand(1).getReg();
    if (gadget->reg1 != gadget->reg2) {
      gadget->Type = GadgetType::XCHG;
      GadgetPrimitives[GadgetType::XCHG].push_back(gadget);
    }
    break;
  }
  // xchg REG1, REG2: xchg
  case X86::XCHG32rr: {
    gadget->reg1 = inst.getOperand(0).getReg();
    gadget->reg2 = inst.getOperand(1).getReg();
    if (gadget->reg1 != gadget->reg2) {
      gadget->Type = GadgetType::XCHG;
      GadgetPrimitives[GadgetType::XCHG].push_back(gadget);
    }
    break;
  }
#if LLVM_VERSION_MAJOR >= 9
  case X86::CMOV32rr: {
    gadget->reg1 = inst.getOperand(1).getReg();
    gadget->reg2 = inst.getOperand(2).getReg();
    X86::CondCode cond = (X86::CondCode)inst.getOperand(3).getImm();
    if (gadget->reg1 != gadget->reg2) {
      if (cond == X86::COND_E) {
        gadget->Type = GadgetType::CMOVE;
      } else if (cond == X86::COND_B) {
        gadget->Type = GadgetType::CMOVB;
      } else {
        break;
      }
      GadgetPrimitives[gadget->Type].push_back(gadget);
    }
    break;
  }
#else
  // cmove REG1, REG2: cmove
  case X86::CMOVE32rr: {
    gadget->reg1 = inst.getOperand(1).getReg();
    gadget->reg2 = inst.getOperand(2).getReg();
    if (gadget->reg1 != gadget->reg2) {
      gadget->Type = GadgetType::CMOVE;
      GadgetPrimitives[GadgetType::CMOVE].push_back(gadget);
    }
    break;
  }
  // cmovb REG1, REG2: cmovb
  case X86::CMOVB32rr: {
    gadget->reg1 = inst.getOperand(1).getReg();
    gadget->reg2 = inst.getOperand(2).getReg();
    if (gadget->reg1 != gadget->reg2) {
      gadget->Type = GadgetType::CMOVB;
      GadgetPrimitives[GadgetType::CMOVB].push_back(gadget);
    }
    break;
  }
#endif
  // push REG1; ret: jmp
  // jmp REG1: jmp
  case X86::PUSH32r:
  case X86::PUSH32rmr:
  case X86::JMP32r: {
    gadget->reg1 = inst.getOperand(0).getReg();
    gadget->reg2 = X86::NoRegister;
    gadget->Type = GadgetType::JMP;
    GadgetPrimitives[GadgetType::JMP].push_back(gadget);
    break;
  }
  default:
    // gadget->Type == GadgetType::UNDEFINED;
    // GadgetPrimitives[GadgetType::UNDEFINED].push_back(gadget);
    break;
  }
}

bool BinaryAutopsy::areExchangeable(unsigned int a, unsigned int b) const {
  int pred[N_REGS], dist[N_REGS];
  bool visited[N_REGS];

  return xgraph.checkPath(a, b, pred, dist, visited);
}

ROPChain BinaryAutopsy::findGadgetPrimitive(XchgState &state, GadgetType type,
                                            unsigned int reg1,
                                            unsigned int reg2) const {
  // Note: everytime we need to operate on reg1 and reg2, we need to check
  // which is the actual register that holds that operand.
  ROPChain result;
  const Microgadget *found = nullptr;

  auto it_gadgets = GadgetPrimitives.find(type);

  if (it_gadgets == GadgetPrimitives.end())
    return result;

  const auto &gadgets = it_gadgets->second;

  // Attempt #1: find a primitive gadget having the same operands
  for (auto &gadget : gadgets) {
    if (gadget->reg1 == getEffectiveReg(state, reg1) &&
        (reg1 == X86::NoRegister ||
         gadget->reg2 == getEffectiveReg(state, reg2))) {
      found = gadget.get();
      break;
    }
  }

  // we cannot exchange registers in jmp gadget; just fail
  if (!found && type == GadgetType::JMP) {
    return result;
  }

  if (found) {
    result.emplace_back(ChainElem::fromGadget(found));
    return result;
  }

  // Attempt #2: find a primitive gadget that has at least operands
  // exchangeable with the ones required. A proper xchg chain will be
  // generated.

  for (auto &gadget : gadgets) {

    // check if given op0 and op1 are respectively exchangeable with
    // op0 and op1 of the gadget
    if (areExchangeable(getEffectiveReg(state, reg1), gadget->reg1) &&
        ((reg2 == X86::NoRegister) // only if op1 is present
         ^ areExchangeable(getEffectiveReg(state, reg2), gadget->reg2))) {

      if (reg2 != X86::NoRegister) {
        if ((getEffectiveReg(state, reg1) == gadget->reg2 &&
             getEffectiveReg(state, reg2) == gadget->reg1) ||
            (getEffectiveReg(state, reg1) == gadget->reg1 &&
             getEffectiveReg(state, reg2) == gadget->reg2) ||
            (getEffectiveReg(state, reg1) == getEffectiveReg(state, reg2) &&
             gadget->reg1 == gadget->reg2)) {
          DEBUG_WITH_TYPE(XCHG_CHAIN, dbg_fmt("\t\tavoiding double xchg\n"));
        } else {
          auto xchgChain1 =
              exchangeRegs(state, getEffectiveReg(state, reg2), gadget->reg2);
          result.append(xchgChain1);
        }
      }

      auto xchgChain0 =
          exchangeRegs(state, getEffectiveReg(state, reg1), gadget->reg1);
      result.append(xchgChain0);

      result.emplace_back(ChainElem::fromGadget(gadget.get()));
      break;
    }
  }

  return result;
}

ROPChain BinaryAutopsy::buildXchgChain(XchgPath const &path) const {
  ROPChain result;

  for (auto &edge : path) {
    // in XCHG instructions the operands order doesn't matter
    auto found = findGadget(GadgetType::XCHG, edge.first, edge.second);

    if (!found)
      found = findGadget(GadgetType::XCHG, edge.second, edge.first);

    result.emplace_back(ChainElem::fromGadget(found));
  }

  return result;
}

ROPChain BinaryAutopsy::exchangeRegs(XchgState &state, unsigned int reg1,
                                     unsigned int reg2) const {
  ROPChain result;

  if (reg1 != reg2) {
    XchgPath path = xgraph.getPath(state, reg1, reg2);
    result = buildXchgChain(path);
  }

  return result;
}

ROPChain BinaryAutopsy::undoXchgs(XchgState &state) const {
  XchgPath path = xgraph.reorderRegisters(state);
  return buildXchgChain(path);
}

unsigned int BinaryAutopsy::getEffectiveReg(const XchgState &state,
                                            unsigned int reg) const {
  return state.searchLogicalReg(reg);
}

void BinaryAutopsy::debugPrintGadgets() const {
  auto regInfo = target.getMCRegisterInfo();
  for (auto &kv : GadgetPrimitives) {
    dbg_fmt("Gadgets of type {}:\n", (int)kv.first);
    for (auto &g : kv.second) {
      dbg_fmt("  {}\t{}#{}, {}#{}\t@", g->asmInstr, regInfo->getName(g->reg1),
              g->reg1, regInfo->getName(g->reg2), g->reg2);
      for (uint64_t addr : g->addresses) {
        dbg_fmt(" 0x{:x}", addr);
      }
      dbg_fmt("\n");
    }
  }
}

} // namespace ropf
