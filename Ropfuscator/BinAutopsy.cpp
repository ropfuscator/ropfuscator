// ==============================================================================
//   BINARY AUTOPSY
//   part of the ROPfuscator project
// ==============================================================================

#include "BinAutopsy.h"
#include "ROPEngine.h"
#include "CapstoneLLVMAdpt.h"
#include "ChainElem.h"
#include "Debug.h"

#include <assert.h>
#include <fstream>
#include <sstream>
#include <stdlib.h>
#include <string.h>
#include <time.h>

using namespace std;

#include "llvm/Object/ELF.h"
using llvm::object::ELF32LE;
using llvm::object::ELF32LEFile;

static const bool searchSegmentForGadget = true;

class ELFParser {
public:
  ELFParser(const std::string &path) {
    ifstream f(path, std::ios::binary);
    if (!f.good()) {
      llvm::dbgs() << "Given file " << path
                   << " doesn't exist or is invalid!";
      exit(1);
    }
    llvm::dbgs() << "USING: " << path << "\n";
    f.seekg(0, std::ios::end);
    size_t size = f.tellg();
    f.seekg(0, std::ios::beg);
    buf.resize(size);
    f.read(&buf[0], size);
    f.close();
    if (auto elf_opt = ELF32LEFile::create(StringRef(&buf[0], size))) {
      this->elf.reset(new ELF32LEFile(*elf_opt));
    } else {
      dbgs() << "ELF file error: " << path << " : " << elf_opt.takeError()
             << "\n";
      exit(1);
    }
    parseSections();
    parseVerdefs();
  }

  const uint8_t *base() const {
    return elf->base();
  }

  std::vector<ELF32LE::Phdr> getCodeSegments() {
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

  std::vector<ELF32LE::Shdr> getCodeSections() {
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

  std::string getSectionName(const ELF32LE::Shdr &section) {
    if (auto sectname_opt = elf->getSectionName(&section)) {
      return sectname_opt->str();
    } else {
      return "<unnamed>";
    }
  }

  ArrayRef<ELF32LE::Sym> getDynamicSymbols() {
    auto symbols = elf->symbols(dynsym);
    if (symbols)
      return *symbols;
    else
      return ArrayRef<ELF32LE::Sym>();
  }

  Expected<StringRef> getSymbolName(const ELF32LE::Sym &sym) {
    return sym.getName(dynstrtab);
  }

  bool isGlobalFunction(const ELF32LE::Sym &sym) {
    return sym.getType() == ELF_STT_FUNC && sym.getBinding() == ELF_STB_GLOBAL;
  }

  std::string getSymbolVersion(int symindex) {
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
  // version table index: local
  static const int ELF_VER_NDX_LOCAL = 0;
  // version table index: global
  static const int ELF_VER_NDX_GLOBAL = 1;
  // version table index: max value + 1
  static const int ELF_VER_NDX_LORESERVE = 0xff00;

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

BinaryAutopsy::BinaryAutopsy(string path) : elf(new ELFParser(path)) {
  // Seeds the PRNG (we'll use it in getRandomSymbol());
  srand(time(nullptr));
  isModuleSymbolAnalysed = false;

  dissect();
}

// workaround for LLVM build problem ???
const std::error_category &llvm::object::object_category() {
  struct _object_error_category : public std::error_category {
    const char *name() const noexcept override { return "llvm.object"; }
    std::string message(int ev) const override {
      return "ELF object parse error";
    }
  };
  static const _object_error_category instance;
  return instance;
}

BinaryAutopsy::~BinaryAutopsy() {
}

void BinaryAutopsy::dissect() {
  dumpSections();
  dumpSegments();
  dumpDynamicSymbols();
  dumpGadgets();
  applyGadgetFilters();
  buildXchgGraph();
}

BinaryAutopsy *BinaryAutopsy::instance = 0;

BinaryAutopsy *BinaryAutopsy::getInstance(string path) {
  if (instance == nullptr) {
    instance = new BinaryAutopsy(path);
  }

  return instance;
}

BinaryAutopsy *BinaryAutopsy::getInstance() {
  assert(instance != nullptr && "No pre-existing instance of Binary Autopsy.");
  return instance;
}

void BinaryAutopsy::dumpSegments() {
  for (auto &seg : elf->getCodeSegments()) {
    Segments.push_back(
        Section("<unnamed-segment>", seg.p_offset, seg.p_filesz));
  }
}

void BinaryAutopsy::dumpSections() {
  DEBUG_WITH_TYPE(SECTIONS,
                  llvm::dbgs() << "[SECTIONS]\tLooking for CODE sections... \n");
  using namespace std;
  // Iterates through only the sections that contain executable code
  for (auto &section : elf->getCodeSections()) {
    std::string sectname = elf->getSectionName(section);
    Sections.push_back(Section(sectname, section.sh_addr, section.sh_size));
    DEBUG_WITH_TYPE(SECTIONS, llvm::dbgs() << "[SECTIONS]\tFound section "
                                           << sectname << "\n");
  }
}

void BinaryAutopsy::dumpDynamicSymbols() {
  std::string symbolName;

  // Dumps sections if it wasn't already done
  if (Sections.empty())
    dumpSections();

  // llvm::dbgs() << "[*] Scanning for symbols... \n";
  auto symbols = elf->getDynamicSymbols();

  // Scan for all the symbols
  for (size_t i = 0; i < symbols.size(); i++) {
    const ELF32LE::Sym &sym = symbols[i];

    // Consider only function symbols with global scope
    if (elf->isGlobalFunction(sym) && sym.isDefined()) {
      if (auto name_opt = elf->getSymbolName(sym)) {
        symbolName = name_opt->str();
      } else {
        continue;
      }

      // those two symbols are very often subject to aliasing (they can be found
      // in many different libraries loaded in memory), so better avoiding them!
      if (symbolName == "_init" || symbolName == "_fini")
        continue;

      // functions with name prefixed with "_dl" is possibly created
      // by dynamic linkers, so we aviod them
      if (symbolName.rfind("_dl", 0) != std::string::npos)
        continue;

      // these symbols are also used in libgcc_s.so (often linked), so we avoid
      // them
      static const char *LIBGCC_SYMBOLS[] = {
          "__register_frame",
          "__register_frame_table",
          "__register_frame_info",
          "__register_frame_info_bases",
          "__register_frame_info_table",
          "__register_frame_info_table_bases",
          "__deregister_frame",
          "__deregister_frame_info",
          "__deregister_frame_info_bases",
          "__frame_state_for",
          "__moddi3",
          "__umoddi3",
          "__divdi3",
          "__udivdi3"};

      bool avoided = false;
      for (const char *avoided_name : LIBGCC_SYMBOLS) {
        if (symbolName == avoided_name) {
          avoided = true;
          break;
        }
      }
      if (avoided)
        continue;

      uint64_t addr = sym.getValue();

      // Get version string to avoid symbol aliasing
      std::string versionString = elf->getSymbolVersion(i);

      // symbols whose version starts with "GCC"
      // may also exist in libgcc_s.so, so avoided
      if (versionString.rfind("GCC", 0) != std::string::npos)
        continue;

      // we cannot use multiple versions of the same symbol, so we discard any
      // duplicate.
      bool alreadyPresent = false;
      for (auto &s : Symbols) {
        if (symbolName == s.Label) {
          alreadyPresent = true;
          break;
        }
      }
      if (!alreadyPresent)
        Symbols.emplace_back(Symbol(symbolName, versionString, addr));
    }
  }
  if (Symbols.empty()) {
    dbgs() << "No symbols found!\n";
    exit(1);
  }
}

void BinaryAutopsy::analyseUsedSymbols(const llvm::Module *module) {
  isModuleSymbolAnalysed = true;
  std::set<std::string> names;
  for (const auto &f : module->getFunctionList()) {
    names.insert(f.getName().str());
  }
  for (const auto &g : module->getGlobalList()) {
    names.insert(g.getName().str());
  }
  for (auto it = Symbols.begin(); it != Symbols.end(); ) {
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

void BinaryAutopsy::dumpGadgets() {
  uint8_t ret[] = "\xc3";

  // capstone stuff
  csh handle;
  cs_insn *instructions;

  // Dumps sections if it wasn't already done
  if (Sections.empty())
    dumpSections();

  // Initizialises capstone engine
  cs_open(CS_ARCH_X86, CS_MODE_32, &handle);
  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

  const uint8_t *buf = elf->base();

  for (auto &s : (searchSegmentForGadget ? Segments : Sections)) {
    int cnt = 0;

    // Scan for RET instructions
    for (uint64_t i = s.Address; i < (uint64_t)(s.Address + s.Length); i++) {

      if (buf[i] == *ret) {
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

          size_t count = cs_disasm(handle, cur_pos - depth, depth,
                                   offset - depth, 2, &instructions);

          // Valid gadgets must have two instructions, and the
          // last one must be a RET
          if (count == 2 && instructions[1].id == X86_INS_RET) {

            // Each gadget is identified with its mnemonic
            // and operators (ugly but straightforward :P)
            string asm_instr;
            for (size_t j = 0; j < count - 1; j++) {
              asm_instr += instructions[j].mnemonic;
              asm_instr += " ";
              asm_instr += instructions[j].op_str;
              asm_instr += ";";
            }

            if (!findGadget(asm_instr)) {
              Microgadgets.push_back(Microgadget(instructions, asm_instr));

              cnt++;
            }
          }
        }
      }
    }
    // scan for indirect jmp instructions
    for (uint64_t i = s.Address; i < (uint64_t)(s.Address + s.Length) - 1;
         i++) {

      if (buf[i] == 0xff && buf[i + 1] >= 0xe0 && buf[i + 1] < 0xe8) {
        size_t count = cs_disasm(handle, &buf[i], 2, i, 1, &instructions);

        // Valid gadgets must have two instructions, and the
        // last one must be a RET
        if (count == 1 && instructions[0].id == X86_INS_JMP) {

          string asm_instr;
          asm_instr += instructions[0].mnemonic;
          asm_instr += " ";
          asm_instr += instructions[0].op_str;
          asm_instr += ";";

          if (!findGadget(asm_instr)) {
            Microgadgets.push_back(Microgadget(instructions, asm_instr));

            cnt++;
          }
        }
      }
    }
    // llvm::dbgs() << cnt << " found!\n";
  }
}

const Microgadget *BinaryAutopsy::findGadget(string asmInstr) const {
  // Legacy: lookup by asm_instr string
  if (Microgadgets.empty()) {
    return nullptr;
  }

  for (auto &g : Microgadgets) {
    if (g.asmInstr.compare(asmInstr) == 0)
      return &g;
  }

  return nullptr;
}

const Microgadget *BinaryAutopsy::findGadget(x86_insn insn, x86_reg op0,
                                       x86_reg op1) const {
  for (auto &gadget : Microgadgets) {
    if (gadget.getID() == insn &&               // same instruction opcode
        gadget.getOp(0).type == X86_OP_REG &&   // operand 0: register
        gadget.getOp(0).reg == op0 &&           // operand 0: equal to op0
        (op1 == X86_REG_INVALID ||              // if operand 1 is present:
         (gadget.getOp(1).type == X86_OP_REG && //   operand 1: register
          gadget.getOp(1).reg == op1)))         //   operand 1: equal to op1

      return &gadget;
  }
  return nullptr;
}

std::vector<const Microgadget *>
BinaryAutopsy::findAllGadgets(x86_insn insn, x86_op_type op0, x86_op_type op1) const {
  std::vector<const Microgadget *> res;

  if (Microgadgets.empty()) {
    return res;
  }

  for (auto &gadget : Microgadgets) {
    if (gadget.getID() == insn && op0 == gadget.getOp(0).type &&
        (op1 == 0 || op1 == gadget.getOp(1).type))
      res.push_back(&gadget);
  }

  return res;
}

void BinaryAutopsy::buildXchgGraph() {
  DEBUG_WITH_TYPE("xchg_graph", llvm::dbgs()
                                    << "[XchgGraph]\t"
                                    << "Building the eXCHanGe Graph ...\n");
  xgraph = XchgGraph();

  // search for all the "xchg reg, reg" gadgets
  auto XchgGadgets = findAllGadgets(X86_INS_XCHG, X86_OP_REG, X86_OP_REG);

  if (XchgGadgets.empty()) {
    DEBUG_WITH_TYPE(XCHG_GRAPH, llvm::dbgs()
                                    << "[XchgGraph]\t"
                                    << "[!] Unable to build the eXCHanGe "
                                       "Graph: no XCHG gadgets found\n");
    return;
  }

  for (auto &g : XchgGadgets) {
    xgraph.addEdge(g->getOp(0).reg, g->getOp(1).reg);

    DEBUG_WITH_TYPE(XCHG_GRAPH, llvm::dbgs()
                                    << "[XchgGraph]\t"
                                    << "Added new edge: " << g->getOp(0).reg
                                    << ", " << g->getOp(1).reg << "\n");
  }
}

void BinaryAutopsy::applyGadgetFilters() {
  int excluded = 0;

  for (auto g = Microgadgets.begin(); g != Microgadgets.end();) {
    if
        // gadgets with ESP as operand, since we cannot deal with the
        // stack pointer using just microgadgets.
        (((g->getOp(0).type == X86_OP_REG && g->getOp(0).reg == X86_REG_ESP) ||
          (g->getOp(1).type == X86_OP_REG && g->getOp(1).reg == X86_REG_ESP) ||
          (g->getOp(0).type == X86_OP_MEM &&
           g->getOp(0).mem.base == X86_REG_ESP) ||
          (g->getOp(1).type == X86_OP_MEM &&
           g->getOp(1).mem.base == X86_REG_ESP)) ||

         // gadgets with memory operands having index and segment
         // registers, or invalid base register, or a displacement value
         ((g->getOp(0).type == X86_OP_MEM &&
           (g->getOp(0).mem.base == X86_REG_INVALID ||
            g->getOp(0).mem.index != X86_REG_INVALID ||
            g->getOp(0).mem.segment != X86_REG_INVALID ||
            g->getOp(0).mem.disp != 0)) ||
          (g->getOp(1).type == X86_OP_MEM &&
           (g->getOp(1).mem.base == X86_REG_INVALID ||
            g->getOp(1).mem.index != X86_REG_INVALID ||
            g->getOp(1).mem.segment != X86_REG_INVALID ||
            g->getOp(1).mem.disp != 0)))) {

      DEBUG_WITH_TYPE(GADGET_FILTER, llvm::dbgs()
                                         << "[GadgetFilter]\texcluded: "
                                         << g->asmInstr << "\n");
      g = Microgadgets.erase(g);
      excluded++;
    } else {
      ++g;
    }
  }

  // Categorise the gadgets in primitives
  for (auto &gadget : Microgadgets) {
    switch (gadget.getID()) {
    case X86_INS_POP: {
      // pop REG: init
      if (gadget.getOp(0).type == X86_OP_REG)
        GadgetPrimitives["init"].push_back(gadget);
      break;
    }
    case X86_INS_ADD: {
      // add REG1, REG2: add
      cs_x86_op op0 = gadget.getOp(0);
      cs_x86_op op1 = gadget.getOp(1);
      if (op0.type == X86_OP_REG && op1.type == X86_OP_REG) {
        // Register-register
        if (op0.reg != op1.reg)
          GadgetPrimitives["add"].push_back(gadget);
        else
          GadgetPrimitives["add_1"].push_back(gadget);
      }
      break;
    }
    case X86_INS_SUB: {
      // sub REG1, REG2: sub
      cs_x86_op op0 = gadget.getOp(0);
      cs_x86_op op1 = gadget.getOp(1);
      if (op0.type == X86_OP_REG && op1.type == X86_OP_REG) {
        if (op0.reg != op1.reg)
          GadgetPrimitives["sub"].push_back(gadget);
        else
          GadgetPrimitives["sub_1"].push_back(gadget);
      }
      break;
    }
    case X86_INS_AND: {
      // and REG1, REG2: and
      cs_x86_op op0 = gadget.getOp(0);
      cs_x86_op op1 = gadget.getOp(1);
      if (op0.type == X86_OP_REG && op1.type == X86_OP_REG) {
        if (op0.reg != op1.reg)
          GadgetPrimitives["and"].push_back(gadget);
        else
          GadgetPrimitives["and_1"].push_back(gadget);
      }
      break;
    }
    case X86_INS_XOR: {
      // xor REG1, REG2: xor_1, xor_2
      if (gadget.getOp(0).type == X86_OP_REG && // Register-register
          gadget.getOp(1).type == X86_OP_REG) {
        if (gadget.getOp(0).reg == gadget.getOp(1).reg)
          GadgetPrimitives["xor_1"].push_back(gadget);
        else
          GadgetPrimitives["xor_2"].push_back(gadget);
      }
      break;
    }
    case X86_INS_MOV: {
      // mov REG1, REG2: copy
      if (gadget.getOp(0).type == X86_OP_REG && // Register-register: copy
          gadget.getOp(1).type == X86_OP_REG)
        GadgetPrimitives["copy"].push_back(gadget);

      else if (gadget.getOp(0).type == X86_OP_REG && // Register-memory: load
               gadget.getOp(1).type == X86_OP_MEM) {
        if (gadget.getOp(0).reg == gadget.getOp(1).mem.base)
          // data is loaded in the same register of the source
          GadgetPrimitives["load_1"].push_back(gadget);
        else
          // data is loaded onto another register
          GadgetPrimitives["load_2"].push_back(gadget);

      } else if (gadget.getOp(0).type == X86_OP_MEM // Register-memory: store
                 && gadget.getOp(1).type == X86_OP_REG)
        GadgetPrimitives["store"].push_back(gadget);
      break;
    }
    case X86_INS_XCHG: {
      // xchg REG1, REG2: xchg
      if (gadget.getOp(0).type == X86_OP_REG && // Register-register
          gadget.getOp(1).type == X86_OP_REG)
        GadgetPrimitives["xchg"].push_back(gadget);
      break;
    }
    case X86_INS_CMOVE: {
      // cmove REG1, REG2: cmove
      if (gadget.getOp(0).type == X86_OP_REG &&
          gadget.getOp(1).type == X86_OP_REG)
        GadgetPrimitives["cmove"].push_back(gadget);
      break;
    }
    case X86_INS_CMOVB: {
      // cmovb REG1, REG2: cmovb
      if (gadget.getOp(0).type == X86_OP_REG &&
          gadget.getOp(1).type == X86_OP_REG)
        GadgetPrimitives["cmovb"].push_back(gadget);
      break;
    }
    case X86_INS_PUSH: {
      // push REG1; ret: jmp
      if (gadget.getOp(0).type == X86_OP_REG)
        GadgetPrimitives["jmp"].push_back(gadget);
      break;
    }
    case X86_INS_JMP: {
      // jmp REG1: jmp
      if (gadget.getOp(0).type == X86_OP_REG)
        GadgetPrimitives["jmp"].push_back(gadget);
      break;
    }
    default:
      continue;
    }
  }

  DEBUG_WITH_TYPE(GADGET_FILTER, llvm::dbgs() << "[GadgetFilter]\t" << excluded
                                              << " gadgets have been excluded!"
                                              << "\n");
}

bool BinaryAutopsy::areExchangeable(x86_reg a, x86_reg b) const {
  int pred[N_REGS], dist[N_REGS];
  bool visited[N_REGS];

  return xgraph.checkPath(a, b, pred, dist, visited);
}

ROPChain BinaryAutopsy::findGadgetPrimitive(XchgState &state, string type, x86_reg op0,
                                            x86_reg op1) const {
  // Note: everytime we need to operate on op0 and op1, we need to check which
  // is the actual register that holds that operand.
  ROPChain result;
  const Microgadget *found = nullptr;

  auto it_gadgets = GadgetPrimitives.find(type);
  if (it_gadgets == GadgetPrimitives.end())
    return result;
  const auto &gadgets = it_gadgets->second;

  // Attempt #1: find a primitive gadget having the same operands
  for (auto &gadget : gadgets) {
    if (extractReg(gadget.getOp(0)) == getEffectiveReg(state, op0) &&
        (op1 == X86_REG_INVALID ||
         extractReg(gadget.getOp(1)) == getEffectiveReg(state, op1))) {
      found = &gadget;
      break;
    }
  }

  if (found) {
    result.emplace_back(ChainElem::fromGadget(found));
  } else {
    // Attempt #2: find a primitive gadget that has at least operands
    // exchangeable with the ones required. A proper xchg chain will be
    // generated.
    if (type == "jmp") {
      // we cannot exchange registers in jmp gadget; just fail
      return result;
    }
    x86_reg gadget_op0, gadget_op1;
    for (auto &gadget : gadgets) {
      gadget_op0 = extractReg(gadget.getOp(0));
      gadget_op1 = extractReg(gadget.getOp(1));

      // check if given op0 and op1 are respectively exchangeable with
      // op0 and op1 of the gadget
      if (areExchangeable(getEffectiveReg(state, op0), gadget_op0) &&
          ((op1 == X86_REG_INVALID) // only if op1 is present
           ^ areExchangeable(getEffectiveReg(state, op1), gadget_op1))) {

        if (op1 != X86_REG_INVALID) {
          if ((getEffectiveReg(state, op0) == gadget_op1 &&
               getEffectiveReg(state, op1) == gadget_op0) ||
              (getEffectiveReg(state, op0) == gadget_op0 &&
               getEffectiveReg(state, op1) == gadget_op1) ||
              (getEffectiveReg(state, op0) == getEffectiveReg(state, op1) &&
               gadget_op0 == gadget_op1)) {
            DEBUG_WITH_TYPE(XCHG_CHAIN, llvm::dbgs()
                                            << "\t\tavoiding double xchg\n");
          } else {
            auto xchgChain1 = exchangeRegs(state, getEffectiveReg(state, op1), gadget_op1);
            result.append(xchgChain1);
          }
        }

        auto xchgChain0 = exchangeRegs(state, getEffectiveReg(state, op0), gadget_op0);
        result.append(xchgChain0);

        result.emplace_back(ChainElem::fromGadget(&gadget));
        break;
      }
    }
  }
  return result;
}

ROPChain BinaryAutopsy::buildXchgChain(XchgPath const &path) const {
  ROPChain result;

  for (auto &edge : path) {
    // in XCHG instructions the operands order doesn't matter
    auto found =
        findGadget(X86_INS_XCHG, (x86_reg)edge.first, (x86_reg)edge.second);
    if (!found)
      found =
          findGadget(X86_INS_XCHG, (x86_reg)edge.second, (x86_reg)edge.first);

    result.emplace_back(ChainElem::fromGadget(found));
  }

  return result;
}

ROPChain BinaryAutopsy::exchangeRegs(XchgState &state, x86_reg reg0, x86_reg reg1) const {
  ROPChain result;

  if (reg0 != reg1) {
    XchgPath path = xgraph.getPath(state, reg0, reg1);
    result = buildXchgChain(path);
  }

  return result;
}

ROPChain BinaryAutopsy::undoXchgs(XchgState &state) const {
  XchgPath path = xgraph.reorderRegisters(state);
  return buildXchgChain(path);
}

x86_reg BinaryAutopsy::getEffectiveReg(const XchgState &state, x86_reg reg) const {
  return (x86_reg)state.searchLogicalReg(reg);
}