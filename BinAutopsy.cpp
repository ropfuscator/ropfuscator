// ==============================================================================
//   BINARY AUTOPSY
//   part of the ROPfuscator project
// ==============================================================================

#include "BinAutopsy.h"
#include "XchgGraph.h"
#include <assert.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdlib.h>
#include <string.h>
#include <time.h>

using namespace std;

// Max bytes before the RET to be examined (RET included!)
// see BinaryAutopsy::extractGadgets()
#define MAXDEPTH 4

// ------------------------------------------------------------------------
// Symbol
// ------------------------------------------------------------------------
Symbol::Symbol(string label, string version, uint64_t address)
    : Address(address) {
  Label = new char[label.length() + 1];
  Version = new char[version.length() + 1];
  strcpy(Label, label.c_str());
  strcpy(Version, version.c_str());
};

char *Symbol::getSymVerDirective() {
  stringstream ss;
  ss << ".symver " << Label << "," << Label << "@" << Version;
  SymVerDirective = new char[ss.str().length() + 1];
  strcpy(SymVerDirective, ss.str().c_str());
  return SymVerDirective;
}

// ------------------------------------------------------------------------
// Section
// ------------------------------------------------------------------------

Section::Section(string label, uint64_t address, uint64_t length)
    : Label(label), Address(address), Length(length){};

// ------------------------------------------------------------------------
// Microgadget
// ------------------------------------------------------------------------
Microgadget::Microgadget(cs_insn *instr, string asmInstr)
    : Instr(instr), asmInstr(asmInstr){};

uint64_t Microgadget::getAddress() const { return Instr[0].address; }

x86_insn Microgadget::getID() const {
  // Returns the ID (opcode)
  return static_cast<x86_insn>(Instr[0].id);
}

cs_x86_op Microgadget::getOp(int i) const {
  // Returns the i-th operand
  return Instr[0].detail->x86.operands[i];
}

uint8_t Microgadget::getNumOp() const {
  // Returns the number of operands
  return Instr[0].detail->x86.op_count;
}

// ------------------------------------------------------------------------
// BinaryAutopsy
// ------------------------------------------------------------------------

BinaryAutopsy::BinaryAutopsy(string path) {
  BinaryPath = new char[path.length() + 1];
  strcpy(BinaryPath, path.c_str());

  // Initialises LibBFD and opens the binary
  bfd_init();
  BfdHandle = bfd_openr(BinaryPath, NULL);
  assert(bfd_check_format(BfdHandle, bfd_object) &&
         "Given file does not look like a valid ELF file");

  // Seeds the PRNG (we'll use it in getRandomSymbol());
  srand(time(NULL));

  dumpGadgets();
}

BinaryAutopsy *BinaryAutopsy::instance = 0;

BinaryAutopsy *BinaryAutopsy::getInstance(string path) {
  if (instance == 0) {
    instance = new BinaryAutopsy(path);
  }

  return instance;
}

void BinaryAutopsy::dumpSections() {
  int flags;
  asection *s;
  uint64_t vma, size;
  const char *sec_name;

  cout << "[*] Looking for CODE sections... \n";

  // Iterates through all the sections, picking only the ones that contain
  // executable code
  for (s = BfdHandle->sections; s; s = s->next) {
    flags = bfd_get_section_flags(BfdHandle, s);

    if (flags & SEC_CODE) {
      vma = bfd_section_vma(BfdHandle, s);
      size = bfd_section_size(BfdHandle, s);
      sec_name = bfd_section_name(BfdHandle, s);

      if (!sec_name)
        sec_name = "<unnamed>";

      Sections.push_back(Section(sec_name, vma, size));
    }
  }
}

void BinaryAutopsy::dumpDynamicSymbols() {
  const char *symbolName;
  size_t addr, size, nsym;

  // Dumps sections if it wasn't already done
  if (Sections.size() == 0)
    dumpSections();

  cout << "[*] Scanning for symbols... \n";

  // Allocate memory and get the symbol table
  size = bfd_get_dynamic_symtab_upper_bound(BfdHandle);
  auto **asymtab = static_cast<asymbol **>(malloc(size));
  nsym = bfd_canonicalize_dynamic_symtab(BfdHandle, asymtab);

  // Scan for all the symbols
  for (size_t i = 0; i < nsym; i++) {
    asymbol *sym = asymtab[i];

    // Consider only function symbols with global scope
    if ((sym->flags & BSF_FUNCTION) && (sym->flags & BSF_GLOBAL)) {
      symbolName = bfd_asymbol_name(sym);

      if (strcmp(symbolName, "_init") == 0 || strcmp(symbolName, "_fini") == 0)
        continue;

      addr = bfd_asymbol_value(sym);

      // Get version string to avoid symbol aliasing
      const char *versionString = NULL;
      bfd_boolean hidden = false;
      // TODO: if version = Base, then skip
      if ((sym->flags & (BSF_SECTION_SYM | BSF_SYNTHETIC)) == 0)
        versionString = bfd_get_symbol_version_string(BfdHandle, sym, &hidden);

      Symbol s = Symbol(symbolName, versionString, addr);
      // printf("Found symbol: %s at %#08x\n", symbolName, addr);
      Symbols.push_back(s);
    }
  }

  free(asymtab);
  cout << "[*] Found " << Symbols.size() << " symbols\n";

  assert(Symbols.size() > 0 && "No symbols found!");
}

Symbol *BinaryAutopsy::getRandomSymbol() {
  // Dumps the dynamic symbol table if it wasn't already done
  if (Symbols.size() == 0)
    dumpDynamicSymbols();

  unsigned long i = rand() % Symbols.size();
  return &(Symbols.at(i));
}

void BinaryAutopsy::dumpGadgets() {
  uint8_t ret[] = "\xc3";

  // capstone stuff
  csh handle;
  cs_insn *instructions;

  //  assert(getLibcPath(libcPath));

  // Dumps sections if it wasn't already done
  if (Sections.size() == 0)
    dumpSections();

  // Initizialises capstone engine
  cs_open(CS_ARCH_X86, CS_MODE_32, &handle);
  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
  cout << "[*] Looking for gadgets in " << BinaryPath << "\n";

  ifstream input_file(BinaryPath, ios::binary);
  assert(input_file.good() && "Unable to open given binary file!");

  // Get input size
  input_file.seekg(0, ios::end);
  streamoff input_size = input_file.tellg();
  cout << "[*] Scanning the whole binary (" << input_size << " bytes) ...\n";

  // Read the whole file
  input_file.seekg(0, ios::beg);
  uint8_t *buf = new uint8_t[input_size];
  input_file.read(reinterpret_cast<char *>(buf), input_size);

  for (auto &s : Sections) {
    cout << "[*] Searching gadgets in section " + s.Label + " ... ";
    int cnt = 0;

    // Scan for RET instructions
    for (uint64_t i = s.Address;
         i < static_cast<uint64_t>(s.Address + s.Length); i++) {

      if (buf[i] == *ret) {
        size_t offset = i + 1;
        uint8_t *cur_pos = buf + offset;

        // Iteratively try to decode starting from (MAXDEPTH to 0)
        // instructions before the actual RET
        for (int depth = MAXDEPTH; depth >= 0; depth--) {

          size_t count = cs_disasm(handle, cur_pos - depth, depth,
                                   offset - depth, depth, &instructions);

          // Valid gadgets must have two instructions, and the
          // last one must be a RET
          if (count == 2 && instructions[count - 1].id == X86_INS_RET) {

            // Each gadget is identified with its mnemonic
            // and operators (ugly but straightforward :P)
            string asm_instr;
            for (size_t j = 0; j < count - 1; j++) {
              asm_instr += instructions[j].mnemonic;
              asm_instr += " ";
              asm_instr += instructions[j].op_str;
              asm_instr += ";";
            }

            if (!gadgetLookup(asm_instr)) {
              Microgadgets.push_back(Microgadget(instructions, asm_instr));

              cnt++;
            }
          }
        }
      }
    }
    cout << cnt << " found!\n";
  }
  delete[] buf;
  input_file.close();

  cout << "[*] Found " << Microgadgets.size() << " unique microgadgets!\n";

  /*for (auto const &gadget : Microgadgets) {
    cout << "0x" << gadget.getAddress() << ":   \t" << gadget.asmInstr << "\n";
  }*/

  auto xpath = XchgGraph();
  xpath.addEdge(0, 1);
  xpath.addEdge(1, 2);
  xpath.generateCode(0, 2);
}

Microgadget *BinaryAutopsy::gadgetLookup(string asmInstr) {
  // Legacy: lookup by asm_instr string
  if (Microgadgets.size() > 0) {
    for (auto &g : Microgadgets) {
      if (g.asmInstr.compare(asmInstr) == 0)
        return &g;
    }
  }
  return nullptr;
}

std::vector<Microgadget *>