//
// ROPseeker engine aims to find gadgets within a given binary.
//
#define PACKAGE "ropfuscator" /* see https://bugs.gentoo.org/428728 */

#include <bfd.h>
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <dirent.h>
#include <fstream>
#include <iostream>
#include <map>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <vector>

// Max bytes before the RET to be examined
#define MAXDEPTH 3
using namespace std;
struct Symbol;
struct Section;

string POSSIBLE_LIBC_FOLDERS[] = {"/lib", "/usr/lib", "/usr/local/lib"};
vector<Symbol> symbols;
vector<Section> sections;

struct Symbol {
  string name;
  string version;
  uint64_t address;
  string symVer;

  Symbol(string name, string version, uint64_t address)
      : name(name), version(version), address(address) {
    symVer = ".symver ";
    symVer += name;
    symVer += ",";
    symVer += name;
    symVer += "@";
    symVer += version;
  };
};

struct Gadget {
  size_t length;
  cs_insn *instructions;
  uint64_t address;

  Gadget(size_t length, cs_insn *instructions, uint64_t address)
      : length(length), instructions(instructions), address(address){};
};

struct Section {
  string name;
  uint64_t address, size;

  Section(string name, uint64_t address, uint64_t size)
      : name(name), address(address), size(size){};
};

Symbol *getRandomSymbol() {
  unsigned long i = rand() % symbols.size();
  return &(symbols.at(i));
}

// TODO: plz improve me
bool recurseLibcDir(const char *path, string &libcPath, uint current_depth) {
  DIR *dir;
  struct dirent *entry;

  if (!current_depth) {
    return false;
  }

  dir = opendir(path);

  if (dir == NULL)
    return false;

  // searching for libc in regular files only
  while ((entry = readdir(dir)) != NULL) {
    if (!strcmp(entry->d_name, "libc.so")) {
      libcPath += path;
      libcPath += "/";
      libcPath += entry->d_name;

      // llvm::dbgs() << "libc found here: " << libcPath << "\n";

      return true;
    }
  }

  // could not find libc, recursing into directories
  dir = opendir(path);

  if (dir == NULL)
    return false;

  while ((entry = readdir(dir)) != NULL) {
    // must be a dir and not "." or ".."
    if (entry->d_type == DT_DIR && strcmp(entry->d_name, ".") &&
        strcmp(entry->d_name, "..")) {

      // constructing path to dir
      string newpath = std::string();

      newpath += path;
      newpath += "/";
      newpath += entry->d_name;

      // llvm::dbgs() << "recursing into: " << newpath << "\n";

      // recurse into dir
      if (recurseLibcDir(newpath.c_str(), libcPath, current_depth - 1))
        return true;
    }
  }

  return false;
}

// TODO: plz improve me
bool getLibcPath(string &libcPath) {
  uint maxrecursedepth = 3;

  libcPath.clear();

  for (auto &folder : POSSIBLE_LIBC_FOLDERS) {
    if (recurseLibcDir(folder.c_str(), libcPath, maxrecursedepth))
      return true;
  }
  return false;
}

int getSections(bfd *bfd_h) {
  int flags;
  asection *s;
  uint64_t vma, size;
  const char *sec_name;

  llvm::dbgs() << "[*] Looking for CODE sections... \n";

  // Iterate through all the sections, picking only the ones that contain
  // executable code
  for (s = bfd_h->sections; s; s = s->next) {
    flags = bfd_get_section_flags(bfd_h, s);

    if (flags & SEC_CODE) {
      vma = bfd_section_vma(bfd_h, s);
      size = bfd_section_size(bfd_h, s);
      sec_name = bfd_section_name(bfd_h, s);

      if (!sec_name)
        sec_name = "<unnamed>";

      sections.push_back(Section(sec_name, vma, size));
      // printf("Found code section <%s> at %#08llx [%d bytes]\n", sec_name,
      // vma, size);
    }
  }
  return 0;
}

void initBfd(string &libcPath, bfd *&bfd_h) {
  // Opens the binary file and returns a BFD handle
  bfd_init();
  const char *path = libcPath.c_str();
  bfd_h = bfd_openr(path, NULL);
}

void getDynamicSymbols(bfd *bfd_h) {
  const char *symbolName;
  size_t addr, size, nsym;

  llvm::dbgs() << "[*] Scanning for symbols... \n";

  // Allocate memory and get the symbol table
  size = bfd_get_dynamic_symtab_upper_bound(bfd_h);
  auto **asymtab = static_cast<asymbol **>(malloc(size));
  nsym = bfd_canonicalize_dynamic_symtab(bfd_h, asymtab);

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
      if ((sym->flags & (BSF_SECTION_SYM | BSF_SYNTHETIC)) == 0)
        versionString = bfd_get_symbol_version_string(bfd_h, sym, &hidden);

      Symbol s = Symbol(symbolName, versionString, addr);
      // printf("Found symbol: %s at %#08x\n", symbolName, addr);
      symbols.push_back(s);
    }
  }

  free(asymtab);

  assert(symbols.size() > 0 && "No symbols found!");
}

map<string, Gadget *> findGadgets() {
  const uint8_t ret[] = "\xc3";
  string libcPath;
  map<string, Gadget *> gadgets;

  // capstone stuff
  csh handle;
  cs_insn *instructions;

  srand(time(NULL));

  assert(getLibcPath(libcPath));

  // bfd
  bfd *bfd_h;
  initBfd(libcPath, bfd_h);
  assert(bfd_check_format(bfd_h, bfd_object) &&
         "Given file does not look like a valid ELF file");

  // Gets executable sections from the library file
  getSections(&(*bfd_h));

  // Get symbols from .dynsym table, to use them for symbol hooking
  getDynamicSymbols(&(*bfd_h));
  llvm::dbgs() << "[*] Found " << symbols.size() << " symbols\n";

  assert((cs_open(CS_ARCH_X86, CS_MODE_32, &handle) == CS_ERR_OK) &&
         "Unable to initialise capstone-engine");
  llvm::dbgs() << "[*] Looking for gadgets in " << libcPath << "\n";

  ifstream input_file(libcPath, ios::binary);
  assert(input_file.good() && "Unable to find libc!");

  // Get input size
  input_file.seekg(0, ios::end);
  streamoff input_size = input_file.tellg();
  llvm::dbgs() << "[*] Scanning the whole binary (" << input_size
               << " bytes) ...\n";

  // Read the whole file
  input_file.seekg(0, ios::beg);
  uint8_t *buf = new uint8_t[input_size];
  input_file.read(reinterpret_cast<char *>(buf), input_size);

  for (auto &s : sections) {
    llvm::dbgs() << "[*] Searching gadgets in section " + s.name + " ... ";
    int cnt = 0;

    // Scan for RET instructions
    for (uint64_t i = s.address; i < static_cast<uint64_t>(s.address + s.size);
         i++) {

      if (buf[i] == *ret) {
        // llvm::dbgs() << "    ret @ " << i;
        size_t offset = i + 1;
        uint8_t *cur_pos = buf + offset;

        // Iteratively try to decode starting from (MAXDEPTH to 0) instructions
        // before the actual RET
        for (int depth = MAXDEPTH; depth >= 0; depth--) {

          size_t count = cs_disasm(handle, cur_pos - depth, depth,
                                   offset - depth, depth, &instructions);

          // Valid gadgets must have at least two instructions, and the
          // last one must be a RET
          if (count >= 2 && instructions[count - 1].id == X86_INS_RET) {

            // Each gadget is identified with its mnemonic
            // and operators (ugly but straightforward :P)
            string asm_instr;
            for (size_t j = 0; j < count - 1; j++) {
              asm_instr += instructions[j].mnemonic;
              asm_instr += " ";
              asm_instr += instructions[j].op_str;
              asm_instr += ";";
            }

            auto *g = new Gadget(count, instructions, instructions[0].address);
            gadgets[asm_instr] = g;
            cnt++;
          }
        }
      }
    }
    llvm::dbgs() << cnt << " found!\n";
  }
  free(buf);
  input_file.close();

  llvm::dbgs() << "[*] Found " << gadgets.size() << " gadgets!\n";

  /*for (auto const &gadget : gadgets) {
     dbgs() << "0x"  << (*gadget.second).address << ":   \t" << gadget.first
  <<
  "\n");
  }*/

  return gadgets;
}