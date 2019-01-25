//
// SymExtractor
// Extracts dynamic symbols related only to sections of executable code
//
#define PACKAGE "ropfuscator" /* see https://bugs.gentoo.org/428728 */

#include <bfd.h>
#include <cstring>
#include <iostream>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <vector>

using namespace std;

struct Symbol;
struct Section;
struct Gadget;

vector<Symbol> symbols;
vector<Section> sections;

struct Symbol {
  // string name;
  char *name;
  char *version;
  char *symVerDirective;
  uint64_t address;

  Symbol(string symName, string symVersion, uint64_t address)
      : address(address) {
    name = new char[symName.length() + 1];
    version = new char[symVersion.length() + 1];
    strcpy(name, symName.c_str());
    strcpy(version, symVersion.c_str());
  };

  char *getSymVerDirective() {
    stringstream ss;
    ss << ".symver " << name << "," << name << "@" << version;
    symVerDirective = new char[ss.str().length() + 1];
    strcpy(symVerDirective, ss.str().c_str());
    return symVerDirective;
  }
};

struct Section {
  string name;
  uint64_t address, size;

  Section(string name, uint64_t address, uint64_t size)
      : name(name), address(address), size(size){};
};

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

Symbol *getRandomSymbol() {
  unsigned long i = rand() % symbols.size();
  return &(symbols.at(i));
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