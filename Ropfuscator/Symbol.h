// Symbol - entry of the dynamic symbol table. We use them as references
#include <sstream>
#include <string.h>
#include <string>

#ifndef SYMBOL_H
#define SYMBOL_H

// to locate the needed gadgets.
struct Symbol {
  // Label - symbol name.
  std::string Label;

  // Version - this is mostly useful when dealing with libc, because within it
  // there are lots of symbols with the same label. GNU LIBC uses versioning to
  // ensure compatibility with binaries using old ABI versions.
  std::string Version;

  // SymVerDirective - it is just an inline asm directive we need to place to
  // force the static linker to pick the right symbol version during the
  // compilation.
  mutable char *SymVerDirective;

  // Address - offset relative to the analysed binary file. When we'll reference
  // a gadget in memory we'll use this as base address.
  uint64_t Address;

  // Constructor
  Symbol(std::string label, std::string version, uint64_t address)
      : Label(label), Version(version), Address(address) {
    SymVerDirective = nullptr;
  }

  // getSymVerDirective - returns a pointer to the SymVerDirective string.
  const char *getSymVerDirective() const {
    if (SymVerDirective == nullptr) {
      std::stringstream ss;

      ss << ".symver " << Label << "," << Label << "@" << Version;

      SymVerDirective = new char[ss.str().length() + 1];

      strcpy(SymVerDirective, ss.str().c_str());
    }

    return SymVerDirective;
  }

  // TODO: free heap for Label, Version, SymVerDirective
};

#endif