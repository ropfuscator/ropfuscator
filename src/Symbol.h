// Symbol - entry of the dynamic symbol table. We use them as references
#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <string>

#ifndef SYMBOL_H
#define SYMBOL_H

namespace ropf {

// to locate the needed gadgets.
struct Symbol {
  // Label - symbol name.
  std::string Label;

  // Version - this is mostly useful when dealing with libc, because within it
  // there are lots of symbols with the same label. GNU LIBC uses versioning to
  // ensure compatibility with binaries using old ABI versions.
  std::string Version;

  // Address - offset relative to the analysed binary file. When we'll reference
  // a gadget in memory we'll use this as base address.
  uint64_t Address;

  mutable bool isUsed;

  // Constructor
  Symbol(std::string label, std::string version, uint64_t address)
      : Label(label), Version(version), Address(address), isUsed(false) {}

  // SymVerDirective - it is just an inline asm directive we need to place to
  // force the static linker to pick the right symbol version during the
  // compilation.
  std::string getSymverDirective() const {
    if (!Version.empty()) {
      return fmt::format(".symver {},{}@{}", Label, Label, Version);
    }
    return "";
  }
};

} // namespace ropf

#endif