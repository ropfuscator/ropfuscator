#include <string>

#ifndef SECTION_H
#define SECTION_H

// Section - section data dumped from the ELF header
struct Section {
  // Label - section name
  std::string Label;

  // Address - offset relative to the analysed binary file.
  // Length - Size of the section.
  uint64_t Address, Length;

  // Constructor
  Section(std::string label, uint64_t address, uint64_t length)
    : Label(label), Address(address), Length(length) {}
};


#endif