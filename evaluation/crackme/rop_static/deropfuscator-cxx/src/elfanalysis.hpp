#ifndef ELFANALYSIS_HPP_INCLUDED
#define ELFANALYSIS_HPP_INCLUDED

#include <cstdint>
#include <utility>
#include <string>
#include <map>
#include <vector>
#include <memory>

#include <elfio/elfio.hpp>

// symbol name, represented in (name, version string) pair
typedef std::pair<std::string, std::string> symbol_name;

// .symtab and .dynsym analysis result
struct symbol_table {
  // map from address to symtab index
  std::map<int64_t, unsigned int> addr_to_index;
  // map from symbol name to symtab index
  std::map<std::string, unsigned int> name_to_index;
  // map from symtab index to address
  std::vector<int64_t> index_to_addr;
  // map from symtab index to symbol name
  std::vector<std::string> index_to_name;
  // map from symtab index to symbol version string
  std::vector<std::string> index_to_version;
  // map from (name, version) pair to symtab index
  std::map<symbol_name, unsigned int> namever_to_index;
  // map from index to (name, version)
  symbol_name index_to_namever(unsigned int i) const {
    return symbol_name(index_to_name[i], index_to_version[i]);
  }
};

// .rel.dyn analysis result
struct relocation_table {
  // map from relocated address to symtab index
  std::map<int64_t, int> addr_to_symbol;
  // map from relocated address to relocation table index
  std::map<int64_t, int> addr_to_index;
  // map from relocation table index to relocated address
  std::vector<int64_t> index_to_addr;
  // map from relocation table index to relocation type
  std::vector<int32_t> index_to_type;
};


// analyse ELF data
class ElfAnalysis
{
public:
  bool debug;
  ELFIO::elfio elf;
  std::string filename;
  symbol_table symtab;
  symbol_table dynsym;
  std::map<int, std::string> verdefs;
  relocation_table reldyn;

  ElfAnalysis() {
    debug = true;
  }

  bool load(const char *filename_) {
    filename = filename_;
    return elf.load(filename_);
  }

  // run all required analysis
  void analyse() {
    analyse_symtab();
    analyse_gnu_version();
    analyse_relocation();
  }

  // find code at the given address
  const char *find_code_at(int64_t addr);

  // find relocation to the given address
  bool find_reloc_at(int64_t addr, uint32_t &rtype, symbol_name &name) const;

private:
  // analyse .symtab and .dynsym
  void analyse_symtab();
  // analyse .gnu.version, .gnu.version_d and .gnu.version_r
  void analyse_gnu_version();
  // analyse .rel.dyn
  void analyse_relocation();
};


// modify ELF data
class ElfModifier
{
  ELFIO::elfio &elf;
  std::vector<std::shared_ptr<std::vector<char>>> sectiondata;

public:
  explicit ElfModifier(ElfAnalysis &elf_)
    : elf(elf_.elf), sectiondata(elf_.elf.sections.size()) {}

  // get a pointer to a memory where any modification to the memory
  // is staged for ELF file modification.
  // the staged modifications should be committed by commit_modifications().
  char *get_modifiable_memory(int64_t addr);

  // commit all the modifications made by get_modifiable_memory().
  void commit_modifications();
};

#endif // ELFANALYSIS_HPP_INCLUDED
