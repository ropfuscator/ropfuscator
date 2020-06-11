
#include <string>
#include <map>
#include <vector>
#include <iostream>

#include <elfio/elfio.hpp>

#include "elfanalysis.hpp"

using namespace ELFIO;

static void get_symbol_table(const elfio &elf, const char *sectname, symbol_table &symtab) {
  symtab.name_to_index.clear();
  symtab.addr_to_index.clear();
  symtab.index_to_name.clear();
  symtab.index_to_version.clear();

  section *sec = elf.sections[sectname];
  if (sec == nullptr) {
    return;
  }
  const_symbol_section_accessor symtab_access(elf, sec);
  std::string sym_name;
  Elf64_Addr sym_value;
  Elf_Xword sym_size;
  unsigned char sym_bind;
  unsigned char sym_type;
  Elf_Half sym_section_index;
  unsigned char sym_other;
  for (unsigned int i = 0; i < symtab_access.get_symbols_num(); i++) {
    symtab_access.get_symbol(i, sym_name, sym_value, sym_size, sym_bind, sym_type, sym_section_index, sym_other);
    
    symtab.name_to_index[sym_name] = i;
    symtab.addr_to_index[sym_value] = i;
    symtab.index_to_name.push_back(sym_name);
    symtab.index_to_addr.push_back(sym_value);
  }
}

static void get_relocation_table(const elfio &elf, const char *sectname, relocation_table &reltab) {
  reltab.addr_to_symbol.clear();
  reltab.addr_to_index.clear();
  reltab.index_to_addr.clear();
  reltab.index_to_type.clear();
  section *sec = elf.sections[sectname];
  if (sec == nullptr) {
    return;
  }
  const_relocation_section_accessor relsec(elf, sec);
  Elf64_Addr rel_offset;
  Elf_Word rel_symbol;
  Elf_Word rel_type;
  Elf_Sxword rel_addend;
  int rel_ent_count = relsec.get_entries_num();
  for (Elf_Xword i = 0; i < rel_ent_count; i++) {
    relsec.get_entry(i, rel_offset, rel_symbol, rel_type, rel_addend);
    reltab.addr_to_symbol[rel_offset] = rel_symbol;
    reltab.addr_to_index[rel_offset] = i;
    reltab.index_to_addr.push_back(rel_offset);
    reltab.index_to_type.push_back(rel_type);
  }
}

struct ELF_GNU_Verdef {
  Elf_Half version;
  Elf_Half flags;
  Elf_Half ndx;
  Elf_Half cnt;
  Elf_Word hash;
  Elf_Word aux;
  Elf_Word next;
};

struct ELF_GNU_VerdefAux {
  Elf_Word name;
  Elf_Word next;
};

struct ELF_GNU_Verneed {
  Elf_Half version;
  Elf_Half cnt;
  Elf_Word file;
  Elf_Word aux;
  Elf_Word next;
};

struct ELF_GNU_VerneedAux {
  Elf_Word hash;
  Elf_Half flags;
  Elf_Half other;
  Elf_Word name;
  Elf_Word next;
};

static Elf_Half get_ver_index(const ELF_GNU_Verdef *p, const ELF_GNU_VerdefAux *q) {
  return p->ndx;
}

static Elf_Half get_ver_index(const ELF_GNU_Verneed *p, const ELF_GNU_VerneedAux *q) {
  return q->other;
}

template<typename VerXXX, typename VerXXXAux>
void get_gnu_version_table(const elfio &elf, const char *sectname, const char *strtabname, std::map<int, std::string> &ver_index) {
  const auto &convertor = elf.get_convertor();
  section *sec = elf.sections[sectname];
  section *strtabsec = elf.sections[strtabname];
  if (sec == nullptr || strtabsec == nullptr) {
    return;
  }
  const_string_section_accessor strtab(strtabsec);
  const char *data = sec->get_data();
  unsigned int section_size = sec->get_size();
  for (unsigned int offset = 0; offset <= section_size - sizeof(VerXXX);) {
    const VerXXX *p = reinterpret_cast<const VerXXX *>(data + offset);
    Elf_Half version = convertor(p->version);
    Elf_Word aux = convertor(p->aux);
    if (aux) {
      for (unsigned int offset2 = offset + aux; offset2 <= section_size - sizeof(VerXXXAux); ) {
        const VerXXXAux *q = reinterpret_cast<const VerXXXAux *>(data + offset2);
        std::string vername = strtab.get_string(q->name);
        Elf_Half idx = get_ver_index(p, q);
        if (ver_index.find(idx) == ver_index.end()) {
          ver_index[idx] = vername;
        }
        Elf32_Word next = convertor(q->next);
        if (next == 0) break;
        offset2 += next;
      }
    }
    Elf32_Word next = convertor(p->next);
    if (next == 0) break;
    offset += next;
  }
}

static void get_gnu_verdef_table(const elfio &elf, std::map<int, std::string> &ver_index) {
  get_gnu_version_table<ELF_GNU_Verdef, ELF_GNU_VerdefAux>(elf, ".gnu.version_d", ".dynstr", ver_index);
}

static void get_gnu_verneed_table(const elfio &elf, std::map<int, std::string> &ver_index) {
  get_gnu_version_table<ELF_GNU_Verneed, ELF_GNU_VerneedAux>(elf, ".gnu.version_r", ".dynstr", ver_index);
}

static void get_gnu_symvers(const elfio &elf, const char *sectname, const std::map<int, std::string> &ver_index, std::vector<std::string> &symver_index) {
  const auto &convertor = elf.get_convertor();
  section *sec = elf.sections[sectname];
  if (sec == nullptr) {
    return;
  }
  const char *data = sec->get_data();
  unsigned int section_size = sec->get_size();
  for (unsigned int offset = 0; offset <= section_size - sizeof(Elf_Half); offset += sizeof(Elf_Half)) {
    Elf_Half idx = *reinterpret_cast<const Elf_Half *>(data + offset);
    std::string emptystr;
    idx = idx & 0x7fff;
    const auto &it = ver_index.find(idx);
    const std::string &ver = it != ver_index.end() ? it->second : emptystr;
    symver_index.push_back(ver);
  }
}

// ========== ElfAnalysis ==========

void ElfAnalysis::analyse_symtab() {
  get_symbol_table(elf, ".symtab", symtab);
  get_symbol_table(elf, ".dynsym", dynsym);
  if (debug) {
    std::cout << "==================== .symtab of " << filename << std::endl;
    for (const auto &kv : symtab.name_to_index) {
      std::cout << kv.first << " " << std::hex << "0x" << symtab.index_to_addr[kv.second] << std::dec << std::endl;
    }
    std::cout << "==================== .dynsym of " << filename << std::endl;
    for (const auto &kv : dynsym.name_to_index) {
      std::cout << kv.first << " " << std::hex << "0x" << dynsym.index_to_addr[kv.second] << std::dec << std::endl;
    }
  }
}


void ElfAnalysis::analyse_gnu_version() {
  get_gnu_verneed_table(elf, verdefs);
  get_gnu_verdef_table(elf, verdefs);
  if (debug) {
    std::cout << "==================== .gnu.version_d/r of " << filename << std::endl;
    for (const auto &ver : verdefs) {
      std::cout << ver.first << ": " << ver.second << std::endl;
    }
  }

  get_gnu_symvers(elf, ".gnu.version", verdefs, dynsym.index_to_version);
  for (unsigned int i = 1; i < dynsym.index_to_name.size(); i++) {
    // index 0: undefined symbol, so we start with index 1
    const std::string& name = dynsym.index_to_name[i];
    const std::string& ver = dynsym.index_to_version[i];
    dynsym.namever_to_index[symbol_name(name, ver)] = i;
  }
  if (debug) {
    std::cout << "==================== .gnu.version / .dynsym of " << filename << std::endl;
    for (int i = 0; i < dynsym.index_to_version.size(); i++) {
      std::cout << i << ": " << dynsym.index_to_name[i] << " @ " << dynsym.index_to_version[i]
                << " @ 0x" << std::hex << dynsym.index_to_addr[i] << std::dec << std::endl;
    }
  }
}


void ElfAnalysis::analyse_relocation() {
  get_relocation_table(elf, ".rel.dyn", reldyn);
  if (reldyn.addr_to_symbol.empty()) {
    get_relocation_table(elf, ".rela.dyn", reldyn);
  }
  if (debug) {
    std::cout << "==================== .rel(a).dyn " << std::endl;
    for (const auto &kv : reldyn.addr_to_symbol) {
      std::cout << std::hex << "0x" << kv.first << std::dec << " symbol#" << kv.second
                << " = " <<  dynsym.index_to_name[kv.second]
                << " @ " << dynsym.index_to_version[kv.second]
                << " @ 0x" << std::hex << dynsym.index_to_addr[kv.second] << std::dec << std::endl;
    }
  }
}


const char *ElfAnalysis::find_code_at(int64_t addr) {
  int sec_count = elf.sections.size();
  for (int i = 0; i < sec_count; i++) {
    auto *section = elf.sections[i];
    Elf64_Addr begin = section->get_address();
    Elf_Xword size = section->get_size();
    if (begin <= addr && addr < begin + size) {
      return section->get_data() + static_cast<int>(addr - begin);
    }
  }
  return nullptr;
}


bool ElfAnalysis::find_reloc_at(int64_t addr, uint32_t &rtype, symbol_name &name) const {
  auto it = reldyn.addr_to_symbol.find(addr);
  if (it != reldyn.addr_to_symbol.end()) {
    name = dynsym.index_to_namever(it->second);
    rtype = reldyn.index_to_type[reldyn.addr_to_index.find(addr)->second];
    return true;
  } else {
    return false;
  }
}


// ========== ElfModifier ==========

char *ElfModifier::get_modifiable_memory(int64_t addr) {
  int sec_count = elf.sections.size();
  for (int i = 0; i < sec_count; i++) {
    section *s = elf.sections[i];
    Elf64_Addr begin = s->get_address();
    Elf_Xword size = s->get_size();
    if (begin <= addr && addr < begin + size) {
      int offset = addr - begin;
      if (!sectiondata[i]) {
        auto *newdata = new std::vector<char>(s->get_size());
        sectiondata[i].reset(newdata);
        memcpy(&(*newdata)[0], s->get_data(), s->get_size());
      }
      return &(*sectiondata[i])[offset];
    }
  }
  return nullptr;
}


void ElfModifier::commit_modifications() {
  int sec_count = elf.sections.size();
  for (int i = 0; i < sec_count; i++) {
    if (sectiondata[i]) {
      section *s = elf.sections[i];
      const std::vector<char> &data = *sectiondata[i];
      s->set_data(&data[0], data.size());
      sectiondata[i].reset();
    }
  }
}
