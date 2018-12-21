//
// ROPseeker engine aims to find gadgets within a given binary.
//

#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <dirent.h>
#include <fstream>
#include <map>
#include <vector>
#include <bfd.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

// Max bytes before the RET to be examined
#define MAXDEPTH 4
using namespace std;

string POSSIBLE_LIBC_FOLDERS[] = {"/lib", "/usr/lib", "/usr/local/lib"};

struct Gadget {
  size_t length;
  cs_insn *instructions;
  uint64_t address;
  string symbolName;

  Gadget(size_t length, cs_insn *instructions, uint64_t address, string symbolName)
      : length(length), instructions(instructions), address(address), symbolName(symbolName){};
};

struct Symbol {
  string name;
  uint64_t address;

  Symbol(string name, uint64_t address) : name(name), address(address){};
};

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
    if (!strcmp(entry->d_name, "libc.so.6")) {
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

vector<Symbol> getDynamicSymbols(char *path) {
  vector<Symbol> dynamicSymbols;
  const char *symbolName;
  size_t addr, size, nsym;

  /* Open binary file */
  bfd_init();
  bfd *bfd_h = bfd_openr(path, NULL);
  assert(bfd_check_format(bfd_h, bfd_object) &&
         "file '%s' does not look like an executable");

  /* Allocate memory and get the symbol table */
  size = bfd_get_dynamic_symtab_upper_bound(bfd_h);
  asymbol **asymtab = static_cast<asymbol**>(malloc(size));
  nsym = bfd_canonicalize_dynamic_symtab(bfd_h, asymtab);

  /* Scan for all the symbols */
  for (size_t i = 0; i < nsym; i++) {
    symbolName = bfd_asymbol_name(asymtab[i]);
    addr = bfd_asymbol_value(asymtab[i]);
    if (addr < 0x100)
      continue;

    Symbol s = Symbol(symbolName, addr);
    dynamicSymbols.push_back(s);
  }

  free(asymtab);
  return dynamicSymbols;
}

Symbol getRandomSymbol(vector<Symbol> dynamicSymbols) {
  unsigned long i = rand() % dynamicSymbols.size();

  return dynamicSymbols.at(i);
}

map<string, Gadget *> findGadgets() {
  const uint8_t ret[] = "\xc3";
  string libcPath;
  csh handle;
  cs_insn *instructions;
  map<string, Gadget *> gadgets;
  srand (time(NULL));

  assert(getLibcPath(libcPath) == true);
  vector<Symbol> dynamicSymbols = getDynamicSymbols("/lib/i386-linux-gnu/libc.so.6");

  assert((cs_open(CS_ARCH_X86, CS_MODE_32, &handle) == CS_ERR_OK) &&
         "Unable to initialise capstone-engine");

  string pane = dynamicSymbols.at(4).name;
  llvm::dbgs() << pane;
  llvm::dbgs() << "[*] Looking for gadgets in " << libcPath << "\n";
  ifstream input_file(libcPath, ios::binary);

  assert(input_file.good() && "Unable to find libc!");

  // Get input size
  input_file.seekg(0, ios::end);
  streamoff input_size = input_file.tellg();
  llvm::dbgs() << "[*] Reading binary (" << input_size << " bytes) ...\n";

  // Read the whole file
  input_file.seekg(0, ios::beg);

  uint8_t *buf = new uint8_t[input_size];
  input_file.read(reinterpret_cast<char *>(buf), input_size);

  // Scan for RET instructions
  for (uint64_t i = 0; i < static_cast<uint64_t>(input_size); i++) {
    if (buf[i] == *ret) {

      size_t offset = i + 1;
      uint8_t *cur_pos = buf + offset;

      // Iteratively try to decode starting from (MAXDEPTH to 0) instructions
      // before the actual RET
      for (int depth = MAXDEPTH; depth >= 0; depth--) {

        size_t count = cs_disasm(handle, cur_pos - depth, depth, offset - depth,
                                 depth, &instructions);

        // Valid gadgets must have at least two instructions, and the
        // last one must be a RET
        if (count >= 2) {
          if (instructions[count - 1].id == X86_INS_RET) {

            // Each gadget is identified with its mnemonic
            // ans operators within the map (ugly but straightforward :P)
            string asm_instr;
            for (size_t j = 0; j < count - 1; j++) {
              asm_instr += instructions[j].mnemonic;
              asm_instr += " ";
              asm_instr += instructions[j].op_str;
              asm_instr += ";";
            }
            Symbol s = getRandomSymbol(dynamicSymbols);
            auto *g = new Gadget(count, instructions, instructions[0].address - s.address, s.name);
            gadgets[asm_instr] = g;
          }
        }
      }
    }
  }

  input_file.close();

  llvm::dbgs() << "[*] Found " << gadgets.size() << " gadgets!\n";

  /*for (auto const &gadget : gadgets) {
     dbgs() << "0x"  << (*gadget.second).address << ":   \t" << gadget.first
  <<
  "\n");
  }*/

  return gadgets;
}