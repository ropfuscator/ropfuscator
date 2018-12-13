//
// ROPseeker engine aims to find gadgets within a given binary.
//

#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <fstream>
#include <map>
#include <filesystem>

// Max bytes before the RET to be examined
#define MAXDEPTH 4

// TODO: find other paths
#define LIBC_PATH "/lib/i386-linux-gnu/libc.so.6"

using namespace std;

struct Gadget {
  size_t length;
  cs_insn *instructions;
  uint64_t address;

  Gadget(size_t length, cs_insn *instructions, uint64_t address)
      : length(length), instructions(instructions), address(address){};
};

map<string, Gadget *> findGadgets() {
  const uint8_t ret[] = "\xc3";
  csh handle;
  cs_insn *instructions;
  map<string, Gadget *> gadgets;
  assert((cs_open(CS_ARCH_X86, CS_MODE_32, &handle) == CS_ERR_OK) &&
         "Unable to initialise capstone-engine");

  llvm::dbgs() << "[*] Looking for gadgets in " << LIBC_PATH << "\n";
  ifstream input_file(LIBC_PATH, ios::binary);

  assert(input_file.good() && "Unable to find libc!");

  // Get input size
  input_file.seekg(0, ios::end);
  streamoff input_size = input_file.tellg();
  llvm::dbgs() << "[*] Reading binary (" << input_size << " bytes) ...\n";

  // Read the whole file
  input_file.seekg(0, ios::beg);

  // TODO: move to heap
  uint8_t buf[input_size];
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

            auto *g = new Gadget(count, instructions, instructions[0].address);
            gadgets[asm_instr] = g;
          }
        }
      }
    }
  }

  input_file.close();

  llvm::dbgs() << "[*] Found " << gadgets.size() << " gadgets!\n";

  /*for (auto const &gadget : gadgets) {
     dbgs() << "0x"  << (*gadget.second).address << ":   \t" << gadget.first <<
  "\n");
  }*/

  return gadgets;
}