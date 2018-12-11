// ROPseeker engine aims to find gadgets within a given binary.


#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <vector>
#include <map>

#define MAXDEPTH 4

using namespace std;

struct Gadget {
    size_t length;
    cs_insn* instructions;
    unsigned address;

    Gadget(size_t length, cs_insn* instructions, unsigned address) :
            length(length),
            instructions(instructions),
            address(address){};

};



map<string, Gadget*> findGadgets() {
    const uint8_t ret[] = "\xc3";
    csh handle;
    cs_insn *instructions;
    map<string, Gadget*> gadgets;
    assert ((cs_open(CS_ARCH_X86, CS_MODE_32, &handle) == CS_ERR_OK)
            && "Unable to initialise capstone-engine");

    ifstream input_file("/lib/i386-linux-gnu/libc.so.6", ios::binary);

    if (input_file.good()) {

        // Get input size
        input_file.seekg(0, ios::end);
        streamoff input_size = input_file.tellg();
        cout << "Reading " << input_size << " bytes ...\n";

        // Read the whole file
        input_file.seekg(0, ios::beg);
        uint8_t buf[input_size];
        input_file.read(reinterpret_cast<char *>(buf), input_size);

        // Scan for RET instructions
        for (uint64_t i = 0; i < input_size; i++) {
            if (buf[i] == *ret) {

                size_t offset = i + 1;
                uint8_t* cur_pos = buf + offset;

                // Iteratively try to decode starting from (MAXDEPTH to 0) instructions
                // before the actual RET
                for (int depth=MAXDEPTH; depth>=0; depth--) {

                    size_t count = cs_disasm(handle, cur_pos-depth, depth, offset-depth, depth, &instructions);

                    // Valid gadgets must have at least two instructions, and the
                    // last one must be a RET
                    if (count >= 2) {
                        if (instructions[count - 1].id == X86_INS_RET) {

                            // Each gadget is identified with its sequence of
                            // raw bytes within the map
                            string asm_instr;
                            for (size_t i=0; i<count-1; i++) {
                                asm_instr += instructions[i].mnemonic;
                                asm_instr += " ";
                                asm_instr += instructions[i].op_str;
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

        cout << "[*] Found "<< gadgets.size() <<" gadgets: \n" ;
        for (auto const &gadget : gadgets) {
            cout << "0x" << hex << (*gadget.second).address << ":   \t" << gadget.first << "\n";
        }


    }
    return gadgets;
}