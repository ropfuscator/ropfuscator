// ==============================================================================
//   Capstone - LLVM IR Adapter
//   part of the ROPfuscator project
// ==============================================================================
// This module exposes a series of helper functions to manipulate capstone
// instruction structs in a simpler way, like they were instructions of the LLVM
// IR.

#include <capstone/capstone.h>
#include <capstone/x86.h>

// opValid - checks if the operands has the "type" defined. This is used
// in gadgetLookup() to figure out if the optional parameter has been set.
bool opValid(cs_x86_op op);

// convertToCapstoneReg - simple lookup table that translates register enums
// from the LLVM representation (e.g. X86::EAX) to capstone (X86_REG_EAX).
x86_reg convertToCapstoneReg(unsigned int reg);

bool areEqualOps(const cs_x86_op &op0, const cs_x86_op &op1);

x86_reg extractReg(const cs_x86_op op);