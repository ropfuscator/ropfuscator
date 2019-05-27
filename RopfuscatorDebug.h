#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

#define XCHG_CHAIN "xchg_chains"
#define ROPCHAIN "ropchains"
#define LIVENESS_ANALYSIS "liveness_analysis"
#define PROCESSED_INSTR "processed_instr"
#define OBF_STATS "obf_stats"

// not working
#define SECTIONS "sections"
#define GADGET_ANALYSIS "gadget_analysis"
#define GADGET_EXTRACTION "gadget_extraction"
#define GADGET_FILTER "gadget_filter"
#define SYMBOL_EXTRACTION "symbol_extraction"
#define XCHG_GRAPH "xchg_graph"

/*
 * COLORS
 */

#define COLOR_RED "\x1b[31m"
#define COLOR_GREEN "\x1b[32m"
#define COLOR_YELLOW "\x1b[33m"
#define COLOR_BLUE "\x1b[34m"
#define COLOR_RESET "\x1b[0m"