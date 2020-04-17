#ifndef DEBUG_H
#define DEBUG_H

#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include <fmt/ostream.h>
#include <iosfwd>

#define XCHG_CHAIN "xchg_chains"
#define ROPCHAIN "ropchains"
#define LIVENESS_ANALYSIS "liveness_analysis"
#define PROCESSED_INSTR "processed_instr"
#define OBF_STATS "obf_stats"
#define OBF_CONFIG "obf_config"

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

// get llvm::dbgs() wrapped in std::ostream
std::ostream &debugs();

namespace llvm {
// forward declaration
class Error;
class StringRef;
class MachineInstr;
class GlobalValue;
class MachineBasicBlock;

// std::ostream printer for llvm classes
std::ostream &operator<<(std::ostream &, const Error &);
std::ostream &operator<<(std::ostream &, const StringRef &);
std::ostream &operator<<(std::ostream &, const GlobalValue &);
std::ostream &operator<<(std::ostream &, const MachineInstr &);
std::ostream &operator<<(std::ostream &, const MachineBasicBlock &);

} // namespace llvm

template <typename... Args>
void dbg_fmt(const char *fmt, const Args &... args) {
  fmt::print(debugs(), fmt, args...);
}

#endif
