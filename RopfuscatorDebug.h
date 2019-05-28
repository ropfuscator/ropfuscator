#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include <fmt/format.h>

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

template <> struct fmt::formatter<llvm::MachineInstr> {
  template <typename ParseContext> constexpr auto parse(ParseContext &ctx) {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const llvm::MachineInstr &MI, FormatContext &ctx) {
    std::string s;
    llvm::raw_string_ostream rso(s);
    MI.print(rso);

    return fmt::format_to(ctx.begin(), "{}", rso.str());
  }
};
