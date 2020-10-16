#ifndef ROPFUSCATORCONFIG_H
#define ROPFUSCATORCONFIG_H

#include "OpaqueConstruct.h"
#include <map>
#include <string>
#include <vector>

namespace ropf {

// =========================
// CONFIGURATION FILE STRINGS

#define CONFIG_GENERAL_SECTION "general"
#define CONFIG_FUNCTIONS_SECTION "functions"
#define CONFIG_FUNCTIONS_DEFAULT "default"

// general section
#define CONFIG_OBF_ENABLED "obfuscation_enabled"
#define CONFIG_SEARCH_SEGMENT "search_segment_for_gadget"
#define CONFIG_AVOID_MULTIVER "avoid_multiversion_symbol"
#define CONFIG_CUSTOM_LIB_PATH "custom_library_path"
#define CONFIG_LIB_SHA1 "library_hash_sha1"
#define CONFIG_LINKED_LIBS "linked_libraries"
#define CONFIG_SHOW_PROGRESS "show_progress"
#define CONFIG_PRINT_INSTR_STAT "print_instr_stat"
#define CONFIG_USE_CHAIN_LABEL "use_chain_label"

// functions section
#define CONFIG_FUNCTION_NAME "name"
#define CONFIG_OPA_PRED_ENABLED "opaque_predicates_enabled"
#define CONFIG_OPA_PRED_ALGO "opaque_predicates_algorithm"
#define CONFIG_OPA_PRED_INPUT_ALGO "opaque_predicates_input_algorithm"
#define CONFIG_OPA_PRED_CONTEXTUAL_ENABLED                                     \
  "opaque_predicates_contextual_enabled"
#define CONFIG_OPA_OBF_IMM_OPERAND "obfuscate_immediate_operand"
#define CONFIG_OPA_OBF_BRANCH_TARGET "obfuscate_branch_target"
#define CONFIG_OPA_OBF_STACK_SAVED "obfuscate_stack_saved_values"
#define CONFIG_OPA_STEGANO_ENABLED "opaque_stegano_enabled"
#define CONFIG_BRANCH_DIV_ENABLED "branch_divergence_enabled"
#define CONFIG_BRANCH_DIV_MAX "branch_divergence_max_branches"
#define CONFIG_BRANCH_DIV_ALGO "branch_divergence_algorithm"

//===========================

/// obfuscation configuration parameter for each function
struct ObfuscationParameter {
  /// true if obfuscation is enabled for this function
  bool obfuscationEnabled;
  /// true if opaque construct is enabled for this function
  bool opaquePredicateEnabled;
  /// true if obfuscation of immediate operand is enabled for this function
  /// (only effective if opaquePredicateEnabled == true)
  bool obfuscateImmediateOperand;
  /// true if contextual opaque predicate is enabled
  bool opaquePredicateContextualEnabled;
  /// true if obfuscation of branch address is enabled for this function
  /// (only effective if opaquePredicateEnabled == true)
  bool obfuscateBranchTarget;
  /// true if save dummy constants
  bool obfuscateStackSavedValues;
  /// true if instruction steganography into opaque predicates enabled
  bool opaqueSteganoEnabled;
  /// true if branch divergence is enabled for this function
  bool opaqueBranchDivergenceEnabled;
  /// maximum number of branches in branch divergence
  unsigned int opaqueBranchDivergenceMaxBranches;
  /// opaque constant algorithm for this function
  std::string opaqueConstantAlgorithm;
  /// opaque predicate input generation algorithm for this function
  std::string opaqueInputGenAlgorithm;
  /// branch divergence algorithm for this function
  std::string opaqueBranchDivergenceAlgorithm;

  ObfuscationParameter()
      : obfuscationEnabled(true), opaquePredicateEnabled(false),
        obfuscateImmediateOperand(true), opaquePredicateContextualEnabled(true),
        obfuscateBranchTarget(true), obfuscateStackSavedValues(true),
        opaqueSteganoEnabled(false), opaqueBranchDivergenceEnabled(false),
        opaqueBranchDivergenceMaxBranches(32),
        opaqueConstantAlgorithm(OPAQUE_CONSTANT_ALGORITHM_MOV),
        opaqueInputGenAlgorithm(OPAQUE_RANDOM_ALGORITHM_ADDREG),
        opaqueBranchDivergenceAlgorithm(OPAQUE_BRANCH_ALGORITHM_ADDREG_MOV) {}
};

/// obfuscation configuration for the entire compilation unit
struct GlobalConfig {
  // [BinaryAutopsy] library path where the gadgets are extracted
  std::string libraryPath;
  // [BinaryAutopsy] expected library sha1 hash where the gadgets are extracted
  // If set, SHA1 hash is checked and stop obfuscation if it does not match
  std::string librarySHA1;
  // [BinaryAutopsy] other library paths linked at run-time
  // If set, the symbol names in these libraries are put in avoid-list in gadget
  std::vector<std::string> linkedLibraries;
  // true if obfuscation is enabled, false if obfuscation is disabled globally
  bool obfuscationEnabled;
  // [BinaryAutopsy] If set to true, find gadget in code segment instead of code
  // section (which will find more gadgets since code segment is wider)
  bool searchSegmentForGadget;
  // [BinaryAutopsy] If set to true, symbols which have multiple versions are
  // not used; if set to false, only one version of those symbols is used. (angr
  // will not work correctly if this is set to false)
  bool avoidMultiversionSymbol;
  // show obfuscation progress
  bool showProgress;
  // print instruction obfuscated status
  bool printInstrStat;
  // use chain label
  bool useChainLabel;

  GlobalConfig()
      : libraryPath(), librarySHA1(), linkedLibraries(),
        obfuscationEnabled(true), searchSegmentForGadget(true),
        avoidMultiversionSymbol(false), showProgress(false),
        printInstrStat(false), useChainLabel(false) {}
};

struct ROPfuscatorConfig {
  ObfuscationParameter defaultParameter;
  GlobalConfig globalConfig;
  std::map<std::string, ObfuscationParameter> functionsParameter;

  ObfuscationParameter getParameter(const std::string &funcname) const;

  void loadFromFile(const std::string &filename);
};

} // namespace ropf

#endif
