#ifndef ROPFUSCATORCONFIG_H
#define ROPFUSCATORCONFIG_H

#include "OpaqueConstruct.h"
#include <map>
#include <string>

/* =========================
 * CONFIGURATION FILE STRINGS
 */

#define CONFIG_GENERAL_SECTION "general"
#define CONFIG_FUNCTIONS_SECTION "functions"
#define CONFIG_FUNCTIONS_DEFAULT "default"

// general section
#define CONFIG_OBF_ENABLED "obfuscation_enabled"
#define CONFIG_SEARCH_SEGMENT "search_segment_for_gadget"
#define CONFIG_AVOID_MULTIVER "avoid_multiversion_symbol"
#define CONFIG_CUSTOM_LIB_PATH "custom_library_path"
#define CONFIG_PRINT_INSTR_STAT "print_instr_stat"
#define CONFIG_USE_CHAIN_LABEL "use_chain_label"

// functions section
#define CONFIG_FUNCTION_NAME "name"
#define CONFIG_OPA_PRED_ENABLED "opaque_predicates_enabled"
#define CONFIG_OPA_PRED_ALGO "opaque_predicates_algorithm"
#define CONFIG_OPA_OBF_IMM_OPERAND "obfuscate_immediate_operand"
#define CONFIG_OPA_OBF_BRANCH_TARGET "obfuscate_branch_target"
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
  /// true if obfuscation of branch address is enabled for this function
  /// (only effective if opaquePredicateEnabled == true)
  bool obfuscateBranchTarget;
  /// true if branch divergence is enabled for this function
  bool opaqueBranchDivergenceEnabled;
  /// maximum number of branches in branch divergence
  unsigned int opaqueBranchDivergenceMaxBranches;
  /// opaque constant algorithm for this function
  std::string opaqueConstantAlgorithm;
  /// branch divergence algorithm for this function
  std::string opaqueBranchDivergenceAlgorithm;

  ObfuscationParameter()
      : obfuscationEnabled(true), opaquePredicateEnabled(false),
        obfuscateImmediateOperand(true), obfuscateBranchTarget(true),
        opaqueBranchDivergenceEnabled(false),
        opaqueBranchDivergenceMaxBranches(32),
        opaqueConstantAlgorithm(OPAQUE_CONSTANT_ALGORITHM_MOV),
        opaqueBranchDivergenceAlgorithm(OPAQUE_BRANCH_ALGORITHM_ADDREG_MOV) {}
};

/// obfuscation configuration for the entire compilation unit
struct GlobalConfig {
  // [BinaryAutopsy] library path where the gadgets are extracted
  std::string libraryPath;
  // [BinaryAutopsy] If set to true, find gadget in code segment instead of code
  // section (which will find more gadgets since code segment is wider)
  bool searchSegmentForGadget;
  // [BinaryAutopsy] If set to true, symbols which have multiple versions are
  // not used; if set to false, only one version of those symbols is used. (angr
  // will not work correctly if this is set to false)
  bool avoidMultiversionSymbol;
  // print instruction obfuscated status
  bool printInstrStat;
  // use chain label
  bool useChainLabel;

  GlobalConfig()
      : libraryPath(), searchSegmentForGadget(true),
        avoidMultiversionSymbol(false), printInstrStat(false),
        useChainLabel(false) {}
};

struct ROPfuscatorConfig {
  ObfuscationParameter defaultParameter;
  GlobalConfig globalConfig;
  std::map<std::string, ObfuscationParameter> functionsParameter;

  ObfuscationParameter getParameter(const std::string &funcname) const;

  void loadFromFile(const std::string &filename);
};

#endif
