#ifndef ROPFUSCATORCONFIG_H
#define ROPFUSCATORCONFIG_H

#include "Debug.h"
#include "toml.hpp"
#include <string>

// default configuration (defined in OpaqueConstruct.h)
extern const std::string OPAQUE_CONSTANT_ALGORITHM_MOV;
extern const std::string OPAQUE_BRANCH_ALGORITHM_ADDREG_MOV;

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

// functions section
#define CONFIG_FUNCTION_NAME "name"
#define CONFIG_OPA_PRED_ENABLED "opaque_predicates_enabled"
#define CONFIG_OPA_PRED_ALGO "opaque_predicates_algorithm"
#define CONFIG_BRANCH_DIV_ENABLED "branch_divergence_enabled"
#define CONFIG_BRANCH_DIV_MAX "branch_divergence_max_branches"

//===========================

/// obfuscation configuration parameter for each function
struct ObfuscationParameter {
  /// true if obfuscation is enabled for this function
  bool obfuscationEnabled;
  /// true if opaque construct is enabled for this function
  bool opaquePredicateEnabled;
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

  GlobalConfig()
      : libraryPath(), searchSegmentForGadget(true),
        avoidMultiversionSymbol(false) {}
};

// TODO: stub implementation
struct ROPfuscatorConfig {
  ObfuscationParameter defaultParameter;
  GlobalConfig globalConfig;
  // TODO: add data structure here

  ObfuscationParameter getParameter(const std::string &funcname) const {
    // TODO: return per-function configuration (maybe implement in .cpp?)
    return defaultParameter;
  }

  void loadFromFile(const std::string &filename) {
    dbg_fmt("Loading configuration from file {}.\n", filename);

    toml::value configuration_data;

    try {
      configuration_data = toml::parse(filename);
    } catch (const std::runtime_error &e) {
      // TODO: better output
      printf("Error while parsing configuration file:\n %s", e.what());
      exit(-1);
    } catch (const toml::syntax_error &e) {
      // TODO: better output
      printf("Syntax error in configuration file:\n %s", e.what());
      exit(-1);
    }

    // checking if [general] is in the configuration
    if (!configuration_data.contains(CONFIG_GENERAL_SECTION)) {
      fmt::print("Could not find \"[{}]\" section in configuration file.\n",
                 CONFIG_GENERAL_SECTION);
      exit(-1);
    }

    // checking if [functions.default] is in the configuration
    // the way this check is conducted is silly.
    if (!configuration_data.contains(CONFIG_FUNCTIONS_SECTION) ||
        (configuration_data.contains(CONFIG_FUNCTIONS_SECTION) &&
         (configuration_data.at(CONFIG_FUNCTIONS_SECTION)
              .count(CONFIG_FUNCTIONS_DEFAULT) == 0))) {
      fmt::print("Could not find \"[{}]\" section in configuration file.\n",
                 CONFIG_FUNCTIONS_DEFAULT);
      exit(-1);
    }

    toml::value general_section =
        toml::find(configuration_data, CONFIG_GENERAL_SECTION);
    toml::value functions_section =
        toml::find(configuration_data, CONFIG_FUNCTIONS_SECTION);

    dbg_fmt("{}", general_section);
    dbg_fmt("{}", functions_section);
  }
};

#endif
