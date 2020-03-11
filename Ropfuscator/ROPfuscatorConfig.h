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
#define CONFIG_BRANCH_DIV_ALGO "branch_divergence_algorithm"

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

    // setting default values
    globalConfig = GlobalConfig();
    defaultParameter = ObfuscationParameter();

    /* =====================================
     * applying [general] section, if present
     */
    if (configuration_data.contains(CONFIG_GENERAL_SECTION)) {
      toml::value general_section =
          toml::find(configuration_data, CONFIG_GENERAL_SECTION);

      // Custom library path
      if (general_section.contains(CONFIG_CUSTOM_LIB_PATH)) {
        auto library_path =
            general_section.at(CONFIG_CUSTOM_LIB_PATH).as_string();

        dbg_fmt("Setting library path to {}\n", library_path);
        globalConfig.libraryPath = library_path;
      }

      // Avoid multiversion symbols
      if (general_section.contains(CONFIG_AVOID_MULTIVER)) {
        auto avoid_multiver =
            general_section.at(CONFIG_AVOID_MULTIVER).as_boolean();

        dbg_fmt("Setting {} flag to {}\n", CONFIG_AVOID_MULTIVER,
                avoid_multiver);
        globalConfig.avoidMultiversionSymbol = avoid_multiver;
      }

      // Search in segment
      if (general_section.contains(CONFIG_SEARCH_SEGMENT)) {
        auto search_segment =
            general_section.at(CONFIG_SEARCH_SEGMENT).as_boolean();

        dbg_fmt("Setting {} flag to {}\n", CONFIG_SEARCH_SEGMENT,
                search_segment);
        globalConfig.searchSegmentForGadget = search_segment;
      }
    }
    // =====================================

    /* =====================================
     * applying [functions.default] section, if present
     * note: these settings will be overridden if multiple [functions.default]
     * sections are defined! TODO: fixme
     */
    if (configuration_data.contains(CONFIG_FUNCTIONS_SECTION) &&
        configuration_data.at(CONFIG_FUNCTIONS_SECTION)
                .count(CONFIG_FUNCTIONS_DEFAULT) != 0) {
      auto functions_section =
          toml::find(configuration_data, CONFIG_FUNCTIONS_SECTION);
      auto default_keys =
          toml::find(functions_section, CONFIG_FUNCTIONS_DEFAULT);

      // Opaque predicates enabled
      if (default_keys.contains(CONFIG_OPA_PRED_ENABLED)) {
        auto op_enabled = default_keys.at(CONFIG_OPA_PRED_ENABLED).as_boolean();

        dbg_fmt("Setting {} flag to {}\n", CONFIG_OPA_PRED_ENABLED, op_enabled);
        defaultParameter.opaquePredicateEnabled = op_enabled;
      }

      // Opaque predicates algorithm
      if (default_keys.contains(CONFIG_OPA_PRED_ALGO)) {
        auto op_algo = default_keys.at(CONFIG_OPA_PRED_ALGO).as_string();

        dbg_fmt("Setting {} to {} (NOT BEING SET, REALLY)\n",
                CONFIG_OPA_PRED_ALGO, op_algo);

        // TODO: parse string to extrapolate algorithm
        // defaultParameter.opaqueConstantAlgorithm = op_algo;
      }

      // Branch divergence enabled
      if (default_keys.contains(CONFIG_BRANCH_DIV_ENABLED)) {
        auto branch_div_enabled =
            default_keys.at(CONFIG_BRANCH_DIV_ENABLED).as_boolean();

        dbg_fmt("Setting {} flag to {}\n", CONFIG_BRANCH_DIV_ENABLED,
                branch_div_enabled);

        defaultParameter.opaqueBranchDivergenceEnabled = branch_div_enabled;
      }

      // Branch divergence max depth
      if (default_keys.contains(CONFIG_BRANCH_DIV_MAX)) {
        auto branch_div_max =
            default_keys.at(CONFIG_BRANCH_DIV_MAX).as_integer();

        dbg_fmt("Setting {} to {}\n", CONFIG_BRANCH_DIV_MAX, branch_div_max);

        defaultParameter.opaqueBranchDivergenceMaxBranches = branch_div_max;
      }

      // Branch divergence algorithm
      if (default_keys.contains(CONFIG_BRANCH_DIV_ALGO)) {
        auto branch_div_algo =
            default_keys.at(CONFIG_BRANCH_DIV_ALGO).as_string();

        dbg_fmt("Setting {} to {} (NOT BEING SET, REALLY)\n",
                CONFIG_BRANCH_DIV_ALGO, branch_div_algo);

        // TODO: parse string to extrapolate algorithm
        // defaultParameter.opaqueBranchDivergenceAlgorithm =
        // branch_div_algo;
      }
    }
    // =====================================
  }
};

#endif
