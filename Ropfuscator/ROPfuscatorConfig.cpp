#include "ROPfuscatorConfig.h"
#include "Debug.h"
#include "toml.hpp"

ObfuscationParameter
ROPfuscatorConfig::getParameter(const std::string &funcname) const {
  for (auto &kv : functionsParameter) {
    auto &function_name = kv.first;
    auto &function_ob_parameter = kv.second;
    auto function_regex = std::regex(function_name);

    if (std::regex_match(funcname, function_regex)) {
      return function_ob_parameter;
    }
  }

  dbg_fmt("Returning default obfuscation parameter for {}\n", funcname);
  return defaultParameter;
}

void ROPfuscatorConfig::loadFromFile(const std::string &filename) {
  dbg_fmt("Loading configuration from file {}.\n", filename);

  toml::value configuration_data;

  try {
    configuration_data = toml::parse(filename);
  } catch (const std::runtime_error &e) {
    // TODO: better output
    fmt::print(stderr, "Error while parsing configuration file:\n {}",
               e.what());
    exit(-1);
  } catch (const toml::syntax_error &e) {
    // TODO: better output
    fmt::print(stderr, "Syntax error in configuration file:\n {}", e.what());
    exit(-1);
  }

  // setting default values
  globalConfig = GlobalConfig();
  defaultParameter = ObfuscationParameter();

  /* =====================================
   * parsing [general] section, if present
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

      dbg_fmt("Setting {} flag to {}\n", CONFIG_AVOID_MULTIVER, avoid_multiver);
      globalConfig.avoidMultiversionSymbol = avoid_multiver;
    }

    // Search in segment
    if (general_section.contains(CONFIG_SEARCH_SEGMENT)) {
      auto search_segment =
          general_section.at(CONFIG_SEARCH_SEGMENT).as_boolean();

      dbg_fmt("Setting {} flag to {}\n", CONFIG_SEARCH_SEGMENT, search_segment);
      globalConfig.searchSegmentForGadget = search_segment;
    }
  }

  /* =====================================
   * parsing [functions] section, if present
   */
  if (configuration_data.contains(CONFIG_FUNCTIONS_SECTION)) {
    auto functions_section =
        toml::find(configuration_data, CONFIG_FUNCTIONS_SECTION);

    /*
     * parsing [functions.default]
     * note: these settings will be overridden if multiple
     * [functions.default] sections are defined! TODO: fixme
     */
    if (functions_section.count(CONFIG_FUNCTIONS_DEFAULT)) {
      auto default_keys =
          toml::find(functions_section, CONFIG_FUNCTIONS_DEFAULT);

      dbg_fmt("Found [functions.default] section.\n");

      // Opaque predicates enabled
      if (default_keys.contains(CONFIG_OPA_PRED_ENABLED)) {
        auto op_enabled = default_keys.at(CONFIG_OPA_PRED_ENABLED).as_boolean();

        dbg_fmt("Setting {} flag to {}\n", CONFIG_OPA_PRED_ENABLED, op_enabled);
        defaultParameter.opaquePredicateEnabled = op_enabled;
      }

      // Opaque predicates algorithm
      if (default_keys.contains(CONFIG_OPA_PRED_ALGO)) {
        auto op_algo = default_keys.at(CONFIG_OPA_PRED_ALGO).as_string();
        auto parsed_op_algo = parseOpaquePredicateAlgorithm(op_algo);

        if (parsed_op_algo.empty()) {
          fmt::print(stderr,
                     "Could not understand \"{}\" as opaque predicate "
                     "algorithm. Terminating.\n",
                     op_algo);
          exit(-1);
        }

        dbg_fmt("Setting {} to {}\n", CONFIG_OPA_PRED_ALGO, parsed_op_algo);

        defaultParameter.opaqueConstantAlgorithm = parsed_op_algo;
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
        auto parsed_branch_div_algo =
            parseBranchDivergenceAlgorithm(branch_div_algo);

        if (parsed_branch_div_algo.empty()) {
          fmt::print(stderr,
                     "Could not understand \"{}\" as branch divergence "
                     "algorithm. Terminating.\n",
                     branch_div_algo);
          exit(-1);
        }

        dbg_fmt("Setting {} to {}\n", CONFIG_BRANCH_DIV_ALGO,
                parsed_branch_div_algo);

        defaultParameter.opaqueBranchDivergenceAlgorithm =
            parsed_branch_div_algo;
      }
    }

    /*
     * parsing [functions.*] sections
     */
    for (auto kv : functions_section.as_table()) {
      auto subsection_name = kv.first;
      auto subsection_data = kv.second;

      // ignoring default since it was parsed already
      if (!subsection_name.compare(CONFIG_FUNCTIONS_DEFAULT)) {
        continue;
      }

      dbg_fmt("Parsing: [functions.{}]\n", subsection_name);

      // ignoring subsection if it doesn't have a name entry
      if (!subsection_data.contains(CONFIG_FUNCTION_NAME)) {
        fmt::print(stderr,
                   "Subsection {} does not contain a {} entry. Ignoring "
                   "subsection.\n",
                   subsection_name, CONFIG_FUNCTION_NAME);
        continue;
      }

      auto function_ob_parameter = ObfuscationParameter();
      auto function_name = subsection_data.at(CONFIG_FUNCTION_NAME).as_string();

      // Opaque predicates enabled
      if (subsection_data.contains(CONFIG_OPA_PRED_ENABLED)) {
        auto op_enabled =
            subsection_data.at(CONFIG_OPA_PRED_ENABLED).as_boolean();

        dbg_fmt("Setting {} flag to {}\n", CONFIG_OPA_PRED_ENABLED, op_enabled);
        function_ob_parameter.opaquePredicateEnabled = op_enabled;
      }

      // Opaque predicates algorithm
      if (subsection_data.contains(CONFIG_OPA_PRED_ALGO)) {
        auto op_algo = subsection_data.at(CONFIG_OPA_PRED_ALGO).as_string();
        auto parsed_op_algo = parseOpaquePredicateAlgorithm(op_algo);

        if (parsed_op_algo.empty()) {
          fmt::print(stderr,
                     "Could not understand \"{}\" as opaque predicate "
                     "algorithm. Ignoring.\n",
                     op_algo);
        } else {
          dbg_fmt("Setting {} to {}\n", CONFIG_OPA_PRED_ALGO, parsed_op_algo);

          function_ob_parameter.opaqueConstantAlgorithm = parsed_op_algo;
        }
      }

      // Branch divergence enabled
      if (subsection_data.contains(CONFIG_BRANCH_DIV_ENABLED)) {
        auto branch_div_enabled =
            subsection_data.at(CONFIG_BRANCH_DIV_ENABLED).as_boolean();

        dbg_fmt("Setting {} flag to {}\n", CONFIG_BRANCH_DIV_ENABLED,
                branch_div_enabled);

        function_ob_parameter.opaqueBranchDivergenceEnabled =
            branch_div_enabled;
      }

      // Branch divergence max depth
      if (subsection_data.contains(CONFIG_BRANCH_DIV_MAX)) {
        auto branch_div_max =
            subsection_data.at(CONFIG_BRANCH_DIV_MAX).as_integer();

        dbg_fmt("Setting {} to {}\n", CONFIG_BRANCH_DIV_MAX, branch_div_max);

        function_ob_parameter.opaqueBranchDivergenceMaxBranches =
            branch_div_max;
      }

      // Branch divergence algorithm
      if (subsection_data.contains(CONFIG_BRANCH_DIV_ALGO)) {
        auto branch_div_algo =
            subsection_data.at(CONFIG_BRANCH_DIV_ALGO).as_string();
        auto parsed_branch_div_algo =
            parseBranchDivergenceAlgorithm(branch_div_algo);

        if (parsed_branch_div_algo.empty()) {
          fmt::print(stderr,
                     "Could not understand \"{}\" as branch divergence "
                     "algorithm. Ignoring.\n",
                     branch_div_algo);
        } else {
          dbg_fmt("Setting {} to {}\n", CONFIG_BRANCH_DIV_ALGO,
                  parsed_branch_div_algo);

          function_ob_parameter.opaqueBranchDivergenceAlgorithm =
              parsed_branch_div_algo;
        }
      }

      functionsParameter.insert({function_name, function_ob_parameter});
    }
  }
  // =====================================
}

std::string ROPfuscatorConfig::parseOpaquePredicateAlgorithm(
    const std::string &configString) {
  std::string lowerConfigString = configString;

  // transforming configString to lowercase
  std::transform(lowerConfigString.begin(), lowerConfigString.end(),
                 lowerConfigString.begin(),
                 [](unsigned char c) { return std::tolower(c); });

  if (!lowerConfigString.compare("mov")) {
    return OPAQUE_CONSTANT_ALGORITHM_MOV;
  }

  if (!lowerConfigString.compare("multcomp")) {
    return OPAQUE_CONSTANT_ALGORITHM_MULTCOMP;
  }

  return "";
}

std::string ROPfuscatorConfig::parseBranchDivergenceAlgorithm(
    const std::string &configString) {
  std::string lowerConfigString = configString;

  // transforming configString to lowercase
  std::transform(lowerConfigString.begin(), lowerConfigString.end(),
                 lowerConfigString.begin(),
                 [](unsigned char c) { return std::tolower(c); });

  if (!lowerConfigString.compare("addreg")) {
    return OPAQUE_BRANCH_ALGORITHM_ADDREG_MOV;
  }

  if (!lowerConfigString.compare("rdtsc")) {
    return OPAQUE_BRANCH_ALGORITHM_RDTSC_MOV;
  }

  if (!lowerConfigString.compare("negative_stack")) {
    return OPAQUE_BRANCH_ALGORITHM_NEGSTK_MOV;
  }

  return "";
}