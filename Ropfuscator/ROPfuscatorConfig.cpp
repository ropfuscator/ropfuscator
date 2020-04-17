#include "ROPfuscatorConfig.h"
#include "Debug.h"
//#include "toml.hpp"

#define TOML_HAVE_FAILWITH_REPLACEMENT

namespace toml {
template <typename... Args>[[noreturn]] void failwith(Args &&... args) {
  std::stringstream ss;
  int _dummy[] = {(ss << args, 0)...};
  (void)_dummy;
  dbg_fmt("TOML parse error: {}\n", ss.str());
  exit(1);
}
} // namespace toml

#include "toml/toml.h"

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

  DEBUG_WITH_TYPE(
      OBF_CONFIG,
      dbg_fmt("Returning default obfuscation parameter for {}\n", funcname));
  return defaultParameter;
}

void ROPfuscatorConfig::loadFromFile(const std::string &filename) {
  dbg_fmt("Loading configuration from file {}.\n", filename);

  toml::ParseResult parseResult = toml::parseFile(filename);
  if (!parseResult.valid()) {
    fmt::print(stderr, "Error while parsing configuration file:\n {}",
               parseResult.errorReason);
    exit(-1);
  }

  const toml::Value &configuration_data = parseResult.value;

  // setting default values
  globalConfig = GlobalConfig();
  defaultParameter = ObfuscationParameter();

  // =====================================
  // parsing [general] section, if present
  if (auto *general_section = configuration_data.find(CONFIG_GENERAL_SECTION)) {

    // Custom library path
    if (auto *library_path_v = general_section->find(CONFIG_CUSTOM_LIB_PATH)) {
      std::string library_path = library_path_v->as<std::string>();

      dbg_fmt("Setting library path to {}\n", library_path);
      globalConfig.libraryPath = library_path;
    }

    // Avoid multiversion symbols
    if (auto *avoid_multiver_v = general_section->find(CONFIG_AVOID_MULTIVER)) {
      bool avoid_multiver = avoid_multiver_v->as<bool>();

      dbg_fmt("Setting {} flag to {}\n", CONFIG_AVOID_MULTIVER, avoid_multiver);
      globalConfig.avoidMultiversionSymbol = avoid_multiver;
    }

    // Search in segment
    if (auto *search_segment_v = general_section->find(CONFIG_SEARCH_SEGMENT)) {
      bool search_segment = search_segment_v->as<bool>();

      dbg_fmt("Setting {} flag to {}\n", CONFIG_SEARCH_SEGMENT, search_segment);
      globalConfig.searchSegmentForGadget = search_segment;
    }

    // Print instruction statistics
    if (auto *print_instr_stat_v =
            general_section->find(CONFIG_PRINT_INSTR_STAT)) {
      auto print_instr_stat = print_instr_stat_v->as<bool>();

      dbg_fmt("Setting {} flag to {}\n", CONFIG_PRINT_INSTR_STAT,
              print_instr_stat);
      globalConfig.printInstrStat = print_instr_stat;
    }
  }

  // =====================================
  // parsing [functions] section, if present
  if (auto *functions_section =
          configuration_data.find(CONFIG_FUNCTIONS_SECTION)) {

    if (!functions_section->is<toml::Table>()) {
      // error
      dbg_fmt("[functions] should be a section.\n");
      exit(-1);
    }

    // parsing [functions.default]
    // note: these settings will be overridden if multiple
    // [functions.default] sections are defined! TODO: fixme
    if (auto *default_keys =
            functions_section->find(CONFIG_FUNCTIONS_DEFAULT)) {

      dbg_fmt("Found [functions.default] section.\n");

      // Obfuscation enabled
      if (auto *obf_enabled_v = default_keys->find(CONFIG_OBF_ENABLED)) {
        bool obf_enabled = obf_enabled_v->as<bool>();

        dbg_fmt("Setting {} flag to {}\n", CONFIG_OBF_ENABLED, obf_enabled);
        defaultParameter.obfuscationEnabled = obf_enabled;
      }

      // Opaque predicates enabled
      if (auto *op_enabled_v = default_keys->find(CONFIG_OPA_PRED_ENABLED)) {
        bool op_enabled = op_enabled_v->as<bool>();

        dbg_fmt("Setting {} flag to {}\n", CONFIG_OPA_PRED_ENABLED, op_enabled);
        defaultParameter.opaquePredicateEnabled = op_enabled;
      }

      // Opaque predicates algorithm
      if (auto *op_algo_v = default_keys->find(CONFIG_OPA_PRED_ALGO)) {
        std::string op_algo = op_algo_v->as<std::string>();
        std::string parsed_op_algo = parseOpaquePredicateAlgorithm(op_algo);

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
      if (auto *branch_div_enabled_v =
              default_keys->find(CONFIG_BRANCH_DIV_ENABLED)) {
        bool branch_div_enabled = branch_div_enabled_v->as<bool>();

        dbg_fmt("Setting {} flag to {}\n", CONFIG_BRANCH_DIV_ENABLED,
                branch_div_enabled);

        defaultParameter.opaqueBranchDivergenceEnabled = branch_div_enabled;
      }

      // Branch divergence max depth
      if (auto *branch_div_max_v = default_keys->find(CONFIG_BRANCH_DIV_MAX)) {
        int branch_div_max = branch_div_max_v->as<int>();

        dbg_fmt("Setting {} to {}\n", CONFIG_BRANCH_DIV_MAX, branch_div_max);

        defaultParameter.opaqueBranchDivergenceMaxBranches =
            static_cast<unsigned int>(branch_div_max);
      }

      // Branch divergence algorithm
      if (auto *branch_div_algo_v =
              default_keys->find(CONFIG_BRANCH_DIV_ALGO)) {
        std::string branch_div_algo = branch_div_algo_v->as<std::string>();
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

    // parsing [functions.*] sections
    for (auto &kv : functions_section->as<toml::Table>()) {
      const std::string &subsection_name = kv.first;
      const toml::Value &subsection_data = kv.second;

      // ignoring default since it was parsed already
      if (subsection_name == CONFIG_FUNCTIONS_DEFAULT) {
        continue;
      }

      dbg_fmt("Parsing: [functions.{}]\n", subsection_name);

      // ignoring subsection if it doesn't have a name entry
      if (!subsection_data.find(CONFIG_FUNCTION_NAME)) {
        fmt::print(stderr,
                   "Subsection {} does not contain a {} entry. Ignoring "
                   "subsection.\n",
                   subsection_name, CONFIG_FUNCTION_NAME);
        continue;
      }

      auto function_ob_parameter = ObfuscationParameter();
      std::string function_name;
      if (auto *function_name_v = subsection_data.find(CONFIG_FUNCTION_NAME)) {
        function_name = function_name_v->as<std::string>();
      } else {
        dbg_fmt("Warning: section [functions.{}] should include {}\n",
                subsection_name, CONFIG_FUNCTION_NAME);
        continue;
      }

      // Opaque predicates enabled
      if (auto *op_enabled_v = subsection_data.find(CONFIG_OPA_PRED_ENABLED)) {
        bool op_enabled = op_enabled_v->as<bool>();

        dbg_fmt("Setting {} flag to {}\n", CONFIG_OPA_PRED_ENABLED, op_enabled);
        function_ob_parameter.opaquePredicateEnabled = op_enabled;
      }

      // Opaque predicates algorithm
      if (auto *op_algo_v = subsection_data.find(CONFIG_OPA_PRED_ALGO)) {
        std::string op_algo = op_algo_v->as<std::string>();
        std::string parsed_op_algo = parseOpaquePredicateAlgorithm(op_algo);

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
      if (auto *branch_div_enabled_v =
              subsection_data.find(CONFIG_BRANCH_DIV_ENABLED)) {
        bool branch_div_enabled = branch_div_enabled_v->as<bool>();

        dbg_fmt("Setting {} flag to {}\n", CONFIG_BRANCH_DIV_ENABLED,
                branch_div_enabled);

        function_ob_parameter.opaqueBranchDivergenceEnabled =
            branch_div_enabled;
      }

      // Branch divergence max depth
      if (auto *branch_div_max_v =
              subsection_data.find(CONFIG_BRANCH_DIV_MAX)) {
        int branch_div_max = branch_div_max_v->as<int>();

        dbg_fmt("Setting {} to {}\n", CONFIG_BRANCH_DIV_MAX, branch_div_max);

        function_ob_parameter.opaqueBranchDivergenceMaxBranches =
            branch_div_max;
      }

      // Branch divergence algorithm
      if (auto *branch_div_algo_v =
              subsection_data.find(CONFIG_BRANCH_DIV_ALGO)) {
        std::string branch_div_algo = branch_div_algo_v->as<std::string>();
        std::string parsed_branch_div_algo =
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