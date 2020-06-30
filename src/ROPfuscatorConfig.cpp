#include "ROPfuscatorConfig.h"
#include "Debug.h"
#include <cctype>
#include <regex>
#include <set>
#include <string>
#include <vector>

#define TOML_HAVE_FAILWITH_REPLACEMENT

namespace toml {
template <typename... Args>[[noreturn]] void failwith(Args &&... args) {
  std::stringstream ss;
  // this will expand to ss << args_0, ss << args_1, ...
  int _dummy[] = {(ss << args, 0)...};
  (void)_dummy;
  ropf::dbg_fmt("TOML parse error: {}\n", ss.str());
  exit(1);
}
} // namespace toml

#include <toml/toml.h>

namespace toml::internal {
template <> inline const char *type_name<std::vector<std::string>>() {
  return "array of string";
}
} // namespace toml::internal

namespace ropf {

namespace {

template <typename T>
inline bool parseOption(const toml::Value &section,
                        const std::string &sectionname, const std::string &key,
                        T &ref) {
  if (const toml::Value *v = section.find(key)) {
    if (!v->is<T>()) {
      dbg_fmt("TOML parse warning: {}.{} should have type {}, thus ignored\n",
              sectionname, key, toml::internal::type_name<T>());
      return false;
    }
    const auto &value = v->as<T>();
    ref = value;
    DEBUG_WITH_TYPE(OBF_CONFIG,
                    dbg_fmt("Setting {}.{} to {}\n", sectionname, key, value));
    return true;
  } else {
    return false;
  }
}

std::string str_tolower(const std::string &s) {
  std::string s_lower = s;
  std::transform(s_lower.begin(), s_lower.end(), s_lower.begin(),
                 [](unsigned char c) { return std::tolower(c); });
  return s_lower;
}

std::set<std::string> validOpaquePredicateAlgorithmNames = {
    OPAQUE_CONSTANT_ALGORITHM_MOV,
    OPAQUE_CONSTANT_ALGORITHM_R3SAT32,
    OPAQUE_CONSTANT_ALGORITHM_MULTCOMP,
};

std::set<std::string> validBranchDivergenceAlgorithmNames = {
    OPAQUE_BRANCH_ALGORITHM_ADDREG_MOV,
    OPAQUE_BRANCH_ALGORITHM_NEGSTK_MOV,
    OPAQUE_BRANCH_ALGORITHM_RDTSC_MOV,
};

void parseFunctionOptions(const toml::Value &config,
                          const std::string &tomlSect,
                          ObfuscationParameter &funcParam) {

  // Obfuscation enabled
  parseOption(config, tomlSect, CONFIG_OBF_ENABLED,
              funcParam.obfuscationEnabled);

  // Opaque predicates enabled
  parseOption(config, tomlSect, CONFIG_OPA_PRED_ENABLED,
              funcParam.opaquePredicateEnabled);

  // Obfuscation of immediate operand enabled
  parseOption(config, tomlSect, CONFIG_OPA_OBF_IMM_OPERAND,
              funcParam.obfuscateImmediateOperand);

  // Obfuscation of branch target enabled
  parseOption(config, tomlSect, CONFIG_OPA_OBF_BRANCH_TARGET,
              funcParam.obfuscateBranchTarget);

  // Obfuscation of stack saved values enabled
  parseOption(config, tomlSect, CONFIG_OPA_OBF_STACK_SAVED,
              funcParam.obfuscateStackSavedValues);

  // Opaque predicates algorithm
  std::string op_algo;
  if (parseOption(config, tomlSect, CONFIG_OPA_PRED_ALGO, op_algo)) {
    op_algo = str_tolower(op_algo);
    if (validOpaquePredicateAlgorithmNames.count(op_algo) == 0) {
      dbg_fmt("Warning: cannot understand \"{}\" as an opaque predicate "
              "algorithm. Algorithm configuration is ignored.\n",
              op_algo);
    } else {
      funcParam.opaqueConstantAlgorithm = op_algo;
    }
  }

  // Opaque predicate steganography enabled
  parseOption(config, tomlSect, CONFIG_OPA_STEGANO_ENABLED,
              funcParam.opaqueSteganoEnabled);

  // Branch divergence enabled
  parseOption(config, tomlSect, CONFIG_BRANCH_DIV_ENABLED,
              funcParam.opaqueBranchDivergenceEnabled);

  // Branch divergence max depth
  parseOption(config, tomlSect, CONFIG_BRANCH_DIV_MAX,
              (int &)funcParam.opaqueBranchDivergenceMaxBranches);

  // Branch divergence algorithm
  std::string branch_div_algo;
  if (parseOption(config, tomlSect, CONFIG_BRANCH_DIV_ALGO, branch_div_algo)) {
    branch_div_algo = str_tolower(branch_div_algo);
    if (validBranchDivergenceAlgorithmNames.count(branch_div_algo) == 0) {
      dbg_fmt("Warning: cannot understand \"{}\" as a branch divergence "
              "algorithm. Algorithm configuration is ignored.\n",
              branch_div_algo);
    } else {
      funcParam.opaqueBranchDivergenceAlgorithm = branch_div_algo;
    }
  }
}

} // namespace

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
  dbg_fmt("[*] Loading obfuscation configuration from file {}.\n", filename);

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

    // Obfuscation enabled
    parseOption(*general_section, CONFIG_GENERAL_SECTION, CONFIG_OBF_ENABLED,
                globalConfig.obfuscationEnabled);

    // Custom library path
    parseOption(*general_section, CONFIG_GENERAL_SECTION,
                CONFIG_CUSTOM_LIB_PATH, globalConfig.libraryPath);

    parseOption(*general_section, CONFIG_GENERAL_SECTION, CONFIG_LINKED_LIBS,
                globalConfig.linkedLibraries);

    // Avoid multiversion symbols
    parseOption(*general_section, CONFIG_GENERAL_SECTION, CONFIG_AVOID_MULTIVER,
                globalConfig.avoidMultiversionSymbol);

    // Search in segment
    parseOption(*general_section, CONFIG_GENERAL_SECTION, CONFIG_SEARCH_SEGMENT,
                globalConfig.searchSegmentForGadget);

    // Print instruction statistics
    parseOption(*general_section, CONFIG_GENERAL_SECTION,
                CONFIG_PRINT_INSTR_STAT, globalConfig.printInstrStat);

    // Print instruction statistics
    parseOption(*general_section, CONFIG_GENERAL_SECTION,
                CONFIG_USE_CHAIN_LABEL, globalConfig.useChainLabel);
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

      const std::string sectname =
          CONFIG_FUNCTIONS_SECTION "." CONFIG_FUNCTIONS_DEFAULT;

      DEBUG_WITH_TYPE(OBF_CONFIG, dbg_fmt("Parsing: [{}]\n", sectname));

      parseFunctionOptions(*default_keys, sectname, defaultParameter);
    }

    // parsing [functions.*] sections
    for (auto &kv : functions_section->as<toml::Table>()) {
      std::string sectname = CONFIG_FUNCTIONS_SECTION "." + kv.first;
      const toml::Value &subsection_data = kv.second;

      // ignoring default since it was parsed already
      if (sectname == CONFIG_FUNCTIONS_SECTION "." CONFIG_FUNCTIONS_DEFAULT) {
        continue;
      }

      DEBUG_WITH_TYPE(OBF_CONFIG, dbg_fmt("Parsing: [{}]\n", sectname));

      std::string function_name;
      // ignoring subsection if it doesn't have a name entry
      if (!parseOption(subsection_data, sectname, CONFIG_FUNCTION_NAME,
                       function_name)) {
        fmt::print(stderr,
                   "Warning: subsection {} does not contain a {} entry. "
                   "Ignoring subsection.\n",
                   sectname, CONFIG_FUNCTION_NAME);
        continue;
      }

      ObfuscationParameter function_ob_parameter;
      parseFunctionOptions(subsection_data, sectname, function_ob_parameter);

      functionsParameter.insert({function_name, function_ob_parameter});
    }
  }
  // =====================================
}

} // namespace ropf
