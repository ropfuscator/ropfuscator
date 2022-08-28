#include "ROPfuscatorConfig.h"
#include "Debug.h"
#include <cctype>
#include <regex>
#include <set>
#include <string>
#include <vector>

#define TOML_HAVE_FAILWITH_REPLACEMENT

namespace toml {
template <typename... Args> [[noreturn]] void failwith(Args &&...args) {
  std::stringstream ss;
  // this will expand to ss << args_0, ss << args_1, ...
  int               _dummy[] = {(ss << args, 0)...};
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
                        const std::string &sectionname,
                        const std::string &key,
                        T                 &ref) {
  if (const toml::Value *v = section.find(key)) {
    if (!v->is<T>()) {
      dbg_fmt("TOML parse warning: {}.{} should have type {}, thus ignored\n",
              sectionname,
              key,
              toml::internal::type_name<T>());

      return false;
    }
    const auto &value = v->as<T>();
    ref               = value;

    // TODO: implement formattable<T> for libfmt
    //    DEBUG_WITH_TYPE(OBF_CONFIG,
    //                   dbg_fmt("Setting {}.{} to {}\n", sectionname, key,
    //                   value));
    return true;
  }

  return false;
}

std::string strTolower(const std::string &s) {
  std::string s_lower = s;
  std::transform(s_lower.begin(),
                 s_lower.end(),
                 s_lower.begin(),
                 [](unsigned char c) { return std::tolower(c); });
  return s_lower;
}

std::set<std::string> validOpaquePredicateAlgorithmNames = {
    OPAQUE_CONSTANT_ALGORITHM_MOV,
    OPAQUE_CONSTANT_ALGORITHM_R3SAT32,
    OPAQUE_CONSTANT_ALGORITHM_MULTCOMP,
};

std::set<std::string> validOpaquePredicateInputAlgorithmNames = {
    OPAQUE_RANDOM_ALGORITHM_CONSTANT,
    OPAQUE_RANDOM_ALGORITHM_ADDREG,
    OPAQUE_RANDOM_ALGORITHM_RDTSC,
};

std::set<std::string> validBranchDivergenceAlgorithmNames = {
    OPAQUE_BRANCH_ALGORITHM_ADDREG_MOV,
    OPAQUE_BRANCH_ALGORITHM_NEGSTK_MOV,
    OPAQUE_BRANCH_ALGORITHM_RDTSC_MOV,
};

void parseFunctionOptions(const toml::Value    &config,
                          const std::string    &tomlSect,
                          ObfuscationParameter &funcParam) {

  /* =========================
   * TOGGLES PARSING
   */

  // Obfuscation enabled
  parseOption(config,
              tomlSect,
              CONFIG_OBFUSCATION_ENABLED,
              funcParam.obfuscationEnabled);

  // Opaque predicates enabled
  parseOption(config,
              tomlSect,
              CONFIG_OPAQUE_PREDICATED_ENABLED,
              funcParam.opaquePredicatesEnabled);

  // Obfuscation of immediate operand enabled
  parseOption(config,
              tomlSect,
              CONFIG_OPAQUE_IMMEDIATE_OPERANDS_ENABLED,
              funcParam.opaqueImmediateOperandsEnabled);

  // Opaque predicates (contextual OP) enabled
  parseOption(config,
              tomlSect,
              CONFIG_CONTEXTUAL_OPAQUE_PREDICATES_ENABLED,
              funcParam.contextualOpaquePredicatesEnabled);

  // Obfuscation of branch target enabled
  parseOption(config,
              tomlSect,
              CONFIG_OPAQUE_BRANCH_TARGETS_ENABLED,
              funcParam.opaqueBranchTargetsEnabled);

  // Obfuscation of stack saved values enabled
  parseOption(config,
              tomlSect,
              CONFIG_OPAQUE_STACK_VALUES_ENABLED,
              funcParam.opaqueSavedStackValuesEnabled);

  // Gadget addresses obfuscation enabled
  parseOption(config,
              tomlSect,
              CONFIG_OPAQUE_GADGET_ADDRESSES_ENABLED,
              funcParam.opaqueGadgetAddressesEnabled);

  /* =========================
   * STRINGS PARSING
   */

  // Opaque predicates algorithm
  std::string op_algo, op_input_algo;
  if (parseOption(config,
                  tomlSect,
                  CONFIG_OPAQUE_PREDICATES_ALGORITHM,
                  op_algo)) {
    op_algo = strTolower(op_algo);
    if (validOpaquePredicateAlgorithmNames.count(op_algo) == 0) {
      dbg_fmt("Warning: cannot understand \"{}\" as an opaque predicate "
              "algorithm. Algorithm configuration is ignored.\n",
              op_algo);
    } else {
      funcParam.opaqueConstantsAlgorithm = op_algo;
    }
  }

  if (parseOption(config,
                  tomlSect,
                  CONFIG_OPAQUE_PREDICATES_INPUT_ALGORITHM,
                  op_input_algo)) {
    op_input_algo = strTolower(op_input_algo);
    if (validOpaquePredicateInputAlgorithmNames.count(op_input_algo) == 0) {
      dbg_fmt("Warning: cannot understand \"{}\" as an opaque predicate "
              "input algorithm. Algorithm configuration is ignored.\n",
              op_input_algo);
    } else {
      funcParam.opaqueInputGenAlgorithm = op_input_algo;
    }
  }

  /* =========================
   * VALUES PARSING
   */

  // gadget addresses percentage
  int addresses_obfuscation_percentage;
  if (parseOption(config,
                  tomlSect,
                  CONFIG_OPAQUE_GADGET_ADDRESSES_PERCENTAGE,
                  addresses_obfuscation_percentage)) {
    if (addresses_obfuscation_percentage < 0 ||
        addresses_obfuscation_percentage > 100) {
      dbg_fmt("Ignoring address obfuscation percentage \"{}\". It should be a "
              "value between 0 and 100. Ignoring.",
              addresses_obfuscation_percentage);
    } else {
      funcParam.gadgetAddressesObfuscationPercentage =
          addresses_obfuscation_percentage;
    }
  }

  // immediates percentage
  int immediates_obfuscation_percentage;
  if (parseOption(config,
                  tomlSect,
                  CONFIG_OPAQUE_IMMEDIATE_OPERANDS_PERCENTAGE,
                  immediates_obfuscation_percentage)) {
    if (immediates_obfuscation_percentage < 0 ||
        immediates_obfuscation_percentage > 100) {
      dbg_fmt("Ignoring immediate operands obfuscation percentage \"{}\". It "
              "should be a "
              "value between 0 and 100. Ignoring.",
              immediates_obfuscation_percentage);
    } else {
      funcParam.opaqueImmediateOperandsPercentage =
          immediates_obfuscation_percentage;
    }
  }

  // branches percentage
  int branches_obfuscation_percentage;
  if (parseOption(config,
                  tomlSect,
                  CONFIG_OPAQUE_BRANCH_TARGETS_PERCENTAGE,
                  branches_obfuscation_percentage)) {
    if (branches_obfuscation_percentage < 0 ||
        branches_obfuscation_percentage > 100) {
      dbg_fmt("Ignoring branch targets obfuscation percentage \"{}\". It "
              "should be a "
              "value between 0 and 100. Ignoring.",
              branches_obfuscation_percentage);
    } else {
      funcParam.opaqueBranchTargetsPercentage = branches_obfuscation_percentage;
    }
  }
}

} // namespace

ObfuscationParameter
ROPfuscatorConfig::getParameter(const std::string &funcname) const {
  for (auto &kv : functionsParameter) {
    auto &function_name         = kv.first;
    auto &function_ob_parameter = kv.second;
    auto  function_regex        = std::regex(function_name);

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
  dbg_fmt("[*] Loading obfuscation configuration \"{}\".\n", filename);

  toml::ParseResult parseResult = toml::parseFile(filename);
  if (!parseResult.valid()) {
    fmt::print(stderr,
               "Error while parsing configuration file: {}\n",
               parseResult.errorReason);
    exit(-1);
  }

  const toml::Value &configuration_data = parseResult.value;

  // setting default values
  globalConfig     = GlobalConfig();
  defaultParameter = ObfuscationParameter();

  // =====================================
  // parsing [general] section, if present
  if (auto *general_section = configuration_data.find(CONFIG_GENERAL_SECTION)) {

    // Obfuscation enabled
    parseOption(*general_section,
                CONFIG_GENERAL_SECTION,
                CONFIG_OBFUSCATION_ENABLED,
                globalConfig.obfuscationEnabled);

    // Custom library path
    parseOption(*general_section,
                CONFIG_GENERAL_SECTION,
                CONFIG_CUSTOM_LIB_PATH,
                globalConfig.libraryPath);

    // library SHA1 hash
    parseOption(*general_section,
                CONFIG_GENERAL_SECTION,
                CONFIG_LIB_SHA1,
                globalConfig.librarySHA1);
    globalConfig.librarySHA1 = strTolower(globalConfig.librarySHA1);

    // linked libraries
    parseOption(*general_section,
                CONFIG_GENERAL_SECTION,
                CONFIG_LINKED_LIBS,
                globalConfig.linkedLibraries);

    // Avoid multiversion symbols
    parseOption(*general_section,
                CONFIG_GENERAL_SECTION,
                CONFIG_AVOID_MULTIVER,
                globalConfig.avoidMultiversionSymbol);

    // Search in segment
    parseOption(*general_section,
                CONFIG_GENERAL_SECTION,
                CONFIG_SEARCH_SEGMENT,
                globalConfig.searchSegmentForGadget);

    // Show obfuscation progress
    parseOption(*general_section,
                CONFIG_GENERAL_SECTION,
                CONFIG_SHOW_PROGRESS,
                globalConfig.showProgress);

    // Print instruction statistics
    parseOption(*general_section,
                CONFIG_GENERAL_SECTION,
                CONFIG_PRINT_INSTR_STAT,
                globalConfig.printInstrStat);

    // Print instruction statistics
    parseOption(*general_section,
                CONFIG_GENERAL_SECTION,
                CONFIG_USE_CHAIN_LABEL,
                globalConfig.useChainLabel);

    // RNG seed
    parseOption(*general_section,
                CONFIG_GENERAL_SECTION,
                CONFIG_RNG_SEED,
                (int &)globalConfig.rng_seed);

    // Write instruction statistics to file
    parseOption(*general_section,
                CONFIG_GENERAL_SECTION,
                CONFIG_WRITE_INSTR_STAT,
                globalConfig.writeInstrStat);
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
      std::string        sectname = CONFIG_FUNCTIONS_SECTION "." + kv.first;
      const toml::Value &subsection_data = kv.second;

      // ignoring default since it was parsed already
      if (sectname == CONFIG_FUNCTIONS_SECTION "." CONFIG_FUNCTIONS_DEFAULT) {
        continue;
      }

      DEBUG_WITH_TYPE(OBF_CONFIG, dbg_fmt("Parsing: [{}]\n", sectname));

      std::string function_name;
      // ignoring subsection if it doesn't have a name entry
      if (!parseOption(subsection_data,
                       sectname,
                       CONFIG_FUNCTION_NAME,
                       function_name)) {
        fmt::print(stderr,
                   "Warning: subsection {} does not contain a {} entry. "
                   "Ignoring subsection.\n",
                   sectname,
                   CONFIG_FUNCTION_NAME);
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
