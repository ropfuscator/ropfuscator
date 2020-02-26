#ifndef ROPFUSCATORCONFIG_H
#define ROPFUSCATORCONFIG_H

#include <string>

// default configuration (defined in OpaqueConstruct.h)
extern const std::string OPAQUE_CONSTANT_ALGORITHM_MOV;
extern const std::string OPAQUE_BRANCH_ALGORITHM_ADDREG_MOV;

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
    // TODO: not implemented (maybe implement in .cpp?)
  }
};

#endif
