{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/4b675777";
    flake-utils.url = "github:numtide/flake-utils";
    librop.url = "git+ssh://git@github.com/ropfuscator/librop.git";
    ropfuscator-utils = {
      url = "git+ssh://git@github.com/ropfuscator/utilities.git";
      flake = false;
    };
    fmt = {
      url = "github:fmtlib/fmt/7bdf0628";
      flake = false;
    };
    tinytoml = {
      url = "github:mayah/tinytoml/ea34092";
      flake = false;
    };
    llvm = {
      url =
        "https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.1/llvm-10.0.1.src.tar.xz";
      flake = false;
    };
    clang = {
      url =
        "https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.1/clang-10.0.1.src.tar.xz";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, librop, ropfuscator-utils, tinytoml
    , fmt, llvm, clang }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        librop_drv = librop.defaultPackage.${system};
        ropfuscator = import ./ropfuscator.nix {
          inherit pkgs tinytoml fmt llvm clang;
          lib = nixpkgs.lib;
        };
      in rec {
        releaseBuild = ropfuscator.ropfuscator;
        releaseCcacheBuild = ropfuscator.ropfuscatorCcache;
        debugBuild = ropfuscator.ropfuscatorDebug;
        debugCcacheBuild = ropfuscator.ropfuscatorCcacheDebug;
        ropfuscatorStdenv = ropfuscator.stdenv;
        ropfuscatorStdenvCcache = ropfuscator.stdenvCcache;
        ropfuscatorStdenvDebug = ropfuscator.stdenvDebug;
        ropfuscatorStdenvCcacheDebug = ropfuscator.stdenvCcacheDebug;

        defaultPackage = releaseBuild;

        # exposed shells
        devShells = flake-utils.lib.flattenTree {
          release = import ./shell.nix {
            inherit pkgs system;
            lib = nixpkgs.lib;
            librop = librop_drv;
            ropfuscatorStdenv = ropfuscatorStdenv;
          };
          releaseCcache = import ./shell.nix {
            inherit pkgs system;
            lib = nixpkgs.lib;
            librop = librop_drv;
            ropfuscatorStdenv = ropfuscatorStdenvCcache;
          };
          debug = import ./shell.nix {
            inherit pkgs system;
            lib = nixpkgs.lib;
            librop = librop_drv;
            ropfuscatorStdenv = ropfuscatorStdenvDebug;
            debug = true;
          };
          debugCcache = import ./shell.nix {
            inherit pkgs system;
            lib = nixpkgs.lib;
            librop = librop_drv;
            ropfuscatorStdenv = ropfuscatorStdenvCcacheDebug;
            debug = true;
          };
        };

        # exposed packages
        packages = flake-utils.lib.flattenTree {
          release = releaseBuild;
          debug = debugBuild;
          releaseCcache = releaseCcacheBuild;
          debugCcache = debugCcacheBuild;
          stdenv = ropfuscatorStdenv;
          stdenvDebug = ropfuscatorStdenvDebug;
          tests = import ./tests.nix {
            inherit pkgs ropfuscator-utils ropfuscatorStdenv;
            librop = librop_drv;
          };
        };
      });
}
