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

        # defaults unwrapped package (in debug mode) to allow development.
        # the shell proceeds to setup a complete LLVM tree with ropfuscator inside
        devShell = (packages.unwrapped.override { debug = true; }).overrideAttrs
          (_: {
            shellHook = ''
              # move to temporary directory
              cd `mktemp -d`
              # unpack and configure project
              echo "Preparing LLVM source tree..."
              eval "$unpackPhase" && runHook patchPhase && eval "$configurePhase"
              # get compile_commands.json and put them in root of LLVM tree
              cd .. && mv build/compile_commands.json .
            '';
          });

        # exposed dev "shells" (not really shells as they have ropfuscator compiled)
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
          unwrapped = ropfuscator.ropfuscator-unwrapped;
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
