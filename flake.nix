{
  inputs = {
    # pinned on fix for https://github.com/NixOS/nixpkgs/issues/146865
    nixpkgs.url =
      "github:nixos/nixpkgs/5e540d6ee674183446d57666f5fccc0b57001fe4";
    flake-utils.url = "github:numtide/flake-utils";
    librop-git.url = "git+ssh://git@github.com/ropfuscator/librop.git";
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
  };

  outputs = { self, nixpkgs, flake-utils, librop-git, ropfuscator-utils
    , tinytoml, fmt }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        pkgs32 = pkgs.pkgsi686Linux;
        lib = nixpkgs.lib;

        librop = librop-git.defaultPackage.${system};

        ropfuscator =
          import ./ropfuscator.nix { inherit pkgs tinytoml fmt lib librop; };
      in rec {
        releaseBuild = ropfuscator.ropfuscator-clang;
        debugBuild = ropfuscator.ropfuscator-clang-debug;

        defaultPackage = releaseBuild;

        # development shell
        devShell = ropfuscator.ropfuscator-llvm-debug.overrideAttrs (_: {
          shellHook = ''
            # move to temporary directory
            cd `mktemp -d`
            # unpack and configure project
            echo "Preparing LLVM source tree..."
            eval "$unpackPhase" && cd llvm && runHook patchPhase && eval "$configurePhase"
            # get compile_commands.json and put them in root of LLVM tree
            cd .. && mv build/compile_commands.json .
          '';
        });

        # exposed packages
        packages = flake-utils.lib.flattenTree {
          llvm = ropfuscator.ropfuscator-llvm;
          clang = ropfuscator.ropfuscator-clang;
          release = releaseBuild;
          debug = debugBuild;
          stdenv = ropfuscator.stdenv;
          stdenvDebug = ropfuscator.stdenvDebug;
          stdenvLibrop = ropfuscator.stdenvLibrop;
          stdenvLibc = ropfuscator.stdenvLibc;
          tests = import ./tests.nix {
            inherit ropfuscator-utils librop;
            ropfuscatorStdenv = ropfuscator.stdenv;
            pkgs = pkgs32;
          };
          testsDebug = import ./tests.nix {
            inherit ropfuscator-utils librop;
            ropfuscatorStdenv = ropfuscator.stdenvDebug;
            pkgs = pkgs32;
          };
        };
      });
}
