{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs";
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

        #  # defaults unwrapped package (in debug mode) to allow development.
        #  # the shell proceeds to setup a complete LLVM tree with ropfuscator inside
        #  devShell = (packages.unwrapped.override { debug = true; }).overrideAttrs
        #    (_: {
        #      shellHook = ''
        #        # move to temporary directory
        #        cd `mktemp -d`
        #        # unpack and configure project
        #        echo "Preparing LLVM source tree..."
        #        eval "$unpackPhase" && runHook patchPhase && eval "$configurePhase"
        #        # get compile_commands.json and put them in root of LLVM tree
        #        cd .. && mv build/compile_commands.json .
        #      '';
        #    });

        # exposed dev "shells" (not really shells as they have ropfuscator compiled)

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
