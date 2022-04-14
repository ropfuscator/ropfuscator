{
  inputs = {
    # pinned on fix for https://github.com/NixOS/nixpkgs/pull/166977
    nixpkgs.url = "github:peperunas/nixpkgs/multibintoolsdedup";
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
    flake-utils.lib.eachSystem [ flake-utils.lib.system.x86_64-linux ] (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        pkgs32 = pkgs.pkgsi686Linux;
        lib = nixpkgs.lib;

        librop = librop-git.defaultPackage.${system};

        ropfuscator = import ./ropfuscator.nix {
          inherit nixpkgs pkgs tinytoml fmt lib librop;
        };
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
          chocolateDoom = ropfuscate {
            stdenv = ropfuscator.stdenvLibrop;
            deriv = pkgs32.chocolateDoom;
          };
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

        ropfuscate = { deriv, stdenv ? ropfuscator.stdenvLibrop, config ? "" }:
          let
            stdenv_ = if config == "" then
              stdenv
            else
              pkgs.overrideCC stdenv (stdenv.cc.override (old: {
                extraBuildCommands = old.extraBuildCommands + ''
                  echo "-mllvm --ropfuscator-config=${config}" >> $out/nix-support/cc-cflags
                '';
              }));

            config_name = if (config == "") then
              ""
            else
              lib.removeSuffix ".toml"
              (lib.lists.last (lib.splitString "/" config));
          in (deriv.override { stdenv = stdenv_; }).overrideAttrs (old: {
            pname = old.pname + "-ropfuscated"
              + lib.optionalString (config != "") "-${config_name}";
            doCheck = true;
          });

        # helper functions
        ropfuscateLevelZero = { deriv, stdenv ? ropfuscator.stdenvLibrop }:
          ropfuscate {
            inherit deriv stdenv;
            config = "${ropfuscator-utils}/configs/level0.toml";
          };
        ropfuscateLevelOne = { deriv, stdenv ? ropfuscator.stdenvLibrop }:
          ropfuscate {
            inherit deriv stdenv;
            config = "${ropfuscator-utils}/configs/level1.toml";
          };
        ropfuscateLevelTwo = { deriv, stdenv ? ropfuscator.stdenvLibrop }:
          ropfuscate {
            inherit deriv stdenv;
            config = "${ropfuscator-utils}/configs/level2.toml";
          };
        ropfuscateLevelThree = { deriv, stdenv ? ropfuscator.stdenvLibrop }:
          ropfuscate {
            inherit deriv stdenv;
            config = "${ropfuscator-utils}/configs/level3.toml";
          };
      });
}
