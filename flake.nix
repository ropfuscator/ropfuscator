{
  inputs = {
    # pinned on fix for https://github.com/NixOS/nixpkgs/pull/166977
    nixpkgs.url = "github:peperunas/nixpkgs/llvm-i686-cross-fix";
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
        localSystem = { inherit system; };
        crossSystem = {
          config = "i686-unknown-linux-gnu";
          useLLVM = true;
        };

        # vanilla upstream nix packages
        pkgs = import nixpkgs {
          inherit localSystem crossSystem;
          overlays = [
            # see: https://github.com/NixOS/nixpkgs/issues/170002
            (self: super: {
              zlib =
                if super.stdenv.hostPlatform != super.stdenv.buildPlatform then
                  super.zlib.overrideAttrs (_: rec {
                    version = "1.2.11";
                    src = builtins.fetchurl {
                      url = "https://www.zlib.net/fossils/zlib-${version}.tar.gz";
                      sha256 =
                        "c3e5e9fdd5004dcb542feda5ee4f0ff0744628baf8ed2dd5d66f8ca1197cb1a1";
                    };
                  })
                else
                  super.zlib;
            })
          ];
        };

        # upstream nix packages that use ROPfuscator as default compiler
        pkgsRopfuscator = import nixpkgs {
          inherit localSystem crossSystem;
          overlays =
            [ (import ./ropfuscator.nix { inherit tinytoml fmt lib librop; }) ];
          };

        lib = nixpkgs.lib;
        librop = librop-git.defaultPackage.${system};
      in rec {
        inherit pkgs pkgsRopfuscator;

        releaseBuild = pkgsRopfuscator.buildPackages.ropfuscator-clang;
        debugBuild = pkgsRopfuscator.buildPackages.ropfuscator-clang-debug;

        defaultPackage = releaseBuild;

        # development shell
        devShell = pkgs.buildPackages.ropfuscator-llvm-debug.overrideAttrs (_: {
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
          llvm = pkgsRopfuscator.buildPackages.ropfuscator-llvm;
          clang = pkgsRopfuscator.buildPackages.ropfuscator-clang;
          tests = import ./tests.nix {
            inherit pkgs ropfuscator-utils librop;
            ropfuscatorStdenv = pkgsRopfuscator.stdenv;
          };
          #  testsDebug = import ./tests.nix {
          #    inherit pkgs ropfuscator-utils librop;
          #    ropfuscatorStdenv = pkgs.stdenvDebug;
          #  };
          # justOne = pkgsVanilla.chocolateDooom.override (old: {
          #   stdenv = pkgsVanilla.overrideCC
          #     old.stdenv
          #     pkgs.buildPackges.ropfuscator-clang;
          # });
        };

        # helper functions
        ropfuscate =
          { deriv, stdenv ? pkgsRopfuscator.stdenvLibrop, config ? "" }:
          let
            stdenv_ = if config == "" then
              stdenv
            else
              pkgs.buildPkgs.overrideCC stdenv (stdenv.cc.override (old: {
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
        ropfuscateLevelZero = { deriv, stdenv ? pkgsRopfuscator.stdenvLibrop }:
          ropfuscate {
            inherit deriv stdenv;
            config = "${ropfuscator-utils}/configs/level0.toml";
          };
        ropfuscateLevelOne = { deriv, stdenv ? pkgsRopfuscator.stdenvLibrop }:
          ropfuscate {
            inherit deriv stdenv;
            config = "${ropfuscator-utils}/configs/level1.toml";
          };
        ropfuscateLevelTwo = { deriv, stdenv ? pkgsRopfuscator.stdenvLibrop }:
          ropfuscate {
            inherit deriv stdenv;
            config = "${ropfuscator-utils}/configs/level2.toml";
          };
        ropfuscateLevelThree = { deriv, stdenv ? pkgsRopfuscator.stdenvLibrop }:
          ropfuscate {
            inherit deriv stdenv;
            config = "${ropfuscator-utils}/configs/level3.toml";
          };
      });
}
