{
  inputs = {
    # pinned on fix for https://github.com/NixOS/nixpkgs/pull/166977
    nixpkgs.url = "github:peperunas/nixpkgs/llvm-i686-cross-fix";
    flake-utils.url = "github:numtide/flake-utils";
    librop-git = {
      url = "git+ssh://git@github.com/ropfuscator/librop.git";
      flake = false;
    };
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
        zlib-fix = import ./zlib-fix.nix;

        ropfuscatorLibcOverlay = (self: super: {
          stdenv = super.overrideCC super.stdenv (super.stdenv.cc.override
            (old: {
              extraBuildCommands = old.extraBuildCommands
                + "echo '-mllvm --ropfuscator-library=${self.glibc}/lib/libc.so.6' >> $out/nix-support/cc-cflags";
            }));
        });

        ropfuscatorLibropOverlay = (self: super:
          let librop-path = "${librop}/lib/librop.so";
          in {
            stdenv = super.overrideCC super.stdenv (super.stdenv.cc.override
              (old: {
                extraBuildCommands = old.extraBuildCommands
                  + "echo '-mllvm --ropfuscator-library=${librop-path} ${librop-path}' >> $out/nix-support/cc-cflags";
              }));
          });

        localSystem = { inherit system; };
        crossSystem = {
          config = "i686-unknown-linux-gnu";
          useLLVM = true;
        };

        # vanilla upstream nix packages
        pkgs = import nixpkgs {
          inherit localSystem crossSystem;
          overlays = [ zlib-fix ];
        };

        # upstream nix packages that use ROPfuscator as default compiler
        # the pass is disabled, though, because no library is defined
        pkgsRopfuscator = import nixpkgs {
          inherit localSystem crossSystem;
          overlays = [
            zlib-fix
            (import ./ropfuscator.nix { inherit tinytoml fmt lib; })
          ];
        };

        # upstream nix packages that use ROPfuscator as default compiler
        # with libc as default library
        pkgsRopfuscatorLibc = import nixpkgs {
          inherit localSystem crossSystem;
          overlays = [
            zlib-fix
            (import ./ropfuscator.nix { inherit tinytoml fmt lib; })
          ];
          crossOverlays = [ ropfuscatorLibcOverlay ];
        };

        # upstream nix packages that use ROPfuscator as default compiler
        # with librop as default library
        pkgsRopfuscatorLibrop = import nixpkgs {
          inherit localSystem crossSystem;
          overlays = [
            zlib-fix
            (import ./ropfuscator.nix { inherit tinytoml fmt lib; })
          ];
          crossOverlays = [ ropfuscatorLibropOverlay ];
        };

        lib = nixpkgs.lib;
        librop = pkgs.callPackage (librop-git + "/pkg.nix") { };
      in rec {
        inherit pkgs pkgsRopfuscator pkgsRopfuscatorLibc pkgsRopfuscatorLibrop;

        releaseBuild = pkgsRopfuscator.buildPackages.ropfuscator-clang;
        debugBuild = pkgsRopfuscator.buildPackages.ropfuscator-clang-debug;

        defaultPackage = releaseBuild;

       # # development shell
       # devShell = pkgs.buildPackages.ropfuscator-llvm-debug.overrideAttrs (_: {
       #   shellHook = ''
       #     # move to temporary directory
       #     cd `mktemp -d`
       #     # unpack and configure project
       #     echo "Preparing LLVM source tree..."
       #     eval "$unpackPhase" && cd llvm && runHook patchPhase && eval "$configurePhase"
       #     # get compile_commands.json and put them in root of LLVM tree
       #     cd .. && mv build/compile_commands.json .
       #   '';
       # });

        # exposed packages
        packages = flake-utils.lib.flattenTree {
          llvm = pkgsRopfuscator.buildPackages.ropfuscator-llvm;
          clang = pkgsRopfuscator.buildPackages.ropfuscator-clang;
          chocolateDoom = pkgsRopfuscator.chocolateDoom;
          tests = pkgsRopfuscator.callPackage ./tests.nix {
            inherit ropfuscator-utils librop;
          };
          #  testsDebug = import ./tests.nix {
          #    inherit ropfuscator-utils librop;
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
              pkgs.buildPackages.overrideCC stdenv (stdenv.cc.override (old: {
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
