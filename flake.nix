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
        pkgsVanilla = import nixpkgs { inherit localSystem crossSystem; };
        pkgs = import nixpkgs {
          inherit localSystem crossSystem;
          overlays =
            [ (import ./ropfuscator.nix { inherit tinytoml fmt lib librop; }) ];
        };
        lib = nixpkgs.lib;

        librop = librop-git.defaultPackage.${system};
      in rec {
        inherit pkgs pkgsVanilla;

        releaseBuild = pkgs.buildPackages.ropfuscator-clang;
        debugBuild = pkgs.buildPackages.ropfuscator-clang-debug;

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
          llvm = pkgs.buildPackages.ropfuscator-llvm;
          clang = pkgs.buildPackages.ropfuscator-clang;
          release = releaseBuild;
          debug = debugBuild;
          inherit (pkgs) stdenv stdenvLibrop stdenvLibc chocolateDoom;
          tests = import ./tests.nix {
            inherit pkgs ropfuscator-utils librop;
            ropfuscatorStdenv = pkgs.stdenv;
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

        /* ropfuscate = { deriv, stdenv ? ropfuscator.stdenvLibrop, config ? "" }:
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
        */
      });
}
