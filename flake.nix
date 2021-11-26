{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/4b675777";
    flake-utils.url = "github:numtide/flake-utils";
    librop = {
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
        ropfuscator = import ./ropfuscator.nix {
          inherit pkgs tinytoml fmt llvm clang;
          lib = nixpkgs.lib;
        };
      in rec {
        defaultPackage = ropfuscator.ropfuscator;
        releaseBuild = defaultPackage;
        debugBuild = defaultPackage.override { debug = true; };
        ropfuscator_stdenv = ropfuscator.stdenv;
        ropfuscator_tests =
          import ./tests.nix { inherit pkgs ropfuscator_stdenv; };

        devShells = {
          default = import ./shell.nix {
            inherit pkgs librop ropfuscator_stdenv;
            ropfuscator = releaseBuild;
          };
          debug = import ./shell.nix {
            inherit pkgs librop ropfuscator_stdenv;
            ropfuscator = debugBuild;
          };
        };

        devShell = devShells.default;
        packages = {
          releaseBuild = releaseBuild;
          debugBuild = debugBuild;
          testsBuild = ropfuscator_tests;
          stdenv = ropfuscator_stdenv;
        };
      });
}
