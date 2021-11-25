{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/4b675777";
    flake-utils.url = "github:numtide/flake-utils";
    librop = {
      url = "github:ropfuscator/librop";
      flake = false;
    };
    ropfuscator-utils = {
      url = "github:ropfuscator/utilities";
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

  outputs =
    { self, nixpkgs, flake-utils, librop, ropfuscator-utils, tinytoml, fmt }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        ropfuscator = import ./ropfuscator.nix {
          inherit pkgs tinytoml fmt;
          lib = nixpkgs.lib;
        };
      in rec {
        defaultPackage = ropfuscator.ropfuscator;
        releaseBuild = defaultPackage;
        debugBuild = defaultPackage.overrideAttrs (_: { debug = true; });
        ropfuscator_stdenv = ropfuscator.stdenv;

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
        };
      });
}
