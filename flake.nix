{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/4b675777";
    flake-utils.url = "github:numtide/flake-utils";
    librop = {
      url = "github:ropfuscator/librop";
      flake = false;
    };
    ropfuscator.url = "github:ropfuscator/ropfuscator";
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

  outputs = { self, nixpkgs, flake-utils, librop, ropfuscator, ropfuscator-utils
    , tinytoml, fmt }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        ropfuscator_release =
          import ./release.nix { inherit pkgs ropfuscator tinytoml fmt; };
      in {
        defaultPackage = ropfuscator_release.ropfuscator;
        stdenv = ropfuscator_release.stdenv;
        devShell = (import ./shell.nix {
          inherit librop pkgs;
          ropfuscator = ropfuscator_release.ropfuscator;
          ropfuscator_stdenv = ropfuscator_release.stdenv;
        });
      });
}
