{
  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    ropfuscator.url = "github:ropfuscator/ropfuscator";
    librop = {
      url = "github:ropfuscator/librop";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, ropfuscator, librop }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        ropfuscator_release =
          import ./release.nix { inherit pkgs ropfuscator; };
        ropfuscator_debug = import ./debug.nix { inherit pkgs ropfuscator; };
      in {
        defaultPackage = ropfuscator_release.ropfuscator;
        stdenv = ropfuscator_release.stdenv;
        debugBuild = ropfuscator_debug.ropfuscator;
        devShell = (import ./shell.nix {
          inherit librop pkgs;
          ropfuscator = ropfuscator_release.ropfuscator;
          ropfuscator_stdenv = ropfuscator_release.stdenv;
        });
      });
}
