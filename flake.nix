{
  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    librop = {
      url = "github:ropfuscator/librop";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, librop }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        ropfuscator_release = import ./release.nix { inherit pkgs; };
        ropfuscator_debug = import ./debug.nix { inherit pkgs; };
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
