{
  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  inputs.flake-utils.url = "github:numtide/flake-utils";
  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (
      let pkgs = nixpkgs.legacyPackages.i686-linux;
      in { defaultPackage = pkgs.callPackage ./default.nix { }; });
}
