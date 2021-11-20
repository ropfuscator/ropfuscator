{ }:
let 
  pkgs64 = (import (builtins.fetchTarball {
    name = "nixos-unstable-20211116";
    url =
      "https://releases.nixos.org/nixpkgs/nixpkgs-21.11pre330734.5cb226a06c4/nixexprs.tar.xz";
    sha256 = "0hi1lfp8kq9p4lfqclydgsx5dzc59g71gx1lay2akvn2ibqzhg21";
  }) { });
  pkgs = pkgs64.pkgsi686Linux;
  ropfuscator = import ../default.nix {};
in
  pkgs.mkShell {
    nativeBuildInputs = [ ropfuscator ] ++ ropfuscator.nativeBuildInputs;
    shellHook = "export ROPFUSCATOR_LLC=${ropfuscator}/bin/llc";
}
