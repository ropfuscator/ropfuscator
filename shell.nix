{ }:
let
  pkgs64 = (import (builtins.fetchTarball {
    name = "nixos-unstable-20211116";
    url =
      "https://releases.nixos.org/nixpkgs/nixpkgs-21.11pre330734.5cb226a06c4/nixexprs.tar.xz";
    sha256 = "0hi1lfp8kq9p4lfqclydgsx5dzc59g71gx1lay2akvn2ibqzhg21";
  }) { });
  pkgs = pkgs64.pkgsi686Linux;
  ropf_mod = import ../default.nix { };
  myStdenv = pkgs.mkShell.override { stdenv = ropf_mod.stdenv; };
in myStdenv {
  nativeBuildInputs = ropf_mod.ropfuscator.nativeBuildInputs;
  shellHook = ''
    export ROPFUSCATOR_LLC=${ropf_mod.ropfuscator}/bin/llc
    export ROPFUSCATOR_CLANG=${ropf_mod.stdenv.cc}/bin/clang
  '';
}
