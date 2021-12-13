{ pkgs, librop, ropfuscatorStdenv, system }:
let
  pkgs32 = pkgs.pkgsi686Linux;
  ropfuscatorLibropStdenv = pkgs.stdenvAdapters.addAttrsToDerivation {
    NIX_CFLAGS_COMPILE =
      "-mllvm --ropfuscator-library=${librop}/lib/librop.so -L${librop}/lib -lrop";
  } ropfuscatorStdenv;
  myStdenv = pkgs32.mkShell.override { stdenv = ropfuscatorLibropStdenv; };
in pkgs32.mkShell.override { stdenv = myStdenv; }
