{ pkgs, librop, ropfuscatorStdenv, system, lib, debug ? false }:
let
  pkgs32 = pkgs.pkgsi686Linux;
  ropfuscatorLibropStdenv = pkgs.stdenvAdapters.addAttrsToDerivation {
    NIX_CFLAGS_COMPILE = [
      "-mllvm --ropfuscator-library=${librop}/lib/librop.so -L${librop}/lib -lrop"
    ] ++ lib.optional (debug == true)
      "-mllvm -debug-only=xchg_chains,ropchains,processed_instr,liveness_analysis";
  } ropfuscatorStdenv;
  ropfuscatorShell =
    pkgs32.mkShell.override { stdenv = ropfuscatorLibropStdenv; };
in ropfuscatorShell { buildInputs = [ ropfuscatorLibropStdenv ]; }
