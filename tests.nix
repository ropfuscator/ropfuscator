{ pkgs, ropfuscator-utils, ropfuscator_stdenv }:
let
  pkgs32 = pkgs.pkgsi686Linux;

  ropfuscator_tests = ropfuscator_stdenv.mkDerivation {
    pname = "ropfuscator_tests";
    version = "0.1.0";
    stdenv = ropfuscator_stdenv;
    src = ./tests;
    doCheck = true;
    unpackPhase = ''
      runHook preUnpack

      cp -r --no-preserve=mode,ownership $src/* .
      mkdir -p utils
      cp -r --no-preserve=mode,ownership ${ropfuscator-utils}/* utils

      runHook postUnpack
    '';
  };
in ropfuscator_tests
