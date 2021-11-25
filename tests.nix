{ pkgs, ropfuscator, ropfuscator_stdenv, ropfuscator-utils }:
let
  pkgs32 = pkgs.pkgsi686Linux;

  ropfuscator_tests = ropfuscator.overrideAttrs (_: {
    pname = "ropfuscator_tests";
    stdenv = ropfuscator_stdenv;
    src = ./tests;
    doCheck = true;
    unpackPhase = ''
      runHook preUnpack
      
      cp -r --no-preserve=mode,ownership ${src}/* .
      cp -r --no-preserve=mode,ownership ${ropfuscator-utils}/* utils

      runHook postUnpack
    '';
  });
in ropfuscator_tests
