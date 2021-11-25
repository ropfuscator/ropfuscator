{ pkgs, ropfuscator, ropfuscator_stdenv, ropfuscator-utils, tinytoml, fmt, llvm, clang }:
let
  pkgs32 = pkgs.pkgsi686Linux;

  ropfuscator_tests = ropfuscator.overrideAttrs (_: {
    pname = "ropfuscator_tests";
    stdenv = ropfuscator_stdenv;
    src = ./tests;
    doCheck = true;
  });
in ropfuscator_tests
