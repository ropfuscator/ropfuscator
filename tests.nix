{ pkgs, ropfuscator, ropfuscator_stdenv, ropfuscator-utils, tinytoml, fmt, llvm, clang }:
let
  pkgs32 = pkgs.pkgsi686Linux;

  ropfuscator_tests = ropfuscator.overrideAttrs (_: {
    pname = "ropfuscator_tests";
    stdenv = ropfuscator_stdenv;
    srcs = ropfuscator.srcs ++ [ ./tests ];
    doCheck = true;
    unpackPhase = ''
      runHook preUnpack

      cp --no-preserve=mode,ownership -r ${llvm}/* .

      # insert clang
      pushd tools
        mkdir clang
        cp --no-preserve=mode,ownership -r ${clang}/* clang
      popd

      # insert ropfuscator
      pushd lib/Target/X86
        mkdir ropfuscator
        
        for s in $srcs; do
          # strip hashes
          cp --no-preserve=mode,ownership -r $s ropfuscator/`echo $s | cut -d "-" -f 2`
        done
        
        # manually copy submodules due to nix currently not having
        # proper support for submodules
        pushd ropfuscator/thirdparty
          mkdir -p {tinytoml,fmt}
          cp --no-preserve=mode,ownership -r ${tinytoml}/* tinytoml
          cp --no-preserve=mode,ownership -r ${fmt}/* fmt
        popd

        pushd ropfuscator/tests
          mkdir -p utils
          cp --no-preserve=mode,ownership -r ${ropfuscator-utils}/* utils
        popd

        tree ropfuscator
      popd
      
      runHook postUnpack
    '';
  });
in ropfuscator_tests
