{ pkgs, llvm, clang, lib, fmt, tinytoml }:
let
  pkgs32 = pkgs.pkgsi686Linux;

  python-deps = python-packages: with python-packages; [ pygments ];
  python = pkgs32.python3.withPackages python-deps;

  derivation_function =
    { stdenv, cmake, ninja, git, curl, pkg-config, z3, libxml2, debug ? false }:
    stdenv.mkDerivation {
      pname = "ropfuscator";
      version = "0.1.0";
      nativeBuildInputs = [ cmake ninja git curl python pkg-config z3 libxml2 ];
      srcs = [ ./cmake ./src ./thirdparty ];
      patches = [ ./patches/ropfuscator_pass.patch ];
      postPatch = "patchShebangs .";

      cmakeFlags = [ "-DLLVM_TARGETS_TO_BUILD=X86" ]
        ++ lib.optional (debug == true) "-DCMAKE_BUILD_TYPE=Debug";
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
        popd

        runHook postUnpack
      '';
    };
in let
  ropfuscator =
    pkgs32.callPackage derivation_function { stdenv = pkgs32.stdenv; };
  wrapped_clang = pkgs32.llvmPackages_10.clang.override { cc = ropfuscator; };
  stdenv = pkgs32.overrideCC pkgs32.clangStdenv wrapped_clang;
in {
  ropfuscator = ropfuscator;
  stdenv = stdenv;
}
