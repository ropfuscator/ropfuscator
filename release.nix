{ pkgs }:
let
  pkgs32 = pkgs.pkgsi686Linux;
  
  ext_llvm = pkgs32.fetchurl {
    url =
      "https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.1/llvm-10.0.1.src.tar.xz";
    sha256 = "1wydhbp9kyjp5y0rc627imxgkgqiv3dfirbqil9dgpnbaw5y7n65";
  };

  ext_clang = pkgs32.fetchurl {
    url =
      "https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.1/clang-10.0.1.src.tar.xz";
    sha256 = "091bvcny2lh32zy8f3m9viayyhb2zannrndni7325rl85cwgr6pr";
  };

  python-deps = python-packages: with python-packages; [ pygments ];
  python = pkgs32.python3.withPackages python-deps;

  derivation_function =
    { stdenv, cmake, ninja, git, curl, pkg-config, z3, libxml2 }:
    stdenv.mkDerivation {
      pname = "ropfuscator";
      version = "0.1.0";
      nativeBuildInputs = [ cmake ninja git curl python pkg-config z3 libxml2 ];
      srcs = [
        ./cmake
        ./src
        ./thirdparty
      ];
      patches = [ ./patches/ropfuscator_pass.patch ];
      postPatch = "patchShebangs .";

      cmakeFlags = [ "-DLLVM_TARGETS_TO_BUILD=X86" ];
      unpackPhase = ''
        runHook preUnpack

        tar -xf ${ext_llvm} --strip-components=1

        # insert clang
        pushd tools
        tar -xf ${ext_clang}
        popd

        # insert ropfuscator
        pushd lib/Target/X86
        mkdir ropfuscator
        for s in $srcs; do
          cp -r $s ropfuscator
        done
        chmod +w ropfuscator -R
        popd

        runHook postUnpack
      '';
    };
in let
  ropfuscator = pkgs32.callPackage derivation_function { stdenv = pkgs32.stdenv; };
  wrapped_clang = pkgs32.llvmPackages_10.clang.override { cc = ropfuscator; };
  stdenv = pkgs32.overrideCC pkgs32.clangStdenv wrapped_clang;
in {
  ropfuscator = ropfuscator;
  stdenv = stdenv;
}
