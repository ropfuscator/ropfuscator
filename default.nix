{ }:
let
  pkgs64 = (import (builtins.fetchTarball {
    name = "nixos-unstable-20211116";
    url =
      "https://releases.nixos.org/nixpkgs/nixpkgs-21.11pre330734.5cb226a06c4/nixexprs.tar.xz";
    sha256 = "0hi1lfp8kq9p4lfqclydgsx5dzc59g71gx1lay2akvn2ibqzhg21";
  }) { });
  pkgs = pkgs64.pkgsi686Linux;

  # upstream clang stdenv uses gcc 7.5 (outdated)
  stdenv_clang = pkgs.overrideCC pkgs.stdenv
    (pkgs.clang_10.override ({ gccForLibs = pkgs.gcc.cc; }));

  ext_llvm = pkgs64.fetchurl {
    url =
      "https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.1/llvm-10.0.1.src.tar.xz";
    sha256 = "1wydhbp9kyjp5y0rc627imxgkgqiv3dfirbqil9dgpnbaw5y7n65";
  };

  python-deps = python-packages: with python-packages; [ pygments ];
  python = pkgs.python3.withPackages python-deps;

  derivation_function = { stdenv, cmake, ninja, z3, git, SDL2, SDL2_net
    , SDL2_mixer, pkg-config, libxml2, curl, openal, libpng, libsamplerate }:
    stdenv.mkDerivation {
      pname = "ropfuscator";
      version = "0.1.0";
      nativeBuildInputs = [ cmake ninja git curl python pkg-config z3 ];
      srcs = [ ./cmake ./src ./CMakeLists.txt ];
      patches = [ ./patches/ropfuscator_pass.patch ];
      postPatch = "patchShebangs .";

      cmakeFlags = [ "-DLLVM_TARGETS_TO_BUILD=X86" ];
      unpackPhase = ''
        runHook preUnpack

        tar -xf ${ext_llvm} --strip-components=1

        pushd lib/Target/X86
        mkdir ropfuscator
        for s in $srcs; do
          # strip the hash
          cp -r $s ropfuscator/`echo $s | cut -d "-" -f2`
        done
        chmod +w ropfuscator -R
        ls -lah ropfuscator
        sleep 1
        popd

        runHook postUnpack
      '';
    };
in pkgs.callPackage derivation_function { stdenv = stdenv_clang; }
