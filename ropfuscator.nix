{ pkgs, llvm, clang, lib, fmt, tinytoml }:
let
  pkgs32 = pkgs.pkgsi686Linux;
  python-deps = python-packages: with python-packages; [ pygments ];
  python = pkgs.python3.withPackages python-deps;
  ccache_path = "/nix/var/cache/ccache";

  derivation_function = { stdenv, llvmPackages_13, cmake, git, curl, pkg-config
    , z3, libxml2, ninja, ccache, glibc_multi, use_ccache ? false, debug ? false
    }:
    stdenv.mkDerivation {
      pname = "ropfuscator";
      version = "0.1.0";
      enableParallelBuilding = true;
      nativeBuildInputs =
        [ cmake git curl pkg-config ninja llvmPackages_13.bintools ]
        ++ lib.optional (use_ccache == true) [ ccache ];
      buildInputs = [ libxml2 python glibc_multi ];
      srcs = [ ./cmake ./src ./thirdparty ];
      patches = [ ./patches/ropfuscator_pass.patch ];
      postPatch = "patchShebangs .";
      dontStrip = debug;

      cmakeFlags = [
        "-DLLVM_TARGETS_TO_BUILD=X86"
        "-DLLVM_USE_LINKER=lld"
        "-DLLVM_ENABLE_BINDINGS=Off"
        "-DLLVM_INCLUDE_BENCHMARKS=Off"
        "-DLLVM_INCLUDE_EXAMPLES=Off"
        "-DLLVM_INCLUDE_TESTS=Off"
        "-DLLVM_BUILD_TOOLS=Off"
        "-DLLVM_TARGET_ARCH=X86"
        "-GNinja"
      ] ++ lib.optional (debug == true) [
        "-DCMAKE_BUILD_TYPE=Debug"
        "-DLLVM_PARALLEL_LINK_JOBS=2"
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=On"
      ] ++ lib.optional (use_ccache == true) [ "-DLLVM_CCACHE_BUILD=On" ];

      CCACHE_DIR = ccache_path;

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

      buildPhase = ''
        runHook preBuild

        cmake --build . -- clang

        runHook postBuild
      '';
    };
in rec {
  ropfuscator-unwrapped =
    pkgs.pkgsCross.gnu32.callPackage derivation_function { };

  # release
  ropfuscator = pkgs32.wrapCCWith { cc = ropfuscator-unwrapped; };
  ropfuscatorCcache = pkgs32.wrapCCWith {
    cc = ropfuscator-unwrapped.override { use_ccache = true; };
  };

  # debug
  ropfuscatorDebug = pkgs32.wrapCCWith {
    cc = ropfuscator-unwrapped.override { debug = true; };
  };
  ropfuscatorCcacheDebug = pkgs32.wrapCCWith {
    cc = ropfuscator-unwrapped.override {
      debug = true;
      use_ccache = true;
    };
  };

  # stdenvs
  stdenv = pkgs32.overrideCC pkgs32.stdenv ropfuscator;
  stdenvCcache = pkgs32.overrideCC pkgs32.stdenv ropfuscatorCcache;
  stdenvDebug = pkgs32.overrideCC pkgs32.stdenv ropfuscatorDebug;
  stdenvCcacheDebug = pkgs32.overrideCC pkgs32.stdenv ropfuscatorCcacheDebug;
}
