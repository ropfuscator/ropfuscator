{ pkgs, lib, fmt, tinytoml, librop }:
let
  pkgs32 = pkgs.pkgsi686Linux;
  pkgsCross = pkgs.pkgsCross.gnu32;

  pkgsLLVM13 = pkgsCross.llvmPackages_13;
  stdenv = pkgsCross.stdenv;

  # this builds ropfuscator's llvm
  llvm_derivation_function = { pkgs, debug ? false }:
    (pkgs.llvmPackages_10.libllvm.override {
      inherit stdenv;
      enablePolly = false;
    }).overrideAttrs (old: {
      pname = "ropfuscator-llvm" + lib.optionalString debug "-debug";
      debug = debug;
      srcs = [ old.src ./cmake ./src ./thirdparty ];
      patches = old.patches ++ [ ./patches/ropfuscator_pass.patch ];
      doCheck = false;
      nativeBuildInputs = with pkgs;
        old.nativeBuildInputs ++ [ llvmPackages_13.bintools ];
      cmakeFlags = old.cmakeFlags ++ [
        "-DLLVM_TARGETS_TO_BUILD=X86"
        "-DLLVM_USE_LINKER=lld"
        "-DLLVM_ENABLE_BINDINGS=Off"
        "-DLLVM_INCLUDE_BENCHMARKS=Off"
        "-DLLVM_INCLUDE_EXAMPLES=Off"
        "-DLLVM_INCLUDE_TESTS=Off"
        "-DLLVM_TARGET_ARCH=X86"
      ] ++ lib.optional debug [
        "-DCMAKE_BUILD_TYPE=Debug"
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=On"
      ];

      unpackPhase = old.unpackPhase + ''
        # insert ropfuscator
        pushd llvm/lib/Target/X86
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
      '';
    });

  # this builds and wraps ropfuscator's clang
  clang_derivation_function = { pkgs, ropfuscator-llvm }:
    let
      pkgsLLVM10 = pkgs.llvmPackages_10;
      gccForLibs = pkgs.gcc.cc;

      clang-unwrapped = (pkgsLLVM10.libclang.override {
        stdenv = pkgs.stdenv;
        libllvm = ropfuscator-llvm;
      }).overrideAttrs (old: {
        pname = "ropfuscator-clang"
          + lib.optionalString ropfuscator-llvm.debug "-debug";
      });
    in pkgsLLVM10.clang.override (old: {
      inherit gccForLibs;
      cc = clang-unwrapped;
      # add librop to library path
      extraBuildCommands = old.extraBuildCommands + ''
        echo '-L${librop}/lib' >> $out/nix-support/cc-ldflags
      '';
    });

  # this builds a stdenv with librop to the library path
  stdenv_derivation_function = { pkgs, clang }:
    pkgs.overrideCC pkgs.llvmPackages_10.stdenv clang;
in rec {
  ropfuscator-llvm = llvm_derivation_function { pkgs = pkgsCross; };
  ropfuscator-llvm-debug = llvm_derivation_function {
    pkgs = pkgsCross;
    debug = true;
  };

  ropfuscator-clang = clang_derivation_function {
    pkgs = pkgs32;
    inherit ropfuscator-llvm;
  };
  ropfuscator-clang-debug = clang_derivation_function {
    pkgs = pkgs32;
    ropfuscator-llvm = ropfuscator-llvm-debug;
  };

  # stdenvs
  stdenv = stdenv_derivation_function {
    pkgs = pkgs32;
    clang = ropfuscator-clang;
  };
  stdenvDebug = stdenv_derivation_function {
    pkgs = pkgs32;
    clang = ropfuscator-clang-debug;
  };
}
