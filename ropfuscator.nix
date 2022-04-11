{ nixpkgs, pkgs, lib, fmt, tinytoml, librop }:
let
  pkgs32 = pkgs.pkgsi686Linux;
  pkgsLLVM13 = pkgs.llvmPackages_13;
  stdenv = pkgs.gcc11Stdenv;

  # this builds ropfuscator's llvm
  llvm_derivation_function = { pkgs, debug ? false, use_ccache ? false }:
    let ccache_dir = "/nix/var/cache/ccache";
    in (pkgs.llvmPackages_10.libllvm.override {
      inherit stdenv;
      enablePolly = false;
      debugVersion = debug;
    }).overrideAttrs (old: {
      pname = "ropfuscator-llvm" + lib.optionalString debug "-debug";
      debug = debug;
      srcs = [ old.src ./cmake ./src ./thirdparty ];
      patches = old.patches ++ [ ./patches/ropfuscator_pass.patch ];
      doCheck = false;
      dontStrip = debug;

      nativeBuildInputs = with pkgs;
        old.nativeBuildInputs ++ [ llvmPackages_13.bintools ]
        ++ lib.optional use_ccache [ ccache ];

      cmakeFlags = old.cmakeFlags ++ [
        "-DLLVM_TARGETS_TO_BUILD=X86"
        "-DLLVM_USE_LINKER=lld"
        "-DLLVM_ENABLE_BINDINGS=Off"
        "-DLLVM_INCLUDE_BENCHMARKS=Off"
        "-DLLVM_INCLUDE_EXAMPLES=Off"
        "-DLLVM_INCLUDE_TESTS=Off"
        "-DLLVM_TARGET_ARCH=X86"
      ] ++ lib.optional debug [ "-DCMAKE_EXPORT_COMPILE_COMMANDS=On" ]
        ++ lib.optional use_ccache [ "-DLLVM_CCACHE_BUILD=On" ];

      preConfigure = lib.optional use_ccache ''
        export CCACHE_DIR=${ccache_dir}
        export CCACHE_UMASK=007
      '';

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

      clang-unwrapped = (pkgsLLVM10.libclang.override {
        stdenv = pkgs.gcc11Stdenv;
        libllvm = ropfuscator-llvm;
      }).overrideAttrs (old: {
        pname = "ropfuscator-clang"
          + lib.optionalString ropfuscator-llvm.debug "-debug";
      });
    in pkgsLLVM10.clang.override (old: {
      cc = clang-unwrapped;
      extraBuildCommands = old.extraBuildCommands
        # add -pie as default linking flag as it's needed for ropfuscator to work
        + "echo '-pie' >> $out/nix-support/cc-ldflags"
        # add -fno-pie as default compiling flag as it's needed for ropfuscator to work
        + "echo '-fno-pie -m32' >> $out/nix-support/cc-cflags"
        + lib.optionalString ropfuscator-llvm.debug
        "-mllvm -debug-only=xchg_chains,ropchains,processed_instr,liveness_analysis";
    });

  # this builds a stdenv with librop to the library path
  stdenv_derivation_function = { pkgs, clang }:
    pkgs.overrideCC pkgs.stdenv (pkgs.wrapClangMulti clang);
in rec {
  ropfuscator-llvm = llvm_derivation_function { inherit pkgs; };
  ropfuscator-llvm-debug = llvm_derivation_function {
    inherit pkgs;
    debug = true;
  };

  ropfuscator-clang =
    clang_derivation_function { inherit pkgs ropfuscator-llvm; };
  ropfuscator-clang-debug = clang_derivation_function {
    inherit pkgs;
    ropfuscator-llvm = ropfuscator-llvm-debug;
  };

  # stdenvs
  stdenv = stdenv_derivation_function {
    inherit pkgs;
    clang = ropfuscator-clang;
  };
  stdenvDebug = stdenv_derivation_function {
    inherit pkgs;
    clang = ropfuscator-clang-debug;
  };

  stdenvLibc = stdenv_derivation_function {
    inherit pkgs;
    clang = ropfuscator-clang.override (old: {
      extraBuildCommands = old.extraBuildCommands
        + "echo '-mllvm --ropfuscator-library=${pkgs32.glibc}/lib/libc.so.6' >> $out/nix-support/cc-cflags";
    });
  };

  stdenvLibrop = stdenv_derivation_function {
    inherit pkgs;
    clang = ropfuscator-clang.override (old: {
      extraBuildCommands = old.extraBuildCommands
        + "echo '-L${librop}/lib' >> $out/nix-support/cc-ldflags"
        + "echo '-mllvm --ropfuscator-library=${librop}/lib/librop.so -lrop' >> $out/nix-support/cc-cflags";
    });
  };
}
