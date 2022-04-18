{ lib, fmt, tinytoml, librop }:

self: super:

let
  LLVM10 = self.llvmPackages_10;
  LLVM13 = self.llvmPackages_13;

  # this builds ropfuscator's llvm
  llvm_derivation_function = { debug ? false, use_ccache ? false }:
    let ccache_dir = "/nix/var/cache/ccache";
    in (LLVM10.libllvm.override {
      enablePolly = false;
      debugVersion = debug;
    }).overrideAttrs (old: {
      pname = "ropfuscator-llvm" + lib.optionalString debug "-debug";
      debug = debug;
      srcs = [ old.src ./cmake ./src ./thirdparty ];
      patches = old.patches ++ [ ./patches/ropfuscator_pass.patch ];
      doCheck = false;
      dontStrip = debug;

      nativeBuildInputs = old.nativeBuildInputs ++ [ LLVM13.bintools ]
        ++ lib.optional use_ccache
        [ (self.buildPackages.ccache.overrideAttrs (_: { doCheck = false; })) ];

      cmakeFlags = old.cmakeFlags ++ [
        "-DLLVM_TARGETS_TO_BUILD=X86"
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
  clang_derivation_function = { ropfuscator-llvm }:
    let
      clang-unwrapped =
        (LLVM10.libclang.override { libllvm = ropfuscator-llvm; }).overrideAttrs
        (old: {
          pname = "ropfuscator-clang"
            + lib.optionalString ropfuscator-llvm.debug "-debug";
        });
    in LLVM10.clang.override (old: {
      cc = clang-unwrapped;
      extraBuildCommands = old.extraBuildCommands
        # add mandatory compiler flags neededed for ropfuscator to work
        + "echo '-fno-pie -pie -Wl,-z,notext' >> $out/nix-support/cc-cflags"
        # in case Werror is specified, treat unused command line arguments as warning anyway
        + "echo '-Wno-error=unused-command-line-argument' >> $out/nix-support/cc-cflags"
        + lib.optionalString ropfuscator-llvm.debug
        "echo '-mllvm -debug-only=xchg_chains,ropchains,processed_instr,liveness_analysis' >> $out/nix-support/cc-flags";
    });

  # this builds a stdenv with librop to the library path
  stdenv_derivation_function = { clang }: super.overrideCC super.stdenv clang;
in {
  ropfuscator-llvm = llvm_derivation_function { };
  ropfuscator-llvm-debug = llvm_derivation_function { debug = true; };

  ropfuscator-clang =
    clang_derivation_function { inherit (self) ropfuscator-llvm; };
  ropfuscator-clang-debug = clang_derivation_function {
    ropfuscator-llvm = self.ropfuscator-llvm-debug;
  };

  # stdenvs
  stdenv = if super.stdenv.hostPlatform != super.stdenv.buildPlatform then
    stdenv_derivation_function { clang = self.buildPackages.ropfuscator-clang; }
  else
    super.stdenv;
  #stdenvDebug = stdenv_derivation_function { clang = ropfuscator-clang-debug; };

  stdenvLibc = self.overrideCC self.stdenv (self.stdenv.cc.override (old: {
    extraBuildCommands = old.extraBuildCommands
      + "echo '-mllvm --ropfuscator-library=${self.glibc}/lib/libc.so.6' >> $out/nix-support/cc-cflags";
  }));

  stdenvLibrop = self.overrideCC self.stdenv (self.stdenv.cc.override (old: {
    extraBuildCommands = old.extraBuildCommands
      + "echo '-L${librop}/lib' >> $out/nix-support/cc-ldflags"
      + "echo '-mllvm --ropfuscator-library=${librop}/lib/librop.so -lrop' >> $out/nix-support/cc-cflags";
  }));
}
