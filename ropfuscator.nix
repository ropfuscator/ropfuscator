{ lib, fmt, tinytoml, stdenv }:

self: super:

let
  LLVM10 = self.llvmPackages_10;

  # this builds ropfuscator's llvm
  llvm_derivation_function = { debug ? false }:
    (LLVM10.libllvm.override {
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

      cmakeFlags = old.cmakeFlags ++ [
        "-DLLVM_TARGETS_TO_BUILD=X86"
        "-DLLVM_ENABLE_BINDINGS=Off"
        "-DLLVM_INCLUDE_BENCHMARKS=Off"
        "-DLLVM_INCLUDE_EXAMPLES=Off"
        "-DLLVM_INCLUDE_TESTS=Off"
        "-DLLVM_TARGET_ARCH=X86"
      ] ++ lib.optional debug [ "-DCMAKE_EXPORT_COMPILE_COMMANDS=On" ];

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
      clang-unwrapped = (LLVM10.libclang.override {
        inherit stdenv;
        libllvm = ropfuscator-llvm;
      }).overrideAttrs (old: {
        pname = "ropfuscator-clang"
          + lib.optionalString ropfuscator-llvm.debug "-debug";
      });
    in LLVM10.clang.override (old: {
      cc = clang-unwrapped;
      extraBuildCommands = old.extraBuildCommands
        # add mandatory compiler flags neededed for ropfuscator to work
        + "echo '-pie -fno-pic -fuse-ld=bfd' >> $out/nix-support/cc-cflags"
        # in case Werror is specified, treat unused command line arguments as warning anyway
        + "echo '-Wno-error=unused-command-line-argument' >> $out/nix-support/cc-cflags"
        + lib.optionalString ropfuscator-llvm.debug
        "echo '-mllvm -debug-only=xchg_chains,ropchains,processed_instr,liveness_analysis' >> $out/nix-support/cc-flags";
    });

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
  stdenvDebug = if super.stdenv.hostPlatform != super.stdenv.buildPlatform then
    stdenv_derivation_function {
      clang = self.buildPackages.ropfuscator-clang-debug;
    }
  else
    super.stdenv;
}
