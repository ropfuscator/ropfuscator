{ }:
let
  pkgs64 = (import (builtins.fetchTarball {
    name = "nixos-unstable-20211116";
    url = "https://releases.nixos.org/nixpkgs/nixpkgs-21.11pre330734.5cb226a06c4/nixexprs.tar.xz";
    sha256 = "0hi1lfp8kq9p4lfqclydgsx5dzc59g71gx1lay2akvn2ibqzhg21";
  }) {});
  pkgs = pkgs64.pkgsi686Linux;

  # upstream clang stdenv uses gcc 7.5 (outdated)
  stdenv_clang = pkgs.overrideCC pkgs.stdenv (pkgs.clang_10.override ({ gccForLibs = pkgs.gcc10.cc;}));

  ext_llvm = fetchTarball {
    url =
      "https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.1/llvm-10.0.1.src.tar.xz";
      sha256 = "0xx9q8s4sg0nwc24abp7xnyckfms8qfskydvqch06q4ak4zdliii";
    };
    ext_clang = fetchTarball {
      url =
        "https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.1/clang-10.0.1.src.tar.xz";
        sha256 = "0bbhf5664gpmdd9vpsifqb6886n25j3yd9knj80hna81ab81n3v9";
      };

      ropfuscator_staging_dir = "$TMPDIR/llvm";
      ropfuscator_build_dir = "$TMPDIR/build";
      python-deps = python-packages: with python-packages; [ pygments ];
      python = pkgs.python3.withPackages python-deps;

      derivation_function = { stdenv, cmake, ninja, z3, git, SDL2, SDL2_net
      , SDL2_mixer, pkg-config, libxml2, curl, openal, libpng
      , libsamplerate }:
      stdenv.mkDerivation {
        name = "ropfuscator";
        version = "0.1.0";
        buildInputs = [
          ext_llvm
          ext_clang
          cmake
          ninja
          z3
          git
          SDL2
          SDL2_net
          SDL2_mixer
          pkg-config
          libxml2
          curl
          openal
          libpng
          python
          libsamplerate
        ];
        src = ./.;
        patches = [ ./patches/ropfuscator_pass.patch ];
        postPatch = "patchShebangs .";

        unpackPhase = ''
          cp -r ${ext_llvm}/* .

        # adding clang to source tree
          pushd tools
          chmod +w .
          cp -r ${ext_clang} clang
          popd

        # copying ropfuscator sources to source tree
          pushd lib/Target/X86
          chmod +w . *
          cp -r $src ropfuscator
          popd

        # make directories writable for cmake conf phase
          find . -type d -exec chmod +w {} \;   
        '';

        configurePhase = ''
          mkdir -p ${ropfuscator_build_dir} && pushd ${ropfuscator_build_dir}
          cmake -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD=X86 -G Ninja $TMPDIR
          popd
        '';

        buildPhase = ''
          pushd ${ropfuscator_build_dir}
          ninja 
          popd
        '';

        installPhase = ''
          mkdir -p $out/bin
          cp -r ${ropfuscator_build_dir}/bin/* $out/bin
        '';
      };
in pkgs.callPackage derivation_function { stdenv = stdenv_clang; }
