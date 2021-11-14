with import <nixpkgs> {};

let 
  ext_llvm = fetchTarball {
    url = https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.1/llvm-10.0.1.src.tar.xz;
    sha256 = "0xx9q8s4sg0nwc24abp7xnyckfms8qfskydvqch06q4ak4zdliii";
  };
  ext_clang = fetchTarball {
    url = https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.1/clang-10.0.1.src.tar.xz;
    sha256 = "0bbhf5664gpmdd9vpsifqb6886n25j3yd9knj80hna81ab81n3v9";
  };
  ropfuscator_staging_dir = "$TMPDIR/ropfuscator";
  python-deps = python-packages: with python-packages; [ pygments ]; 
  python = python3.withPackages python-deps;
in pkgs.pkgsi686Linux.llvmPackages_10.stdenv.mkDerivation {
  system = "i686-linux";

  name = "ropfuscator";
  version = "0.1.0";
  buildInputs = with pkgs.pkgsi686Linux; [ ext_llvm ext_clang cmake ninja z3 git SDL2 SDL2_net SDL2_mixer pkg-config libxml2 curl openal  libpng python libsamplerate ];
  src = [ ./. ];

  configurePhase = ''
    cd $TMPDIR

    mkdir -p ${ropfuscator_staging_dir}

    pushd ${ropfuscator_staging_dir}

    # copying llvm source tree to staging dir
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
    patch < ropfuscator/patch/llvm-10.patch
    popd

    # make directories writable for cmake conf phase
    find . -type d -exec chmod +w {} \; 

    popd

    echo "pwd: $(pwd)"
    mkdir build && cd build
    cmake -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD=X86 -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -G Ninja ${ropfuscator_staging_dir}
  '';

  buildPhase = '' 
    ninja
  '';

  installPhase = ''
    mkdir -p $out/bin
  '';
}
