{ pkgs, ropfuscator-utils, ropfuscatorStdenv, librop }:
let
  ropfuscator_tests = ropfuscatorStdenv.mkDerivation rec {
    pname = "ropfuscator_tests";
    nativeBuildInputs = with pkgs; [ cmake librop ];
    version = "0.1.0";
    src = ./tests;
    doCheck = true;
    dontInstall = true;
    cmakeFlags = [
      "-DUSE_LIBROP=On"
      "-DUSE_LIBC=On"
      # hardcoded /build, could break if build root is changed!
      "-DROPFUSCATOR_CONFIGS_DIR=/build/utils/configs"
    ];
    unpackPhase = ''
      runHook preUnpack
      
      mkdir utils

      cp -r --no-preserve=mode,ownership $src/* .
      cp -r --no-preserve=mode,ownership ${ropfuscator-utils}/* utils
      
      # fake output
      mkdir $out

      runHook postUnpack
    '';
  };
in ropfuscator_tests
