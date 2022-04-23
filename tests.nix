{ ropfuscator-utils, ropfuscatorStdenv, librop, cmake }:
let
  ropfuscator_tests = ropfuscatorStdenv.mkDerivation rec {
    pname = "ropfuscator_tests";
    nativeBuildInputs = [ cmake ];
    buildInputs = [ librop ];
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

      # force, in case tests are automatically
      doCheck=1

      runHook postUnpack
    '';
  };
in ropfuscator_tests
