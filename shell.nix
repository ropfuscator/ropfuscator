{ pkgs, librop, ropfuscator, ropfuscator_stdenv, system }:
let
  ropfuscator_librop_stdenv = pkgs.stdenvAdapters.addAttrsToDerivation {
    NIX_CFLAGS_COMPILE =
      "-mllvm --ropfuscator-library=${librop}/lib/librop.so -L${librop}/lib -lrop";
  } ropfuscator_stdenv;
  myStdenv = pkgs.mkShell.override { stdenv = ropfuscator_librop_stdenv; };
in myStdenv {
  nativeBuildInputs = ropfuscator.nativeBuildInputs ++ [ librop ];
  shellHook = ''
    export LIBROP=${librop}/lib/librop.so
  '';
}
