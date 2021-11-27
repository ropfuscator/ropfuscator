{ pkgs, librop, ropfuscator, ropfuscator_stdenv, system }:
let myStdenv = pkgs.mkShell.override { stdenv = ropfuscator_stdenv; };
in myStdenv {
  nativeBuildInputs = ropfuscator.nativeBuildInputs
    ++ [ librop.defaultPackage.${system} ];
  shellHook = ''
    export LIBROP=${librop}/lib/librop.so
  '';
}
