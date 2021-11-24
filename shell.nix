{ pkgs, librop, ropfuscator, ropfuscator_stdenv }:
let myStdenv = pkgs.mkShell.override { stdenv = ropfuscator_stdenv; };
in myStdenv {
  nativeBuildInputs = ropfuscator.nativeBuildInputs ++ [ librop ];
  shellHook = ''
    export LIBROP=${librop}/lib/librop.so
  '';
}
