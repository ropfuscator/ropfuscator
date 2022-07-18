{ pkgs, stdenv }:

pkgs.mkShell {
  inherit stdenv;
  nativeBuildInputs = [ stdenv ];
  buildInputs = [ stdenv ];
}
