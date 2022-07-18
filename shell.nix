{ pkgs, stdenv }:
pkgs.mkShell {
  inherit stdenv;
  buildInputs = [ stdenv ];
}
