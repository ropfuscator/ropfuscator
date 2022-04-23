self: super: {
  # Newer zlib doesn't want to do a shared build cross compiling for
  # some reason.
  #
  # See: https://github.com/NixOS/nixpkgs/issues/170002
  zlib =
    if super.stdenv.hostPlatform != super.stdenv.buildPlatform then
      super.zlib.overrideAttrs (_: rec {
        version = "1.2.11";
        src = builtins.fetchurl {
          url = "https://www.zlib.net/fossils/zlib-${version}.tar.gz";
          sha256 =
            "c3e5e9fdd5004dcb542feda5ee4f0ff0744628baf8ed2dd5d66f8ca1197cb1a1";
        };
      })
    else
      super.zlib;
}
