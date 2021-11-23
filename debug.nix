{ }:
let
  ropfuscator = ./.;
  debug_build = ropfuscator.overrideAttrs (old: {
    pname = "ropfuscator-debug";
    cmakeFlags = ropfuscator.cmakeFlags ++ [ "-DCMAKE_BUILD_TYPE=Debug" ];
  });
in pkgs.callPackage debug_build { }
