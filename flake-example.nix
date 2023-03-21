{
  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    ropfuscator.url = "github:ropfuscator/ropfuscator";
  };

  outputs = { self, flake-utils, ropfuscator }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = ropfuscator.pkgs.${system};
        # wrappers to obfuscate using ROPfuscator's default configs
        ropfuscateAllAddresses = ropfuscator.ropfuscateAllAddresses.${system};
        ropfuscateFull = ropfuscator.ropfuscateFull.${system};
        ropfuscateHalfAddresses = ropfuscator.ropfuscateHalfAddresses.${system};
        ropfuscateRopOnly = ropfuscator.ropfuscateRopOnly.${system};

        inherit (ropfuscator.packages.${system})

          # this stdenv uses unmodified nix packages
          # ropfuscator acts like a "vanilla" clang
          vanillaRopStdenv

          # this stdenv uses libc to extract gadgets from
          libcRopStdenv

          # this stdenv uses librop to extract gadgets from
          libropRopStdenv;

        obfuscatedHello = ropfuscateFull {
          deriv = pkgs.hello;
          stdenv = libropRopStdenv;
        };
      in
      {
        packages = {
          inherit obfuscatedHello;
          hello = pkgs.hello;

          default = obfuscatedHello;
        };
      });
}
