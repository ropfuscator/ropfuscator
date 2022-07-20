{
  inputs = {
    # pinned on fix for https://github.com/NixOS/nixpkgs/pull/166977
    nixpkgs.url = "github:peperunas/nixpkgs/llvm-i686-cross-fix";
    flake-utils.url = "github:numtide/flake-utils";
    librop-git = { url = "github:ropfuscator/librop"; };
    ropfuscator-utils = {
      url = "github:ropfuscator/utilities";
      flake = false;
    };
    fmt = {
      url = "github:fmtlib/fmt/7bdf0628";
      flake = false;
    };
    tinytoml = {
      url = "github:mayah/tinytoml/ea34092";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, librop-git, ropfuscator-utils
    , tinytoml, fmt }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        zlib-fix = import ./zlib-fix.nix;

        ropfuscatorLibcOverlay = (self: super: {
          stdenv = super.overrideCC super.stdenv (super.stdenv.cc.override
            (old: {
              extraBuildCommands = old.extraBuildCommands
                + "echo '-mllvm --ropfuscator-library=${self.glibc}/lib/libc.so.6' >> $out/nix-support/cc-cflags";
            }));
        });

        ropfuscatorLibropOverlay = (self: super:
          let librop-path = "${librop}/lib/librop.so";
          in {
            stdenv = super.overrideCC super.stdenv (super.stdenv.cc.override
              (old: {
                extraBuildCommands = old.extraBuildCommands
                  + "echo '-mllvm --ropfuscator-library=${librop-path} ${librop-path}' >> $out/nix-support/cc-cflags";
              }));
          });

        localSystem = { inherit system; };
        crossSystem = {
          config = "i686-unknown-linux-gnu";
          linker = "bfd";
          useLLVM = true;
        };

        # vanilla upstream nix packages
        pkgs = import nixpkgs {
          inherit localSystem crossSystem;
          overlays = [ zlib-fix ];
        };

        # upstream nix packages that use ROPfuscator as default compiler
        # the pass is disabled, though, because no library is defined
        pkgsRopfuscator = import nixpkgs {
          inherit localSystem crossSystem;
          overlays = [
            zlib-fix
            (import ./ropfuscator.nix { inherit tinytoml fmt lib; })
          ];
        };

        # upstream nix packages that use ROPfuscator as default compiler
        # with libc as default library
        pkgsRopfuscatorLibc = import nixpkgs {
          inherit localSystem crossSystem;
          overlays = [
            zlib-fix
            (import ./ropfuscator.nix { inherit tinytoml fmt lib; })
          ];
          crossOverlays = [ ropfuscatorLibcOverlay ];
        };

        # upstream nix packages that use ROPfuscator as default compiler
        # with librop as default library
        pkgsRopfuscatorLibrop = import nixpkgs {
          inherit localSystem crossSystem;
          overlays = [
            zlib-fix
            (import ./ropfuscator.nix { inherit tinytoml fmt lib; })
          ];
          crossOverlays = [ ropfuscatorLibropOverlay ];
        };

        lib = nixpkgs.lib;
        librop = librop-git.packages.${system}.librop;
      in rec {
        inherit pkgs pkgsRopfuscator pkgsRopfuscatorLibc pkgsRopfuscatorLibrop;

        releaseBuild = pkgsRopfuscator.buildPackages.ropfuscator-clang;
        debugBuild = pkgsRopfuscator.buildPackages.ropfuscator-clang-debug;

        defaultPackage = releaseBuild;

        # development shell
        devShell = import ./shell.nix {
          inherit pkgs;
          stdenv = packages.vanillaRopStdenv;
        };
        # pkgs.buildPackages.ropfuscator-llvm-debug.overrideAttrs (_: {
        #   shellHook = ''
        #     # move to temporary directory
        #     cd `mktemp -d`
        #     # unpack and configure project
        #     echo "Preparing LLVM source tree..."
        #     eval "$unpackPhase" && cd llvm && runHook patchPhase && eval "$configurePhase"
        #     # get compile_commands.json and put them in root of LLVM tree
        #     cd .. && mv build/compile_commands.json .
        #   '';
        # });

        # exposed packages
        packages = flake-utils.lib.flattenTree rec {
          llvm = pkgsRopfuscator.buildPackages.ropfuscator-llvm;
          clang = pkgsRopfuscator.buildPackages.ropfuscator-clang;
          vanillaRopStdenv = pkgs.overrideCC pkgs.stdenv clang;
          libcRopStdenv = pkgs.overrideCC vanillaRopStdenv
            (vanillaRopStdenv.cc.override (old: {
              extraBuildCommands = old.extraBuildCommands
                + "echo '-mllvm --ropfuscator-library=${pkgs.glibc}/lib/libc.so' >> $out/nix-support/cc-cflags";
            }));
          libropRopStdenv = pkgs.overrideCC vanillaRopStdenv
            (let librop-path = "${librop}/lib/librop.so";
            in (vanillaRopStdenv.cc.override (old: {
              extraBuildCommands = old.extraBuildCommands
                + "echo '-mllvm --ropfuscator-library=${librop-path} ${librop-path}' >> $out/nix-support/cc-cflags";
            })));

          tests = pkgs.callPackage ./tests.nix {
            inherit ropfuscator-utils librop;
            stdenv = vanillaRopStdenv;
          };

          helloZero = forceTests {
            deriv = ropfuscateLevelZero {
              deriv = pkgs.hello;
              stdenv = libropRopStdenv;
            };
          };
          
          helloOne = forceTests {
            deriv = ropfuscateLevelOne {
              deriv = pkgs.hello;
              stdenv = libropRopStdenv;
            };
          };
          
          helloTwo = forceTests {
            deriv = ropfuscateLevelTwo {
              deriv = pkgs.hello;
              stdenv = libropRopStdenv;
            };
          };
          
          helloThree = forceTests {
            deriv = ropfuscateLevelThree {
              deriv = pkgs.hello;
              stdenv = libropRopStdenv;
            };
          };

          llvmZero = ropfuscateLevelZero {
            deriv = pkgs.libllvm;
            stdenv = libropRopStdenv;
          };
          llvmZeroTested = forceTests { deriv = llvmZero; };

          llvmOne = ropfuscateLevelOne {
            deriv = pkgs.libllvm;
            stdenv = libropRopStdenv;
          };
          llvmOneTested = forceTests { deriv = llvmOne; };

          llvmTwo = ropfuscateLevelTwo {
            deriv = pkgs.libllvm;
            stdenv = libropRopStdenv;
          };
          llvmTwoTested = forceTests { deriv = llvmTwo; };

          llvmThree = ropfuscateLevelThree {
            deriv = pkgs.libllvm;
            stdenv = libropRopStdenv;
          };
          llvmThreeTested = forceTests { deriv = llvmThree; };
        };

        forceTests = { deriv }:
          deriv.overrideAttrs (old: {
            # forcing the derivation to run tests (if any)
            doCheck = true;
            postPatch = (old.postPatch or "") + "export doCheck=1;";
          });

        # helper functions
        ropfuscate = { deriv, stdenv, config ? "" }:
          let
            stdenv_ = if config == "" then
              stdenv
            else
              pkgs.buildPackages.overrideCC stdenv (stdenv.cc.override (old: {
                extraBuildCommands = old.extraBuildCommands + ''
                  echo "-mllvm --ropfuscator-config=${config}" >> $out/nix-support/cc-cflags
                '';
              }));

            config_name = if (config == "") then
              ""
            else
              lib.removeSuffix ".toml"
              (lib.lists.last (lib.splitString "/" config));
          in (deriv.override { stdenv = stdenv_; }).overrideAttrs (old: {
            pname = old.pname + "-ropfuscated"
              + lib.optionalString (config != "") "-${config_name}";
          });
        ropfuscateLevelZero = { deriv, stdenv }:
          ropfuscate {
            inherit deriv stdenv;
            config = "${ropfuscator-utils}/configs/level0.toml";
          };
        ropfuscateLevelOne = { deriv, stdenv }:
          ropfuscate {
            inherit deriv stdenv;
            config = "${ropfuscator-utils}/configs/level1.toml";
          };
        ropfuscateLevelTwo = { deriv, stdenv }:
          ropfuscate {
            inherit deriv stdenv;
            config = "${ropfuscator-utils}/configs/level2.toml";
          };
        ropfuscateLevelThree = { deriv, stdenv }:
          ropfuscate {
            inherit deriv stdenv;
            config = "${ropfuscator-utils}/configs/level3.toml";
          };
      });
}
