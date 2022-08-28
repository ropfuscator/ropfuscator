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
        pkgs = import nixpkgs { inherit localSystem crossSystem; };

        # upstream nix packages that use ROPfuscator as default compiler
        # the pass is disabled, though, because no library is defined
        pkgsRopfuscator = import nixpkgs {
          inherit localSystem crossSystem;
          overlays =
            [ (import ./ropfuscator.nix { inherit tinytoml fmt lib; }) ];
        };

        # upstream nix packages that use ROPfuscator as default compiler
        # with libc as default library
        pkgsRopfuscatorLibc = import nixpkgs {
          inherit localSystem crossSystem;
          overlays =
            [ (import ./ropfuscator.nix { inherit tinytoml fmt lib; }) ];
          crossOverlays = [ ropfuscatorLibcOverlay ];
        };

        # upstream nix packages that use ROPfuscator as default compiler
        # with librop as default library
        pkgsRopfuscatorLibrop = import nixpkgs {
          inherit localSystem crossSystem;
          overlays =
            [ (import ./ropfuscator.nix { inherit tinytoml fmt lib; }) ];
          crossOverlays = [ ropfuscatorLibropOverlay ];
        };

        lib = nixpkgs.lib;
        librop = librop-git.packages.${system}.librop;

        # helper functions
        timePhases = { deriv }:
          let
            obfuscation_stats_file = "ropfuscator_obfuscation_stats.log";
            performance_stats_file = "ropfuscator_performance_stats.log";
            ropfuscator_dir = "$out/ropfuscator";
          in deriv.overrideAttrs (old: {
            nativeBuildInputs = (old.nativeBuildInputs or [ ])
              ++ [ pkgs.bc pkgs.datamash ];

            preBuild = ''
              if [ ! -x ${ropfuscator_dir} ]; then
                mkdir -p ${ropfuscator_dir}
              fi

              touch ${ropfuscator_dir}/${performance_stats_file}

              export ROPFUSCATOR_BUILD_START=`date +%s.%N`
            '' + (old.preBuild or "");
            postBuild = ''
              export ROPFUSCATOR_BUILD_END=`date +%s.%N`
              export ROPFUSCATOR_BUILD_DURATION=`echo "$ROPFUSCATOR_BUILD_END - $ROPFUSCATOR_BUILD_START" | bc`

              printf "BUILD_DURATION = %.3f\n" $ROPFUSCATOR_BUILD_DURATION >> ${ropfuscator_dir}/${performance_stats_file}
            '' + (old.postBuild or "");

            preCheck = ''
              # allow phase to fail
              set +e 
              export ROPFUSCATOR_CHECK_START=`date +%s.%N`
            '' + (old.preCheck or "");
            postCheck = ''
              set -e
              export ROPFUSCATOR_CHECK_END=`date +%s.%N`
              export ROPFUSCATOR_CHECK_DURATION=`echo "$ROPFUSCATOR_CHECK_END - $ROPFUSCATOR_CHECK_START" | bc`

              printf "CHECK_DURATION = %.3f\n" $ROPFUSCATOR_CHECK_DURATION >> ${ropfuscator_dir}/${performance_stats_file}

              # find and move obfuscation stats into ropfuscator out folder
              find . -type f -name ${obfuscation_stats_file} -exec sh -c "mv {} ${ropfuscator_dir}/tmp" \;

              # process and prettify obfuscation stats
              cat ${ropfuscator_dir}/tmp | (sed -u 1q; sort) | datamash -HW groupby OPCODE sum 2,3,4,5,6,7,8 | tr "\\t" "," > ${ropfuscator_dir}/${obfuscation_stats_file} && rm ${ropfuscator_dir}/tmp
            '' + (old.postCheck or "");
          });

        forceTests = { deriv }:
          deriv.overrideAttrs (old: {
            # forcing the derivation to run tests (if any)
            doCheck = true;
            postPatch = (old.postPatch or "") + "export doCheck=1;";
          });

        timePhasesAndForceTests = { deriv }:
          forceTests { deriv = timePhases { inherit deriv; }; };

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
      in rec {
        # expose packages
        inherit pkgs pkgsRopfuscator pkgsRopfuscatorLibc pkgsRopfuscatorLibrop;

        # expose helper functions
        inherit ropfuscate ropfuscateLevelZero ropfuscateLevelOne
          ropfuscateLevelTwo ropfuscateLevelThree;
        inherit timePhases timePhasesAndForceTests;

        releaseBuild = pkgsRopfuscator.buildPackages.ropfuscator-clang;
        debugBuild = pkgsRopfuscator.buildPackages.ropfuscator-clang-debug;

        defaultPackage = releaseBuild;

        # development shell
        devShell = packages.llvmDebug.overrideAttrs (_: {
          shellHook = ''
            # move to temporary directory
            cd `mktemp -d`
            # unpack and configure project
            echo "Preparing LLVM source tree..."
            eval "$unpackPhase" && cd llvm && runHook patchPhase && eval "$configurePhase"
            # get compile_commands.json and put them in root of LLVM tree
            cd .. && mv build/compile_commands.json .
          '';
        });

        # exposed packages
        packages = flake-utils.lib.flattenTree rec {
          llvm = pkgsRopfuscator.buildPackages.ropfuscator-llvm;
          llvmDebug = pkgsRopfuscator.buildPackages.ropfuscator-llvm-debug;
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

          helloVanilla = timePhasesAndForceTests { deriv = pkgs.hello; };

          helloZero = timePhasesAndForceTests {
            deriv = ropfuscateLevelZero {
              deriv = pkgs.hello;
              stdenv = libropRopStdenv;
            };
          };

          helloOne = timePhasesAndForceTests {
            deriv = ropfuscateLevelOne {
              deriv = pkgs.hello;
              stdenv = libropRopStdenv;
            };
          };

          helloTwo = timePhasesAndForceTests {
            deriv = ropfuscateLevelTwo {
              deriv = pkgs.hello;
              stdenv = libropRopStdenv;
            };
          };

          helloThree = timePhasesAndForceTests {
            deriv = ropfuscateLevelThree {
              deriv = pkgs.hello;
              stdenv = libropRopStdenv;
            };
          };

          llvmVanilla = timePhasesAndForceTests { deriv = pkgs.libllvm; };

          llvmZero = timePhasesAndForceTests {
            deriv = ropfuscateLevelZero {
              deriv = pkgs.libllvm;
              stdenv = libropRopStdenv;
            };
          };

          llvmOne = timePhasesAndForceTests {
            deriv = ropfuscateLevelOne {
              deriv = pkgs.libllvm;
              stdenv = libropRopStdenv;
            };
          };

          llvmTwo = timePhasesAndForceTests {
            deriv = ropfuscateLevelTwo {
              deriv = pkgs.libllvm;
              stdenv = libropRopStdenv;
            };
          };

          llvmThree = timePhasesAndForceTests {
            deriv = ropfuscateLevelThree {
              deriv = pkgs.libllvm;
              stdenv = libropRopStdenv;
            };
          };

          coreutilsVanilla =
            timePhasesAndForceTests { deriv = pkgs.coreutils; };

          coreutilsZero = timePhasesAndForceTests {
            deriv = ropfuscateLevelZero {
              deriv = pkgs.coreutils;
              stdenv = libropRopStdenv;
            };
          };
          coreutilsOne = timePhasesAndForceTests {
            deriv = ropfuscateLevelOne {
              deriv = pkgs.coreutils;
              stdenv = libropRopStdenv;
            };
          };

          coreutilsTwo = timePhasesAndForceTests {
            deriv = ropfuscateLevelTwo {
              deriv = pkgs.coreutils;
              stdenv = libropRopStdenv;
            };
          };
          coreutilsThree = timePhasesAndForceTests {
            deriv = ropfuscateLevelThree {
              deriv = pkgs.coreutils;
              stdenv = libropRopStdenv;
            };
          };
        };
      });
}
