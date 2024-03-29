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

        # helper functions
        benchmarkPhases = { deriv }:
          let
            obfuscation_stats_file_header = "ropfuscator_obfuscation_stats";
            ropfuscator_dir = "$TMPDIR/ropfuscator";
            performance_stats_file =
              "${ropfuscator_dir}/ropfuscator_performance_stats.log";
            aggregated_obfuscation_stats_file =
              "${ropfuscator_dir}/ropfuscator_obfuscation_stats-aggregated.log";
          in deriv.overrideAttrs (old: {
            nativeBuildInputs = (old.nativeBuildInputs or [ ])
              ++ [ pkgs.bc pkgs.datamash ];

            preConfigure = ''
              if [ ! -d ${ropfuscator_dir} ]; then
                echo "[*] Creating ROPfuscator directory in output store"
                mkdir -p ${ropfuscator_dir}
              fi

              echo "[*] Touching performance statistics file"
              touch ${performance_stats_file}

              export ROPFUSCATOR_CONFIGURE_START=`date +%s.%N`
            '' + (old.preConfigure or "");

            postConfigure = ''
              export ROPFUSCATOR_CONFIGURE_END=`date +%s.%N`
              export ROPFUSCATOR_CONFIGURE_DURATION=`echo "$ROPFUSCATOR_CONFIGURE_END - $ROPFUSCATOR_CONFIGURE_START" | bc`

              echo "[*] Writing configure phase duration into performance statistics file"
              printf "CONFIGURE_DURATION = %.3f\n" $ROPFUSCATOR_CONFIGURE_DURATION >> ${performance_stats_file}
            '' + (old.postConfigure or "");

            preBuild = ''
              export ROPFUSCATOR_BUILD_START=`date +%s.%N`
            '' + (old.preBuild or "");

            postBuild = ''
              export ROPFUSCATOR_BUILD_END=`date +%s.%N`
              export ROPFUSCATOR_BUILD_DURATION=`echo "$ROPFUSCATOR_BUILD_END - $ROPFUSCATOR_BUILD_START" | bc`

              echo "[*] Writing build time into performance statistics file"
              printf "BUILD_DURATION = %.3f\n" $ROPFUSCATOR_BUILD_DURATION >> ${performance_stats_file}
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

              echo "[*] Writing check phase duration into performance statistics file"
              printf "CHECK_DURATION = %.3f\n" $ROPFUSCATOR_CHECK_DURATION >> ${performance_stats_file}
            '' + (old.postCheck or "");

            postInstall = ''
              # find and move obfuscation stats into ropfuscator out folder
              find /build -type f -name "${obfuscation_stats_file_header}*" -exec sh -c "([[ ! -f ${ropfuscator_dir}/tmp ]] && cat {} > ${ropfuscator_dir}/tmp || tail -n +2 {} >> ${ropfuscator_dir}/tmp) && mv {} ${ropfuscator_dir}" \;

              # process and prettify obfuscation stats, if present
              if [ -f ${ropfuscator_dir}/tmp ]; then cat ${ropfuscator_dir}/tmp | (sed -u 1q; sort) | datamash -HW groupby 1 sum 2,3,4,5,6,7,8,9 | tr "\\t" "," > ${aggregated_obfuscation_stats_file} && rm ${ropfuscator_dir}/tmp; fi

              echo "[*] Moving ROPfuscator stats folder to output"
              mv "${ropfuscator_dir}" $out
            '' + (old.postInstall or "");
          });

        forceTests = { deriv }:
          # since ROPfuscator works only on x86_32,
          # we should execute the tests only if the host
          # is x86
          if (pkgs.stdenv.hostPlatform.isx86_32 or pkgs.stdenv.hostPlatform.isx86_64) then
            deriv.overrideAttrs (old: {
              # forcing the derivation to run tests (if any)
              doCheck = true;

              # allow phase to fail
              preCheck = "set +e;" + (old.preCheck or "");
              postCheck = "set -e;" + (old.postCheck or "");
              postPatch = (old.postPatch or "") + "export doCheck=1;";
            })
          else
            deriv;

        benchmarkPhasesAndForceTests = { deriv }:
          forceTests { deriv = benchmarkPhases { inherit deriv; }; };

        noOptimize = { deriv }:
          deriv.overrideAttrs (old: {
            pname = old.pname + "-ozero";
            NIX_CFLAGS_COMPILE = "-O0";
            NIX_CXXFLAGS_COMPILE = "-O0";
          });

        optimize = { deriv }:
          deriv.overrideAttrs (old: {
            pname = old.pname + "-othree";
            NIX_CFLAGS_COMPILE = "-O3";
            NIX_CXXFLAGS_COMPILE = "-O3";
          });

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

            dontStrip = false;
          });
        ropfuscateRopOnly = { deriv, stdenv }:
          ropfuscate {
            inherit deriv stdenv;
            config = "${ropfuscator-utils}/configs/roponly.toml";
          };
        ropfuscateHalfAddresses = { deriv, stdenv }:
          ropfuscate {
            inherit deriv stdenv;
            config = "${ropfuscator-utils}/configs/halfaddresses.toml";
          };
        ropfuscateAllAddresses = { deriv, stdenv }:
          ropfuscate {
            inherit deriv stdenv;
            config = "${ropfuscator-utils}/configs/alladdresses.toml";
          };
        ropfuscateFull = { deriv, stdenv }:
          ropfuscate {
            inherit deriv stdenv;
            config = "${ropfuscator-utils}/configs/full.toml";
          };
      in rec {
        # expose packages
        inherit pkgs pkgsRopfuscator pkgsRopfuscatorLibc pkgsRopfuscatorLibrop;

        # expose helper functions
        inherit ropfuscate ropfuscateRopOnly ropfuscateHalfAddresses
          ropfuscateAllAddresses ropfuscateFull;
        inherit benchmarkPhases benchmarkPhasesAndForceTests forceTests;
        inherit optimize noOptimize;

        defaultPackage = packages.clang;

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

          helloVanilla = pkgs.hello;

          helloRopOnly = ropfuscateRopOnly {
            deriv = pkgs.hello;
            stdenv = libropRopStdenv;
          };

          helloFull = ropfuscateFull {
            deriv = pkgs.hello;
            stdenv = libropRopStdenv;
          };
        };
      });
}
