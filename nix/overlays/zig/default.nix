{
  inputs,
  lib,
  ...
}: {
  flake.overlays.zig = final: prev: {
    buildZigPackage = lib.extendMkDerivation {
      constructDrv = final.stdenv.mkDerivation;
      excludeDrvArgNames = [
        "buildZigZon"
        "zigDepsHash"
        "zigRelease"
        "zigTarget"
        "zigDynamicLinker"
      ];
      extendDrvArgs = finalAttrs: args @ {
        src,
        buildZigZon ? "build.zig.zon",
        zigDepsHash ? "",
        # Can be a boolean for for `-Drelease` or a string for `-Doptimize`.
        zigRelease ? true,
        # Passed to `-Dtarget` if not null.
        zigTarget ? let
          zig-env = inputs.zig2nix.zig-env.${final.stdenv.hostPlatform.system} {inherit (final) zig;};
        in
          (zig-env.target final.stdenv.targetPlatform.system).zig,
        # Passed to `-Ddynamic-linker` if not null.
        zigDynamicLinker ?
          if zigTarget == null
          then null
          else final.stdenv.cc.bintools.dynamicLinker,
        ...
      }: let
        info = lib.importJSON (finalAttrs.passthru.packageInfo.overrideAttrs {
          withFingerprint = false;
        });
      in {
        pname = info.name;
        inherit (info) version;

        postPatch = lib.optionalString (finalAttrs.passthru ? deps) ''
          cd ${lib.escapeShellArg (builtins.dirOf buildZigZon)}
        '';

        doCheck = true;

        dontStrip =
          if builtins.isBool zigRelease
          then !zigRelease
          else zigRelease == "Debug";

        nativeBuildInputs =
          args.nativeBuildInputs or []
          ++ lib.singleton final.zig.hook;

        env =
          args.env or {}
          // rec {
            zig_default_optimize_flag =
              if builtins.isBool zigRelease
              then "-Drelease=${builtins.toJSON zigRelease}"
              else "-Doptimize=${zigRelease}";

            zigBuildFlags = toString (
              [
                "--system"
                finalAttrs.passthru.deps

                "-freference-trace"
              ]
              ++ lib.optional (zigTarget != null) "-Dtarget=${zigTarget}"
              ++ lib.optional (zigDynamicLinker != null) "-Ddynamic-linker=${zigDynamicLinker}"
            );

            zigCheckFlags = zigBuildFlags;
          };

        passthru =
          args.passthru or {}
          // {
            packageInfo = final.zigPackageInfo (
              lib.optionalString (!lib.hasPrefix "/" buildZigZon) "${finalAttrs.src}/"
              + buildZigZon
            );

            # builds the $ZIG_GLOBAL_CACHE_DIR/p directory
            depsCache = let
              buildZigZonDir = builtins.dirOf buildZigZon;
            in
              final.runCommand (with finalAttrs; "${pname}-${version}-deps-cache") {
                nativeBuildInputs = [final.zig];

                outputHashMode = "recursive";
                outputHashAlgo = "sha256";
                outputHash = zigDepsHash;
              } (
                ''
                  mkdir "$TMPDIR"/{src,cache}

                  shopt -s nullglob
                  cp --recursive --symbolic-link \
                    ${src}/* \
                    ${src}/.* \
                    "$TMPDIR"/src/
                  cd "$TMPDIR"/src
                ''
                + (
                  lib.foldl
                  (
                    acc: component: let
                      path = lib.path.subpath.join [acc.path component];
                    in
                      acc
                      // {
                        inherit path;
                        script =
                          acc.script
                          + "\n"
                          + ''
                            chmod --recursive u+w ${lib.escapeShellArg component}
                            rm --recursive ${lib.escapeShellArg component}
                            mkdir ${lib.escapeShellArg component}
                            cp --recursive --symbolic-link \
                              ${src}/${lib.escapeShellArg path}/* \
                              ${src}/${lib.escapeShellArg path}/.* \
                              ${lib.escapeShellArg component}
                            cd ${lib.escapeShellArg component}
                          '';
                      }
                  )
                  {
                    path = ".";
                    script = "";
                  }
                  (lib.path.subpath.components buildZigZonDir)
                )
                    .script
                + ''
                  cd "$TMPDIR"/src/${lib.escapeShellArg buildZigZonDir}

                  # `zig build --fetch` does not fetch lazy dependencies
                  # so we make them all eager to make sure they are all present.
                  # XXX Of course this means that we fetch all dependencies
                  # even if the build does not actually need them.
                  # see https://github.com/ziglang/zig/issues/20976
                  rm build.zig.zon
                  sed 's/\.lazy[[:space:]]*=[[:space:]]*true[[:space:]]*,\?//' > build.zig.zon \
                    ${src}/${lib.escapeShellArg buildZigZon}

                  zig build --fetch \
                    --cache-dir "$TMPDIR" \
                    --global-cache-dir "$TMPDIR"/cache

                  # create an empty directory if there are no dependencies
                  mv "$TMPDIR"/cache/p $out || mkdir $out
                ''
              );

            # builds the zig-pkg directory
            # newer zig versions can consume this directly using --system
            deps = final.runCommand (with finalAttrs; "${pname}-${version}-deps") {} ''
              mkdir "$out"
              for tarball in ${finalAttrs.passthru.depsCache}/*; do
                name=$(basename "$tarball" .tar.gz)
                mkdir "$out/$name"
                tar --extract --file "$tarball" --directory "$out"
              done
            '';
          };
      };
    };

    zigPackageInfo = buildZigZon:
      prev.runCommand "zig-package-info" rec {
        # Include the fingerprint in the output.
        # The fingerprint value can exceed Nix' max int value.
        # Disable this using `.overrideAttrs` when you intend to import as JSON in Nix.
        withFingerprint = true;

        nativeBuildInputs = with prev; [zig jaq];
        passthru = {inherit buildZigZon withFingerprint;};
      } ''
        cp ${./package-info.zig} main.zig
        cp ${buildZigZon} build.zig.zon

        zig run > raw.json \
          --global-cache-dir "$TMPDIR" \
          -fstrip \
          main.zig

        if [[ -n "$withFingerprint" ]]; then
          mv raw.json $out
        else
          jaq 'del(.fingerprint)' raw.json > $out
        fi
      '';
  };
}
