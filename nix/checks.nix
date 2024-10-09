{inputs, ...}: {
  perSystem = {pkgs, ...}: {
    checks.test = pkgs.buildZigPackage {
      src = inputs.inclusive.lib.inclusive ./.. [
        ../build.zig
        ../build.zig.zon
        ../src
      ];

      zigDepsHash = "sha256-os8vNTirCjNyLFSUEBKw7RQtgKodaC1dR+3Jp+Z7xkU=";

      zigRelease = "ReleaseSafe";

      zigTarget = null;

      dontBuild = true;
      dontInstall = true;

      nativeCheckInputs = with pkgs; [sqlite];

      zigCheckFlags = "-Dzqlite";

      postCheck = ''
        touch $out
      '';
    };
  };
}
