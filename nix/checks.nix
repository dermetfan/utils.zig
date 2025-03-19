{inputs, ...}: {
  perSystem = {pkgs, ...}: {
    checks.test = pkgs.buildZigPackage {
      src = inputs.inclusive.lib.inclusive ./.. [
        ../build.zig
        ../build.zig.zon
        ../src
      ];

      zigDepsHash = "sha256-UAToaMbNu+3Zeirjx8FjeKbbHdBBDfvcU8HPe3DRsKA=";

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
