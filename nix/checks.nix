{inputs, ...}: {
  perSystem = {pkgs, ...}: {
    checks.test = pkgs.buildZigPackage {
      src = inputs.inclusive.lib.inclusive ./.. [
        ../build.zig
        ../build.zig.zon
        ../src
      ];

      zigDepsHash = "sha256-pQpattmS9VmO3ZIQUFn66az8GSmB4IvYhTTCFn6SUmo=";

      zigRelease = "ReleaseSafe";

      zigTarget = null;

      dontBuild = true;
      dontInstall = true;

      nativeCheckInputs = with pkgs; [sqlite];

      postCheck = ''
        touch $out
      '';
    };
  };
}
