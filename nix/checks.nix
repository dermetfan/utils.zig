{inputs, ...}: {
  perSystem = {
    lib,
    pkgs,
    ...
  }: {
    checks.test = pkgs.buildZigPackage {
      src = inputs.inclusive.lib.inclusive ./.. [
        ../build.zig
        ../build.zig.zon
        ../src
      ];

      zigDepsHash = "sha256-4f9ibOc6OHK8GIezoRaID7xOq3MCBFkqvBtociRYIn4=";

      zigRelease = "ReleaseSafe";

      zigTarget = null;

      dontBuild = true;
      dontInstall = true;

      PROTOC_PATH = lib.getExe pkgs.protobuf;

      nativeCheckInputs = with pkgs; [sqlite];

      zigCheckFlags = toString [
        "-Dotel"
        "-Dzqlite"
      ];

      preCheck = ''
        zig build generate \
          "''${zigDefaultFlagsArray[@]}" \
          $zigCheckFlags "''${zigCheckFlagsArray[@]}"
      '';

      postCheck = ''
        touch $out
      '';
    };
  };
}
