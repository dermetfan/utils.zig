{inputs, ...}: {
  imports = [
    inputs.treefmt-nix.flakeModule
  ];

  perSystem.treefmt = {
    projectRootFile = "flake.nix";
    programs = {
      alejandra.enable = true;
      deadnix.enable = true;
      statix = {
        enable = true;
        disabled-lints = [
          "unquoted_uri"
        ];
      };
      zig.enable = true;
    };
    settings.formatter.zig.excludes = [
      "nix/overlays/zig/package-info.zig"
    ];
  };
}
