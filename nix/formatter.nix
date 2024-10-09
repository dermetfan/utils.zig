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
    };
  };
}
