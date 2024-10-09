{
  inputs = {
    nixpkgs.url = github:NixOS/nixpkgs/nixpkgs-unstable;
    parts.url = github:hercules-ci/flake-parts;
    make-shell.url = github:nicknovitski/make-shell;
    treefmt-nix = {
      url = github:numtide/treefmt-nix;
      inputs.nixpkgs.follows = "nixpkgs";
    };
    inclusive = {
      url = github:input-output-hk/nix-inclusive;
      inputs.stdlib.follows = "parts/nixpkgs-lib";
    };
    zig2nix = {
      url = github:Cloudef/zig2nix;
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs:
    inputs.parts.lib.mkFlake {inherit inputs;} (parts: {
      systems = ["x86_64-linux"];

      imports = [
        nix/overlays
        nix/checks.nix
        nix/devShells.nix
        nix/formatter.nix
        nix/hydraJobs.nix
      ];

      perSystem = {
        inputs',
        config,
        ...
      }: {
        _module.args.pkgs =
          inputs'.nixpkgs.legacyPackages.extend
          parts.config.flake.overlays.zig;
      };
    });
}
