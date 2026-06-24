{
  inputs,
  config,
  ...
}: {
  imports = with inputs; [
    make-shell.flakeModules.default
  ];

  flake.shellModules.zig = {pkgs, ...}: {
    packages = with pkgs; [zig zls];
  };

  perSystem.make-shells.default = {pkgs, ...}: {
    imports = [config.flake.shellModules.zig];

    packages = with pkgs; [sqlite.dev];
  };
}
