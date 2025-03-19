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

    shellHook = ''
      # TODO remove once merged: https://github.com/NixOS/nixpkgs/pull/310588
      # Set to `/build/tmp.XXXXXXXXXX` by the zig hook.
      unset ZIG_GLOBAL_CACHE_DIR
    '';
  };

  perSystem.make-shells.default = {pkgs, ...}: {
    imports = [config.flake.shellModules.zig];

    packages = with pkgs; [sqlite.dev];
  };
}
