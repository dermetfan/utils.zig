{inputs, ...}: {
  imports = with inputs; [
    make-shell.flakeModules.default
  ];

  perSystem = {
    config,
    pkgs,
    ...
  }: {
    devShells.default = config.make-shells.zig.finalPackage;

    make-shells.zig = {
      packages = with pkgs; [zig zls];

      shellHook = ''
        # TODO remove once merged: https://github.com/NixOS/nixpkgs/pull/310588
        # Set to `/build/tmp.XXXXXXXXXX` by the zig hook.
        unset ZIG_GLOBAL_CACHE_DIR
      '';
    };
  };
}
