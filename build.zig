const std = @import("std");
const Build = std.Build;

pub fn build(b: *Build) !void {
    const opts = .{
        .target = b.standardTargetOptions(.{}),
        .optimize = b.standardOptimizeOption(.{}),
    };

    const lib_mod = b.addModule("lib", .{
        .root_source_file = b.path("root.zig"),
        .target = opts.target,
        .optimize = opts.optimize,
    });
    configureModule(b, lib_mod, opts);

    const test_step = b.step("test", "Run unit tests");
    {
        const lib_mod_test = b.addTest(.{
            .name = "lib",
            .root_source_file = lib_mod.root_source_file.?,
            .target = opts.target,
            .optimize = opts.optimize,
        });
        configureModule(b, &lib_mod_test.root_module, opts);

        const run_lib_mod_test = b.addRunArtifact(lib_mod_test);
        test_step.dependOn(&run_lib_mod_test.step);
    }
}

fn configureModule(b: *Build, module: *Build.Module, opts: anytype) void {
    module.addImport("trait", b.dependency("trait", opts).module("zigtrait"));
}
