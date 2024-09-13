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

    _ = lib.addCheckTls(b);
}

fn configureModule(b: *Build, module: *Build.Module, opts: anytype) void {
    module.addImport("trait", b.dependency("trait", opts).module("zigtrait"));
}

pub const lib = struct {
    pub fn addCheckTls(b: *Build) *Build.Step {
        const check_step = b.step("check", "Check compilation for errors");

        for (b.top_level_steps.values()) |tls|
            addCheckTlsDependencies(check_step, &tls.step);

        return check_step;
    }

    fn addCheckTlsDependencies(check_step: *Build.Step, step: *Build.Step) void {
        if (step.id == .compile) {
            if (std.mem.indexOfScalar(*Build.Step, check_step.dependencies.items, step) == null)
                check_step.dependOn(step);
        } else for (step.dependencies.items) |dep_step|
            addCheckTlsDependencies(check_step, dep_step);
    }

    /// Like `std.Build.Step.InstallDir`
    /// but does nothing instead of returning an error
    /// if the source directory does not exist.
    pub const InstallDirLenientStep = struct {
        step: Build.Step,
        inner: *Build.Step.InstallDir,

        pub const base_id = .install_dir_lenient;

        pub fn create(owner: *Build, options: Build.Step.InstallDir.Options) *@This() {
            const self = owner.allocator.create(@This()) catch @panic("OOM");

            const inner = Build.Step.InstallDir.create(owner, options);

            self.* = .{
                .step = Build.Step.init(.{
                    .id = inner.step.id,
                    .name = inner.step.name,
                    .owner = inner.step.owner,
                    .makeFn = make,
                }),
                .inner = inner,
            };

            return self;
        }

        fn make(step: *Build.Step, progress_node: std.Progress.Node) !void {
            const self: *@This() = @fieldParentPtr("step", step);
            const src_dir_path = self.inner.options.source_dir.getPath2(step.owner, step);

            std.fs.accessAbsolute(src_dir_path, .{}) catch |err| switch (err) {
                error.FileNotFound => {
                    step.result_cached = true;
                    return;
                },
                else => return err,
            };

            try self.inner.step.makeFn(&self.inner.step, progress_node);
            step.result_cached = self.inner.step.result_cached;
        }
    };
};
