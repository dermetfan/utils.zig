const std = @import("std");
const Build = std.Build;

pub const Options = struct {
    target: Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,

    zqlite: bool,
};

pub fn build(b: *Build) !void {
    const options = Options{
        .target = b.standardTargetOptions(.{}),
        .optimize = b.standardOptimizeOption(.{}),

        .zqlite = b.option(bool, "zqlite", "Enable the zqlite utils") orelse false,
    };

    const options_mod = options_mod: {
        const src = b.addOptions();
        src.addOption(bool, "zqlite", options.zqlite);
        break :options_mod src.createModule();
    };

    const utils_mod = b.addModule("utils", .{
        .root_source_file = b.path("src/root.zig"),
        .target = options.target,
        .optimize = options.optimize,
        .imports = &.{
            .{ .name = "build_options", .module = options_mod },
        },
    });
    addDependencyImports(b, utils_mod, options);

    const test_step = b.step("test", "Run unit tests");
    {
        const utils_mod_test = b.addTest(.{
            .root_source_file = utils_mod.root_source_file.?,
            .target = options.target,
            .optimize = options.optimize,
        });
        addDependencyImports(b, &utils_mod_test.root_module, options);
        linkSystemLibraries(&utils_mod_test.root_module, options);
        utils_mod_test.root_module.addImport("build_options", options_mod);

        const run_utils_mod_test = b.addRunArtifact(utils_mod_test);
        test_step.dependOn(&run_utils_mod_test.step);
    }

    _ = utils.addCheckTls(b);
}

fn addDependencyImports(b: *Build, module: *Build.Module, options: Options) void {
    const common_options = .{
        .target = options.target,
        .optimize = options.optimize,
    };

    module.addImport("trait", b.dependency("trait", common_options).module("zigtrait"));

    if (options.zqlite) {
        module.addImport("zqlite", (b.lazyDependency("zqlite", common_options) orelse return).module("zqlite"));
    }
}

fn linkSystemLibraries(module: *Build.Module, options: Options) void {
    if (options.zqlite) {
        module.link_libc = true;
        module.linkSystemLibrary("sqlite3", .{});
    }
}

pub const utils = struct {
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

            std.fs.accessAbsolute(src_dir_path, .{}) catch |err| return switch (err) {
                error.FileNotFound => step.result_cached = true,
                else => err,
            };

            try self.inner.step.makeFn(&self.inner.step, progress_node);
            step.result_cached = self.inner.step.result_cached;
        }
    };
};
