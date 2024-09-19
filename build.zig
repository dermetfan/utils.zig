const std = @import("std");

const Build = std.Build;

pub const Options = struct {
    target: Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,

    otel: bool,
    zqlite: bool,

    pub fn common(self: @This()) struct {
        target: Build.ResolvedTarget,
        optimize: std.builtin.OptimizeMode,
    } {
        return .{
            .target = self.target,
            .optimize = self.optimize,
        };
    }
};

pub fn build(b: *Build) !void {
    const options = Options{
        .target = b.standardTargetOptions(.{}),
        .optimize = b.standardOptimizeOption(.{}),

        .otel = b.option(bool, "otel", "Enable the OpenTelemetry SDK") orelse false,
        .zqlite = b.option(bool, "zqlite", "Enable the zqlite utils") orelse false,
    };

    const options_mod = options_mod: {
        const src = b.addOptions();
        src.addOption(bool, "otel", options.otel);
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

    if (options.otel) {
        const generate = b.step("generate", "generate source files from protobuf definitions");
        {
            const proto_path = (b.lazyDependency("opentelemetry-proto", .{}) orelse return).path("").getPath(b);

            var protoc_step = (b.lazyImport(@This(), "protobuf") orelse return).RunProtocStep.create(
                b,
                (b.lazyDependency("protobuf", options.common()) orelse return).builder,
                options.target,
                .{
                    .destination_directory = b.path("src/otel/otlp"),
                    .source_files = &.{
                        "opentelemetry/proto/collector/trace/v1/trace_service.proto",
                        "opentelemetry/proto/trace/v1/trace.proto",
                    },
                    .include_directories = &.{proto_path},
                },
            );
            protoc_step.verbose = b.verbose;

            generate.dependOn(&protoc_step.step);
        }
    }
}

fn addDependencyImports(b: *Build, module: *Build.Module, options: Options) void {
    module.addImport("trait", b.dependency("trait", options.common()).module("zigtrait"));

    if (options.zqlite) {
        module.addImport("zqlite", (b.lazyDependency("zqlite", options.common()) orelse return).module("zqlite"));
    }

    if (options.otel) {
        module.addImport("protobuf", (b.lazyDependency("protobuf", options.common()) orelse return).module("protobuf"));
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
