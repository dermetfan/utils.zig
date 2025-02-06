const std = @import("std");
const meta = @import("src/meta.zig");

const Build = std.Build;

pub const Options = struct {
    target: Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,

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
            .{ .name = "trait", .module = b.dependency("trait", options.common()).module("zigtrait") },
        },
    });
    if (options.zqlite)
        utils_mod.addImport("zqlite", (b.lazyDependency("zqlite", options.common()) orelse return).module("zqlite"));

    const test_step = b.step("test", "Run unit tests");
    {
        const utils_mod_test = utils.addModuleTest(b, utils_mod, .{});
        linkSystemLibraries(&utils_mod_test.root_module, options);
        utils_mod_test.root_module.addImport("build_options", options_mod);

        const run_utils_mod_test = b.addRunArtifact(utils_mod_test);
        test_step.dependOn(&run_utils_mod_test.step);
    }

    _ = utils.addCheckTls(b);
}

fn linkSystemLibraries(module: *Build.Module, options: Options) void {
    if (options.zqlite) {
        module.link_libc = true;
        module.linkSystemLibrary("sqlite3", .{});
    }
}

pub const utils = struct {
    pub const ModuleTestOptions = meta.SubStruct(Build.TestOptions, fields: {
        var fields = std.enums.EnumSet(std.meta.FieldEnum(Build.TestOptions)).initFull();
        fields.remove(.root_source_file);
        fields.remove(.optimize);
        fields.remove(.target);
        break :fields fields;
    });

    pub fn addModuleTest(
        b: *Build,
        module: *const Build.Module,
        options: ModuleTestOptions,
    ) *Build.Step.Compile {
        var test_options = Build.TestOptions{
            .root_source_file = module.root_source_file.?,
        };
        inline for (@typeInfo(ModuleTestOptions).Struct.fields) |field|
            @field(test_options, field.name) = @field(options, field.name);
        if (module.optimize) |optimize|
            test_options.optimize = optimize;
        if (module.resolved_target) |target|
            test_options.target = target;

        const module_test = b.addTest(test_options);

        {
            var module_import_iter = module.import_table.iterator();
            while (module_import_iter.next()) |import|
                module_test.root_module.addImport(import.key_ptr.*, import.value_ptr.*);
        }

        return module_test;
    }

    pub fn addCheckTls(b: *Build) *Build.Step {
        const check_step = b.step("check", "Check compilation for errors");

        var checked = std.AutoHashMap(*const Build.Step, void).init(b.allocator);
        defer checked.deinit();

        for (b.top_level_steps.values()) |tls|
            if (&tls.step != check_step)
                addCheckTlsDependencies(check_step, &tls.step, &checked);

        return check_step;
    }

    fn addCheckTlsDependencies(
        check_step: *Build.Step,
        step: *Build.Step,
        checked: *std.AutoHashMap(*const Build.Step, void),
    ) void {
        if (step.id == .compile) {
            if (checked.contains(step)) return;
            checked.put(step, {}) catch @panic("OOM");

            const compile = step.cast(Build.Step.Compile).?;

            var check_compile = step.owner.allocator.create(Build.Step.Compile) catch @panic("OOM");
            check_compile.* = compile.*;
            check_compile.step.name = std.mem.concat(step.owner.allocator, u8, &.{ "check ", step.name }) catch @panic("OOM");
            check_compile.generated_bin = null;

            check_step.dependOn(&check_compile.step);
        } else for (step.dependencies.items) |dep_step|
            addCheckTlsDependencies(check_step, dep_step, checked);
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
