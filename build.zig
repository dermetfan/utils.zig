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
        },
    });
    if (options.zqlite)
        utils_mod.addImport("zqlite", (b.lazyDependency("zqlite", options.common()) orelse return).module("zqlite"));

    const test_step = b.step("test", "Run unit tests");
    {
        const utils_mod_test = b.addTest(.{ .root_module = utils_mod });
        linkSystemLibraries(utils_mod_test.root_module, options);
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

    pub const NixIncludeDirIterator = struct {
        tokenizer: std.mem.TokenIterator(u8, .scalar),
        expect: ?std.meta.Tag(Build.Module.IncludeDir) = null,

        pub const Error = error{RelativeNixIncludeDir};

        /// Only needed after `initOwned()`.
        pub fn deinit(self: @This(), allocator: std.mem.Allocator) void {
            allocator.free(self.tokenizer.buffer);
        }

        pub fn init(flags: []const u8) @This() {
            return .{ .tokenizer = std.mem.tokenizeScalar(u8, flags, ' ') };
        }

        pub fn initOwned(allocator: std.mem.Allocator) std.process.GetEnvVarOwnedError!@This() {
            const flags = try std.process.getEnvVarOwned(allocator, "NIX_CFLAGS_COMPILE");
            errdefer allocator.free(flags);

            return init(flags);
        }

        pub fn next(self: *@This()) Error!?Build.Module.IncludeDir {
            while (self.tokenizer.next()) |flag| {
                if (self.expect) |e| {
                    defer self.expect = null;

                    if (!std.fs.path.isAbsolute(flag))
                        return error.RelativeNixIncludeDir;

                    return switch (e) {
                        inline .path, .path_after, .path_system => |tag| @unionInit(
                            Build.Module.IncludeDir,
                            @tagName(tag),
                            .{ .cwd_relative = flag },
                        ),
                        else => unreachable,
                    };
                } else self.expect = if (std.mem.eql(u8, flag, "-I"))
                    .path
                else if (std.mem.eql(u8, flag, "-idirafter"))
                    .path_after
                else if (std.mem.eql(u8, flag, "-isystem"))
                    .path_system
                else
                    continue;
            } else return null;
        }
    };

    test NixIncludeDirIterator {
        const path1 = "/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-foo/include";
        const path2 = "/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-bar/include";
        const path3 = "/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-baz/include";

        var iter = NixIncludeDirIterator.init(
            \\ -frandom-seed=cbjljz61s4 -I
        ++ " " ++ path1 ++
            \\ -idirafter
        ++ " " ++ path2 ++
            \\ -isystem
        ++ " " ++ path3,
        );

        try std.testing.expectEqualStrings(path1, (try iter.next()).?.path.cwd_relative);
        try std.testing.expectEqualStrings(path2, (try iter.next()).?.path_after.cwd_relative);
        try std.testing.expectEqualStrings(path3, (try iter.next()).?.path_system.cwd_relative);
    }

    pub fn addNixIncludePaths(target: anytype) (std.process.GetEnvVarOwnedError || NixIncludeDirIterator.Error)!void {
        const Target = @TypeOf(target);

        const allocator = switch (Target) {
            *Build.Module => target.owner.allocator,
            *Build.Step.Compile, *Build.Step.TranslateC => target.step.owner.allocator,
            else => @compileError(@typeName(Target) ++ " is not supported"),
        };

        var iter = try NixIncludeDirIterator.initOwned(allocator);
        defer iter.deinit(allocator);

        while (try iter.next()) |include_dir|
            addIncludeDir(target, include_dir);
    }

    pub fn addIncludeDir(target: anytype, include_dir: Build.Module.IncludeDir) void {
        switch (include_dir) {
            .path => |path| target.addIncludePath(path),
            .path_after => |path| target.addAfterIncludePath(path),
            .path_system => |path| target.addSystemIncludePath(path),
            .framework_path => |path| target.addFrameworkPath(path),
            .framework_path_system => |path| target.addSystemFrameworkPath(path),
            .other_step => |other| {
                // Modeled after `Build.Module.IncludeDir.appendZigProcessFlags()`.
                if (other.generated_h) |header|
                    target.addSystemIncludePath(.{ .generated = .{ .file = header } });
                if (other.installed_headers_include_tree) |include_tree|
                    target.addIncludePath(.{ .generated = .{ .file = &include_tree.generated_directory } });
            },
            .config_header_step => |header| target.addConfigHeader(header),
        }
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

        fn make(step: *Build.Step, options: Build.Step.MakeOptions) !void {
            const self: *@This() = @fieldParentPtr("step", step);
            const src_dir_path = self.inner.options.source_dir.getPath2(step.owner, step);

            std.fs.accessAbsolute(src_dir_path, .{}) catch |err| return switch (err) {
                error.FileNotFound => step.result_cached = true,
                else => err,
            };

            try self.inner.step.makeFn(&self.inner.step, options);
            step.result_cached = self.inner.step.result_cached;
        }
    };
};

test {
    _ = utils;
}
