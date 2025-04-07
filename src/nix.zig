const root = @import("root");
const builtin = @import("builtin");
const std = @import("std");

const mem = @import("mem.zig");
const meta = @import("meta.zig");
const uri = @import("uri.zig");

pub const build_hook = @import("nix/build-hook.zig");

/// The Nix internal JSON log message format.
/// This corresponds to `--log-format internal-json`.
pub const log = @import("nix/log.zig");

/// The Nix daemon wire protocol format.
pub const wire = @import("nix/wire.zig");

pub const Options = struct {
    log_scope: @TypeOf(.EnumLiteral) = .@"utils/nix",
    runFn: @TypeOf(defaultRunFn) = defaultRunFn,

    const RunArgs = @typeInfo(@TypeOf(std.process.Child.run)).@"fn".params[0].type.?;

    /// Only has the fields that are actually needed
    /// so that an implementation that supports only these can be supplied.
    pub const RunFnArgs = meta.SubStruct(RunArgs, std.enums.EnumSet(std.meta.FieldEnum(RunArgs)).initMany(&.{
        .allocator,
        .max_output_bytes,
        .argv,
    }));

    fn defaultRunFn(args: RunFnArgs) std.process.Child.RunError!std.process.Child.RunResult {
        return std.process.Child.run(.{
            .allocator = args.allocator,
            .max_output_bytes = args.max_output_bytes,
            .argv = args.argv,
        });
    }
};

pub const options: Options = if (@hasDecl(root, "utils_nix_options")) root.utils_nix_options else .{};

const log_scoped = std.log.scoped(options.log_scope);

fn embedExpr(comptime name: []const u8) [:0]const u8 {
    return @embedFile("nix/" ++ name ++ ".nix");
}

const ExprBinding = struct {
    identifier: []const u8,
    value: []const u8,
};

/// `bindings` must not have a `lib`.
fn libLeaf(allocator: std.mem.Allocator, comptime name: []const u8, extra_bindings: []const ExprBinding) !std.ArrayListUnmanaged(u8) {
    var expr = std.ArrayListUnmanaged(u8){};

    // using `with` instead of a `let` block so that
    // `lib` and `bindings` have no access to anything else
    try expr.appendSlice(allocator, "with {\n");

    inline for (.{
        [_]ExprBinding{
            .{ .identifier = "lib", .value = embedExpr("lib") },
        },
        extra_bindings,
    }) |bindings|
        for (bindings) |binding| {
            const eq = " = ";
            const term = ";\n";

            try expr.ensureUnusedCapacity(allocator, binding.identifier.len + eq.len + binding.value.len + term.len);

            expr.appendSliceAssumeCapacity(binding.identifier);
            expr.appendSliceAssumeCapacity(eq);
            expr.appendSliceAssumeCapacity(binding.value);
            expr.appendSliceAssumeCapacity(term);
        };

    try expr.appendSlice(allocator, "};\n");
    try expr.appendSlice(allocator, embedExpr(name));

    return expr;
}

/// A nix expression function that takes a flake and evaluates to the output of the `hydra-eval-jobs` executable.
pub const hydraEvalJobs = expr: {
    var buf: [
        switch (builtin.target.cpu.arch) {
            .wasm32 => 4792,
            else => 4602,
        }
    ]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const allocator = fba.allocator();

    var expr = libLeaf(allocator, "hydra-eval-jobs", &.{}) catch |err| @compileError(@errorName(err));
    defer expr.deinit(allocator);

    var expr_buf: [expr.items.len:0]u8 = undefined;
    @memcpy(&expr_buf, expr.items);

    break :expr expr_buf;
};

/// Returns a new expression that evaluates to a list of derivations
/// that are found in the given expression.
pub fn recurseForDerivations(allocator: std.mem.Allocator, expression: []const u8) !std.ArrayListUnmanaged(u8) {
    return libLeaf(
        allocator,
        "recurseForDerivations",
        &.{
            .{ .identifier = "expression", .value = expression },
        },
    );
}

test recurseForDerivations {
    // this test spawns a process
    if (true) return error.SkipZigTest;

    const expr = expr: {
        var expr = try recurseForDerivations(std.testing.allocator,
            \\let
            \\  mkDerivation = name: builtins.derivation {
            \\    inherit name;
            \\    system = "dummy";
            \\    builder = "dummy";
            \\  };
            \\in [
            \\  (mkDerivation "a")
            \\  [(mkDerivation "b")]
            \\  {c = mkDerivation "c";}
            \\  {
            \\    recurseForDerivations = true;
            \\    a = {
            \\      recurseForDerivations = false;
            \\      d = mkDerivation "d";
            \\    };
            \\    b = {e = mkDerivation "e";};
            \\    c = [(mkDerivation "f")];
            \\  }
            \\]
        );
        break :expr try expr.toOwnedSlice(std.testing.allocator);
    };
    defer std.testing.allocator.free(expr);

    const result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &.{
            "nix",
            "eval",
            "--restrict-eval",
            "--expr",
            expr,
            "--raw",
            "--apply",
            \\drvs: builtins.concatStringsSep "\n" (map (drv: drv.name) drvs)
        },
    });
    defer {
        std.testing.allocator.free(result.stdout);
        std.testing.allocator.free(result.stderr);
    }

    try std.testing.expectEqual(std.process.Child.Term{ .Exited = 0 }, result.term);
    try std.testing.expectEqualStrings(
        \\a
        \\b
        \\c
        \\e
    , result.stdout);
    try std.testing.expectEqualStrings("", result.stderr);
}

pub const FailedBuilds = struct {
    /// derivations that failed to build
    builds: []const []const u8,
    /// derivations that have dependencies that failed
    dependents: []const []const u8,

    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        for (self.builds) |drv| allocator.free(drv);
        allocator.free(self.builds);

        for (self.dependents) |drv| allocator.free(drv);
        allocator.free(self.dependents);

        self.* = undefined;
    }

    /// Duplicates the slices taken from `stderr` so you can free it after the call.
    pub fn fromErrorMessage(allocator: std.mem.Allocator, stderr_reader: anytype) !@This() {
        var builds = std.StringArrayHashMapUnmanaged(void){};
        defer builds.deinit(allocator);

        var dependents = std.StringArrayHashMapUnmanaged(void){};
        defer dependents.deinit(allocator);

        var line = std.ArrayListUnmanaged(u8){};
        defer line.deinit(allocator);
        const line_writer = line.writer(allocator);

        line: while (true) : (line.clearRetainingCapacity()) {
            stderr_reader.streamUntilDelimiter(line_writer, '\n', null) catch |err| switch (err) {
                error.EndOfStream => break :line,
                else => |e| return e,
            };

            const readExpected = struct {
                fn call(reader: anytype, comptime slice: []const u8) !bool {
                    var buf: [slice.len]u8 = undefined;
                    const len = reader.readAll(&buf) catch |err|
                        return if (err == error.EndOfStream) false else err;
                    return std.mem.eql(u8, buf[0..len], slice);
                }
            }.call;

            builds: {
                var line_stream = std.io.fixedBufferStream(line.items);
                const line_reader = line_stream.reader();

                var drv_list = std.ArrayListUnmanaged(u8){};
                errdefer drv_list.deinit(allocator);

                try line_reader.skipUntilDelimiterOrEof('e'); // skip whitespace
                if (!try readExpected(line_reader, "rror: builder for '")) break :builds;
                line_reader.streamUntilDelimiter(drv_list.writer(allocator), '\'', null) catch break :builds;
                if (!try readExpected(line_reader, " failed")) break :builds;

                const drv = try drv_list.toOwnedSlice(allocator);
                errdefer allocator.free(drv);

                try builds.put(allocator, drv, {});
            }

            foreign_builds: {
                var line_stream = std.io.fixedBufferStream(line.items);
                const line_reader = line_stream.reader();

                var drv_list = std.ArrayListUnmanaged(u8){};
                errdefer drv_list.deinit(allocator);

                try line_reader.skipUntilDelimiterOrEof('e'); // skip whitespace
                if (!try readExpected(line_reader, "rror: a '")) break :foreign_builds;
                line_reader.streamUntilDelimiter(std.io.null_writer, '\'', null) catch break :foreign_builds;
                if (!try readExpected(line_reader, " with features {")) break :foreign_builds;
                line_reader.streamUntilDelimiter(std.io.null_writer, '}', null) catch break :foreign_builds;
                if (!try readExpected(line_reader, " is required to build '")) break :foreign_builds;
                line_reader.streamUntilDelimiter(drv_list.writer(allocator), '\'', null) catch break :foreign_builds;
                if (!try readExpected(line_reader, ", but I am a '")) break :foreign_builds;
                line_reader.streamUntilDelimiter(std.io.null_writer, '\'', null) catch break :foreign_builds;
                if (!try readExpected(line_reader, " with features {")) break :foreign_builds;
                line_reader.streamUntilDelimiter(std.io.null_writer, '}', null) catch break :foreign_builds;
                if (line_reader.readByte() != error.EndOfStream) break :foreign_builds;

                const drv = try drv_list.toOwnedSlice(allocator);
                errdefer allocator.free(drv);

                try builds.put(allocator, drv, {});
            }

            dependents: {
                var line_stream = std.io.fixedBufferStream(line.items);
                const line_reader = line_stream.reader();

                var drv_list = std.ArrayListUnmanaged(u8){};
                errdefer drv_list.deinit(allocator);

                try line_reader.skipUntilDelimiterOrEof('e'); // skip whitespace
                if (!try readExpected(line_reader, "rror: ")) break :dependents;
                line_reader.streamUntilDelimiter(std.io.null_writer, ' ', null) catch break :dependents;
                if (!try readExpected(line_reader, "dependencies of derivation '")) break :dependents;
                line_reader.streamUntilDelimiter(drv_list.writer(allocator), '\'', null) catch break :dependents;
                if (!try readExpected(line_reader, " failed to build")) break :dependents;

                const drv = try drv_list.toOwnedSlice(allocator);
                errdefer allocator.free(drv);

                try dependents.put(allocator, drv, {});
            }
        }

        const builds_slice = try allocator.dupe([]const u8, builds.keys());
        errdefer allocator.free(builds_slice);

        const dependents_slice = try allocator.dupe([]const u8, dependents.keys());
        errdefer allocator.free(dependents_slice);

        return .{
            .builds = builds_slice,
            .dependents = dependents_slice,
        };
    }
};

pub const ChildProcessDiagnostics = struct {
    term: std.process.Child.Term,
    stderr: []u8,

    fn fromRunResult(result: std.process.Child.RunResult) @This() {
        return .{
            .term = result.term,
            .stderr = result.stderr,
        };
    }

    pub fn deinit(self: @This(), allocator: std.mem.Allocator) void {
        allocator.free(self.stderr);
    }
};

pub const VersionError =
    std.process.Child.RunError ||
    error{ InvalidVersion, Overflow, UnknownNixVersion };

pub fn version(allocator: std.mem.Allocator) VersionError!std.SemanticVersion {
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "nix", "eval", "--raw", "--expr", "builtins.nixVersion" },
    });
    defer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }

    if (result.term != .Exited or result.term.Exited != 0) {
        log_scoped.warn("could not get nix version:\nstdout: {s}\nstderr: {s}", .{ result.stdout, result.stderr });
        return error.UnknownNixVersion;
    }

    return std.SemanticVersion.parse(result.stdout);
}

/// Some options are optional to support older Nix versions
/// or because they only appear once their corresponding
/// experimental feature is enabled.
pub const Config = struct {
    @"abort-on-warn": ?Option(bool) = null,
    @"accept-flake-config": Option(bool),
    @"access-tokens": Option(std.json.ArrayHashMap([]const u8)),
    @"allow-dirty": Option(bool),
    @"allow-import-from-derivation": Option(bool),
    @"allow-new-privileges": Option(bool),
    @"allow-symlinked-store": Option(bool),
    @"allow-unsafe-native-code-during-evaluation": Option(bool),
    @"allowed-impure-host-deps": Option([]const []const u8),
    @"allowed-uris": Option([]const []const u8),
    @"allowed-users": Option([]const []const u8),
    @"always-allow-substitutes": ?Option(bool) = null,
    @"auto-allocate-uids": Option(bool),
    @"auto-optimise-store": Option(bool),
    @"bash-prompt": Option([]const u8),
    @"bash-prompt-prefix": Option([]const u8),
    @"bash-prompt-suffix": Option([]const u8),
    @"build-dir": ?Option(?[]const u8) = null,
    @"build-hook": Option([]const []const u8),
    @"build-poll-interval": Option(u16),
    @"build-users-group": Option([]const u8),
    builders: Option([]const u8),
    @"builders-use-substitutes": Option(bool),
    // Called `commit-lock-file-summary` (note the additional dash) since Nix 2.23.
    // Newer Nix versions have an alias for the old name
    // so we use the old name to support both old and new versions.
    @"commit-lockfile-summary": Option([]const u8),
    @"compress-build-log": Option(bool),
    @"connect-timeout": Option(u16),
    cores: Option(u16),
    @"debugger-on-trace": ?Option(bool) = null,
    @"debugger-on-warn": ?Option(bool) = null,
    @"diff-hook": Option(?[]const u8),
    @"download-attempts": Option(u16),
    @"download-buffer-size": ?Option(usize) = null,
    @"download-speed": Option(u32),
    @"eval-cache": Option(bool),
    @"eval-system": ?Option([]const u8) = null,
    @"experimental-features": Option([]const []const u8),
    @"extra-platforms": Option([]const []const u8),
    fallback: Option(bool),
    @"filter-syscalls": Option(bool),
    @"flake-registry": Option([]const u8),
    @"fsync-metadata": Option(bool),
    @"gc-reserved-space": Option(u64),
    @"hashed-mirrors": Option([]const []const u8),
    @"http-connections": Option(u16),
    http2: Option(bool),
    @"id-count": Option(u32),
    @"ignore-try": Option(bool),
    @"ignored-acls": Option([]const []const u8),
    @"impersonate-linux-26": Option(bool),
    @"impure-env": ?Option(std.json.ArrayHashMap([]const u8)) = null,
    @"keep-build-log": Option(bool),
    @"keep-derivations": Option(bool),
    @"keep-env-derivations": Option(bool),
    @"keep-failed": Option(bool),
    @"keep-going": Option(bool),
    @"keep-outputs": Option(bool),
    @"log-lines": Option(u32),
    @"max-build-log-size": Option(u64),
    @"max-call-depth": ?Option(u16) = null,
    @"max-free": Option(u64),
    @"max-jobs": Option(u16),
    @"max-silent-time": Option(u32),
    @"max-substitution-jobs": Option(u16),
    @"min-free": Option(u64),
    @"min-free-check-interval": Option(u16),
    @"nar-buffer-size": Option(u32),
    @"narinfo-cache-negative-ttl": Option(u32),
    @"narinfo-cache-positive-ttl": Option(u32),
    @"netrc-file": Option([]const u8),
    @"nix-path": Option([]const []const u8),
    @"nix-shell-always-looks-for-shell-nix": ?Option(bool) = null,
    @"nix-shell-shebang-arguments-relative-to-script": ?Option(bool) = null,
    @"plugin-files": Option([]const []const u8),
    @"post-build-hook": Option([]const u8),
    @"pre-build-hook": Option([]const u8),
    @"preallocate-contents": Option(bool),
    @"print-missing": Option(bool),
    @"pure-eval": Option(bool),
    @"require-drop-supplementary-groups": Option(bool),
    @"require-sigs": Option(bool),
    @"restrict-eval": Option(bool),
    @"run-diff-hook": Option(bool),
    sandbox: Option(bool),
    @"sandbox-build-dir": Option([]const u8),
    @"sandbox-dev-shm-size": Option([]const u8),
    @"sandbox-fallback": Option(bool),
    @"sandbox-paths": Option([]const []const u8),
    @"secret-key-files": Option([]const []const u8),
    @"show-trace": Option(bool),
    @"ssl-cert-file": Option([]const u8),
    @"stalled-download-timeout": Option(u16),
    @"start-id": Option(u32),
    store: Option([]const u8),
    substitute: Option(bool),
    substituters: Option([]const []const u8),
    @"sync-before-registering": Option(bool),
    system: Option([]const u8),
    @"system-features": Option([]const []const u8),
    @"tarball-ttl": Option(u32),
    timeout: Option(u32),
    @"trace-function-calls": Option(bool),
    @"trace-verbose": Option(bool),
    @"trust-tarballs-from-git-forges": ?Option(bool) = null,
    @"trusted-public-keys": Option([]const []const u8),
    @"trusted-substituters": Option([]const []const u8),
    @"trusted-users": Option([]const []const u8),
    @"upgrade-nix-store-path-url": ?Option([]const u8) = null,
    @"use-case-hack": Option(bool),
    @"use-cgroups": Option(bool),
    @"use-registries": Option(bool),
    @"use-sqlite-wal": Option(bool),
    @"use-xdg-base-directories": Option(bool),
    @"user-agent-suffix": Option([]const u8),
    @"warn-dirty": Option(bool),
    @"warn-large-path-threshold": ?Option(u64) = null,

    pub fn Option(comptime T: type) type {
        return struct {
            aliases: []const []const u8,
            defaultValue: T,
            description: []const u8,
            documentDefault: bool,
            experimentalFeature: ?[]const u8,
            value: T,
        };
    }

    pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, opts: std.json.ParseOptions) std.json.ParseError(@TypeOf(source.*))!@This() {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();

        const value = try std.json.innerParse(std.json.Value, arena.allocator(), source, opts);

        return jsonParseFromValue(allocator, value, opts);
    }

    pub fn jsonParseFromValue(allocator: std.mem.Allocator, source: std.json.Value, opts: std.json.ParseOptions) std.json.ParseFromValueError!@This() {
        if (source != .object) return error.UnexpectedToken;

        var self: @This() = undefined;

        inline for (std.meta.fields(@This())) |field| {
            const option_object = source.object.get(field.name) orelse alias: for (source.object.keys()) |key| {
                const option_object = source.object.get(key).?;
                if (option_object != .object) return error.UnexpectedToken;

                const aliases_array = option_object.object.get("aliases") orelse return error.MissingField;
                if (aliases_array != .array) return error.UnexpectedToken;

                for (aliases_array.array.items) |alias_string| {
                    if (alias_string != .string) return error.UnexpectedToken;

                    if (!std.mem.eql(u8, alias_string.string, field.name)) continue;

                    break :alias option_object;
                }
            } else if (field.defaultValue()) |default_value| {
                @field(self, field.name) = default_value;
                comptime continue;
            } else return error.MissingField;

            @field(self, field.name) = try std.json.innerParseFromValue(field.type, allocator, option_object, opts);
        }

        return self;
    }
};

pub const ConfigError =
    std.process.Child.RunError ||
    std.json.ParseError(std.json.Scanner) ||
    error{CouldNotReadNixConfig};

pub const ConfigDiagnostics = union {
    CouldNotReadNixConfig: ChildProcessDiagnostics,
};

pub fn config(
    allocator: std.mem.Allocator,
    diagnostics: ?*ConfigDiagnostics,
) ConfigError!std.json.Parsed(Config) {
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .max_output_bytes = 100 * mem.b_per_kib,
        .argv = &.{ "nix", "show-config", "--json" },
    });
    defer allocator.free(result.stdout);

    if (result.term != .Exited or result.term.Exited != 0) {
        if (diagnostics) |d| d.* = .{ .CouldNotReadNixConfig = ChildProcessDiagnostics.fromRunResult(result) };
        return error.CouldNotReadNixConfig;
    }
    allocator.free(result.stderr);

    return std.json.parseFromSlice(Config, allocator, result.stdout, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
}

test config {
    // this test spawns a process
    if (true) return error.SkipZigTest;

    (try config(std.testing.allocator, null)).deinit();
}

/// Output of `nix flake metadata --json`.
pub const FlakeMetadata = struct {
    description: ?[]const u8 = null,
    lastModified: i64,
    locked: Input,
    locks: Locks,
    original: Input,
    originalUrl: []const u8,
    path: []const u8,
    resolved: Input,
    resolvedUrl: []const u8,
    revision: []const u8,
    flake: bool = true,

    /// As of Nix 2.20, the manual says
    /// the key should be called `lockedUrl`,
    /// but it is actually called just `url`:
    /// https://github.com/NixOS/nix/blob/d9775222fbfa7e5d8ce1f722ea2968ff840324b4/src/nix/flake.cc#L218
    /// This has been wrong from the start:
    /// https://github.com/NixOS/nix/commit/68b43e01ddf990182c87a924d647dc7aa93b34f7#diff-98db1e334292594945051880fac0aecb52c9206898bd3cbc79730d647b260824R108
    url: []const u8,

    /// Basically a partial port of Nix' `src/libfetchers/*.cc`.
    pub const Input = union(enum) {
        indirect: IndirectScheme,
        path: PathScheme,
        git: GitScheme,
        mercurial: MercurialScheme,
        tarball: CurlScheme,
        file: CurlScheme,
        github: GitArchiveScheme,
        gitlab: GitArchiveScheme,
        sourcehut: GitArchiveScheme,

        const Scheme = struct {
            dir: ?[]const u8 = null,
            narHash: ?[]const u8 = null,
            lastModified: ?i64 = null,
        };

        pub const IndirectScheme = meta.MergedStructs(&.{ Scheme, struct {
            id: []const u8,
            ref: ?[]const u8 = null,
            rev: ?[]const u8 = null,
        } });

        pub const PathScheme = meta.MergedStructs(&.{ Scheme, struct {
            path: []const u8,
            rev: ?[]const u8 = null,
            revCount: u64 = 0,
        } });

        pub const GitScheme = meta.MergedStructs(&.{
            Scheme,
            struct {
                url: []const u8,
                ref: ?[]const u8 = null,
                rev: ?[]const u8 = null,
                shallow: bool = false,
                submodules: bool = false,
                exportIgnore: bool = false,
                revCount: u64 = 0,
                allRefs: bool = false,
                // name: ?[]const u8, // XXX remove, seems to have no use
                // XXX make sure these are the same as `rev` but with "-dirty" suffix
                dirtyRev: ?[]const u8 = null,
                dirtyShortRev: ?[]const u8 = null,
                verifyCommit: bool = false,
                keytype: ?[]const u8 = null,
                publicKey: ?[]const u8 = null,
                publicKeys: ?[]const u8 = null,
            },
        });

        pub const MercurialScheme = meta.MergedStructs(&.{
            Scheme,
            struct {
                url: []const u8,
                ref: ?[]const u8 = null,
                rev: ?[]const u8 = null,
                revCount: u64 = 0,
                // name: ?[]const u8 = null, // XXX remove, seems to have no use
            },
        });

        pub const CurlScheme = meta.MergedStructs(&.{
            Scheme,
            struct {
                // type: []const u8, // XXX remove, makes no sense
                url: []const u8,
                // name: ?[]const u8 = null, // XXX remove, seems to have no use
                unpack: bool = true,
                rev: ?[]const u8 = null,
                revCount: u64 = 0,
            },
        });

        pub const GitArchiveScheme = meta.MergedStructs(&.{ Scheme, struct {
            owner: []const u8,
            repo: []const u8,
            ref: ?[]const u8 = null,
            rev: ?[]const u8 = null,
            host: ?[]const u8 = null,
            treeHash: ?[]const u8 = null,
        } });

        pub fn locked(self: @This(), trust_tarballs_from_git_forges: bool) bool {
            return switch (self) {
                .github, .gitlab, .sourcehut => |v| v.rev != null and
                    (trust_tarballs_from_git_forges or v.narHash != null),
                inline else => |v| v.narHash != null or
                    @hasField(@TypeOf(v), "rev") and v.rev != null,
            };
        }

        pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, opts: std.json.ParseOptions) std.json.ParseError(@TypeOf(source.*))!@This() {
            var arena = std.heap.ArenaAllocator.init(allocator);
            defer arena.deinit();

            const value = try std.json.innerParse(std.json.Value, arena.allocator(), source, opts);

            return jsonParseFromValue(allocator, value, opts);
        }

        pub fn jsonParseFromValue(allocator: std.mem.Allocator, source: std.json.Value, opts: std.json.ParseOptions) std.json.ParseFromValueError!@This() {
            if (source != .object) return error.UnexpectedToken;

            const type_str = (source.object.get("type") orelse return error.MissingField).string;

            var active_options = opts;
            active_options.ignore_unknown_fields = true;

            return self: inline for (std.meta.fields(@This())) |field| {
                if (std.mem.eql(u8, field.name, type_str))
                    break :self @unionInit(
                        @This(),
                        field.name,
                        try std.json.innerParseFromValue(field.type, allocator, source, active_options),
                    );
            } else return error.InvalidEnumTag;
        }

        test jsonParse {
            (try std.json.parseFromSlice(@This(), std.testing.allocator,
                \\{
                \\  "type": "path",
                \\  "path": "foo/bar"
                \\}
            , .{})).deinit();
            (try std.json.parseFromSlice(@This(), std.testing.allocator,
                \\{
                \\  "type": "git",
                \\  "url": "git+https://example.com/foo/bar"
                \\}
            , .{})).deinit();
        }

        pub fn valid(self: @This()) bool {
            return switch (self) {
                .github, .gitlab, .sourcehut => |v| v.ref == null or v.rev == null,
                else => true,
            };
        }

        pub fn toUrl(self: @This(), arena: std.mem.Allocator) (std.mem.Allocator.Error || std.Uri.ParseError)!std.Uri {
            var url: std.Uri = switch (self) {
                .indirect => |input| .{
                    .scheme = "flake",
                    .path = path: {
                        var parts = std.ArrayListUnmanaged([]const u8){};
                        defer parts.deinit(arena);

                        try parts.append(arena, input.id);
                        if (input.ref) |ref| try parts.append(arena, ref);
                        if (input.rev) |rev| try parts.append(arena, rev);

                        break :path .{ .raw = try std.mem.join(arena, "/", parts.items) };
                    },
                    .query = try structToQuery(arena, input, fields: {
                        var fields = std.EnumSet(std.meta.FieldEnum(@TypeOf(input))).initFull();
                        fields.remove(.id);
                        fields.remove(.ref);
                        fields.remove(.rev);
                        break :fields fields;
                    }),
                },
                .path => |input| .{
                    .scheme = @tagName(self),
                    .path = .{ .raw = input.path },
                    .query = try structToQuery(arena, input, fields: {
                        var fields = std.EnumSet(std.meta.FieldEnum(@TypeOf(input))).initFull();
                        fields.remove(.path);
                        fields.remove(.revCount);
                        break :fields fields;
                    }),
                },
                .git => |input| try urlFromInputUrl(arena, input, "git", fields: {
                    // XXX
                    // const publicKeys = getPublicKeys(input.attrs);
                    // if (publicKeys.size() == 1) {
                    //     url.query.insert_or_assign("keytype", publicKeys.at(0).type);
                    //     url.query.insert_or_assign("publicKey", publicKeys.at(0).key);
                    // } else if (publicKeys.size() > 1)
                    //     url.query.insert_or_assign("publicKeys", publicKeys_to_string(publicKeys));
                    var fields = std.EnumSet(std.meta.FieldEnum(@TypeOf(input))).initFull();
                    fields.remove(.revCount);
                    fields.remove(.dirtyRev);
                    fields.remove(.dirtyShortRev);
                    break :fields fields;
                }),
                .mercurial => |input| try urlFromInputUrl(arena, input, "hg", fields: {
                    var fields = std.EnumSet(std.meta.FieldEnum(@TypeOf(input))).initFull();
                    fields.remove(.revCount);
                    break :fields fields;
                }),
                .tarball, .file => |input| try urlFromInputUrl(arena, input, @tagName(self), fields: {
                    var fields = std.EnumSet(std.meta.FieldEnum(@TypeOf(input))).initFull();
                    fields.remove(.unpack);
                    fields.remove(.rev);
                    fields.remove(.revCount);
                    break :fields fields;
                }),
                .github, .gitlab, .sourcehut => |input| .{
                    .scheme = @tagName(self),
                    .path = path: {
                        var path = std.ArrayListUnmanaged(u8){};
                        defer path.deinit(arena);

                        try path.appendSlice(arena, input.owner);
                        try path.append(arena, '/');
                        try path.appendSlice(arena, input.repo);
                        std.debug.assert(input.ref == null or input.rev == null);
                        if (input.ref) |ref| {
                            try path.append(arena, '/');
                            try path.appendSlice(arena, ref);
                        }
                        if (input.rev) |rev| {
                            try path.append(arena, '/');
                            try path.appendSlice(arena, rev);
                        }

                        break :path .{ .raw = try path.toOwnedSlice(arena) };
                    },
                    .query = try structToQuery(arena, input, fields: {
                        var fields = std.EnumSet(std.meta.FieldEnum(@TypeOf(input))).initFull();
                        fields.remove(.owner);
                        fields.remove(.repo);
                        fields.remove(.ref);
                        fields.remove(.rev);
                        break :fields fields;
                    }),
                },
            };

            // An empty query causes a trailing `?` when `url` is formatted.
            if (url.query) |query| {
                if (query.isEmpty())
                    url.query = null;
            }

            return url;
        }

        fn urlFromInputUrl(
            arena: std.mem.Allocator,
            input: anytype,
            scheme: ?[]const u8,
            comptime fields: std.EnumSet(std.meta.FieldEnum(@TypeOf(input))),
        ) (std.mem.Allocator.Error || std.Uri.ParseError)!std.Uri {
            var url = try std.Uri.parse(input.url);

            if (scheme) |s| {
                if (!std.mem.eql(u8, url.scheme, s)) {
                    const url_scheme = try std.mem.concat(arena, u8, &.{ s, "+", url.scheme });
                    url.scheme = url_scheme;
                }
            }

            const query = query: {
                var query_map = try structToQueryMap(arena, input, fields: {
                    var fields_ = fields;
                    fields_.remove(.url);
                    break :fields fields_;
                });

                if (url.query) |url_query| {
                    var url_query_iter = uri.QueryIterator.init(switch (url_query) {
                        inline else => |v| v,
                    });
                    while (url_query_iter.next()) |param| {
                        // XXX Skip if the `param.value` is the default.
                        // Not needed when emitting `--allowed-uris`
                        // with inputs parsed from a `flake.lock`
                        // because Nix has already done that for us
                        // before writing into the `flake.lock`.
                        // Would be nice to have though because it
                        // would make this function also canonicalize the URL,
                        // allowing users to construct it whatever way they like.

                        const gop = try query_map.getOrPut(param.key);
                        // Fields take precendence over the URL's query parameters.
                        if (!gop.found_existing)
                            gop.value_ptr.* = param.value;
                    }
                }

                break :query try mapToQuery(arena, &query_map.unmanaged);
            };
            url.query = query;

            return url;
        }

        test toUrl {
            var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
            defer arena.deinit();
            const allocator = arena.allocator();

            try std.testing.expectFmt(
                "flake:cizero",
                "{}",
                .{try (@This(){ .indirect = .{
                    .id = "cizero",
                } }).toUrl(allocator)},
            );
            try std.testing.expectFmt(
                "flake:cizero/master/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee?dir=nix",
                "{}",
                .{try (@This(){ .indirect = .{
                    .id = "cizero",
                    .ref = "master",
                    .rev = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                    .dir = "nix",
                } }).toUrl(allocator)},
            );

            try std.testing.expectFmt(
                "path:foo",
                "{}",
                .{try (@This(){ .path = .{
                    .path = "foo",
                } }).toUrl(allocator)},
            );
            try std.testing.expectFmt(
                "path:/cizero?dir=nix&rev=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                "{}",
                .{try (@This(){
                    .path = .{
                        .path = "/cizero",
                        .dir = "nix",
                        .rev = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                        .revCount = 1, // Make sure this is not emitted.
                    },
                }).toUrl(allocator)},
            );

            try std.testing.expectFmt(
                "git+https://example.com:42/cizero/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee?dir=nix",
                "{}",
                .{try (@This(){ .git = .{
                    .url = "https://example.com:42/cizero/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                    .dir = "nix",
                } }).toUrl(allocator)},
            );
            try std.testing.expectFmt(
                "hg+https://example.com:42/cizero/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee?dir=nix",
                "{}",
                .{try (@This(){ .mercurial = .{
                    .url = "https://example.com:42/cizero/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                    .dir = "nix",
                } }).toUrl(allocator)},
            );
            try std.testing.expectFmt(
                "tarball+https://example.com:42/cizero.tar.gz?dir=nix",
                "{}",
                .{try (@This(){ .tarball = .{
                    .url = "https://example.com:42/cizero.tar.gz",
                    .dir = "nix",
                } }).toUrl(allocator)},
            );
            try std.testing.expectFmt(
                "file+https://example.com:42/cizero.tar.gz?dir=nix",
                "{}",
                .{try (@This(){ .file = .{
                    .url = "https://example.com:42/cizero.tar.gz",
                    .dir = "nix",
                } }).toUrl(allocator)},
            );

            try std.testing.expectFmt(
                "git+file:/cizero?shallow=1&submodules=1",
                "{}",
                .{try (@This(){
                    .git = .{
                        .url = "file:/cizero",
                        .shallow = true,
                        .submodules = true,
                        .lastModified = 0, // Make sure this is not emitted.
                    },
                }).toUrl(allocator)},
            );
            // XXX see "XXX Skip if the `param.value` is the default."
            if (false) try std.testing.expectFmt(
                "git+https://example.com:42/cizero/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee?dir=nix",
                "{}",
                .{try (@This(){
                    .git = .{
                        .url = "https://example.com:42/cizero/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee?submodules=1",
                        .dir = "nix",
                        .submodules = false, // Make sure this precedes the `url`'s query parameter.
                    },
                }).toUrl(allocator)},
            );

            try std.testing.expectFmt(
                "github:input-output-hk/cizero/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                "{}",
                .{try (@This(){ .github = .{
                    .owner = "input-output-hk",
                    .repo = "cizero",
                    .rev = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                } }).toUrl(allocator)},
            );

            try std.testing.expectFmt(
                "github:input-output-hk/cizero/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee?dir=nix&host=example.com",
                "{}",
                .{try (@This(){ .github = .{
                    .owner = "input-output-hk",
                    .repo = "cizero",
                    .rev = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                    .host = "example.com",
                    .dir = "nix",
                } }).toUrl(allocator)},
            );
            try std.testing.expectFmt(
                "gitlab:input-output-hk/cizero/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee?dir=nix&host=example.com",
                "{}",
                .{try (@This(){ .gitlab = .{
                    .owner = "input-output-hk",
                    .repo = "cizero",
                    .rev = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                    .host = "example.com",
                    .dir = "nix",
                } }).toUrl(allocator)},
            );
            try std.testing.expectFmt(
                "sourcehut:~input-output-hk/cizero/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee?dir=nix&host=example.com",
                "{}",
                .{try (@This(){ .sourcehut = .{
                    .owner = "~input-output-hk",
                    .repo = "cizero",
                    .rev = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                    .host = "example.com",
                    .dir = "nix",
                } }).toUrl(allocator)},
            );
        }

        fn structToQuery(
            allocator: std.mem.Allocator,
            strukt: anytype,
            comptime fields: std.EnumSet(std.meta.FieldEnum(@TypeOf(strukt))),
        ) std.mem.Allocator.Error!std.Uri.Component {
            var arena = std.heap.ArenaAllocator.init(allocator);
            defer arena.deinit();

            var map = try structToQueryMap(arena.allocator(), strukt, fields);
            return mapToQuery(allocator, &map.unmanaged);
        }

        fn structToQueryMap(
            arena: std.mem.Allocator,
            strukt: anytype,
            comptime fields: std.EnumSet(std.meta.FieldEnum(@TypeOf(strukt))),
        ) std.mem.Allocator.Error!std.StringArrayHashMap([]const u8) {
            var map = std.StringArrayHashMap([]const u8).init(arena);

            comptime var fields_ = fields;
            comptime if (@hasField(@TypeOf(strukt), "lastModified")) fields_.remove(.lastModified);

            comptime var fields_iter = fields_.iterator();
            inline while (comptime fields_iter.next()) |field| {
                const value = @field(strukt, @tagName(field));

                if (std.meta.fieldInfo(@TypeOf(strukt), field).defaultValue()) |default_value|
                    if (eqlFlakeUrlQueryParam(value, default_value)) comptime continue;

                if (try stringifyFlakeUrlQueryParam(arena, value)) |v|
                    try map.put(@tagName(field), v);
            }

            return map;
        }

        fn eqlFlakeUrlQueryParam(a: anytype, b: @TypeOf(a)) bool {
            const A = @TypeOf(a);
            const a_child, const b_child = switch (@typeInfo(A)) {
                .optional => optional: {
                    if (a == null and b == null) return true;
                    if ((a == null) != (b == null)) return false;
                    break :optional .{ a.?, b.? };
                },
                else => .{ a, b },
            };
            return switch (@TypeOf(a_child)) {
                []const u8 => std.mem.eql(u8, a_child, b_child),
                bool => a_child == b_child,
                u64, i64 => a_child == b_child,
                else => @compileError("unsupported type \"" ++ @typeName(A) ++ "\" for flake URL query parameters"),
            };
        }

        fn stringifyFlakeUrlQueryParam(allocator: std.mem.Allocator, param: anytype) std.mem.Allocator.Error!?[]const u8 {
            const Param = @TypeOf(param);
            const param_child = switch (@typeInfo(Param)) {
                .optional => if (param) |p| p else return null,
                else => param,
            };
            return switch (@TypeOf(param_child)) {
                []const u8 => param_child,
                bool => if (param_child) "1" else "0",
                u64, i64 => try std.fmt.allocPrint(allocator, "{d}", .{param_child}),
                else => @compileError("unsupported type \"" ++ @typeName(Param) ++ "\" for flake URL query parameters"),
            };
        }

        fn mapToQuery(
            allocator: std.mem.Allocator,
            /// Will be sorted after this function returns without error.
            map: *std.StringArrayHashMapUnmanaged([]const u8),
        ) std.mem.Allocator.Error!std.Uri.Component {
            if (map.count() == 0) return std.Uri.Component.empty;

            var query = std.ArrayListUnmanaged(u8){};
            defer query.deinit(allocator);

            {
                // When matching `allowed-uris`, Nix does not take into account
                // that a URL could have query parameters.
                // Instead it just checks whether any allowed URI
                // is a string prefix of the URL in question:
                // https://github.com/NixOS/nix/blob/a4f978bd9b872f0d51aff95b83054358767ef193/src/libexpr/eval.cc#L397
                // That also means it is impossible to use `--allowed-uris`
                // to allow URLs like `github:foo/bar?host=example.com`
                // or `https://github.com/foo/bar?rev=refs/tags/baz`
                // which excludes flake inputs of type `git`
                // with commit granularity, *unless* we emit
                // the _exact_ same URL including the query.
                // Luckily the query Nix compares against is deterministic
                // because it iterates over the query parameters as a sorted map:
                // https://github.com/NixOS/nix/blob/a4f978bd9b872f0d51aff95b83054358767ef193/src/libfetchers/fetchers.cc#L128
                // So that's what we need to do also.
                map.sortUnstable(struct {
                    keys: []const []const u8,

                    pub fn lessThan(ctx: @This(), a_index: usize, b_index: usize) bool {
                        return std.mem.order(u8, ctx.keys[a_index], ctx.keys[b_index]) == .lt;
                    }
                }{ .keys = map.keys() });

                // We cannot use a raw component and rely on it
                // being percent-encoded by `std.Uri.format()`
                // because that only percent-encodes what is necessary.
                // Nix percent-encodes the query more aggressively
                // and does not recognize Zig's minimally escaped form
                // when matching against its `allowed-uris` setting.
                // Therefore we explicitely percent-encode the set of characters Nix does.
                const isValidChar = struct {
                    /// Same as `std.Uri.isQueryChar()` but without `=` and `+`.
                    /// Unfortunately that function is not public
                    /// so we need to repeat its implementation here.
                    /// Because `=` must be encoded in values but is also a separator,
                    /// we cannot simply encode the entire query at once
                    /// and instead need to encode the values separately.
                    fn isValidChar(c: u8) bool {
                        return switch (c) {
                            // same as `std.Uri.isUnreserved()`
                            'A'...'Z',
                            'a'...'z',
                            '0'...'9',
                            '-',
                            '.',
                            '_',
                            '~',
                            // same as `std.Uri.isSubLimit()` but without `=` and `+`
                            '!',
                            '$',
                            '&',
                            '\'',
                            '(',
                            ')',
                            '*',
                            ',',
                            ';',
                            // additions from `std.Uri.isPathChar()`
                            '/',
                            ':',
                            '@',
                            // additions from `std.Uri.isQueryChar()`
                            '?',
                            => true,
                            else => false,
                        };
                    }
                }.isValidChar;

                var iter = map.iterator();
                var first = true;
                while (iter.next()) |entry| {
                    if (first)
                        first = false
                    else
                        try query.append(allocator, '&');

                    try std.Uri.Component.percentEncode(query.writer(allocator), entry.key_ptr.*, isValidChar);
                    if (entry.value_ptr.len != 0) {
                        try query.append(allocator, '=');
                        try std.Uri.Component.percentEncode(query.writer(allocator), entry.value_ptr.*, isValidChar);
                    }
                }
            }

            return .{ .percent_encoded = try query.toOwnedSlice(allocator) };
        }

        /// Writes the URL-like form suitable to be passed to `--allowed-uris`,
        /// possibly multiple variants, separated by a space character,
        /// in order to pass Nix' primitive `allowed-uris` matching in all possible cases.
        pub fn writeAllowedUri(self: @This(), allocator: std.mem.Allocator, writer: anytype) !void {
            var arena = std.heap.ArenaAllocator.init(allocator);
            defer arena.deinit();

            const write_to_stream_options = std.Uri.WriteToStreamOptions{
                .scheme = true,
                .authentication = true,
                .authority = true,
                .path = true,
                .query = true,
            };

            {
                const url = try self.toUrl(arena.allocator());
                try url.writeToStream(write_to_stream_options, writer);
            }

            switch (self) {
                inline else => |v, tag| if (v.narHash != null) {
                    // We don't need the previously allocated stuff.
                    // Free it to so we don't allocate more than necessary.
                    _ = arena.reset(.retain_capacity);

                    var input = v;
                    input.narHash = null;

                    try writer.writeByte(' ');

                    const url = try @unionInit(@This(), @tagName(tag), input).toUrl(arena.allocator());
                    try url.writeToStream(write_to_stream_options, writer);
                },
            }
        }

        test writeAllowedUri {
            const This = @This();

            const expectAllowedUris = struct {
                pub fn expectAllowedUris(expected: []const u8, input: This) !void {
                    var actual = std.ArrayList(u8).init(std.testing.allocator);
                    defer actual.deinit();

                    try input.writeAllowedUri(std.testing.allocator, actual.writer());

                    try std.testing.expectEqualStrings(expected, actual.items);
                }
            }.expectAllowedUris;

            try expectAllowedUris(
                "path:foo",
                @This(){ .path = .{ .path = "foo" } },
            );

            try expectAllowedUris(
                "path:foo?narHash=sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D path:foo",
                @This(){ .path = .{ .path = "foo", .narHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" } },
            );
        }
    };

    /// Contents of `flake.lock`.
    pub const Locks = struct {
        root: []const u8,
        version: u8,
        nodes: std.json.ArrayHashMap(Node),

        pub const Node = union(enum) {
            root: Root,
            full: Full,
            leaf: Leaf,
            non_flake: NonFlake,

            pub const Full = struct {
                inputs: std.json.ArrayHashMap([]const []const u8),
                locked: Input,
                original: Input,
            };

            pub const Leaf = meta.SubStruct(Full, std.enums.EnumSet(std.meta.FieldEnum(Full)).initMany(&.{ .locked, .original }));

            pub const Root = meta.SubStruct(Full, std.enums.EnumSet(std.meta.FieldEnum(Full)).initMany(&.{.inputs}));

            pub const NonFlake = struct {
                flake: bool = false,
                locked: Input,
                original: Input,
            };

            /// Assumes `trust-tarballs-from-git-forges = true` for checking whether inputs are locked for validation.
            pub fn jsonParseFromValue(allocator: std.mem.Allocator, source: std.json.Value, opts: std.json.ParseOptions) !@This() {
                if (source != .object) return error.UnexpectedToken;

                if (source.object.get("flake")) |flake| if (flake == .bool and !flake.bool) return .{ .non_flake = try std.json.parseFromValueLeaky(NonFlake, allocator, source, opts) };

                const inputs = if (source.object.get("inputs")) |inputs| inputs: {
                    var map = std.StringArrayHashMapUnmanaged([]const []const u8){};
                    errdefer map.deinit(allocator);

                    var iter = inputs.object.iterator();
                    while (iter.next()) |input| try map.put(allocator, input.key_ptr.*, switch (input.value_ptr.*) {
                        .string => |string| &.{string},
                        .array => try std.json.parseFromValueLeaky([]const []const u8, allocator, input.value_ptr.*, opts),
                        else => return error.UnexpectedToken,
                    });

                    break :inputs std.json.ArrayHashMap([]const []const u8){ .map = map };
                } else null;
                const locked = if (source.object.get("locked")) |locked| try std.json.parseFromValueLeaky(Input, allocator, locked, opts) else null;
                if (locked) |l| {
                    if (!l.locked(true)) return error.MissingField;
                    std.debug.assert(l.valid());
                }
                const original = if (source.object.get("original")) |original| try std.json.parseFromValueLeaky(Input, allocator, original, opts) else null;
                if (original) |o| std.debug.assert(o.valid());

                return if (inputs != null and locked != null and original != null) .{ .full = .{
                    .inputs = inputs.?,
                    .locked = locked.?,
                    .original = original.?,
                } } else if (inputs == null and locked != null and original != null) .{ .leaf = .{
                    .locked = locked.?,
                    .original = original.?,
                } } else if (inputs != null and locked == null and original == null) .{ .root = .{
                    .inputs = inputs.?,
                } } else if (inputs == null and locked == null and original == null) .{ .root = .{
                    .inputs = .{ .map = .{} },
                } } else error.MissingField;
            }
        };
    };
};

pub const FlakeMetadataDiagnostics = union {
    FlakeMetadataFailed: ChildProcessDiagnostics,
};

pub const FlakeMetadataOptions = struct {
    max_output_bytes: usize = 50 * mem.b_per_kib,
    refresh: bool = true,
    no_write_lock_file: bool = true,
};

pub fn flakeMetadata(
    allocator: std.mem.Allocator,
    flake: []const u8,
    opts: FlakeMetadataOptions,
    diagnostics: ?*FlakeMetadataDiagnostics,
) !std.json.Parsed(FlakeMetadata) {
    const argv = try std.mem.concat(allocator, []const u8, &.{
        &.{
            "nix",
            "flake",
            "metadata",
        },
        if (opts.refresh) &.{"--refresh"} else &.{},
        if (opts.no_write_lock_file) &.{"--no-write-lock-file"} else &.{},
        &.{
            "--json",
            flake,
        },
    });
    defer allocator.free(argv);

    const result = try options.runFn(.{
        .allocator = allocator,
        .max_output_bytes = opts.max_output_bytes,
        .argv = argv,
    });
    defer allocator.free(result.stdout);

    if (result.term != .Exited or result.term.Exited != 0) {
        log_scoped.debug("could not get flake metadata {s}: {}\n{s}", .{ flake, result.term, result.stderr });
        if (diagnostics) |d| d.* = .{ .FlakeMetadataFailed = ChildProcessDiagnostics.fromRunResult(result) };
        return error.FlakeMetadataFailed; // TODO return more specific error
    }
    defer allocator.free(result.stderr);

    const json_options = std.json.ParseOptions{ .ignore_unknown_fields = true };

    const json = try std.json.parseFromSlice(std.json.Value, allocator, result.stdout, json_options);
    defer json.deinit();

    return std.json.parseFromValue(FlakeMetadata, allocator, json.value, json_options);
}

pub const FlakePrefetchOptions = struct {
    max_output_bytes: usize = 50 * mem.b_per_kib,
    refresh: bool = true,
};

pub const FlakeMetadataLocksDiagnostics = union {
    FlakePrefetchFailed: ChildProcessDiagnostics,
};

/// This is faster than `flakeMetadata()` if you only need the contents of `flake.lock`.
pub fn flakeMetadataLocks(
    allocator: std.mem.Allocator,
    flake: []const u8,
    opts: FlakePrefetchOptions,
    diagnostics: ?*FlakeMetadataLocksDiagnostics,
) !?std.json.Parsed(FlakeMetadata.Locks) {
    const argv = try std.mem.concat(allocator, []const u8, &.{
        &.{
            "nix",
            "flake",
            "prefetch",
            "--no-use-registries",
            "--flake-registry",
            "",
        },
        if (opts.refresh) &.{"--refresh"} else &.{},
        &.{
            "--json",
            flake,
        },
    });
    defer allocator.free(argv);

    const result = try options.runFn(.{
        .allocator = allocator,
        .max_output_bytes = opts.max_output_bytes,
        .argv = argv,
    });
    defer allocator.free(result.stdout);

    if (result.term != .Exited or result.term.Exited != 0) {
        log_scoped.debug("could not prefetch flake {s}: {}\n{s}", .{ flake, result.term, result.stderr });
        if (diagnostics) |d| d.* = .{ .FlakePrefetchFailed = ChildProcessDiagnostics.fromRunResult(result) };
        return error.FlakePrefetchFailed; // TODO return more specific error
    }
    defer allocator.free(result.stderr);

    const json_options = std.json.ParseOptions{ .ignore_unknown_fields = true };

    const json = json: {
        const flake_lock = flake_lock: {
            var stdout_parsed = try std.json.parseFromSlice(struct { storePath: []const u8 }, allocator, result.stdout, json_options);
            defer stdout_parsed.deinit();

            const path = try std.fs.path.join(allocator, &.{ stdout_parsed.value.storePath, "flake.lock" });
            defer allocator.free(path);

            break :flake_lock std.fs.openFileAbsolute(path, .{}) catch |err|
                return if (err == error.FileNotFound) null else err;
        };
        defer flake_lock.close();

        var json_reader = std.json.reader(allocator, flake_lock.reader());
        defer json_reader.deinit();

        break :json try std.json.parseFromTokenSource(std.json.Value, allocator, &json_reader, json_options);
    };
    defer json.deinit();

    return try std.json.parseFromValue(FlakeMetadata.Locks, allocator, json.value, json_options);
}

test flakeMetadataLocks {
    // this test needs internet and spawns child processes
    if (true) return error.SkipZigTest;

    if (try flakeMetadataLocks(std.testing.allocator, "github:IntersectMBO/cardano-db-sync/13.0.4", .{ .refresh = false }, null)) |locks| locks.deinit();
}

pub fn lockFlakeRef(
    allocator: std.mem.Allocator,
    flake_ref: []const u8,
    opts: FlakeMetadataOptions,
    diagnostics: ?*FlakeMetadataDiagnostics,
) ![]const u8 {
    const flake = std.mem.sliceTo(flake_ref, '#');

    const metadata = try flakeMetadata(allocator, flake, opts, diagnostics);
    defer metadata.deinit();

    const flake_ref_locked = try std.mem.concat(allocator, u8, &.{
        metadata.value.url,
        flake_ref[flake.len..],
    });
    errdefer allocator.free(flake_ref_locked);

    return flake_ref_locked;
}

test lockFlakeRef {
    // this test spawns child processes
    if (true) return error.SkipZigTest;

    const latest = "github:NixOS/nixpkgs";
    const input = latest ++ "/23.11";
    const expected = latest ++ "/057f9aecfb71c4437d2b27d3323df7f93c010b7e?narHash=sha256-MxCVrXY6v4QmfTwIysjjaX0XUhqBbxTWWB4HXtDYsdk%3D";

    {
        const locked = locked: {
            var diagnostics: FlakeMetadataDiagnostics = undefined;
            errdefer |err| switch (err) {
                error.FlakeMetadataFailed => {
                    defer diagnostics.FlakeMetadataFailed.deinit(std.testing.allocator);
                    log_scoped.err("term: {}\nstderr: {s}", .{
                        diagnostics.FlakeMetadataFailed.term,
                        diagnostics.FlakeMetadataFailed.stderr,
                    });
                },
                else => {},
            };
            break :locked try lockFlakeRef(std.testing.allocator, input, .{}, &diagnostics);
        };
        defer std.testing.allocator.free(locked);

        try std.testing.expectEqualStrings(expected, locked);
    }

    {
        const locked = locked: {
            var diagnostics: FlakeMetadataDiagnostics = undefined;
            errdefer |err| switch (err) {
                error.FlakeMetadataFailed => {
                    defer diagnostics.FlakeMetadataFailed.deinit(std.testing.allocator);
                    log_scoped.err("term: {}\nstderr: {s}", .{
                        diagnostics.FlakeMetadataFailed.term,
                        diagnostics.FlakeMetadataFailed.stderr,
                    });
                },
                else => {},
            };
            break :locked try lockFlakeRef(std.testing.allocator, input ++ "#hello^out", .{}, &diagnostics);
        };
        defer std.testing.allocator.free(locked);

        try std.testing.expectEqualStrings(expected ++ "#hello^out", locked);
    }
}

pub const StoreInfo = struct {
    url: []const u8,
    version: ?std.SemanticVersion = null,
    trusted: bool = false,

    pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, opts: std.json.ParseOptions) std.json.ParseError(@TypeOf(source.*))!@This() {
        const inner = try std.json.innerParse(struct {
            url: []const u8,
            version: ?[]const u8 = null,
            trusted: ?u1 = null,
        }, allocator, source, opts);

        return .{
            .url = try allocator.dupe(u8, inner.url),
            .version = if (inner.version) |v|
                std.SemanticVersion.parse(v) catch |err| return switch (err) {
                    error.InvalidVersion => error.UnexpectedToken,
                    else => |e| e,
                }
            else
                null,
            .trusted = inner.trusted orelse 0 == 1,
        };
    }
};

pub const StoreInfoError =
    std.process.Child.RunError ||
    std.json.ParseError(std.json.Scanner) ||
    error{CouldNotPingNixStore};

pub const StoreInfoDiagnostics = union {
    CouldNotPingNixStore: ChildProcessDiagnostics,
};

pub fn storeInfo(
    allocator: std.mem.Allocator,
    store: []const u8,
    diagnostics: ?*StoreInfoDiagnostics,
) StoreInfoError!std.json.Parsed(StoreInfo) {
    const result = try options.runFn(.{
        .allocator = allocator,
        .argv = &.{ "nix", "store", "info", "--json", "--store", store },
    });
    defer allocator.free(result.stdout);

    if (result.term != .Exited or result.term.Exited != 0) {
        if (diagnostics) |d| d.* = .{ .CouldNotPingNixStore = ChildProcessDiagnostics.fromRunResult(result) };
        return error.CouldNotPingNixStore;
    }
    allocator.free(result.stderr);

    return std.json.parseFromSlice(StoreInfo, allocator, result.stdout, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
}
