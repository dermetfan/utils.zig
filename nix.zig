const std = @import("std");

const meta = @import("meta.zig");

pub const build_hook = @import("nix/build-hook.zig");

/// The Nix internal JSON log message format.
/// This corresponds to `--log-format internal-json`.
pub const log = @import("nix/log.zig");

/// The Nix daemon wire protocol format.
pub const wire = @import("nix/wire.zig");

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
    var buf: [4602]u8 = undefined;
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

/// Output of `nix flake metadata --json`.
pub const FlakeMetadata = struct {
    description: ?[]const u8 = null,
    lastModified: i64,
    locked: Source,
    locks: Locks,
    original: Source,
    originalUrl: []const u8,
    path: []const u8,
    resolved: Source,
    resolvedUrl: []const u8,
    revision: []const u8,

    /// As of Nix 2.20, the manual says
    /// the key should be called `lockedUrl`,
    /// but it is actually called just `url`.
    url: []const u8,

    pub const Source = struct {
        type: Type,
        id: ?[]const u8 = null,
        url: ?[]const u8 = null,
        host: ?[]const u8 = null,
        path: ?[]const u8 = null,
        dir: ?[]const u8 = null,
        owner: ?[]const u8 = null,
        repo: ?[]const u8 = null,
        ref: ?[]const u8 = null,
        rev: ?[]const u8 = null,
        submodules: ?bool = null,
        narHash: ?[]const u8 = null,

        // can only be present if locked, not given by the user (read-only)
        lastModified: ?i64 = null,
        revCount: ?u64 = null,

        pub const Type = enum { indirect, path, git, mercurial, tarball, file, github, gitlab, sourcehut };

        pub fn immutable(self: @This()) bool {
            return self.narHash != null or self.rev != null;
        }

        // TODO do we already check all possible constraints?
        pub fn valid(self: @This()) bool {
            return switch (self.type) {
                .indirect => self.id != null and
                    self.path == null and
                    self.owner == null and
                    self.repo == null,
                .path, .tarball, .file => self.submodules == null and
                    self.owner == null and
                    self.repo == null and
                    self.host == null and
                    self.id == null and
                    self.ref == null and
                    self.rev == null and
                    self.revCount == null,
                .git, .mercurial => self.url != null and
                    if (self.rev != null) self.ref != null else true,
                .github, .gitlab, .sourcehut => self.path == null and
                    !(self.ref != null and self.rev != null),
            } and
                (if (self.lastModified != null) self.narHash != null else true) and
                (if (self.revCount != null) self.lastModified != null else true);
        }

        /// Returns the canonical URL-like form without locking information.
        pub fn toUrl(self: @This(), allocator: std.mem.Allocator) !std.Uri {
            var arena = std.heap.ArenaAllocator.init(allocator);
            defer arena.deinit();
            const alloc = arena.allocator();

            const url = if (self.url) |url| try std.Uri.parse(url) else null;

            var result = if (url) |u| u else std.Uri{ .scheme = "" };

            result.scheme = switch (self.type) {
                .indirect => "flake",
                .mercurial => try std.mem.concat(alloc, u8, &.{ "hg+", url.?.scheme }),
                .git, .tarball, .file => try std.mem.concat(alloc, u8, &.{ @tagName(self.type), "+", url.?.scheme }),
                else => @tagName(self.type),
            };
            result.path = switch (self.type) {
                .indirect => path: {
                    var parts = std.ArrayListUnmanaged([]const u8){};
                    defer parts.deinit(alloc);

                    try parts.append(alloc, self.id.?);
                    if (self.ref) |ref| try parts.append(alloc, ref);
                    if (self.rev) |rev| try parts.append(alloc, rev);

                    break :path .{ .percent_encoded = try std.mem.join(alloc, "/", parts.items) };
                },
                .path => .{ .percent_encoded = self.path.? },
                .github, .gitlab, .sourcehut => .{ .percent_encoded = try std.mem.join(
                    alloc,
                    "/",
                    if (self.ref) |ref|
                        &.{ self.owner.?, self.repo.?, ref }
                    else if (self.rev) |rev|
                        &.{ self.owner.?, self.repo.?, rev }
                    else
                        &.{ self.owner.?, self.repo.? },
                ) },
                .git, .mercurial, .tarball, .file => url.?.path,
            };
            result.query = query: {
                var query_args = std.StringArrayHashMapUnmanaged([]const u8){};
                defer query_args.deinit(alloc);

                if (self.host) |host| try query_args.put(alloc, "host", host);
                if (self.dir) |dir| try query_args.put(alloc, "dir", dir);
                if (self.submodules orelse false) try query_args.put(alloc, "submodules", "1");

                switch (self.type) {
                    .indirect, .github, .gitlab, .sourcehut => {},
                    else => {
                        if (self.narHash) |narHash| try query_args.put(alloc, "narHash", narHash);
                    },
                }

                if (query_args.count() == 0) break :query if (url) |u| u.query else null;

                var query = std.ArrayListUnmanaged(u8){};
                errdefer query.deinit(alloc);

                if (url) |u| if (u.query) |url_query| {
                    try url_query.format("raw", .{}, query.writer(alloc));
                    try query.append(alloc, '&');
                };

                {
                    var iter = query_args.iterator();
                    var first = true;
                    while (iter.next()) |entry| {
                        if (first)
                            first = false
                        else
                            try query.append(alloc, '&');

                        try query.appendSlice(alloc, entry.key_ptr.*);
                        try query.append(alloc, '=');
                        try query.appendSlice(alloc, entry.value_ptr.*);
                    }
                }

                break :query .{ .percent_encoded = try query.toOwnedSlice(alloc) };
            };

            return result;
        }

        test toUrl {
            var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
            defer arena.deinit();
            const allocator = arena.allocator();

            try std.testing.expectFmt("flake:cizero/master/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee?dir=nix&submodules=1", "{}", .{try (Source{
                .type = .indirect,
                .id = "cizero",
                .ref = "master",
                .rev = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                .dir = "nix",
                .submodules = true,
            }).toUrl(allocator)});

            try std.testing.expectFmt("path:/cizero?dir=nix", "{}", .{try (Source{
                .type = .path,
                .path = "/cizero",
                .dir = "nix",
            }).toUrl(allocator)});

            try std.testing.expectFmt("git+https://example.com:42/cizero/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee?dir=nix&submodules=1", "{}", .{try (Source{
                .type = .git,
                .url = "https://example.com:42/cizero/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee?dir=nix&submodules=1",
            }).toUrl(allocator)});
            try std.testing.expectFmt("hg+https://example.com:42/cizero/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee?dir=nix&submodules=1", "{}", .{try (Source{
                .type = .mercurial,
                .url = "https://example.com:42/cizero/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee?dir=nix&submodules=1",
            }).toUrl(allocator)});
            try std.testing.expectFmt("tarball+https://example.com:42/cizero.tar.gz?dir=nix", "{}", .{try (Source{
                .type = .tarball,
                .url = "https://example.com:42/cizero.tar.gz?dir=nix",
            }).toUrl(allocator)});
            try std.testing.expectFmt("file+https://example.com:42/cizero.tar.gz?dir=nix", "{}", .{try (Source{
                .type = .file,
                .url = "https://example.com:42/cizero.tar.gz?dir=nix",
            }).toUrl(allocator)});

            try std.testing.expectFmt("git+file:/cizero?submodules=1", "{}", .{try (Source{
                .type = .git,
                .url = "file:/cizero?submodules=1",
            }).toUrl(allocator)});

            try std.testing.expectFmt("github:input-output-hk/cizero/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee?host=example.com&dir=nix&submodules=1", "{}", .{try (Source{
                .type = .github,
                .owner = "input-output-hk",
                .repo = "cizero",
                .rev = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                .host = "example.com",
                .dir = "nix",
                .submodules = true,
            }).toUrl(allocator)});
            try std.testing.expectFmt("gitlab:input-output-hk/cizero/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee?host=example.com&dir=nix&submodules=1", "{}", .{try (Source{
                .type = .gitlab,
                .owner = "input-output-hk",
                .repo = "cizero",
                .rev = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                .host = "example.com",
                .dir = "nix",
                .submodules = true,
            }).toUrl(allocator)});
            try std.testing.expectFmt("sourcehut:~input-output-hk/cizero/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee?host=example.com&dir=nix&submodules=1", "{}", .{try (Source{
                .type = .sourcehut,
                .owner = "~input-output-hk",
                .repo = "cizero",
                .rev = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                .host = "example.com",
                .dir = "nix",
                .submodules = true,
            }).toUrl(allocator)});
        }

        /// Writes the URL-like form suitable to be passed to `--allowed-uris`.
        pub fn writeAllowedUri(self: @This(), allocator: std.mem.Allocator, writer: anytype) !void {
            var arena = std.heap.ArenaAllocator.init(allocator);
            defer arena.deinit();
            const arena_allocator = arena.allocator();

            const write_to_stream_options = .{
                .scheme = true,
                .authentication = true,
                .authority = true,
                .path = true,

                // As of Nix 2.19, Nix does not parse the query.
                // Instead it just does a prefix match
                // against the URL in question without its query.
                // That also means it is impossible to use `--allowed-uris`
                // to allow URLs like `github:foo/bar?host=example.com`.
                // TODO As of Nix 2.21 (maybe also earlier),
                // the `narHash` query param is included and checked against,
                // so we should allow that as well.
                .query = false,
            };

            const url = try self.toUrl(arena_allocator);

            try url.writeToStream(write_to_stream_options, writer);
            try writer.writeByte(' ');

            // As of Nix 2.19, shorthands are translated
            // into their target URL and that is checked against,
            // so we need to allow the target URL as well.
            // This is fixed in Nix 2.21 (maybe also earlier).
            if (switch (self.type) {
                .github => std.Uri{
                    .scheme = "https",
                    .host = .{ .percent_encoded = self.host orelse "github.com" },
                    .path = .{ .percent_encoded = try std.mem.concat(arena_allocator, u8, &.{
                        "/",
                        self.owner.?,
                        "/",
                        self.repo.?,
                        "/",
                        "archive",
                        "/",
                        self.ref orelse self.rev.?,
                        ".tar.gz",
                    }) },
                },
                // TODO gitlab
                // TODO sourcehut
                else => null,
            }) |target_url|
                try target_url.writeToStream(write_to_stream_options, writer);
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
                locked: Source,
                original: Source,
            };

            pub const Leaf = meta.SubStruct(Full, &.{ .locked, .original });

            pub const Root = meta.SubStruct(Full, &.{.inputs});

            pub const NonFlake = struct {
                flake: bool = false,
                locked: Source,
                original: Source,
            };

            pub fn jsonParseFromValue(allocator: std.mem.Allocator, source: std.json.Value, options: std.json.ParseOptions) !@This() {
                if (source != .object) return error.UnexpectedToken;

                if (source.object.get("flake")) |flake| if (flake == .bool and !flake.bool) return .{ .non_flake = try std.json.parseFromValueLeaky(NonFlake, allocator, source, options) };

                const inputs = if (source.object.get("inputs")) |inputs| inputs: {
                    var map = std.StringArrayHashMapUnmanaged([]const []const u8){};
                    errdefer map.deinit(allocator);

                    var iter = inputs.object.iterator();
                    while (iter.next()) |input| try map.put(allocator, input.key_ptr.*, switch (input.value_ptr.*) {
                        .string => |string| &.{string},
                        .array => try std.json.parseFromValueLeaky([]const []const u8, allocator, input.value_ptr.*, options),
                        else => return error.UnexpectedToken,
                    });

                    break :inputs std.json.ArrayHashMap([]const []const u8){ .map = map };
                } else null;
                const locked = if (source.object.get("locked")) |locked| try std.json.parseFromValueLeaky(Source, allocator, locked, options) else null;
                if (locked) |l| {
                    if (!l.immutable()) return error.MissingField;
                    std.debug.assert(l.valid());
                }
                const original = if (source.object.get("original")) |original| try std.json.parseFromValueLeaky(Source, allocator, original, options) else null;
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

pub const Config = struct {
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
    @"build-hook": Option([]const []const u8),
    @"build-poll-interval": Option(u16),
    @"build-users-group": Option([]const u8),
    builders: Option([]const u8),
    @"builders-use-substitutes": Option(bool),
    @"commit-lockfile-summary": Option([]const u8),
    @"compress-build-log": Option(bool),
    @"connect-timeout": Option(u16),
    cores: Option(u16),
    @"diff-hook": Option(?[]const u8),
    @"download-attempts": Option(u16),
    @"download-speed": Option(u32),
    @"eval-cache": Option(bool),
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
};

pub const FlakeMetadataOptions = struct {
    max_output_bytes: usize = 50 * 1024,
    refresh: bool = true,
    no_write_lock_file: bool = true,
};

pub const FlakePrefetchOptions = struct {
    max_output_bytes: usize = 50 * 1024,
    refresh: bool = true,
};

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
    pub fn fromErrorMessage(allocator: std.mem.Allocator, stderr: []const u8) !@This() {
        var builds = std.ArrayListUnmanaged([]const u8){};
        errdefer {
            for (builds.items) |drv| allocator.free(drv);
            builds.deinit(allocator);
        }

        var dependents = std.ArrayListUnmanaged([]const u8){};
        errdefer {
            for (dependents.items) |drv| allocator.free(drv);
            dependents.deinit(allocator);
        }

        var iter = std.mem.splitScalar(u8, stderr, '\n');
        while (iter.next()) |line| {
            const readExpected = struct {
                fn call(reader: anytype, comptime slice: []const u8) !bool {
                    var buf: [slice.len]u8 = undefined;
                    const len = reader.readAll(&buf) catch |err|
                        return if (err == error.EndOfStream) false else err;
                    return std.mem.eql(u8, buf[0..len], slice);
                }
            }.call;

            builds: {
                var line_stream = std.io.fixedBufferStream(line);
                const line_reader = line_stream.reader();

                var drv_list = std.ArrayListUnmanaged(u8){};
                errdefer drv_list.deinit(allocator);

                try line_reader.skipUntilDelimiterOrEof('e'); // skip whitespace
                if (!try readExpected(line_reader, "rror: builder for '")) break :builds;
                line_reader.streamUntilDelimiter(drv_list.writer(allocator), '\'', null) catch break :builds;
                if (!try readExpected(line_reader, " failed")) break :builds;

                const drv = try drv_list.toOwnedSlice(allocator);
                errdefer allocator.free(drv);

                try builds.append(allocator, drv);
            }

            foreign_builds: {
                var line_stream = std.io.fixedBufferStream(line);
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

                try builds.append(allocator, drv);
            }

            dependents: {
                var line_stream = std.io.fixedBufferStream(line);
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

                try dependents.append(allocator, drv);
            }
        }

        return .{
            .builds = try builds.toOwnedSlice(allocator),
            .dependents = try dependents.toOwnedSlice(allocator),
        };
    }
};

pub const StoreInfo = struct {
    url: []const u8,
    version: ?std.SemanticVersion = null,
    trusted: bool = false,

    pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) std.json.ParseError(@TypeOf(source.*))!@This() {
        const inner = try std.json.innerParse(struct {
            url: []const u8,
            version: ?[]const u8 = null,
            trusted: ?u1 = null,
        }, allocator, source, options);

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

pub fn impl(
    comptime run_fn: anytype,
    comptime log_scope: ?@TypeOf(.enum_literal),
) type {
    const log_scoped = if (log_scope) |scope| std.log.scoped(scope) else std.log;

    return struct {
        pub fn version(allocator: std.mem.Allocator) (std.process.Child.RunError || error{ InvalidVersion, Overflow, UnknownNixVersion })!std.SemanticVersion {
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

        pub fn config(allocator: std.mem.Allocator, diagnostics: ?*ChildProcessDiagnostics) (std.process.Child.RunError || std.json.ParseError(std.json.Scanner) || error{CouldNotReadNixConfig})!std.json.Parsed(Config) {
            const result = try std.process.Child.run(.{
                .allocator = allocator,
                .max_output_bytes = 100 * 1024,
                .argv = &.{ "nix", "show-config", "--json" },
            });
            defer allocator.free(result.stdout);

            if (result.term != .Exited or result.term.Exited != 0) {
                if (diagnostics) |d| d.* = ChildProcessDiagnostics.fromRunResult(result);
                return error.CouldNotReadNixConfig;
            }
            allocator.free(result.stderr);

            return std.json.parseFromSlice(Config, allocator, result.stdout, .{
                .ignore_unknown_fields = true,
                .allocate = .alloc_always,
            });
        }

        pub fn flakeMetadata(
            allocator: std.mem.Allocator,
            flake: []const u8,
            opts: FlakeMetadataOptions,
            diagnostics: ?*ChildProcessDiagnostics,
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

            const result = try run_fn(.{
                .allocator = allocator,
                .max_output_bytes = opts.max_output_bytes,
                .argv = argv,
            });
            defer allocator.free(result.stdout);

            if (result.term != .Exited or result.term.Exited != 0) {
                log_scoped.debug("could not get flake metadata {s}: {}\n{s}", .{ flake, result.term, result.stderr });
                if (diagnostics) |d| d.* = ChildProcessDiagnostics.fromRunResult(result);
                return error.FlakeMetadataFailed; // TODO return more specific error
            }
            defer allocator.free(result.stderr);

            const json_options = .{ .ignore_unknown_fields = true };

            const json = try std.json.parseFromSlice(std.json.Value, allocator, result.stdout, json_options);
            defer json.deinit();

            return std.json.parseFromValue(FlakeMetadata, allocator, json.value, json_options);
        }

        /// This is faster than `flakeMetadata()` if you only need the contents of `flake.lock`.
        pub fn flakeMetadataLocks(
            allocator: std.mem.Allocator,
            flake: []const u8,
            opts: FlakePrefetchOptions,
            diagnostics: ?*ChildProcessDiagnostics,
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

            const result = try run_fn(.{
                .allocator = allocator,
                .max_output_bytes = opts.max_output_bytes,
                .argv = argv,
            });
            defer allocator.free(result.stdout);

            if (result.term != .Exited or result.term.Exited != 0) {
                log_scoped.debug("could not prefetch flake {s}: {}\n{s}", .{ flake, result.term, result.stderr });
                if (diagnostics) |d| d.* = ChildProcessDiagnostics.fromRunResult(result);
                return error.FlakePrefetchFailed; // TODO return more specific error
            }
            defer allocator.free(result.stderr);

            const json_options = .{ .ignore_unknown_fields = true };

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

        test "flakeMetadataLocks: cardano-db-sync/13.0.4" {
            // this test needs internet and spawns child processes
            if (true) return error.SkipZigTest;

            if (try flakeMetadataLocks(std.testing.allocator, "github:IntersectMBO/cardano-db-sync/13.0.4", .{ .refresh = false }, null)) |locks| locks.deinit();
        }

        pub fn lockFlakeRef(
            allocator: std.mem.Allocator,
            flake_ref: []const u8,
            opts: FlakeMetadataOptions,
            diagnostics: ?*ChildProcessDiagnostics,
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
            const expected = latest ++ "/057f9aecfb71c4437d2b27d3323df7f93c010b7e";

            {
                const locked = locked: {
                    var diagnostics: ChildProcessDiagnostics = undefined;
                    errdefer {
                        defer diagnostics.deinit(std.testing.allocator);
                        std.log.err("term: {}\nstderr: {s}", .{ diagnostics.term, diagnostics.stderr });
                    }
                    break :locked try lockFlakeRef(std.testing.allocator, input, .{}, &diagnostics);
                };
                defer std.testing.allocator.free(locked);

                try std.testing.expectEqualStrings(expected, locked);
            }

            {
                const locked = locked: {
                    var diagnostics: ChildProcessDiagnostics = undefined;
                    errdefer {
                        defer diagnostics.deinit(std.testing.allocator);
                        std.log.err("term: {}\nstderr: {s}", .{ diagnostics.term, diagnostics.stderr });
                    }
                    break :locked try lockFlakeRef(std.testing.allocator, input ++ "#hello^out", .{}, &diagnostics);
                };
                defer std.testing.allocator.free(locked);

                try std.testing.expectEqualStrings(expected ++ "#hello^out", locked);
            }
        }

        pub fn storeInfo(
            allocator: std.mem.Allocator,
            store: []const u8,
            diagnostics: ?*ChildProcessDiagnostics,
        ) (std.process.Child.RunError || std.json.ParseError(std.json.Scanner) || error{CouldNotPingNixStore})!std.json.Parsed(StoreInfo) {
            const result = try run_fn(.{
                .allocator = allocator,
                .argv = &.{ "nix", "store", "info", "--json", "--store", store },
            });
            defer allocator.free(result.stdout);

            if (result.term != .Exited or result.term.Exited != 0) {
                if (diagnostics) |d| d.* = ChildProcessDiagnostics.fromRunResult(result);
                return error.CouldNotPingNixStore;
            }
            allocator.free(result.stderr);

            return std.json.parseFromSlice(StoreInfo, allocator, result.stdout, .{
                .ignore_unknown_fields = true,
                .allocate = .alloc_always,
            });
        }
    };
}

pub usingnamespace impl(
    std.process.Child.run,
    null,
);
