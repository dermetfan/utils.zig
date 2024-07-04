const std = @import("std");

const meta = @import("meta.zig");

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

pub const FlakeMetadataOptions = struct {
    max_output_bytes: usize = 50 * 1024,
    refresh: bool = true,
    no_write_lock_file: bool = true,
};

pub const FlakePrefetchOptions = struct {
    max_output_bytes: usize = 50 * 1024,
    refresh: bool = true,
};

pub fn impl(
    comptime run_fn: anytype,
    comptime log_scope: ?@TypeOf(.enum_literal),
) type {
    const log = if (log_scope) |scope| std.log.scoped(scope) else std.log;

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
                log.warn("could not get nix version:\nstdout: {s}\nstderr: {s}", .{ result.stdout, result.stderr });
                return error.UnknownNixVersion;
            }

            return std.SemanticVersion.parse(result.stdout);
        }

        pub fn flakeMetadata(
            allocator: std.mem.Allocator,
            flake: []const u8,
            opts: FlakeMetadataOptions,
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
            defer {
                allocator.free(result.stdout);
                allocator.free(result.stderr);
            }

            if (result.term != .Exited or result.term.Exited != 0) {
                log.debug("could not get flake metadata {s}: {}\n{s}", .{ flake, result.term, result.stderr });
                return error.FlakeMetadataFailed; // TODO return more specific error
            }

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
            defer {
                allocator.free(result.stdout);
                allocator.free(result.stderr);
            }

            if (result.term != .Exited or result.term.Exited != 0) {
                log.debug("could not prefetch flake {s}: {}\n{s}", .{ flake, result.term, result.stderr });
                return error.FlakePrefetchFailed; // TODO return more specific error
            }

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

            if (try flakeMetadataLocks(std.testing.allocator, "github:IntersectMBO/cardano-db-sync/13.0.4", .{ .refresh = false })) |locks| locks.deinit();
        }

        pub fn lockFlakeRef(allocator: std.mem.Allocator, flake_ref: []const u8, opts: FlakeMetadataOptions) ![]const u8 {
            const flake = std.mem.sliceTo(flake_ref, '#');

            const metadata = try flakeMetadata(allocator, flake, opts);
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
                const locked = try lockFlakeRef(std.testing.allocator, input, .{});
                defer std.testing.allocator.free(locked);

                try std.testing.expectEqualStrings(expected, locked);
            }

            {
                const locked = try lockFlakeRef(std.testing.allocator, input ++ "#hello^out", .{});
                defer std.testing.allocator.free(locked);

                try std.testing.expectEqualStrings(expected ++ "#hello^out", locked);
            }
        }
    };
}

pub usingnamespace impl(
    std.process.Child.run,
    null,
);
