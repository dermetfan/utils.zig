const root = @import("root");
const std = @import("std");

// const otlp = @import("../otlp.zig").trace;

/// > Tracers are identified by `name`, `version`, and `schema_url` fields.
/// https://opentelemetry.io/docs/specs/otel/trace/api/#get-a-tracer
pub const TracerId = struct {
    name: []const u8,
    version: ?std.SemanticVersion = null,
    schema_url: ?std.Uri = null,
};

pub fn GenericTracerProvider(comptime Context: type) type {
    return struct {
        context: Context,

        pub const Tracer = Context.Tracer;

        pub fn tracer(self: @This(), id: TracerId) Tracer {
            return self.context.tracer(id);
        }
    };
}

pub fn GenericTracer(comptime Context: type) type {
    return struct {
        context: Context,

        pub fn span(
            self: @This(),
            name: []const u8,
            options: SpanCreationOptions,
        ) Span {
            return self.context.span(name, options);
        }

        pub fn enabled(self: @This()) bool {
            return self.context.enabled();
        }
    };
}

pub const SpanCreationOptions = struct {
    parent: ?Span.Context = null,
    kind: Span.Kind = .internal,
    // TODO attributes
    // TODO links
    start: ?i128 = null,
};

pub const NoopTracerProvider = GenericTracerProvider(struct {
    pub const Tracer = NoopTracer;

    pub fn tracer(_: @This(), _: TracerId) NoopTracer {
        return .{ .context = .{} };
    }
});

pub const NoopTracer = GenericTracer(struct {
    pub fn span(
        _: @This(),
        name: []const u8,
        options: SpanCreationOptions,
    ) Span {
        return .{
            .name = name,
            .context = .{
                .trace_id = [_]u8{0} ** 16,
                .span_id = [_]u8{0} ** 8,
                .trace_flags = std.EnumSet(TraceFlag).initEmpty(),
            },
            .parent = options.parent,
            .kind = options.kind,
            .start = options.start orelse 0,
        };
    }

    pub fn enabled(_: @This()) bool {
        return false;
    }
});

pub const Span = struct {
    name: []const u8,
    context: Context,
    parent: ?Context = null,
    kind: Kind = .internal,
    start: i128,
    end: ?i128 = null,
    // TODO attributes
    // TODO links
    // TODO events
    /// Do not set manually, use `update()` instead.
    status: Status = .unset,

    pub const Context = struct {
        trace_id: TraceId,
        span_id: SpanId,
        trace_flags: std.EnumSet(TraceFlag) = std.EnumSet(TraceFlag).initOne(.sampled),
        trace_state: TraceState = .{},
        is_remote: bool = false,
    };

    pub const Kind = enum {
        internal,
        client,
        server,
        consumer,
        producer,
    };

    pub const Status = union(enum) {
        unset,
        @"error": []const u8,
        ok,

        pub fn update(self: *@This(), new: @This()) void {
            if (@intFromEnum(self.*) < @intFromEnum(new))
                self.* = new;
        }

        test update {
            var status: @This() = .unset;
            status.update(.ok);
            try std.testing.expectEqual(@This().unset, status);
        }
    };
};

pub const TraceId = [16]u8;

pub fn isValidTraceId(trace_id: TraceId) bool {
    return !std.mem.allEqual(u8, &trace_id, 0);
}

pub const SpanId = [8]u8;

pub fn isValidSpanId(span_id: SpanId) bool {
    return !std.mem.allEqual(u8, &span_id, 0);
}

pub const TraceFlag = enum { sampled };

// TODO Should this copy keys and values to own them like `std.BufMap`?
pub const TraceState = struct {
    entries: std.ArrayHashMapUnmanaged(Key, []const u8, struct {
        pub fn eql(_: @This(), a: Key, b: Key, _: usize) bool {
            if (std.meta.activeTag(a) != std.meta.activeTag(b))
                return false;

            return switch (a) {
                .simple => |s| std.mem.eql(u8, s, b.simple),
                .multi_tenant => |mt| std.mem.eql(u8, mt.tenant, b.multi_tenant.tenant) and
                    std.mem.eql(u8, mt.system, b.multi_tenant.system),
            };
        }

        pub fn hash(_: @This(), key: Key) u32 {
            var hasher = std.hash.Wyhash.init(0);
            hasher.update(@tagName(std.meta.activeTag(key)));
            switch (key) {
                .simple => |s| hasher.update(s),
                .multi_tenant => |mt| {
                    hasher.update(mt.tenant);
                    hasher.update("@");
                    hasher.update(mt.system);
                },
            }
            return @truncate(hasher.final());
        }
    }, false) = .{},

    // https://opentelemetry.io/docs/specs/otel/trace/tracestate-handling/#key
    otel_entries: std.AutoArrayHashMapUnmanaged(OtelKey, []const u8) = .{},

    pub const ValidityError = error{
        InvalidTraceStateKey,
        InvalidTraceStateValue,
    };

    pub const OtelValidityError = error{
        InvalidTraceStateOtelValue,
    };

    pub const Key = union(enum) {
        simple: []const u8,
        multi_tenant: struct {
            tenant: []const u8,
            system: []const u8,
        },

        fn validate(self: @This()) error{InvalidTraceStateKey}!void {
            if (switch (self) {
                .simple => |key| key.len > 256 or
                    !isValidPart(key),
                .multi_tenant => |multi_tenant| multi_tenant.tenant.len > 241 or
                    multi_tenant.system.len > 14 or
                    !isValidPart(multi_tenant.tenant) or
                    !isValidPart(multi_tenant.system),
            })
                return error.InvalidTraceStateKey;
        }

        fn isValidPart(chars: []const u8) bool {
            for (chars) |char|
                switch (char) {
                    '_', '-', '*', '/' => continue,
                    else => |c| if (!std.ascii.isLower(c) or !std.ascii.isDigit(c))
                        return false,
                };
            return true;
        }
    };

    pub const OtelKey = enum {
        // TODO remove this. Where are the valid keys specified?
        // https://opentelemetry.io/docs/specs/otel/trace/tracestate-handling/#key
        testing0,

        comptime {
            for (std.enums.values(@This())) |value|
                for (@tagName(value)) |char|
                    std.debug.assert(std.ascii.isLower(char) or std.ascii.isDigit(char));
        }
    };

    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        self.entries.deinit(allocator);
        self.otel_entries.deinit(allocator);
        self.* = undefined;
    }

    fn validateValue(value: []const u8) error{InvalidTraceStateValue}!void {
        if (value.len > 256)
            return error.InvalidTraceStateValue;

        for (value) |char|
            switch (char) {
                ',', '=' => continue,
                else => |c| if (!std.ascii.isPrint(c))
                    return error.InvalidTraceStateValue,
            };
    }

    fn validateOtelValue(value: []const u8) OtelValidityError!void {
        for (value) |char|
            if (switch (char) {
                '.', '_', '-' => continue,
                else => |c| !std.ascii.isAlphanumeric(c),
            })
                return error.InvalidTraceStateOtelValue;
    }

    pub fn put(self: *@This(), allocator: std.mem.Allocator, key: Key, value: []const u8) (ValidityError || std.mem.Allocator.Error)!void {
        try key.validate();
        try validateValue(value);

        if (std.debug.runtime_safety) std.debug.assert(!std.mem.eql(u8, "ot", switch (key) {
            .simple => |s| s,
            .multi_tenant => |mt| mt.system,
        }));

        try self.entries.put(allocator, key, value);
    }

    pub fn putOtel(self: *@This(), allocator: std.mem.Allocator, key: OtelKey, value: []const u8) (OtelValidityError || std.mem.Allocator.Error)!void {
        try validateOtelValue(value);

        try self.otel_entries.put(allocator, key, value);
    }

    pub fn toString(self: @This(), allocator: std.mem.Allocator) std.mem.Allocator.Error![]const u8 {
        var str = std.ArrayListUnmanaged(u8){};

        try toStringImpl(allocator, &str, self.entries, ",", "=");

        if (self.otel_entries.count() != 0) {
            if (self.entries.count() != 0)
                try str.append(allocator, ',');

            try str.appendSlice(allocator, "ot=");
            try toStringImpl(allocator, &str, self.otel_entries, ",", "=");
        }

        return str.toOwnedSlice(allocator);
    }

    fn toStringImpl(
        allocator: std.mem.Allocator,
        str: *std.ArrayListUnmanaged(u8),
        map: anytype,
        separator: []const u8,
        assignment: []const u8,
    ) std.mem.Allocator.Error!void {
        const entries_slice = map.entries.slice();
        for (entries_slice.items(.key), entries_slice.items(.value), 0..) |key, value, i| {
            try str.ensureUnusedCapacity(
                allocator,
                (if (i != 0) separator.len else 0) +
                    switch (@TypeOf(key)) {
                    Key => switch (key) {
                        .simple => |s| s.len,
                        .multi_tenant => |mt| mt.tenant.len + "@".len + mt.system.len,
                    },
                    OtelKey => @tagName(key).len,
                    else => comptime unreachable,
                } +
                    assignment.len +
                    value.len,
            );
            if (i != 0) str.appendSliceAssumeCapacity(separator);
            switch (@TypeOf(key)) {
                Key => switch (key) {
                    .simple => |s| str.appendSliceAssumeCapacity(s),
                    .multi_tenant => |mt| {
                        str.appendSliceAssumeCapacity(mt.tenant);
                        str.appendAssumeCapacity('@');
                        str.appendSliceAssumeCapacity(mt.system);
                    },
                },
                OtelKey => str.appendSliceAssumeCapacity(@tagName(key)),
                else => comptime unreachable,
            }
            str.appendSliceAssumeCapacity(assignment);
            str.appendSliceAssumeCapacity(value);
        }
    }

    test toString {
        const allocator = std.testing.allocator;

        var trace_state = TraceState{};
        defer trace_state.deinit(allocator);

        try trace_state.put(allocator, .{ .simple = "simple" }, "simple");
        try trace_state.put(allocator, .{
            .multi_tenant = .{
                .tenant = "tenant",
                .system = "system",
            },
        }, "multi_tenant");
        try trace_state.putOtel(allocator, .testing0, "testing");

        const str = try trace_state.toString(allocator);
        defer allocator.free(str);

        try std.testing.expectEqualStrings("simple1=simple1,tenant@system=multi_tenant,ot=testing0:testing", str);
    }
};
