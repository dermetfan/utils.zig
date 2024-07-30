const std = @import("std");

const stderr = std.io.getStdErr().writer();

pub fn logFn(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    const prefix =
        "[" ++ comptime level.asText() ++ "] " ++
        if (scope != .default) "(" ++ @tagName(scope) ++ ") " else "";

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit() == .leak) std.debug.panic("could not log memory leak after logging\n", .{});

    var sfa = std.heap.stackFallback(format.len + @sizeOf(@TypeOf(args)), gpa.allocator());
    const allocator = sfa.get();

    const verbosity = switch (level) {
        .err => .@"error",
        .warn => .warn,
        .info => .info,
        .debug => .debug,
    };

    logMsg(allocator, verbosity, prefix ++ format, args) catch |err|
        std.debug.panic("could not log: {}", .{err});
}

// Translated from `src/libutil/logging.hh`.
pub const Action = union(enum) {
    msg: struct {
        level: Verbosity,
        msg: []const u8,
    },
    error_info: struct {
        level: Verbosity,
        msg: []const u8,
        raw_msg: []const u8,
    },
    start_activity: struct {
        id: ActivityId,
        level: Verbosity,
        type: ActivityType,
        text: []const u8,
        parent: ActivityId,
        fields: []const Field,
    },
    stop_activity: ActivityId,
    result: struct {
        id: ActivityId,
        type: ResultType,
        fields: []const Field,
    },

    pub const Verbosity = enum {
        @"error",
        warn,
        notice,
        info,
        talkative,
        chatty,
        debug,
        vomit,

        pub fn jsonStringify(self: @This(), write_stream: anytype) !void {
            try write_stream.write(@intFromEnum(self));
        }
    };

    pub const Field = union(enum) {
        int: u64,
        string: []const u8,

        pub fn jsonStringify(self: @This(), write_stream: anytype) !void {
            switch (self) {
                inline else => |value| try write_stream.write(value),
            }
        }
    };

    pub const ActivityId = u64;

    pub const ActivityType = enum(std.math.IntFittingRange(0, 111)) {
        unknown = 0,
        copy_path = 100,
        file_transfer = 101,
        realise = 102,
        copy_paths = 103,
        builds = 104,
        build = 105,
        optimise_store = 106,
        verify_paths = 107,
        substitute = 108,
        query_path_info = 109,
        post_build_hook = 110,
        build_waiting = 111,

        pub fn jsonStringify(self: @This(), write_stream: anytype) !void {
            try write_stream.write(@intFromEnum(self));
        }
    };

    pub const ResultType = enum(std.math.IntFittingRange(0, 107)) {
        file_linked = 100,
        build_log_line = 101,
        untrusted_path = 102,
        corrupted_path = 103,
        set_phase = 104,
        progress = 105,
        set_expected = 106,
        post_build_log_line = 107,

        pub fn jsonStringify(self: @This(), write_stream: anytype) !void {
            try write_stream.write(@intFromEnum(self));
        }
    };

    pub fn jsonStringify(self: @This(), write_stream: anytype) !void {
        try write_stream.beginObject();

        try write_stream.objectField("action");
        try write_stream.write(switch (self) {
            .msg, .error_info => "msg",
            .start_activity => "start",
            .stop_activity => "stop",
            .result => "result",
        });

        switch (self) {
            .stop_activity => |id| {
                try write_stream.objectField("id");
                try write_stream.write(id);
            },
            inline else => |action| inline for (@typeInfo(@TypeOf(action)).Struct.fields) |field| {
                try write_stream.objectField(field.name);
                try write_stream.write(@field(action, field.name));
            },
        }

        try write_stream.endObject();
    }

    fn logTo(self: @This(), writer: anytype) !void {
        try writer.writeAll("@nix ");
        try std.json.stringify(self, .{}, writer);
        try writer.writeByte('\n');
    }

    pub fn log(self: @This()) !void {
        const stderr_mutex = std.debug.getStderrMutex();
        stderr_mutex.lock();
        defer stderr_mutex.unlock();

        try self.logTo(stderr);
    }
};

fn logMsgTo(allocator: std.mem.Allocator, level: Action.Verbosity, comptime fmt: []const u8, args: anytype, writer: anytype) !void {
    const message = try std.fmt.allocPrint(allocator, fmt, args);
    defer allocator.free(message);

    try (Action{ .msg = .{
        .level = level,
        .msg = message,
    } }).logTo(writer);
}

pub fn logMsg(allocator: std.mem.Allocator, level: Action.Verbosity, comptime fmt: []const u8, args: anytype) !void {
    try logMsgTo(allocator, level, fmt, args, stderr);
}

fn logErrorInfoTo(allocator: std.mem.Allocator, level: Action.Verbosity, err: anyerror, comptime fmt: []const u8, args: anytype, writer: anytype) !void {
    const msg = try std.fmt.allocPrint(allocator, fmt, args);
    defer allocator.free(msg);

    try (Action{ .error_info = .{
        .level = level,
        .msg = msg,
        .raw_msg = @errorName(err),
    } }).logTo(writer);
}

pub fn logErrorInfo(allocator: std.mem.Allocator, level: Action.Verbosity, err: anyerror, comptime fmt: []const u8, args: anytype) !void {
    try logErrorInfoTo(allocator, level, err, fmt, args, stderr);
}

test Action {
    const allocator = std.testing.allocator;

    var testing_stderr = std.ArrayList(u8).init(allocator);
    defer testing_stderr.deinit();
    const testing_stderr_writer = testing_stderr.writer();

    try logMsgTo(allocator, .info, "log {d}", .{1}, testing_stderr_writer);
    try std.testing.expectEqualStrings(
        \\@nix {"action":"msg","level":3,"msg":"log 1"}
        \\
    , testing_stderr.items);
    testing_stderr.clearRetainingCapacity();

    try logErrorInfoTo(allocator, .info, error.Foobar, "error_info {d}", .{1}, testing_stderr_writer);
    try std.testing.expectEqualStrings(
        \\@nix {"action":"msg","level":3,"msg":"error_info 1","raw_msg":"Foobar"}
        \\
    , testing_stderr.items);
    testing_stderr.clearRetainingCapacity();

    try (Action{ .start_activity = .{
        .id = 1,
        .level = .info,
        .type = .optimise_store,
        .text = "start_activity",
        .parent = 0,
        .fields = &.{
            .{ .int = 4 },
            .{ .string = "str" },
        },
    } }).logTo(testing_stderr_writer);
    try std.testing.expectEqualStrings(
        \\@nix {"action":"start","id":1,"level":3,"type":106,"text":"start_activity","parent":0,"fields":[4,"str"]}
        \\
    , testing_stderr.items);
    testing_stderr.clearRetainingCapacity();

    try (Action{ .stop_activity = 1 }).logTo(testing_stderr_writer);
    try std.testing.expectEqualStrings(
        \\@nix {"action":"stop","id":1}
        \\
    , testing_stderr.items);
    testing_stderr.clearRetainingCapacity();

    try (Action{ .result = .{
        .id = 1,
        .type = .progress,
        .fields = &.{
            .{ .int = 4 },
            .{ .string = "str" },
        },
    } }).logTo(testing_stderr_writer);
    try std.testing.expectEqualStrings(
        \\@nix {"action":"result","id":1,"type":105,"fields":[4,"str"]}
        \\
    , testing_stderr.items);
    testing_stderr.clearRetainingCapacity();
}
