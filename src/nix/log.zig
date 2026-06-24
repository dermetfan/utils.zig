const std = @import("std");

const debug = @import("../debug.zig");

const stderr = std.io.getStdErr().writer();
const stderr_mutex = debug.getStderrMutex();

const prefix = "@nix ";

pub fn logFn(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    const meta =
        comptime level.asText() ++
        (if (scope != .default) "(" ++ @tagName(scope) ++ ")" else "") ++
        ": ";

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

    logMsg(allocator, verbosity, meta ++ format, args) catch |err|
        std.debug.panic("{s}: could not log", .{@errorName(err)});
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

        /// See `comptimeCli()`.
        pub fn cli(self: @This(), shorthands: bool) []const []const u8 {
            return self.comptimeCli(shorthands, .{}, .{});
        }

        /// Returns the command line flags to pass to nix
        /// to make its log verbosity match.
        pub fn comptimeCli(
            self: @This(),
            /// Use combined flag shorthands if possible.
            shorthands: bool,
            /// Prepend this at comptime.
            head: anytype,
            /// Append this at comptime.
            tail: anytype,
        ) []const []const u8 {
            return switch (@intFromEnum(self)) {
                inline 0...2 => |n| &(head ++ .{"--quiet"} ** (2 - n) ++ tail),
                inline else => |n| if (shorthands)
                    &(head ++ .{"-" ++ "v" ** (n - 2)} ++ tail)
                else
                    &(head ++ .{"--verbose"} ** (n - 2) ++ tail),
            };
        }

        test comptimeCli {
            try std.testing.expectEqual(0, @This().notice.comptimeCli(false, .{}, .{}).len);
            try std.testing.expectEqualDeep(&[_][]const u8{ "head", "--quiet", "--quiet", "tail" }, @This().@"error".comptimeCli(true, .{"head"}, .{"tail"}));
            try std.testing.expectEqualDeep(&[_][]const u8{"--quiet"}, @This().warn.comptimeCli(false, .{}, .{}));
            try std.testing.expectEqualDeep(&[_][]const u8{ "--verbose", "--verbose" }, @This().talkative.comptimeCli(false, .{}, .{}));
            try std.testing.expectEqualDeep(&[_][]const u8{ "foo", "bar", "-vvv" }, @This().chatty.comptimeCli(true, .{ "foo", "bar" }, .{}));
        }

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
            inline else => |action| inline for (@typeInfo(@TypeOf(action)).@"struct".fields) |field| {
                try write_stream.objectField(field.name);
                try write_stream.write(@field(action, field.name));
            },
        }

        try write_stream.endObject();
    }

    fn logTo(self: @This(), io: std.Io, writer: *std.Io.Writer, writer_mutex: anytype) !void {
        try writer_mutex.lock(io);
        defer writer_mutex.unlock(io);

        nosuspend {
            try writer.writeAll(prefix);
            try writer.print("{f}", .{std.json.fmt(self, .{})});
            try writer.writeByte('\n');

            try writer.flush();
        }
    }

    pub fn log(self: @This()) !void {
        try self.logTo(stderr, stderr_mutex);
    }
};

fn logMsgTo(
    allocator: std.mem.Allocator,
    io: std.Io,
    level: Action.Verbosity,
    comptime fmt: []const u8,
    args: anytype,
    writer: *std.Io.Writer,
    writer_mutex: anytype,
) !void {
    const message = try std.fmt.allocPrint(allocator, fmt, args);
    defer allocator.free(message);

    try (Action{ .msg = .{
        .level = level,
        .msg = message,
    } }).logTo(io, writer, writer_mutex);
}

pub fn logMsg(
    allocator: std.mem.Allocator,
    io: std.Io,
    level: Action.Verbosity,
    comptime fmt: []const u8,
    args: anytype,
) !void {
    try logMsgTo(allocator, io, level, fmt, args, stderr, stderr_mutex);
}

fn logErrorInfoTo(
    allocator: std.mem.Allocator,
    io: std.Io,
    level: Action.Verbosity,
    err: anyerror,
    comptime fmt: []const u8,
    args: anytype,
    writer: *std.Io.Writer,
    writer_mutex: anytype,
) !void {
    const msg = try std.fmt.allocPrint(allocator, fmt, args);
    defer allocator.free(msg);

    try (Action{ .error_info = .{
        .level = level,
        .msg = msg,
        .raw_msg = @errorName(err),
    } }).logTo(io, writer, writer_mutex);
}

pub fn logErrorInfo(
    allocator: std.mem.Allocator,
    io: std.Io,
    level: Action.Verbosity,
    err: anyerror,
    comptime fmt: []const u8,
    args: anytype,
) !void {
    try logErrorInfoTo(allocator, io, level, err, fmt, args, stderr, stderr_mutex);
}

test Action {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var testing_stderr = std.Io.Writer.Allocating.init(allocator);
    defer testing_stderr.deinit();
    var testing_stderr_mutex = std.Io.Mutex.init;

    try logMsgTo(allocator, io, .info, "log {d}", .{1}, &testing_stderr.writer, &testing_stderr_mutex);
    try std.testing.expectEqualStrings(prefix ++
        \\{"action":"msg","level":3,"msg":"log 1"}
        \\
    , testing_stderr.written());
    testing_stderr.clearRetainingCapacity();

    try logErrorInfoTo(allocator, io, .info, error.Foobar, "error_info {d}", .{1}, &testing_stderr.writer, &testing_stderr_mutex);
    try std.testing.expectEqualStrings(prefix ++
        \\{"action":"msg","level":3,"msg":"error_info 1","raw_msg":"Foobar"}
        \\
    , testing_stderr.written());
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
    } }).logTo(io, &testing_stderr.writer, &testing_stderr_mutex);
    try std.testing.expectEqualStrings(prefix ++
        \\{"action":"start","id":1,"level":3,"type":106,"text":"start_activity","parent":0,"fields":[4,"str"]}
        \\
    , testing_stderr.written());
    testing_stderr.clearRetainingCapacity();

    try (Action{ .stop_activity = 1 }).logTo(io, &testing_stderr.writer, &testing_stderr_mutex);
    try std.testing.expectEqualStrings(prefix ++
        \\{"action":"stop","id":1}
        \\
    , testing_stderr.written());
    testing_stderr.clearRetainingCapacity();

    try (Action{ .result = .{
        .id = 1,
        .type = .progress,
        .fields = &.{
            .{ .int = 4 },
            .{ .string = "str" },
        },
    } }).logTo(io, &testing_stderr.writer, &testing_stderr_mutex);
    try std.testing.expectEqualStrings(prefix ++
        \\{"action":"result","id":1,"type":105,"fields":[4,"str"]}
        \\
    , testing_stderr.written());
    testing_stderr.clearRetainingCapacity();
}

/// Writes bytes that are not part of Nix' `--log-format internal-json` to `discard_writer`.
pub const LogReader = struct {
    inner_reader: *std.Io.Reader,
    discard_writer: *std.Io.Writer,
    state: union(enum) {
        /// The last byte read was a newline or part of the prefix.
        /// We are now expecting the byte at this index in the prefix.
        unknown: PrefixIndex,
        /// The prefix has been read and on the next read we will write
        /// this index in the prefix to the output buffer.
        prefix: PrefixIndex,
        /// The last byte read was part of a log message.
        inside,
        /// The last byte read was not part of a log message.
        outside,
    } = .{ .unknown = 0 },
    interface: std.Io.Reader,

    const PrefixIndex = std.math.IntFittingRange(0, prefix.len - 1);

    pub fn init(log_r: *std.Io.Reader, discard_w: *std.Io.Writer) @This() {
        return .{
            .inner_reader = log_r,
            .discard_writer = discard_w,
            .interface = .{
                .vtable = &.{ .stream = stream },
                .buffer = &.{},
                .seek = 0,
                .end = 0,
            },
        };
    }

    /// Returns the number of bytes written to `io_w`
    /// so in case of zero it could still have written to `discard_writer`.
    pub fn stream(io_r: *std.Io.Reader, io_w: *std.Io.Writer, _: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *@This() = @fieldParentPtr("interface", io_r);

        return switch (self.state) {
            .unknown => |prefix_idx| unknown: {
                const byte = try self.inner_reader.takeByte();

                if (prefix[prefix_idx] == byte) {
                    self.state = if (prefix_idx == prefix.len - 1)
                        .{ .prefix = 0 }
                    else
                        .{ .unknown = prefix_idx + 1 };
                } else {
                    try self.discard_writer.writeAll(prefix[0..prefix_idx]);
                    try self.discard_writer.writeByte(byte);

                    self.state = if (byte == '\n')
                        .{ .unknown = 0 }
                    else
                        .outside;
                }

                break :unknown 0;
            },
            .prefix => |prefix_idx| prefix: {
                try io_w.writeByte(prefix[prefix_idx]);

                self.state = if (prefix_idx == prefix.len - 1)
                    .inside
                else
                    .{ .prefix = prefix_idx + 1 };

                break :prefix 1;
            },
            .inside => inside: {
                const byte = try self.inner_reader.takeByte();

                try io_w.writeByte(byte);

                if (byte == '\n') self.state = .{ .unknown = 0 };

                break :inside 1;
            },
            .outside => outside: {
                const byte = try self.inner_reader.takeByte();

                try self.discard_writer.writeByte(byte);

                if (byte == '\n') self.state = .{ .unknown = 0 };

                break :outside 0;
            },
        };
    }
};

test LogReader {
    const input_buf =
        prefix ++
        \\{"foo": 1}
        \\# postpone
        \\# decline
        \\# decline-permanently
        \\
        ++ prefix ++
        \\{"foo": 2}
        \\# accept
        \\dummy://
        \\
        ;
    var input_r = std.Io.Reader.fixed(input_buf);

    var discard_buf: [input_buf.len]u8 = undefined;
    var discard_w = std.Io.Writer.Discarding.init(&discard_buf);

    var log_reader = LogReader.init(&input_r, &discard_w.writer);

    var logs_buf: [input_buf.len]u8 = undefined;
    const logs = logs_buf[0..try log_reader.interface.readSliceShort(&logs_buf)];

    try std.testing.expectEqualStrings(prefix ++
        \\{"foo": 1}
        \\
    ++ prefix ++
        \\{"foo": 2}
        \\
    , logs);

    try std.testing.expectEqualStrings(
        \\# postpone
        \\# decline
        \\# decline-permanently
        \\# accept
        \\dummy://
        \\
    , discard_w.writer.buffered());
}

test {
    std.testing.refAllDecls(@This());
}
