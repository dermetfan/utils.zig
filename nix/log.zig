const std = @import("std");

const stderr = std.io.getStdErr().writer();
const stderr_mutex = std.debug.getStderrMutex();

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

    fn logTo(self: @This(), writer: anytype, writer_mutex: *std.Thread.Mutex) !void {
        var buffered_writer = std.io.bufferedWriter(writer);
        const buf_writer = buffered_writer.writer();

        writer_mutex.lock();
        defer writer_mutex.unlock();

        nosuspend {
            try buf_writer.writeAll(prefix);
            try std.json.stringify(self, .{}, buf_writer);
            try buf_writer.writeByte('\n');

            try buffered_writer.flush();
        }
    }

    pub fn log(self: @This()) !void {
        try self.logTo(stderr, stderr_mutex);
    }
};

fn logMsgTo(allocator: std.mem.Allocator, level: Action.Verbosity, comptime fmt: []const u8, args: anytype, writer: anytype, writer_mutex: *std.Thread.Mutex) !void {
    const message = try std.fmt.allocPrint(allocator, fmt, args);
    defer allocator.free(message);

    try (Action{ .msg = .{
        .level = level,
        .msg = message,
    } }).logTo(writer, writer_mutex);
}

pub fn logMsg(allocator: std.mem.Allocator, level: Action.Verbosity, comptime fmt: []const u8, args: anytype) !void {
    try logMsgTo(allocator, level, fmt, args, stderr, stderr_mutex);
}

fn logErrorInfoTo(allocator: std.mem.Allocator, level: Action.Verbosity, err: anyerror, comptime fmt: []const u8, args: anytype, writer: anytype, writer_mutex: anytype) !void {
    const msg = try std.fmt.allocPrint(allocator, fmt, args);
    defer allocator.free(msg);

    try (Action{ .error_info = .{
        .level = level,
        .msg = msg,
        .raw_msg = @errorName(err),
    } }).logTo(writer, writer_mutex);
}

pub fn logErrorInfo(allocator: std.mem.Allocator, level: Action.Verbosity, err: anyerror, comptime fmt: []const u8, args: anytype) !void {
    try logErrorInfoTo(allocator, level, err, fmt, args, stderr, stderr_mutex);
}

test Action {
    const allocator = std.testing.allocator;

    var testing_stderr = std.ArrayList(u8).init(allocator);
    defer testing_stderr.deinit();
    const testing_stderr_writer = testing_stderr.writer();
    var testing_stderr_mutex = std.Thread.Mutex{};

    try logMsgTo(allocator, .info, "log {d}", .{1}, testing_stderr_writer, &testing_stderr_mutex);
    try std.testing.expectEqualStrings(prefix ++
        \\{"action":"msg","level":3,"msg":"log 1"}
        \\
    , testing_stderr.items);
    testing_stderr.clearRetainingCapacity();

    try logErrorInfoTo(allocator, .info, error.Foobar, "error_info {d}", .{1}, testing_stderr_writer, &testing_stderr_mutex);
    try std.testing.expectEqualStrings(prefix ++
        \\{"action":"msg","level":3,"msg":"error_info 1","raw_msg":"Foobar"}
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
    } }).logTo(testing_stderr_writer, &testing_stderr_mutex);
    try std.testing.expectEqualStrings(prefix ++
        \\{"action":"start","id":1,"level":3,"type":106,"text":"start_activity","parent":0,"fields":[4,"str"]}
        \\
    , testing_stderr.items);
    testing_stderr.clearRetainingCapacity();

    try (Action{ .stop_activity = 1 }).logTo(testing_stderr_writer, &testing_stderr_mutex);
    try std.testing.expectEqualStrings(prefix ++
        \\{"action":"stop","id":1}
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
    } }).logTo(testing_stderr_writer, &testing_stderr_mutex);
    try std.testing.expectEqualStrings(prefix ++
        \\{"action":"result","id":1,"type":105,"fields":[4,"str"]}
        \\
    , testing_stderr.items);
    testing_stderr.clearRetainingCapacity();
}

/// Writes bytes that are not part of Nix' `--log-format internal-json` to `DiscardWriter`.
pub fn LogStream(comptime InnerReader: type, comptime DiscardWriter: type) type {
    return struct {
        inner_reader: InnerReader,
        discard_writer: DiscardWriter,
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

        const PrefixIndex = std.math.IntFittingRange(0, prefix.len - 1);

        pub const Error = InnerReader.NoEofError || DiscardWriter.Error;
        pub const Reader = std.io.Reader(*@This(), Error, read);

        pub fn read(self: *@This(), buf: []u8) Error!usize {
            var buf_idx: usize = 0;
            while (buf_idx < buf.len) {
                switch (self.state) {
                    .unknown => |prefix_idx| {
                        const byte = self.inner_reader.readByte() catch |err|
                            if (err == error.EndOfStream) break else return err;

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
                    },
                    .prefix => |prefix_idx| {
                        buf[buf_idx] = prefix[prefix_idx];
                        buf_idx += 1;

                        self.state = if (prefix_idx == prefix.len - 1)
                            .inside
                        else
                            .{ .prefix = prefix_idx + 1 };
                    },
                    .inside => {
                        const byte = self.inner_reader.readByte() catch |err|
                            if (err == error.EndOfStream) break else return err;

                        buf[buf_idx] = byte;
                        buf_idx += 1;

                        if (byte == '\n') self.state = .{ .unknown = 0 };
                    },
                    .outside => {
                        const byte = self.inner_reader.readByte() catch |err|
                            if (err == error.EndOfStream) break else return err;

                        try self.discard_writer.writeByte(byte);

                        if (byte == '\n') self.state = .{ .unknown = 0 };
                    },
                }
            }
            return buf_idx;
        }

        pub fn reader(self: *@This()) Reader {
            return .{ .context = self };
        }
    };
}

test LogStream {
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
    var input_stream = std.io.fixedBufferStream(input_buf);

    var discard_buf: [input_buf.len]u8 = undefined;
    var discard_stream = std.io.fixedBufferStream(&discard_buf);

    var log_stream = logStream(input_stream.reader(), discard_stream.writer());

    const logs = (try log_stream.reader().readBoundedBytes(input_buf.len)).constSlice();

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
    , discard_stream.getWritten());
}

pub fn logStream(inner_reader: anytype, discard_writer: anytype) LogStream(@TypeOf(inner_reader), @TypeOf(discard_writer)) {
    return .{ .inner_reader = inner_reader, .discard_writer = discard_writer };
}
