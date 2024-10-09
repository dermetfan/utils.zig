//! Translated from nix' `src/build-remote/build-remote.cc`,
//! which is spawned by `src/libstore/build/derivation-goal.cc`
//! and fed mostly in `tryBuildHook()`.

const std = @import("std");

const log = @import("log.zig");
const wire = @import("wire.zig");

const debug = @import("../debug.zig");
const mem = @import("../mem.zig");

pub fn Connection(comptime Reader: type, comptime Writer: type, comptime WriterMutex: type) type {
    return struct {
        reader: Reader,
        writer: Writer,
        writer_mutex: WriterMutex,

        pub fn readDerivation(self: @This(), allocator: std.mem.Allocator) (wire.ReadError(Reader, true) || error{ UnexpectedPacket, BadBool })!Derivation {
            return (try Request.read(allocator, self.reader)).derivation;
        }

        /// The nix daemon will immediately kill the build hook after we decline
        /// the last derivation it offers us
        /// so make sure to clean up all resources before calling this function.
        pub fn decline(self: @This()) Writer.Error!void {
            self.writer_mutex.lock();
            defer self.writer_mutex.unlock();

            try @as(Response, .decline).write(self.writer);
        }

        /// The nix daemon will immediately kill the build hook after we decline permanently
        /// so make sure to clean up all resources before calling this function.
        ///
        /// This is because (if I interpret nix' code correctly)
        /// [`worker.hook = 0`](https://github.com/NixOS/nix/blob/5fe2accb754249df6cb8f840330abfcf3bd26695/src/libstore/build/derivation-goal.cc#L1160)
        /// invokes the [destructor](https://github.com/NixOS/nix/blob/5fe2accb754249df6cb8f840330abfcf3bd26695/src/libstore/build/hook-instance.cc#L82)
        /// which sends SIGKILL [by default](https://github.com/NixOS/nix/blob/5fe2accb754249df6cb8f840330abfcf3bd26695/src/libutil/processes.cc#L54) (oof).
        pub fn declinePermanently(self: @This()) Writer.Error!noreturn {
            {
                self.writer_mutex.lock();
                defer self.writer_mutex.unlock();

                try @as(Response, .decline_permanently).write(self.writer);
            }

            // Make sure we don't return in case the nix daemon
            // does not send SIGKILL fast enough.
            var event = std.Thread.ResetEvent{};
            event.wait();
        }

        pub fn postpone(self: @This()) Writer.Error!void {
            self.writer_mutex.lock();
            defer self.writer_mutex.unlock();

            try @as(Response, .postpone).write(self.writer);
        }

        /// The nix daemon will close stdin and wait for EOF from the build hook.
        /// Therefore we can only accept once.
        /// The nix daemon will start another instance of the build hook for the remaining derivations.
        ///
        /// The given store URI is displayed to the user but does not otherwise matter.
        pub fn accept(self: *@This(), allocator: std.mem.Allocator, store_uri: []const u8) (wire.ReadError(Reader, true) || Writer.Error || error{BadBool})!BuildIo {
            {
                self.writer_mutex.lock();
                defer self.writer_mutex.unlock();

                try (Response{ .accept = store_uri }).write(self.writer);
            }
            defer self.* = undefined;

            return wire.readStruct(BuildIo, allocator, self.reader);
        }
    };
}

/// Returns the nix config and a connection.
pub fn start(allocator: std.mem.Allocator) (wire.ReadError(std.fs.File.Reader, true) || std.fs.File.Writer.Error || error{ UnexpectPacket, BadBool })!struct { std.BufMap, Connection(std.fs.File.Reader, std.fs.File.Writer, *debug.StderrMutex) } {
    return startAdvanced(
        allocator,
        std.io.getStdIn().reader(),
        std.io.getStdErr().writer(),
        debug.getStderrMutex(),
    );
}

pub fn startAdvanced(
    allocator: std.mem.Allocator,
    reader: anytype,
    writer: anytype,
    writer_mutex: anytype,
) (wire.ReadError(@TypeOf(reader), true) || @TypeOf(writer).Error || error{ UnexpectPacket, BadBool })!struct { std.BufMap, Connection(@TypeOf(reader), @TypeOf(writer), @TypeOf(writer_mutex)) } {
    return .{
        try wire.readStringStringMap(allocator, reader),
        .{
            .reader = reader,
            .writer = writer,
            .writer_mutex = writer_mutex,
        },
    };
}

pub fn parseArgs(args: *std.process.ArgIterator) !log.Action.Verbosity {
    var last_arg: ?[]const u8 = null;
    while (args.next()) |arg| last_arg = arg;

    return if (std.fmt.parseUnsigned(std.meta.Tag(log.Action.Verbosity), last_arg orelse return error.BadProcessArguments, 10)) |int|
        @enumFromInt(int)
    else |err| switch (err) {
        error.Overflow => .vomit,
        else => err,
    };
}

pub const Derivation = struct {
    am_willing: bool,
    needed_system: []const u8,
    drv_path: []const u8,
    required_features: []const []const u8,

    pub fn deinit(self: @This(), allocator: std.mem.Allocator) void {
        allocator.free(self.needed_system);

        allocator.free(self.drv_path);

        for (self.required_features) |feature| allocator.free(feature);
        allocator.free(self.required_features);
    }
};

pub const BuildIo = struct {
    inputs: []const []const u8,
    wanted_outputs: []const []const u8,

    pub fn deinit(self: @This(), allocator: std.mem.Allocator) void {
        for (self.inputs) |input| allocator.free(input);
        allocator.free(self.inputs);

        for (self.wanted_outputs) |output| allocator.free(output);
        allocator.free(self.wanted_outputs);
    }
};

pub const Initialization = struct {
    nix_config: std.BufMap,

    pub fn read(allocator: std.mem.Allocator, reader: anytype) @TypeOf(reader).NoEofError!@This() {
        return .{ .nix_config = try wire.readStringStringMap(allocator, reader) };
    }

    pub fn write(self: @This(), writer: anytype) @TypeOf(writer).Error!void {
        try wire.writeStringStringMap(writer, self.nix_config.hash_map.unmanaged);
    }
};

pub const Request = struct {
    derivation: Derivation,

    pub fn read(allocator: std.mem.Allocator, reader: anytype) (wire.ReadError(@TypeOf(reader), true) || error{ UnexpectedPacket, BadBool })!@This() {
        try wire.expectPacket("try", reader);
        return .{ .derivation = try wire.readStruct(Derivation, allocator, reader) };
    }

    pub fn write(self: @This(), writer: anytype) (@TypeOf(writer).Error || error{BadBool})!void {
        try wire.writePacket(writer, "try");
        try wire.writeStruct(Derivation, writer, self.derivation);
    }
};

pub const Response = union((enum {
    decline,
    decline_permanently,
    postpone,
    accept,

    /// the first line (without the trailing newline)
    pub fn head(self: @This()) []const u8 {
        return switch (self) {
            .decline_permanently => "# decline-permanently",
            inline else => |v| "# " ++ @tagName(v),
        };
    }

    pub fn maxHeadLen() usize {
        var largest_head: ?[]const u8 = null;
        for (std.enums.values(@This())) |tag| {
            if (largest_head) |lh|
                if (lh.len >= tag.head().len) continue;
            largest_head = tag.head();
        }
        return largest_head.?.len;
    }
})) {
    decline,
    decline_permanently,
    postpone,
    /// the store that the the derivation will be built in
    accept: []const u8,

    pub const Tag = std.meta.Tag(@This());

    pub fn deinit(self: @This(), allocator: std.mem.Allocator) void {
        switch (self) {
            .accept => |store| allocator.free(store),
            else => {},
        }
    }

    pub fn read(allocator: std.mem.Allocator, reader: anytype) (@TypeOf(reader).NoEofError || std.mem.Allocator.Error || error{ BadResponse, NoSpaceLeft, StreamTooLong })!@This() {
        return switch (tag: {
            var head_buf: [Tag.maxHeadLen()]u8 = undefined;
            var head_stream = std.io.fixedBufferStream(&head_buf);

            try reader.streamUntilDelimiter(head_stream.writer(), '\n', head_buf.len + 1);

            for (std.enums.values(Tag)) |tag| {
                if (std.mem.eql(u8, head_stream.getWritten(), tag.head())) break :tag tag;
            } else return error.BadResponse;
        }) {
            .accept => store: {
                var store = try std.ArrayList(u8).initCapacity(
                    allocator,
                    // Somewhat arbitrary, should fit all stores encountered in practice.
                    2 * mem.b_per_kib,
                );
                errdefer store.deinit();

                try reader.streamUntilDelimiter(store.writer(), '\n', store.capacity);

                break :store .{ .accept = try store.toOwnedSlice() };
            },
            inline else => |tag| tag,
        };
    }

    test read {
        const allocator = std.testing.allocator;

        {
            var stream = std.io.fixedBufferStream(comptime Tag.decline.head() ++ "\n");
            try std.testing.expectEqual(.decline, try read(allocator, stream.reader()));
        }

        {
            var stream = std.io.fixedBufferStream(comptime Tag.accept.head() ++ "\ndummy://\n");
            const response = try read(allocator, stream.reader());
            defer response.deinit(allocator);
            try std.testing.expectEqualDeep(@This(){ .accept = "dummy://" }, response);
        }
    }

    pub fn write(self: @This(), writer: anytype) @TypeOf(writer).Error!void {
        try writer.writeAll(std.meta.activeTag(self).head());
        try writer.writeByte('\n');

        switch (self) {
            .accept => |store| {
                try writer.writeAll(store);
                try writer.writeByte('\n');
            },
            else => {},
        }
    }
};
