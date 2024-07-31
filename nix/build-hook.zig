//! Translated from nix' `src/build-remote/build-remote.cc`,
//! which is spawned by `src/libstore/build/derivation-goal.cc`
//! and fed mostly in `tryBuildHook()`.

const std = @import("std");

const log = @import("log.zig");
const wire = @import("wire.zig");

pub fn Connection(comptime Reader: type, comptime Writer: type) type {
    return struct {
        reader: Reader,
        writer: Writer,

        pub fn readDerivation(self: @This(), allocator: std.mem.Allocator) (wire.ReadError(Reader, true) || error{ UnexpectedPacket, BadBool })!Derivation {
            try wire.expectPacket("try", self.reader);
            return wire.readStruct(Derivation, allocator, self.reader);
        }

        /// The nix daemon will immediately kill the build hook after we decline
        /// the last derivation it offers us
        /// so make sure to clean up all resources before calling this function.
        pub fn decline(self: @This()) Writer.Error!void {
            try self.writer.print("# decline\n", .{});
        }

        /// The nix daemon will immediately kill the build hook after we decline permanently
        /// so make sure to clean up all resources before calling this function.
        ///
        /// This is because (if I interpret nix' code correctly)
        /// [`worker.hook = 0`](https://github.com/NixOS/nix/blob/5fe2accb754249df6cb8f840330abfcf3bd26695/src/libstore/build/derivation-goal.cc#L1160)
        /// invokes the [destructor](https://github.com/NixOS/nix/blob/5fe2accb754249df6cb8f840330abfcf3bd26695/src/libstore/build/hook-instance.cc#L82)
        /// which sends SIGKILL [by default](https://github.com/NixOS/nix/blob/5fe2accb754249df6cb8f840330abfcf3bd26695/src/libutil/processes.cc#L54) (oof).
        pub fn declinePermanently(self: @This()) Writer.Error!noreturn {
            try self.writer.print("# decline-permanently\n", .{});

            // Make sure we don't return in case the nix daemon
            // does not send SIGKILL fast enough.
            var event = std.Thread.ResetEvent{};
            event.wait();
        }

        pub fn postpone(self: @This()) Writer.Error!void {
            try self.writer.print("# postpone\n", .{});
        }

        /// The nix daemon will close stdin and wait for EOF from the build hook.
        /// Therefore we can only accept once.
        /// The nix daemon will start another instance of the build hook for the remaining derivations.
        ///
        /// The given store URI is displayed to the user but does not otherwise matter.
        pub fn accept(self: *@This(), allocator: std.mem.Allocator, store_uri: []const u8) (wire.ReadError(Reader, true) || Writer.Error || error{BadBool})!BuildIo {
            defer self.* = undefined;

            try self.writer.print("# accept\n{s}\n", .{store_uri});
            return wire.readStruct(BuildIo, allocator, self.reader);
        }
    };
}

/// Returns the nix config and a connection.
pub fn start(allocator: std.mem.Allocator) (wire.ReadError(std.fs.File.Reader, true) || std.fs.File.Writer.Error || error{ UnexpectPacket, BadBool })!struct { std.BufMap, Connection(std.fs.File.Reader, std.fs.File.Writer) } {
    return startAdvanced(allocator, std.io.getStdIn().reader(), std.io.getStdErr().writer());
}

pub fn startAdvanced(
    allocator: std.mem.Allocator,
    reader: anytype,
    writer: anytype,
) (wire.ReadError(@TypeOf(reader), true) || @TypeOf(writer).Error || error{ UnexpectPacket, BadBool })!struct { std.BufMap, Connection(@TypeOf(reader), @TypeOf(writer)) } {
    return .{
        try wire.readStringStringMap(allocator, reader),
        .{
            .reader = reader,
            .writer = writer,
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

test {
    _ = log;
    _ = wire;
}
