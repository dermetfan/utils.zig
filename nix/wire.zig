const std = @import("std");

pub const block_len = 8;

pub const PaddingError = error{
    /// The padding contains bytes that are not zeroes.
    BadPadding,

    /// The stream ended before the expected amount of padding could be read.
    EndOfStream,
};

pub fn ReadError(comptime Reader: type, allocates: bool) type {
    var set = Reader.NoEofError || PaddingError;
    if (allocates) set = set || std.mem.Allocator.Error;
    return set;
}

/// Returns the number of padding bytes.
pub fn padding(len: usize) std.math.IntFittingRange(0, block_len) {
    return if (len % block_len == 0) 0 else @intCast(block_len - len % block_len);
}

test padding {
    const Padding = @typeInfo(@TypeOf(padding)).Fn.return_type.?;
    try std.testing.expectEqual(@as(Padding, 0), padding(0));
    try std.testing.expectEqual(@as(Padding, 3), padding(5));
    try std.testing.expectEqual(@as(Padding, 0), padding(24));
}

/// Reads the padding for the given length and asserts it is all zeroes.
pub fn readPadding(reader: anytype, len: usize) ReadError(@TypeOf(reader), false)!void {
    const padding_len = padding(len);
    if (padding_len == 0) return;

    var padding_buf: [block_len]u8 = undefined;
    const padding_slice = padding_buf[0..padding_len];
    try reader.readNoEof(padding_slice);

    if (!std.mem.allEqual(u8, padding_slice, 0)) return error.BadPadding;
}

test readPadding {
    {
        const len = 5;
        var stream = std.io.fixedBufferStream(&([_]u8{0} ** padding(len)));
        try readPadding(stream.reader(), len);

        try std.testing.expectError(error.EndOfStream, stream.reader().readByte());
    }

    {
        var stream = std.io.fixedBufferStream(&[_]u8{ 0, 0, 1 });

        try std.testing.expectError(error.BadPadding, readPadding(stream.reader(), 5));
    }
}

pub fn writePadding(writer: anytype, len: usize) @TypeOf(writer).Error!void {
    try writer.writeByteNTimes(0, padding(len));
}

/// Fills the buffer and discards the padding.
pub fn readPadded(reader: anytype, buf: []u8) ReadError(@TypeOf(reader), false)!void {
    if (try reader.readAll(buf) < buf.len) return error.EndOfStream;
    try readPadding(reader, buf.len);
}

test readPadded {
    const input: []const u8 = &.{ 0, 1, 2, 3, 4, 0, 0, 0, 8, 9 };
    var stream = std.io.fixedBufferStream(input);

    var packet: [5]u8 = undefined;
    try readPadded(stream.reader(), &packet);

    try std.testing.expectEqualStrings(input[0..packet.len], &packet);

    {
        var buf: [input.len - block_len]u8 = undefined;
        try std.testing.expectEqual(buf.len, try stream.reader().readAll(&buf));
        try std.testing.expectEqualSlices(u8, input[block_len..], &buf);
    }
}

pub fn writePadded(writer: anytype, buf: []const u8) @TypeOf(writer).Error!void {
    try writer.writeAll(buf);
    try writePadding(writer, buf.len);
}

pub fn readU64(reader: anytype) ReadError(@TypeOf(reader), false)!u64 {
    const result = try reader.readInt(u64, .little);
    try readPadding(reader, @sizeOf(u64));
    return result;
}

pub fn writeU64(writer: anytype, value: u64) @TypeOf(writer).Error!void {
    try writer.writeInt(u64, value, .little);
    try writePadding(writer, @sizeOf(u64));
}

pub fn readBool(reader: anytype) (ReadError(@TypeOf(reader), false) || error{BadBool})!bool {
    return switch (try readU64(reader)) {
        0 => false,
        1 => true,
        else => error.BadBool,
    };
}

pub fn writeBool(writer: anytype, value: bool) @TypeOf(writer).Error!void {
    try writeU64(writer, @intFromBool(value));
}

pub fn readPacket(allocator: std.mem.Allocator, reader: anytype) ReadError(@TypeOf(reader), true)![]const u8 {
    const buf = try allocator.alloc(u8, try readU64(reader));
    errdefer allocator.free(buf);
    try readPadded(reader, buf);
    return buf;
}

pub fn writePacket(writer: anytype, packet: []const u8) @TypeOf(writer).Error!void {
    try writeU64(writer, packet.len);
    try writePadded(writer, packet);
}

pub fn readPackets(allocator: std.mem.Allocator, reader: anytype) ReadError(@TypeOf(reader), true)![]const []const u8 {
    const bufs = try allocator.alloc([]const u8, try readU64(reader));
    errdefer {
        for (bufs) |buf| allocator.free(buf);
        allocator.free(bufs);
    }
    for (bufs) |*buf| buf.* = try readPacket(allocator, reader);
    return bufs;
}

pub fn writePackets(writer: anytype, packets: []const []const u8) @TypeOf(writer).Error!void {
    try writeU64(writer, packets.len);
    for (packets) |packet| try writePacket(writer, packet);
}

pub fn readStringStringMap(allocator: std.mem.Allocator, reader: anytype) (ReadError(@TypeOf(reader), true) || error{BadBool})!std.BufMap {
    var map = std.BufMap.init(allocator);
    errdefer map.deinit();

    while (try readU64(reader) != 0) {
        const key = try readPacket(allocator, reader);
        errdefer allocator.free(key);

        const value = try readPacket(allocator, reader);
        errdefer allocator.free(value);

        // XXX Why does `putMove()` not take const slices?
        // Submit a PR upstream that makes them const?
        try map.putMove(@constCast(key), @constCast(value));
    }

    return map;
}

pub fn writeStringStringMap(writer: anytype, map: std.StringHashMapUnmanaged([]const u8)) @TypeOf(writer).Error!void {
    var iter = map.iterator();
    while (iter.next()) |entry| {
        try writeBool(writer, true);
        try writePacket(writer, entry.key_ptr.*);
        try writePacket(writer, entry.value_ptr.*);
    } else try writeBool(writer, false);
}

/// Reads fields in declaration order.
pub fn readStruct(comptime T: type, allocator: std.mem.Allocator, reader: anytype) (ReadError(@TypeOf(reader), true) || error{BadBool})!T {
    var strukt: T = undefined;

    const fields = @typeInfo(T).Struct.fields;
    inline for (fields, 0..) |field, field_idx| {
        @field(strukt, field.name) = switch (field.type) {
            []const u8 => readPacket(allocator, reader),
            []const []const u8 => readPackets(allocator, reader),
            u64 => readU64(reader),
            bool => readBool(reader),
            std.BufMap => readStringStringMap(allocator, reader),
            std.StringHashMapUnmanaged([]const u8) => if (readStringStringMap(allocator, reader)) |map|
                map.hash_map.unmanaged
            else |err|
                err,
            else => @compileError("type \"" ++ @typeName(T) ++ "\" does not exist in the nix protocol"),
        } catch |err| {
            inline for (fields[0..field_idx]) |field_| {
                const field_value = @field(strukt, field.name);
                switch (field_.type) {
                    []const u8 => allocator.free(field_value),
                    []const []const u8 => for (field_value) |item| allocator.free(item),
                    std.BufMap => field_value.deinit(),
                    std.StringHashMapUnmanaged([]const u8) => {
                        var map = std.BufMap{ .hash_map = field_value.promote(allocator) };
                        map.deinit();
                    },
                    else => {},
                }
            }
            return err;
        };
    }

    return strukt;
}

pub fn writeStruct(comptime T: type, writer: anytype, value: T) (@TypeOf(writer).Error || error{BadBool})!void {
    const fields = @typeInfo(T).Struct.fields;
    inline for (fields) |field| {
        const field_value = @field(value, field.name);
        try switch (field.type) {
            []const u8 => writePacket(writer, field_value),
            []const []const u8 => writePackets(writer, field_value),
            u64 => writeU64(writer, field_value),
            bool => writeBool(writer, field_value),
            std.BufMap => writeStringStringMap(writer, field_value),
            std.StringHashMapUnmanaged([]const u8) => if (writeStringStringMap(writer, field_value)) |map|
                map.hash_map.unmanaged
            else |err|
                err,
            else => @compileError("type \"" ++ @typeName(T) ++ "\" does not exist in the nix protocol"),
        };
    }
}

pub fn expectPacket(comptime expected: []const u8, reader: anytype) (ReadError(@TypeOf(reader), true) || error{UnexpectedPacket})!void {
    var buf: [expected.len]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);

    const packet = readPacket(fba.allocator(), reader) catch |err| return switch (err) {
        error.OutOfMemory => error.UnexpectedPacket,
        else => err,
    };

    if (!std.mem.eql(u8, packet, expected))
        return error.UnexpectedPacket;
}
