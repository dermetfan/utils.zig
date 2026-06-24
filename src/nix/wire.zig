const std = @import("std");

pub const block_len = 8;

pub const PaddingError = error{
    /// The padding contains bytes that are not zeroes.
    BadPadding,

    /// The stream ended before the expected amount of padding could be read.
    EndOfStream,
};
pub const ReadError = std.Io.Reader.Error || PaddingError;
pub const ReadAllocError = ReadError || std.mem.Allocator.Error;

/// Returns the number of padding bytes.
pub fn padding(len: usize) std.math.IntFittingRange(0, block_len) {
    return @intCast((block_len - len % block_len) % block_len);
}

test padding {
    const Padding = @typeInfo(@TypeOf(padding)).@"fn".return_type.?;
    try std.testing.expectEqual(@as(Padding, 0), padding(0));
    try std.testing.expectEqual(@as(Padding, 3), padding(5));
    try std.testing.expectEqual(@as(Padding, 0), padding(24));
}

/// Reads the padding for the given length and asserts it is all zeroes.
pub fn readPadding(reader: *std.Io.Reader, len: usize) ReadError!void {
    const padding_len = padding(len);
    if (padding_len == 0) return;

    var padding_buf: [block_len]u8 = undefined;
    const padding_slice = padding_buf[0..padding_len];
    try reader.readSliceAll(padding_slice);

    if (!std.mem.allEqual(u8, padding_slice, 0)) return error.BadPadding;
}

test readPadding {
    {
        const len = 5;
        var reader = std.Io.Reader.fixed(&([_]u8{0} ** padding(len)));
        try readPadding(&reader, len);

        try std.testing.expectError(error.EndOfStream, reader.takeByte());
    }

    {
        var reader = std.Io.Reader.fixed(&[_]u8{ 0, 0, 1 });

        try std.testing.expectError(error.BadPadding, readPadding(&reader, 5));
    }
}

pub fn writePadding(writer: *std.Io.Writer, len: usize) std.Io.Writer.Error!void {
    try writer.splatByteAll(0, padding(len));
}

/// Fills the buffer and discards the padding.
pub fn readPadded(reader: *std.Io.Reader, buf: []u8) ReadError!void {
    try reader.readSliceAll(buf);
    try readPadding(reader, buf.len);
}

test readPadded {
    const input: []const u8 = &.{ 0, 1, 2, 3, 4, 0, 0, 0, 8, 9 };
    var reader = std.Io.Reader.fixed(input);

    var packet: [5]u8 = undefined;
    try readPadded(&reader, &packet);

    try std.testing.expectEqualStrings(input[0..packet.len], &packet);

    {
        var buf: [input.len - block_len]u8 = undefined;
        try reader.readSliceAll(&buf);
        try std.testing.expectEqualSlices(u8, input[block_len..], &buf);
    }
}

pub fn writePadded(writer: *std.Io.Writer, buf: []const u8) std.Io.Writer.Error!void {
    try writer.writeAll(buf);
    try writePadding(writer, buf.len);
}

pub fn readU64(reader: *std.Io.Reader) ReadError!u64 {
    const result = try reader.takeInt(u64, .little);
    try readPadding(reader, @sizeOf(u64));
    return result;
}

pub fn writeU64(writer: *std.Io.Writer, value: u64) std.Io.Writer.Error!void {
    try writer.writeInt(u64, value, .little);
    try writePadding(writer, @sizeOf(u64));
}

pub fn readBool(reader: *std.Io.Reader) (ReadError || error{BadBool})!bool {
    return switch (try readU64(reader)) {
        @intFromBool(false) => false,
        @intFromBool(true) => true,
        else => error.BadBool,
    };
}

pub fn writeBool(writer: *std.Io.Writer, value: bool) std.Io.Writer.Error!void {
    try writeU64(writer, @intFromBool(value));
}

pub fn readPacket(allocator: std.mem.Allocator, reader: *std.Io.Reader) ReadAllocError![]const u8 {
    const buf = try allocator.alloc(u8, try readU64(reader));
    errdefer allocator.free(buf);
    try readPadded(reader, buf);
    return buf;
}

pub fn writePacket(writer: *std.Io.Writer, packet: []const u8) std.Io.Writer.Error!void {
    try writeU64(writer, packet.len);
    try writePadded(writer, packet);
}

pub fn readPackets(allocator: std.mem.Allocator, reader: *std.Io.Reader) ReadAllocError![]const []const u8 {
    const bufs = try allocator.alloc([]const u8, try readU64(reader));
    errdefer {
        for (bufs) |buf| allocator.free(buf);
        allocator.free(bufs);
    }
    for (bufs) |*buf| buf.* = try readPacket(allocator, reader);
    return bufs;
}

pub fn writePackets(writer: *std.Io.Writer, packets: []const []const u8) std.Io.Writer.Error!void {
    try writeU64(writer, packets.len);
    for (packets) |packet| try writePacket(writer, packet);
}

pub fn readStringStringMap(allocator: std.mem.Allocator, reader: *std.Io.Reader) (ReadAllocError || error{BadBool})!std.BufMap {
    var map = std.BufMap.init(allocator);
    errdefer map.deinit();

    while (try readBool(reader)) {
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

pub fn writeStringStringMap(writer: *std.Io.Writer, map: std.StringHashMapUnmanaged([]const u8)) std.Io.Writer.Error!void {
    var iter = map.iterator();
    while (iter.next()) |entry| {
        try writeBool(writer, true);
        try writePacket(writer, entry.key_ptr.*);
        try writePacket(writer, entry.value_ptr.*);
    } else try writeBool(writer, false);
}

/// Reads fields in declaration order.
pub fn readStruct(comptime T: type, allocator: std.mem.Allocator, reader: *std.Io.Reader) (ReadAllocError || error{BadBool})!T {
    var strukt: T = undefined;

    const fields = @typeInfo(T).@"struct".fields;
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
            else => @compileError("type \"" ++ @typeName(field.type) ++ "\" does not exist in the nix protocol"),
        } catch |err| {
            inline for (fields[0..field_idx]) |field_| {
                const field_value = @field(strukt, field_.name);
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

test readStruct {
    var serialized = std.Io.Reader.fixed(&TestStruct.default_serialized);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var test_struct = try readStruct(TestStruct, arena.allocator(), &serialized);
    defer test_struct.deinit();

    var expected = try TestStruct.default(std.testing.allocator);
    defer expected.deinit();

    try std.testing.expectEqual(expected.bar, test_struct.bar);
    try std.testing.expectEqualStrings(expected.baz, test_struct.baz);
    try std.testing.expectEqual(expected.qux, test_struct.qux);
    try std.testing.expectEqual(expected.foobar.count(), test_struct.foobar.count());
    try std.testing.expectEqualStrings(expected.foobar.get("foo").?, test_struct.foobar.get("foo").?);
}

pub fn writeStruct(comptime T: type, writer: *std.Io.Writer, value: T) (std.Io.Writer.Error || error{BadBool})!void {
    const fields = @typeInfo(T).@"struct".fields;
    inline for (fields) |field| {
        const field_value = @field(value, field.name);
        try switch (field.type) {
            []const u8 => writePacket(writer, field_value),
            []const []const u8 => writePackets(writer, field_value),
            u64 => writeU64(writer, field_value),
            bool => writeBool(writer, field_value),
            std.BufMap => writeStringStringMap(writer, field_value.hash_map.unmanaged),
            std.StringHashMapUnmanaged([]const u8) => if (writeStringStringMap(writer, field_value)) |map|
                map.hash_map.unmanaged
            else |err|
                err,
            else => @compileError("type \"" ++ @typeName(field.type) ++ "\" does not exist in the nix protocol"),
        };
    }
}

test writeStruct {
    var test_struct = try TestStruct.default(std.testing.allocator);
    defer test_struct.deinit();

    var serialized = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer serialized.deinit();

    try writeStruct(TestStruct, &serialized.writer, test_struct);

    try std.testing.expectEqualSlices(u8, &TestStruct.default_serialized, serialized.writer.buffered());
}

const TestStruct = struct {
    bar: u64,
    baz: []const u8,
    baaz: []const []const u8,
    qux: bool,
    foobar: std.BufMap,

    pub const default_serialized = [_]u8{
        0x2A, 0,    0,    0, 0, 0, 0, 0, 0x03, 0,    0,    0, 0, 0, 0, 0,
        0x62, 0x61, 0x7A, 0, 0, 0, 0, 0, 0x03, 0,    0,    0, 0, 0, 0, 0,
        0x01, 0,    0,    0, 0, 0, 0, 0, 0x61, 0,    0,    0, 0, 0, 0, 0,
        0x01, 0,    0,    0, 0, 0, 0, 0, 0x62, 0,    0,    0, 0, 0, 0, 0,
        0x01, 0,    0,    0, 0, 0, 0, 0, 0x63, 0,    0,    0, 0, 0, 0, 0,
        0x01, 0,    0,    0, 0, 0, 0, 0, 0x01, 0,    0,    0, 0, 0, 0, 0,
        0x03, 0,    0,    0, 0, 0, 0, 0, 0x66, 0x6F, 0x6F, 0, 0, 0, 0, 0,
        0x03, 0,    0,    0, 0, 0, 0, 0, 0x62, 0x61, 0x72, 0, 0, 0, 0, 0,
        0,    0,    0,    0, 0, 0, 0, 0,
    };

    pub fn default(allocator: std.mem.Allocator) !@This() {
        var self = @This(){
            .bar = 42,
            .baz = "baz",
            .baaz = &.{ "a", "b", "c" },
            .qux = true,
            .foobar = .init(allocator),
        };

        try self.foobar.put("foo", "bar");

        return self;
    }

    pub fn deinit(self: *@This()) void {
        self.foobar.deinit();
        self.* = undefined;
    }
};

pub fn expectPacket(comptime expected: []const u8, reader: *std.Io.Reader) (ReadError(@TypeOf(reader), true) || error{UnexpectedPacket})!void {
    var buf: [expected.len]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);

    const packet = readPacket(fba.allocator(), reader) catch |err| return switch (err) {
        error.OutOfMemory => error.UnexpectedPacket,
        else => err,
    };

    if (!std.mem.eql(u8, packet, expected))
        return error.UnexpectedPacket;
}

test {
    std.testing.refAllDecls(@This());
}
