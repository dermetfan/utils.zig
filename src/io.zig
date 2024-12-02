const std = @import("std");

pub fn TeeReader(
    ReaderType: type,
    WriterType: type,
) type {
    return struct {
        src: ReaderType,
        dst: WriterType,

        pub const Reader = std.io.GenericReader(@This(), Error, read);
        pub const Error = ReaderType.Error || WriterType.Error;

        pub fn reader(self: @This()) Reader {
            return .{ .context = self };
        }

        pub fn read(self: @This(), dst: []u8) Error!usize {
            const n = try self.src.read(dst);
            try self.dst.writeAll(dst[0..n]);
            return n;
        }
    };
}

pub fn teeReader(src: anytype, dst: anytype) TeeReader(@TypeOf(src), @TypeOf(dst)) {
    return .{ .src = src, .dst = dst };
}

test teeReader {
    var src = std.io.fixedBufferStream("foo");
    var dst = dst: {
        var buf: [3]u8 = undefined;
        break :dst std.io.fixedBufferStream(&buf);
    };
    const tee_reader = teeReader(src.reader(), dst.writer()).reader();

    var buf: [3]u8 = undefined;
    try std.testing.expectEqual(3, try tee_reader.readAll(&buf));
    try std.testing.expectEqualStrings("foo", &buf);
    try std.testing.expectEqualStrings("foo", dst.buffer);
}
