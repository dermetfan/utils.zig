const std = @import("std");

const Io = std.Io;

pub const TeeReader = struct {
    src: *Io.Reader,
    dst: *Io.Writer,
    interface: Io.Reader,

    pub fn init(src: *Io.Reader, dst: *Io.Writer, buffer: []u8) @This() {
        return .{
            .src = src,
            .dst = dst,
            .interface = .{
                .vtable = &.{ .stream = stream },
                .buffer = buffer,
                .seek = 0,
                .end = 0,
            },
        };
    }

    pub fn stream(io_r: *Io.Reader, io_w: *Io.Writer, limit: Io.Limit) Io.Reader.Error!usize {
        const self: *@This() = @fieldParentPtr("interface", io_r);

        var buffer_w = Io.Writer.fixed(self.interface.buffer);

        const written = self.src.stream(&buffer_w, limit) catch |err| switch (err) {
            error.WriteFailed => unreachable,
            else => |e| return e,
        };
        if (std.debug.runtime_safety)
            std.debug.assert(written == buffer_w.buffered().len);

        self.dst.writeAll(buffer_w.buffered()) catch |err| switch (err) {
            error.WriteFailed => unreachable,
            else => |e| return e,
        };
        io_w.writeAll(buffer_w.buffered()) catch |err| switch (err) {
            error.WriteFailed => unreachable,
            else => |e| return e,
        };

        return written;
    }
};

test TeeReader {
    var src = Io.Reader.fixed("foo");
    var dst = dst: {
        var buf: [3]u8 = undefined;
        break :dst Io.Writer.fixed(&buf);
    };
    var tee_buf: [3]u8 = undefined;
    var tee_reader = TeeReader.init(&src, &dst, &tee_buf);

    var buf: [3]u8 = undefined;
    try tee_reader.interface.readSliceAll(&buf);
    try std.testing.expectEqualStrings("foo", &buf);
    try std.testing.expectEqualStrings("foo", dst.buffer);
}

test {
    std.testing.refAllDecls(@This());
}
