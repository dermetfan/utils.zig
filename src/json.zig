const std = @import("std");

/// Writes the input to its inner writer as a JSON-encoded string
/// (without any surrounding quotation marks).
pub fn EncodeWriter(comptime InnerWriter: type) type {
    return struct {
        inner: InnerWriter,
        options: std.json.StringifyOptions,

        pub const Error = InnerWriter.Error;
        pub const Writer = std.io.GenericWriter(@This(), Error, write);

        pub fn writer(self: @This()) Writer {
            return .{ .context = self };
        }

        /// May write more bytes than it returns!
        pub fn write(self: @This(), buf: []const u8) Error!usize {
            var num_written: usize = 0;
            for (buf) |char| {
                try std.json.encodeJsonStringChars(&[_]u8{char}, self.options, self.inner);
                num_written += 1;
            }
            return num_written;
        }
    };
}

pub fn encodeWriter(writer: anytype, options: std.json.StringifyOptions) EncodeWriter(@TypeOf(writer)) {
    return .{ .inner = writer, .options = options };
}
