const std = @import("std");

pub const Oneline = struct {
    str: []const u8,

    pub fn init(str: []const u8) @This() {
        return .{ .str = str };
    }

    pub fn format(self: @This(), comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        for (self.str) |char| try switch (char) {
            '\n' => writer.writeByte(' '),
            '\r' => {},
            else => writer.writeByte(char),
        };
    }
};

pub fn oneline(str: []const u8) Oneline {
    return .{ .str = str };
}
