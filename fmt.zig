const std = @import("std");

pub const Oneline = struct {
    str: []const u8,

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

/// Formats strings by simply printing them separated by a separator.
/// Useful if you don't want the `{a, b}` style for slices of strings with `{s}`.
pub const Join = struct {
    strs: []const []const u8,
    sep: []const u8 = " ",

    pub fn format(self: @This(), comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        for (self.strs, 0..) |str, idx| {
            if (idx != 0) try writer.writeAll(self.sep);
            try std.fmt.formatText(str, fmt, options, writer);
        }
    }
};

pub fn join(sep: []const u8, strs: []const []const u8) Join {
    return .{ .sep = sep, .strs = strs };
}
