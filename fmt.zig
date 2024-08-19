const std = @import("std");

fn formatOneline(str: []const u8, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
    for (str) |char| try switch (char) {
        '\n' => writer.writeByte(' '),
        '\r' => {},
        else => writer.writeByte(char),
    };
}

pub fn fmtOneline(str: []const u8) std.fmt.Formatter(formatOneline) {
    return .{ .data = str };
}

fn formatJoin(
    data: struct {
        strs: []const []const u8,
        sep: []const u8 = " ",
    },
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    for (data.strs, 0..) |str, idx| {
        if (idx != 0) try writer.writeAll(data.sep);
        try std.fmt.formatText(str, fmt, options, writer);
    }
}

/// Formats strings by simply printing them separated by a separator.
/// Useful if you don't want the `{a, b}` style for slices of strings with `{s}`.
pub fn fmtJoin(sep: []const u8, strs: []const []const u8) std.fmt.Formatter(formatJoin) {
    return .{ .data = .{ .sep = sep, .strs = strs } };
}
