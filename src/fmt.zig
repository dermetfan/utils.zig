const std = @import("std");

fn formatOneline(str: []const u8, writer: *std.Io.Writer) !void {
    for (str) |char|
        try writer.writeByte(switch (char) {
            '\n' => ' ',
            '\r' => continue,
            else => char,
        });
}

pub fn fmtOneline(str: []const u8) std.fmt.Alt([]const u8, formatOneline) {
    return .{ .data = str };
}

const FormatJoinData = struct {
    strs: []const []const u8,
    sep: []const u8 = " ",
};

fn formatJoin(
    data: FormatJoinData,
    writer: *std.Io.Writer,
) !void {
    for (data.strs, 0..) |str, idx| {
        if (idx != 0) try writer.writeAll(data.sep);
        try writer.writeAll(str);
    }
}

/// Formats strings by simply printing them separated by a separator.
/// Useful if you don't want the `{a, b}` style for slices of strings with `{s}`.
pub fn fmtJoin(sep: []const u8, strs: []const []const u8) std.fmt.Alt(FormatJoinData, formatJoin) {
    return .{ .data = .{ .sep = sep, .strs = strs } };
}

fn formatSourceLocation(src: std.builtin.SourceLocation, writer: *std.Io.Writer) !void {
    try writer.print(
        "{s}() in {s}:{d}:{d}",
        .{ src.fn_name, src.file, src.line, src.column },
    );
}

pub fn fmtSourceLocation(src: std.builtin.SourceLocation) std.fmt.Alt(std.builtin.SourceLocation, formatSourceLocation) {
    return .{ .data = src };
}

test {
    std.testing.refAllDecls(@This());
}
