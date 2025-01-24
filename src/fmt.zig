const std = @import("std");
const json = @import("json.zig");

fn formatOneline(str: []const u8, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
    for (str) |char|
        try std.fmt.formatText(&[1]u8{switch (char) {
            '\n' => ' ',
            '\r' => continue,
            else => char,
        }}, fmt, options, writer);
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

fn formatSourceLocation(src: std.builtin.SourceLocation, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
    try std.fmt.format(
        writer,
        "{s}() in {s}:{d}:{d}",
        .{ src.fn_name, src.file, src.line, src.column },
    );
}

pub fn fmtSourceLocation(src: std.builtin.SourceLocation) std.fmt.Formatter(formatSourceLocation) {
    return .{ .data = src };
}

/// XXX Only works on `data` that has a `format()` method.
pub fn fmtEscapeJson(data: anytype, options: std.json.StringifyOptions) struct {
    data_: @TypeOf(data),
    options: std.json.StringifyOptions,

    pub fn format(
        formatter: @This(),
        comptime fmt: []const u8,
        format_options: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        try formatter.data_.format(
            fmt,
            format_options,
            json.encodeWriter(writer, formatter.options).writer(),
        );
    }
} {
    return .{ .data_ = data, .options = options };
}
