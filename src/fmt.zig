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

fn FormatJoin(T: type, Separator: type, fmt: []const u8, fmt_separator: []const u8) type {
    return struct {
        items: []const T,
        separator: Separator,

        pub fn format(self: @This(), writer: *std.Io.Writer) !void {
            for (self.items, 0..) |item, idx| {
                if (idx != 0) try writer.print(fmt_separator, .{self.separator});
                try writer.print(fmt, .{item});
            }
        }
    };
}

pub fn fmtJoin(
    comptime T: type,
    comptime Separator: type,
    comptime fmt: []const u8,
    comptime fmt_separator: []const u8,
    items: []const T,
    separator: Separator,
) FormatJoin(T, Separator, fmt, fmt_separator) {
    return .{ .items = items, .separator = separator };
}

test fmtJoin {
    try std.testing.expectFmt("(a),(b)", "{f}", .{fmtJoin(u8, u8, "({c})", "{c}", "ab", ',')});
}

pub fn fmtJoinSepStr(comptime T: type, comptime fmt: []const u8, items: []const T, separator: []const u8) FormatJoin(T, []const u8, fmt, "{s}") {
    return .{
        .items = items,
        .separator = separator,
    };
}

test fmtJoinSepStr {
    try std.testing.expectFmt("(a), (b)", "{f}", .{fmtJoinSepStr(u8, "({c})", "ab", ", ")});
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

fn FormatIterator(Iterator: type, fmt: []const u8) type {
    return struct {
        iterator: *Iterator,

        pub fn format(self: @This(), writer: *std.Io.Writer) !void {
            while (if (@typeInfo(@typeInfo(@TypeOf(Iterator.next)).@"fn".return_type.?) == .error_set)
                try self.iterator.next()
            else
                self.iterator.next()) |item|
                try writer.print(fmt, .{item});
        }
    };
}

pub fn fmtIterator(comptime I: type, comptime fmt: []const u8, iterator: *I) FormatIterator(I, fmt) {
    return .{ .iterator = iterator };
}

test fmtIterator {
    var iter = std.mem.splitScalar(u8, "a b c", ' ');
    try std.testing.expectFmt("(a)(b)(c)", "{f}", .{fmtIterator(@TypeOf(iter), "({s})", &iter)});
}

test {
    std.testing.refAllDecls(@This());
}
