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

/// Runs `std.fmt.formatType()` through a `json.EncodeWriter`.
/// Not to be confused with the result of `std.json.stringify()`,
/// use `fmtStringifyJson()` and its friends for that.
/// This results in the input's `format()` function or its default format,
/// but JSON-encoded (or as one might say, JSON-escaped).
pub fn fmtJsonEncode(data: anytype, options: std.json.StringifyOptions) struct {
    data: @TypeOf(data),
    options: std.json.StringifyOptions,

    pub fn format(
        self: @This(),
        comptime fmt: []const u8,
        format_options: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        try std.fmt.formatType(
            self.data,
            fmt,
            format_options,
            json.encodeWriter(writer, self.options).writer(),
            std.options.fmt_max_depth,
        );
    }
} {
    return .{ .data = data, .options = options };
}

pub fn fmtJsonStringify(data: anytype, options: std.json.StringifyOptions) struct {
    data: @TypeOf(data),
    options: std.json.StringifyOptions,

    pub fn format(
        self: @This(),
        comptime fmt: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        std.debug.assert(fmt.len == 0);
        try std.json.stringify(self.data, self.options, writer);
    }
} {
    return .{ .data = data, .options = options };
}

pub fn fmtJsonStringifyMaxDepth(
    data: anytype,
    options: std.json.StringifyOptions,
    comptime max_depth: ?usize,
) struct {
    data: @TypeOf(data),
    options: std.json.StringifyOptions,

    pub fn format(
        self: @This(),
        comptime fmt: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        std.debug.assert(fmt.len == 0);
        try std.json.stringifyMaxDepth(self.data, self.options, writer, max_depth);
    }
} {
    return .{ .data = data, .options = options };
}

pub fn fmtJsonStringifyArbitraryDepth(
    allocator: std.mem.Allocator,
    data: anytype,
    options: std.json.StringifyOptions,
) struct {
    data: @TypeOf(data),
    options: std.json.StringifyOptions,
    allocator: std.mem.Allocator,

    pub fn format(
        self: @This(),
        comptime fmt: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        std.debug.assert(fmt.len == 0);
        try std.json.stringifyArbitraryDepth(allocator, self.data, self.options, writer);
    }
} {
    return .{ .data = data, .options = options, .allocator = allocator };
}

fn formatJsonDiagnostics(diagnostics: std.json.Diagnostics, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
    const scanner: *const std.json.Scanner = @fieldParentPtr("cursor", diagnostics.cursor_pointer);

    const line_end = std.mem.indexOfScalarPos(u8, scanner.input, diagnostics.line_start_cursor + 1, '\n') orelse scanner.input.len;
    const line = scanner.input[diagnostics.line_start_cursor + 1 .. line_end];

    try writer.print("at {d}:{d}:\n{s}\n", .{
        diagnostics.getLine(),
        diagnostics.getColumn(),
        line,
    });
    try writer.writeByteNTimes('.', diagnostics.getColumn() - 1);
    try writer.writeAll("^\n");
}

pub fn fmtJsonDiagnostics(diagnostics: std.json.Diagnostics) std.fmt.Formatter(formatJsonDiagnostics) {
    return .{ .data = diagnostics };
}

test fmtJsonDiagnostics {
    var scanner = std.json.Scanner.initCompleteInput(std.testing.allocator,
        \\{
        \\  "foo": 1,
        \\  "bar": 2
        \\}
    );
    defer scanner.deinit();

    var diagnostics = std.json.Diagnostics{};
    scanner.enableDiagnostics(&diagnostics);

    try std.testing.expectError(
        std.json.ParseFromValueError.UnknownField,
        std.json.parseFromTokenSourceLeaky(struct { foo: u8 }, std.testing.allocator, &scanner, .{}),
    );

    try std.testing.expectFmt(
        \\at 3:8:
        \\  "bar": 2
        \\.......^
        \\
    , "{}", .{fmtJsonDiagnostics(diagnostics)});
}
