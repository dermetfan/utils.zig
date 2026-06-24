const std = @import("std");

fn formatJsonDiagnostics(diagnostics: std.json.Diagnostics, writer: *std.Io.Writer) !void {
    const scanner: *const std.json.Scanner = @fieldParentPtr("cursor", diagnostics.cursor_pointer);

    const line_end = std.mem.indexOfScalarPos(u8, scanner.input, diagnostics.line_start_cursor + 1, '\n') orelse scanner.input.len;
    const line = scanner.input[diagnostics.line_start_cursor + 1 .. line_end];

    try writer.print("at {d}:{d}:\n{s}\n", .{
        diagnostics.getLine(),
        diagnostics.getColumn(),
        line,
    });
    try writer.splatByteAll('.', diagnostics.getColumn() - 1);
    try writer.writeAll("^\n");
}

pub fn fmtJsonDiagnostics(diagnostics: std.json.Diagnostics) std.fmt.Alt(std.json.Diagnostics, formatJsonDiagnostics) {
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
    , "{f}", .{fmtJsonDiagnostics(diagnostics)});
}

test {
    std.testing.refAllDecls(@This());
}
