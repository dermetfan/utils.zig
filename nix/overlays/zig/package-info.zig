const std = @import("std");

const info = @buildZigZon@;

pub fn main() !void {
    try std.json.stringify(info, .{}, std.io.getStdOut().writer());
}
