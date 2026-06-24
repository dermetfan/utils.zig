const std = @import("std");

pub fn main(init: std.process.Init) !void {
    var buf: [1024]u8 = undefined;
    var writer = std.Io.File.stdout().writer(init.io, &buf);
    try writer.interface.print("{f}", .{std.json.fmt(@import("build.zig.zon"), .{})});
    try writer.flush();
}
