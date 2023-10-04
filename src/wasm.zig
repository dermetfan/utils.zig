const std = @import("std");

pub const Val = union(std.wasm.Valtype) {
    i32: i32,
    i64: i64,
    f32: f32,
    f64: f64,
    v128: @Vector(16, u8),
};

pub fn span(memory: []const u8, addr: Val) ![]const u8 {
    if (std.meta.activeTag(addr) != .i32) return error.ValNotAnAddress;

    return std.mem.span(@as(
        [*c]const u8,
        &memory[@intCast(addr.i32)],
    ));
}
