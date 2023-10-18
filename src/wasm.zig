const std = @import("std");

pub const @"usize" = u32;

pub const Val = union(std.wasm.Valtype) {
    i32: i32,
    i64: i64,
    f32: f32,
    f64: f64,
    v128: @Vector(128 / 8, u8),
};

pub fn span(memory: []u8, addr_val: anytype) []u8 {
    const addr: @"usize" = switch (@TypeOf(addr_val)) {
        Val => @intCast(addr_val.i32),
        i32 => @intCast(addr_val),
        u32 => addr_val,
        else => |T| @compileError("unsupported type for address: " ++ @typeName(T)),
    };
    return std.mem.span(@as([*c]u8, &memory[a]));
}
