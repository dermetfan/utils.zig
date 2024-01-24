const std = @import("std");

const enums = @import("enums.zig");

pub const @"usize" = u32;

pub const Value = union(enums.Merged(&.{
    std.wasm.Valtype,
    std.wasm.RefType,
})) {
    i32: i32,
    i64: i64,
    f32: f32,
    f64: f64,
    v128: @Vector(128 / 8, u8),
    funcref: *const anyopaque,
    externref: ?*const anyopaque,

    pub const Type = std.meta.Tag(@This());
};

/// Alternative to `std.wasm.Type` that supports refs.
pub const Type = struct {
    params: []const Value.Type,
    returns: []const Value.Type,
};

pub fn span(memory: []u8, addr: anytype) []u8 {
    const a: @"usize" = switch (@TypeOf(addr)) {
        Value => @intCast(addr.i32),
        i32 => @intCast(addr),
        u32 => addr,
        else => |T| @compileError("unsupported type for address: " ++ @typeName(T)),
    };
    return std.mem.span(@as([*c]u8, &memory[a]));
}
