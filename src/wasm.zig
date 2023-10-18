const std = @import("std");

pub const @"usize" = u32;

pub const Val = union(std.wasm.Valtype) {
    i32: i32,
    i64: i64,
    f32: f32,
    f64: f64,
    v128: @Vector(128 / 8, u8),
};

pub const Ref = union(std.wasm.RefType) {
    funcref: *const anyopaque,
    externref: ?*const anyopaque,
};

pub const ValueType = union(enum) {
    val: std.wasm.Valtype,
    ref: std.wasm.RefType,
};

pub const Value = union(std.meta.Tag(ValueType)) {
    val: Val,
    ref: Ref,

    pub fn valueType(self: @This()) ValueType {
        return switch (self) {
            .val => |val| .{ .val = val },
            .ref => |ref| .{ .ref = ref },
        };
    }
};

/// Alternative to `std.wasm.Type` that supports refs.
pub const Type = struct {
    params: []const ValueType,
    returns: []const ValueType,
};

pub fn span(memory: []u8, addr: anytype) []u8 {
    const a: @"usize" = switch (@TypeOf(addr)) {
        Value => @intCast(addr.val.i32),
        Val => @intCast(addr.i32),
        i32 => @intCast(addr),
        u32 => addr,
        else => |T| @compileError("unsupported type for address: " ++ @typeName(T)),
    };
    return std.mem.span(@as([*c]u8, &memory[a]));
}
