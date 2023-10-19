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

    pub const @"i32" = @This(){ .val = .i32 };
    pub const @"i64" = @This(){ .val = .i64 };
    pub const @"f32" = @This(){ .val = .f32 };
    pub const @"f64" = @This(){ .val = .f64 };
    pub const v128 = @This(){ .val = .v128 };
    pub const funcref = @This(){ .ref = .funcref };
    pub const externref = @This(){ .ref = .externref };
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

    pub inline fn @"i32"(v: i32) @This() {
        return .{ .val = .{ .i32 = v } };
    }

    pub inline fn @"i64"(v: i64) @This() {
        return .{ .val = .{ .i64 = v } };
    }

    pub inline fn @"f32"(v: f32) @This() {
        return .{ .val = .{ .f32 = v } };
    }

    pub inline fn @"f64"(v: f64) @This() {
        return .{ .val = .{ .f64 = v } };
    }

    pub inline fn v128(v: @Vector(128 / 8, u8)) @This() {
        return .{ .val = .{ .v128 = v } };
    }

    pub inline fn funcref(v: *const anyopaque) @This() {
        return .{ .ref = .{ .funcref = v } };
    }

    pub inline fn externref(v: ?*const anyopaque) @This() {
        return .{ .ref = .{ .externref = v } };
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
