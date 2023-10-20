const std = @import("std");

const mem = @import("mem.zig");

pub fn hashMapFromStruct(comptime T: type, allocator: std.mem.Allocator, strukt: anytype) !T {
    const info = hashMapInfo(T);

    var map = info.uniformInit(allocator);
    errdefer info.uniformDeinit(&map, allocator);

    const fields = @typeInfo(@TypeOf(strukt)).Struct.fields;
    try info.uniformCall(&map, T.ensureTotalCapacity, allocator, .{fields.len});
    inline for (fields) |field|
        map.putAssumeCapacityNoClobber(field.name, @field(strukt, field.name));

    return map;
}

pub fn hashMapInfo(comptime T: type) struct {
    K: type,
    V: type,
    managed: bool,

    pub fn uniformInit(comptime self: @This(), allocator: std.mem.Allocator) T {
        return if (self.managed) T.init(allocator) else .{};
    }

    pub fn uniformDeinit(comptime self: @This(), map: anytype, allocator: std.mem.Allocator) void {
        if (self.managed) map.deinit() else map.deinit(allocator);
    }

    pub fn UniformCall(comptime Func: type) type {
        return @typeInfo(Func).Fn.return_type orelse noreturn;
    }

    pub fn uniformCall(comptime self: @This(), map: anytype, func: anytype, allocator: std.mem.Allocator, params: anytype) UniformCall(@TypeOf(func)) {
        if (self.managed) std.debug.assert(mem.eqlAllocator(allocator, map.allocator));
        return @call(
            .auto,
            func,
            if (self.managed) concatTuples(.{ .{map}, params }) else concatTuples(.{ .{ map, allocator }, params }),
        );
    }
} {
    var K: type = undefined;
    var V: type = undefined;
    inline for (@typeInfo(T.KV).Struct.fields) |field| {
        inline for (&.{ "key", "value" }, &.{ &K, &V }) |name, ptr| { // XXX &.{}
            if (std.mem.eql(u8, field.name, name)) ptr.* = field.type;
        }
    }

    return .{
        .K = K,
        .V = V,
        .managed = std.meta.trait.hasField("unmanaged")(T),
    };
}

pub fn ConcatenatedTuples(comptime tuples: []const type) type {
    var tuple_info = @typeInfo(tuples[0]).Struct;
    tuple_info.fields = &.{};
    tuple_info.decls = &.{};

    comptime var i = 0;
    inline for (tuples) |tuple| {
        const info = switch (@typeInfo(tuple)) {
            .Struct => |s| s,
            .Pointer => |p| @typeInfo(p.child).Struct,
            else => unreachable,
        };

        tuple_info.decls = tuple_info.decls ++ info.decls;

        inline for (info.fields) |field| {
            defer i += 1;
            tuple_info.fields = tuple_info.fields ++ [_]std.builtin.Type.StructField{.{
                .name = std.fmt.comptimePrint("{d}", .{i}),
                .type = field.type,
                .default_value = field.default_value,
                .is_comptime = field.is_comptime,
                .alignment = field.alignment,
            }};
        }
    }

    return @Type(.{ .Struct = tuple_info });
}

pub fn ConcatTuples(comptime Tuples: type) type {
    const fields = @typeInfo(Tuples).Struct.fields;
    var types: [fields.len]type = undefined;
    inline for (fields, 0..) |field, i| types[i] = field.type;
    return ConcatenatedTuples(&types);
}

pub fn concatTuples(tuples: anytype) ConcatTuples(@TypeOf(tuples)) {
    var target: ConcatTuples(@TypeOf(tuples)) = undefined;

    comptime var i: usize = 0;
    inline for (tuples) |tuple| {
        inline for (tuple) |field| {
            defer i += 1;
            @field(target, std.fmt.comptimePrint("{d}", .{i})) = field;
        }
    }

    return target;
}

test concatTuples {
    const result = concatTuples(.{
        .{ 1, "2" },
        .{ 3.0, 4, 5 },
    });
    try std.testing.expectEqual(1, result.@"0");
    try std.testing.expectEqualStrings("2", result.@"1");
    try std.testing.expectEqual(3.0, result.@"2");
    try std.testing.expectEqual(4, result.@"3");
    try std.testing.expectEqual(5, result.@"4");
}
