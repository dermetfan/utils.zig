const std = @import("std");

pub fn hashMapFromStruct(comptime T: type, allocator: std.mem.Allocator, strukt: anytype) !T {
    const info = hashMapInfo(T);

    var map = info.uniformInit(allocator);
    errdefer info.uniformDeinit(&map, allocator);

    const fields = std.meta.fields(@TypeOf(strukt));
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
        if (self.managed) std.debug.assert(std.meta.eql(allocator, map.allocator));
        return @call(
            .auto,
            func,
            if (self.managed) concatTuples(.{ .{map}, params }) else concatTuples(.{ .{ map, allocator }, params }),
        );
    }
} {
    var K: type = undefined;
    var V: type = undefined;
    inline for (std.meta.fields(T.KV)) |field| {
        inline for (.{ "key", "value" }, .{ &K, &V }) |name, ptr| {
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
    var types: []const type = &.{};
    for (tuples) |tuple| {
        for (std.meta.fields(tuple)) |field|
            types = types ++ [_]type{field.type};
    }
    return std.meta.Tuple(types);
}

pub fn ConcatTuples(comptime Tuples: type) type {
    const fields = std.meta.fields(Tuples);
    var types: [fields.len]type = undefined;
    for (fields, &types) |field, *t| t.* = field.type;
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

pub fn OptionalChild(comptime T: type) ?type {
    return switch (@typeInfo(T)) {
        .Array, .Vector, .Pointer, .Optional => std.meta.Child(T),
        else => null,
    };
}

pub fn DropUfcsParam(comptime T: type) type {
    var fn_info = @typeInfo(T).Fn;
    fn_info.params = fn_info.params[1..];
    return @Type(.{ .Fn = fn_info });
}

pub fn Closure(comptime Func: type, comptime mutable: bool) type {
    const fn_info = @typeInfo(Func).Fn;
    return union(enum) {
        stateful: Stateful,
        stateless: Stateless,

        pub const Fn = Func;

        const Self = @This();

        pub const Stateful = struct {
            state_fn: *const OpaqueStateFn,
            state: OpaqueStatePtr,

            pub const OpaqueStatePtr = if (mutable) *anyopaque else *const anyopaque;

            pub const OpaqueStateFn = @Type(.{ .Fn = blk: {
                var info = fn_info;
                info.params = .{.{
                    .type = OpaqueStatePtr,
                    .is_generic = false,
                    .is_noalias = false,
                }} ++ info.params;
                break :blk info;
            } });

            pub fn init(comptime state_fn: anytype, state: anytype) @This() {
                const StateFn = @TypeOf(state_fn);
                const state_fn_info = @typeInfo(StateFn).Fn;
                const bad_fn_msg = "cannot safely cast " ++ @typeName(StateFn) ++ " to " ++ @typeName(OpaqueStateFn);
                const State = std.meta.Child(@TypeOf(state));
                const StatePtr = if (mutable) *State else *const State;

                if (state_fn_info.params[0].type.? != StatePtr) @compileError(bad_fn_msg);
                inline for (state_fn_info.params[1..], fn_info.params) |state_fn_param, fn_param|
                    if (state_fn_param.type != fn_param.type) @compileError(bad_fn_msg);
                if (state_fn_info.return_type != fn_info.return_type) @compileError(bad_fn_msg);

                return .{
                    .state_fn = @ptrCast(&state_fn),
                    .state = state,
                };
            }
        };

        pub const Stateless = *const Fn;

        pub fn stateful(comptime state_fn: anytype, state: anytype) Self {
            return .{ .stateful = Stateful.init(state_fn, state) };
        }

        pub fn stateless(comptime func: anytype) Self {
            return .{ .stateless = func };
        }

        pub fn call(self: Self, args: anytype) fn_info.return_type.? {
            return switch (self) {
                .stateful => |sf| @call(.auto, sf.state_fn, .{sf.state} ++ args),
                .stateless => |func| @call(.auto, func, args),
            };
        }
    };
}

const TestClosureState = struct {
    count: usize = 0,

    pub fn call(self: *@This(), n: usize) usize {
        self.count += n;
        return self.count;
    }

    pub fn tests(self: *const @This(), closed: Closure(DropUfcsParam(@TypeOf(call)), true)) !void {
        for (1..3) |i| {
            try std.testing.expectEqual(@as(usize, i), closed.call(.{1}));
            try std.testing.expectEqual(@as(usize, i), self.count);
        }
    }
};

test Closure {
    var state = TestClosureState{};
    try state.tests(Closure(fn (usize) usize, true).stateful(TestClosureState.call, &state));

    try std.testing.expectEqual(@as(usize, 5), Closure(fn () usize, false).stateless(struct {
        fn call() usize {
            return 5;
        }
    }.call).call(.{}));
}

pub fn closure(state_fn: anytype, state: anytype) Closure(DropUfcsParam(@TypeOf(state_fn)), !std.meta.trait.isConstPtr(@TypeOf(state))) {
    return Closure(DropUfcsParam(@TypeOf(state_fn)), !std.meta.trait.isConstPtr(@TypeOf(state))).stateful(state_fn, state);
}

pub fn disclosure(func: anytype, comptime mutable: bool) Closure(@TypeOf(func), mutable) {
    return Closure(@TypeOf(func), mutable).stateless(func);
}

test closure {
    var state = TestClosureState{};
    try state.tests(closure(TestClosureState.call, &state));
}

test disclosure {
    try std.testing.expectEqual(@as(usize, 2), disclosure(struct {
        fn call(foo: usize) usize {
            return foo + 1;
        }
    }.call, false).call(.{1}));
}
