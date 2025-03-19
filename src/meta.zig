const std = @import("std");

const enums = @import("enums.zig");

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
        return @typeInfo(Func).@"fn".return_type orelse noreturn;
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
        .managed = @hasField(T, "unmanaged"),
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
        .array, .vector, .pointer, .optional => std.meta.Child(T),
        else => null,
    };
}

pub fn ChildOrelseSelf(comptime T: type) type {
    return OptionalChild(T) orelse T;
}

pub fn fieldTypes(comptime T: type) []const type {
    comptime var types: []const type = &.{};
    inline for (std.meta.fields(T)) |field|
        types = types ++ .{field.type};
    return types;
}

test fieldTypes {
    try std.testing.expectEqualSlices(type, &.{ u1, u2 }, fieldTypes(struct { a: u1, b: u2 }));
    try std.testing.expectEqualSlices(type, &.{ u1, u2 }, fieldTypes(union { a: u1, b: u2 }));
    try std.testing.expectEqualSlices(type, &.{ u1, u2 }, fieldTypes(union(enum) { a: u1, b: u2 }));
}

pub fn FieldsTuple(Struct: type) type {
    if (@typeInfo(Struct).@"struct".is_tuple) return Struct;
    return std.meta.Tuple(fieldTypes(Struct));
}

test FieldsTuple {
    const Struct = struct {
        a: u8,
        b: bool,
    };
    const Tuple = FieldsTuple(Struct);

    try std.testing.expectEqual(std.meta.FieldType(Struct, .a), std.meta.FieldType(Tuple, .@"0"));
    try std.testing.expectEqual(std.meta.FieldType(Struct, .b), std.meta.FieldType(Tuple, .@"1"));
    try std.testing.expectEqual(2, @as(Tuple, undefined).len);
}

pub fn NamedArgs(Function: type, names: []const [:0]const u8) type {
    return @Type(.{ .@"struct" = std.builtin.Type.Struct{
        .layout = .auto,
        .backing_integer = null,
        .decls = &.{},
        .fields = fields: {
            var fields: []const std.builtin.Type.StructField = &.{};
            for (@typeInfo(Function).@"fn".params, names) |param, name|
                fields = fields ++ .{std.builtin.Type.StructField{
                    .name = name,
                    .type = param.type orelse @compileError("`NamedArgs()` does not support generic parameters"),
                    .default_value_ptr = null,
                    .is_comptime = false,
                    .alignment = @alignOf(param.type.?),
                }};
            break :fields fields;
        },
        .is_tuple = false,
    } });
}

test NamedArgs {
    const Func = @TypeOf(struct {
        fn func(_: u1, _: u2, _: u3) void {}
    }.func);
    const NamedFuncArgs = NamedArgs(Func, &.{ "a", "b", "c" });

    try std.testing.expectEqual(std.meta.FieldType(NamedFuncArgs, .a), std.meta.FieldType(std.meta.ArgsTuple(Func), .@"0"));
    try std.testing.expectEqual(std.meta.FieldType(NamedFuncArgs, .b), std.meta.FieldType(std.meta.ArgsTuple(Func), .@"1"));
    try std.testing.expectEqual(std.meta.FieldType(NamedFuncArgs, .c), std.meta.FieldType(std.meta.ArgsTuple(Func), .@"2"));
    try std.testing.expectEqual(3, @typeInfo(NamedFuncArgs).@"struct".fields.len);
}

pub fn SubUnion(comptime Union: type, comptime fields: []const std.meta.FieldEnum(Union)) type {
    comptime var info = @typeInfo(Union).@"union";

    info.fields = &.{};
    inline for (fields) |field|
        info.fields = info.fields ++ .{std.meta.fieldInfo(Union, field)};

    if (@typeInfo(Union).@"union".tag_type) |tag_type|
        info.tag_type = enums.Sub(tag_type, fields);

    return @Type(.{ .@"union" = info });
}

test SubUnion {
    const U1 = union { a: u1, b: u2, c: u3 };
    const U2 = SubUnion(U1, &.{ .a, .c });

    const u2_field_names = std.meta.fieldNames(U2);

    try std.testing.expectEqual(2, u2_field_names.len);
    try std.testing.expectEqualStrings("a", u2_field_names[0]);
    try std.testing.expectEqualStrings("c", u2_field_names[1]);
}

pub fn MergedUnions(comptime A: type, comptime B: type, comptime tagged: bool) type {
    const a = @typeInfo(A).@"union";
    const b = @typeInfo(B).@"union";

    var info = a;

    info.fields = info.fields ++ b.fields;
    info.decls = info.decls ++ b.decls;

    info.tag_type = if (tagged) blk: {
        const a_tag = if (a.tag_type) |tag| tag else std.meta.FieldEnum(A);
        const b_tag = if (b.tag_type) |tag| tag else std.meta.FieldEnum(B);

        break :blk enums.Merged(&.{ a_tag, b_tag }, true);
    } else null;

    return @Type(.{ .@"union" = info });
}

test MergedUnions {
    const expectEqualUnions = struct {
        fn expectEqualUnions(comptime A: type, comptime B: type) !void {
            const a = @typeInfo(A).@"union";
            const b = @typeInfo(B).@"union";

            inline for (a.fields, b.fields) |a_field, b_field| {
                try std.testing.expectEqualStrings(a_field.name, b_field.name);
                try std.testing.expectEqual(a_field.alignment, b_field.alignment);
                try std.testing.expectEqual(a_field.type, b_field.type);
            }

            inline for (a.decls, b.decls) |a_decl, b_decl|
                try std.testing.expectEqualStrings(a_decl.name, b_decl.name);

            if (a.tag_type != null and b.tag_type != null) {
                const a_tag = @typeInfo(a.tag_type.?).@"enum";
                const b_tag = @typeInfo(b.tag_type.?).@"enum";

                try std.testing.expectEqual(a_tag.tag_type, b_tag.tag_type);
            } else try std.testing.expect((a.tag_type == null) == (b.tag_type == null));

            try std.testing.expectEqual(a.layout, b.layout);
        }
    }.expectEqualUnions;

    const TagA = enum(u8) { a = 2 };
    const TagB = enum(u8) { b = 4 };

    try expectEqualUnions(
        union { a: u1, b: u2 },
        MergedUnions(
            union(TagA) { a: u1 },
            union(TagB) { b: u2 },
            false,
        ),
    );

    {
        const TagMerged = enum(u1) { a, b };

        try expectEqualUnions(
            union(TagMerged) { a: u1, b: u2 },
            MergedUnions(
                union(TagA) { a: u1 },
                union(TagB) { b: u2 },
                true,
            ),
        );
    }
}

pub fn MergedStructs(comptime A: type, comptime B: type) type {
    var info = @typeInfo(A).@"struct";
    info.decls = &.{};
    info.fields = info.fields ++ @typeInfo(B).@"struct".fields;
    return @Type(.{ .@"struct" = info });
}

test MergedStructs {
    comptime try std.testing.expectEqualDeep(
        @typeInfo(MergedStructs(
            struct {
                foo: u1,
                bar: u2,
            },
            struct {
                baz: u3,
            },
        )).@"struct",
        std.builtin.Type.Struct{
            .layout = .auto,
            .is_tuple = false,
            .decls = &.{},
            .fields = &.{
                .{ .name = "foo", .type = u1, .default_value_ptr = null, .is_comptime = false, .alignment = @alignOf(u1) },
                .{ .name = "bar", .type = u2, .default_value_ptr = null, .is_comptime = false, .alignment = @alignOf(u2) },
                .{ .name = "baz", .type = u3, .default_value_ptr = null, .is_comptime = false, .alignment = @alignOf(u3) },
            },
        },
    );
}

pub fn SubStruct(comptime T: type, comptime fields: std.enums.EnumSet(std.meta.FieldEnum(T))) type {
    var info = @typeInfo(T).@"struct";
    info.decls = &.{};
    info.fields = &.{};

    var fields_iter = fields.iterator();
    while (fields_iter.next()) |field|
        info.fields = info.fields ++ .{std.meta.fieldInfo(T, field)};

    return @Type(.{ .@"struct" = info });
}

test SubStruct {
    const T = struct { a: u1, b: u2, c: u3 };
    const Sub = SubStruct(T, std.enums.EnumSet(std.meta.FieldEnum(T)).initMany(&.{ .a, .c }));

    const sub_field_names = std.meta.fieldNames(Sub);
    try std.testing.expectEqual(2, sub_field_names.len);
    try std.testing.expectEqualStrings("a", sub_field_names[0]);
    try std.testing.expectEqualStrings("c", sub_field_names[1]);
}

pub fn WithoutDecls(comptime T: type) type {
    var info = @typeInfo(T);

    switch (info) {
        inline .@"struct", .@"enum", .@"union" => |*active_info| active_info.decls = &.{},
        inline else => |_, tag| @compileError(@tagName(tag) ++ " " ++ @typeName(T) ++ " cannot have declarations"),
    }

    return @Type(info);
}

test WithoutDecls {
    _ = WithoutDecls(struct {});
    _ = WithoutDecls(enum {});
    _ = WithoutDecls(union {});
    _ = WithoutDecls(union(enum) {});
}

pub fn FieldInfo(comptime T: type) type {
    return std.meta.Elem(@TypeOf(std.meta.fields(T)));
}

test FieldInfo {
    try std.testing.expectEqual(std.builtin.Type.StructField, FieldInfo(struct {}));
    try std.testing.expectEqual(std.builtin.Type.EnumField, FieldInfo(enum {}));
    try std.testing.expectEqual(std.builtin.Type.UnionField, FieldInfo(union {}));
    try std.testing.expectEqual(std.builtin.Type.Error, FieldInfo(error{}));
}

pub fn MapFields(comptime T: type, map: fn (FieldInfo(T)) FieldInfo(T)) type {
    var info = @typeInfo(T);
    switch (info) {
        .error_set => |*error_set| if (error_set.*) |errs| {
            var new_errs: [errs.len]std.builtin.Type.Error = undefined;
            for (errs, &new_errs) |err, *new_err| new_err.* = map(err);
            error_set.* = &new_errs;
        },
        inline else => |*i| {
            i.fields = &.{};
            for (std.meta.fields(T)) |field|
                i.fields = i.fields ++ [_]FieldInfo(T){map(field)};
        },
    }
    return @Type(info);
}

test MapFields {
    const fns = struct {
        fn simpleTest(comptime T: type) !void {
            const TMapped = MapFields(T, mapFn(T));
            try expectFieldNames(TMapped);
        }

        fn mapFn(comptime T: type) fn (FieldInfo(T)) FieldInfo(T) {
            return struct {
                fn map(field: FieldInfo(T)) FieldInfo(T) {
                    var f = field;
                    f.name = "foo_" ++ f.name;
                    return f;
                }
            }.map;
        }

        fn expectFieldNames(comptime T: type) !void {
            const field_names = std.meta.fieldNames(T);

            try std.testing.expectEqual(2, field_names.len);
            try std.testing.expectEqualStrings("foo_a", field_names[0]);
            try std.testing.expectEqualStrings("foo_b", field_names[1]);
        }
    };

    try fns.simpleTest(struct { a: u1, b: u2 });
    try fns.simpleTest(enum { a, b });
    try fns.simpleTest(error{ a, b });
    try fns.simpleTest(union { a: u1, b: u2 });
}

pub fn MapTaggedUnionFields(
    comptime T: type,
    map_field: fn (FieldInfo(T)) FieldInfo(T),
    map_tag_field: fn (FieldInfo(@typeInfo(T).@"union".tag_type.?)) FieldInfo(@typeInfo(T).@"union".tag_type.?),
) type {
    var info = @typeInfo(T).@"union";

    info.fields = &.{};
    for (std.meta.fields(T)) |field|
        info.fields = info.fields ++ [_]FieldInfo(T){map_field(field)};

    info.tag_type = MapFields(info.tag_type.?, map_tag_field);

    return @Type(.{ .@"union" = info });
}

test MapTaggedUnionFields {
    const Foo = union(enum) { a: u1, b: u2 };

    const fns = struct {
        fn map(field: FieldInfo(Foo)) FieldInfo(Foo) {
            var f = field;
            f.name = "foo_" ++ f.name;
            return f;
        }

        fn mapTag(field: FieldInfo(@typeInfo(Foo).@"union".tag_type.?)) FieldInfo(@typeInfo(Foo).@"union".tag_type.?) {
            var f = field;
            f.name = "foo_" ++ f.name;
            return f;
        }
    };

    const FooMapped = MapTaggedUnionFields(Foo, fns.map, fns.mapTag);

    const field_names = std.meta.fieldNames(FooMapped);

    try std.testing.expectEqual(2, field_names.len);
    try std.testing.expectEqualStrings("foo_a", field_names[0]);
    try std.testing.expectEqualStrings("foo_b", field_names[1]);
}

/// Raises the number of bits to the next power of two
/// if it is not a power of two already.
pub fn EnsurePowBits(comptime T: type, min: comptime_int) type {
    var info = @typeInfo(T).int;
    info.bits = std.math.ceilPowerOfTwoAssert(@TypeOf(info.bits), @max(min, info.bits));
    return @Type(.{ .int = info });
}

test EnsurePowBits {
    try std.testing.expectEqual(u8, EnsurePowBits(u0, 8));
    try std.testing.expectEqual(u8, EnsurePowBits(u8, 8));
}

pub fn ErrorSetExcluding(comptime ErrorSet: type, comptime errors: []const ErrorSet) type {
    if (@typeInfo(ErrorSet).error_set) |info| {
        var new_info: []const std.builtin.Type.Error = &.{};
        errors: inline for (info) |err| {
            for (errors) |excluded_err|
                if (std.mem.eql(u8, err.name, @errorName(excluded_err)))
                    continue :errors;
            new_info = new_info ++ .{err};
        }
        return @Type(.{ .error_set = new_info });
    } else if (errors.len != 0)
        @compileError("cannot exclude errors from an empty error set");
}

test ErrorSetExcluding {
    const E1 = error{ A, B, C };
    const E2 = ErrorSetExcluding(E1, &.{ error.A, error.C });

    const e2_tags = std.meta.tags(E2);

    try std.testing.expectEqual(1, e2_tags.len);
    try std.testing.expectEqual(error.B, e2_tags[0]);
}

pub fn FnErrorSet(comptime Fn: type) type {
    const info = @typeInfo(Fn).@"fn";
    const ret = info.return_type.?;
    const ret_info = @typeInfo(ret);
    return switch (ret_info) {
        .error_set => ret,
        .error_union => |error_union| error_union.error_set,
        else => @compileError(@typeName(Fn) ++ " does not return an error union or error set"),
    };
}

test FnErrorSet {
    try std.testing.expectEqual(error{Foo}, FnErrorSet(fn () error{Foo}));
    try std.testing.expectEqual(error{Foo}, FnErrorSet(fn () error{Foo}!void));
}

pub fn FnErrorUnionPayload(comptime Fn: type) type {
    return @typeInfo(@typeInfo(Fn).@"fn".return_type.?).error_union.payload;
}

test FnErrorUnionPayload {
    try std.testing.expectEqual(void, FnErrorUnionPayload(fn () error{Foo}!void));
}

pub fn LikeReceiver(
    comptime Object: type,
    comptime method: std.meta.DeclEnum(ChildOrelseSelf(Object)),
    comptime T: type,
) type {
    const Method = @TypeOf(@field(ChildOrelseSelf(Object), @tagName(method)));
    const Receiver = @typeInfo(Method).@"fn".params[0].type.?;
    return switch (@typeInfo(Receiver)) {
        .pointer => |pointer| t_pointer: {
            var t_pointer = pointer;
            t_pointer.child = T;
            t_pointer.alignment = @alignOf(T);
            break :t_pointer @Type(.{ .pointer = t_pointer });
        },
        else => T,
    };
}

test LikeReceiver {
    const Foo = struct {
        pub fn foo(_: @This()) void {}
        pub fn fooPtr(_: *@This()) void {}
        pub fn fooConstPtr(_: *const @This()) void {}
    };

    try std.testing.expectEqual(u0, LikeReceiver(Foo, .foo, u0));
    try std.testing.expectEqual(*u0, LikeReceiver(Foo, .fooPtr, u0));
    try std.testing.expectEqual(*const u0, LikeReceiver(Foo, .fooConstPtr, u0));
}

pub fn DropUfcsParam(comptime T: type) type {
    var fn_info = @typeInfo(T).@"fn";
    fn_info.params = fn_info.params[1..];
    return @Type(.{ .@"fn" = fn_info });
}

/// Dynamic dispatch with a context pointer.
pub fn Closure(comptime Func: type) type {
    const func_info = @typeInfo(Func).@"fn";
    return struct {
        context: *const anyopaque,
        func: *const FnWithContext(*const anyopaque),

        pub const Fn = Func;

        fn FnWithContext(Context: type) type {
            return @Type(.{ .@"fn" = blk: {
                var info = func_info;
                info.params = .{std.builtin.Type.Fn.Param{
                    .type = Context,
                    .is_generic = false,
                    .is_noalias = false,
                }} ++ info.params;
                break :blk info;
            } });
        }

        pub fn init(context: anytype, func: FnWithContext(@TypeOf(context))) @This() {
            if (@typeInfo(@TypeOf(context)) != .pointer)
                @compileError("context must be a pointer");

            return .{
                .context = context,
                .func = @ptrCast(&func),
            };
        }

        pub fn call(self: @This(), args: std.meta.ArgsTuple(Func)) func_info.return_type.? {
            return @call(.auto, self.func, .{self.context} ++ args);
        }
    };
}

pub fn closure(context: anytype, func: anytype) Closure(DropUfcsParam(@TypeOf(func))) {
    return Closure(DropUfcsParam(@TypeOf(func))).init(context, func);
}

test Closure {
    var count: usize = 0;

    var closed = closure(&count, struct {
        fn func(context: *usize, v: usize) void {
            context.* += v;
        }
    }.func);

    for (1..3) |i| {
        closed.call(.{1});
        try std.testing.expectEqual(@as(usize, i), count);
    }
}

/// Intended to make it easier to create interface functions.
/// Reduces boilerplate if you want one for each kind of backing type.
/// Works for both runtime and comptime interfaces.
/// Fails compilation if the interface implementation type
/// is not compatible with the caller's chosen kind of backing type.
///
/// ```zig
/// pub inline fn interface(self: anytype, comptime iface: IfaceCtx) Interface(iface.Type(@This())) {
///     return .{ .impl = iface.context(self) };
/// }
/// ```
pub const IfaceCtx = enum {
    ptr,
    const_ptr,
    copy,

    pub fn Type(self: @This(), T: type) type {
        return switch (self) {
            .ptr => *T,
            .const_ptr => *const T,
            .copy => T,
        };
    }

    pub inline fn context(
        comptime self: @This(),
        ctx: anytype,
    ) self.Type(ChildOrelseSelf(@TypeOf(ctx))) {
        return switch (self) {
            .ptr, .const_ptr => ctx,
            .copy => if (@typeInfo(@TypeOf(ctx)) == .pointer) ctx.* else ctx,
        };
    }
};
