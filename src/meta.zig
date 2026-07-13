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
    return @Tuple(types);
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

pub fn fieldTypes(T: type) [std.meta.fields(T).len]type {
    const fields = std.meta.fields(T);
    var field_types: [fields.len]type = undefined;
    for (&field_types, fields) |*field_type, field|
        field_type.* = field.type;
    return field_types;
}

test fieldTypes {
    comptime {
        try std.testing.expectEqualSlices(type, &.{ u1, u2 }, &fieldTypes(struct { a: u1, b: u2 }));
        try std.testing.expectEqualSlices(type, &.{ u1, u2 }, &fieldTypes(union { a: u1, b: u2 }));
        try std.testing.expectEqualSlices(type, &.{ u1, u2 }, &fieldTypes(union(enum) { a: u1, b: u2 }));
    }
}

pub fn fieldAttrs(T: type) [std.meta.fields(T).len]FieldInfo(T).Attributes {
    const fields = std.meta.fields(T);
    var field_attrs: [fields.len]FieldInfo(T).Attributes = undefined;
    inline for (&field_attrs, fields) |*field_attr, field| {
        field_attr.* = switch (@typeInfo(T)) {
            .@"struct" => .{
                .@"comptime" = field.is_comptime,
                .@"align" = field.alignment,
                .default_value_ptr = field.default_value_ptr,
            },
            .@"union" => .{
                .@"align" = field.alignment,
            },
            else => @compileError("unsupported type"),
        };
    }
    return field_attrs;
}

test fieldAttrs {
    try std.testing.expectEqualSlices(std.builtin.Type.StructField.Attributes, &.{ .{
        .@"comptime" = false,
        .default_value_ptr = null,
    }, .{
        .@"comptime" = false,
        .default_value_ptr = null,
    } }, &fieldAttrs(struct { a: u1, b: u2 }));
    try std.testing.expectEqualSlices(std.builtin.Type.UnionField.Attributes, &.{ .{}, .{} }, &fieldAttrs(union { a: u1, b: u2 }));
    try std.testing.expectEqualSlices(std.builtin.Type.UnionField.Attributes, &.{ .{}, .{} }, &fieldAttrs(union(enum) { a: u1, b: u2 }));
}

pub fn FieldsTuple(Struct: type) type {
    if (@typeInfo(Struct).@"struct".is_tuple) return Struct;
    return @Tuple(&fieldTypes(Struct));
}

test FieldsTuple {
    const Struct = struct {
        a: u8,
        b: bool,
    };
    const Tuple = FieldsTuple(Struct);

    try std.testing.expectEqual(@FieldType(Struct, "a"), @FieldType(Tuple, "0"));
    try std.testing.expectEqual(@FieldType(Struct, "b"), @FieldType(Tuple, "1"));
    try std.testing.expectEqual(2, @as(Tuple, undefined).len);
}

pub fn NamedArgs(Function: type, names: []const [:0]const u8) type {
    const params = @typeInfo(Function).@"fn".params;

    var field_names: [params.len][:0]const u8 = undefined;
    var field_types: [params.len]type = undefined;

    for (&field_names, &field_types, params, names) |*field_name, *field_type, param, name| {
        field_name.* = name;
        field_type.* = param.type orelse @compileError("`NamedArgs()` does not support generic parameters");
    }

    return @Struct(.auto, null, &field_names, &field_types, &@splat(.{}));
}

test NamedArgs {
    const Func = @TypeOf(struct {
        fn func(_: u1, _: u2, _: u3) void {}
    }.func);
    const NamedFuncArgs = NamedArgs(Func, &.{ "a", "b", "c" });

    try std.testing.expectEqual(@FieldType(NamedFuncArgs, "a"), @FieldType(std.meta.ArgsTuple(Func), "0"));
    try std.testing.expectEqual(@FieldType(NamedFuncArgs, "b"), @FieldType(std.meta.ArgsTuple(Func), "1"));
    try std.testing.expectEqual(@FieldType(NamedFuncArgs, "c"), @FieldType(std.meta.ArgsTuple(Func), "2"));
    try std.testing.expectEqual(3, @typeInfo(NamedFuncArgs).@"struct".fields.len);
}

pub fn SubUnion(comptime Union: type, comptime fields: []const std.meta.FieldEnum(Union)) type {
    const info = @typeInfo(Union).@"union";

    const tag_type = if (info.tag_type) |tt|
        enums.Sub(tt, fields)
    else
        null;

    var field_names: [fields.len][:0]const u8 = undefined;
    var field_types: [fields.len]type = undefined;

    for (&field_names, &field_types, fields) |*field_name, *field_type, field| {
        const field_info = std.meta.fieldInfo(Union, field);
        field_name.* = field_info.name;
        field_type.* = field_info.type;
    }

    return @Union(info.layout, tag_type, &field_names, &field_types, &@splat(.{}));
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

    return @Union(
        a.layout,
        if (tagged) blk: {
            const a_tag = if (a.tag_type) |tag| tag else std.meta.FieldEnum(A);
            const b_tag = if (b.tag_type) |tag| tag else std.meta.FieldEnum(B);

            break :blk enums.Merged(&.{ a_tag, b_tag }, true);
        } else null,
        std.meta.fieldNames(A) ++ std.meta.fieldNames(B),
        &(fieldTypes(A) ++ fieldTypes(B)),
        &@splat(.{}),
    );
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

pub fn MergedStructs(structs: []const type) type {
    switch (structs.len) {
        0 => @compileError("Cannot merge zero structs."),
        1 => return structs[0],
        else => {},
    }

    var fields_count = 0;
    for (structs) |strukt|
        fields_count += @typeInfo(strukt).@"struct".fields.len;

    var field_names: [fields_count][:0]const u8 = undefined;
    var field_types: [fields_count]type = undefined;
    var field_attrs: [fields_count]std.builtin.Type.StructField.Attributes = undefined;

    var field_idx = 0;
    for (structs) |strukt| {
        const strukt_field_names = std.meta.fieldNames(strukt);
        @memcpy(field_names[field_idx .. field_idx + strukt_field_names.len], strukt_field_names);

        const strukt_field_types = fieldTypes(strukt);
        @memcpy(field_types[field_idx .. field_idx + strukt_field_types.len], &strukt_field_types);

        const strukt_field_attrs = fieldAttrs(strukt);
        @memcpy(field_attrs[field_idx .. field_idx + strukt_field_types.len], &strukt_field_attrs);

        field_idx += @typeInfo(strukt).@"struct".fields.len;
    }

    const info = @typeInfo(structs[0]).@"struct";
    return @Struct(info.layout, info.backing_integer, &field_names, &field_types, &field_attrs);
}

test MergedStructs {
    comptime try std.testing.expectEqualDeep(
        std.builtin.Type.Struct{
            .layout = .auto,
            .is_tuple = false,
            .decls = &.{},
            .fields = &.{
                .{ .name = "foo", .type = u1, .default_value_ptr = null, .is_comptime = false, .alignment = null },
                .{ .name = "bar", .type = u2, .default_value_ptr = null, .is_comptime = false, .alignment = null },
                .{ .name = "baz", .type = u3, .default_value_ptr = null, .is_comptime = false, .alignment = null },
            },
        },
        @typeInfo(MergedStructs(&.{
            struct {
                foo: u1,
                bar: u2,
            },
            struct {
                baz: u3,
            },
        })).@"struct",
    );
}

pub fn SubStruct(comptime T: type, comptime fields: std.enums.EnumSet(std.meta.FieldEnum(T))) type {
    const info = @typeInfo(T).@"struct";

    var field_names: [fields.count()][:0]const u8 = undefined;
    var field_types: [fields.count()]type = undefined;
    var field_attrs: [fields.count()]std.builtin.Type.StructField.Attributes = undefined;

    var fields_iter = fields.iterator();
    var field_idx = 0;
    while (fields_iter.next()) |field| {
        defer field_idx += 1;

        const field_info = std.meta.fieldInfo(T, field);

        field_names[field_idx] = field_info.name;
        field_types[field_idx] = field_info.type;
        field_attrs[field_idx] = .{
            .@"comptime" = field_info.is_comptime,
            .@"align" = field_info.alignment,
            .default_value_ptr = field_info.default_value_ptr,
        };
    }

    return @Struct(info.layout, info.backing_integer, &field_names, &field_types, &field_attrs);
}

test SubStruct {
    const T = struct { a: u1, b: u2, c: u3 };
    const Sub = SubStruct(T, std.enums.EnumSet(std.meta.FieldEnum(T)).initMany(&.{ .a, .c }));

    const sub_field_names = std.meta.fieldNames(Sub);
    try std.testing.expectEqual(2, sub_field_names.len);
    try std.testing.expectEqualStrings("a", sub_field_names[0]);
    try std.testing.expectEqualStrings("c", sub_field_names[1]);
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
    return switch (@typeInfo(T)) {
        .@"struct" => |info| blk: {
            var field_names: [info.fields.len][:0]const u8 = undefined;
            var field_types: [info.fields.len]type = undefined;
            var field_attrs: [info.fields.len]std.builtin.Type.StructField.Attributes = undefined;

            for (&field_names, &field_types, &field_attrs, info.fields) |*field_name, *field_type, *field_attr, field_info| {
                const field_info_mapped = map(field_info);
                field_name.* = field_info_mapped.name;
                field_type.* = field_info_mapped.type;
                field_attr.* = .{
                    .@"comptime" = field_info_mapped.is_comptime,
                    .@"align" = field_info_mapped.alignment,
                    .default_value_ptr = field_info_mapped.default_value_ptr,
                };
            }

            break :blk if (info.is_tuple)
                @Tuple(&field_types)
            else
                @Struct(info.layout, info.backing_integer, &field_names, &field_types, &field_attrs);
        },
        .@"enum" => |info| blk: {
            var field_names: [info.fields.len][:0]const u8 = undefined;
            var field_values: [info.fields.len]info.tag_type = undefined;

            for (&field_names, &field_values, info.fields) |*field_name, *field_value, field_info| {
                const field_info_mapped = map(field_info);
                field_name.* = field_info_mapped.name;
                field_value.* = field_info_mapped.value;
            }

            break :blk @Enum(info.tag_type, if (info.is_exhaustive) .exhaustive else .nonexhaustive, &field_names, &field_values);
        },
        .@"union" => |info| blk: {
            var field_names: [info.fields.len][:0]const u8 = undefined;
            var field_types: [info.fields.len]type = undefined;
            var field_attrs: [info.fields.len]std.builtin.Type.UnionField.Attributes = undefined;

            for (&field_names, &field_types, &field_attrs, info.fields) |*field_name, *field_type, *field_attr, field_info| {
                const field_info_mapped = map(field_info);
                field_name.* = field_info_mapped.name;
                field_type.* = field_info_mapped.type;
                field_attr.* = .{
                    .@"align" = field_info_mapped.alignment,
                };
            }

            break :blk @Union(info.layout, info.tag_type, &field_names, &field_types, &field_attrs);
        },
        else => @compileError("unsupported type"),
    };
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
    try fns.simpleTest(union { a: u1, b: u2 });
}

pub fn MapTaggedUnionFields(
    comptime T: type,
    map_field: fn (FieldInfo(T)) FieldInfo(T),
    map_tag_field: fn (FieldInfo(@typeInfo(T).@"union".tag_type.?)) FieldInfo(@typeInfo(T).@"union".tag_type.?),
) type {
    const info = @typeInfo(T).@"union";

    var field_names: [info.fields.len][:0]const u8 = undefined;
    var field_types: [info.fields.len]type = undefined;
    var field_attrs: [info.fields.len]std.builtin.Type.UnionField.Attributes = undefined;
    for (&field_names, &field_types, &field_attrs, info.fields) |*field_name, *field_type, *field_attr, field_info| {
        const field_info_mapped = map_field(field_info);
        field_name.* = field_info_mapped.name;
        field_type.* = field_info_mapped.type;
        field_attr.* = .{
            .@"align" = field_info_mapped.alignment,
        };
    }

    return @Union(info.layout, MapFields(info.tag_type.?, map_tag_field), &field_names, &field_types, &field_attrs);
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
    const info = @typeInfo(T).int;
    return @Int(
        info.signedness,
        std.math.ceilPowerOfTwoAssert(@TypeOf(info.bits), @max(min, info.bits)),
    );
}

test EnsurePowBits {
    try std.testing.expectEqual(u8, EnsurePowBits(u0, 8));
    try std.testing.expectEqual(u8, EnsurePowBits(u8, 8));
}

pub fn eqlErrorSets(A: type, B: type) bool {
    if (A == B) return true;

    const as = std.meta.tags(A);
    const bs = std.meta.tags(B);

    if (as.len != bs.len) return false;

    for (as, bs) |a, b|
        if (a != b) return false;
    return true;
}

test eqlErrorSets {
    try std.testing.expect(eqlErrorSets(error{}, error{}));
    try std.testing.expect(eqlErrorSets(error{A}, error{A}));
    try std.testing.expect(eqlErrorSets(error{ A, B }, error{ A, B }));
    try std.testing.expect(eqlErrorSets(error{ A, B }, error{ B, A }));

    try std.testing.expect(!eqlErrorSets(error{}, error{A}));
    try std.testing.expect(!eqlErrorSets(error{A}, error{ A, B }));
    try std.testing.expect(!eqlErrorSets(error{A}, error{B}));
}

pub fn errorSetContains(ErrorSet: type, err: anyerror) bool {
    inline for (@typeInfo(ErrorSet).error_set.?) |member|
        if (@field(ErrorSet, member.name) == err) return true;
    return false;
}

test errorSetContains {
    const E = error{ A, B };

    try std.testing.expect(errorSetContains(E, error.A));
    try std.testing.expect(errorSetContains(E, error.B));
    try std.testing.expect(!errorSetContains(E, error.C));
}

pub fn ErrorSetExcluding(ErrorSet: type, excluded: ErrorSet) type {
    const Foo = struct {
        fn throw() ErrorSet!void {}

        fn excluding() !void {
            return throw() catch |err| switch (err) {
                excluded => {},
                else => |e| e,
            };
        }
    };

    return FnErrorSet(@TypeOf(Foo.excluding));
}

test ErrorSetExcluding {
    try std.testing.expect(eqlErrorSets(error{ A, C }, ErrorSetExcluding(error{ A, B, C }, error.B)));
}

pub fn SubErrorSet(ErrorSet: type, ExcludedErrorSet: type) type {
    if (ErrorSet == ExcludedErrorSet) return error{};

    const excluded = std.meta.tags(ExcludedErrorSet);

    // not needed but hopefully saves comptime branches
    switch (excluded.len) {
        0 => return ErrorSet,
        1 => return ErrorSetExcluding(ErrorSet, excluded[0]),
        else => {},
    }

    var steps: [excluded.len + 1]type = undefined;
    steps[0] = ErrorSet;
    for (steps[0 .. steps.len - 1], steps[1..], excluded) |prev, *curr, tag|
        curr.* = if (errorSetContains(ErrorSet, tag))
            ErrorSetExcluding(prev, @errorCast(tag))
        else
            prev;

    return steps[steps.len - 1];
}

test SubErrorSet {
    const E = error{ A, B, C };

    try std.testing.expect(eqlErrorSets(error{ A, C }, SubErrorSet(E, error{ B, D })));
    try std.testing.expect(eqlErrorSets(error{C}, SubErrorSet(E, error{ A, B, D })));

    try std.testing.expectEqual(E, SubErrorSet(E, error{}));
    try std.testing.expectEqual(error{}, SubErrorSet(error{}, E));
    try std.testing.expectEqual(error{}, SubErrorSet(E, E));
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
        .pointer => |pointer| @Pointer(
            pointer.size,
            .{
                .@"const" = pointer.is_const,
                .@"volatile" = pointer.is_volatile,
                .@"allowzero" = pointer.is_allowzero,
                .@"addrspace" = pointer.address_space,
            },
            T,
            null,
        ),
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
    const info = @typeInfo(T).@"fn";

    var param_types: [info.params.len - 1]type = undefined;
    var param_attrs: [info.params.len - 1]std.builtin.Type.Fn.Param.Attributes = undefined;
    for (&param_types, &param_attrs, info.params[1..]) |*param_type, *param_attr, param_info| {
        param_type.* = param_info.type orelse @compileError("Generic parameters not supported");
        param_attr.* = .{ .@"noalias" = param_info.is_noalias };
    }

    return @Fn(&param_types, &param_attrs, info.return_type orelse @compileError("Generic return types not supported"), .{
        .@"callconv" = info.calling_convention,
        .varargs = info.is_var_args,
    });
}

/// Dynamic dispatch with a context pointer.
pub fn Closure(comptime Func: type) type {
    const func_info = @typeInfo(Func).@"fn";
    return struct {
        context: *anyopaque,
        func: *const FnWithContext(*anyopaque),

        pub const Fn = Func;

        fn FnWithContext(Context: type) type {
            var param_types: [func_info.params.len + 1]type = undefined;
            var param_attrs: [func_info.params.len + 1]std.builtin.Type.Fn.Param.Attributes = undefined;

            param_types[0] = Context;
            param_attrs[0] = .{};

            for (param_types[1..], param_attrs[1..], func_info.params) |*param_type, *param_attr, param_info| {
                param_type.* = param_info.type orelse @compileError("Generic parameters not supported");
                param_attr.* = .{ .@"noalias" = param_info.is_noalias };
            }

            return @Fn(&param_types, &param_attrs, func_info.return_type orelse @compileError("Generic return types not supported"), .{
                .@"callconv" = func_info.calling_convention,
                .varargs = func_info.is_var_args,
            });
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
    return .init(context, func);
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

test {
    std.testing.refAllDecls(@This());
}
