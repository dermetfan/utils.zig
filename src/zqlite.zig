const root = @import("root");
const std = @import("std");
const trait = @import("trait");
const zqlite = @import("zqlite");

const fmt = @import("fmt.zig");
const mem = @import("mem.zig");
const meta = @import("meta.zig");

pub const Options = struct {
    log_scope: @TypeOf(.EnumLiteral) = .@"utils/zqlite",
    logErr: fn (err: anyerror, conn: zqlite.Conn, args: anytype) void = logErrDefault,

    fn logErrDefault(err: anyerror, conn: zqlite.Conn, args: anytype) void {
        const sql: []const u8 = args.@"0";
        log.err("{s}: {s}. Statement: {s}", .{ @errorName(err), conn.lastError(), fmt.fmtOneline(sql) });
    }
};

pub const options: Options = if (@hasDecl(root, "utils_zqlite_options")) root.utils_zqlite_options else .{};

pub const log = std.log.scoped(options.log_scope);

pub fn logErr(conn: zqlite.Conn, comptime func_name: std.meta.DeclEnum(zqlite.Conn), args: anytype) zqlite.Error!(blk: {
    const func = @field(zqlite.Conn, @tagName(func_name));
    const func_info = @typeInfo(@TypeOf(func)).Fn;
    break :blk @typeInfo(func_info.return_type.?).ErrorUnion.payload;
}) {
    const func = @field(zqlite.Conn, @tagName(func_name));
    return if (@call(.auto, func, .{conn} ++ args)) |result| result else |err| err: {
        options.logErr(err, conn, args);
        break :err err;
    };
}

pub fn MergedTables(
    comptime a_qualification: ?[]const u8,
    comptime A: type,
    comptime b_qualification: ?[]const u8,
    comptime B: type,
) type {
    const mapFn = struct {
        fn mapFn(comptime table: []const u8, comptime T: type) fn (meta.FieldInfo(T)) meta.FieldInfo(T) {
            return struct {
                fn map(field: meta.FieldInfo(T)) meta.FieldInfo(T) {
                    var f = field;
                    f.name = table ++ "." ++ f.name;
                    return f;
                }
            }.map;
        }
    }.mapFn;

    return meta.MergedStructs(
        if (a_qualification) |qualification| meta.MapFields(A, mapFn(qualification, A)) else A,
        if (b_qualification) |qualification| meta.MapFields(B, mapFn(qualification, B)) else B,
    );
}

test MergedTables {
    const TableA = struct {
        foo: []const u8,
        bar: zqlite.Blob,
    };
    const TableB = struct {
        foo: []const u8,
        baz: zqlite.Blob,
    };

    {
        const TableMerged = MergedTables("a", TableA, "b", TableB);
        const column_names = std.meta.tags(std.meta.FieldEnum(TableMerged));

        try std.testing.expectEqual(4, column_names.len);
        try std.testing.expectEqual(.@"a.foo", column_names[0]);
        try std.testing.expectEqual(.@"a.bar", column_names[1]);
        try std.testing.expectEqual(.@"b.foo", column_names[2]);
        try std.testing.expectEqual(.@"b.baz", column_names[3]);
    }

    {
        const TableMerged = MergedTables(null, TableA, "b", TableB);
        const column_names = std.meta.tags(std.meta.FieldEnum(TableMerged));

        try std.testing.expectEqual(4, column_names.len);
        try std.testing.expectEqual(.foo, column_names[0]);
        try std.testing.expectEqual(.bar, column_names[1]);
        try std.testing.expectEqual(.@"b.foo", column_names[2]);
        try std.testing.expectEqual(.@"b.baz", column_names[3]);
    }
}

pub fn Query(comptime sql: []const u8, comptime multi: bool, comptime Row: type, comptime Values_: type) type {
    return struct {
        pub const Column = std.meta.FieldEnum(Row);
        pub const Values = Values_;

        fn GetterResult(comptime Result: type) type {
            return switch (Result) {
                zqlite.Blob => []const u8,
                ?zqlite.Blob => ?[]const u8,
                else => Result,
            };
        }

        fn getter(comptime Result: type) fn (zqlite.Row, usize) GetterResult(Result) {
            return switch (Result) {
                bool => zqlite.Row.boolean,
                ?bool => zqlite.Row.nullableBoolean,

                i64 => zqlite.Row.int,
                ?i64 => zqlite.Row.nullableInt,

                f64 => zqlite.Row.float,
                ?f64 => zqlite.Row.nullableFloat,

                []const u8 => zqlite.Row.text,
                ?[]const u8 => zqlite.Row.nullableText,

                [*:0]const u8 => zqlite.Row.textZ,
                ?[*:0]const u8 => zqlite.Row.nullableTextZ,
                usize => zqlite.Row.textLen,

                zqlite.Blob => zqlite.Row.blob,
                ?zqlite.Blob => zqlite.Row.nullableBlob,

                else => @compileError("There is no zqlite getter for type '" ++ @typeName(Result) ++ "'"),
            };
        }

        fn column(result: zqlite.Row, comptime col: Column) GetterResult(std.meta.FieldType(Row, col)) {
            const info = std.meta.fieldInfo(Row, col);
            const index = std.meta.fieldIndex(Row, info.name).?;
            return getter(info.type)(result, index);
        }

        pub usingnamespace if (multi) struct {
            fn rows(conn: zqlite.Conn, values: Values) !zqlite.Rows {
                return logErr(conn, .rows, .{ sql, values });
            }

            pub const Rows = struct {
                zqlite_rows: zqlite.Rows,
                allocator: std.mem.Allocator,

                pub fn deinit(self: @This()) void {
                    self.zqlite_rows.deinit();
                }

                pub fn deinitErr(self: @This()) !void {
                    try self.zqlite_rows.deinitErr();
                }

                pub fn next(self: *@This()) !?Row {
                    if (self.zqlite_rows.next()) |zqlite_row| {
                        var typed_row: Row = undefined;
                        try structFromRow(self.allocator, &typed_row, zqlite_row, column);

                        return typed_row;
                    }
                    return null;
                }

                /// Consumes this so `deinit()` or `deinitErr()` no longer have to be called.
                pub fn toOwnedSlice(self: *@This()) ![]Row {
                    errdefer self.deinit();

                    var typed_rows = std.ArrayListUnmanaged(Row){};
                    errdefer {
                        for (typed_rows.items) |typed_row| freeStructFromRow(Row, self.allocator, typed_row);
                        typed_rows.deinit(self.allocator);
                    }

                    while (try self.next()) |typed_row|
                        (typed_rows.addOne(self.allocator) catch |err| {
                            freeStructFromRow(Row, self.allocator, typed_row);
                            return err;
                        }).* = typed_row;

                    try self.deinitErr();

                    return typed_rows.toOwnedSlice(self.allocator);
                }
            };

            pub fn queryIterator(allocator: std.mem.Allocator, conn: zqlite.Conn, values: Values) !Rows {
                return .{
                    .zqlite_rows = try rows(conn, values),
                    .allocator = allocator,
                };
            }

            pub fn query(allocator: std.mem.Allocator, conn: zqlite.Conn, values: Values) ![]Row {
                var iter = try queryIterator(allocator, conn, values);
                return iter.toOwnedSlice();
            }
        } else struct {
            fn row(conn: zqlite.Conn, values: Values) !?zqlite.Row {
                return logErr(conn, .row, .{ sql, values });
            }

            pub fn query(allocator: std.mem.Allocator, conn: zqlite.Conn, values: Values) !?Row {
                const zqlite_row = try row(conn, values) orelse return null;
                errdefer zqlite_row.deinit();

                var typed_row: Row = undefined;
                try structFromRow(allocator, &typed_row, zqlite_row, column);
                errdefer freeStructFromRow(Row, allocator, typed_row);

                try zqlite_row.deinitErr();

                return typed_row;
            }
        };
    };
}

test Query {
    {
        const Q = Query("SELECT a, b, c, d, e, f, g, h, i, j, k, l, m FROM foo", false, struct {
            a: bool,
            b: ?bool,
            c: i64,
            d: ?i64,
            e: f64,
            f: ?f64,
            g: []const u8,
            h: ?[]const u8,
            i: [*:0]const u8,
            j: ?[*:0]const u8,
            k: usize,
            l: zqlite.Blob,
            m: ?zqlite.Blob,
        }, struct {});

        try std.testing.expectEqual(bool, @TypeOf(Q.column(undefined, .a)));
        try std.testing.expectEqual(?bool, @TypeOf(Q.column(undefined, .b)));
        try std.testing.expectEqual(i64, @TypeOf(Q.column(undefined, .c)));
        try std.testing.expectEqual(?i64, @TypeOf(Q.column(undefined, .d)));
        try std.testing.expectEqual(f64, @TypeOf(Q.column(undefined, .e)));
        try std.testing.expectEqual(?f64, @TypeOf(Q.column(undefined, .f)));
        try std.testing.expectEqual([]const u8, @TypeOf(Q.column(undefined, .g)));
        try std.testing.expectEqual(?[]const u8, @TypeOf(Q.column(undefined, .h)));
        try std.testing.expectEqual([*:0]const u8, @TypeOf(Q.column(undefined, .i)));
        try std.testing.expectEqual(?[*:0]const u8, @TypeOf(Q.column(undefined, .j)));
        try std.testing.expectEqual(usize, @TypeOf(Q.column(undefined, .k)));
        try std.testing.expectEqual([]const u8, @TypeOf(Q.column(undefined, .l)));
        try std.testing.expectEqual(?[]const u8, @TypeOf(Q.column(undefined, .m)));
    }

    {
        const Row = struct {};
        const Q = Query("", false, Row, struct {});
        try std.testing.expectEqualDeep(@typeInfo(@typeInfo(@typeInfo(@TypeOf(Q.query)).Fn.return_type.?).ErrorUnion.payload), @typeInfo(?Row));
    }

    {
        const Row = struct {};
        const Q = Query("", true, Row, struct {});
        try std.testing.expectEqualDeep(@typeInfo(std.meta.Elem(@typeInfo(@typeInfo(@TypeOf(Q.query)).Fn.return_type.?).ErrorUnion.payload)), @typeInfo(Row));
    }
}

pub fn Exec(comptime sql: []const u8, comptime Values_: type) type {
    const Q = Query(sql, false, struct {}, Values_);

    return struct {
        pub const Values = Q.Values;

        pub usingnamespace if (@typeInfo(Values).Struct.fields.len == 0) struct {
            pub fn execNoArgs(conn: zqlite.Conn) !void {
                return logErr(conn, .execNoArgs, .{sql});
            }
        } else struct {
            pub fn exec(conn: zqlite.Conn, values: Values) !void {
                return logErr(conn, .exec, .{ sql, values });
            }
        };
    };
}

test Exec {
    {
        const E = Exec("", struct { a: u0 });
        try std.testing.expect(std.meta.hasFn(E, "exec"));
        try std.testing.expect(!std.meta.hasFn(E, "execNoArgs"));
    }

    {
        const E = Exec("", struct {});
        try std.testing.expect(std.meta.hasFn(E, "execNoArgs"));
        try std.testing.expect(!std.meta.hasFn(E, "exec"));
    }
}

pub fn SimpleInsert(comptime table: []const u8, comptime Column: type) type {
    return Exec(
        \\INSERT INTO "
    ++ table ++
        \\" (
    ++ columnList(null, std.meta.fieldNames(Column)) ++
        \\) VALUES (
    ++ "?, " ** (std.meta.fields(Column).len - 1) ++ "?" ++
        \\)
    , meta.FieldsTuple(Column));
}

pub fn columnList(comptime table: ?[]const u8, comptime columns: anytype) []const u8 {
    comptime var selects: [columns.len][]const u8 = undefined;
    inline for (columns, &selects) |column, *select| {
        const column_name = if (trait.isZigString(@TypeOf(column))) column else @tagName(column);
        select.* = "\"" ++ column_name ++ "\"";
        if (table) |t| select.* = "\"" ++ t ++ "\"." ++ select.*;
    }
    return comptime mem.comptimeJoin(&selects, ", ");
}

test columnList {
    try std.testing.expectEqualStrings(
        \\"foo", "bar", "baz"
    , columnList(null, .{ .foo, .bar, .baz }));

    {
        const expected =
            \\"a"."foo", "a"."bar", "a"."baz"
        ;
        try std.testing.expectEqualStrings(expected, columnList("a", .{ .foo, .bar, .baz }));
        try std.testing.expectEqualStrings(expected, columnList("a", .{ "foo", "bar", "baz" }));
    }
}

pub fn structFromRow(
    allocator: std.mem.Allocator,
    target_ptr: anytype,
    row: zqlite.Row,
    column_fn: anytype,
) !void {
    const Target = std.meta.Child(@TypeOf(target_ptr));
    const target: *Target = @ptrCast(target_ptr);

    const fields = comptime std.enums.values(std.meta.FieldEnum(Target));

    var clone_ctx = struct {
        allocator: std.mem.Allocator,

        allocated_mem: [fields.len][]const u8 = undefined,
        allocated: usize = 0,
        allocated_mem_z: [fields.len][:0]const u8 = undefined,
        allocated_z: usize = 0,

        fn deinit(self: *@This()) void {
            for (self.allocated_mem[0..self.allocated]) |slice| self.allocator.free(slice);
            for (self.allocated_mem_z[0..self.allocated_z]) |slice_z| self.allocator.free(slice_z);
        }

        fn clone(self: *@This(), comptime T: type, value: anytype) std.mem.Allocator.Error!T {
            return switch (@typeInfo(T)) {
                .Pointer => |pointer| pointer: {
                    const cloned = if (pointer.sentinel == null) blk: {
                        const slice = try self.allocator.dupe(pointer.child, value);
                        self.allocated_mem[self.allocated] = slice;
                        self.allocated += 1;
                        break :blk slice;
                    } else blk: {
                        const slice_z = try self.allocator.dupeZ(pointer.child, value);
                        self.allocated_mem_z[self.allocated_z] = slice_z;
                        self.allocated_z += 1;
                        break :blk slice_z;
                    };

                    break :pointer switch (pointer.size) {
                        .Slice => cloned,
                        .Many => cloned.ptr,
                        else => @compileError("unsupported pointer size"),
                    };
                },

                .Optional => |optional| if (value) |v| try self.clone(optional.child, v) else null,

                else => switch (T) {
                    zqlite.Blob => .{ .value = try self.clone(std.meta.FieldType(T, .value), value) },
                    else => value,
                },
            };
        }
    }{ .allocator = allocator };
    errdefer clone_ctx.deinit();

    inline for (fields) |field| {
        const value = column_fn(row, field);

        const target_field = &@field(target, @tagName(field));
        const TargetField = @TypeOf(target_field.*);

        target_field.* = try clone_ctx.clone(TargetField, value);
    }
}

pub fn freeStructFromRow(comptime Row: type, allocator: std.mem.Allocator, row: Row) void {
    const free = struct {
        fn free(alloc: std.mem.Allocator, value: anytype) void {
            const Value = @TypeOf(value);

            switch (@typeInfo(Value)) {
                .Pointer => |pointer| alloc.free(switch (pointer.size) {
                    .Slice => value,
                    .Many => if (pointer.sentinel != null)
                        std.mem.span(value)
                    else
                        @compileError("many-item pointers only supported with sentinel"),
                    else => @compileError("unsupported pointer size"),
                }),

                .Optional => if (value) |v| free(alloc, v),

                else => switch (Value) {
                    zqlite.Blob => alloc.free(value.value),
                    else => {},
                },
            }
        }
    }.free;

    inline for (@typeInfo(Row).Struct.fields) |field| {
        const field_value = @field(row, field.name);

        free(allocator, field_value);
    }
}
