const std = @import("std");

// Divisions of a byte.
pub const b_per_kib = 1024;
pub const b_per_mib = 1024 * b_per_kib;
pub const b_per_gib = 1024 * b_per_mib;
pub const b_per_tib = 1024 * b_per_gib;

// Divisions of a KiB.
pub const kib_per_mib = 1024;
pub const kib_per_gib = 1024 * kib_per_mib;
pub const kib_per_tib = 1024 * kib_per_gib;

// Divisions of a MiB.
pub const mib_per_gib = 1024;
pub const mib_per_tib = 1024 * mib_per_gib;

// Divisions of a GiB.
pub const gib_per_tib = 1024;

// Divisions of a byte.
pub const b_per_kb = 1000;
pub const b_per_mb = 1000 * b_per_kb;
pub const b_per_gb = 1000 * b_per_mb;
pub const b_per_tb = 1000 * b_per_gb;

// Divisions of a KB.
pub const kb_per_mb = 1000;
pub const kb_per_gb = 1000 * kb_per_mb;
pub const kb_per_tb = 1000 * kb_per_gb;

// Divisions of a MB.
pub const mb_per_gb = 1000;
pub const mb_per_tb = 1000 * mb_per_gb;

// Divisions of a GB.
pub const gb_per_tb = 1000;

pub const CapFrom = enum { start, end };

pub fn cap(comptime T: type, slice: []T, max_len: usize, from: CapFrom) []T {
    if (max_len >= slice.len) return slice;
    return switch (from) {
        .start => slice[slice.len - max_len ..],
        .end => slice[0..max_len],
    };
}

pub fn capConst(comptime T: type, slice: []const T, max_len: usize, from: CapFrom) []const T {
    return cap(T, @constCast(slice), max_len, from);
}

test cap {
    try std.testing.expectEqualStrings("abc", cap(u8, @constCast("abcde"), 3, .end));
    try std.testing.expectEqualStrings("cde", cap(u8, @constCast("abcde"), 3, .start));
}

test capConst {
    try std.testing.expectEqualStrings("abc", capConst(u8, "abcde", 3, .end));
    try std.testing.expectEqualStrings("cde", capConst(u8, "abcde", 3, .start));
}

pub fn AnyAsBytesUnpad(Any: type) type {
    return if (switch (@typeInfo(Any)) {
        .pointer => |pointer| pointer.is_const,
        else => false,
    }) []const u8 else []u8;
}

pub fn anyAsBytesUnpad(any: anytype) AnyAsBytesUnpad(@TypeOf(any)) {
    const Any = @TypeOf(any);
    if (comptime switch (@typeInfo(Any)) {
        .null, .void => true,
        else => false,
    }) return &.{};
    const bytes = if (comptime switch (@typeInfo(Any)) {
        .pointer => |pointer| pointer.size == .slice,
        else => false,
    }) std.mem.sliceAsBytes(any) else std.mem.asBytes(any);
    return bytes[0 .. bytes.len - paddingOf(std.meta.Child(Any))];
}

test anyAsBytesUnpad {
    try std.testing.expectEqualSlices(u8, switch (@import("builtin").cpu.arch.endian()) {
        .little => "\x11\x00\x00\x00\x12\x00\x00",
        .big => "\x00\x00\x11\x00\x00\x00\x12",
    }, anyAsBytesUnpad(@as([]const u17, &.{ 17, 18 })));

    try std.testing.expectEqualSlices(u8, &.{}, anyAsBytesUnpad(null));
}

/// Like `@sizeOf()` without padding.
pub fn sizeOfUnpad(comptime T: type) comptime_int {
    return std.math.divCeil(comptime_int, @bitSizeOf(T), 8) catch unreachable;
}

test sizeOfUnpad {
    try std.testing.expectEqual(@as(usize, 0), sizeOfUnpad(u0));
    try std.testing.expectEqual(@as(usize, 1), sizeOfUnpad(u8));
    try std.testing.expectEqual(@as(usize, 2), sizeOfUnpad(u16));
    try std.testing.expectEqual(@as(usize, 3), sizeOfUnpad(u17));
    try std.testing.expectEqual(@as(usize, 3), sizeOfUnpad(u23));
    try std.testing.expectEqual(@as(usize, 3), sizeOfUnpad(u24));
    try std.testing.expectEqual(@as(usize, 4), sizeOfUnpad(u25));
    try std.testing.expectEqual(@as(usize, 4), sizeOfUnpad(u32));
    try std.testing.expectEqual(@as(usize, 5), sizeOfUnpad(u33));
}

pub fn paddingOf(comptime T: type) comptime_int {
    return @sizeOf(T) - sizeOfUnpad(T);
}

test paddingOf {
    try std.testing.expectEqual(@as(usize, 0), paddingOf(u8));
    try std.testing.expectEqual(@as(usize, 0), paddingOf(u16));
    try std.testing.expectEqual(@as(usize, 1), paddingOf(u17));
    try std.testing.expectEqual(@as(usize, 1), paddingOf(u24));
    try std.testing.expectEqual(@as(usize, 0), paddingOf(u25));
    try std.testing.expectEqual(@as(usize, 0), paddingOf(u32));
    try std.testing.expectEqual(@as(usize, 3), paddingOf(u33));
}

pub fn copySlicesForwards(comptime T: type, dest: []T, sources: []const []const T) void {
    var i: usize = 0;
    for (sources) |source| {
        std.mem.copyForwards(T, dest[i .. i + source.len], source);
        i += source.len;
    }
}

test copySlicesForwards {
    var dest: [10]u8 = undefined;
    copySlicesForwards(u8, &dest, &.{ "01234", "56789" });
    try std.testing.expectEqualStrings("0123456789", &dest);
}

pub fn comptimeJoin(comptime strs: []const []const u8, comptime sep: []const u8) []const u8 {
    comptime var result: []const u8 = "";
    inline for (strs, 0..) |str, i| {
        result = result ++ str;
        if (i + 1 < strs.len) result = result ++ sep;
    }
    return result;
}

test comptimeJoin {
    try std.testing.expectEqualStrings(
        \\a, b, c
    , comptimeJoin(&.{ "a", "b", "c" }, ", "));
    try std.testing.expectEqualStrings(
        \\a
    , comptimeJoin(&.{"a"}, ", "));
}

pub fn Cloned(comptime T: type) type {
    return struct {
        arena: *std.heap.ArenaAllocator,
        value: T,

        pub fn deinit(self: @This()) void {
            const allocator = self.arena.child_allocator;
            self.arena.deinit();
            allocator.destroy(self.arena);
        }

        pub fn init(allocator: std.mem.Allocator) !@This() {
            return .{
                .arena = arena: {
                    const arena_ptr = try allocator.create(std.heap.ArenaAllocator);
                    errdefer allocator.destroy(arena_ptr);

                    arena_ptr.* = std.heap.ArenaAllocator.init(allocator);

                    break :arena arena_ptr;
                },
                .value = undefined,
            };
        }
    };
}

pub fn clone(allocator: std.mem.Allocator, obj: anytype) std.mem.Allocator.Error!Cloned(@TypeOf(obj)) {
    var cloned = try Cloned(@TypeOf(obj)).init(allocator);
    errdefer cloned.deinit();

    cloned.value = try cloneLeaky(cloned.arena.allocator(), obj);

    return cloned;
}

test clone {
    (try clone(std.testing.allocator, std.Uri{
        .scheme = "http",
        .host = .{ .raw = "example.com" },
        .port = 8080,
    })).deinit();
}

pub fn cloneLeaky(allocator: std.mem.Allocator, obj: anytype) std.mem.Allocator.Error!@TypeOf(obj) {
    const Obj = @TypeOf(obj);
    return switch (@typeInfo(Obj)) {
        .pointer => |pointer| switch (pointer.size) {
            .one, .c => ptr: {
                const ptr = try allocator.create(pointer.child);
                ptr.* = try cloneLeaky(allocator, obj.*);
                break :ptr ptr;
            },
            .slice => slice: {
                const slice = try allocator.alloc(pointer.child, obj.len);
                for (slice, obj) |*dst, src|
                    dst.* = try cloneLeaky(allocator, src);
                break :slice slice;
            },
            .many => @compileError("cannot clone many-item pointer"),
        },
        .array => array: {
            const array: Obj = undefined;
            for (&array, obj) |*dst, src|
                dst.* = try cloneLeaky(allocator, src);
            break :array array;
        },
        .optional => if (obj) |child| @as(Obj, try cloneLeaky(allocator, child)) else null,
        .int, .float, .vector, .@"enum", .bool => obj,
        .@"union" => switch (obj) {
            inline else => |value, tag| @unionInit(Obj, @tagName(tag), try cloneLeaky(allocator, value)),
        },
        .@"struct" => |strukt| strukt: {
            var cloned: Obj = undefined;
            inline for (strukt.fields) |field|
                @field(cloned, field.name) = try cloneLeaky(allocator, @field(obj, field.name));
            break :strukt cloned;
        },
        else => if (@bitSizeOf(Obj) == 0)
            undefined
        else
            @compileError("cannot clone comptime-only type " ++ @typeName(Obj)),
    };
}
