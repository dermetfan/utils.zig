const std = @import("std");
const trait = @import("trait");

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

pub fn AnyAsBytesUnpad(Any: type) type {
    return if (trait.ptrQualifiedWith(.@"const")(Any)) []const u8 else []u8;
}

pub fn anyAsBytesUnpad(any: anytype) AnyAsBytesUnpad(@TypeOf(any)) {
    const Any = @TypeOf(any);
    if (comptime trait.is(.Null)(Any) or trait.is(.Void)(Any)) return &.{};
    const bytes = if (comptime trait.ptrOfSize(.Slice)(Any)) std.mem.sliceAsBytes(any) else std.mem.asBytes(any);
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
