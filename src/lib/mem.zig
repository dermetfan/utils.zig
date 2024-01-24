const std = @import("std");
const trait = @import("trait");

pub fn AnyAsBytesUnpad(Any: type) type {
    return if (trait.ptrQualifiedWith(.@"const")(Any)) []const u8 else []u8;
}

pub fn anyAsBytesUnpad(any: anytype) AnyAsBytesUnpad(@TypeOf(any)) {
    const Any = @TypeOf(any);
    if (comptime Any == @TypeOf(null)) return &.{};
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
