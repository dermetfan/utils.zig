const std = @import("std");

const meta = @import("meta.zig");

pub fn Merged(comptime enums: []const type, comptime reindex: bool) type {
    var tag_int = std.builtin.Type.Int{
        .signedness = .unsigned,
        .bits = 0,
    };
    var fields: []const std.builtin.Type.EnumField = &.{};
    var decls: []const std.builtin.Type.Declaration = &.{};
    var is_exhaustive = true;

    for (enums) |e| {
        const info = @typeInfo(e).Enum;

        for (info.fields) |field| {
            var new_field = field;
            if (reindex) new_field.value = fields.len;
            fields = fields ++ [_]std.builtin.Type.EnumField{new_field};
        }

        for (info.decls) |decl| decls = decls ++ [_]std.builtin.Type.Declaration{decl};

        if (!info.is_exhaustive) is_exhaustive = false;

        {
            const tag_info = @typeInfo(info.tag_type).Int;

            switch (tag_info.signedness) {
                .signed => |s| tag_int.signedness = s,
                .unsigned => {},
            }

            if (reindex)
                tag_int = @typeInfo(std.math.IntFittingRange(0, fields.len - 1)).Int
            else
                tag_int.bits = @max(tag_int.bits, tag_info.bits);
        }
    }

    const tag_type = @Type(.{ .Int = tag_int });

    if (!is_exhaustive and std.math.pow(tag_type, 2, tag_int.bits) == fields.len) is_exhaustive = true;

    return @Type(.{ .Enum = .{
        .tag_type = tag_type,
        .is_exhaustive = is_exhaustive,
        .fields = fields,
        .decls = decls,
    } });
}

test Merged {
    {
        const E = Merged(&.{
            enum { a, b },
            enum(u3) { c = 2, d, e, f },
        }, false);
        const info = @typeInfo(E).Enum;
        try std.testing.expectEqual(u3, info.tag_type);
        try std.testing.expectEqual(6, info.fields.len);
    }

    {
        const E = Merged(&.{
            enum { a, b },
            enum(u3) { c, d, e, f },
        }, true);
        const info = @typeInfo(E).Enum;
        try std.testing.expectEqual(u3, info.tag_type);
        try std.testing.expectEqual(6, info.fields.len);
    }
}

pub fn Sub(comptime Enum: type, comptime tags: []const Enum) type {
    var info = @typeInfo(Enum).Enum;
    info.fields = &.{};
    inline for (tags) |tag| info.fields = info.fields ++ .{.{
        .name = @tagName(tag),
        .value = @intFromEnum(tag),
    }};
    return @Type(.{ .Enum = info });
}

test Sub {
    const E1 = enum { a, b, c };
    const E2 = Sub(E1, &.{ .a, .c });

    const e2_tags = std.meta.tags(E2);

    try std.testing.expectEqual(2, e2_tags.len);
    try std.testing.expectEqual(.a, e2_tags[0]);
    try std.testing.expectEqual(.c, e2_tags[1]);
}

/// Raises the tag type to the next power of two
/// if it is not a power of two already.
pub fn EnsurePowTag(comptime E: type, min: comptime_int) type {
    var info = @typeInfo(E).Enum;
    info.tag_type = meta.EnsurePowBits(info.tag_type, min);
    return @Type(.{ .Enum = info });
}

test EnsurePowTag {
    try std.testing.expectEqual(u8, std.meta.Tag(EnsurePowTag(enum(u0) {}, 8)));
    try std.testing.expectEqual(u8, std.meta.Tag(EnsurePowTag(enum(u8) {}, 8)));
}
