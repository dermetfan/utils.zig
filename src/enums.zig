const std = @import("std");

const meta = @import("meta.zig");

pub fn Merged(comptime enums: []const type, comptime reindex: bool) type {
    var tag_int = std.builtin.Type.Int{
        .signedness = .unsigned,
        .bits = 0,
    };
    var mode = .exhaustive;
    var fields_count = 0;

    for (enums) |e| {
        const info = @typeInfo(e).@"enum";
        fields_count += info.fields.len;
        if (!info.is_exhaustive) mode = .nonexhaustive;

        if (!reindex) {
            const tag_info = @typeInfo(info.tag_type).int;
            if (tag_info.signedness == .signed)
                tag_int.signedness = .signed;
            tag_int.bits = @max(tag_int.bits, tag_info.bits);
        }
    }

    if (reindex)
        tag_int = @typeInfo(std.math.IntFittingRange(0, fields_count - 1)).int;

    const Tag = @Int(tag_int.signedness, tag_int.bits);

    if (mode == .nonexhaustive and std.math.pow(Tag, 2, tag_int.bits) == fields_count) mode = .exhaustive;

    var field_names: [fields_count][:0]const u8 = undefined;
    var field_values: [fields_count]Tag = undefined;

    var field_idx = 0;
    for (enums) |e|
        for (@typeInfo(e).@"enum".fields) |field| {
            field_names[field_idx] = field.name;
            field_values[field_idx] = if (reindex) field_idx else field.value;

            field_idx += 1;
        };

    return @Enum(Tag, mode, &field_names, &field_values);
}

test Merged {
    {
        const E = Merged(&.{
            enum { a, b },
            enum(u3) { c = 2, d, e, f },
        }, false);
        const info = @typeInfo(E).@"enum";
        try std.testing.expectEqual(u3, info.tag_type);
        try std.testing.expectEqual(6, info.fields.len);
    }

    {
        const E = Merged(&.{
            enum { a, b },
            enum(u3) { c, d, e, f },
        }, true);
        const info = @typeInfo(E).@"enum";
        try std.testing.expectEqual(u3, info.tag_type);
        try std.testing.expectEqual(6, info.fields.len);
    }
}

pub fn Sub(comptime Enum: type, comptime tags: []const Enum) type {
    const info = @typeInfo(Enum).@"enum";

    var field_names: [tags.len][:0]const u8 = undefined;
    var field_values: [tags.len]info.tag_type = undefined;

    for (&field_names, &field_values, tags) |*field_name, *field_value, tag| {
        field_name.* = @tagName(tag);
        field_value.* = @intFromEnum(tag);
    }

    return @Enum(
        info.tag_type,
        if (info.is_exhaustive) .exhaustive else .nonexhaustive,
        &field_names,
        &field_values,
    );
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
    const info = @typeInfo(E).@"enum";

    const Tag = meta.EnsurePowBits(info.tag_type, min);

    var field_names: [info.fields.len][:0]const u8 = undefined;
    var field_values: [info.fields.len]Tag = undefined;

    for (&field_names, &field_values, info.fields) |*field_name, *field_value, field| {
        field_name.* = field.name;
        field_value.* = field.value;
    }

    return @Enum(
        Tag,
        if (info.is_exhaustive) .exhaustive else .nonexhaustive,
        &field_names,
        &field_values,
    );
}

test EnsurePowTag {
    try std.testing.expectEqual(u8, std.meta.Tag(EnsurePowTag(enum(u0) {}, 8)));
    try std.testing.expectEqual(u8, std.meta.Tag(EnsurePowTag(enum(u8) {}, 8)));
}

test {
    std.testing.refAllDecls(@This());
}
