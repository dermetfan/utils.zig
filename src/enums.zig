const std = @import("std");

pub fn Merged(comptime enums: []const type) type {
    var tag_int = std.builtin.Type.Int{
        .signedness = .unsigned,
        .bits = 0,
    };
    var fields: []const std.builtin.Type.EnumField = &.{};
    var decls: []const std.builtin.Type.Declaration = &.{};
    var is_exhaustive = true;

    for (enums) |e| {
        const info = @typeInfo(e).Enum;

        {
            const tag_info = @typeInfo(info.tag_type).Int;

            switch (tag_info.signedness) {
                .signed => |s| tag_int.signedness = s,
                .unsigned => {},
            }

            tag_int.bits = @max(tag_int.bits, tag_info.bits);
        }

        for (info.fields) |field| fields = fields ++ [_]std.builtin.Type.EnumField{field};

        for (info.decls) |decl| decls = decls ++ [_]std.builtin.Type.Declaration{decl};

        if (!info.is_exhaustive) is_exhaustive = false;
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
            enum{ a, b },
            enum(u3) { c = 2, d, e, f },
        });
        const info = @typeInfo(E).Enum;
        try std.testing.expectEqual(u3, info.tag_type);
        try std.testing.expectEqual(6, info.fields.len);
    }
}
