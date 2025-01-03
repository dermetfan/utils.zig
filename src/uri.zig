const std = @import("std");

pub const QueryIterator = struct {
    param_iter: std.mem.SplitIterator(u8, .scalar),

    pub const Parameter = struct {
        key: []const u8,
        value: []const u8,
    };

    pub fn init(query: []const u8) @This() {
        return .{ .param_iter = std.mem.splitScalar(u8, query, '&') };
    }

    pub fn next(self: *@This()) ?Parameter {
        return if (self.param_iter.next()) |param|
            if (std.mem.indexOfScalar(u8, param, '=')) |assign_idx| .{
                .key = param[0..assign_idx],
                .value = param[assign_idx + 1 ..],
            } else .{
                .key = param,
                .value = "",
            }
        else
            null;
    }
};

test QueryIterator {
    var iter = QueryIterator.init("foo=1&bar=&baz");

    try std.testing.expectEqualDeep(QueryIterator.Parameter{
        .key = "foo",
        .value = "1",
    }, iter.next());
    try std.testing.expectEqualDeep(QueryIterator.Parameter{
        .key = "bar",
        .value = "",
    }, iter.next());
    try std.testing.expectEqualDeep(QueryIterator.Parameter{
        .key = "baz",
        .value = "",
    }, iter.next());
    try std.testing.expect(iter.next() == null);
}
