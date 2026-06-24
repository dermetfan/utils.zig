const std = @import("std");

pub fn scoped(comptime new_scope: @EnumLiteral()) type {
    return struct {
        pub const scope = new_scope;

        const inner = std.log.scoped(scope);

        pub fn err(comptime format: []const u8, args: anytype) void {
            inner.err(format, args);
        }

        pub fn warn(comptime format: []const u8, args: anytype) void {
            inner.warn(format, args);
        }

        pub fn info(comptime format: []const u8, args: anytype) void {
            inner.info(format, args);
        }

        pub fn debug(comptime format: []const u8, args: anytype) void {
            inner.debug(format, args);
        }

        pub fn scopeLogEnabled(comptime message_level: std.log.Level) bool {
            return std.log.logEnabled(message_level, scope);
        }
    };
}

test {
    std.testing.refAllDecls(@This());
}
