const std = @import("std");

pub fn scoped(comptime new_scope: @Type(.EnumLiteral)) type {
    return struct {
        pub const scope = new_scope;

        pub usingnamespace std.log.scoped(scope);

        pub fn scopeLogEnabled(comptime message_level: std.log.Level) bool {
            return std.log.logEnabled(message_level, scope);
        }
    };
}
