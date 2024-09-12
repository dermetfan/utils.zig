const std = @import("std");

pub const StderrMutex = struct {
    pub fn lock(_: *@This()) void {
        std.debug.lockStdErr();
    }

    pub fn unlock(_: *@This()) void {
        std.debug.unlockStdErr();
    }
};

var stderr_mutex = StderrMutex{};

/// Workaround needed because `std.debug.getStderrMutex()` was
/// removed in Zig 0.13.0 and `std.Progress.stderr_mutex` is private.
pub fn getStderrMutex() *StderrMutex {
    return &stderr_mutex;
}
