const builtin = @import("builtin");
const std = @import("std");

const mem = @import("mem.zig");

const posix = std.posix;

pub const ProxyDuplexFinish = enum { downstream_eof, downstream_closed, upstream_eof, upstream_closed, canceled };

pub fn proxyDuplex(
    allocator: std.mem.Allocator,
    downstream: posix.fd_t,
    upstream: posix.fd_t,
    /// Will return `.canceled` when this file descriptor
    /// is ready for reading, ready for writing,
    /// or, if it is the read end of a pipe,
    /// when the write end of the pipe is closed.
    cancel: ?posix.fd_t,
    options: struct {
        /// Behaves according to `fifo_max_size_behavior`
        /// if a read would cause the buffer size to exceed this.
        /// Note there are two buffers that may grow up to this size, one for each direction.
        fifo_max_size: ?usize = mem.b_per_mib,
        fifo_max_size_behavior: enum { block, oom } = .oom,
        /// Will shrink the buffer back down to this size if possible.
        fifo_desired_size: ?usize = 512 * mem.b_per_kib,
        /// Read/write buffer size on the stack.
        comptime buf_size: usize = 4 * mem.b_per_kib,
    },
) !ProxyDuplexFinish {
    // If the `buf_size` is as large as the `fifo_max_size`
    // we may unset both `POLL.IN` and `POLL.OUT` from `posix.pollfd.events`
    // leading to a deadlock:
    // 1. Read until a fifo fills up.
    // 2. Unset `POLL.IN` because the fifo is full anyway.
    // 3. Write all the data from the fifo.
    // 4. Unset `POLL.OUT` because we have nothing to write anyway.
    if (options.fifo_max_size) |fifo_max_size|
        std.debug.assert(options.buf_size < fifo_max_size);

    const POLL = posix.POLL;

    // downstream → upstream
    var fifo_up = std.fifo.LinearFifo(u8, .Dynamic).init(allocator);
    defer fifo_up.deinit();

    // downstream ← upstream
    var fifo_down = std.fifo.LinearFifo(u8, .Dynamic).init(allocator);
    defer fifo_down.deinit();

    // Cannot use `std.io.poll()` because that only supports `POLL.IN`.
    var poll_fds = [_]posix.pollfd{
        .{
            .fd = downstream,
            .events = POLL.IN,
            .revents = undefined,
        },
        .{
            .fd = upstream,
            .events = POLL.IN,
            .revents = undefined,
        },
        .{
            .fd = cancel orelse -1,
            .events = POLL.IN | POLL.OUT,
            .revents = undefined,
        },
    };

    while (true) {
        std.debug.assert(try posix.poll(&poll_fds, -1) != 0);

        const buf_size = options.buf_size;

        const fns = struct {
            options: @TypeOf(options),

            /// Returns the number of bytes read from the file descriptor or null
            /// if it was not ready for reading or `options.fifo_max_size` would be exceeded.
            fn handleReadEnd(fns: @This(), src_poll_fd: *posix.pollfd, fifo: *std.fifo.LinearFifo(u8, .Dynamic), dst_poll_fd: *std.posix.pollfd) !?usize {
                if (src_poll_fd.revents & POLL.IN == 0) return null;

                var buf: [buf_size]u8 = undefined;
                const max_read = if (fns.options.fifo_max_size) |fifo_max_size|
                    @min(fifo.readableLength() + buf.len, fifo_max_size) - fifo.readableLength()
                else
                    buf.len;
                if (max_read == 0) {
                    // The fifo for this file descriptor is full.
                    // Stop polling for new data as that would result in a busy wait loop.
                    src_poll_fd.events &= ~@as(@TypeOf(src_poll_fd.events), POLL.IN);
                    return switch (fns.options.fifo_max_size_behavior) {
                        .oom => error.OutOfMemory,
                        .block => null,
                    };
                }

                // There is now new data in the fifo that we want to write,
                // so poll for the destination becoming ready for writing.
                dst_poll_fd.events |= @as(@TypeOf(dst_poll_fd.events), POLL.OUT);

                const num_read = try posix.read(src_poll_fd.fd, buf[0..max_read]);
                try fifo.write(buf[0..num_read]);

                return num_read;
            }

            fn handleWriteEnd(fns: @This(), src_poll_fd: *posix.pollfd, fifo: *std.fifo.LinearFifo(u8, .Dynamic), dst_poll_fd: *posix.pollfd) !void {
                if (dst_poll_fd.revents & POLL.OUT == 0) return;

                const num_written = posix.write(dst_poll_fd.fd, fifo.readableSlice(0)) catch |err| return switch (err) {
                    error.WouldBlock => {}, // retry next time
                    else => err,
                };
                fifo.discard(num_written);

                if (num_written != 0) {
                    // We have freed up space in the fifo
                    // so we can poll for new data to read into it.
                    src_poll_fd.events |= @as(@TypeOf(src_poll_fd.events), POLL.IN);

                    if (fifo.readableLength() == 0) {
                        // The fifo is empty so we don't need to poll for ready for writing
                        // because we have nothing to write anyway.
                        dst_poll_fd.events &= ~@as(@TypeOf(dst_poll_fd.events), POLL.OUT);
                    }
                }

                if (fns.options.fifo_desired_size) |fifo_desired_size|
                    if (fifo.readableLength() <= fifo_desired_size and fifo.readableLength() + num_written > fifo_desired_size)
                        fifo.shrink(fifo_desired_size);
            }
        }{ .options = options };

        if (try fns.handleReadEnd(&poll_fds[0], &fifo_up, &poll_fds[1])) |num_read|
            if (num_read == 0) return .downstream_eof;
        if (try fns.handleReadEnd(&poll_fds[1], &fifo_down, &poll_fds[0])) |num_read|
            if (num_read == 0) return .upstream_eof;

        try fns.handleWriteEnd(&poll_fds[0], &fifo_up, &poll_fds[1]);
        try fns.handleWriteEnd(&poll_fds[1], &fifo_down, &poll_fds[0]);

        inline for (poll_fds, 0..) |poll_fd, idx| {
            if (poll_fd.revents & POLL.HUP != 0)
                return switch (idx) {
                    0 => .downstream_closed,
                    1 => .upstream_closed,
                    2 => .canceled,
                    inline else => unreachable,
                };

            if (poll_fd.revents & POLL.ERR != 0)
                return posix.PollError.Unexpected;

            if (poll_fd.revents & POLL.NVAL != 0)
                unreachable; // always a race condition
        }

        if (poll_fds[2].revents & (POLL.IN | POLL.OUT) != 0)
            return .canceled;
    }
}
