const builtin = @import("builtin");
const std = @import("std");

const fmt = @import("fmt.zig");
const mem = @import("mem.zig");
const meta = @import("meta.zig");

const posix = std.posix;

pub const FileHandleType = enum {
    fd,
    socket,

    pub fn @"type"(self: @This()) type {
        return switch (self) {
            .fd => posix.fd_t,
            .socket => posix.socket_t,
        };
    }
};

pub const ProxyDuplexFinish = enum {
    /// The `cancel` file descriptor, if any, became ready.
    canceled,
    /// Both sides returned EOF and
    /// we have written all data we received.
    eof,
    /// Downstream closed or returned an error.
    downstream_closed,
    /// Upstream closed or returned an error.
    upstream_closed,
};

pub fn proxyDuplex(
    allocator: std.mem.Allocator,
    // These cannot be comptime fields of `options`
    // as when the caller tries to change them from their defaults
    // we hit https://github.com/ziglang/zig/issues/19985.
    comptime comptime_options: struct {
        downstream_kind: FileHandleType = .fd,
        upstream_kind: FileHandleType = .fd,
        /// Read/write buffer size on the stack.
        buf_size: usize = 4 * mem.b_per_kib,
    },
    downstream: comptime_options.downstream_kind.type(),
    upstream: comptime_options.upstream_kind.type(),
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
        std.debug.assert(comptime_options.buf_size < fifo_max_size);

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

    var downstream_eof = false;
    var upstream_eof = false;

    while (true) {
        std.debug.assert(try posix.poll(&poll_fds, -1) != 0);

        const fns = struct {
            options: @TypeOf(options),

            fn handleRead(
                fns: @This(),
                src_eof: *bool,
                src_kind: FileHandleType,
                src_poll_fd: *posix.pollfd,
                fifo: *std.fifo.LinearFifo(u8, .Dynamic),
                dst_poll_fd: *std.posix.pollfd,
            ) !void {
                if (src_poll_fd.revents & POLL.IN == 0) return;

                var buf: [comptime_options.buf_size]u8 = undefined;
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
                        .block => {},
                    };
                }

                const num_read = switch (src_kind) {
                    .fd => posix.read(src_poll_fd.fd, buf[0..max_read]),
                    .socket => posix.recv(src_poll_fd.fd, buf[0..max_read], 0),
                } catch |err| switch (err) {
                    error.WouldBlock => unreachable, // There is at least one byte available.
                    else => |e| return e,
                };

                if (num_read != 0) {
                    try fifo.write(buf[0..num_read]);

                    // There is now new data in the fifo that we want to write
                    // so poll for the destination becoming ready for writing.
                    dst_poll_fd.events |= @as(@TypeOf(dst_poll_fd.events), POLL.OUT);
                } else {
                    src_eof.* = true;

                    // There won't be more data to read after EOF
                    // so we don't need to poll for it.
                    src_poll_fd.events &= ~@as(@TypeOf(src_poll_fd.events), POLL.IN);
                }
            }

            fn handleWrite(
                fns: @This(),
                src_poll_fd: *posix.pollfd,
                fifo: *std.fifo.LinearFifo(u8, .Dynamic),
                dst_kind: FileHandleType,
                dst_poll_fd: *posix.pollfd,
            ) !void {
                if (dst_poll_fd.revents & POLL.OUT == 0) return;

                const num_written = switch (dst_kind) {
                    .fd => posix.write(dst_poll_fd.fd, fifo.readableSlice(0)),
                    .socket => posix.send(dst_poll_fd.fd, fifo.readableSlice(0), 0),
                } catch |err| return switch (err) {
                    error.WouldBlock => unreachable, // There is at least one byte available.
                    else => |e| return e,
                };

                if (num_written != 0) {
                    fifo.discard(num_written);

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

        try fns.handleRead(&downstream_eof, comptime_options.downstream_kind, &poll_fds[0], &fifo_up, &poll_fds[1]);
        try fns.handleRead(&upstream_eof, comptime_options.upstream_kind, &poll_fds[1], &fifo_down, &poll_fds[0]);

        try fns.handleWrite(&poll_fds[0], &fifo_up, comptime_options.upstream_kind, &poll_fds[1]);
        try fns.handleWrite(&poll_fds[1], &fifo_down, comptime_options.downstream_kind, &poll_fds[0]);

        if (downstream_eof and fifo_up.readableLength() == 0 and
            upstream_eof and fifo_down.readableLength() == 0)
            return .eof;

        inline for (poll_fds, 0..) |poll_fd, idx| {
            if (poll_fd.revents & (POLL.HUP | POLL.ERR) != 0) {
                return switch (idx) {
                    0 => .downstream_closed,
                    1 => .upstream_closed,
                    2 => .canceled,
                    else => comptime unreachable,
                };
            }

            if (poll_fd.revents & POLL.NVAL != 0)
                unreachable; // Always a race condition.
        }

        if (poll_fds[2].revents & (POLL.IN | POLL.OUT) != 0)
            return .canceled;
    }
}

/// Polls before attempting to `read()` or `write()`
/// and returns `error.NotOpenForReading` or `error.NotOpenForWriting`
/// when the FD's state changes while polling.
/// This helps avoid using a reused FD that was closed
/// in between reads/writes because you get the error immediately
/// as opposed to on the next read/write.
pub fn PollingStream(comptime kind: FileHandleType) type {
    return struct {
        handle: kind.type(),

        pub const ReadError = posix.PollError || meta.ErrorSetExcluding(switch (kind) {
            .fd => posix.ReadError,
            .socket => posix.RecvFromError,
        }, &.{error.WouldBlock});
        pub const Reader = std.io.Reader(@This(), ReadError, read);

        pub const WriteError = posix.PollError || meta.ErrorSetExcluding(switch (kind) {
            .fd => posix.WriteError,
            .socket => posix.SendError,
        }, &.{error.WouldBlock});
        pub const Writer = std.io.Writer(@This(), WriteError, write);

        /// Returns `error.NotOpenForReading` on `POLL.HUP` and `POLL.ERR`.
        pub fn read(self: @This(), buf: []u8) ReadError!usize {
            const POLL = posix.POLL;

            var poll_fds = [1]posix.pollfd{
                .{
                    .fd = self.handle,
                    .events = POLL.IN,
                    .revents = undefined,
                },
            };

            std.debug.assert(try posix.poll(&poll_fds, -1) != 0);

            if (poll_fds[0].revents & POLL.IN != 0)
                return switch (kind) {
                    .fd => posix.read(poll_fds[0].fd, buf),
                    .socket => posix.recv(poll_fds[0], buf, 0),
                } catch |err| switch (err) {
                    error.WouldBlock => unreachable, // There is at least one byte available.
                    else => |e| return e,
                };

            if (poll_fds[0].revents & (POLL.HUP | POLL.ERR) != 0)
                return error.NotOpenForReading;

            if (poll_fds[0].revents & POLL.NVAL != 0)
                std.debug.panic(
                    "polled invalid FD {d} in {}",
                    .{ poll_fds[0].fd, fmt.fmtSourceLocation(@src()) },
                );

            unreachable;
        }

        /// Returns `error.NotOpenForWriting` on `POLL.HUP` and `POLL.ERR`.
        pub fn write(self: @This(), buf: []const u8) WriteError!usize {
            const POLL = posix.POLL;

            var poll_fds = [1]posix.pollfd{
                .{
                    .fd = self.handle,
                    .events = POLL.OUT,
                    .revents = undefined,
                },
            };

            std.debug.assert(try posix.poll(&poll_fds, -1) != 0);

            if (poll_fds[0].revents & POLL.OUT != 0)
                return switch (kind) {
                    .fd => posix.write(poll_fds[0].fd, buf),
                    .socket => posix.send(poll_fds[0].fd, buf, 0),
                } catch |err| switch (err) {
                    error.WouldBlock => unreachable, // There is at least one byte available.
                    else => |e| e,
                };

            if (poll_fds[0].revents & (POLL.HUP | POLL.ERR) != 0)
                return error.NotOpenForWriting;

            if (poll_fds[0].revents & POLL.NVAL != 0)
                std.debug.panic(
                    "polled closed FD {d} in {}",
                    .{ poll_fds[0].fd, fmt.fmtSourceLocation(@src()) },
                );

            unreachable;
        }

        pub fn reader(self: @This()) Reader {
            return .{ .context = self };
        }

        pub fn writer(self: @This()) Writer {
            return .{ .context = self };
        }
    };
}
