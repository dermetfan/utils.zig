const builtin = @import("builtin");
const std = @import("std");

const mem = @import("mem.zig");

const posix = std.posix;

/// Pumps from a blocking `reader` into a blocking `writer` using two threads.
/// Unblocks `join()` on end of stream or when `shutdown` is set.
/// Always writes all bytes that were read before unblocking `join()`,
/// so a blocking `writer` can block `join()`.
pub fn Pump(
    comptime Reader: type,
    comptime Writer: type,
    comptime fifo_type: std.fifo.LinearFifoBufferType,
    fifo_max_size: ?comptime_int,
    fifo_desired_size: ?comptime_int,
    buf_size: comptime_int,
) type {
    return struct {
        reader: Reader,
        writer: Writer,

        fifo: std.fifo.LinearFifo(u8, fifo_type),
        fifo_mutex: std.Thread.Mutex = .{},

        read_thread: std.Thread = undefined,
        write_thread: std.Thread = undefined,

        /// New data is available in `fifo`.
        writable_event: std.Thread.ResetEvent = .{},
        /// Unused capacity is available in `fifo`.
        readable_event: std.Thread.ResetEvent = .{},
        /// Set this to unblock `join()` eventually.
        /// `join()` still blocks until blocked calls to
        /// `reader.read()` and `writer.write()` return.
        // TODO wrap this in an atomic?
        shutdown: bool = false,

        read_err: ?ReadError = null,
        write_err: ?WriteError = null,

        pub const ReadError = Reader.Error || std.mem.Allocator.Error || error{StreamTooLong};
        pub const WriteError = Writer.Error || std.mem.Allocator.Error || error{StreamTooLong};

        pub fn spawn(self: *@This()) std.Thread.SpawnError!void {
            self.read_thread = try std.Thread.spawn(.{}, read, .{self});
            errdefer {
                self.shutdown = true;
                self.read_thread.join();
            }

            self.write_thread = try std.Thread.spawn(.{}, write, .{self});
        }

        /// Check both `read_err` and `write_err` if this returns an error.
        pub fn join(self: *@This()) (ReadError || WriteError)!void {
            self.read_thread.join();
            self.write_thread.join();

            self.fifo.deinit();

            defer self.* = undefined;

            if (self.read_err) |err| return err;
            if (self.write_err) |err| return err;
        }

        fn read(self: *@This()) ReadError!void {
            defer {
                self.shutdown = true;
                self.writable_event.set();
            }
            errdefer |err| self.read_err = err;

            var buf: [buf_size]u8 = undefined;
            while (!self.shutdown) : (self.writable_event.set()) {
                const num_read = try self.reader.read(&buf);

                var num_written: usize = 0;
                while (num_written != num_read) {
                    const num_write = num_write: {
                        self.fifo_mutex.lock();
                        defer self.fifo_mutex.unlock();

                        var max_write: ?usize = if (fifo_type == .Dynamic) null else self.fifo.writableLength();
                        if (fifo_max_size) |max_size| {
                            if (max_write) |_max_write|
                                max_write = @min(_max_write, max_size - self.fifo.readableLength())
                            else
                                max_write = max_size - self.fifo.readableLength();
                        }

                        break :num_write (if (max_write) |max| @min(max, num_read) else num_read) -
                            num_written;
                    };

                    if (num_write == 0) {
                        self.readable_event.wait();
                        self.readable_event.reset();
                        continue;
                    }

                    self.fifo_mutex.lock();
                    defer self.fifo_mutex.unlock();

                    try self.fifo.write(buf[num_written .. num_written + num_write]);

                    num_written += num_write;
                }

                if (num_read == 0)
                    break;
            }
        }

        fn write(self: *@This()) WriteError!void {
            defer self.shutdown = true;
            errdefer |err| self.write_err = err;

            self.writable_event.wait();
            self.writable_event.reset();

            while (true) {
                var buf: [buf_size]u8 = undefined;
                const num_read = num_read: {
                    self.fifo_mutex.lock();
                    defer self.fifo_mutex.unlock();

                    const num_read = self.fifo.read(&buf);

                    if (fifo_desired_size) |desired_size|
                        self.fifo.shrink(@max(desired_size, self.fifo.readableLength()));

                    break :num_read num_read;
                };

                if (num_read != 0) {
                    self.readable_event.set();

                    try self.writer.writeAll(buf[0..num_read]);
                }

                if (num_read < buf.len or num_read == 0) {
                    if (self.shutdown)
                        break;

                    self.writable_event.wait();
                    self.writable_event.reset();
                }
            }
        }
    };
}

pub fn pump(
    reader: anytype,
    writer: anytype,
    comptime fifo_type: std.fifo.LinearFifoBufferType,
    fifo: std.fifo.LinearFifo(u8, fifo_type),
    fifo_max_size: ?comptime_int,
    fifo_desired_size: ?comptime_int,
    buf_size: comptime_int,
) Pump(@TypeOf(reader), @TypeOf(writer), fifo_type, fifo_max_size, fifo_desired_size, buf_size) {
    return .{ .reader = reader, .writer = writer, .fifo = fifo };
}

test "Pump (static buffer)" {
    if (builtin.single_threaded) return error.SkipZigTest;

    var src = std.io.fixedBufferStream("abc");
    var dst_buf: [3]u8 = undefined;
    var dst = std.io.fixedBufferStream(&dst_buf);

    const fifo_type = .{ .Static = 2 };
    var p = pump(src.reader(), dst.writer(), fifo_type, std.fifo.LinearFifo(u8, fifo_type).init(), null, null, 1);
    try p.spawn();
    try p.join();

    try std.testing.expectEqual(src.getEndPos(), src.getPos());
    try std.testing.expectEqualStrings(src.buffer, dst.getWritten());
}

test "Pump (dynamic buffer)" {
    if (builtin.single_threaded) return error.SkipZigTest;

    var src = std.io.fixedBufferStream("abc");
    var dst_buf: [3]u8 = undefined;
    var dst = std.io.fixedBufferStream(&dst_buf);

    const fifo_type = .Dynamic;
    var p = pump(src.reader(), dst.writer(), fifo_type, std.fifo.LinearFifo(u8, fifo_type).init(std.testing.allocator), null, null, 1);
    try p.spawn();
    try p.join();

    try std.testing.expectEqual(src.getEndPos(), src.getPos());
    try std.testing.expectEqualStrings(src.buffer, dst.getWritten());
}

pub const PollStream = struct {
    fd: posix.fd_t,
    cancel_fd: ?posix.fd_t = null,
    thread: ?std.Thread = null,
    read_semaphone: std.Thread.Semaphore = .{},
    write_semaphone: std.Thread.Semaphore = .{},
    canceled: bool = false,

    const POLL = posix.POLL;

    pub fn spawn(self: *@This()) std.Thread.SpawnError!void {
        self.thread = try std.Thread.spawn(.{}, poll, .{self});
    }

    pub fn join(self: @This()) void {
        self.thread.?.join();
    }

    fn poll(self: *@This()) !void {
        defer {
            self.read_semaphone.post();
            self.write_semaphone.post();
        }

        var poll_fds = [_]posix.pollfd{
            .{
                .fd = self.fd,
                .events = POLL.IN | POLL.OUT,
                .revents = undefined,
            },
            .{
                .fd = self.cancel_fd orelse -1,
                .events = POLL.IN | POLL.OUT | POLL.HUP,
                .revents = undefined,
            },
        };

        const poll_err_mask = POLL.ERR | POLL.NVAL | POLL.HUP;

        while (true) : (std.atomic.spinLoopHint()) {
            std.debug.assert(try posix.poll(&poll_fds, -1) != 0);

            if (poll_fds[1].revents & (POLL.IN | POLL.OUT | poll_err_mask) != 0) {
                self.canceled = true;
                break;
            }

            if (poll_fds[0].revents & POLL.IN != 0)
                self.read_semaphone.post();

            if (poll_fds[0].revents & POLL.OUT != 0)
                self.write_semaphone.post();

            if (poll_fds[0].revents & poll_err_mask != 0)
                break;
        }
    }

    pub fn read(self: *@This(), buf: []u8) posix.ReadError!usize {
        self.read_semaphone.wait();

        return if (self.canceled)
            0
        else
            posix.read(self.fd, buf);
    }

    pub fn write(self: *@This(), buf: []const u8) posix.WriteError!usize {
        self.write_semaphone.wait();

        return if (self.canceled)
            error.NotOpenForWriting
        else
            posix.write(self.fd, buf);
    }

    pub const Reader = std.io.GenericReader(*@This(), posix.ReadError, read);
    pub const Writer = std.io.GenericWriter(*@This(), posix.WriteError, write);

    pub fn reader(self: *@This()) Reader {
        return .{ .context = self };
    }

    pub fn writer(self: *@This()) Writer {
        return .{ .context = self };
    }
};

pub const ProxyDuplexPosixFinish = enum { downstream_eof, downstream_closed, upstream_eof, upstream_closed, canceled };

pub fn proxyDuplexPosix(
    allocator: std.mem.Allocator,
    downstream: posix.fd_t,
    upstream: posix.fd_t,
    /// Will return `.canceled` when this file descriptor
    /// is ready for reading, ready for writing,
    /// or, if it is the read end of a pipe,
    /// when the write end of the pipe is closed.
    cancel: ?posix.fd_t,
    options: struct {
        /// Blocks if a read would cause the buffer size to exceed this.
        /// Note there are two buffers that may grow up to this size, one for each direction.
        fifo_max_size: ?usize = mem.b_per_mib,
        /// Will shrink the buffer back down to this size if possible.
        fifo_desired_size: ?usize = 512 * mem.b_per_kib,
        /// Read/write buffer size on the stack.
        comptime buf_size: usize = 4 * mem.b_per_kib,
    },
) !ProxyDuplexPosixFinish {
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
            .events = POLL.IN | POLL.OUT,
            .revents = undefined,
        },
        .{
            .fd = upstream,
            .events = POLL.IN | POLL.OUT,
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
            fn handleReadEnd(fns: @This(), poll_fd: posix.pollfd, fifo: *std.fifo.LinearFifo(u8, .Dynamic)) !?usize {
                if (poll_fd.revents & POLL.IN == 0) return null;

                var buf: [buf_size]u8 = undefined;
                const max_read = if (fns.options.fifo_max_size) |fifo_max_size|
                    @min(fifo.readableLength() + buf.len, fifo_max_size) - fifo.readableLength()
                else
                    buf.len;
                if (max_read == 0) return null;

                const num_read = try posix.read(poll_fd.fd, buf[0..max_read]);
                try fifo.write(buf[0..num_read]);

                return num_read;
            }

            fn handleWriteEnd(fns: @This(), poll_fd: posix.pollfd, fifo: *std.fifo.LinearFifo(u8, .Dynamic)) !void {
                if (poll_fd.revents & POLL.OUT == 0) return;

                const num_bytes = posix.write(poll_fd.fd, fifo.readableSlice(0)) catch |err| return switch (err) {
                    error.WouldBlock => {}, // retry next time
                    else => err,
                };
                fifo.discard(num_bytes);

                if (fns.options.fifo_desired_size) |fifo_desired_size|
                    if (fifo.readableLength() <= fifo_desired_size and fifo.readableLength() + num_bytes > fifo_desired_size)
                        fifo.shrink(fifo_desired_size);
            }
        }{ .options = options };

        if (try fns.handleReadEnd(poll_fds[0], &fifo_up)) |num_read|
            if (num_read == 0) return .downstream_eof;
        if (try fns.handleReadEnd(poll_fds[1], &fifo_down)) |num_read|
            if (num_read == 0) return .upstream_eof;

        try fns.handleWriteEnd(poll_fds[0], &fifo_down);
        try fns.handleWriteEnd(poll_fds[1], &fifo_up);

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
