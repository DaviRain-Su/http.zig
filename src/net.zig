const std = @import("std");
const posix = @import("posix_compat");
const linux = std.os.linux;

pub const has_unix_sockets = true;

pub const Address = struct {
    any: linux.sockaddr.storage,
    len: posix.socklen_t,

    pub const ParseError = error{InvalidAddress};
    pub const UnixError = error{PathTooLong};

    pub fn initIp4(bytes: [4]u8, port: u16) Address {
        var addr: linux.sockaddr.in = .{
            .family = posix.AF.INET,
            .port = std.mem.nativeToBig(u16, port),
            .addr = @bitCast(bytes),
        };
        var storage: linux.sockaddr.storage = undefined;
        @memcpy(@as([*]u8, @ptrCast(&storage))[0..@sizeOf(linux.sockaddr.in)], std.mem.asBytes(&addr));
        return .{
            .any = storage,
            .len = @intCast(@sizeOf(linux.sockaddr.in)),
        };
    }

    pub fn parseIp(host: []const u8, port: u16) !Address {
        const ip = try std.Io.net.IpAddress.parse(host, port);
        return fromIpAddress(ip);
    }

    pub fn initUnix(path: []const u8) UnixError!Address {
        if (path.len >= @sizeOf(linux.sockaddr.un.path)) return error.PathTooLong;
        var addr: linux.sockaddr.un = .{};
        @memset(&addr.path, 0);
        @memcpy(addr.path[0..path.len], path);
        var storage: linux.sockaddr.storage = undefined;
        @memcpy(@as([*]u8, @ptrCast(&storage))[0..@sizeOf(linux.sockaddr.un)], std.mem.asBytes(&addr));
        return .{
            .any = storage,
            .len = @intCast(@sizeOf(linux.sockaddr.un)),
        };
    }

    pub fn getOsSockLen(self: *const Address) posix.socklen_t {
        return self.len;
    }

    pub fn format(self: Address, w: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self.any.family) {
            posix.AF.INET => {
                const addr: *const linux.sockaddr.in = @ptrCast(&self.any);
                const ip4 = std.Io.net.Ip4Address{
                    .bytes = @bitCast(addr.addr),
                    .port = std.mem.bigToNative(u16, addr.port),
                };
                return ip4.format(w);
            },
            posix.AF.INET6 => {
                const addr: *const linux.sockaddr.in6 = @ptrCast(&self.any);
                const ip6 = std.Io.net.Ip6Address{
                    .bytes = addr.addr,
                    .port = std.mem.bigToNative(u16, addr.port),
                    .flow = addr.flowinfo,
                    .interface = .none,
                };
                return ip6.format(w);
            },
            posix.AF.UNIX => {
                const addr: *const linux.sockaddr.un = @ptrCast(&self.any);
                const path = std.mem.sliceTo(&addr.path, 0);
                return w.print("unix:{s}", .{path});
            },
            else => return w.print("unknown", .{}),
        }
    }

    fn fromIpAddress(ip: std.Io.net.IpAddress) Address {
        return switch (ip) {
            .ip4 => |ip4| initIp4(ip4.bytes, ip4.port),
            .ip6 => |ip6| blk: {
                var addr: linux.sockaddr.in6 = .{
                    .family = posix.AF.INET6,
                    .port = std.mem.nativeToBig(u16, ip6.port),
                    .flowinfo = ip6.flow,
                    .addr = ip6.bytes,
                    .scope_id = 0,
                };
                var storage: linux.sockaddr.storage = undefined;
                @memcpy(@as([*]u8, @ptrCast(&storage))[0..@sizeOf(linux.sockaddr.in6)], std.mem.asBytes(&addr));
                break :blk .{
                    .any = storage,
                    .len = @intCast(@sizeOf(linux.sockaddr.in6)),
                };
            },
        };
    }
};

pub const Stream = struct {
    handle: posix.socket_t,

    pub const Reader = struct {
        interface: std.Io.Reader,
        stream: Stream,
        err: ?std.posix.ReadError = null,

        pub fn init(stream: Stream, buffer: []u8) Reader {
            return .{
                .stream = stream,
                .interface = .{
                    .vtable = &.{
                        .stream = streamImpl,
                        .readVec = readVec,
                    },
                    .buffer = buffer,
                    .seek = 0,
                    .end = 0,
                },
            };
        }

        fn streamImpl(io_r: *std.Io.Reader, io_w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
            const dest = limit.slice(try io_w.writableSliceGreedy(1));
            var data: [1][]u8 = .{dest};
            const n = try readVec(io_r, &data);
            io_w.advance(n);
            return n;
        }

        fn readVec(io_r: *std.Io.Reader, data: [][]u8) std.Io.Reader.Error!usize {
            const reader_ptr: *Reader = @alignCast(@fieldParentPtr("interface", io_r));
            if (data.len == 0) return 0;
            const slice = data[0];
            const n = posix.read(reader_ptr.stream.handle, slice) catch |err| {
                reader_ptr.err = err;
                return error.ReadFailed;
            };
            if (n == 0) return error.EndOfStream;
            return n;
        }
    };

    pub const Writer = struct {
        interface: std.Io.Writer,
        stream: Stream,
        err: ?posix.WriteError = null,

        pub fn init(stream: Stream, buffer: []u8) Writer {
            return .{
                .stream = stream,
                .interface = .{
                    .vtable = &.{
                        .drain = drain,
                        .sendFile = sendFile,
                    },
                    .buffer = buffer,
                },
            };
        }

        fn drain(io_w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
            const writer_ptr: *Writer = @alignCast(@fieldParentPtr("interface", io_w));
            _ = splat;
            var iovecs: [8]posix.iovec_const = undefined;
            var count: usize = 0;
            const buffered = io_w.buffered();
            if (buffered.len != 0) {
                iovecs[count] = .{ .base = buffered.ptr, .len = buffered.len };
                count += 1;
            }
            for (data) |slice| {
                if (slice.len == 0) continue;
                iovecs[count] = .{ .base = slice.ptr, .len = slice.len };
                count += 1;
                if (count == iovecs.len) break;
            }
            if (count == 0) return 0;
            const n = posix.writev(writer_ptr.stream.handle, iovecs[0..count]) catch |err| {
                writer_ptr.err = err;
                return error.WriteFailed;
            };
            return io_w.consume(n);
        }

        fn sendFile(_: *std.Io.Writer, _: *std.Io.File.Reader, _: std.Io.Limit) std.Io.Writer.FileError!usize {
            return error.Unimplemented;
        }
    };

    pub fn reader(self: Stream, buffer: []u8) Reader {
        return Reader.init(self, buffer);
    }

    pub fn writer(self: Stream, buffer: []u8) Writer {
        return Writer.init(self, buffer);
    }

    pub fn close(self: Stream) void {
        posix.close(self.handle);
    }
};

pub fn tcpConnectToAddress(address: Address) !Stream {
    const proto = if (address.any.family == posix.AF.UNIX) @as(u32, 0) else posix.IPPROTO.TCP;
    const fd = try posix.socket(address.any.family, posix.SOCK.STREAM, proto);
    errdefer posix.close(fd);
    try posix.connect(fd, @ptrCast(&address.any), address.len);
    return .{ .handle = fd };
}
