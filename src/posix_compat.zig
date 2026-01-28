const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

pub const system = std.posix.system;
pub const errno = std.posix.errno;
pub const UnexpectedError = std.posix.UnexpectedError;

// Helper function to get errno on macOS
inline fn getErrno(rc: anytype) std.posix.E {
    if (builtin.os.tag == .macos) {
        _ = rc;
        return @enumFromInt(std.c._errno().*);
    }
    return .SUCCESS;
}

pub const fd_t = std.posix.fd_t;
pub const socket_t = std.posix.socket_t;
pub const socklen_t = std.posix.socklen_t;
pub const sockaddr = std.posix.sockaddr;
pub const timeval = std.posix.timeval;
pub const iovec_const = std.posix.iovec_const;
pub const iovec = std.posix.iovec;

pub const AF = std.posix.AF;
pub const SOCK = std.posix.SOCK;
pub const SOL = std.posix.SOL;
pub const SO = std.posix.SO;
pub const IPPROTO = std.posix.IPPROTO;
pub const O = std.posix.O;
pub const F = std.posix.F;

pub const SIG = std.posix.SIG;
pub const Sigaction = std.posix.Sigaction;
pub const sigemptyset = std.posix.sigemptyset;

pub const Kevent = std.posix.Kevent;

pub const close = std.posix.close;
pub const fcntl = std.posix.fcntl;
pub const setsockopt = std.posix.setsockopt;
pub const read = std.posix.read;

pub const SocketError = std.posix.SocketError || UnexpectedError;

pub const AcceptError = error{
    ConnectionAborted,
    SocketNotListening,
    WouldBlock,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    SystemResources,
    NetworkDown,
    BlockedByFirewall,
    ProtocolFailure,
} || UnexpectedError;

pub const BindError = error{
    AddressInUse,
    AddressUnavailable,
    AddressFamilyUnsupported,
    SystemResources,
    NetworkDown,
    ProtocolUnsupportedBySystem,
    ProtocolUnsupportedByAddressFamily,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
} || UnexpectedError;

pub const ListenError = error{
    AddressInUse,
    AddressUnavailable,
    SystemResources,
    NetworkDown,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
} || UnexpectedError;

pub const ConnectError = std.Io.net.IpAddress.ConnectError || UnexpectedError;

pub const ShutdownError = error{SocketNotConnected} || UnexpectedError;

pub const WriteError = error{
    WouldBlock,
    BrokenPipe,
    ConnectionResetByPeer,
    InputOutput,
    SystemResources,
    AccessDenied,
    NetworkDown,
    SocketNotConnected,
} || UnexpectedError;

pub const WritevError = WriteError;

pub const PipeError = error{SystemResources} || UnexpectedError;

pub fn eventfd(count: u32, flags: u32) UnexpectedError!fd_t {
    if (builtin.os.tag != .linux) @compileError("posix_compat.eventfd only implemented for Linux");
    const rc = linux.eventfd(count, flags);
    switch (linux.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .MFILE => return std.posix.unexpectedErrno(.MFILE),
        .NFILE => return std.posix.unexpectedErrno(.NFILE),
        else => |err| return std.posix.unexpectedErrno(err),
    }
}

pub fn socket(domain: u32, socket_type: u32, protocol: u32) SocketError!socket_t {
    if (builtin.os.tag == .linux) {
        const rc = linux.socket(@intCast(domain), @intCast(socket_type), @intCast(protocol));
        switch (linux.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .ACCES => error.AccessDenied,
            .AFNOSUPPORT => return error.AddressFamilyUnsupported,
            .PROTONOSUPPORT, .NOPROTOOPT => return error.ProtocolNotSupported,
            .NFILE => return error.ProcessFdQuotaExceeded,
            .MFILE => return error.SystemFdQuotaExceeded,
            .NOMEM, .NOBUFS => return error.SystemResources,
            .INVAL => return error.SocketTypeNotSupported,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    } else if (builtin.os.tag == .macos) {
        // macOS doesn't support SOCK_CLOEXEC and SOCK_NONBLOCK in socket()
        // These need to be set via fcntl() after socket creation
        // Extract just the socket type (SOCK_STREAM=1, SOCK_DGRAM=2, etc.)
        const clean_type = socket_type & 0xff;
        const needs_nonblock = (socket_type & std.posix.SOCK.NONBLOCK) != 0; // 0x10000 on macOS
        const needs_cloexec = (socket_type & std.posix.SOCK.CLOEXEC) != 0;  // 0x8000 on macOS

        const rc = std.c.socket(@intCast(domain), @intCast(clean_type), @intCast(protocol));
        if (rc < 0) {
            const err = getErrno(rc);
            return switch (err) {
                .ACCES => error.AccessDenied,
                .AFNOSUPPORT => return error.AddressFamilyUnsupported,
                .PROTONOSUPPORT, .NOPROTOOPT, .PROTOTYPE => return error.ProtocolNotSupported,
                .NFILE => return error.ProcessFdQuotaExceeded,
                .MFILE => return error.SystemFdQuotaExceeded,
                .NOMEM, .NOBUFS => return error.SystemResources,
                .INVAL => return error.SocketTypeNotSupported,
                else => std.posix.unexpectedErrno(err),
            };
        }
        const fd: socket_t = @intCast(rc);

        // Set CLOEXEC via fcntl if requested
        if (needs_cloexec) {
            var cloexec_flags = std.c.fcntl(fd, std.posix.F.GETFD, @as(c_int, 0));
            if (cloexec_flags < 0) {
                _ = std.c.close(fd);
                return error.SystemResources;
            }
            cloexec_flags |= std.posix.FD_CLOEXEC;
            const set_result = std.c.fcntl(fd, std.posix.F.SETFD, cloexec_flags);
            if (set_result < 0) {
                _ = std.c.close(fd);
                return error.SystemResources;
            }
        }

        // Set NONBLOCK via fcntl if requested
        if (needs_nonblock) {
            const O_NONBLOCK: c_int = 0x0004; // macOS O_NONBLOCK value
            var nonblock_flags = std.c.fcntl(fd, std.posix.F.GETFL, @as(c_int, 0));
            if (nonblock_flags < 0) {
                _ = std.c.close(fd);
                return error.SystemResources;
            }
            nonblock_flags |= O_NONBLOCK;
            const set_result = std.c.fcntl(fd, std.posix.F.SETFL, nonblock_flags);
            if (set_result < 0) {
                _ = std.c.close(fd);
                return error.SystemResources;
            }
        }

        return fd;
    } else {
        @compileError("posix_compat.socket only implemented for Linux and macOS");
    }
}

pub fn bind(fd: socket_t, addr: *const sockaddr, len: socklen_t) BindError!void {
    if (builtin.os.tag == .linux) {
        const rc = linux.bind(@intCast(fd), @ptrCast(addr), len);
        switch (linux.errno(rc)) {
            .SUCCESS => return,
            .ACCES => return error.AddressUnavailable,
            .ADDRINUSE => return error.AddressInUse,
            .ADDRNOTAVAIL => return error.AddressUnavailable,
            .AFNOSUPPORT => return error.AddressFamilyUnsupported,
            .NOBUFS, .NOMEM => return error.SystemResources,
            .NETDOWN => return error.NetworkDown,
            .PROTONOSUPPORT => return error.ProtocolUnsupportedBySystem,
            .PFNOSUPPORT => return error.ProtocolUnsupportedByAddressFamily,
            .NFILE => return error.ProcessFdQuotaExceeded,
            .MFILE => return error.SystemFdQuotaExceeded,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    } else if (builtin.os.tag == .macos) {
        const rc = std.c.bind(@intCast(fd), @ptrCast(addr), len);
        if (rc < 0) {
            const err = getErrno(rc);
            return switch (err) {
                .ACCES => error.AddressUnavailable,
                .ADDRINUSE => error.AddressInUse,
                .ADDRNOTAVAIL => error.AddressUnavailable,
                .AFNOSUPPORT => error.AddressFamilyUnsupported,
                .NOBUFS, .NOMEM => error.SystemResources,
                .NETDOWN => error.NetworkDown,
                .PROTONOSUPPORT => error.ProtocolUnsupportedBySystem,
                .PFNOSUPPORT => error.ProtocolUnsupportedByAddressFamily,
                .NFILE => error.ProcessFdQuotaExceeded,
                .MFILE => error.SystemFdQuotaExceeded,
                else => std.posix.unexpectedErrno(err),
            };
        }
    } else {
        @compileError("posix_compat.bind only implemented for Linux and macOS");
    }
}

pub fn listen(fd: socket_t, backlog: u31) ListenError!void {
    if (builtin.os.tag == .linux) {
        const rc = linux.listen(@intCast(fd), backlog);
        switch (linux.errno(rc)) {
            .SUCCESS => return,
            .ADDRINUSE => return error.AddressInUse,
            .ADDRNOTAVAIL => return error.AddressUnavailable,
            .NOBUFS, .NOMEM => return error.SystemResources,
            .NETDOWN => return error.NetworkDown,
            .NFILE => return error.ProcessFdQuotaExceeded,
            .MFILE => return error.SystemFdQuotaExceeded,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    } else if (builtin.os.tag == .macos) {
        const rc = std.c.listen(@intCast(fd), @intCast(backlog));
        if (rc < 0) {
            const err = getErrno(rc);
            return switch (err) {
                .ADDRINUSE => error.AddressInUse,
                .ADDRNOTAVAIL => error.AddressUnavailable,
                .NOBUFS, .NOMEM => error.SystemResources,
                .NETDOWN => error.NetworkDown,
                .NFILE => error.ProcessFdQuotaExceeded,
                .MFILE => error.SystemFdQuotaExceeded,
                else => std.posix.unexpectedErrno(err),
            };
        }
    } else {
        @compileError("posix_compat.listen only implemented for Linux and macOS");
    }
}

pub fn accept(fd: socket_t, addr: ?*sockaddr, len: ?*socklen_t, flags: u32) AcceptError!socket_t {
    if (builtin.os.tag == .linux) {
        const addr_cast: ?*linux.sockaddr = if (addr) |a| @ptrCast(a) else null;
        const rc = if (flags == 0)
            linux.accept(@intCast(fd), addr_cast, len)
        else
            linux.accept4(@intCast(fd), addr_cast, len, flags);
        switch (linux.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .AGAIN => return error.WouldBlock,
            .CONNABORTED => return error.ConnectionAborted,
            .INVAL => return error.SocketNotListening,
            .NOBUFS, .NOMEM => return error.SystemResources,
            .NFILE => return error.ProcessFdQuotaExceeded,
            .MFILE => return error.SystemFdQuotaExceeded,
            .NETDOWN => return error.NetworkDown,
            .PERM, .ACCES => return error.BlockedByFirewall,
            .PROTO => return error.ProtocolFailure,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    } else if (builtin.os.tag == .macos) {
        // macOS accept() doesn't support flags parameter
        // We need to use fcntl to set socket options after accept
        const needs_nonblock = (flags & std.posix.SOCK.NONBLOCK) != 0; // 0x10000 on macOS
        const needs_cloexec = (flags & std.posix.SOCK.CLOEXEC) != 0;  // 0x8000 on macOS

        const rc = std.c.accept(@intCast(fd), @ptrCast(addr), len);
        if (rc < 0) {
            const err = getErrno(rc);
            return switch (err) {
                .AGAIN => error.WouldBlock,
                .CONNABORTED => error.ConnectionAborted,
                .INVAL => error.SocketNotListening,
                .NOBUFS, .NOMEM => error.SystemResources,
                .NFILE => error.ProcessFdQuotaExceeded,
                .MFILE => error.SystemFdQuotaExceeded,
                .NETDOWN => error.NetworkDown,
                .PERM, .ACCES => error.BlockedByFirewall,
                .PROTO => error.ProtocolFailure,
                else => std.posix.unexpectedErrno(err),
            };
        }
        const accepted_fd: socket_t = @intCast(rc);

        // Set CLOEXEC via fcntl if requested
        if (needs_cloexec) {
            const cloexec_flags = std.c.fcntl(accepted_fd, std.posix.F.GETFD, @as(c_int, 0));
            if (cloexec_flags >= 0) {
                _ = std.c.fcntl(accepted_fd, std.posix.F.SETFD, @as(c_int, @intCast(cloexec_flags | std.posix.FD_CLOEXEC)));
            }
        }

        // Set NONBLOCK via fcntl if requested
        if (needs_nonblock) {
            const O_NONBLOCK: c_int = 0x0004; // macOS O_NONBLOCK value
            var nonblock_flags = std.c.fcntl(accepted_fd, std.posix.F.GETFL, @as(c_int, 0));
            if (nonblock_flags < 0) {
                _ = std.c.close(accepted_fd);
                return error.SystemResources;
            }
            nonblock_flags |= O_NONBLOCK;
            const set_result = std.c.fcntl(accepted_fd, std.posix.F.SETFL, nonblock_flags);
            if (set_result < 0) {
                _ = std.c.close(accepted_fd);
                return error.SystemResources;
            }
        }

        return accepted_fd;
    } else {
        @compileError("posix_compat.accept only implemented for Linux and macOS");
    }
}

pub fn connect(fd: socket_t, addr: *const sockaddr, len: socklen_t) ConnectError!void {
    if (builtin.os.tag == .linux) {
        const rc = linux.connect(@intCast(fd), @ptrCast(addr), len);
        switch (linux.errno(rc)) {
            .SUCCESS => return,
            .ADDRNOTAVAIL => return error.AddressUnavailable,
            .AFNOSUPPORT => return error.AddressFamilyUnsupported,
            .NOBUFS, .NOMEM => return error.SystemResources,
            .INPROGRESS => return error.ConnectionPending,
            .CONNREFUSED => return error.ConnectionRefused,
            .CONNRESET => return error.ConnectionResetByPeer,
            .HOSTUNREACH => return error.HostUnreachable,
            .NETUNREACH => return error.NetworkUnreachable,
            .TIMEDOUT => return error.Timeout,
            .ACCESS => return error.AccessDenied,
            .AGAIN => return error.WouldBlock,
            .NETDOWN => return error.NetworkDown,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    } else if (builtin.os.tag == .macos) {
        const rc = std.c.connect(@intCast(fd), @ptrCast(addr), len);
        if (rc < 0) {
            const err = getErrno(rc);
            return switch (err) {
                .ADDRNOTAVAIL => error.AddressUnavailable,
                .AFNOSUPPORT => error.AddressFamilyUnsupported,
                .NOBUFS, .NOMEM => error.SystemResources,
                .INPROGRESS => error.ConnectionPending,
                .CONNREFUSED => error.ConnectionRefused,
                .CONNRESET => error.ConnectionResetByPeer,
                .HOSTUNREACH => error.HostUnreachable,
                .NETUNREACH => error.NetworkUnreachable,
                .TIMEDOUT => error.Timeout,
                .ACCES => error.AccessDenied,
                .AGAIN => error.WouldBlock,
                .NETDOWN => error.NetworkDown,
                else => std.posix.unexpectedErrno(err),
            };
        }
    } else {
        @compileError("posix_compat.connect only implemented for Linux and macOS");
    }
}

pub fn shutdown(fd: socket_t, how: ShutdownHow) ShutdownError!void {
    if (builtin.os.tag == .linux) {
        const rc = linux.shutdown(@intCast(fd), @intFromEnum(how));
        switch (linux.errno(rc)) {
            .SUCCESS => return,
            .NOTCONN => return error.SocketNotConnected,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    } else if (builtin.os.tag == .macos) {
        const rc = std.c.shutdown(@intCast(fd), @intFromEnum(how));
        if (rc < 0) {
            const err = getErrno(rc);
            return switch (err) {
                .NOTCONN => error.SocketNotConnected,
                else => std.posix.unexpectedErrno(err),
            };
        }
    } else {
        @compileError("posix_compat.shutdown only implemented for Linux and macOS");
    }
}

pub fn getsockname(fd: socket_t, addr: *sockaddr, len: *socklen_t) UnexpectedError!void {
    if (builtin.os.tag == .linux) {
        const rc = linux.getsockname(@intCast(fd), @ptrCast(addr), len);
        switch (linux.errno(rc)) {
            .SUCCESS => return,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    } else if (builtin.os.tag == .macos) {
        const rc = std.c.getsockname(@intCast(fd), @ptrCast(addr), len);
        if (rc < 0) {
            const err = getErrno(rc);
            return std.posix.unexpectedErrno(err);
        }
    } else {
        @compileError("posix_compat.getsockname only implemented for Linux and macOS");
    }
}

pub fn write(fd: socket_t, buf: []const u8) WriteError!usize {
    if (buf.len == 0) return 0;
    if (builtin.os.tag == .linux) {
        const rc = linux.write(@intCast(fd), buf.ptr, buf.len);
        switch (linux.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .AGAIN => return error.WouldBlock,
            .PIPE => return error.BrokenPipe,
            .CONNRESET => return error.ConnectionResetByPeer,
            .IO => return error.InputOutput,
            .NOBUFS, .NOMEM => return error.SystemResources,
            .PERM, .ACCES => return error.AccessDenied,
            .NETDOWN => return error.NetworkDown,
            .NOTCONN => return error.SocketNotConnected,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    } else if (builtin.os.tag == .macos) {
        const rc = std.c.write(@intCast(fd), buf.ptr, buf.len);
        if (rc < 0) {
            const err = getErrno(rc);
            return switch (err) {
                .AGAIN => error.WouldBlock,
                .PIPE => error.BrokenPipe,
                .CONNRESET => error.ConnectionResetByPeer,
                .IO => error.InputOutput,
                .NOBUFS, .NOMEM => error.SystemResources,
                .PERM, .ACCES => error.AccessDenied,
                .NETDOWN => error.NetworkDown,
                .NOTCONN => error.SocketNotConnected,
                else => std.posix.unexpectedErrno(err),
            };
        }
        return @intCast(rc);
    } else {
        @compileError("posix_compat.write only implemented for Linux and macOS");
    }
}

pub fn writev(fd: socket_t, vec: []const iovec_const) WritevError!usize {
    if (vec.len == 0) return 0;
    if (builtin.os.tag == .linux) {
        const rc = linux.writev(@intCast(fd), @ptrCast(vec.ptr), vec.len);
        switch (linux.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .AGAIN => return error.WouldBlock,
            .PIPE => return error.BrokenPipe,
            .CONNRESET => return error.ConnectionResetByPeer,
            .IO => return error.InputOutput,
            .NOBUFS, .NOMEM => return error.SystemResources,
            .PERM, .ACCES => return error.AccessDenied,
            .NETDOWN => return error.NetworkDown,
            .NOTCONN => return error.SocketNotConnected,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    } else if (builtin.os.tag == .macos) {
        const rc = std.c.writev(@intCast(fd), @ptrCast(vec.ptr), @intCast(vec.len));
        if (rc < 0) {
            const err = getErrno(rc);
            return switch (err) {
                .AGAIN => error.WouldBlock,
                .PIPE => error.BrokenPipe,
                .CONNRESET => error.ConnectionResetByPeer,
                .IO => error.InputOutput,
                .NOBUFS, .NOMEM => error.SystemResources,
                .PERM, .ACCES => error.AccessDenied,
                .NETDOWN => error.NetworkDown,
                .NOTCONN => error.SocketNotConnected,
                else => std.posix.unexpectedErrno(err),
            };
        }
        return @intCast(rc);
    } else {
        @compileError("posix_compat.writev only implemented for Linux and macOS");
    }
}

pub fn epoll_create1(flags: u32) UnexpectedError!fd_t {
    if (builtin.os.tag != .linux) @compileError("posix_compat.epoll_create1 only implemented for Linux");
    const rc = linux.epoll_create1(flags);
    switch (linux.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        else => |err| return std.posix.unexpectedErrno(err),
    }
}

pub fn epoll_ctl(fd: fd_t, op: u32, sock: socket_t, event: ?*linux.epoll_event) UnexpectedError!void {
    if (builtin.os.tag != .linux) @compileError("posix_compat.epoll_ctl only implemented for Linux");
    const rc = linux.epoll_ctl(@intCast(fd), op, @intCast(sock), event);
    switch (linux.errno(rc)) {
        .SUCCESS => return,
        else => |err| return std.posix.unexpectedErrno(err),
    }
}

pub fn epoll_wait(fd: fd_t, events: []linux.epoll_event, timeout: i32) UnexpectedError!usize {
    if (builtin.os.tag != .linux) @compileError("posix_compat.epoll_wait only implemented for Linux");
    const rc = linux.epoll_wait(@intCast(fd), events.ptr, @intCast(events.len), timeout);
    switch (linux.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        else => |err| return std.posix.unexpectedErrno(err),
    }
}

pub fn pipe2(flags: linux.O) PipeError![2]fd_t {
    if (builtin.os.tag != .linux) @compileError("posix_compat.pipe2 only implemented for Linux");
    var fds: [2]fd_t = undefined;
    const rc = linux.pipe2(&fds, @bitCast(flags));
    switch (linux.errno(rc)) {
        .SUCCESS => return fds,
        .NOMEM => return error.SystemResources,
        else => |err| return std.posix.unexpectedErrno(err),
    }
}

pub fn getrandom(buf: []u8) std.Io.RandomSecureError!void {
    const io = std.Io.Threaded.global_single_threaded.ioBasic();
    return io.randomSecure(buf);
}

pub const ShutdownHow = if (builtin.os.tag == .linux)
    enum(u32) {
        recv = linux.SHUT.RD,
        send = linux.SHUT.WR,
        both = linux.SHUT.RDWR,
    }
else
    enum(u32) {
        recv = 0,
        send = 1,
        both = 2,
    };

pub const timespec = std.posix.timespec;

pub fn kqueue() UnexpectedError!fd_t {
    if (builtin.os.tag == .macos) {
        const rc = std.c.kqueue();
        if (rc < 0) {
            const err = getErrno(rc);
            return std.posix.unexpectedErrno(err);
        }
        return @intCast(rc);
    } else {
        @compileError("kqueue only supported on macOS");
    }
}

pub fn kevent(kq: fd_t, changelist: []const Kevent, eventlist: []Kevent, timeout: ?*const timespec) UnexpectedError!usize {
    if (builtin.os.tag == .macos) {
        const rc = std.c.kevent(
            @intCast(kq),
            @ptrCast(changelist.ptr),
            @intCast(changelist.len),
            @ptrCast(eventlist.ptr),
            @intCast(eventlist.len),
            timeout,
        );
        if (rc < 0) {
            const err = getErrno(rc);
            return std.posix.unexpectedErrno(err);
        }
        return @intCast(rc);
    } else {
        @compileError("kevent only supported on macOS");
    }
}
