const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

pub const system = std.posix.system;
pub const errno = std.posix.errno;
pub const UnexpectedError = std.posix.UnexpectedError;

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
    if (builtin.os.tag != .linux) @compileError("posix_compat.socket only implemented for Linux");
    const rc = linux.socket(@intCast(domain), @intCast(socket_type), @intCast(protocol));
    switch (linux.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .ACCES => return error.AccessDenied,
        .AFNOSUPPORT => return error.AddressFamilyUnsupported,
        .PROTONOSUPPORT, .NOPROTOOPT => return error.ProtocolNotSupported,
        .NFILE => return error.ProcessFdQuotaExceeded,
        .MFILE => return error.SystemFdQuotaExceeded,
        .NOMEM, .NOBUFS => return error.SystemResources,
        .INVAL => return error.SocketTypeNotSupported,
        else => |err| return std.posix.unexpectedErrno(err),
    }
}

pub fn bind(fd: socket_t, addr: *const sockaddr, len: socklen_t) BindError!void {
    if (builtin.os.tag != .linux) @compileError("posix_compat.bind only implemented for Linux");
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
}

pub fn listen(fd: socket_t, backlog: u31) ListenError!void {
    if (builtin.os.tag != .linux) @compileError("posix_compat.listen only implemented for Linux");
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
}

pub fn accept(fd: socket_t, addr: ?*sockaddr, len: ?*socklen_t, flags: u32) AcceptError!socket_t {
    if (builtin.os.tag != .linux) @compileError("posix_compat.accept only implemented for Linux");
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
}

pub fn connect(fd: socket_t, addr: *const sockaddr, len: socklen_t) ConnectError!void {
    if (builtin.os.tag != .linux) @compileError("posix_compat.connect only implemented for Linux");
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
}

pub fn shutdown(fd: socket_t, how: ShutdownHow) ShutdownError!void {
    if (builtin.os.tag != .linux) @compileError("posix_compat.shutdown only implemented for Linux");
    const rc = linux.shutdown(@intCast(fd), @intFromEnum(how));
    switch (linux.errno(rc)) {
        .SUCCESS => return,
        .NOTCONN => return error.SocketNotConnected,
        else => |err| return std.posix.unexpectedErrno(err),
    }
}

pub fn getsockname(fd: socket_t, addr: *sockaddr, len: *socklen_t) UnexpectedError!void {
    if (builtin.os.tag != .linux) @compileError("posix_compat.getsockname only implemented for Linux");
    const rc = linux.getsockname(@intCast(fd), @ptrCast(addr), len);
    switch (linux.errno(rc)) {
        .SUCCESS => return,
        else => |err| return std.posix.unexpectedErrno(err),
    }
}

pub fn write(fd: socket_t, buf: []const u8) WriteError!usize {
    if (builtin.os.tag != .linux) @compileError("posix_compat.write only implemented for Linux");
    if (buf.len == 0) return 0;
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
}

pub fn writev(fd: socket_t, vec: []const iovec_const) WritevError!usize {
    if (builtin.os.tag != .linux) @compileError("posix_compat.writev only implemented for Linux");
    if (vec.len == 0) return 0;
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

pub const ShutdownHow = enum(u32) {
    recv = linux.SHUT.RD,
    send = linux.SHUT.WR,
    both = linux.SHUT.RDWR,
};

pub fn kqueue() UnexpectedError!fd_t {
    @compileError("kqueue not supported on this platform");
}

pub fn kevent(_: fd_t, _: []const Kevent, _: []Kevent, _: ?*const std.posix.timespec) UnexpectedError!usize {
    @compileError("kevent not supported on this platform");
}
