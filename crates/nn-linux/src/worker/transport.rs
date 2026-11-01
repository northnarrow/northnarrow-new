//! The core ↔ worker channel's packets (R14a, plan §3.5): a
//! `socketpair(AF_UNIX, SOCK_SEQPACKET)`, one message per packet. No
//! descriptor ever crosses it (`nn_proto::ipc`): a receive gives no control
//! buffer, so a descriptor sent along is closed by the kernel and the
//! packet is refused (`MSG_CTRUNC`); a packet larger than the buffer is
//! refused too (`MSG_TRUNC`, its real length asked for). Used by both
//! ends: the worker's seccomp filter keeps `recvmsg` and `sendmsg` on its
//! channel only.

use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::time::Instant;

use nn_proto::ipc::{Violation, MAX_FRAME};

fn cvt(rc: libc::c_int) -> io::Result<libc::c_int> {
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc)
    }
}

/// A connected `SOCK_SEQPACKET` pair, both ends close-on-exec.
pub fn socketpair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: a valid out-array of two ints.
    cvt(unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    })?;
    // SAFETY: the kernel just returned these two descriptors to us.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Send one packet of at most [`MAX_FRAME`] bytes. `MSG_NOSIGNAL`: a
/// closed peer is an `EPIPE`, never a `SIGPIPE`.
pub fn send(sock: RawFd, bytes: &[u8]) -> io::Result<()> {
    if bytes.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "packet too large",
        ));
    }
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr() as *mut libc::c_void,
        iov_len: bytes.len(),
    };
    // SAFETY: zeroed msghdr is a valid empty header.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    loop {
        // SAFETY: msg describes a live buffer for the duration of the call.
        let n = unsafe { libc::sendmsg(sock, &msg, libc::MSG_NOSIGNAL) };
        if n >= 0 {
            if n as usize != bytes.len() {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "short packet"));
            }
            return Ok(());
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

/// What a receive gave.
#[derive(Debug, PartialEq, Eq)]
pub enum Recv {
    /// One whole packet of this many bytes, in the buffer.
    Packet(usize),
    /// The peer closed the channel.
    Closed,
    /// Nothing to read (a non-blocking receive).
    Empty,
    /// The packet broke the channel's rules: too large, or ancillary
    /// data (a descriptor) came with it — dropped, the descriptor closed.
    Refused(Violation),
}

/// Receive one packet into `buf` (at least [`MAX_FRAME`] bytes).
pub fn recv(sock: RawFd, buf: &mut [u8], nonblocking: bool) -> io::Result<Recv> {
    debug_assert!(buf.len() >= MAX_FRAME);
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    // SAFETY: zeroed msghdr is a valid empty header: no control buffer.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    // MSG_TRUNC: the real length of a packet larger than the buffer.
    let flags = libc::MSG_TRUNC | if nonblocking { libc::MSG_DONTWAIT } else { 0 };
    let n = loop {
        // SAFETY: msg describes a live, writable buffer.
        let n = unsafe { libc::recvmsg(sock, &mut msg, flags) };
        if n >= 0 {
            break n as usize;
        }
        let e = io::Error::last_os_error();
        match e.kind() {
            io::ErrorKind::Interrupted => continue,
            io::ErrorKind::WouldBlock => return Ok(Recv::Empty),
            _ => return Err(e),
        }
    };
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Ok(Recv::Refused(Violation::Ancillary));
    }
    if msg.msg_flags & libc::MSG_TRUNC != 0 || n > buf.len() {
        return Ok(Recv::Refused(Violation::Oversized(n)));
    }
    if n == 0 {
        // SOCK_SEQPACKET: a zero-length read is the peer's end (a worker
        // never sends an empty packet: postcard frames are never empty).
        return Ok(Recv::Closed);
    }
    Ok(Recv::Packet(n))
}

/// Wait until `sock` is readable or `deadline` passes: `Ok(true)` readable
/// (or hung up), `Ok(false)` timed out.
pub fn wait_readable(sock: RawFd, deadline: Instant) -> io::Result<bool> {
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let ms = libc::c_int::try_from(left.as_millis()).unwrap_or(libc::c_int::MAX);
        let mut pfd = libc::pollfd {
            fd: sock,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd.
        let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
        if rc > 0 {
            return Ok(true);
        }
        if rc == 0 {
            if Instant::now() >= deadline {
                return Ok(false);
            }
            continue;
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::time::Duration;

    #[test]
    fn a_packet_crosses_whole() {
        let (a, b) = socketpair().unwrap();
        send(a.as_raw_fd(), b"hello").unwrap();
        let mut buf = vec![0u8; MAX_FRAME];
        assert_eq!(
            recv(b.as_raw_fd(), &mut buf, true).unwrap(),
            Recv::Packet(5)
        );
        assert_eq!(&buf[..5], b"hello");
        assert_eq!(recv(b.as_raw_fd(), &mut buf, true).unwrap(), Recv::Empty);
        drop(a);
        // closed once every copy of `a` is gone: a child another test of
        // this process forked meanwhile may hold one for a moment
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match recv(b.as_raw_fd(), &mut buf, true).unwrap() {
                Recv::Closed => break,
                Recv::Empty if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn an_oversized_packet_is_refused_and_the_next_one_reads() {
        let (a, b) = socketpair().unwrap();
        // the sender's bound is ours; a raw sendmsg of a larger packet is
        // what a hostile worker would do
        let big = vec![7u8; MAX_FRAME + 100];
        let iov = libc::iovec {
            iov_base: big.as_ptr() as *mut libc::c_void,
            iov_len: big.len(),
        };
        // SAFETY: zeroed msghdr, one live iovec.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &iov as *const _ as *mut _;
        msg.msg_iovlen = 1;
        // SAFETY: sendmsg on our own socket.
        let n = unsafe { libc::sendmsg(a.as_raw_fd(), &msg, 0) };
        assert_eq!(n as usize, big.len(), "{}", io::Error::last_os_error());
        send(a.as_raw_fd(), b"next").unwrap();
        let mut buf = vec![0u8; MAX_FRAME];
        assert_eq!(
            recv(b.as_raw_fd(), &mut buf, true).unwrap(),
            Recv::Refused(Violation::Oversized(MAX_FRAME + 100))
        );
        assert_eq!(
            recv(b.as_raw_fd(), &mut buf, true).unwrap(),
            Recv::Packet(4)
        );
        assert!(
            send(a.as_raw_fd(), &big).is_err(),
            "our own sender refuses it"
        );
    }

    #[test]
    fn a_descriptor_sent_along_is_refused_and_closed() {
        let (a, b) = socketpair().unwrap();
        let (x, _y) = socketpair().unwrap();
        let fd = x.as_raw_fd();
        let payload = b"fd";
        let iov = libc::iovec {
            iov_base: payload.as_ptr() as *mut libc::c_void,
            iov_len: payload.len(),
        };
        let mut cbuf = [0u64; 8];
        // SAFETY: zeroed msghdr; a control buffer large enough for one fd.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &iov as *const _ as *mut _;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr().cast();
        // SAFETY: CMSG_* are size computations and writes inside cbuf.
        unsafe {
            msg.msg_controllen = libc::CMSG_SPACE(4) as _;
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(4) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(c) as *mut RawFd, fd);
            assert_eq!(libc::sendmsg(a.as_raw_fd(), &msg, 0), 2);
        }
        let mut buf = vec![0u8; MAX_FRAME];
        assert_eq!(
            recv(b.as_raw_fd(), &mut buf, true).unwrap(),
            Recv::Refused(Violation::Ancillary)
        );
    }

    #[test]
    fn the_wait_ends_at_its_deadline_or_at_a_packet() {
        let (a, b) = socketpair().unwrap();
        let t = Instant::now();
        assert!(!wait_readable(b.as_raw_fd(), t + Duration::from_millis(30)).unwrap());
        assert!(t.elapsed() >= Duration::from_millis(30));
        send(a.as_raw_fd(), b"x").unwrap();
        assert!(wait_readable(b.as_raw_fd(), Instant::now() + Duration::from_secs(5)).unwrap());
    }
}
