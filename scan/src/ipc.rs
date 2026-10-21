//! The agent ↔ scanner channel (lab PR 223): a `SOCK_SEQPACKET` socket
//! pair, one message per packet, at most one descriptor per packet
//! (`SCM_RIGHTS`). Used by both ends: the agent links this crate's library
//! for these functions only.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use common::execq::MAX_PACKET;

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

/// Size of the control buffer for one descriptor.
const CMSG_SPACE_ONE_FD: usize = 64;

/// Send one packet, with `pass` attached when given. `MSG_NOSIGNAL`: a
/// closed peer is an `EPIPE`, never a `SIGPIPE`.
pub fn send(sock: RawFd, bytes: &[u8], pass: Option<RawFd>) -> io::Result<()> {
    if bytes.len() > MAX_PACKET {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "packet too large",
        ));
    }
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr() as *mut libc::c_void,
        iov_len: bytes.len(),
    };
    let mut cbuf = [0u64; CMSG_SPACE_ONE_FD / 8];
    // SAFETY: zeroed msghdr is a valid empty header.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if let Some(fd) = pass {
        // SAFETY: CMSG_SPACE/CMSG_LEN are pure size computations.
        let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
        debug_assert!(space <= CMSG_SPACE_ONE_FD);
        msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = space as _;
        // SAFETY: msg_control points at `space` writable, aligned bytes;
        // CMSG_FIRSTHDR returns a header inside them.
        unsafe {
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(c) as *mut RawFd, fd);
        }
    }
    loop {
        // SAFETY: msg describes live buffers for the duration of the call.
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

/// One received packet.
#[derive(Debug)]
pub struct Packet {
    /// Bytes received (0: the peer closed the channel).
    pub len: usize,
    /// The descriptor that came with it (close-on-exec).
    pub fd: Option<OwnedFd>,
}

/// Receive one packet into `buf` (at least [`MAX_PACKET`] bytes). A packet
/// or a control message that did not fit is an error, and every
/// descriptor received beyond the first is closed.
pub fn recv(sock: RawFd, buf: &mut [u8], nonblocking: bool) -> io::Result<Packet> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let mut cbuf = [0u64; 32];
    // SAFETY: zeroed msghdr is a valid empty header.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = std::mem::size_of_val(&cbuf) as _;
    let flags = libc::MSG_CMSG_CLOEXEC | if nonblocking { libc::MSG_DONTWAIT } else { 0 };
    let n = loop {
        // SAFETY: msg describes live, writable buffers.
        let n = unsafe { libc::recvmsg(sock, &mut msg, flags) };
        if n >= 0 {
            break n as usize;
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    };
    let mut first: Option<OwnedFd> = None;
    // SAFETY: walking the control messages the kernel wrote into cbuf.
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(c) as *const RawFd;
                let count = ((*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize)
                    / std::mem::size_of::<RawFd>();
                for i in 0..count {
                    let fd = OwnedFd::from_raw_fd(std::ptr::read_unaligned(data.add(i)));
                    if first.is_none() {
                        first = Some(fd);
                    } // else: dropped, closed
                }
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
    }
    if msg.msg_flags & libc::MSG_TRUNC != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "packet truncated",
        ));
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control data truncated",
        ));
    }
    Ok(Packet { len: n, fd: first })
}

/// `bytes` in a memfd sealed against any change (write, shrink, grow,
/// further seals), for the scanner's configuration.
pub fn sealed_memfd(name: &str, bytes: &[u8]) -> io::Result<OwnedFd> {
    let cname = std::ffi::CString::new(name).map_err(|_| io::ErrorKind::InvalidInput)?;
    // SAFETY: a valid C string; flags are plain constants.
    let fd = cvt(unsafe {
        libc::memfd_create(cname.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
    })?;
    // SAFETY: just created, owned here.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut off = 0usize;
    while off < bytes.len() {
        // SAFETY: the slice is valid for the length given.
        let n = unsafe {
            libc::write(
                fd.as_raw_fd(),
                bytes[off..].as_ptr() as *const libc::c_void,
                bytes.len() - off,
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        off += n as usize;
    }
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    // SAFETY: fcntl on an owned descriptor.
    cvt(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, seals) })?;
    Ok(fd)
}

/// `pread` the whole of `fd` up to `max` bytes (the configuration memfd).
pub fn read_all_at(fd: RawFd, len: u64, max: u64) -> io::Result<Vec<u8>> {
    if len > max {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "too large"));
    }
    let mut out = vec![0u8; len as usize];
    let mut got = 0usize;
    while got < out.len() {
        // SAFETY: the destination slice is valid for its length.
        let n = unsafe {
            libc::pread(
                fd,
                out[got..].as_mut_ptr() as *mut libc::c_void,
                out.len() - got,
                got as libc::off_t,
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short config"));
        }
        got += n as usize;
    }
    Ok(out)
}

/// A file the scanner reads through its descriptor: `pread` and a raw
/// `fstat(2)` (glibc's `fstat` is `newfstatat` with a path argument, which
/// the seccomp filter does not allow).
pub struct FdFile<'a>(pub &'a OwnedFd);

impl FdFile<'_> {
    /// Mode and size, from `fstat(2)`.
    pub fn stat(&self) -> io::Result<(u32, u64)> {
        // SAFETY: zeroed stat is a valid out-buffer.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: raw fstat on an owned descriptor into a stat buffer.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_fstat,
                self.0.as_raw_fd(),
                &mut st as *mut libc::stat,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((st.st_mode, st.st_size as u64))
    }
}

impl crate::engine::ReadAt for FdFile<'_> {
    fn read_at(&self, buf: &mut [u8], off: u64) -> io::Result<usize> {
        // SAFETY: the destination slice is valid for its length.
        let n = unsafe {
            libc::pread(
                self.0.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                off as libc::off_t,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }
    fn size(&self) -> io::Result<u64> {
        self.stat().map(|(_, s)| s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_packet_and_its_descriptor_cross_the_pair() {
        let (a, b) = socketpair().unwrap();
        let memfd = sealed_memfd("nn-test", b"config bytes").unwrap();
        send(a.as_raw_fd(), b"hello", Some(memfd.as_raw_fd())).unwrap();
        let mut buf = vec![0u8; MAX_PACKET];
        let p = recv(b.as_raw_fd(), &mut buf, false).unwrap();
        assert_eq!(&buf[..p.len], b"hello");
        let fd = p.fd.expect("descriptor received");
        assert_eq!(
            read_all_at(fd.as_raw_fd(), 12, 100).unwrap(),
            b"config bytes"
        );
        assert!(read_all_at(fd.as_raw_fd(), 12, 4).is_err(), "bounded");
        // sealed: the receiver cannot change it
        let n = unsafe { libc::write(fd.as_raw_fd(), b"x".as_ptr() as *const _, 1) };
        assert!(n < 0);
        // without a descriptor; then EOF once the peer is gone
        send(a.as_raw_fd(), b"no fd", None).unwrap();
        let p = recv(b.as_raw_fd(), &mut buf, false).unwrap();
        assert!(p.fd.is_none());
        assert_eq!(p.len, 5);
        assert!(
            recv(b.as_raw_fd(), &mut buf, true).is_err(),
            "nothing queued"
        );
        drop(a);
        assert_eq!(recv(b.as_raw_fd(), &mut buf, false).unwrap().len, 0);
    }

    #[test]
    fn an_oversized_packet_is_refused() {
        let (a, b) = socketpair().unwrap();
        assert!(send(a.as_raw_fd(), &vec![0; MAX_PACKET + 1], None).is_err());
        send(a.as_raw_fd(), &[1; 100], None).unwrap();
        let mut small = [0u8; 10];
        assert!(recv(b.as_raw_fd(), &mut small, false).is_err(), "truncated");
    }
}
