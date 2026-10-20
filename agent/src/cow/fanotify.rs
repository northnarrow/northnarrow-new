//! The fanotify side of the guard: the group, its marks, its events and
//! answers, and how the writer meant to open the file.
//!
//! `FAN_OPEN_PERM` stops the opening task inside `open()` — after the
//! LSM's `file_open` and before `O_TRUNC` is applied and before the open
//! returns — until the group answers. The event gives a file descriptor
//! the kernel opened for the listener (with the group's `event_f_flags`:
//! read-only here) and the opener's thread id (`FAN_REPORT_TID`). It does
//! **not** give the opener's flags: the metadata has no such field, and
//! the event descriptor's own `fdinfo` shows the listener's `O_RDONLY`,
//! not the writer's. The writer's flags are read from
//! `/proc/<tid>/syscall` instead — the syscall the blocked task is in and
//! its arguments, from the registers saved at syscall entry (not from the
//! task's memory, so another thread of the writer cannot rewrite them):
//! `open`, `openat` and `open_by_handle_at` carry the flags in a register.
//! `openat2` carries them in user memory (`struct open_how`), which a
//! second thread could change after the kernel read it: it counts as a
//! write. So does anything else the file does not explain (an `io_uring`
//! open, a 32-bit task, a task the kernel reports `running`).

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;

use parking_lot::Mutex;

/// One event of the group's queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawEvent {
    pub mask: u64,
    /// The listener's descriptor on the file (`FAN_NOFD` for an overflow).
    pub fd: RawFd,
    /// The opener's thread id (`FAN_REPORT_TID`).
    pub tid: i32,
}

/// Parse a buffer `read(2)` filled from the group. Stops at a truncated
/// record or one of a version this code does not know (the caller answers
/// the descriptors it got and reports the rest).
pub fn parse_events(buf: &[u8]) -> (Vec<RawEvent>, Option<String>) {
    const META_LEN: usize = std::mem::size_of::<libc::fanotify_event_metadata>();
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + META_LEN <= buf.len() {
        let event_len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap_or([0; 4])) as usize;
        let vers = buf[off + 4];
        let metadata_len =
            u16::from_ne_bytes(buf[off + 6..off + 8].try_into().unwrap_or([0; 2])) as usize;
        if vers != libc::FANOTIFY_METADATA_VERSION {
            return (out, Some(format!("fanotify metadata version {vers}")));
        }
        if event_len < META_LEN || metadata_len < META_LEN || off + event_len > buf.len() {
            return (
                out,
                Some(format!("truncated fanotify record ({event_len} bytes)")),
            );
        }
        let mask = u64::from_ne_bytes(buf[off + 8..off + 16].try_into().unwrap_or([0; 8]));
        let fd = i32::from_ne_bytes(buf[off + 16..off + 20].try_into().unwrap_or([0; 4]));
        let tid = i32::from_ne_bytes(buf[off + 20..off + 24].try_into().unwrap_or([0; 4]));
        out.push(RawEvent { mask, fd, tid });
        off += event_len;
    }
    (out, None)
}

/// The fanotify group: one descriptor, written by several threads (the
/// answers) and closed by any of them in an emergency. Closing it allows
/// every pending and queued open (the kernel's release of the group).
pub struct Group {
    fd: Mutex<Option<OwnedFd>>,
    raw: std::sync::atomic::AtomicI32,
}

impl Group {
    /// `fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_REPORT_TID)`,
    /// event descriptors read-only. Needs `CAP_SYS_ADMIN`.
    pub fn init() -> io::Result<Self> {
        // SAFETY: plain syscall with constant flags.
        let fd = unsafe {
            libc::fanotify_init(
                libc::FAN_CLASS_CONTENT | libc::FAN_CLOEXEC | libc::FAN_REPORT_TID,
                (libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC) as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a fresh descriptor we own.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Self {
            fd: Mutex::new(Some(owned)),
            raw: std::sync::atomic::AtomicI32::new(fd),
        })
    }

    /// The descriptor for `poll`/`read` (`-1` once closed).
    pub fn raw(&self) -> RawFd {
        self.raw.load(std::sync::atomic::Ordering::Acquire)
    }

    pub fn is_open(&self) -> bool {
        self.raw() >= 0
    }

    /// `fanotify_mark(FAN_MARK_ADD | flags, mask, AT_FDCWD, path)`.
    pub fn mark(&self, flags: libc::c_uint, mask: u64, path: &Path) -> io::Result<()> {
        let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        let g = self.fd.lock();
        let Some(fd) = g.as_ref() else {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        };
        // SAFETY: valid descriptor and NUL-terminated path.
        let rc = unsafe {
            libc::fanotify_mark(
                fd.as_raw_fd(),
                libc::FAN_MARK_ADD | flags,
                mask,
                libc::AT_FDCWD,
                c.as_ptr(),
            )
        };
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Answer `FAN_ALLOW` for `event_fd`. This lot never denies.
    pub fn allow(&self, event_fd: RawFd) -> io::Result<()> {
        let resp = libc::fanotify_response {
            fd: event_fd,
            response: libc::FAN_ALLOW,
        };
        let g = self.fd.lock();
        let Some(fd) = g.as_ref() else {
            // Closed: the kernel allowed everything pending at the release.
            return Ok(());
        };
        let len = std::mem::size_of::<libc::fanotify_response>();
        // SAFETY: valid descriptor, a response struct of the right size.
        let n = unsafe {
            libc::write(
                fd.as_raw_fd(),
                &resp as *const libc::fanotify_response as *const libc::c_void,
                len,
            )
        };
        if n as usize == len {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Read events into `buf` through the group's own descriptor, under
    /// its lock (the reader calls it once `poll` reported the group
    /// readable, so it does not block): `Ok(None)` once the group is closed
    /// ([`Self::close_now`]). Never a `read` of the number the closed
    /// descriptor had, which the process may already have given to another
    /// file — whose bytes the reader would take (lab, 21/10: the reader's
    /// read after the stop failed with EBADF, logged as an ERROR).
    pub fn read_events(&self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        let g = self.fd.lock();
        let Some(fd) = g.as_ref() else {
            return Ok(None);
        };
        // SAFETY: valid descriptor (held under the lock) and buffer.
        let n = unsafe {
            libc::read(
                fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Some(n as usize))
        }
    }

    /// Close the group now: the kernel allows every pending open, and no
    /// further event is generated. Idempotent.
    pub fn close_now(&self) {
        let mut g = self.fd.lock();
        self.raw.store(-1, std::sync::atomic::Ordering::Release);
        g.take();
    }
}

/// How the blocked writer opens the file, from `/proc/<tid>/syscall`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenIntent {
    /// `O_RDONLY` without `O_TRUNC`, or an exec.
    ReadOnly,
    /// For writing (`O_WRONLY`, `O_RDWR`, `O_TRUNC`, `creat`).
    Write,
    /// Not known: treated as a write.
    Unknown(&'static str),
}

impl OpenIntent {
    pub fn may_write(self) -> bool {
        !matches!(self, OpenIntent::ReadOnly)
    }
}

/// The open-family syscalls of one architecture: (number, index of the
/// flags argument), the always-writing `creat`, `openat2` and the execs.
struct SyscallTable {
    with_flags: &'static [(i64, usize)],
    creat: Option<i64>,
    openat2: i64,
    execs: &'static [i64],
}

#[cfg(target_arch = "x86_64")]
const TABLE: SyscallTable = SyscallTable {
    // open, openat, open_by_handle_at
    with_flags: &[(2, 1), (257, 2), (304, 2)],
    creat: Some(85),
    openat2: 437,
    // execve, execveat
    execs: &[59, 322],
};

#[cfg(target_arch = "aarch64")]
const TABLE: SyscallTable = SyscallTable {
    // openat, open_by_handle_at
    with_flags: &[(56, 2), (265, 2)],
    creat: None,
    openat2: 437,
    execs: &[221, 281],
};

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const TABLE: SyscallTable = SyscallTable {
    with_flags: &[],
    creat: None,
    openat2: 437,
    execs: &[],
};

/// Classify one `/proc/<tid>/syscall` line.
pub fn classify_syscall_line(line: &str) -> OpenIntent {
    let line = line.trim();
    if line == "running" {
        return OpenIntent::Unknown("task reported running");
    }
    let mut parts = line.split_whitespace();
    let Some(nr) = parts.next().and_then(|n| n.parse::<i64>().ok()) else {
        return OpenIntent::Unknown("unreadable syscall line");
    };
    if nr < 0 {
        return OpenIntent::Unknown("not in a syscall");
    }
    let args: Option<Vec<u64>> = parts
        .take(6)
        .map(|a| u64::from_str_radix(a.trim_start_matches("0x"), 16).ok())
        .collect();
    let Some(args) = args else {
        return OpenIntent::Unknown("unreadable syscall arguments");
    };
    if TABLE.execs.contains(&nr) {
        return OpenIntent::ReadOnly;
    }
    if TABLE.creat == Some(nr) {
        return OpenIntent::Write;
    }
    if nr == TABLE.openat2 {
        return OpenIntent::Write;
    }
    let Some((_, idx)) = TABLE.with_flags.iter().find(|(n, _)| *n == nr) else {
        return OpenIntent::Unknown("not an open syscall this table knows");
    };
    let Some(flags) = args.get(*idx) else {
        return OpenIntent::Unknown("syscall arguments missing");
    };
    let flags = (*flags & 0xffff_ffff) as u32 as i32;
    let acc = flags & libc::O_ACCMODE;
    if acc == libc::O_RDONLY && flags & libc::O_TRUNC == 0 {
        OpenIntent::ReadOnly
    } else {
        OpenIntent::Write
    }
}

/// Read and classify `/proc/<tid>/syscall` (needs `CAP_SYS_PTRACE` over
/// the task; Yama's `ptrace_scope=3` refuses it — every open then counts
/// as a write).
pub fn read_open_intent(tid: i32) -> OpenIntent {
    match std::fs::read_to_string(format!("/proc/{tid}/syscall")) {
        Ok(text) => classify_syscall_line(&text),
        Err(_) => OpenIntent::Unknown("/proc/<tid>/syscall unreadable"),
    }
}

/// The thread `tid` belongs to this process.
pub fn is_own_thread(tid: i32) -> bool {
    tid > 0 && std::fs::symlink_metadata(format!("/proc/self/task/{tid}")).is_ok()
}

/// The thread group (process) of `tid`, from `/proc/<tid>/status`.
pub fn tgid_of(tid: i32) -> Option<u32> {
    let text = std::fs::read_to_string(format!("/proc/{tid}/status")).ok()?;
    text.lines()
        .find_map(|l| l.strip_prefix("Tgid:"))
        .and_then(|v| v.trim().parse().ok())
}

/// `fstat` of an event descriptor.
pub fn fstat(fd: RawFd) -> io::Result<libc::stat> {
    // SAFETY: zeroed stat buffer filled by the kernel.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: valid pointer to a stat buffer.
    if unsafe { libc::fstat(fd, &mut st) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st)
}

/// The birth time (`statx` `STATX_BTIME`, ns) of the descriptor `fd`
/// itself (`name` `None`) or of `name` in the directory `fd`, without
/// following a link. `None` where the filesystem does not record it. It
/// tells a new file from the old one when the inode number was reused.
pub fn btime(fd: RawFd, name: Option<&str>) -> Option<i64> {
    let (path, flags) = match name {
        Some(n) => (std::ffi::CString::new(n).ok()?, libc::AT_SYMLINK_NOFOLLOW),
        None => (std::ffi::CString::new("").ok()?, libc::AT_EMPTY_PATH),
    };
    // SAFETY: zeroed statx buffer filled by the kernel.
    let mut sx: libc::statx = unsafe { std::mem::zeroed() };
    // SAFETY: valid descriptor, NUL-terminated path and buffer.
    let rc = unsafe { libc::statx(fd, path.as_ptr(), flags, libc::STATX_BTIME, &mut sx) };
    if rc < 0 || sx.stx_mask & libc::STATX_BTIME == 0 {
        return None;
    }
    Some(sx.stx_btime.tv_sec * 1_000_000_000 + sx.stx_btime.tv_nsec as i64)
}

/// The path of an event descriptor (`/proc/self/fd/<fd>`).
pub fn fd_path(fd: RawFd) -> Option<String> {
    let p = std::fs::read_link(format!("/proc/self/fd/{fd}")).ok()?;
    let s = p.to_str()?.to_string();
    (s.starts_with('/') && !s.ends_with(" (deleted)")).then_some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A group over any descriptor (a pipe): the descriptor handling only.
    fn group_of(fd: OwnedFd) -> Group {
        let raw = fd.as_raw_fd();
        Group {
            fd: Mutex::new(Some(fd)),
            raw: std::sync::atomic::AtomicI32::new(raw),
        }
    }

    fn pipe() -> (OwnedFd, OwnedFd) {
        let mut p = [0i32; 2];
        // SAFETY: a two-int array for pipe(2).
        assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0);
        // SAFETY: two fresh descriptors we own.
        unsafe { (OwnedFd::from_raw_fd(p[0]), OwnedFd::from_raw_fd(p[1])) }
    }

    /// Lab (21/10): the reader read the group's number after the guard's
    /// stop had closed it (EBADF, logged as an ERROR; or, the number given
    /// to another file meanwhile, that file's bytes). The read goes through
    /// the group's own descriptor: once closed it reads nothing, whatever
    /// the number now names.
    #[test]
    fn a_closed_group_reads_nothing_even_when_its_number_is_reused() {
        let (r, w) = pipe();
        let number = r.as_raw_fd();
        let g = group_of(r);
        let wr = |w: &OwnedFd, b: &[u8]| {
            // SAFETY: valid descriptor and buffer.
            assert_eq!(
                unsafe { libc::write(w.as_raw_fd(), b.as_ptr() as *const libc::c_void, b.len()) },
                b.len() as isize
            );
        };
        wr(&w, b"ev");
        let mut buf = [0u8; 16];
        assert_eq!(g.read_events(&mut buf).unwrap(), Some(2));
        g.close_now();
        assert!(!g.is_open());
        // the closed number handed to a new pipe, which has data
        let (r2, w2) = pipe();
        if r2.as_raw_fd() == number {
            wr(&w2, b"other file");
        }
        assert_eq!(g.read_events(&mut buf).unwrap(), None);
        drop((w, w2, r2));
    }

    fn record(mask: u64, fd: i32, tid: i32) -> Vec<u8> {
        let len = std::mem::size_of::<libc::fanotify_event_metadata>() as u32;
        let mut v = Vec::new();
        v.extend_from_slice(&len.to_ne_bytes());
        v.push(libc::FANOTIFY_METADATA_VERSION);
        v.push(0);
        v.extend_from_slice(&(len as u16).to_ne_bytes());
        v.extend_from_slice(&mask.to_ne_bytes());
        v.extend_from_slice(&fd.to_ne_bytes());
        v.extend_from_slice(&tid.to_ne_bytes());
        v
    }

    #[test]
    fn events_parse_and_a_bad_record_stops_the_batch() {
        let mut buf = record(libc::FAN_OPEN_PERM, 7, 4242);
        buf.extend(record(libc::FAN_Q_OVERFLOW, -1, 0));
        let (ev, err) = parse_events(&buf);
        assert!(err.is_none());
        assert_eq!(
            ev,
            vec![
                RawEvent {
                    mask: libc::FAN_OPEN_PERM,
                    fd: 7,
                    tid: 4242
                },
                RawEvent {
                    mask: libc::FAN_Q_OVERFLOW,
                    fd: -1,
                    tid: 0
                }
            ]
        );
        let mut bad = record(libc::FAN_OPEN_PERM, 7, 1);
        bad[4] = 2;
        let (ev, err) = parse_events(&bad);
        assert!(ev.is_empty() && err.unwrap().contains("version 2"));
        let mut short = record(libc::FAN_OPEN_PERM, 7, 1);
        short[0] = 200;
        let (ev, err) = parse_events(&short);
        assert!(ev.is_empty() && err.unwrap().contains("truncated"));
        assert_eq!(parse_events(&[]).0, Vec::new());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn syscall_lines_say_how_the_file_is_opened() {
        use OpenIntent::*;
        // openat(AT_FDCWD, p, O_RDONLY|O_CLOEXEC)
        assert_eq!(
            classify_syscall_line("257 0xffffff9c 0x7ffd1 0x80000 0x0 0x0 0x0 0x7ffd 0x7f12\n"),
            ReadOnly
        );
        // openat(…, O_WRONLY|O_CREAT|O_TRUNC)
        assert_eq!(
            classify_syscall_line("257 0xffffff9c 0x7ffd1 0x241 0x1b6 0x0 0x0 0x1 0x2"),
            Write
        );
        // openat(…, O_RDWR)
        assert_eq!(
            classify_syscall_line("257 0xffffff9c 0x1 0x2 0x0 0x0 0x0 0x1 0x2"),
            Write
        );
        // O_RDONLY|O_TRUNC truncates on Linux
        assert_eq!(
            classify_syscall_line("257 0xffffff9c 0x1 0x200 0x0 0x0 0x0 0x1 0x2"),
            Write
        );
        // open(p, O_RDONLY) / open(p, O_WRONLY)
        assert_eq!(
            classify_syscall_line("2 0x7ffd 0x0 0x0 0x0 0x0 0x0 0x1 0x2"),
            ReadOnly
        );
        assert_eq!(
            classify_syscall_line("2 0x7ffd 0x1 0x0 0x0 0x0 0x0 0x1 0x2"),
            Write
        );
        // creat, openat2: writes
        assert_eq!(
            classify_syscall_line("85 0x7ffd 0x1a4 0x0 0x0 0x0 0x0 0x1 0x2"),
            Write
        );
        assert_eq!(
            classify_syscall_line("437 0xffffff9c 0x1 0x7ffd 0x18 0x0 0x0 0x1 0x2"),
            Write
        );
        // execve: a read
        assert_eq!(
            classify_syscall_line("59 0x1 0x2 0x3 0x0 0x0 0x0 0x1 0x2"),
            ReadOnly
        );
        // a 32-bit openat (i386 295 = x86-64 preadv), io_uring, running
        assert!(matches!(
            classify_syscall_line("295 0xffffff9c 0x1 0x0 0x0 0x0 0x0 0x1 0x2"),
            Unknown(_)
        ));
        assert!(matches!(
            classify_syscall_line("426 0x3 0x1 0x0 0x0 0x0 0x0 0x1 0x2"),
            Unknown(_)
        ));
        assert!(matches!(classify_syscall_line("running"), Unknown(_)));
        assert!(matches!(
            classify_syscall_line("-1 0x7ffd 0x7f12"),
            Unknown(_)
        ));
        assert!(matches!(classify_syscall_line(""), Unknown(_)));
        assert!(matches!(
            classify_syscall_line("257 0xffffff9c"),
            Unknown(_)
        ));
        assert!(Write.may_write() && Unknown("x").may_write() && !ReadOnly.may_write());
    }

    #[test]
    fn own_threads_and_tgid() {
        let me = std::process::id();
        assert!(is_own_thread(me as i32));
        assert!(!is_own_thread(0));
        assert_eq!(tgid_of(me as i32), Some(me));
        let child = std::thread::spawn(|| {
            // SAFETY: gettid has no preconditions.
            unsafe { libc::syscall(libc::SYS_gettid) as i32 }
        })
        .join()
        .unwrap();
        // the thread has exited by now: no longer listed
        assert!(!is_own_thread(child) || tgid_of(child) == Some(me));
    }

    /// The blocked-task read works on this host for a thread of our own
    /// that sits in `read(2)` (no root needed for our own threads).
    #[test]
    fn a_blocked_thread_shows_its_syscall() {
        let (r, w) = {
            let mut fds = [0i32; 2];
            // SAFETY: valid array of two descriptors.
            assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
            (fds[0], fds[1])
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let h = std::thread::spawn(move || {
            // SAFETY: gettid has no preconditions.
            tx.send(unsafe { libc::syscall(libc::SYS_gettid) as i32 })
                .unwrap();
            let mut b = [0u8; 1];
            // SAFETY: valid buffer.
            unsafe { libc::read(r, b.as_mut_ptr() as *mut libc::c_void, 1) };
        });
        let tid = rx.recv().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        let text = std::fs::read_to_string(format!("/proc/{tid}/syscall")).unwrap_or_default();
        // SAFETY: valid buffer and descriptors.
        unsafe {
            libc::write(w, b"x".as_ptr() as *const libc::c_void, 1);
        }
        h.join().unwrap();
        // SAFETY: closing our pipe.
        unsafe {
            libc::close(r);
            libc::close(w);
        }
        if text.is_empty() {
            return; // a kernel without CONFIG_HAVE_ARCH_TRACEHOOK
        }
        // read(2) is no open: unknown, never read-only
        assert!(classify_syscall_line(&text).may_write(), "{text}");
    }
}
