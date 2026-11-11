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

use super::identity::FileId;

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
        .by_ref()
        .take(6)
        .map(|a| u64::from_str_radix(a.trim_start_matches("0x"), 16).ok())
        .collect();
    let Some(args) = args else {
        return OpenIntent::Unknown("unreadable syscall arguments");
    };
    // Lot 315 (external bug hunt 1.4, BUG-102): the user stack pointer and
    // program counter follow the arguments. A thread the kernel made — an
    // io_uring worker — never entered a syscall of its own: it shows its
    // creator's registers (the syscall the creator sat in when the worker
    // was made, an `openat(…, O_RDONLY)` if the creator chose so) with
    // both cleared. Whatever the line says then, it is not the open that
    // raised the event: counted as a write. (The worker is also known by
    // its flags, [`read_open_intent`]; this holds where the line is read
    // alone.)
    let regs: Vec<Option<u64>> = parts
        .take(2)
        .map(|a| u64::from_str_radix(a.trim_start_matches("0x"), 16).ok())
        .collect();
    match regs[..] {
        [Some(sp), Some(pc)] if sp != 0 && pc != 0 => {}
        [Some(_), Some(_)] => {
            return OpenIntent::Unknown("no user registers: a thread the kernel made")
        }
        _ => return OpenIntent::Unknown("unreadable user registers"),
    }
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

/// `PF_IO_WORKER` (`include/linux/sched.h`): an io_uring worker (io-wq)
/// or `SQPOLL` thread, made by the kernel inside a user process.
const PF_IO_WORKER: u64 = 0x10;

/// Whether a `/proc/<tid>/stat` text is an io_uring thread's: the task's
/// flags (field 9, the sixth after the `(comm)` field, which may hold
/// spaces or parentheses) carry `PF_IO_WORKER`. `None` when the text
/// does not hold them.
pub fn io_thread_in_stat(stat: &str) -> Option<bool> {
    let flags: u64 = stat
        .rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(6)?
        .parse()
        .ok()?;
    Some(flags & PF_IO_WORKER != 0)
}

/// Read and classify `/proc/<tid>/syscall` (needs `CAP_SYS_PTRACE` over
/// the task; Yama's `ptrace_scope=3` refuses it — every open then counts
/// as a write).
///
/// Lot 315 (external bug hunt 1.4, BUG-102): an io_uring worker's open
/// (`IORING_OP_OPENAT`, `O_WRONLY | O_TRUNC`) is not in its `syscall`
/// file, which shows the syscall its creator sat in when the worker was
/// made — a creator that sat in `openat(fifo, O_RDONLY)` made every later
/// open of that worker a "read", answered at once with no copy: the
/// file truncated and rewritten unprotected. The worker is known by the
/// kernel's flag on the task (`PF_IO_WORKER` in `/proc/<tid>/stat`), never
/// by its `comm` (`iou-wrk-<pid>`, which the process may rename): its
/// opens count as writes, and so does an open by a task whose flags cannot
/// be read.
pub fn read_open_intent(tid: i32) -> OpenIntent {
    let stat = read_task_stat(tid);
    open_intent(stat.as_deref(), || {
        std::fs::read_to_string(format!("/proc/{tid}/syscall"))
    })
}

/// [`read_open_intent`] from the task's `stat` text (`None`: unreadable)
/// and its `syscall` line, read only for a task that is not an io_uring
/// thread.
fn open_intent(stat: Option<&str>, syscall: impl FnOnce() -> io::Result<String>) -> OpenIntent {
    match stat.map(io_thread_in_stat) {
        Some(Some(false)) => {}
        Some(Some(true)) => {
            return OpenIntent::Unknown("an io_uring thread: its syscall line is its creator's")
        }
        _ => return OpenIntent::Unknown("/proc/<tid>/stat unreadable"),
    }
    match syscall() {
        Ok(text) => classify_syscall_line(&text),
        Err(_) => OpenIntent::Unknown("/proc/<tid>/syscall unreadable"),
    }
}

/// `/proc/<tid>/stat`, its `comm` whatever bytes the task chose (the byte
/// reader of lot 311).
fn read_task_stat(tid: i32) -> Option<String> {
    nn_linux::state_read::read_state(format!("/proc/{tid}/stat")).ok()
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

/// The identity of the file open at `fd` (`fstat` and its birth time).
pub fn file_id(fd: RawFd) -> io::Result<FileId> {
    let st = fstat(fd)?;
    Ok(FileId::new(st.st_dev, st.st_ino, btime(fd, None)))
}

/// The path of an event descriptor (`/proc/self/fd/<fd>`), while the file
/// can be reached.
///
/// Lot 315 (external bug hunt 1.4, BUG-109): whether the file was deleted
/// is the kernel's answer, never its name's. A file the writer renamed
/// `x (deleted)` (a rename opens nothing: no event) was taken for an
/// unlinked one by the name's ending alone, and written without a copy
/// (`skipped_unresolved_path`) — ransomware against the guard, one rename
/// per file. Now:
/// - a file with no link left (`st_nlink` 0) has no path: once its writer
///   closes it nothing reaches it, and there is nothing to keep;
/// - the path the kernel shows is the file's when a lookup of it finds
///   the descriptor's file (`lstat` of the path against `fstat` of the
///   descriptor, [`lookup_cached`]) — a live file named `x (deleted)`;
/// - otherwise the name it was opened by was unlinked while another link
///   of the file remains (a hard link made first): the path is that name,
///   the kernel's ` (deleted)` mark taken off. It was skipped too (a variant
///   met in lot 315's mini-hunt): `ln f g`, then an open of `f` for writing
///   and an unlink of `f` while the open waits on the guard.
pub fn fd_path(fd: RawFd) -> Option<String> {
    let p = std::fs::read_link(format!("/proc/self/fd/{fd}")).ok()?;
    let s = p.to_str()?.to_string();
    if !s.starts_with('/') {
        return None;
    }
    let st = fstat(fd).ok()?;
    if st.st_nlink == 0 {
        return None;
    }
    let Some(opened_by) = s.strip_suffix(" (deleted)") else {
        return Some(s);
    };
    let me = FileId::new(st.st_dev, st.st_ino, btime(fd, None));
    if lookup_cached(&s) == Some(me) {
        return Some(s);
    }
    Some(opened_by.to_string())
}

/// The identity of the file at `path`, without following a link at its
/// end — from the kernel's caches only: `openat2(O_PATH,
/// RESOLVE_CACHED | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)` and
/// `statx(AT_STATX_DONT_SYNC)`. A lookup that needs the filesystem fails
/// (`EAGAIN`) instead of waiting on it: the path is the writer's, and a
/// user's FUSE mount over one of its directories (the descriptor still
/// names the file below it) would otherwise hold the guard's reader for
/// as long as the user's daemon does not answer. `None` when the path
/// cannot be looked up so (a kernel before 5.12 too).
pub fn lookup_cached(path: &str) -> Option<FileId> {
    let c = std::ffi::CString::new(path).ok()?;
    // SAFETY: `open_how` is plain integers; zero is a valid value.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_CACHED | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS;
    // SAFETY: a NUL-terminated path and an open_how of the right size.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            c.as_ptr(),
            &how as *const libc::open_how,
            std::mem::size_of::<libc::open_how>(),
        )
    };
    if fd < 0 {
        return None;
    }
    // SAFETY: a fresh descriptor, ours alone.
    let fd = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };
    // SAFETY: zeroed statx buffer filled by the kernel.
    let mut sx: libc::statx = unsafe { std::mem::zeroed() };
    // SAFETY: valid descriptor, an empty NUL-terminated path and a buffer.
    let rc = unsafe {
        libc::statx(
            fd.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_STATX_DONT_SYNC,
            libc::STATX_INO | libc::STATX_BTIME,
            &mut sx,
        )
    };
    if rc < 0 || sx.stx_mask & libc::STATX_INO == 0 {
        return None;
    }
    let btime = (sx.stx_mask & libc::STATX_BTIME != 0)
        .then(|| sx.stx_btime.tv_sec * 1_000_000_000 + sx.stx_btime.tv_nsec as i64);
    Some(FileId::new(
        libc::makedev(sx.stx_dev_major, sx.stx_dev_minor),
        sx.stx_ino,
        btime,
    ))
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
        // Another thread of ours, held while it is looked at: listed, and
        // its thread group is this process (its tid is not our pid).
        let (tid_tx, tid_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let held = std::thread::spawn(move || {
            // SAFETY: gettid has no preconditions.
            let tid = unsafe { libc::syscall(libc::SYS_gettid) as i32 };
            tid_tx.send(tid).unwrap();
            let _ = done_rx.recv();
        });
        let child = tid_rx.recv().unwrap();
        assert_ne!(child, me as i32);
        assert!(is_own_thread(child));
        assert_eq!(tgid_of(child), Some(me));
        drop(done_tx);
        held.join().unwrap();
        // Exited: no longer listed, or still listed and ours. `join`
        // returns once the kernel has cleared the thread's tid (at its
        // `exit_mm`), before it releases the task: `/proc` may list the
        // thread a little longer, and both of its entries go with the
        // release. Lab PR 258: the listing was read first, and a release
        // between the two reads left a listed thread without a `status`
        // (lab PR 254's flake); the `status` is read first now — a thread
        // still listed after it was read had its `status` then.
        let tgid = tgid_of(child);
        let listed = is_own_thread(child);
        assert!(
            !listed || tgid == Some(me),
            "tid {child}: listed {listed}, tgid {tgid:?}"
        );
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

/// Lot 315 (external bug hunt 1.4: BUG-102, BUG-109, and a variant met in the lot's
/// mini-hunt).
#[cfg(test)]
mod lot315 {
    use super::*;

    /// BUG-102: the `/proc/<tid>/syscall` line of an io_uring worker made
    /// while the submitting thread sat in `openat(fifo, O_RDONLY)`: the
    /// creator's syscall registers, user sp and pc cleared. The worker's
    /// own open (`IORING_OP_OPENAT`, `O_WRONLY|O_TRUNC`) is not that one
    /// (on main: ReadOnly, answered without a copy).
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn bug102_an_io_uring_worker_line_is_not_read_only() {
        let line = "257 0xffffffffffffff9c 0x7fcb1d6112e0 0x0 0x0 0x7fcb239fce57 0xc1 0x0 0x0\n";
        let intent = classify_syscall_line(line);
        assert!(
            intent.may_write(),
            "an io_uring worker's line (sp = pc = 0) classified {intent:?}: {line:?}"
        );
        // one register cleared is no user thread either; none at all is
        // not a line the kernel writes for a task in a syscall
        for line in [
            "257 0xffffff9c 0x7ffd1 0x0 0x0 0x0 0x0 0x0 0x7f12",
            "257 0xffffff9c 0x7ffd1 0x0 0x0 0x0 0x0 0x7ffd 0x0",
            "257 0xffffff9c 0x7ffd1 0x0 0x0 0x0 0x0",
            "257 0xffffff9c 0x7ffd1 0x0 0x0 0x0 0x0 0x7ffd zz",
        ] {
            assert!(classify_syscall_line(line).may_write(), "{line}");
        }
    }

    /// BUG-102 guard: a user thread blocked in `openat(…, O_RDONLY)` has a
    /// user stack and pc: still a read.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn bug102_guard_a_user_thread_read_open_stays_read_only() {
        assert_eq!(
            classify_syscall_line("257 0xffffff9c 0x7ffd1 0x80000 0x0 0x0 0x0 0x7ffd 0x7f12\n"),
            OpenIntent::ReadOnly
        );
    }

    /// BUG-102: the worker is known by the kernel's flag on the task
    /// (`PF_IO_WORKER`, field 9 of `stat`), never by its `comm`.
    #[test]
    fn bug102_the_flags_name_an_io_uring_thread() {
        let stat = |comm: &str, flags: u64| {
            format!("4242 ({comm}) S 1 4242 4242 0 -1 {flags} 0 0 0 0 0 0 0 0 20 0 3 0 777 0 0\n")
        };
        assert_eq!(
            io_thread_in_stat(&stat("iou-wrk-4242", 0x404050)),
            Some(true)
        );
        assert_eq!(io_thread_in_stat(&stat("enc", 0x10)), Some(true));
        // a comm that says so is not the flag
        assert_eq!(
            io_thread_in_stat(&stat("iou-wrk-4242", 0x404040)),
            Some(false)
        );
        // nor one that hides fields (spaces, a parenthesis, `0x10`)
        assert_eq!(
            io_thread_in_stat(&stat("a) S 1 1 1 0 -1 16", 0x400040)),
            Some(false)
        );
        assert_eq!(
            io_thread_in_stat(&stat("x) R 1 1 1 0 -1 0", 0x10)),
            Some(true)
        );
        assert_eq!(io_thread_in_stat("4242 (x) S 1"), None);
        assert_eq!(io_thread_in_stat(""), None);
        assert_eq!(
            io_thread_in_stat(&stat("x", 0).replace(" 0 -1 0 ", " 0 -1 zz ")),
            None
        );
    }

    /// BUG-102: the flag decides before the line — an io_uring worker
    /// whose line reads as a user thread's `openat(…, O_RDONLY)` (registers
    /// and all) is still a write; a task whose flags cannot be read too.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn bug102_the_flag_decides_before_the_syscall_line() {
        let read_line = || -> io::Result<String> {
            Ok("257 0xffffff9c 0x7ffd1 0x80000 0x0 0x0 0x0 0x7ffd 0x7f12".to_string())
        };
        let worker =
            "4243 (iou-wrk-4242) S 1 4242 4242 0 -1 2097232 0 0 0 0 0 0 0 0 20 0 3 0 777 0 0";
        let thread = "4242 (enc) S 1 4242 4242 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 3 0 777 0 0";
        assert!(matches!(
            open_intent(Some(worker), read_line),
            OpenIntent::Unknown(_)
        ));
        assert!(matches!(
            open_intent(None, read_line),
            OpenIntent::Unknown(_)
        ));
        assert!(matches!(
            open_intent(Some("4242 (x"), read_line),
            OpenIntent::Unknown(_)
        ));
        assert_eq!(open_intent(Some(thread), read_line), OpenIntent::ReadOnly);
        assert!(matches!(
            open_intent(Some(thread), || Err(io::Error::from_raw_os_error(
                libc::EPERM
            ))),
            OpenIntent::Unknown(_)
        ));
    }

    /// BUG-102: the flags of a task whose `comm` is not UTF-8 (its own
    /// choice) are read — a strict text read refused the whole `stat`,
    /// and every open of that task then counted as a write (a copy each
    /// time: safe, not cheap).
    #[test]
    fn bug102_the_flags_of_a_task_named_with_any_bytes_are_read() {
        let p = nn_linux::state_read::testing::sleeper_with_non_utf8_comm(30);
        let stat = read_task_stat(p.pid() as i32).expect("its stat");
        assert_eq!(io_thread_in_stat(&stat), Some(false), "{stat}");
    }

    /// BUG-102 on this host's kernel: a real io_uring worker of this
    /// process (an `IOSQE_ASYNC` read of an empty pipe holds one) is known
    /// by its flags whatever its `comm`, and its opens count as writes; a
    /// thread of ours named like a worker is no worker. Skipped where
    /// io_uring is not allowed (`io_uring_disabled`, a seccomp profile).
    #[test]
    fn bug102_a_real_io_uring_worker_is_known_by_its_flags() {
        let Some(ring) = AsyncRead::start() else {
            eprintln!("io_uring not available here: skipped");
            return;
        };
        let workers = ring.workers();
        assert!(
            !workers.is_empty(),
            "no io_uring worker seen in /proc/self/task"
        );
        for tid in &workers {
            // the process renames its worker: still a worker
            let _ = std::fs::write(format!("/proc/self/task/{tid}/comm"), "enc");
            let stat = std::fs::read(format!("/proc/self/task/{tid}/stat")).unwrap();
            assert_eq!(
                io_thread_in_stat(&String::from_utf8_lossy(&stat)),
                Some(true),
                "{tid}"
            );
            assert!(
                matches!(read_open_intent(*tid), OpenIntent::Unknown(_)),
                "{tid}: {:?}",
                read_open_intent(*tid)
            );
        }
        // a thread of ours named like a worker is not one
        let (tx, rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let h = std::thread::Builder::new()
            .name("iou-wrk-1".into())
            .spawn(move || {
                // SAFETY: gettid has no preconditions.
                tx.send(unsafe { libc::syscall(libc::SYS_gettid) as i32 })
                    .unwrap();
                let _ = done_rx.recv();
            })
            .unwrap();
        let tid = rx.recv().unwrap();
        let stat = std::fs::read(format!("/proc/self/task/{tid}/stat")).unwrap();
        let stat = String::from_utf8_lossy(&stat);
        assert!(stat.contains("(iou-wrk-1)"), "{stat}");
        assert_eq!(io_thread_in_stat(&stat), Some(false), "{stat}");
        drop(done_tx);
        h.join().unwrap();
        drop(ring);
    }

    /// An io_uring of this process with one `IOSQE_ASYNC` read of an empty
    /// pipe in flight: an io-wq worker blocks in it until the pipe is
    /// written (on drop).
    struct AsyncRead {
        ring: i32,
        pipe: [i32; 2],
        maps: [(*mut libc::c_void, usize); 2],
    }

    impl AsyncRead {
        fn start() -> Option<Self> {
            // struct io_uring_params: 120 bytes; sq_off at byte 40
            let mut p = [0u32; 30];
            // SAFETY: io_uring_setup(entries, params) on a zeroed params
            // buffer of the struct's size.
            let ring =
                unsafe { libc::syscall(libc::SYS_io_uring_setup, 4u32, p.as_mut_ptr()) as i32 };
            if ring < 0 {
                return None;
            }
            let (entries, tail_off, mask_off, array_off) = (p[0], p[11], p[12], p[16]);
            let sq_len = array_off as usize + entries as usize * 4;
            let sqes_len = entries as usize * 64;
            let map = |len: usize, off: i64| {
                // SAFETY: a shared mapping of the ring's own memory.
                unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        len,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_SHARED | libc::MAP_POPULATE,
                        ring,
                        off,
                    )
                }
            };
            let sq = map(sq_len, 0);
            let sqes = map(sqes_len, 0x1000_0000);
            assert!(sq != libc::MAP_FAILED && sqes != libc::MAP_FAILED, "mmap");
            let mut pipe = [0i32; 2];
            // SAFETY: a two-int array for pipe(2).
            assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
            // the worker writes into it after the drop wakes it: never freed
            let buf: &'static mut [u8; 8] = Box::leak(Box::new([0u8; 8]));
            // SAFETY: offsets the kernel gave for the rings just mapped;
            // the sqe is one of `entries` 64-byte entries.
            unsafe {
                let tail = sq.cast::<u8>().add(tail_off as usize).cast::<u32>();
                let mask = *sq.cast::<u8>().add(mask_off as usize).cast::<u32>();
                let array = sq.cast::<u8>().add(array_off as usize).cast::<u32>();
                let t = std::ptr::read_volatile(tail);
                let i = t & mask;
                let sqe = sqes.cast::<u8>().add(i as usize * 64);
                std::ptr::write_bytes(sqe, 0, 64);
                *sqe = 22; // IORING_OP_READ
                *sqe.add(1) = 1 << 4; // IOSQE_ASYNC: an io-wq worker
                sqe.add(4).cast::<i32>().write_unaligned(pipe[0]);
                sqe.add(16)
                    .cast::<u64>()
                    .write_unaligned(buf.as_mut_ptr() as u64);
                sqe.add(24).cast::<u32>().write_unaligned(1);
                *array.add(i as usize) = i;
                std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
                std::ptr::write_volatile(tail, t + 1);
            }
            let me = Self {
                ring,
                pipe,
                maps: [(sq, sq_len), (sqes, sqes_len)],
            };
            // SAFETY: io_uring_enter(ring, to_submit 1, 0, 0, NULL, 0).
            let n = unsafe {
                libc::syscall(
                    libc::SYS_io_uring_enter,
                    ring,
                    1u32,
                    0u32,
                    0u32,
                    std::ptr::null::<libc::c_void>(),
                    0usize,
                )
            };
            (n == 1).then_some(me)
        }

        /// The threads of this process whose flags say io_uring worker,
        /// waited for up to 2 s.
        fn workers(&self) -> Vec<i32> {
            for _ in 0..200 {
                let found: Vec<i32> = std::fs::read_dir("/proc/self/task")
                    .unwrap()
                    .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
                    .filter(|tid: &i32| {
                        std::fs::read(format!("/proc/self/task/{tid}/stat")).is_ok_and(|b| {
                            io_thread_in_stat(&String::from_utf8_lossy(&b)) == Some(true)
                        })
                    })
                    .collect();
                if !found.is_empty() {
                    return found;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Vec::new()
        }
    }

    impl Drop for AsyncRead {
        fn drop(&mut self) {
            // SAFETY: our pipe, ring and mappings.
            unsafe {
                libc::write(self.pipe[1], b"x".as_ptr().cast(), 1);
                for (m, len) in self.maps {
                    libc::munmap(m, len);
                }
                libc::close(self.ring);
                libc::close(self.pipe[0]);
                libc::close(self.pipe[1]);
            }
        }
    }

    /// BUG-109: a live file named `… (deleted)` (one rename by the writer,
    /// which opens nothing) is reachable at that path: `fd_path` names it
    /// (on main: `None`, and the guard let it be written without a copy).
    #[test]
    fn bug109_a_live_file_named_deleted_has_its_path() {
        let d = tempfile::tempdir().unwrap();
        let victim = d.path().join("contract.docx");
        std::fs::write(&victim, b"original content").unwrap();
        let renamed = d.path().join("contract.docx (deleted)");
        std::fs::rename(&victim, &renamed).unwrap();
        let f = std::fs::File::open(&renamed).unwrap();
        assert_eq!(fstat(f.as_raw_fd()).unwrap().st_nlink, 1);
        assert_eq!(
            fd_path(f.as_raw_fd()),
            Some(renamed.display().to_string()),
            "a live file whose name ends with \" (deleted)\" is taken for an unlinked one: \
             the guard lets it be written without a copy (skipped_unresolved_path)"
        );
    }

    /// BUG-109 guard: a file really unlinked has no path.
    #[test]
    fn bug109_guard_an_unlinked_file_has_no_path() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("gone.txt");
        std::fs::write(&p, b"x").unwrap();
        let f = std::fs::File::open(&p).unwrap();
        std::fs::remove_file(&p).unwrap();
        assert_eq!(fd_path(f.as_raw_fd()), None);
        // named so, then unlinked: no path either
        let q = d.path().join("q (deleted)");
        std::fs::write(&q, b"x").unwrap();
        let g = std::fs::File::open(&q).unwrap();
        std::fs::remove_file(&q).unwrap();
        assert_eq!(fd_path(g.as_raw_fd()), None);
    }

    /// BUG-109, a variant (lot 315's mini-hunt): `ln f g`, an open of `f`
    /// for writing, and an unlink of `f` while the open waits on the guard.
    /// The kernel names the descriptor `f (deleted)` while `g` still holds
    /// the file: it is live, its path is the name it was opened by (on
    /// main, and with an `lstat` compared alone: no path, no copy).
    #[test]
    fn bug109_a_file_whose_opened_name_was_unlinked_keeps_a_path_while_linked() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("budget.xlsx");
        std::fs::write(&f, b"original").unwrap();
        std::fs::hard_link(&f, d.path().join(".g")).unwrap();
        let fd = std::fs::File::open(&f).unwrap();
        std::fs::remove_file(&f).unwrap();
        assert_eq!(fstat(fd.as_raw_fd()).unwrap().st_nlink, 1);
        assert_eq!(fd_path(fd.as_raw_fd()), Some(f.display().to_string()));
        // a live file named `x (deleted)` whose name was unlinked, another
        // link left: the name it was opened by, mark and all
        let x = d.path().join("x (deleted)");
        std::fs::write(&x, b"original").unwrap();
        std::fs::hard_link(&x, d.path().join(".h")).unwrap();
        let fx = std::fs::File::open(&x).unwrap();
        std::fs::remove_file(&x).unwrap();
        assert_eq!(fd_path(fx.as_raw_fd()), Some(x.display().to_string()));
    }

    /// The cached lookup names the descriptor's file, by the same identity
    /// `file_id` gives it (the device's encoding included), and another
    /// file as another; a missing path is `None`.
    #[test]
    fn lookup_cached_names_the_descriptors_file() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("a");
        let b = d.path().join("b");
        std::fs::write(&a, b"a").unwrap();
        std::fs::write(&b, b"b").unwrap();
        let fa = std::fs::File::open(&a).unwrap();
        let id = file_id(fa.as_raw_fd()).unwrap();
        assert_eq!(lookup_cached(a.to_str().unwrap()), Some(id));
        assert_ne!(lookup_cached(b.to_str().unwrap()), Some(id));
        assert_eq!(lookup_cached(d.path().join("c").to_str().unwrap()), None);
        // a link at the end is not followed (`lstat`: the link itself)
        std::os::unix::fs::symlink(&a, d.path().join("l")).unwrap();
        let l = lookup_cached(d.path().join("l").to_str().unwrap());
        assert!(l.is_some_and(|l| l != id), "{l:?}");
    }
}
