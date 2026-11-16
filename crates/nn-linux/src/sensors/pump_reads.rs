//! Lot 366: what the exec pumps may read of a process's files, and how
//! long they wait for it.
//!
//! The exec pump and the exec-check pump read, for each exec, the file the
//! process runs (`/proc/<pid>/exe`), its root, the directory it was run
//! from, an AppImage's image and daemon, a module tool's script and
//! library path. A file of a FUSE file system answers through its daemon;
//! a user who may mount one with `allow_other` (`user_allow_other` in
//! `/etc/fuse.conf`) runs a program from it, and a daemon that stops
//! answering the agent held the pump — and every exec behind it — for as
//! long as it liked. So:
//!
//! - **The kernel's identity, never the path's text.** Which file system a
//!   file is on is told by the device the kernel reports for it (`statx`,
//!   from the kernel's cache: [`antitamper_bpf::kernel_roots::cached`])
//!   against PID 1's mount table ([`Judge`]): a FUSE (`fuse`, `fuse.*`,
//!   `fuseblk`, `virtiofs`) or a network file system ([`FOREIGN_TYPES`]) is
//!   not asked; one the table does not show mounted is not either.
//! - **Nothing asked of such a file system.** A process's link (`exe`,
//!   `root`, `fd/<n>`) is followed alone and its target's identity read from
//!   the cache ([`kernel_roots::link_target`]); a path is walked one name at
//!   a time, each directory judged before a name is looked up in it, no
//!   symbolic link followed unless the caller needs the target
//!   ([`kernel_roots::walk_judged`]); a file is opened for reading only
//!   once judged ([`open_exe`]).
//! - **A deadline.** The pumps' reads run on #563's bounded reader
//!   ([`bounded`], [`EXEC_READER`]), waited for at most [`READ_DEADLINE`];
//!   past it the pump goes on, the facts it did not get are judged as not verified — the
//!   flags that take trust away set, the ones that give it left out — and
//!   the condition is signed (`exec_reads_unanswered`, a degradation of
//!   the exec sensor while it lasts). At most [`READERS_MAX`] reads may be
//!   unanswered at once: past it a read is refused at once, no thread made.
//!
//! A FUSE file system mounted without `allow_other` refuses root at once
//! (`EACCES`, nothing asked of its daemon); the kernel reads a process's
//! `environ` and `cmdline` from its anonymous memory only (a file mapped
//! over them is `EFAULT`, since Linux 4.18).

use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use antitamper_bpf::kernel_roots::{self, Cached};
use parking_lot::Mutex;

use crate::mountinfo::{MountEntry, MountTable};
use crate::state_read::TimedReader;

/// The file systems whose files the pumps do not ask about: served by a
/// user-space daemon (FUSE, its block and virtio forms) or over the
/// network — their server, not the kernel, answers, and may never.
pub const FOREIGN_TYPES: &[&str] = &[
    "fuse",
    "fuseblk",
    "virtiofs",
    "9p",
    "nfs",
    "nfs4",
    "cifs",
    "smb3",
    "smbfs",
    "ceph",
    "afs",
    "coda",
    "orangefs",
    "lustre",
    "vboxsf",
    "ncpfs",
    "glusterfs",
];

/// A file system type of [`FOREIGN_TYPES`] (or `fuse.<subtype>`).
pub fn foreign_type(fstype: &OsStr) -> bool {
    let t = fstype.as_bytes();
    t.starts_with(b"fuse.")
        || t.starts_with(b"fuseblk.")
        || FOREIGN_TYPES.iter().any(|f| t == f.as_bytes())
}

/// Whether the pumps may ask the file system of `c`, by `table`: its
/// device is a mounted file system's, of no [`foreign_type`] — every mount
/// of one file system has its type; a namespace's own copy of a mount (the
/// agent's, under `ProtectSystem=`; a container's) has another id, the same
/// device.
pub fn trusted_in(table: &MountTable, c: &Cached) -> bool {
    let mut mounts = table
        .entries
        .iter()
        .filter(|m| m.kernel_dev() == c.dev)
        .peekable();
    mounts.peek().is_some() && mounts.all(|m: &MountEntry| !foreign_type(&m.fstype))
}

/// How often PID 1's table is read again after a change of the mounts.
const REFRESH_MIN: Duration = Duration::from_millis(250);

/// The mounted file systems by device: whether one of its mounts is of a
/// foreign type.
type ById = std::sync::Arc<std::collections::HashMap<u64, bool>>;

fn by_id(table: &MountTable) -> ById {
    let mut by: std::collections::HashMap<u64, bool> = std::collections::HashMap::new();
    for m in &table.entries {
        *by.entry(m.kernel_dev()).or_default() |= foreign_type(&m.fstype);
    }
    std::sync::Arc::new(by)
}

/// PID 1's mount table, kept by device — read again after the kernel
/// flags a change (`POLLPRI` on the open table: the poll clears the flag,
/// so a change seen and not yet read stays `pending`), at most every
/// [`REFRESH_MIN`].
#[derive(Debug)]
struct Mounts {
    by_id: ById,
    loaded: Option<Instant>,
    pending: bool,
    watch: Option<File>,
    source: PathBuf,
    /// A table that cannot be read leaves the last one read in force,
    /// signed.
    read: crate::state_read::LastGood,
}

impl Mounts {
    fn changed(&self) -> bool {
        use std::os::fd::AsRawFd;
        let Some(w) = &self.watch else {
            return true;
        };
        let mut p = libc::pollfd {
            fd: w.as_raw_fd(),
            events: libc::POLLPRI,
            revents: 0,
        };
        // SAFETY: one valid pollfd for a descriptor `self` keeps open; a
        // zero timeout never blocks.
        let n = unsafe { libc::poll(&mut p, 1, 0) };
        n > 0 && p.revents & (libc::POLLPRI | libc::POLLERR) != 0
    }

    fn refresh(&mut self) {
        if self.watch.is_none() {
            self.watch = kernel_roots::open(&self.source, libc::O_RDONLY).ok();
        }
        // a change after the poll below is flagged at the next one
        let _ = self.changed();
        self.loaded = Some(Instant::now());
        match crate::mountinfo::read(&self.source) {
            Ok(t) => {
                self.read.ok();
                self.by_id = by_id(&t);
                self.pending = false;
            }
            // the last table read kept, signed — and a change not read:
            // an anonymous device is judged on none
            Err(e) => {
                self.read.failed(&e);
                self.pending = true;
            }
        }
    }

    /// A judge of one walk: the table read again first when the mounts
    /// changed since (at most every [`REFRESH_MIN`]); a change it could not
    /// read yet leaves an anonymous device (FUSE's, a network file
    /// system's) unjudged.
    fn judge(&mut self) -> Judge {
        if self.changed() {
            self.pending = true;
        }
        let due = self.loaded.is_none_or(|at| at.elapsed() >= REFRESH_MIN);
        if (self.loaded.is_none() || self.pending) && due {
            self.refresh();
        }
        Judge {
            by_id: self.by_id.clone(),
            fresh: !self.pending,
        }
    }
}

/// PID 1's mounts, for the pumps' walks.
static MOUNTS: LazyLock<Mutex<Mounts>> = LazyLock::new(|| {
    Mutex::new(Mounts {
        by_id: ById::default(),
        loaded: None,
        pending: false,
        watch: None,
        source: PathBuf::from("/proc/1/mountinfo"),
        read: crate::state_read::LastGood::new("exec_pump_mounts", "PID 1's mount table"),
    })
});

/// Lot 366: whether the pumps may ask a file system about a file, by the
/// file's cached identity: its device a file system PID 1's table shows
/// mounted, of a type not foreign ([`trusted_in`]).
#[derive(Debug, Clone)]
pub struct Judge {
    by_id: ById,
    fresh: bool,
}

impl Judge {
    /// The judge of the host's mounts now ([`MOUNTS`]).
    pub fn host() -> Judge {
        MOUNTS.lock().judge()
    }

    /// A judge of `table` (read just before: an AppImage's tie, tests).
    pub fn of(table: &MountTable) -> Judge {
        Judge {
            by_id: by_id(table),
            fresh: true,
        }
    }

    /// The file system of `c` may be asked.
    pub fn trusts(&self, c: &Cached) -> bool {
        // a block device's file system is no user's FUSE (`fuseblk` is
        // mounted by root); an anonymous one is judged only on a table read
        // since the last change
        if c.dev >> 20 == 0 && !self.fresh {
            JUDGED_STALE.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        self.by_id.get(&c.dev) == Some(&false)
    }
}

/// Anonymous devices left unjudged because the table had changed.
static JUDGED_STALE: AtomicU64 = AtomicU64::new(0);

/// Lot 366: `rel` walked from the process's root (`proc_dir/root`: the
/// directory its `root` link names), every file system on the way judged
/// by `judge` ([`kernel_roots::walk_judged`]; no symbolic link followed).
pub fn walk_in_root(
    proc_dir: &Path,
    rel: &Path,
    judge: &Judge,
) -> io::Result<kernel_roots::Walked> {
    let (root, c) = kernel_roots::link_target(&proc_dir.join("root"))?;
    if !c.is_dir() {
        return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
    }
    kernel_roots::walk_judged(&root, Path::new("/"), rel, false, &mut |c| judge.trusts(c))
}

/// Lot 366: `path` walked from the agent's own root, as [`walk_in_root`];
/// symbolic links followed when `follow` (each target walked and judged).
pub fn walk_host(
    root: &Path,
    path: &Path,
    follow: bool,
    judge: &Judge,
) -> io::Result<kernel_roots::Walked> {
    let r = kernel_roots::open(root, libc::O_PATH | libc::O_DIRECTORY)?;
    kernel_roots::walk_judged(&r, root, path, follow, &mut |c| judge.trusts(c))
}

/// Lot 366: the file a process's link names (`/proc/<pid>/exe`, `fd/<n>`)
/// opened with `flags` — its identity read from the kernel's cache first
/// and its file system judged (`PermissionDenied` when `judge` refuses it:
/// not verified), then the same file opened again through this thread's own
/// descriptor ([`kernel_roots::reopen_fd`]: compared, same mount and inode).
pub fn open_exe(link: &Path, flags: i32, judge: &Judge) -> io::Result<(File, Cached)> {
    let (f, c) = kernel_roots::link_target(link)?;
    if !judge.trusts(&c) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{}: on a file system the agent does not ask: not verified",
                link.display()
            ),
        ));
    }
    Ok((kernel_roots::reopen_fd(&f, flags)?, c))
}

/// How long a pump waits for one exec's reads.
pub const READ_DEADLINE: Duration = Duration::from_millis(500);
/// How many reads may be unanswered at once — past it, one is refused at
/// once.
pub const READERS_MAX: usize = 4;
/// The degradation's source while reads are unanswered.
pub const UNANSWERED: &str = "exec_reads_unanswered";

/// The exec pumps' reader: #563's bounded reader
/// ([`crate::state_read::TimedReader`]: its helpers reused, at most
/// [`READERS_MAX`] reads unanswered, each waited for [`READ_DEADLINE`]).
pub static EXEC_READER: LazyLock<TimedReader> =
    LazyLock::new(|| TimedReader::new(READ_DEADLINE, READERS_MAX));

/// The signed condition while an exec's reads are not waited for.
static NOT_WAITED: LazyLock<Mutex<crate::state_read::Condition>> = LazyLock::new(|| {
    Mutex::new(crate::state_read::Condition::with_hold(
        UNANSWERED,
        Duration::from_secs(60),
    ))
});

/// Reads not waited for since the start.
static NOT_WAITED_COUNT: AtomicU64 = AtomicU64::new(0);

/// Lot 366: `f` (an exec's reads) run on the exec pumps' reader
/// ([`EXEC_READER`]) and waited for at most its deadline. `Err(why)` when it
/// did not answer in time — the pump goes on, the helper stays with the
/// read until it answers — or when [`READERS_MAX`] reads are already
/// unanswered. Either is signed ([`UNANSWERED`]) until no read is.
pub fn bounded<T: Send + 'static>(
    what: &str,
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, String> {
    bounded_in(&EXEC_READER, what, f)
}

/// [`bounded`] on the reader `reader`.
pub fn bounded_in<T: Send + 'static>(
    reader: &TimedReader,
    what: &str,
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, String> {
    match reader.run(what, f) {
        Ok(v) => {
            if reader.unanswered() == 0 {
                NOT_WAITED.lock().ended();
            }
            Ok(v)
        }
        Err(why) => {
            NOT_WAITED_COUNT.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(read = what, why = %why, "exec pump: a read of a process's files was not waited for");
            NOT_WAITED.lock().holds(format!(
                "the exec pumps' reads of a process's files did not answer within {} ms (a file \
                 system whose server does not answer?): the facts they did not get are judged \
                 as not verified",
                READ_DEADLINE.as_millis()
            ));
            Err(why)
        }
    }
}

/// Lot 366: whether the condition "an exec's reads not waited for" stands
/// (signed, [`UNANSWERED`]).
pub fn not_waited() -> bool {
    NOT_WAITED.lock().holding()
}

/// Reads not waited for since the start, and anonymous devices left
/// unjudged after a change of the mounts.
pub fn counts() -> (u64, u64) {
    (
        NOT_WAITED_COUNT.load(Ordering::Relaxed),
        JUDGED_STALE.load(Ordering::Relaxed),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::channel;

    /// Lot 366: a read that never answers (a user's FUSE daemon that stops
    /// answering the agent) holds a helper, never the caller: given up at
    /// the deadline and signed (`exec_reads_unanswered`, a degradation);
    /// another read meanwhile is answered by another helper, and the first
    /// serves again once its read answers — no helper made for it.
    #[test]
    fn a_read_that_never_answers_holds_a_helper_not_the_pump() {
        let r = TimedReader::new(Duration::from_millis(200), 2);
        let (release, wait) = channel::<()>();
        let before = counts().0;
        let t0 = Instant::now();
        let got = bounded_in(&r, "test", move || {
            let _ = wait.recv();
            1
        });
        let took = t0.elapsed();
        assert!(got.is_err());
        assert!(
            took >= Duration::from_millis(200) && took < Duration::from_secs(5),
            "{took:?}"
        );
        assert!(counts().0 > before && not_waited(), "signed");
        assert_eq!(r.unanswered(), 1);
        assert_eq!(bounded_in(&r, "test", || 2), Ok(2));
        release.send(()).unwrap();
        let t = Instant::now();
        while r.unanswered() != 0 && t.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(10));
        }
        while r.free_helpers() < 2 && t.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(r.free_helpers(), 2, "both helpers free again");
        assert_eq!(bounded_in(&r, "test", || 3), Ok(3));
        assert_eq!(r.free_helpers(), 2, "a free helper reused, none made");
    }

    /// Lot 366: every helper held by a read that does not answer: the next
    /// read is refused at once — no wait, no thread made — and signed.
    #[test]
    fn helpers_held_past_the_bound_refuse_at_once() {
        let r = TimedReader::new(Duration::from_millis(50), 2);
        let mut releases = Vec::new();
        let before = counts().0;
        for _ in 0..2 {
            let (tx, rx) = channel::<()>();
            releases.push(tx);
            let got = bounded_in(&r, "test", move || {
                let _ = rx.recv();
            });
            assert!(got.is_err());
        }
        let t0 = Instant::now();
        assert!(bounded_in(&r, "test", || ()).is_err());
        assert!(t0.elapsed() < Duration::from_millis(50), "refused at once");
        assert_eq!(r.unanswered(), 2);
        assert!(counts().0 >= before + 3 && not_waited(), "each signed");
        drop(releases);
    }

    /// Lot 366: a mount made since the table was read: within
    /// [`REFRESH_MIN`] of the last read the table is not read again, and its
    /// anonymous device (a FUSE's kind) is not trusted; past it the table is
    /// read again and the new mount judged by its type; a FUSE mounted at
    /// once in its place that got its device back is not vouched for by
    /// the table read before. In a user and mount namespace of the test's
    /// own.
    #[test]
    fn a_mount_made_since_the_table_is_judged_only_once_read() {
        let rc = crate::fuse_testing::in_userns(|| {
            let dir = std::env::temp_dir().join(format!("nn-k366-mounts-{}", std::process::id()));
            if std::fs::create_dir(&dir).is_err() {
                return 99;
            }
            let mut m = Mounts {
                by_id: ById::default(),
                loaded: None,
                pending: false,
                watch: None,
                source: PathBuf::from("/proc/self/mountinfo"),
                read: crate::state_read::LastGood::new("exec_pump_mounts_test", "a test's table"),
            };
            let before = m.judge();
            let c = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).unwrap();
            // SAFETY: NUL-terminated strings; a tmpfs of the test's own
            // namespace.
            if unsafe {
                libc::mount(
                    c"t".as_ptr(),
                    c.as_ptr(),
                    c"tmpfs".as_ptr(),
                    0,
                    std::ptr::null(),
                )
            } != 0
            {
                return 99;
            }
            let id = kernel_roots::cached(&File::open(&dir).unwrap()).unwrap();
            let rc = if before.trusts(&id) {
                1
            } else if m.judge().trusts(&id) {
                2
            } else {
                std::thread::sleep(REFRESH_MIN + Duration::from_millis(100));
                if m.judge().trusts(&id) {
                    0
                } else {
                    3
                }
            };
            // SAFETY: as above.
            unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) };
            if rc != 0 {
                let _ = std::fs::remove_dir(&dir);
                return rc;
            }
            // the tmpfs gone and a FUSE mounted there at once: when it got
            // the tmpfs's device back (the kernel hands out the lowest one
            // free), the table read before it — the tmpfs's — does not
            // vouch for it until read again
            let rc = match crate::fuse_testing::smart_fuse_over(&dir, 0) {
                Some(fuse) => {
                    let root = std::os::unix::fs::OpenOptionsExt::custom_flags(
                        std::fs::OpenOptions::new().read(true),
                        libc::O_PATH | libc::O_DIRECTORY,
                    )
                    .open(&dir)
                    .unwrap();
                    let now = kernel_roots::cached(&root).unwrap();
                    let trusted = m.judge().trusts(&now);
                    drop(root);
                    drop(fuse);
                    // SAFETY: as above.
                    unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) };
                    if now.dev == id.dev && trusted {
                        4
                    } else {
                        0
                    }
                }
                None => 0,
            };
            let _ = std::fs::remove_dir(&dir);
            rc
        });
        if let Some(rc) = crate::fuse_testing::ran(rc) {
            assert_eq!(
                rc, 0,
                "1: trusted before its read, 2: stale, 3: never read again, 4: a device reused"
            );
        }
    }

    /// Lot 366: the judge asks a file system PID 1's table shows mounted,
    /// of a local type, by its device (a namespace's copy of the mount too);
    /// not a FUSE or network one, not one the table does not show, and not
    /// an anonymous device (FUSE's kind) while a change of the mounts is not
    /// read yet.
    #[test]
    fn only_a_local_mount_the_table_shows_is_asked() {
        let t = tempfile::tempdir().unwrap();
        let c = kernel_roots::cached(&File::open(t.path()).unwrap()).unwrap();
        let line = |fstype: &str, dev: u64| {
            format!(
                "{} 1 {}:{} / /x rw - {fstype} src rw\n",
                c.mnt_id,
                dev >> 20,
                dev & 0xfffff
            )
        };
        let judge = |text: String| Judge::of(&crate::mountinfo::parse(text.as_bytes()));
        assert!(judge(line("ext4", c.dev)).trusts(&c));
        for fstype in [
            "fuse",
            "fuse.sshfs",
            "fuseblk",
            "virtiofs",
            "nfs4",
            "cifs",
            "9p",
            "ceph",
        ] {
            assert!(!judge(line(fstype, c.dev)).trusts(&c), "{fstype}");
        }
        assert!(!judge(String::new()).trusts(&c), "no such mount");
        assert!(!judge(line("ext4", c.dev + 1)).trusts(&c), "another device");
        // a namespace's own copy of the mount: another id, the same device
        let copy = Cached {
            mnt_id: c.mnt_id + 1000,
            ..c
        };
        assert!(judge(line("ext4", c.dev)).trusts(&copy));
        let table = crate::mountinfo::parse(
            format!("{}{}", line("ext4", c.dev), line("fuse.x", c.dev)).as_bytes(),
        );
        assert!(
            !Judge::of(&table).trusts(&c) && !trusted_in(&table, &c),
            "one of its mounts foreign"
        );
        assert!(trusted_in(
            &crate::mountinfo::parse(line("ext4", c.dev).as_bytes()),
            &c
        ));
        let anon = Cached {
            dev: c.dev & 0xfffff,
            ..c
        };
        assert!(judge(line("tmpfs", anon.dev)).trusts(&anon));
        let stale = Judge {
            fresh: false,
            ..judge(line("tmpfs", anon.dev))
        };
        assert!(!stale.trusts(&anon), "an anonymous device, the table stale");
        let block = Cached {
            dev: (8 << 20) | 1,
            ..c
        };
        let stale = Judge {
            fresh: false,
            ..judge(line("ext4", block.dev))
        };
        assert!(
            stale.trusts(&block),
            "a block device's mount, the table stale"
        );
        assert!(foreign_type(OsStr::new("fuse.App.AppImage")));
        assert!(!foreign_type(OsStr::new("ext4")) && !foreign_type(OsStr::new("tmpfs")));
    }
}
