//! Lot 353 (pre-alpha Phase 3, case X6): the kernel's views — `/proc`,
//! `/sys` and the cgroup2 hierarchy — read beneath descriptors of their
//! roots opened once, at the start, never by walking the mount table as
//! it is now.
//!
//! A FUSE file system mounted over `/sys/fs/cgroup` that never answered
//! the agent's threads held them in the kernel (`FUSE_OPENDIR` of the
//! kernel-state round's open of the cgroup root, `FUSE_LOOKUP` of the
//! integrity round's read of the agent's own `memory.max`), and every
//! other thread that looked up the same names waited behind them. Those
//! rounds ran on the runtime's workers: the admin socket stopped answering
//! the watchdog's STATUS pings, whose stuck recovery restarted an agent
//! that had recorded nothing. A path walked from `/` crosses whatever is
//! mounted on it now; a walk from a descriptor of the view's root taken
//! before the mount does not see a mount over that root at all, and with
//! `RESOLVE_NO_XDEV` it refuses a mount below it (`EXDEV`) without asking
//! that file system anything.
//!
//! - [`init`] (the agent's start, before any round): each root opened
//!   `O_PATH` and checked to be the kernel's own file system (`fstatfs`:
//!   procfs, sysfs, cgroup2 — the type is set by the kernel, never by a
//!   FUSE daemon), on a helper thread with a deadline. A root already
//!   covered when the agent starts (a restart under the mount) is refused:
//!   its paths fail at once, naming why ([`unanchored`]), and the start
//!   reports it.
//! - [`read`], [`read_dir`], [`metadata`], [`read_link`], [`exists`]: a path
//!   under a view is opened beneath its root with `openat2`
//!   (`RESOLVE_BENEATH | RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS`): the file
//!   is then the kernel's own and answers at once, on the caller's thread.
//! - A path that crosses a mount below a view's root (`EXDEV`: securityfs
//!   at `/sys/kernel/security`, binfmt_misc, a cgroup v1 controller — or a
//!   mount laid there) is opened again beneath the root, mounts allowed, on
//!   a helper thread with a deadline ([`WALK_DEADLINE`], at most
//!   [`WALKS_MAX`] unanswered at once): what it reaches is read only when it
//!   is on one of the kernel's file systems ([`KERNEL_MAGICS`]); a FUSE, a
//!   tmpfs or a disk's file system there is refused, and one that does not
//!   answer fails after the deadline. Nothing is crossed below the cgroup2
//!   root, which has no mount of its own.
//! - A magic link on the path (`ELOOP`: `/proc/<pid>/root/…`, `/proc/self/fd/N`)
//!   is resolved from the view's root as the kernel resolves it (`openat`):
//!   the namespace's mount over `/proc` is still not walked.
//! - A path under no view is not this module's ([`view_of`] says `None`).

use std::ffi::{CString, OsString};
use std::fs::{File, Metadata};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

/// `PROC_SUPER_MAGIC` (`include/uapi/linux/magic.h`).
pub const PROC_SUPER_MAGIC: u64 = 0x9fa0;
/// `SYSFS_MAGIC`.
pub const SYSFS_MAGIC: u64 = 0x6265_6572;
/// `CGROUP2_SUPER_MAGIC`.
pub const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;
/// `CGROUP_SUPER_MAGIC` (cgroup v1).
pub const CGROUP_SUPER_MAGIC: u64 = 0x0027_e0eb;
/// `TMPFS_MAGIC`: `/sys/fs/cgroup` on a hybrid or legacy cgroup host.
pub const TMPFS_MAGIC: u64 = 0x0102_1994;
/// `FUSE_SUPER_MAGIC` (`fs/fuse/inode.c`).
pub const FUSE_SUPER_MAGIC: u64 = 0x6573_5546;

/// The kernel's own file systems a view's path may cross into below its
/// root (`include/uapi/linux/magic.h`): the views themselves, securityfs,
/// debugfs, tracefs, bpffs, pstore, fusectl, configfs, efivarfs, SELinux's
/// and Smack's, cgroup v1, binfmt_misc and the autofs systemd puts on
/// `/proc/sys/fs/binfmt_misc`, an NFS server's `/proc/fs/nfsd`, a Xen
/// guest's `/proc/xen`, `/sys/fs/resctrl`. The names are the mount
/// table's (`self_integrity`'s check of the mounts below the views). A tmpfs is one only at `/sys/fs/cgroup`
/// itself (a hybrid host's), never elsewhere.
pub const KERNEL_MAGICS: &[(u64, &str)] = &[
    (PROC_SUPER_MAGIC, "proc"),
    (SYSFS_MAGIC, "sysfs"),
    (CGROUP2_SUPER_MAGIC, "cgroup2"),
    (CGROUP_SUPER_MAGIC, "cgroup"),
    (0x7363_6673, "securityfs"),
    (0x6462_6720, "debugfs"),
    (0x7472_6163, "tracefs"),
    (0xcafe_4a11, "bpf"),
    (0x6165_676c, "pstore"),
    (0x6573_5543, "fusectl"),
    (0x6265_6570, "configfs"),
    (0xde5e_81e4, "efivarfs"),
    (0xf97c_ff8c, "selinuxfs"),
    (0x4341_5d53, "smackfs"),
    (0x4249_4e4d, "binfmt_misc"),
    (0x0187, "autofs"),
    (0x6e66_7364, "nfsd"),
    (0xabba_1974, "xenfs"),
    (0x0765_5821, "resctrl"),
];

/// How long the start waits for a root's `fstatfs` (a FUSE root asks its
/// daemon).
pub const OPEN_DEADLINE: Duration = Duration::from_secs(2);
/// How long a path crossing a mount below a root is waited for.
pub const WALK_DEADLINE: Duration = Duration::from_secs(2);
/// How many such walks may be unanswered at once — past it, one fails at
/// once, no thread made.
pub const WALKS_MAX: usize = 4;

/// The largest file [`read`] reads when the caller gives no bound.
pub const STATE_MAX: u64 = 4 << 20;

/// Which view a path is under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Proc,
    Sys,
    Cgroup,
}

/// One view: where it is mounted and the descriptor of its root opened at
/// the start, or why there is none.
#[derive(Debug)]
pub struct View {
    kind: Kind,
    at: PathBuf,
    root: Result<File, String>,
}

impl View {
    /// Where the view is mounted.
    pub fn at(&self) -> &Path {
        &self.at
    }

    /// Which view.
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// Why the start did not anchor it, if it did not.
    pub fn refused(&self) -> Option<&str> {
        self.root.as_ref().err().map(String::as_str)
    }
}

/// The three views.
#[derive(Debug)]
pub struct Views {
    proc: View,
    sys: View,
    /// `None` on a host without a cgroup2 hierarchy (cgroup v1 only).
    cgroup: Option<View>,
}

static VIEWS: OnceLock<Views> = OnceLock::new();

/// Walks unanswered now ([`WALKS_MAX`]).
static WALKS: AtomicUsize = AtomicUsize::new(0);
/// Walks that did not answer within [`WALK_DEADLINE`] since the start.
static STALLED: AtomicU64 = AtomicU64::new(0);
/// Paths refused because they reached a file system not the kernel's.
static REFUSED: AtomicU64 = AtomicU64::new(0);

/// Anchor the views (once; later calls return the same answer): the
/// reasons a view is not anchored, one line each — empty when all are.
pub fn init() -> Vec<String> {
    let mut why = unanchored();
    // lot 353 (the review of #563, F2): read once now, beneath the root
    if let Err(e) = possible_cpus() {
        why.push(format!("/sys/devices/system/cpu/possible: {e}"));
    }
    why
}

/// Lot 353 (the review of #563, the lab's FUSE over `/proc`): this
/// process's executable (`/proc/self/exe`), read beneath the `/proc` root
/// the start anchored — `std::env::current_exe` reads it by path, and the
/// telemetry probe's round, asking it on a runtime worker, was held by a
/// FUSE over `/proc` (the status stopped answering behind it).
pub fn current_exe() -> io::Result<PathBuf> {
    read_link("/proc/self/exe")
}

/// Lot 353 (the review of #563, F2): the number of possible CPUs (the
/// length of a per-CPU map's value), read once — at [`init`] — from
/// `/sys/devices/system/cpu/possible` beneath the `/sys` root the start
/// anchored. aya's `nr_cpus()` reads that file by path once per thread:
/// every fresh runtime or blocking thread that read a per-CPU map walked
/// the `/sys` mounted now, and a FUSE over it held the thread.
pub fn possible_cpus() -> Result<usize, String> {
    static CPUS: OnceLock<Result<usize, String>> = OnceLock::new();
    CPUS.get_or_init(|| {
        let text = read_text("/sys/devices/system/cpu/possible").map_err(|e| e.to_string())?;
        cpu_count(text.trim()).ok_or_else(|| format!("not a CPU list: {:?}", text.trim()))
    })
    .clone()
}

/// The number of CPUs in a kernel CPU list (`0-3,8,10-11`).
pub fn cpu_count(list: &str) -> Option<usize> {
    let mut n = 0usize;
    for part in list.split(',') {
        let part = part.trim();
        match part.split_once('-') {
            Some((a, b)) => {
                let (a, b) = (a.parse::<usize>().ok()?, b.parse::<usize>().ok()?);
                if b < a {
                    return None;
                }
                n = n.checked_add(b - a + 1)?;
            }
            None => {
                part.parse::<usize>().ok()?;
                n = n.checked_add(1)?;
            }
        }
    }
    (n > 0).then_some(n)
}

/// Lot 353 (the review of #563, F2): the kernel's BTF
/// (`/sys/kernel/btf/vmlinux`), read beneath the `/sys` root the start
/// anchored — aya's `Btf::from_sys_fs` reads it by path, and a start under
/// a FUSE over `/sys` waited for it with no deadline. A `/sys` the start
/// refused is an error at once.
pub fn vmlinux_btf() -> Result<aya::Btf, aya::BtfError> {
    const VMLINUX: &str = "/sys/kernel/btf/vmlinux";
    let data = read_all(VMLINUX).map_err(|error| aya::BtfError::FileError {
        path: PathBuf::from(VMLINUX),
        error,
    })?;
    aya::Btf::parse(&data, aya::Endianness::default())
}

/// The views, anchored at the first call.
pub fn views() -> &'static Views {
    VIEWS.get_or_init(Views::open)
}

/// The descriptor of the `/proc` root the start anchored, when it did —
/// for a forked child's allocation-free read of its own `/proc/self`
/// (`openat`): no initialisation here, `None` before [`init`] ran.
pub fn proc_root_fd() -> Option<std::os::fd::RawFd> {
    VIEWS
        .get()
        .and_then(|v| v.proc.root.as_ref().ok())
        .map(|f| f.as_raw_fd())
}

/// Why each view the start could not anchor is not, one line each.
pub fn unanchored() -> Vec<String> {
    let v = views();
    [Some(&v.proc), Some(&v.sys), v.cgroup.as_ref()]
        .into_iter()
        .flatten()
        .filter_map(|view| {
            view.refused().map(|why| {
                format!(
                    "{}: not anchored at the start ({why}) — its kernel state is not read",
                    view.at.display()
                )
            })
        })
        .collect()
}

/// How many walks below a root did not answer in time, and how many paths
/// were refused because they reached a file system not the kernel's.
pub fn counts() -> (u64, u64) {
    (
        STALLED.load(Ordering::Relaxed),
        REFUSED.load(Ordering::Relaxed),
    )
}

/// Walks unanswered now.
pub fn unanswered() -> usize {
    WALKS.load(Ordering::SeqCst)
}

impl Views {
    fn open() -> Views {
        let mut proc = View {
            kind: Kind::Proc,
            at: PathBuf::from("/proc"),
            root: anchor(Path::new("/proc"), &[PROC_SUPER_MAGIC]).map(|(f, _)| f),
        };
        // lot 353 (the review of #563, F3): the mounts this process sees,
        // read beneath the /proc root just anchored
        let table = proc.root.as_ref().ok().and_then(own_mounts);
        let mut sys = View {
            kind: Kind::Sys,
            at: PathBuf::from("/sys"),
            root: anchor(Path::new("/sys"), &[SYSFS_MAGIC]).map(|(f, _)| f),
        };
        if let Some(t) = &table {
            for v in [&mut proc, &mut sys] {
                if v.root.is_ok() {
                    if let Some(why) = shadowed(t, &v.at.to_string_lossy()) {
                        v.root = Err(why);
                    }
                }
            }
        }
        let unified_only = proc.root.as_ref().ok().is_some_and(cgroup2_alone);
        let cgroup = cgroup_view(table.as_deref(), unified_only);
        Views { proc, sys, cgroup }
    }

    /// The view `path` is under (the cgroup2 one before `/sys`).
    pub fn view_of(&self, path: &Path) -> Option<&View> {
        if let Some(c) = &self.cgroup {
            if path.starts_with(&c.at) {
                return Some(c);
            }
        }
        [&self.proc, &self.sys]
            .into_iter()
            .find(|v| path.starts_with(&v.at))
    }

    /// The cgroup2 view, when the host has one.
    pub fn cgroup(&self) -> Option<&View> {
        self.cgroup.as_ref()
    }
}

/// Lot 353 (the review of #563, F3): the mount table of this process
/// (`/proc/self/mountinfo`), read beneath the `/proc` root `proc`.
fn own_mounts(proc: &File) -> Option<String> {
    let f = openat2(
        proc,
        Path::new("self/mountinfo"),
        libc::O_RDONLY | libc::O_NONBLOCK,
        NO_CROSSING,
    )
    .ok()?;
    String::from_utf8(read_file_bounded(&f, STATE_MAX).ok()?).ok()
}

/// One line of a mount table: (id, parent, `major:minor`, root, mount
/// point, file system type).
fn mount_line(l: &str) -> Option<(&str, &str, &str, &str, &str, &str)> {
    let (left, right) = l.split_once(" - ")?;
    let mut f = left.split(' ');
    let (id, parent, dev, root, point) = (f.next()?, f.next()?, f.next()?, f.next()?, f.next()?);
    let fstype = right.split(' ').next()?;
    Some((id, parent, dev, root, point, fstype))
}

/// Lot 353 (the review of #563, F3): why the mount on top at the view
/// point `point` of the mount table `table` is not the view, if it is not:
/// a directory of a file system bound over it (its source root other than
/// `/`: a cgroup2 subtree over the hierarchy's root, `/proc/sys` over
/// `/proc`), or a file system stacked over another mounted at the same
/// point (a tmpfs over the cgroup2 root, another proc over `/proc`) — a
/// bind of the same mount onto itself is the same view.
pub fn shadowed(table: &str, point: &str) -> Option<String> {
    let at: Vec<_> = table
        .lines()
        .filter_map(mount_line)
        .filter(|m| m.4 == point)
        .collect();
    let top = at.last()?;
    let (_, parent, dev, root, _, fstype) = *top;
    if root != "/" {
        return Some(format!(
            "{point}: the mount there is a directory of a {fstype} (source root {root}) bound \
             over the view's root — a mount over it"
        ));
    }
    let below = at.iter().rev().skip(1).find(|m| m.0 == parent)?;
    (below.2 != dev || below.3 != root).then(|| {
        format!(
            "{point}: a {fstype} mounted over the {} there — a mount over it",
            below.5
        )
    })
}

/// Lot 353 (the review of #563, F3): this process is in the cgroup2
/// hierarchy alone — `/proc/self/cgroup` (read beneath the `/proc` root
/// `proc`) names no cgroup v1 hierarchy: a unified host, whose cgroup2
/// root is mounted at `/sys/fs/cgroup` (the kernel's word, whatever is
/// mounted there now).
fn cgroup2_alone(proc: &File) -> bool {
    let Ok(f) = openat2(
        proc,
        Path::new("self/cgroup"),
        libc::O_RDONLY | libc::O_NONBLOCK,
        NO_CROSSING,
    ) else {
        return false;
    };
    let Ok(text) =
        read_file_bounded(&f, STATE_MAX).map(|b| String::from_utf8_lossy(&b).into_owned())
    else {
        return false;
    };
    unified_hierarchy_only(&text)
}

/// Whether a `/proc/<pid>/cgroup` text names the cgroup2 hierarchy alone
/// (its `0::` line, no v1 hierarchy's).
pub fn unified_hierarchy_only(text: &str) -> bool {
    let mut lines = text.lines().filter(|l| !l.trim().is_empty()).peekable();
    lines.peek().is_some() && lines.all(|l| l.starts_with("0::"))
}

/// The cgroup2 hierarchy's view: `/sys/fs/cgroup` on a unified host, its
/// `unified` directory on a hybrid one (a tmpfs at `/sys/fs/cgroup`), none
/// on a legacy host; a root that is neither is refused. Lot 353 (the
/// review of #563, F3): refused too — never taken for a cgroup v1 host —
/// a mount at `/sys/fs/cgroup` that is not the view ([`shadowed`] in the
/// mount table `table`), and a tmpfs there with no `unified` below it on a
/// host whose processes are in the cgroup2 hierarchy alone
/// (`unified_only`): a mount over its cgroup2 root.
fn cgroup_view(table: Option<&str>, unified_only: bool) -> Option<View> {
    let at = Path::new("/sys/fs/cgroup");
    let refused = |why: String| {
        Some(View {
            kind: Kind::Cgroup,
            at: at.to_path_buf(),
            root: Err(why),
        })
    };
    if let Some(why) = table.and_then(|t| shadowed(t, "/sys/fs/cgroup")) {
        return refused(why);
    }
    match anchor(at, &[CGROUP2_SUPER_MAGIC, TMPFS_MAGIC]) {
        Ok((f, CGROUP2_SUPER_MAGIC)) => Some(View {
            kind: Kind::Cgroup,
            at: at.to_path_buf(),
            root: Ok(f),
        }),
        Ok(_) => {
            let unified = Path::new("/sys/fs/cgroup/unified");
            match anchor(unified, &[CGROUP2_SUPER_MAGIC]) {
                Ok((f, _)) => Some(View {
                    kind: Kind::Cgroup,
                    at: unified.to_path_buf(),
                    root: match table.and_then(|t| shadowed(t, "/sys/fs/cgroup/unified")) {
                        Some(why) => Err(why),
                        None => Ok(f),
                    },
                }),
                Err(_) if unified_only => refused(format!(
                    "{}: a tmpfs, with no cgroup2 hierarchy below it, on a host whose processes \
                     are in the cgroup2 hierarchy alone (/proc/self/cgroup names no v1 \
                     hierarchy) — a mount over its cgroup2 root",
                    at.display()
                )),
                Err(why) if why.contains("No such file") => None,
                Err(why) => Some(View {
                    kind: Kind::Cgroup,
                    at: unified.to_path_buf(),
                    root: Err(why),
                }),
            }
        }
        Err(why) if why.contains("No such file") => None,
        Err(why) => refused(why),
    }
}

/// `path` opened `O_PATH | O_DIRECTORY` and its file system's type, which
/// must be one of `magics` — on a helper thread, waited for at most
/// [`OPEN_DEADLINE`] (the open of a covered root asks nothing, its
/// `fstatfs` asks a FUSE daemon).
fn anchor(path: &Path, magics: &[u64]) -> Result<(File, u64), String> {
    let p = path.to_path_buf();
    let magics_owned = magics.to_vec();
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let spawned = std::thread::Builder::new()
        .name("nn-kview-open".into())
        .spawn(move || {
            let out = (|| {
                let f = open_path(&p, libc::O_PATH | libc::O_DIRECTORY)
                    .and_then(high)
                    .map_err(|e| format!("{}: {e}", p.display()))?;
                let m = magic_of(&f).map_err(|e| format!("{}: fstatfs: {e}", p.display()))?;
                if magics_owned.contains(&m) {
                    Ok((f, m))
                } else {
                    Err(format!(
                        "{}: a file system of type {} ({m:#x}) at the root, not the kernel's — \
                         a mount over it",
                        p.display(),
                        magic_name(m).unwrap_or("unknown")
                    ))
                }
            })();
            let _ = tx.send(out);
        });
    if let Err(e) = spawned {
        return Err(format!("{}: no helper thread ({e})", path.display()));
    }
    rx.recv_timeout(OPEN_DEADLINE).unwrap_or_else(|_| {
        Err(format!(
            "{}: its root did not answer within {} ms — a mount over it that does not answer \
             (FUSE?)",
            path.display(),
            OPEN_DEADLINE.as_millis()
        ))
    })
}

/// The lowest descriptor a view's root is kept on: above the ones a child
/// is handed (a worker's channel is descriptor 3, `dup2`'d over whatever
/// held it before its `pre_exec` reads `/proc/self` beneath this root).
pub const ROOT_FD_MIN: i32 = 64;

/// `f` moved to a descriptor at or above [`ROOT_FD_MIN`] (close-on-exec).
fn high(f: File) -> io::Result<File> {
    // SAFETY: `F_DUPFD_CLOEXEC` of a live descriptor; the new one is ours.
    let fd = unsafe { libc::fcntl(f.as_raw_fd(), libc::F_DUPFD_CLOEXEC, ROOT_FD_MIN) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a new descriptor the kernel gave this call alone.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// The name of a kernel file system's magic, when it is one of
/// [`KERNEL_MAGICS`] (or FUSE, tmpfs).
pub fn magic_name(m: u64) -> Option<&'static str> {
    KERNEL_MAGICS
        .iter()
        .find(|(k, _)| *k == m)
        .map(|(_, n)| *n)
        .or(match m {
            FUSE_SUPER_MAGIC => Some("fuse"),
            TMPFS_MAGIC => Some("tmpfs"),
            _ => None,
        })
}

/// The file system type (`fstatfs`) of `f`.
pub fn magic_of(f: &File) -> io::Result<u64> {
    // SAFETY: `statfs` is plain old data, valid when zeroed.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: the fd is borrowed from a live `File`; `st` is writable.
    if unsafe { libc::fstatfs(f.as_raw_fd(), &mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st.f_type as u64)
}

/// `path` opened with `flags` (plus `O_CLOEXEC | O_NOCTTY`), by path.
fn open_path(path: &Path, flags: i32) -> io::Result<File> {
    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    // SAFETY: `c` is NUL-terminated.
    let fd = unsafe { libc::open(c.as_ptr(), flags | libc::O_CLOEXEC | libc::O_NOCTTY) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a new descriptor the kernel gave this call alone.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// The view `path` is under and its path relative to the view's root
/// (`.` for the root itself) — `None` when it is under none, or is not a
/// plain absolute path (a `..`, a relative path: the caller's own).
pub fn view_of(path: &Path) -> Option<(&'static View, PathBuf)> {
    if !(path.starts_with("/proc") || path.starts_with("/sys")) {
        return None;
    }
    view_in(views(), path)
}

/// [`view_of`] among `views`.
fn view_in<'a>(views: &'a Views, path: &Path) -> Option<(&'a View, PathBuf)> {
    // a path under no view never anchors them (no helper thread for it)
    if !(path.starts_with("/proc") || path.starts_with("/sys"))
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return None;
    }
    let v = views.view_of(path)?;
    let rel = path.strip_prefix(&v.at).ok()?;
    Some((
        v,
        if rel.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            rel.to_path_buf()
        },
    ))
}

/// The resolution flags of a view's own files.
const NO_CROSSING: u64 =
    libc::RESOLVE_BENEATH | libc::RESOLVE_NO_XDEV | libc::RESOLVE_NO_MAGICLINKS;
/// The resolution flags of a walk that may cross a mount below the root.
const CROSSING: u64 = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_MAGICLINKS;

/// `rel` opened beneath `dir` with `flags` (plus `O_CLOEXEC | O_NOCTTY`)
/// and `resolve`. A kernel without `openat2` (before 5.6, or a filter that
/// refuses it): `openat`, and a file on another device than `dir` is a
/// mount crossed (`EXDEV`) when `resolve` forbids one.
fn openat2(dir: &File, rel: &Path, flags: i32, resolve: u64) -> io::Result<File> {
    let c = CString::new(rel.as_os_str().as_bytes())
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    // `openat2` refuses with `O_PATH` any flag but the few it allows
    // (`open` drops them)
    let flags = flags
        | libc::O_CLOEXEC
        | if flags & libc::O_PATH == 0 {
            libc::O_NOCTTY
        } else {
            0
        };
    // SAFETY: `open_how` is plain old data, valid when zeroed.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = flags as u64;
    how.resolve = resolve;
    // SAFETY: `c` is NUL-terminated and `how` outlives the call, its size
    // given.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir.as_raw_fd(),
            c.as_ptr(),
            &how as *const libc::open_how,
            std::mem::size_of::<libc::open_how>(),
        )
    };
    if fd >= 0 {
        // SAFETY: a new descriptor the kernel gave this call alone.
        return Ok(unsafe { File::from_raw_fd(fd as i32) });
    }
    let e = io::Error::last_os_error();
    if e.raw_os_error() != Some(libc::ENOSYS) {
        return Err(e);
    }
    let f = openat(dir, rel, flags)?;
    if resolve & libc::RESOLVE_NO_XDEV != 0 {
        use std::os::unix::fs::MetadataExt;
        if f.metadata()?.dev() != dir.metadata()?.dev() {
            return Err(io::Error::from_raw_os_error(libc::EXDEV));
        }
    }
    Ok(f)
}

/// `rel` opened beneath `dir` with plain `openat` (magic links followed).
fn openat(dir: &File, rel: &Path, flags: i32) -> io::Result<File> {
    let c = CString::new(rel.as_os_str().as_bytes())
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    // SAFETY: `c` is NUL-terminated.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOCTTY,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a new descriptor the kernel gave this call alone.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// The error of a path under a view the start did not anchor.
fn not_anchored(path: &Path, why: &str) -> io::Error {
    io::Error::other(format!(
        "{}: not read — its view was not anchored at the start ({why})",
        path.display()
    ))
}

/// Run `op` on the file `path` reaches, opened with `flags`: beneath its
/// view's root, crossing no mount, on the caller's thread; crossing a
/// mount below the root on a helper thread with a deadline, a file of the
/// kernel's own file systems only; through a magic link as the kernel
/// resolves it. `None` when `path` is under no view (the caller reads it
/// itself).
fn with_file<T: Send + 'static>(
    path: &Path,
    flags: i32,
    op: impl FnOnce(File) -> io::Result<T> + Send + 'static,
) -> Option<io::Result<T>> {
    with_file_in(views(), path, flags, op)
}

/// [`with_file`] among `views`.
fn with_file_in<T: Send + 'static>(
    views: &Views,
    path: &Path,
    flags: i32,
    op: impl FnOnce(File) -> io::Result<T> + Send + 'static,
) -> Option<io::Result<T>> {
    let (view, rel) = view_in(views, path)?;
    let root = match &view.root {
        Ok(r) => r,
        Err(why) => return Some(Err(not_anchored(path, why))),
    };
    Some(match openat2(root, &rel, flags, NO_CROSSING) {
        Ok(f) => op(f),
        Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {
            if view.kind == Kind::Cgroup {
                // the cgroup2 hierarchy has no mount of its own below its root
                REFUSED.fetch_add(1, Ordering::Relaxed);
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "{}: not read — a mount over it or a directory above it, below the \
                         cgroup2 root",
                        path.display()
                    ),
                ))
            } else {
                crossing(path, view.kind, root, rel, flags, op)
            }
        }
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => openat(root, &rel, flags).and_then(op),
        Err(e) => Err(e),
    })
}

/// A path crossing a mount below `root`: opened on a helper thread with a
/// deadline, then used only when what it reached is a kernel file system.
fn crossing<T: Send + 'static>(
    path: &Path,
    kind: Kind,
    root: &File,
    rel: PathBuf,
    flags: i32,
    op: impl FnOnce(File) -> io::Result<T> + Send + 'static,
) -> io::Result<T> {
    let root = root.try_clone()?;
    let shown = path.to_path_buf();
    bounded(path, move || {
        let (f, m) = match openat2(&root, &rel, flags, CROSSING) {
            Ok(f) => {
                let m = magic_of(&f)?;
                (Some(f), m)
            }
            // not there: the answer of the kernel's file system only — the
            // nearest directory reached says which one answered
            Err(e) => match nearest_magic(&root, &rel) {
                Some(m) if !crossing_allowed(kind, &shown, m) => (None, m),
                _ => return Err(e),
            },
        };
        if !crossing_allowed(kind, &shown, m) {
            REFUSED.fetch_add(1, Ordering::Relaxed);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{}: not read — it is on a file system of type {} ({m:#x}) mounted below \
                     {}, not the kernel's",
                    shown.display(),
                    magic_name(m).unwrap_or("unknown"),
                    match kind {
                        Kind::Proc => "/proc",
                        Kind::Sys => "/sys",
                        Kind::Cgroup => "the cgroup2 root",
                    }
                ),
            ));
        }
        match f {
            Some(f) => op(f),
            None => Err(io::Error::from_raw_os_error(libc::ENOENT)),
        }
    })
}

/// The file system type of the nearest directory above `rel` (beneath
/// `root`, mounts crossed) that opens.
fn nearest_magic(root: &File, rel: &Path) -> Option<u64> {
    rel.ancestors()
        .skip(1)
        .take_while(|a| !a.as_os_str().is_empty())
        .find_map(|a| openat2(root, a, libc::O_PATH | libc::O_DIRECTORY, CROSSING).ok())
        .and_then(|d| magic_of(&d).ok())
}

/// Whether a path of the view `kind` that crossed a mount below its root
/// may be read where it arrived: on one of the kernel's own file systems
/// ([`KERNEL_MAGICS`]), or a hybrid host's tmpfs at `/sys/fs/cgroup`.
fn crossing_allowed(kind: Kind, path: &Path, magic: u64) -> bool {
    KERNEL_MAGICS.iter().any(|(k, _)| *k == magic)
        || (kind == Kind::Sys && magic == TMPFS_MAGIC && path.starts_with("/sys/fs/cgroup"))
}

/// `f` on a helper thread, waited for at most [`WALK_DEADLINE`]; at once an
/// error while [`WALKS_MAX`] earlier ones have not answered.
fn bounded<T: Send + 'static>(
    path: &Path,
    f: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> io::Result<T> {
    let busy = WALKS.load(Ordering::SeqCst);
    if busy >= WALKS_MAX {
        STALLED.fetch_add(1, Ordering::Relaxed);
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "{}: not read — {busy} earlier reads crossing a mount have not answered (a \
                 mount that does not answer?)",
                path.display()
            ),
        ));
    }
    WALKS.fetch_add(1, Ordering::SeqCst);
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let spawned = std::thread::Builder::new()
        .name("nn-kview-walk".into())
        .spawn(move || {
            let out = f();
            WALKS.fetch_sub(1, Ordering::SeqCst);
            let _ = tx.send(out);
        });
    if let Err(e) = spawned {
        WALKS.fetch_sub(1, Ordering::SeqCst);
        return Err(io::Error::other(format!(
            "{}: not read — no helper thread ({e})",
            path.display()
        )));
    }
    rx.recv_timeout(WALK_DEADLINE).unwrap_or_else(|_| {
        STALLED.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(
            path = %path.display(),
            "kernel view: a read crossing a mount did not answer"
        );
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "{}: did not answer within {} ms (a mount below its view that does not \
                 answer?): not read",
                path.display(),
                WALK_DEADLINE.as_millis()
            ),
        ))
    })
}

/// The bytes of an open regular file from its offset, at most `max` —
/// more is an error, never a cut answer; a FIFO, a device or a directory
/// is not read.
pub fn read_file_bounded(f: &File, max: u64) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let t = f.metadata()?.file_type();
    if !t.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file (a FIFO, a device, a directory): not read",
        ));
    }
    let mut bytes = Vec::new();
    f.take(max.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("more than {max} bytes: not read"),
        ));
    }
    Ok(bytes)
}

const READ_FLAGS: i32 = libc::O_RDONLY | libc::O_NONBLOCK;

/// The bytes of the regular file at `path`, at most `max`: beneath its
/// view's root when it is under one ([`with_file`]), by path otherwise —
/// the rules of [`read_file_bounded`] either way.
pub fn read<P: AsRef<Path>>(path: P, max: u64) -> io::Result<Vec<u8>> {
    let path = path.as_ref();
    if let Some(r) = with_file(path, READ_FLAGS, move |f| read_file_bounded(&f, max)) {
        return r;
    }
    let f = open_path(path, READ_FLAGS)?;
    read_file_bounded(&f, max)
}

/// [`read`] at most [`STATE_MAX`], as text with what is not UTF-8 replaced
/// (U+FFFD).
pub fn read_text<P: AsRef<Path>>(path: P) -> io::Result<String> {
    read(path, STATE_MAX).map(|b| match String::from_utf8(b) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    })
}

/// `std::fs::read` of `path`, beneath its view when it is under one (any
/// size: a binary sysfs file, `/proc/<pid>/maps`), by path otherwise.
pub fn read_all<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>> {
    let path = path.as_ref();
    let read_whole = |f: File| {
        use std::io::Read;
        let mut out = Vec::new();
        (&f).read_to_end(&mut out)?;
        Ok(out)
    };
    if let Some(r) = with_file(path, READ_FLAGS, read_whole) {
        return r;
    }
    std::fs::read(path)
}

/// `std::fs::read_to_string` of `path`, beneath its view when it is under
/// one (`InvalidData` when it is not UTF-8, as there).
pub fn read_to_string<P: AsRef<Path>>(path: P) -> io::Result<String> {
    let path = path.as_ref();
    if view_of(path).is_none() {
        return std::fs::read_to_string(path);
    }
    String::from_utf8(read_all(path)?).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "stream did not contain valid UTF-8",
        )
    })
}

/// `std::fs::write` of `path` (an existing kernel knob: a cgroup's
/// `memory.max`, a `/proc/<pid>/oom_score_adj`), beneath its view when it
/// is under one — nothing is created there.
pub fn write<P: AsRef<Path>>(path: P, contents: impl AsRef<[u8]>) -> io::Result<()> {
    let path = path.as_ref();
    let bytes = contents.as_ref().to_vec();
    let write_all = move |f: File| {
        use std::io::Write;
        (&f).write_all(&bytes)
    };
    if let Some(r) = with_file(path, libc::O_WRONLY | libc::O_TRUNC, write_all) {
        return r;
    }
    std::fs::write(path, contents)
}

/// `std::fs::create_dir` of `path` (a cgroup), its parent opened beneath
/// its view when it is under one (`mkdirat`).
pub fn create_dir<P: AsRef<Path>>(path: P) -> io::Result<()> {
    create_dir_mode(path, 0o777)
}

/// Lot 353 (re-check 2 of #563): [`create_dir`] with `mode` (less the
/// umask) — a private directory made private at once (the CoW journal's).
pub fn create_dir_mode<P: AsRef<Path>>(path: P, mode: u32) -> io::Result<()> {
    let path = path.as_ref();
    at_parent(path, |dir, name| {
        // SAFETY: the fd is live, `name` NUL-terminated.
        (unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), mode as libc::mode_t) } == 0)
            .then_some(())
            .ok_or_else(io::Error::last_os_error)
    })
    .unwrap_or_else(|| {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(mode).create(path)
    })
}

/// `std::fs::create_dir_all` of `path` (a cgroup and its parents), each
/// directory made beneath its view as [`create_dir`] makes it.
pub fn create_dir_all<P: AsRef<Path>>(path: P) -> io::Result<()> {
    let path = path.as_ref();
    let Some((view, _)) = view_of(path) else {
        return std::fs::create_dir_all(path);
    };
    let mut missing: Vec<&Path> = path
        .ancestors()
        .take_while(|a| a.starts_with(&view.at) && *a != view.at.as_path())
        .collect();
    missing.reverse();
    for dir in missing {
        match create_dir(dir) {
            Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(e),
            _ => {}
        }
    }
    Ok(())
}

/// `std::fs::remove_dir` of `path` (a cgroup), as [`create_dir`].
pub fn remove_dir<P: AsRef<Path>>(path: P) -> io::Result<()> {
    let path = path.as_ref();
    at_parent(path, |dir, name| {
        // SAFETY: the fd is live, `name` NUL-terminated.
        (unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } == 0)
            .then_some(())
            .ok_or_else(io::Error::last_os_error)
    })
    .unwrap_or_else(|| std::fs::remove_dir(path))
}

/// Lot 353 (re-check 2 of #563): `std::fs::remove_file` of `path`, its
/// parent opened beneath its view (the host's view `/proc/1/root/…`: the
/// CoW journal's files).
pub fn remove_file<P: AsRef<Path>>(path: P) -> io::Result<()> {
    let path = path.as_ref();
    at_parent(path, |dir, name| {
        // SAFETY: the fd is live, `name` NUL-terminated.
        (unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } == 0)
            .then_some(())
            .ok_or_else(io::Error::last_os_error)
    })
    .unwrap_or_else(|| std::fs::remove_file(path))
}

/// Lot 353 (re-check 2 of #563): `std::fs::rename` of `from` to `to`,
/// each parent opened beneath its view. Both under a view, or both under
/// none.
pub fn rename<P: AsRef<Path>, Q: AsRef<Path>>(from: P, to: Q) -> io::Result<()> {
    let (from, to) = (from.as_ref(), to.as_ref());
    let parted = |p: &Path| -> Option<io::Result<(File, CString)>> {
        let (parent, name) = (p.parent()?, p.file_name()?);
        view_of(parent)?;
        Some(
            CString::new(name.as_bytes())
                .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
                .and_then(|n| Ok((open(parent, libc::O_RDONLY | libc::O_DIRECTORY)?, n))),
        )
    };
    match (parted(from), parted(to)) {
        (Some(a), Some(b)) => {
            let ((fd, fname), (td, tname)) = (a?, b?);
            // SAFETY: live fds, NUL-terminated names.
            let rc = unsafe {
                libc::renameat(
                    fd.as_raw_fd(),
                    fname.as_ptr(),
                    td.as_raw_fd(),
                    tname.as_ptr(),
                )
            };
            (rc == 0).then_some(()).ok_or_else(io::Error::last_os_error)
        }
        (None, None) => std::fs::rename(from, to),
        _ => Err(io::Error::from_raw_os_error(libc::EXDEV)),
    }
}

/// Lot 353 (re-check 2 of #563): the file at `path` created (`O_CREAT`,
/// with `flags` and `mode`) in its parent opened beneath its view — as
/// [`open`], for a file the caller makes.
pub fn create<P: AsRef<Path>>(path: P, flags: i32, mode: u32) -> io::Result<File> {
    let path = path.as_ref();
    let mut made = None;
    let r = at_parent(path, |dir, name| {
        // SAFETY: the fd is live, `name` NUL-terminated; the mode is read
        // with O_CREAT.
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                mode as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a new descriptor the kernel gave this call alone.
        made = Some(unsafe { File::from_raw_fd(fd) });
        Ok(())
    });
    match r {
        Some(Ok(())) => made.ok_or_else(|| io::Error::from_raw_os_error(libc::EIO)),
        Some(Err(e)) => Err(e),
        None => {
            use std::os::unix::fs::OpenOptionsExt;
            let mut o = std::fs::OpenOptions::new();
            o.custom_flags(flags | libc::O_NOFOLLOW)
                .mode(mode)
                .create(true);
            match flags & libc::O_ACCMODE {
                libc::O_WRONLY => o.write(true),
                libc::O_RDWR => o.read(true).write(true),
                _ => o.read(true),
            };
            if flags & libc::O_APPEND != 0 {
                o.append(true);
            }
            o.open(path)
        }
    }
}

/// `op` on the parent directory of `path` opened beneath its view (no
/// mount crossed) and `path`'s last name; `None` when the parent is under
/// no view.
fn at_parent(
    path: &Path,
    op: impl FnOnce(&File, &std::ffi::CStr) -> io::Result<()>,
) -> Option<io::Result<()>> {
    let (parent, name) = (path.parent()?, path.file_name()?);
    view_of(parent)?;
    let name = match CString::new(name.as_bytes()) {
        Ok(n) => n,
        Err(_) => return Some(Err(io::Error::from_raw_os_error(libc::EINVAL))),
    };
    Some(open(parent, libc::O_RDONLY | libc::O_DIRECTORY).and_then(|d| op(&d, &name)))
}

/// The file at `path` opened with `flags` beneath its view — a file of the
/// view's own file system, crossing no mount (`EXDEV` otherwise), or what
/// a magic link on its path names — for a caller that keeps the
/// descriptor. A path under no view is opened by path.
pub fn open<P: AsRef<Path>>(path: P, flags: i32) -> io::Result<File> {
    let path = path.as_ref();
    match view_of(path) {
        Some((view, rel)) => match &view.root {
            Ok(root) => match openat2(root, &rel, flags, NO_CROSSING) {
                Err(e) if e.raw_os_error() == Some(libc::ELOOP) => openat(root, &rel, flags),
                r => r,
            },
            Err(why) => Err(not_anchored(path, why)),
        },
        None => open_path(path, flags),
    }
}

/// The names in the directory at `path` (not `.` and `..`), beneath its
/// view as [`read`] reads a file.
pub fn read_dir<P: AsRef<Path>>(path: P) -> io::Result<Vec<OsString>> {
    read_dir_max(path, usize::MAX)
}

/// [`read_dir`], at most `max` names (the first the directory gives).
pub fn read_dir_max<P: AsRef<Path>>(path: P, max: usize) -> io::Result<Vec<OsString>> {
    let path = path.as_ref();
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NONBLOCK;
    if let Some(r) = with_file(path, flags, move |f| names_of(f, max)) {
        return r;
    }
    names_of(open_path(path, flags)?, max)
}

/// Lot 353 (the review of #563, F2): `chmod` of the file `f` refers to —
/// an `O_PATH` descriptor too, which `fchmod` refuses — through its
/// `/proc/self/fd` entry beneath the `/proc` root the start anchored (the
/// directory opened crossing no mount), never through the `/proc` mounted
/// now. `Err` when that root is not anchored: the caller's fallback.
pub fn chmod_fd(f: &File, mode: u32) -> io::Result<()> {
    let dir = open("/proc/self/fd", libc::O_PATH | libc::O_DIRECTORY)?;
    let name = CString::new(f.as_raw_fd().to_string())
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    // SAFETY: a live directory fd and a NUL-terminated name; the magic link
    // is followed to the file `f` refers to.
    if unsafe { libc::fchmodat(dir.as_raw_fd(), name.as_ptr(), mode as libc::mode_t, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Lot 353 (the review of #563, F2): the file `f` refers to (an `O_PATH`
/// descriptor too) opened again with `flags`, through its `/proc/self/fd`
/// entry beneath the `/proc` root the start anchored, as [`chmod_fd`].
pub fn reopen_fd(f: &File, flags: i32) -> io::Result<File> {
    let dir = open("/proc/self/fd", libc::O_PATH | libc::O_DIRECTORY)?;
    openat(&dir, Path::new(&f.as_raw_fd().to_string()), flags)
}

/// The names in the open directory `f` (not `.` and `..`): lot 353, the
/// listing of a directory a caller opened beneath a descriptor of its own
/// (the signed logs' anchored directories).
pub fn dir_names(f: File) -> io::Result<Vec<OsString>> {
    names_of(f, usize::MAX)
}

/// The entries of the open directory `f`.
fn names_of(f: File, max: usize) -> io::Result<Vec<OsString>> {
    use std::os::fd::IntoRawFd;
    let fd = f.into_raw_fd();
    // SAFETY: `fd` is an open directory this call owns; `fdopendir` takes
    // it (closed by `closedir`).
    let dir = unsafe { libc::fdopendir(fd) };
    if dir.is_null() {
        let e = io::Error::last_os_error();
        // SAFETY: `fdopendir` failed: the descriptor is still ours.
        unsafe { libc::close(fd) };
        return Err(e);
    }
    let mut out = Vec::new();
    loop {
        // SAFETY: `dir` is a live stream; errno is cleared to tell the end
        // from an error.
        let ent = unsafe {
            *libc::__errno_location() = 0;
            libc::readdir(dir)
        };
        if ent.is_null() {
            // SAFETY: as above.
            let errno = unsafe { *libc::__errno_location() };
            // SAFETY: `dir` is live and closed once.
            unsafe { libc::closedir(dir) };
            if errno != 0 {
                return Err(io::Error::from_raw_os_error(errno));
            }
            return Ok(out);
        }
        // SAFETY: `d_name` is NUL-terminated within the entry `readdir`
        // returned, valid until the next call.
        let name = unsafe { std::ffi::CStr::from_ptr((*ent).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            out.push(OsString::from_vec(name.to_vec()));
        }
        if out.len() >= max {
            // SAFETY: `dir` is live and closed once.
            unsafe { libc::closedir(dir) };
            return Ok(out);
        }
    }
}

/// `std::fs::metadata` of `path`, beneath its view (`O_PATH`: nothing
/// opened, a last symbolic link followed).
pub fn metadata<P: AsRef<Path>>(path: P) -> io::Result<Metadata> {
    stat(path.as_ref(), true)
}

/// `std::fs::symlink_metadata` of `path`, beneath its view.
pub fn symlink_metadata<P: AsRef<Path>>(path: P) -> io::Result<Metadata> {
    stat(path.as_ref(), false)
}

fn stat(path: &Path, follow: bool) -> io::Result<Metadata> {
    let flags = libc::O_PATH | if follow { 0 } else { libc::O_NOFOLLOW };
    if let Some(r) = with_file(path, flags, |f| f.metadata()) {
        return r;
    }
    if follow {
        std::fs::metadata(path)
    } else {
        std::fs::symlink_metadata(path)
    }
}

/// Whether `path` names something, beneath its view: an error other than
/// "none" (`ENOENT`, `ENOTDIR`) is the caller's.
pub fn exists<P: AsRef<Path>>(path: P) -> io::Result<bool> {
    match metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR)) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Whether `path` is a directory, beneath its view (`false` when there is
/// none or it cannot be told).
pub fn is_dir<P: AsRef<Path>>(path: P) -> bool {
    metadata(path).is_ok_and(|m| m.is_dir())
}

/// The target of the symbolic (or magic) link at `path`, beneath its view.
pub fn read_link<P: AsRef<Path>>(path: P) -> io::Result<PathBuf> {
    let path = path.as_ref();
    let flags = libc::O_PATH | libc::O_NOFOLLOW;
    if let Some(r) = with_file(path, flags, |f| link_of(&f)) {
        return r;
    }
    std::fs::read_link(path)
}

/// `readlinkat(fd, "")` of a link opened `O_PATH | O_NOFOLLOW`.
fn link_of(f: &File) -> io::Result<PathBuf> {
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    // SAFETY: the fd is live, the empty path NUL-terminated, `buf` writable
    // for its length.
    let n = unsafe {
        libc::readlinkat(
            f.as_raw_fd(),
            c"".as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(n as usize);
    Ok(PathBuf::from(OsString::from_vec(buf)))
}

/// Lot 353 (pre-alpha Phase 3, X6): the CPUs this process may use, as
/// `std::thread::available_parallelism` counts them — its affinity, within
/// its cgroup's `cpu.max` quota — the quota read beneath the cgroup2 root
/// the start anchored: std reads `/sys/fs/cgroup/<its cgroup>/cpu.max` by
/// path, and a FUSE mounted over `/sys/fs/cgroup` held the thread asking
/// (the runtime's build, the audit log's parallel check). At least 1.
pub fn available_parallelism() -> usize {
    // SAFETY: `cpu_set_t` is plain old data, valid when zeroed; the kernel
    // fills it for this thread.
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    // SAFETY: `set` is writable for its size.
    let rc =
        unsafe { libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) };
    // SAFETY: `set` was filled above.
    let mut n = if rc == 0 {
        (unsafe { libc::CPU_COUNT(&set) }) as usize
    } else {
        1
    }
    .max(1);
    let cgroup = read_text("/proc/self/cgroup").ok();
    let at = views().cgroup().map(|v| v.at.clone());
    if let (Some(text), Some(at)) = (cgroup, at) {
        if let Some(own) = text.lines().find_map(|l| l.strip_prefix("0::")) {
            let mut dir = at.join(own.trim().trim_start_matches('/'));
            loop {
                if let Ok(max) = read_text(dir.join("cpu.max")) {
                    let mut f = max.split_whitespace();
                    if let (Some(q), Some(p)) = (f.next(), f.next()) {
                        if let (Ok(q), Ok(p)) = (q.parse::<u64>(), p.parse::<u64>()) {
                            if p > 0 {
                                n = n.min((q.div_ceil(p) as usize).max(1));
                            }
                        }
                    }
                }
                if dir == at || !dir.pop() || !dir.starts_with(&at) {
                    break;
                }
            }
        }
    }
    n
}

/// The file at `path` opened with `flags` as [`read`] opens one: beneath
/// its view, a mount below the root crossed only into the kernel's own
/// file systems within the deadline (a kernel file system's mount point:
/// `/sys/kernel/security`), by path when it is under no view.
pub fn open_crossing<P: AsRef<Path>>(path: P, flags: i32) -> io::Result<File> {
    let path = path.as_ref();
    with_file(path, flags, Ok).unwrap_or_else(|| open_path(path, flags))
}

/// Lot 353 (re-check 1 of #563, N1): one directory of a walk one name at a
/// time ([`walk_root`]), and the path it stands for.
#[derive(Debug)]
pub struct WalkDir {
    dir: File,
    at: PathBuf,
    in_view: bool,
}

impl WalkDir {
    /// The one name `name` below this directory, opened `O_PATH |
    /// O_NOFOLLOW` (a symbolic link is the link itself, never followed).
    /// Beneath a view's anchored root it crosses no mount and no magic link
    /// (`RESOLVE_BENEATH | RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS`): a mount
    /// below the root — the kernel's, or one laid there — is `EXDEV`, never
    /// walked into, so what it opens is the view's own file system and its
    /// `fstat` is the kernel's answer. Elsewhere it is an `openat`. A name
    /// that is not one component (`..`, `.`, a `/`) is `EINVAL`.
    pub fn step(&self, name: &std::ffi::OsStr) -> io::Result<WalkDir> {
        let b = name.as_bytes();
        if b.is_empty() || b == b"." || b == b".." || b.contains(&b'/') {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        let flags = libc::O_PATH | libc::O_NOFOLLOW;
        let rel = Path::new(name);
        let dir = if self.in_view {
            openat2(&self.dir, rel, flags, NO_CROSSING)?
        } else {
            openat(&self.dir, rel, flags)?
        };
        Ok(WalkDir {
            dir,
            at: self.at.join(name),
            in_view: self.in_view,
        })
    }

    /// The open directory (or the link, or the file, a step reached).
    pub fn file(&self) -> &File {
        &self.dir
    }

    /// The path this directory stands for.
    pub fn at(&self) -> &Path {
        &self.at
    }

    /// Whether the walk is beneath a view's anchored root.
    pub fn in_view(&self) -> bool {
        self.in_view
    }
}

/// Lot 353 (re-check 1 of #563, N1): where a walk of `path` one name at a
/// time starts, and the names left to walk ([`WalkDir::step`] each). A
/// path under `/proc`, `/sys` or the cgroup2 hierarchy starts at the root
/// of its view the start anchored — a mount laid over the view since (a
/// FUSE over `/proc` that never answers) is never walked: the open
/// sensor's rule refresh walked the mass-write carve-out `/proc/` from
/// `/`, and the `fstat` of the FUSE root it reached held a runtime worker
/// for as long as the mount stayed. Any other path starts at `/`. A view
/// the start refused is an error at once; a `..` on the way is
/// `InvalidInput`. `path` is taken from `/` (a relative one too).
pub fn walk_root(path: &Path) -> io::Result<(WalkDir, Vec<OsString>)> {
    let mut names = Vec::new();
    for c in path.components() {
        match c {
            Component::Normal(n) => names.push(n.to_os_string()),
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{}: a `..` on the way — not walked", path.display()),
                ))
            }
        }
    }
    let abs: PathBuf = std::iter::once(std::ffi::OsStr::new("/"))
        .chain(names.iter().map(OsString::as_os_str))
        .collect();
    if let Some((view, rel)) = view_of(&abs) {
        let root = view.root.as_ref().map_err(|why| not_anchored(&abs, why))?;
        let rest = rel
            .components()
            .filter_map(|c| match c {
                Component::Normal(n) => Some(n.to_os_string()),
                _ => None,
            })
            .collect();
        return Ok((
            WalkDir {
                dir: root.try_clone()?,
                at: view.at.clone(),
                in_view: true,
            },
            rest,
        ));
    }
    let dir = open_path(Path::new("/"), libc::O_PATH | libc::O_DIRECTORY)?;
    Ok((
        WalkDir {
            dir,
            at: PathBuf::from("/"),
            in_view: false,
        },
        names,
    ))
}

/// Lot 353: the device (`major:minor`, the kernel's encoding: `major << 20
/// | minor`), inode and mode of the open `f` as the kernel has them cached
/// (`statx` with `AT_STATX_DONT_SYNC`): a FUSE inode — a FUSE mounted over
/// the path the caller opened — is never asked, so its daemon cannot hold
/// the caller.
pub fn stat_cached(f: &File) -> io::Result<(u64, u64, u32)> {
    // SAFETY: `statx` is plain old data, valid when zeroed.
    let mut sx: libc::statx = unsafe { std::mem::zeroed() };
    // SAFETY: the fd is live, the empty path NUL-terminated, `sx` writable.
    let rc = unsafe {
        libc::statx(
            f.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_STATX_DONT_SYNC,
            libc::STATX_INO | libc::STATX_MODE,
            &mut sx,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let dev = (u64::from(sx.stx_dev_major) << 20) | u64::from(sx.stx_dev_minor);
    Ok((dev, sx.stx_ino, u32::from(sx.stx_mode)))
}

/// The cgroup2 hierarchy's root directory, opened read-only beneath the
/// descriptor the start took (`BPF_PROG_QUERY`, `BPF_LINK_CREATE`), and
/// where it is mounted.
pub fn cgroup_root() -> Result<(File, &'static Path), String> {
    let view = views()
        .cgroup()
        .ok_or_else(|| "no cgroup v2 hierarchy (a cgroup v1 host)".to_string())?;
    let root = view
        .root
        .as_ref()
        .map_err(|why| format!("{}: not anchored at the start ({why})", view.at.display()))?;
    openat2(
        root,
        Path::new("."),
        libc::O_RDONLY | libc::O_DIRECTORY,
        NO_CROSSING,
    )
    .map(|f| (f, view.at.as_path()))
    .map_err(|e| format!("{}: {e}", view.at.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lot 353 (re-check 1 of #563, N1): a walk of a view's path starts at
    /// the root the start anchored — the same inode as the view's root —,
    /// one of any other path at `/`; a step crosses no mount below a view,
    /// follows no link, and takes one name only.
    #[test]
    fn a_view_s_walk_starts_at_its_anchored_root() {
        use std::os::unix::fs::MetadataExt;
        assert!(unanchored().is_empty(), "{:?}", unanchored());
        let (start, names) = walk_root(Path::new("/proc/self")).unwrap();
        assert!(start.in_view());
        assert_eq!(start.at(), Path::new("/proc"));
        assert_eq!(names, vec![OsString::from("self")]);
        let root = symlink_metadata("/proc").unwrap();
        let m = start.file().metadata().unwrap();
        assert_eq!((m.dev(), m.ino()), (root.dev(), root.ino()));
        // `/proc/self` is a link: the step is the link itself
        let link = start.step(std::ffi::OsStr::new("self")).unwrap();
        assert!(link.file().metadata().unwrap().file_type().is_symlink());
        assert_eq!(link.at(), Path::new("/proc/self"));
        let (sys, names) = walk_root(Path::new("/sys/")).unwrap();
        assert!(sys.in_view() && names.is_empty());
        // another path: from `/`, every name left
        let (slash, names) = walk_root(Path::new("/etc/hostname")).unwrap();
        assert!(!slash.in_view());
        assert_eq!(slash.at(), Path::new("/"));
        assert_eq!(
            names,
            vec![OsString::from("etc"), OsString::from("hostname")]
        );
        // relative: from `/` as well; a `..` is not walked
        let (_, names) = walk_root(Path::new("proc/self")).unwrap();
        assert_eq!(
            names,
            vec![OsString::from("self")],
            "a relative view path is the view's"
        );
        assert_eq!(
            walk_root(Path::new("/proc/../etc")).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        for bad in ["..", ".", "a/b", ""] {
            assert_eq!(
                start
                    .step(std::ffi::OsStr::new(bad))
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::EINVAL),
                "{bad:?}"
            );
        }
        // a mount below the view (binfmt_misc, securityfs, a cgroup v1
        // controller, where the host has one) is never crossed
        for below in [
            "/proc/sys/fs/binfmt_misc",
            "/sys/kernel/security",
            "/sys/kernel/tracing",
        ] {
            let p = Path::new(below);
            let Ok(m) = std::fs::metadata(p) else {
                continue;
            };
            let Ok(parent) = std::fs::metadata(p.parent().unwrap()) else {
                continue;
            };
            if m.dev() == parent.dev() {
                continue; // not a mount here
            }
            let (mut cur, names) = walk_root(p).unwrap();
            let (last, up) = names.split_last().unwrap();
            for n in up {
                cur = cur.step(n).unwrap();
            }
            assert_eq!(
                cur.step(last).unwrap_err().raw_os_error(),
                Some(libc::EXDEV),
                "{below}"
            );
        }
    }

    /// Lot 353 (named): a state file of `/proc` is read beneath the root the
    /// start took, as by path.
    #[test]
    fn a_proc_file_is_read_beneath_the_anchored_root() {
        assert!(unanchored().is_empty(), "{:?}", unanchored());
        let (v, rel) = view_of(Path::new("/proc/self/stat")).unwrap();
        assert_eq!(v.kind(), Kind::Proc);
        assert_eq!(rel, Path::new("self/stat"));
        let mine = read_text(Path::new("/proc/self/stat")).unwrap();
        assert!(
            mine.starts_with(&format!("{} (", std::process::id())),
            "{mine}"
        );
        let names = read_dir(Path::new("/proc/self/task")).unwrap();
        assert!(!names.is_empty());
        assert!(is_dir(Path::new("/proc/self")));
        assert!(!exists(Path::new("/proc/self/no-such-entry")).unwrap());
        let exe = read_link(Path::new("/proc/self/exe")).unwrap();
        assert_eq!(exe, std::fs::read_link("/proc/self/exe").unwrap());
    }

    /// Lot 353: a path through a magic link reaches what it names, resolved
    /// from the anchored root.
    #[test]
    fn a_magic_link_is_resolved_from_the_root() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("f"), b"x").unwrap();
        let dir = File::open(d.path()).unwrap();
        let via = PathBuf::from(format!("/proc/self/fd/{}/f", dir.as_raw_fd()));
        assert_eq!(read(&via, 16).unwrap(), b"x");
    }

    /// Lot 353: a path that is not plain, or under no view, is not routed.
    #[test]
    fn only_plain_paths_under_a_view_are_routed() {
        assert!(view_of(Path::new("/proc/../etc/passwd")).is_none());
        assert!(view_of(Path::new("proc/self/stat")).is_none());
        assert!(view_of(Path::new("/etc/hostname")).is_none());
        assert!(
            view_of(Path::new("/procfs/x")).is_none(),
            "a component, not a prefix"
        );
        let (v, rel) = view_of(Path::new("/sys")).unwrap();
        assert_eq!((v.kind(), rel.as_path()), (Kind::Sys, Path::new(".")));
    }

    /// Lot 353: a directory, a FIFO or a file past the bound is not read.
    #[test]
    fn only_a_bounded_regular_file_is_read() {
        assert!(read(Path::new("/proc/self"), 16).is_err(), "a directory");
        assert!(
            read(Path::new("/proc/self/status"), 4).is_err(),
            "past the bound"
        );
    }

    /// Lot 353: below a view's root, a path that crosses into the kernel's
    /// own file system (securityfs, fusectl, configfs, binfmt_misc…) reads
    /// as by path.
    #[test]
    fn a_kernel_mount_below_a_view_is_read_through() {
        let table = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
        let mut compared = 0;
        for line in table.lines() {
            let f: Vec<&str> = line.split(' ').collect();
            let Some(dash) = f.iter().position(|x| *x == "-") else {
                continue;
            };
            let (mp, fstype) = (f[4], f[dash + 1]);
            let kernel = KERNEL_MAGICS.iter().any(|(_, n)| *n == fstype);
            if !kernel
                || !(mp.starts_with("/sys/") || mp.starts_with("/proc/"))
                || mp.contains('\\')
            {
                continue;
            }
            if views()
                .view_of(Path::new(mp))
                .is_some_and(|v| v.at == Path::new(mp))
            {
                continue; // a view's own root
            }
            let Ok(by_path) = std::fs::read_dir(mp) else {
                continue;
            };
            let mut want: Vec<OsString> = by_path.flatten().map(|e| e.file_name()).collect();
            let mut got = read_dir(mp).unwrap_or_else(|e| panic!("{mp} ({fstype}): {e}"));
            want.sort();
            got.sort();
            assert_eq!(got, want, "{mp} ({fstype})");
            compared += 1;
        }
        assert!(
            compared > 0,
            "no kernel mount below /sys or /proc on this host:\n{table}"
        );
    }

    /// Lot 353: what a crossing may reach — the kernel's file systems, a
    /// hybrid host's tmpfs at `/sys/fs/cgroup`; never a FUSE, a tmpfs
    /// elsewhere or a disk's.
    #[test]
    fn a_crossing_reads_only_the_kernel_s_file_systems() {
        let p = Path::new("/sys/kernel/security/lsm");
        assert!(crossing_allowed(Kind::Sys, p, 0x7363_6673));
        assert!(crossing_allowed(
            Kind::Proc,
            Path::new("/proc/sys/fs/binfmt_misc/x"),
            0x4249_4e4d
        ));
        assert!(crossing_allowed(
            Kind::Sys,
            Path::new("/sys/fs/cgroup/memory"),
            CGROUP_SUPER_MAGIC
        ));
        assert!(crossing_allowed(
            Kind::Sys,
            Path::new("/sys/fs/cgroup"),
            TMPFS_MAGIC
        ));
        assert!(!crossing_allowed(Kind::Sys, p, FUSE_SUPER_MAGIC));
        assert!(!crossing_allowed(Kind::Sys, p, TMPFS_MAGIC));
        assert!(!crossing_allowed(
            Kind::Proc,
            Path::new("/proc/sys/kernel/tainted"),
            TMPFS_MAGIC
        ));
        assert!(
            !crossing_allowed(Kind::Proc, Path::new("/proc/stat"), 0xef53),
            "ext4"
        );
    }

    /// Lot 353: a walk that does not answer fails after the deadline — the
    /// caller is not held — and is counted.
    #[test]
    fn a_walk_that_does_not_answer_fails_after_its_deadline() {
        let t0 = std::time::Instant::now();
        let r: io::Result<()> = bounded(Path::new("/sys/stalled"), || {
            std::thread::sleep(WALK_DEADLINE + Duration::from_secs(1));
            Ok(())
        });
        let e = r.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut, "{e}");
        assert!(t0.elapsed() < WALK_DEADLINE + Duration::from_millis(800));
        assert!(counts().0 >= 1);
    }

    /// Lot 353 (named, pre-alpha Phase 3 X6): a mount laid over a view after
    /// the start is never walked — over `/sys/fs/cgroup` (as the FUSE that
    /// held the agent's threads) the cgroup2 hierarchy is still read beneath
    /// the root the start took; a tmpfs below `/proc` is a mount crossed
    /// into another file system: refused, never read. In a user and mount
    /// namespace of a child (skipped where the host refuses one).
    #[test]
    fn a_mount_laid_over_a_view_after_the_start_is_never_walked() {
        let _ = views();
        let Ok(want) = std::fs::read_to_string("/sys/fs/cgroup/cgroup.controllers") else {
            return; // no cgroup2 root here
        };
        // SAFETY: fork; the child mounts in namespaces of its own and _exits.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork");
        if pid == 0 {
            let rc = covered_child(&want);
            // SAFETY: _exit in the child.
            unsafe { libc::_exit(rc) };
        }
        let mut status = 0;
        // SAFETY: waiting for our own child.
        unsafe { libc::waitpid(pid, &mut status, 0) };
        assert!(libc::WIFEXITED(status), "child status {status:#x}");
        match libc::WEXITSTATUS(status) {
            0 | 99 => {}
            rc => panic!("the child failed with {rc}"),
        }
    }

    /// The child of [`a_mount_laid_over_a_view_after_the_start_is_never_walked`]:
    /// 0 when it holds, 99 when the host refuses the namespaces.
    fn covered_child(want: &str) -> i32 {
        let tmpfs = |target: &std::ffi::CStr| {
            // SAFETY: NUL-terminated strings, no data.
            unsafe {
                libc::mount(
                    c"none".as_ptr(),
                    target.as_ptr(),
                    c"tmpfs".as_ptr(),
                    0,
                    std::ptr::null(),
                )
            }
        };
        // SAFETY: the child's own namespaces.
        if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) } != 0 {
            return 99;
        }
        // SAFETY: as above; no data.
        let private = unsafe {
            libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            )
        };
        if private != 0 {
            return 99;
        }
        // the child's views, anchored in its own namespace, before the
        // mounts laid over them
        let views = Views::open();
        let text = |p: &str| {
            with_file_in(&views, Path::new(p), READ_FLAGS, |f| {
                read_file_bounded(&f, 1 << 16)
            })
            .expect("a view's path")
        };
        let names = |p: &str| {
            with_file_in(&views, Path::new(p), READ_FLAGS | libc::O_DIRECTORY, |f| {
                names_of(f, usize::MAX)
            })
            .expect("a view's path")
        };
        if tmpfs(c"/sys/fs/cgroup") != 0 {
            return 99;
        }
        if std::fs::read("/sys/fs/cgroup/cgroup.controllers").is_ok() {
            return 10; // the cover did not take
        }
        match text("/sys/fs/cgroup/cgroup.controllers") {
            Ok(t) if t == want.as_bytes() => {}
            _ => return 11,
        }
        if names("/sys/fs/cgroup").map_or(true, |n| n.is_empty()) {
            return 12;
        }
        // a mount below the cgroup2 root: never crossed
        let Some(child) = names("/sys/fs/cgroup")
            .ok()
            .and_then(|n| n.into_iter().find(|x| x.as_bytes().ends_with(b".slice")))
        else {
            return 0;
        };
        let below = format!("/sys/fs/cgroup/{}", child.to_string_lossy());
        let below_c = CString::new(below.clone()).unwrap();
        // the tmpfs over /sys/fs/cgroup hides it from the path: mount the
        // second one through the view's root
        let Ok((root, _)) = views
            .cgroup()
            .map(|v| v.root.as_ref().map(|r| (r, ())))
            .unwrap()
        else {
            return 14;
        };
        let via = format!(
            "/proc/self/fd/{}/{}",
            root.as_raw_fd(),
            child.to_string_lossy()
        );
        if tmpfs(&CString::new(via).unwrap()) != 0 {
            return 0;
        }
        drop(below_c);
        match text(&format!("{below}/cgroup.procs")) {
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {}
            _ => return 15,
        }
        // a cgroup2 directory bound below the root (another cgroup's files
        // in its place): the cgroup2 file system, and still never crossed
        let other = names("/sys/fs/cgroup").ok().and_then(|n| {
            n.into_iter()
                .find(|x| x.as_bytes().ends_with(b".slice") && *x != child)
        });
        if let Some(other) = other {
            let at = |n: &OsString| {
                CString::new(format!(
                    "/proc/self/fd/{}/{}",
                    root.as_raw_fd(),
                    n.to_string_lossy()
                ))
                .unwrap()
            };
            let (from, to) = (at(&other), at(&child));
            // SAFETY: NUL-terminated paths, no data: a bind mount.
            let bound = unsafe {
                libc::mount(
                    from.as_ptr(),
                    to.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                )
            };
            if bound == 0 {
                match text(&format!("{below}/cgroup.procs")) {
                    Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {}
                    _ => return 16,
                }
            }
        }
        if tmpfs(c"/proc/sys/kernel") != 0 {
            return 0; // the last case needs a mount below /proc
        }
        match text("/proc/sys/kernel/osrelease") {
            Err(e)
                if e.kind() == io::ErrorKind::PermissionDenied
                    && e.to_string().contains("not the kernel's") =>
            {
                0
            }
            _ => 13,
        }
    }

    /// Lot 353: a root of another file system than the view's is refused,
    /// naming it.
    #[test]
    fn a_root_of_another_file_system_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let e = anchor(d.path(), &[PROC_SUPER_MAGIC]).unwrap_err();
        assert!(e.contains("not the kernel's"), "{e}");
        assert!(anchor(Path::new("/proc"), &[PROC_SUPER_MAGIC]).is_ok());
    }

    /// Lot 353 (the review of #563, F3, its probe's tables): the mount on
    /// top at a view point that is not the view — a tmpfs stacked over the
    /// cgroup2 root, a cgroup2 subtree bound over it, `/proc/sys` bound
    /// over `/proc`, another proc over `/proc` — is refused at the start; a
    /// view as mounted (and a bind of it onto itself) is not, nor a hybrid
    /// host's tmpfs at `/sys/fs/cgroup`.
    #[test]
    fn a_mount_over_a_view_s_root_is_not_taken_for_the_view() {
        let base = "\
24 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
25 24 0:22 / /sys rw,nosuid shared:2 - sysfs sysfs rw
26 24 0:23 / /proc rw,nosuid shared:3 - proc proc rw
27 25 0:26 / /sys/fs/cgroup rw,nosuid shared:4 - cgroup2 cgroup2 rw,nsdelegate
";
        for p in ["/proc", "/sys", "/sys/fs/cgroup"] {
            assert_eq!(shadowed(base, p), None, "{p}");
        }
        let with = |extra: &str| format!("{base}{extra}");
        let tmpfs = with("900 27 0:91 / /sys/fs/cgroup rw shared:500 - tmpfs tmpfs rw\n");
        assert!(shadowed(&tmpfs, "/sys/fs/cgroup")
            .unwrap()
            .contains("tmpfs mounted over the cgroup2"));
        let subtree =
            with("901 27 0:26 /user.slice /sys/fs/cgroup rw shared:501 - cgroup2 cgroup2 rw\n");
        assert!(shadowed(&subtree, "/sys/fs/cgroup")
            .unwrap()
            .contains("source root /user.slice"));
        let procsys = with("903 26 0:23 /sys /proc rw shared:503 - proc proc rw\n");
        assert!(shadowed(&procsys, "/proc").is_some());
        let other_proc = with("904 26 0:95 / /proc rw shared:504 - proc proc rw\n");
        assert!(shadowed(&other_proc, "/proc")
            .unwrap()
            .contains("proc mounted over the proc"));
        let self_bind = with("905 27 0:26 / /sys/fs/cgroup ro shared:505 - cgroup2 cgroup2 rw\n");
        assert_eq!(
            shadowed(&self_bind, "/sys/fs/cgroup"),
            None,
            "the same view"
        );
        let hybrid = "\
24 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
25 24 0:22 / /sys rw,nosuid shared:2 - sysfs sysfs rw
30 25 0:27 / /sys/fs/cgroup ro shared:5 - tmpfs tmpfs ro,mode=755
31 30 0:28 / /sys/fs/cgroup/unified rw shared:6 - cgroup2 cgroup2 rw
";
        assert_eq!(shadowed(hybrid, "/sys/fs/cgroup"), None);
        assert_eq!(shadowed(hybrid, "/sys/fs/cgroup/unified"), None);
    }

    /// Lot 353 (the review of #563, F3): a start under a tmpfs laid over a
    /// unified host's cgroup2 root does not take the host for a cgroup v1
    /// one (rc2: no view, no degradation, the floors "restored" into the
    /// tmpfs): the cgroup view is refused, naming why, and its paths fail.
    /// In a user and mount namespace of a child, skipped where the host
    /// refuses one or is not unified.
    #[test]
    fn a_start_under_a_tmpfs_over_the_cgroup2_root_refuses_the_view() {
        let own = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
        if !std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
            || !unified_hierarchy_only(&own)
        {
            return; // not a unified host
        }
        // SAFETY: fork; the child mounts in namespaces of its own and _exits.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork");
        if pid == 0 {
            let rc = (|| {
                // SAFETY: the child's own namespaces; no data.
                let refused = unsafe {
                    libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) != 0
                        || libc::mount(
                            std::ptr::null(),
                            c"/".as_ptr(),
                            std::ptr::null(),
                            libc::MS_REC | libc::MS_PRIVATE,
                            std::ptr::null(),
                        ) != 0
                };
                if refused {
                    return 99;
                }
                // the table as it was before the cover (no stack in it: a
                // cgroup2 root unmounted, then a tmpfs mounted alone)
                let before = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
                // SAFETY: NUL-terminated strings, no data.
                if unsafe {
                    libc::mount(
                        c"none".as_ptr(),
                        c"/sys/fs/cgroup".as_ptr(),
                        c"tmpfs".as_ptr(),
                        0,
                        std::ptr::null(),
                    )
                } != 0
                {
                    return 99;
                }
                // the kernel's word on the hierarchies alone refuses it
                let Some(alone) = cgroup_view(Some(&before), true) else {
                    return 10; // taken for a cgroup v1 host
                };
                match alone.refused() {
                    Some(why) if why.contains("cgroup2 hierarchy alone") => {}
                    _ => return 11,
                }
                // and the start as it is (the stack in its table)
                let views = Views::open();
                match views.cgroup().and_then(View::refused) {
                    Some(why) if why.contains("a mount over") => {}
                    _ => return 12,
                }
                match with_file_in(
                    &views,
                    Path::new("/sys/fs/cgroup/x"),
                    READ_FLAGS,
                    |_| Ok(()),
                ) {
                    Some(Err(_)) => 0,
                    _ => 13,
                }
            })();
            // SAFETY: _exit in the child.
            unsafe { libc::_exit(rc) };
        }
        let mut status = 0;
        // SAFETY: waiting for our own child.
        unsafe { libc::waitpid(pid, &mut status, 0) };
        assert!(libc::WIFEXITED(status), "child status {status:#x}");
        match libc::WEXITSTATUS(status) {
            0 | 99 => {}
            rc => panic!("the child failed with {rc}"),
        }
    }

    /// Lot 353 (the review of #563, F3): a unified host is told by the
    /// kernel's word on this process's hierarchies, not by what is mounted
    /// at `/sys/fs/cgroup` — a tmpfs there no longer makes it a v1 host.
    #[test]
    fn a_unified_host_is_told_by_its_processes_hierarchies() {
        assert!(unified_hierarchy_only(
            "0::/system.slice/northnarrow-agent.service\n"
        ));
        assert!(!unified_hierarchy_only(
            "12:memory:/x\n1:name=systemd:/x\n0::/x\n"
        ));
        assert!(!unified_hierarchy_only(""));
        let own = std::fs::read_to_string("/proc/self/cgroup").unwrap();
        let unified = std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists();
        if unified {
            assert!(unified_hierarchy_only(&own), "{own}");
        }
    }

    /// Lot 353 (the review of #563, F2): the CPU count read once beneath
    /// the anchored /sys root is the kernel's possible CPUs (aya's count).
    #[test]
    fn the_possible_cpus_are_read_beneath_the_root() {
        assert_eq!(cpu_count("0-3"), Some(4));
        assert_eq!(cpu_count("0-3,8,10-11"), Some(7));
        assert_eq!(cpu_count("0"), Some(1));
        assert_eq!(cpu_count(""), None);
        assert_eq!(cpu_count("3-1"), None);
        assert_eq!(cpu_count("x"), None);
        let text = std::fs::read_to_string("/sys/devices/system/cpu/possible").unwrap();
        assert_eq!(possible_cpus(), Ok(cpu_count(text.trim()).unwrap()));
        assert_eq!(possible_cpus().unwrap(), aya::util::nr_cpus().unwrap());
    }
}
