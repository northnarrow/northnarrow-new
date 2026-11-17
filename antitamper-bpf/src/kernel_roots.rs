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
//! - Fix round 5 (the KVM suites of #563): the bpffs at `/sys/fs/bpf` — a
//!   mount below `/sys`, where the agent makes and removes its pin
//!   directories — is a view of its own ([`bpf_view`]); a thread whose
//!   seccomp filter refuses `openat2` (the decision thread's) walks one
//!   name at a time instead, no mount crossed ([`openat_walked`]).
//! - Re-check 4 of #563: that walk opens the file it reached again through
//!   the thread's own `thread-self/fd`, every name checked, and compares
//!   it with what the walk reached ([`reopen_checked`]); a link's `..` is
//!   walked from its directory, never above the root; `openat2`'s `EAGAIN`
//!   (a `..` raced by a rename or a mount) is tried again, then walked.
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
/// `BPF_FS_MAGIC`.
pub const BPF_FS_MAGIC: u64 = 0xcafe_4a11;
/// Where the bpffs is mounted (its view's root).
pub const BPF_ROOT: &str = "/sys/fs/bpf";

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
    (BPF_FS_MAGIC, "bpf"),
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
    /// Lot 353 (fix round 5): the bpffs at [`BPF_ROOT`] ([`bpf_view`]).
    Bpf,
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

/// The views.
#[derive(Debug)]
pub struct Views {
    proc: View,
    sys: View,
    /// `None` on a host without a cgroup2 hierarchy (cgroup v1 only).
    cgroup: Option<View>,
    /// `None` on a host with no bpffs at [`BPF_ROOT`] ([`bpf_view`]).
    bpf: Option<View>,
    /// Lot 359: the agent's pin directory when its lock is mounted there
    /// ([`pin_view`]); `None` otherwise (its paths are the bpffs view's).
    pin: Option<View>,
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
    [
        Some(&v.proc),
        Some(&v.sys),
        v.cgroup.as_ref(),
        v.bpf.as_ref(),
        v.pin.as_ref(),
    ]
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
        let bpf = bpf_view();
        let pin = bpf.as_ref().and_then(|_| pin_view(table.as_deref()));
        Views {
            proc,
            sys,
            cgroup,
            bpf,
            pin,
        }
    }

    /// The view `path` is under (the cgroup2 one and the bpffs before
    /// `/sys`; lot 359: the locked pin directory before the bpffs).
    pub fn view_of(&self, path: &Path) -> Option<&View> {
        for v in [&self.cgroup, &self.pin, &self.bpf].into_iter().flatten() {
            if path.starts_with(&v.at) {
                return Some(v);
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

/// Lot 353 (fix round 5, the KVM suites of #563): the bpffs at
/// [`BPF_ROOT`], a mount of its own below `/sys` that a path beneath the
/// `/sys` root does not cross (`EXDEV`): the start-in-cgroup tracker makes
/// and removes its pin directories there by their parent, the bpffs root,
/// and on 92de8ac5 every one was refused — a planted directory beside the
/// pin root was never removed, the debug build's plant never made. Its own
/// view, anchored at the start: the bpffs on top at [`BPF_ROOT`] then, the
/// one the pins made by path reach (aya's `BPF_OBJ_PIN`; a second bpffs
/// stacked there is the integrity round's finding, `bpffs_mount`). None
/// when no bpffs is mounted there (sysfs's own directory, or none: the
/// agent pins nothing); refused when another file system covers it.
fn bpf_view() -> Option<View> {
    let at = Path::new(BPF_ROOT);
    let view = |root| {
        Some(View {
            kind: Kind::Bpf,
            at: at.to_path_buf(),
            root,
        })
    };
    match anchor(at, &[BPF_FS_MAGIC, SYSFS_MAGIC]) {
        Ok((f, BPF_FS_MAGIC)) => view(Ok(f)),
        Ok(_) => None,
        Err(why) if why.contains("No such file") => None,
        Err(why) => view(Err(why)),
    }
}

/// Lot 359 (the re-check 3 of #567, N4): the agent's pin directory, when
/// its lock — the directory bound onto itself, private and unbindable — is
/// mounted there ([`pin_locked`] in this process's table): a view of its
/// own, anchored at the start (a path beneath the bpffs root would cross
/// the lock's mount: `EXDEV`, then a walk on a helper thread for each pin).
/// `None` without the lock (the bpffs view's, as before).
fn pin_view(table: Option<&str>) -> Option<View> {
    let at = Path::new(crate::DEFAULT_BPFFS_ROOT);
    if !table.is_some_and(|t| pin_locked(t, crate::DEFAULT_BPFFS_ROOT)) {
        return None;
    }
    Some(View {
        kind: Kind::Bpf,
        at: at.to_path_buf(),
        root: anchor(at, &[BPF_FS_MAGIC]).map(|(f, _)| f),
    })
}

/// Lot 359: the mount on top at `pin_root` in the mount table `table` is
/// the pin directory's lock: a bpffs whose root is that directory, on a
/// mount of the same bpffs at [`BPF_ROOT`] (or on another lock, stacked).
pub fn pin_locked(table: &str, pin_root: &str) -> bool {
    let lines: Vec<_> = table.lines().filter_map(mount_line).collect();
    let Some(name) = Path::new(pin_root).file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let want_root = format!("/{name}");
    let Some(top) = lines.iter().rev().find(|m| m.4 == pin_root) else {
        return false;
    };
    let mut cur = *top;
    for _ in 0..lines.len() {
        let (_, parent, dev, root, point, fstype) = cur;
        if fstype != "bpf" || root != want_root || point != pin_root {
            return false;
        }
        let Some(below) = lines.iter().rev().find(|m| m.0 == parent) else {
            return false;
        };
        if below.2 != dev || below.5 != "bpf" {
            return false;
        }
        if below.4 == BPF_ROOT {
            return below.3 == "/";
        }
        cur = *below;
    }
    false
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
/// and `resolve`. Where `openat2` cannot be called — a kernel without it
/// (`ENOSYS`), a seccomp filter that refuses it (`EPERM`) — or keeps
/// answering `EAGAIN` (a `..` raced by renames or mounts), the walk it would
/// do, one name at a time ([`openat_walked`]).
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
    // re-check 4 of #563 (the mini-hunt): a `..` beneath the root (a sysfs
    // link's) is `EAGAIN` while any rename or mount on the host raced the
    // walk — tried again, then walked one name at a time
    for _ in 0..4 {
        // SAFETY: `c` is NUL-terminated and `how` outlives the call, its
        // size given.
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
        match e.raw_os_error() {
            Some(libc::EAGAIN) => continue,
            Some(libc::ENOSYS | libc::EPERM) => return openat_walked(dir, rel, flags, resolve),
            _ => return Err(e),
        }
    }
    openat_walked(dir, rel, flags, resolve)
}

/// Lot 353 (fix round 5, the KVM suites of #563): `rel` opened beneath
/// `dir` as `openat2` would open it, where it cannot be called: a kernel
/// without it (`ENOSYS`), or a seccomp filter that refuses it (`EPERM`) —
/// the decision thread's (R14c-1: a filter cannot read the call's flags,
/// so it refuses every `openat2`), and the helper threads that thread
/// starts, which inherit it. On 92de8ac5 every path under a view failed
/// there with `EPERM`: the decision's process facts (uid, cgroup, `exe …
/// sha256`) were never read, no exemption by executable matched, and an
/// injection into an exempt process was not signed. An `EPERM` of the
/// open itself (an LSM's) refuses the walk's open again.
///
/// A walk that may cross mounts (`resolve` without `RESOLVE_NO_XDEV`: a
/// crossing's, on a helper thread with a deadline) is an `openat`. One that
/// may not goes one name at a time: each opened `O_PATH | O_NOFOLLOW` from
/// the one before and its mount read ([`mount_of`]: nothing asked of a FUSE
/// root reached, only the kernel's cached answer), refused (`EXDEV`) when it
/// is not `dir`'s — before any name is looked up in it; a symbolic link to
/// follow is followed from its directory when its target is names and
/// `..` alone (procfs's `self`; re-check 4 of #563, R4-2: sysfs's
/// `class/net/lo -> ../../devices/…`, a `..` going back to the directory
/// the walk came from, never above `dir`: `EXDEV`, as `RESOLVE_BENEATH`),
/// any other (a magic link, an absolute target) is `ELOOP`, which the
/// callers resolve from the root as they resolve a magic link; a `..` of
/// `rel` is `EXDEV`. The file reached is then opened with `flags`: a
/// directory through its own checked descriptor (`.`), any other through
/// [`reopen_checked`] (re-check 4 of #563, R4-1: on 8c1c5d12 by name
/// through `self/fd/N`, crossing a mount over `/proc/<pid>/fd`), or,
/// before `/proc` is anchored, by its name in its checked parent — the
/// file opened compared with the one the walk reached either way (mount
/// and inode: `EXDEV` on any difference).
fn openat_walked(dir: &File, rel: &Path, flags: i32, resolve: u64) -> io::Result<File> {
    if resolve & libc::RESOLVE_NO_XDEV == 0 {
        return openat(dir, rel, flags);
    }
    let err = io::Error::from_raw_os_error;
    // the steps left: a name, or a `..` of a link's target (`None`)
    let mut todo = std::collections::VecDeque::new();
    for c in rel.components() {
        match c {
            Component::Normal(n) => todo.push_back(Some(n.to_os_string())),
            Component::CurDir => {}
            _ => return Err(err(libc::EXDEV)),
        }
    }
    if todo.is_empty() {
        return openat(dir, Path::new("."), flags);
    }
    let mount = mount_of(dir)?.mount;
    // procfs is the one view with magic links (`socket:[N]` a name of none)
    let magic_links = magic_of(dir)? == PROC_SUPER_MAGIC;
    let is = |mode: u32, kind: libc::mode_t| mode & libc::S_IFMT == kind;
    let (path_only, nofollow) = (flags & libc::O_PATH != 0, flags & libc::O_NOFOLLOW != 0);
    // the checked directories below `dir` the walk is in, the last the
    // one it is in now: a `..` goes back to the one before
    let mut dirs: Vec<File> = Vec::new();
    let mut links = 0;
    while let Some(step) = todo.pop_front() {
        let Some(name) = step else {
            // never above `dir` (`RESOLVE_BENEATH`)
            dirs.pop().ok_or_else(|| err(libc::EXDEV))?;
            continue;
        };
        let at = dirs.last().unwrap_or(dir);
        let file = openat(at, Path::new(&name), libc::O_PATH | libc::O_NOFOLLOW)?;
        let id = mount_of(&file)?;
        if id.mount != mount {
            return Err(err(libc::EXDEV));
        }
        let last = todo.is_empty();
        if is(id.mode, libc::S_IFLNK) && !(last && path_only && nofollow) {
            // a link of names and `..` alone, followed from its directory;
            // a magic link (an absolute target, a `socket:[N]`), a ninth
            // link: the caller's
            links += 1;
            let steps = (links <= 8)
                .then(|| link_of(&file).ok())
                .flatten()
                .and_then(|t| link_steps(&t, magic_links))
                .ok_or_else(|| err(libc::ELOOP))?;
            for s in steps.into_iter().rev() {
                todo.push_front(s);
            }
            continue;
        }
        if !last {
            dirs.push(file);
            continue;
        }
        if path_only {
            if flags & libc::O_DIRECTORY != 0 && !is(id.mode, libc::S_IFDIR) {
                return Err(err(libc::ENOTDIR));
            }
            return Ok(file);
        }
        let flags = flags & !libc::O_NOFOLLOW;
        if is(id.mode, libc::S_IFDIR) {
            return reopen_dir(&file, id, flags);
        }
        if VIEWS.get().is_some_and(|v| v.proc.root.as_ref().is_ok()) {
            return reopen_checked(&file, flags);
        }
        let f = openat(at, Path::new(&name), flags | libc::O_NOFOLLOW)?;
        if !mount_of(&f)?.same_file(id) {
            return Err(err(libc::EXDEV));
        }
        return Ok(f);
    }
    // the walk ended on a `..`: the directory it went back to
    match dirs.pop() {
        Some(d) if path_only => Ok(d),
        Some(d) => {
            let id = mount_of(&d)?;
            reopen_dir(&d, id, flags & !libc::O_NOFOLLOW)
        }
        None => openat(dir, Path::new("."), flags),
    }
}

/// The checked directory `d` (`O_PATH`, `id` its [`mount_of`]) opened
/// with `flags` through its own descriptor (`.`: no name looked up, no
/// mount crossed), compared with it.
fn reopen_dir(d: &File, id: Ident, flags: i32) -> io::Result<File> {
    let f = openat(d, Path::new("."), flags)?;
    if !mount_of(&f)?.same_file(id) {
        return Err(io::Error::from_raw_os_error(libc::EXDEV));
    }
    Ok(f)
}

/// The steps of a symbolic link's target made of names and `..` alone —
/// relative, a `..` as `None`; with `magic_links` (procfs), none naming a
/// kernel object (`socket:[N]`, `mnt:[N]`: a magic link's) — or `None`.
fn link_steps(target: &Path, magic_links: bool) -> Option<Vec<Option<OsString>>> {
    let mut steps = Vec::new();
    for c in target.components() {
        match c {
            Component::Normal(n) if !(magic_links && n.as_bytes().contains(&b':')) => {
                steps.push(Some(n.to_os_string()))
            }
            Component::ParentDir => steps.push(None),
            Component::CurDir => {}
            _ => return None,
        }
    }
    (!steps.is_empty()).then_some(steps)
}

/// What [`mount_of`] tells of an open file, as the kernel has it cached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ident {
    /// Its mount's id (its device on a kernel before 5.8, which has none).
    mount: u64,
    /// Its inode's number.
    ino: u64,
    /// Its mode (type and permissions).
    mode: u32,
}

impl Ident {
    /// The same file on the same mount.
    fn same_file(self, other: Ident) -> bool {
        (self.mount, self.ino) == (other.mount, other.ino)
    }
}

/// The mount of the open `f`, its inode and its mode, as the kernel has
/// them cached: `statx` with `AT_STATX_DONT_SYNC` and no attribute asked —
/// a FUSE root a walk reached is never asked anything, so its daemon cannot
/// hold the caller.
fn mount_of(f: &File) -> io::Result<Ident> {
    // SAFETY: `statx` is plain old data, valid when zeroed.
    let mut sx: libc::statx = unsafe { std::mem::zeroed() };
    // SAFETY: the fd is live, the empty path NUL-terminated, `sx` writable.
    let rc = unsafe {
        libc::statx(
            f.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_STATX_DONT_SYNC | libc::AT_SYMLINK_NOFOLLOW,
            0,
            &mut sx,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let mount = if sx.stx_mask & libc::STATX_MNT_ID != 0 {
        sx.stx_mnt_id
    } else {
        (u64::from(sx.stx_dev_major) << 20) | u64::from(sx.stx_dev_minor)
    };
    Ok(Ident {
        mount,
        ino: sx.stx_ino,
        mode: u32::from(sx.stx_mode),
    })
}

thread_local! {
    /// [`with_fd_dir`]'s directory, kept for the thread whose tid it holds.
    static FD_DIR: std::cell::RefCell<Option<(libc::pid_t, File, u64)>> =
        const { std::cell::RefCell::new(None) };
}

/// Lot 353 (re-check 4 of #563, R4-1): `op` on this thread's own
/// descriptor directory and its mount — `thread-self/fd` opened `O_PATH`
/// beneath the `/proc` root the start anchored, every name of the way
/// checked (`openat2` with `RESOLVE_NO_XDEV`, or the walk one name at a
/// time where it cannot be called), never `/proc/<pid>/fd` looked up by
/// name, where a mount may lie. Kept for the thread (a mount laid over it
/// since is never walked), opened again in a forked child (another tid).
/// `Err` when `/proc` was not anchored.
fn with_fd_dir<T>(op: impl FnOnce(&File, u64) -> io::Result<T>) -> io::Result<T> {
    let open = || -> io::Result<(File, u64)> {
        let views = views();
        let proc = views
            .proc
            .root
            .as_ref()
            .map_err(|why| not_anchored(Path::new("/proc/thread-self/fd"), why))?;
        let d = openat2(
            proc,
            Path::new("thread-self/fd"),
            libc::O_PATH | libc::O_DIRECTORY,
            NO_CROSSING,
        )?;
        let m = mount_of(&d)?.mount;
        Ok((d, m))
    };
    // SAFETY: gettid has no preconditions.
    let tid = unsafe { libc::gettid() };
    let mut op = Some(op);
    let kept = FD_DIR.try_with(|c| {
        let mut c = c.try_borrow_mut().ok()?;
        if !matches!(&*c, Some((t, _, _)) if *t == tid) {
            *c = None;
            let (d, m) = open().ok()?;
            *c = Some((tid, d, m));
        }
        let (_, d, m) = c.as_ref()?;
        Some(op.take()?(d, *m))
    });
    match (kept, op) {
        (Ok(Some(r)), _) => r,
        // not kept (a thread ending, a reentrant call, an error): opened
        // for this call alone
        (_, Some(op)) => {
            let (d, m) = open()?;
            op(&d, m)
        }
        (_, None) => Err(io::Error::other("the descriptor directory: no answer")),
    }
}

/// Lot 353 (re-check 4 of #563, R4-1): the file `f` refers to (an `O_PATH`
/// descriptor too) opened again with `flags`, through its entry in this
/// thread's own descriptor directory ([`with_fd_dir`]): the entry itself
/// looked at first (`O_PATH | O_NOFOLLOW`: procfs's, nothing mounted on
/// it), the file opened compared with `f` — the same mount and inode, or
/// `EXDEV`. On 8c1c5d12 the walk's reopen went by name through
/// `self/fd/N`: a tmpfs over `/proc/<pid>/fd` gave the decision thread its
/// files for every fact, a FUSE there held it. The kernel has no reopen of
/// a descriptor without a name (`openat` takes no `AT_EMPTY_PATH`; a
/// directory is opened again through `.`, [`reopen_dir`]).
fn reopen_checked(f: &File, flags: i32) -> io::Result<File> {
    let want = mount_of(f)?;
    let name = PathBuf::from(f.as_raw_fd().to_string());
    with_fd_dir(|dir, mount| {
        let exdev = || io::Error::from_raw_os_error(libc::EXDEV);
        if mount_of(&openat(dir, &name, libc::O_PATH | libc::O_NOFOLLOW)?)?.mount != mount {
            return Err(exdev());
        }
        let got = openat(dir, &name, flags & !libc::O_NOFOLLOW)?;
        if !mount_of(&got)?.same_file(want) {
            return Err(exdev());
        }
        Ok(got)
    })
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
                        Kind::Bpf => BPF_ROOT,
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
/// an `O_PATH` descriptor too, which `fchmod` refuses — through its entry
/// in this thread's own descriptor directory beneath the `/proc` root the
/// start anchored (re-check 4 of #563: `thread-self/fd`, every name of the
/// way checked, and the entry itself procfs's: [`with_fd_dir`]), never
/// through the `/proc` mounted now. `Err` when that root is not anchored:
/// the caller's fallback.
pub fn chmod_fd(f: &File, mode: u32) -> io::Result<()> {
    let name = CString::new(f.as_raw_fd().to_string())
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    with_fd_dir(|dir, mount| {
        let entry = openat(
            dir,
            Path::new(&f.as_raw_fd().to_string()),
            libc::O_PATH | libc::O_NOFOLLOW,
        )?;
        if mount_of(&entry)?.mount != mount {
            return Err(io::Error::from_raw_os_error(libc::EXDEV));
        }
        // SAFETY: a live directory fd and a NUL-terminated name; the magic
        // link is followed to the file `f` refers to.
        if unsafe { libc::fchmodat(dir.as_raw_fd(), name.as_ptr(), mode as libc::mode_t, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    })
}

/// Lot 366: [`dir_names`], at most `max` names (the first the directory
/// gives).
pub fn dir_names_max(f: File, max: usize) -> io::Result<Vec<OsString>> {
    names_of(f, max)
}

/// Lot 353 (the review of #563, F2): the file `f` refers to (an `O_PATH`
/// descriptor too) opened again with `flags`, through its entry in this
/// thread's own descriptor directory, as [`chmod_fd`] — and (re-check 4)
/// compared with `f`: the same mount and inode, or `EXDEV`
/// ([`reopen_checked`]).
pub fn reopen_fd(f: &File, flags: i32) -> io::Result<File> {
    reopen_checked(f, flags)
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

/// Lot 366: a file's identity as the kernel has it cached, never asked of
/// its file system ([`cached`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cached {
    /// The device, in the kernel's encoding (`major << 20 | minor`).
    pub dev: u64,
    pub ino: u64,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    /// The mount the file was reached through (`/proc/<pid>/mountinfo`'s
    /// first field).
    pub mnt_id: u64,
}

impl Cached {
    fn kind(&self) -> u32 {
        self.mode & libc::S_IFMT
    }

    /// A directory.
    pub fn is_dir(&self) -> bool {
        self.kind() == libc::S_IFDIR
    }

    /// A regular file.
    pub fn is_file(&self) -> bool {
        self.kind() == libc::S_IFREG
    }

    /// A symbolic link.
    pub fn is_symlink(&self) -> bool {
        self.kind() == libc::S_IFLNK
    }

    /// Root's, and writable by no one else (no group or other write bit).
    pub fn root_only(&self) -> bool {
        self.uid == 0 && self.mode & 0o022 == 0
    }
}

/// Lot 366: the identity of the open `f` (an `O_PATH` descriptor too) as
/// the kernel has it cached — `statx` with `AT_STATX_DONT_SYNC`, as
/// [`stat_cached`]: a FUSE file system's daemon (or a network file
/// system's server) is never asked, so it cannot hold the caller. A FUSE
/// file system that refuses the caller (mounted by a user without
/// `allow_other`) answers `EACCES` at once.
pub fn cached(f: &File) -> io::Result<Cached> {
    // SAFETY: `statx` is plain old data, valid when zeroed.
    let mut sx: libc::statx = unsafe { std::mem::zeroed() };
    // SAFETY: the fd is live, the empty path NUL-terminated, `sx` writable.
    let rc = unsafe {
        libc::statx(
            f.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_STATX_DONT_SYNC,
            libc::STATX_TYPE
                | libc::STATX_MODE
                | libc::STATX_NLINK
                | libc::STATX_UID
                | libc::STATX_INO
                | libc::STATX_MNT_ID,
            &mut sx,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Cached {
        dev: (u64::from(sx.stx_dev_major) << 20) | u64::from(sx.stx_dev_minor),
        ino: sx.stx_ino,
        mode: u32::from(sx.stx_mode),
        nlink: sx.stx_nlink,
        uid: sx.stx_uid,
        mnt_id: if sx.stx_mask & libc::STATX_MNT_ID != 0 {
            sx.stx_mnt_id
        } else {
            0
        },
    })
}

/// Lot 366: the file a link of a process names — `/proc/<pid>/exe`,
/// `root`, `cwd`, `fd/<n>`: the last name of `path` — opened `O_PATH`, and
/// its identity from the kernel's cache ([`cached`]). The link's directory
/// is opened beneath its view (crossing nothing, [`open`]); the link alone
/// is followed from there: nothing is looked up on the file system the
/// file is on, nothing opened, nothing asked of a FUSE daemon (a
/// `metadata` of the link asked the file's file system, and its caller
/// waited for the answer).
pub fn link_target(path: &Path) -> io::Result<(File, Cached)> {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    };
    // the directory beneath its view, no magic link on the way (`ELOOP`):
    // only the last name is followed
    let dir = match view_of(dir) {
        Some((view, rel)) => {
            let root = view.root.as_ref().map_err(|why| not_anchored(dir, why))?;
            openat2(root, &rel, libc::O_PATH | libc::O_DIRECTORY, NO_CROSSING)?
        }
        None => open_path(dir, libc::O_PATH | libc::O_DIRECTORY)?,
    };
    let f = openat(&dir, Path::new(name), libc::O_PATH)?;
    let c = cached(&f)?;
    Ok((f, c))
}

/// Lot 366: what [`walk_judged`] reached: the file (`O_PATH`), its cached
/// identity, its path from the walk's start, and whether it, every
/// directory on that path and the start are the start's owner's (root's,
/// from `/`) and writable by no one else.
#[derive(Debug)]
pub struct Walked {
    pub file: File,
    pub cached: Cached,
    pub path: PathBuf,
    pub owner_only: bool,
}

/// How many symbolic links one [`walk_judged`] follows at most (the
/// kernel's `MAXSYMLINKS`).
const LINKS_MAX: usize = 40;

/// Lot 366: `rel` reached from the directory `root` (at `root_path` in the
/// agent's view), one name at a time, and judged: `root` and every
/// directory reached — before any name is looked up in it — and the file
/// reached are `judge`d by their cached identity ([`cached`]: device and
/// mount), and a name is looked up only in a directory `judge` accepts (a
/// file system the agent trusts to answer: not a user's FUSE, not a network
/// one). Each name is opened `O_PATH | O_NOFOLLOW` with `openat2`
/// (`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`): a
/// mount below is crossed only to be judged there, nothing opened, nothing
/// asked of it. A symbolic link is refused unless `follow`: then its target
/// (read from the link, on a file system judged) is walked the same way —
/// an absolute one from the agent's `/`, as the kernel resolves it, at most
/// [`LINKS_MAX`] links, a `..` never above where the walk stands on. A `..`
/// or `.` of `rel` itself is `EINVAL`. A file system `judge` refuses is
/// `PermissionDenied`: not verified. `rel` may start with `/` (taken from
/// `root`).
pub fn walk_judged(
    root: &File,
    root_path: &Path,
    rel: &Path,
    follow: bool,
    judge: &mut dyn FnMut(&Cached) -> bool,
) -> io::Result<Walked> {
    let refused = |c: &Cached| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "on a file system the agent does not ask (device {}:{}, mount {}): not verified",
                c.dev >> 20,
                c.dev & 0xfffff,
                c.mnt_id
            ),
        )
    };
    let start = cached(root)?;
    if !judge(&start) {
        return Err(refused(&start));
    }
    let owners = |c: &Cached| c.uid == start.uid && c.mode & 0o022 == 0;
    // the steps left; a `None` is a `..` of a link's target
    let mut todo: std::collections::VecDeque<Option<OsString>> = std::collections::VecDeque::new();
    for c in rel.components() {
        match c {
            Component::Normal(n) => todo.push_back(Some(n.to_os_string())),
            Component::RootDir => {}
            _ => return Err(io::Error::from_raw_os_error(libc::EINVAL)),
        }
    }
    // where the walk stands on (`root`, or `/` after an absolute link), and
    // the directories walked from there: their descriptor, identity, name,
    // and whether they and every one above are the owner's only
    let mut base: (Option<File>, Cached, PathBuf) = (None, start, root_path.to_path_buf());
    let mut stack: Vec<(File, Cached, OsString, bool)> = Vec::new();
    let mut links = 0;
    while let Some(step) = todo.pop_front() {
        let Some(name) = step else {
            stack.pop();
            continue;
        };
        let (dir, here, ro) = match stack.last() {
            Some((f, c, _, ro)) => (f, *c, *ro),
            None => (base.0.as_ref().unwrap_or(root), base.1, owners(&base.1)),
        };
        if !here.is_dir() {
            return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
        }
        let f = openat2(
            dir,
            Path::new(&name),
            libc::O_PATH | libc::O_NOFOLLOW,
            libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS,
        )?;
        let c = cached(&f)?;
        if !judge(&c) {
            return Err(refused(&c));
        }
        if !c.is_symlink() {
            stack.push((f, c, name, ro && owners(&c)));
            continue;
        }
        links += 1;
        if !follow || links > LINKS_MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a symbolic link on the way: not followed",
            ));
        }
        let target = link_of(&f)?;
        if target.is_absolute() {
            let slash = open_path(Path::new("/"), libc::O_PATH | libc::O_DIRECTORY)?;
            let c = cached(&slash)?;
            if !judge(&c) {
                return Err(refused(&c));
            }
            base = (Some(slash), c, PathBuf::from("/"));
            stack.clear();
        }
        for part in target.components().rev() {
            match part {
                Component::Normal(n) => todo.push_front(Some(n.to_os_string())),
                Component::ParentDir => todo.push_front(None),
                _ => {}
            }
        }
    }
    let path: PathBuf = std::iter::once(base.2.as_os_str())
        .chain(stack.iter().map(|(_, _, n, _)| n.as_os_str()))
        .collect();
    Ok(match stack.pop() {
        Some((file, cached, _, owner_only)) => Walked {
            file,
            cached,
            path,
            owner_only,
        },
        None => Walked {
            file: match base.0 {
                Some(f) => f,
                None => root.try_clone()?,
            },
            cached: base.1,
            path,
            owner_only: owners(&base.1),
        },
    })
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

    /// Lot 353 (fix round 5, the KVM suites of #563; named): a path below
    /// `/sys/fs/bpf` is beneath the bpffs's own anchored root — the pin
    /// directories' parent opens there, never a mount crossed below `/sys`
    /// (`EXDEV`). On 92de8ac5 it was the `/sys` view's: the tracker's pin
    /// directories beside the pin root were neither made nor removed by
    /// their parent (a planted one was left, the debug build's plant never
    /// made). Where no bpffs is mounted at `/sys/fs/bpf` (WSL2's kernel), it
    /// is no view.
    /// Named test (lot 359): the pin directory is a view of its own only
    /// when its lock is mounted there — a self-bind of the bpffs at
    /// `/sys/fs/bpf` (one stacked on another too); a tmpfs, another bpffs, a
    /// bind of another directory, a lock under a bpffs elsewhere are not.
    #[test]
    fn the_pin_directory_is_its_own_view_only_under_its_lock() {
        const ROOT: &str = "/sys/fs/bpf/northnarrow";
        let base = "1 0 252:1 / / rw - ext4 /dev/vda1 rw\n\
                    20 1 0:20 / /sys rw shared:7 - sysfs sysfs rw\n\
                    30 20 0:30 / /sys/fs/bpf rw shared:9 - bpf bpf rw,mode=700\n";
        assert!(!pin_locked(base, ROOT), "no lock");
        let lock = format!("{base}90 30 0:30 /northnarrow {ROOT} rw unbindable - bpf bpf rw\n");
        assert!(pin_locked(&lock, ROOT));
        let twice = format!("{lock}91 90 0:30 /northnarrow {ROOT} rw unbindable - bpf bpf rw\n");
        assert!(pin_locked(&twice, ROOT), "a lock stacked on the lock");
        for (what, line) in [
            (
                "a tmpfs over it",
                format!("90 30 0:91 / {ROOT} rw - tmpfs tmpfs rw\n"),
            ),
            (
                "another bpffs",
                format!("90 30 0:92 / {ROOT} rw - bpf bpf rw\n"),
            ),
            (
                "another directory of the bpffs",
                format!("90 30 0:30 /other {ROOT} rw - bpf bpf rw\n"),
            ),
            (
                "a bpffs root over it",
                format!("90 30 0:30 / {ROOT} rw - bpf bpf rw\n"),
            ),
        ] {
            assert!(!pin_locked(&format!("{base}{line}"), ROOT), "{what}");
        }
        let over = format!("{lock}91 90 0:93 / {ROOT} rw - tmpfs tmpfs rw\n");
        assert!(!pin_locked(&over, ROOT), "a tmpfs over the lock");
        // a line of another type naming the lock's root, on the bpffs's device
        let typed = format!("{base}90 30 0:30 /northnarrow {ROOT} rw - tmpfs tmpfs rw\n");
        assert!(!pin_locked(&typed, ROOT), "not a bpffs");
        // the "lock" on a bind of a directory of the bpffs at /sys/fs/bpf
        let sub = "1 0 252:1 / / rw - ext4 /dev/vda1 rw\n\
                   30 1 0:30 /sub /sys/fs/bpf rw - bpf bpf rw\n\
                   90 30 0:30 /northnarrow /sys/fs/bpf/northnarrow rw - bpf bpf rw\n";
        assert!(!pin_locked(sub, ROOT), "on a part of the bpffs");
        let elsewhere = "1 0 252:1 / / rw - ext4 /dev/vda1 rw\n\
                         30 1 0:30 / /mnt/b rw - bpf bpf rw\n\
                         90 30 0:30 /northnarrow /sys/fs/bpf/northnarrow rw - bpf bpf rw\n";
        assert!(
            !pin_locked(elsewhere, ROOT),
            "under a bpffs that is not at /sys/fs/bpf"
        );
    }

    #[test]
    fn a_pin_directory_s_parent_is_beneath_the_bpffs_root() {
        let c = CString::new(BPF_ROOT).unwrap();
        // SAFETY: `statfs` is plain old data; the path is NUL-terminated.
        let mut st: libc::statfs = unsafe { std::mem::zeroed() };
        let bpffs =
            unsafe { libc::statfs(c.as_ptr(), &mut st) } == 0 && st.f_type as u64 == BPF_FS_MAGIC;
        let below = format!("{BPF_ROOT}/northnarrow-cgroup-join-v2_3");
        let Some((view, rel)) = view_of(Path::new(&below)) else {
            panic!("{below}: under no view");
        };
        if !bpffs {
            assert_eq!(view.kind(), Kind::Sys, "no bpffs here: the /sys view's");
            eprintln!("skipped: no bpffs mounted at {BPF_ROOT} here");
            return;
        }
        assert_eq!(
            (view.kind(), rel.as_path(), view.refused()),
            (Kind::Bpf, Path::new("northnarrow-cgroup-join-v2_3"), None)
        );
        // a non-root runner may be refused the root's metadata (mode 0700):
        // the same refusal the open below accepts, never a crossing
        match metadata(BPF_ROOT) {
            Ok(m) => assert!(m.is_dir()),
            Err(e) => assert_eq!(e.raw_os_error(), Some(libc::EACCES), "{e}"),
        }
        // the parent of a pin directory: the bpffs root, opened beneath its
        // view — refused by its mode to another user, never a crossing
        match open(BPF_ROOT, libc::O_RDONLY | libc::O_DIRECTORY) {
            Ok(_) => {}
            Err(e) => assert_eq!(e.raw_os_error(), Some(libc::EACCES), "{e}"),
        }
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            let d = format!("{BPF_ROOT}/nn-test-353-{}", std::process::id());
            create_dir(&d).unwrap();
            assert!(is_dir(&d));
            remove_dir(&d).unwrap();
            assert!(!exists(&d).unwrap());
        }
    }

    /// Lot 353 (fix round 5, the KVM suites of #563; named): where
    /// `openat2` cannot be called (the decision thread's filter refuses it:
    /// `EPERM`), the walk one name at a time opens what `openat2` would — a
    /// file, a directory, a link of names alone followed (`self`), a link
    /// itself with `O_NOFOLLOW` — and refuses what it refuses: a mount
    /// below the root (`EXDEV`, before any name is looked up in it; here a
    /// tmpfs over `/proc/sys/kernel`), a magic link to follow (`ELOOP`), a
    /// `..` (`EXDEV`). And a tmpfs over `/sys/fs/bpf` at the start is not
    /// taken for the bpffs. In a user and mount namespace of a child
    /// (skipped where the host refuses one).
    #[test]
    fn a_walk_without_openat2_crosses_no_mount_and_follows_no_magic_link() {
        let _ = views();
        // SAFETY: fork; the child mounts in namespaces of its own and _exits.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork");
        if pid == 0 {
            let rc = walked_child();
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

    /// The child of
    /// [`a_walk_without_openat2_crosses_no_mount_and_follows_no_magic_link`]:
    /// 0 when it holds, 99 when the host refuses the namespaces.
    fn walked_child() -> i32 {
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
        let views = Views::open();
        let Ok(root) = views.proc.root.as_ref() else {
            return 98;
        };
        let walk = |rel: &str, flags: i32| {
            openat_walked(root, Path::new(rel), flags | libc::O_CLOEXEC, NO_CROSSING)
        };
        let errno = |r: io::Result<File>| r.err().and_then(|e| e.raw_os_error());
        let read = |r: io::Result<File>| r.ok().and_then(|f| read_file_bounded(&f, 1 << 16).ok());
        // a file, as by path; a link of names alone followed
        if read(walk("sys/kernel/osrelease", READ_FLAGS))
            != std::fs::read("/proc/sys/kernel/osrelease").ok()
        {
            return 10;
        }
        if !read(walk("self/status", READ_FLAGS))
            .is_some_and(|b| String::from_utf8_lossy(&b).contains("\nPid:\t"))
        {
            return 11;
        }
        // a directory; a file is not one
        if walk("sys/kernel", libc::O_PATH | libc::O_DIRECTORY).is_err()
            || errno(walk(
                "sys/kernel/osrelease",
                libc::O_PATH | libc::O_DIRECTORY,
            )) != Some(libc::ENOTDIR)
        {
            return 12;
        }
        // a magic link: the link itself with O_NOFOLLOW, never followed
        let Ok(exe) = std::fs::read_link("/proc/self/exe") else {
            return 13;
        };
        if walk("self/exe", libc::O_PATH | libc::O_NOFOLLOW)
            .and_then(|f| link_of(&f))
            .ok()
            != Some(exe)
            || errno(walk("self/exe", READ_FLAGS)) != Some(libc::ELOOP)
        {
            return 14;
        }
        // a magic link whose target is no path (`pipe:[N]`): never taken
        // for names
        let mut fds = [0; 2];
        // SAFETY: `fds` is writable for two descriptors.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0
            || errno(walk(&format!("self/fd/{}", fds[0]), READ_FLAGS)) != Some(libc::ELOOP)
        {
            return 15;
        }
        // a `..`: not beneath
        if errno(walk("sys/../self/status", READ_FLAGS)) != Some(libc::EXDEV) {
            return 19;
        }
        // a mount below the root: refused at its root
        if tmpfs(c"/proc/sys/kernel") != 0 {
            return 99;
        }
        if std::fs::read("/proc/sys/kernel/osrelease").is_ok() {
            return 16; // the cover did not take
        }
        if errno(walk("sys/kernel/osrelease", READ_FLAGS)) != Some(libc::EXDEV)
            || errno(walk("sys/kernel", libc::O_PATH)) != Some(libc::EXDEV)
        {
            return 17;
        }
        // a tmpfs over /sys/fs/bpf at the start: refused, never the bpffs
        if tmpfs(c"/sys/fs/bpf") == 0
            && !bpf_view().is_some_and(|v| v.refused().is_some_and(|w| w.contains("tmpfs")))
        {
            return 18;
        }
        0
    }

    /// `(dev, ino)` of what an open reached, or its errno.
    fn reached(r: io::Result<File>) -> Result<(u64, u64), Option<i32>> {
        use std::os::unix::fs::MetadataExt;
        r.and_then(|f| f.metadata())
            .map(|m| (m.dev(), m.ino()))
            .map_err(|e| e.raw_os_error())
    }

    /// Lot 353 (re-check 4 of #563, R4-2; named): a symbolic link whose
    /// target climbs with `..` (sysfs's `class/net/lo -> ../../devices/…`) is
    /// followed by the walk one name at a time from the link's directory, as
    /// `openat2` beneath the root follows it — the same file reached, the
    /// same refusal of a climb above the root (`EXDEV`). On 8c1c5d12 it was
    /// `ELOOP`, which the callers opened again with a plain `openat`.
    #[test]
    fn a_link_s_dotdot_is_walked_from_its_directory_as_openat2_walks_it() {
        let _ = views();
        let dir = tempfile::TempDir::new().unwrap();
        let d = dir.path();
        std::fs::create_dir_all(d.join("a")).unwrap();
        std::fs::create_dir_all(d.join("b")).unwrap();
        std::fs::write(d.join("b/f"), b"ok").unwrap();
        // a name with a `:` (sysfs's `pci0000:00`): a name, off procfs
        std::fs::create_dir_all(d.join("b:c")).unwrap();
        std::fs::write(d.join("b:c/f"), b"ok").unwrap();
        for (name, target) in [
            ("a/colon", "../b:c"),
            ("a/l", "../b"),
            ("a/deep", "../a/../b/f"),
            ("a/up", "../../x"),
            ("a/m", ".."),
            ("a/n", "l/../l/f"),
        ] {
            std::os::unix::fs::symlink(target, d.join(name)).unwrap();
        }
        let root = open_path(d, libc::O_PATH | libc::O_DIRECTORY).unwrap();
        let dirs = libc::O_PATH | libc::O_DIRECTORY;
        for (rel, flags) in [
            ("a/colon/f", READ_FLAGS),
            ("a/l/f", READ_FLAGS),
            ("a/deep", READ_FLAGS),
            ("a/n", READ_FLAGS),
            ("a/m/b/f", READ_FLAGS),
            ("a/l", dirs),
            ("a/m", dirs),
            ("a/m", libc::O_RDONLY | libc::O_DIRECTORY),
            ("a/up", libc::O_PATH),
            ("a/up/f", READ_FLAGS),
            ("a/m/..", dirs),
        ] {
            let walked = reached(openat_walked(
                &root,
                Path::new(rel),
                flags | libc::O_CLOEXEC,
                NO_CROSSING,
            ));
            let native = reached(openat2(&root, Path::new(rel), flags, NO_CROSSING));
            assert_eq!(
                walked, native,
                "{rel} (flags {flags:#x}): the walk and openat2"
            );
        }
        // what they reached, named
        assert_eq!(
            reached(openat_walked(
                &root,
                Path::new("a/deep"),
                READ_FLAGS,
                NO_CROSSING
            )),
            reached(std::fs::File::open(d.join("b/f")))
        );
        assert_eq!(
            reached(openat_walked(
                &root,
                Path::new("a/up/f"),
                READ_FLAGS,
                NO_CROSSING
            )),
            Err(Some(libc::EXDEV))
        );
    }

    /// Lot 353 (re-check 4 of #563, the mini-hunt; named): a sysfs path
    /// through a link that climbs with `..` is read while renames race it —
    /// `openat2` beneath the root answers `EAGAIN` when any rename or mount
    /// on the host raced a `..`: on 8c1c5d12 that error was the read's.
    #[test]
    fn a_dotdot_raced_by_renames_is_read_all_the_same() {
        const PATH: &str = "/sys/class/net/lo/address";
        let Ok(want) = std::fs::read(PATH) else {
            eprintln!("skipped: no {PATH} here");
            return;
        };
        let dir = tempfile::TempDir::new().unwrap();
        let (a, b) = (dir.path().join("a"), dir.path().join("b"));
        std::fs::write(&a, b"x").unwrap();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hammer = {
            let stop = std::sync::Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let _ = std::fs::rename(&a, &b);
                    let _ = std::fs::rename(&b, &a);
                }
            })
        };
        let mut failed = None;
        for _ in 0..20_000 {
            match read(PATH, 4096) {
                Ok(got) if got == want => {}
                other => {
                    failed = Some(format!("{other:?}"));
                    break;
                }
            }
        }
        stop.store(true, Ordering::Relaxed);
        hammer.join().unwrap();
        assert_eq!(failed, None, "a read of {PATH} raced by renames");
    }

    /// Lot 353 (re-check 4 of #563, R4-1): a descriptor is opened again
    /// through this thread's own descriptor directory — the same file (an
    /// `O_PATH` one too), on another thread through that thread's, and in a
    /// forked child through the child's (the directory a thread keeps is its
    /// tid's: the parent's would name the parent's descriptors).
    #[test]
    fn a_descriptor_is_reopened_through_this_thread_s_own_directory() {
        let _ = views();
        let dir = tempfile::TempDir::new().unwrap();
        let p = dir.path().join("f");
        std::fs::write(&p, b"ok").unwrap();
        let f = open_path(&p, libc::O_PATH).unwrap();
        let same = |r: io::Result<File>| reached(r) == reached(File::open(&p));
        assert!(same(reopen_fd(&f, libc::O_RDONLY)), "this thread");
        assert!(same(reopen_fd(&f, libc::O_RDONLY)), "this thread, kept");
        let g = f.try_clone().unwrap();
        let q = p.clone();
        let other = std::thread::spawn(move || {
            reached(reopen_fd(&g, libc::O_RDONLY)) == reached(File::open(&q))
        });
        assert!(other.join().unwrap(), "another thread");
        // SAFETY: fork; the child reopens and _exits.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork");
        if pid == 0 {
            // a descriptor the parent does not hold, at a number it has free
            let mine: Vec<File> = (0..8)
                .filter_map(|_| open_path(&p, libc::O_PATH).ok())
                .collect();
            let ok = mine.iter().all(|m| same(reopen_fd(m, libc::O_RDONLY)));
            // SAFETY: _exit in the child.
            unsafe { libc::_exit(if ok { 0 } else { 1 }) };
        }
        let mut status = 0;
        // SAFETY: waiting for our own child.
        unsafe { libc::waitpid(pid, &mut status, 0) };
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "the forked child: {status:#x}"
        );
    }

    /// The decision thread's filter in a test's child: `openat2` refused
    /// with `EPERM`, every other call allowed. `false` when refused.
    fn refuse_openat2() -> bool {
        let mut prog = [
            libc::sock_filter {
                code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                jt: 0,
                jf: 0,
                k: 0,
            },
            libc::sock_filter {
                code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                jt: 0,
                jf: 1,
                k: libc::SYS_openat2 as u32,
            },
            libc::sock_filter {
                code: (libc::BPF_RET | libc::BPF_K) as u16,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
            },
            libc::sock_filter {
                code: (libc::BPF_RET | libc::BPF_K) as u16,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ALLOW,
            },
        ];
        let fprog = libc::sock_fprog {
            len: prog.len() as u16,
            filter: prog.as_mut_ptr(),
        };
        // SAFETY: a filter program that outlives the call, on this thread.
        unsafe {
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
                && libc::prctl(
                    libc::PR_SET_SECCOMP,
                    libc::SECCOMP_MODE_FILTER,
                    &fprog as *const libc::sock_fprog as libc::c_ulong,
                    0,
                    0,
                ) == 0
        }
    }

    /// Lot 353 (re-check 4 of #563, R4-2; named): without `openat2` (the
    /// decision thread's filter), a sysfs path through a link that climbs
    /// with `..` is read beneath the `/sys` root as by path, and a mount laid
    /// on the link's target (a tmpfs over `/sys/devices/virtual/net/lo`) is
    /// refused at its root, never read: on 8c1c5d12 the walk's `ELOOP` sent
    /// it to a plain `openat`, which crossed the tmpfs and read its file. In
    /// a user and mount namespace of a child (skipped where the host refuses
    /// one; a failure under CI).
    #[test]
    fn a_sysfs_link_with_a_dotdot_crosses_no_mount_without_openat2() {
        let _ = views();
        // SAFETY: fork; the child mounts in namespaces of its own and _exits.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork");
        if pid == 0 {
            let rc = dotdot_child();
            // SAFETY: _exit in the child.
            unsafe { libc::_exit(rc) };
        }
        let mut status = 0;
        // SAFETY: waiting for our own child.
        unsafe { libc::waitpid(pid, &mut status, 0) };
        assert!(libc::WIFEXITED(status), "child status {status:#x}");
        match libc::WEXITSTATUS(status) {
            0 => {}
            99 => assert!(
                std::env::var_os("CI").is_none(),
                "under CI this test must run, never skip"
            ),
            rc => panic!("the child failed with {rc}"),
        }
    }

    /// The child of
    /// [`a_sysfs_link_with_a_dotdot_crosses_no_mount_without_openat2`]: 0
    /// when it holds, 99 when the host refuses the namespaces.
    fn dotdot_child() -> i32 {
        const PATH: &str = "/sys/class/net/lo/address";
        const FAKE: &[u8] = b"FAKE-FACT\n";
        let Ok(want) = std::fs::read(PATH) else {
            return 99; // no loopback in sysfs here
        };
        if !std::fs::read_link("/sys/class/net/lo")
            .is_ok_and(|t| t.components().any(|c| c == Component::ParentDir))
        {
            return 99;
        }
        // SAFETY: getuid/getgid have no preconditions.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
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
        // uid 0 mapped to the caller's (the cover's file written as it)
        let w = |p: &str, s: String| std::fs::write(p, s).is_ok();
        if refused
            || !(w("/proc/self/setgroups", "deny".into())
                && w("/proc/self/uid_map", format!("0 {uid} 1"))
                && w("/proc/self/gid_map", format!("0 {gid} 1")))
        {
            return 99;
        }
        let views = Views::open();
        let Ok(sys) = views.sys.root.as_ref() else {
            return 98;
        };
        if !refuse_openat2() {
            return 97;
        }
        let text = |p: &str| {
            with_file_in(&views, Path::new(p), READ_FLAGS, |f| {
                read_file_bounded(&f, 1 << 12)
            })
            .expect("a view's path")
        };
        // under the filter: read beneath the root as by path, the walk
        // itself following the link
        if text(PATH).ok() != Some(want) {
            return 10;
        }
        if reached(openat_walked(
            sys,
            Path::new("class/net/lo/address"),
            READ_FLAGS,
            NO_CROSSING,
        ))
        .is_err()
        {
            return 11;
        }
        // a tmpfs over the link's target, holding a file of the name read
        // SAFETY: NUL-terminated strings, no data.
        let covered = unsafe {
            libc::mount(
                c"none".as_ptr(),
                c"/sys/devices/virtual/net/lo".as_ptr(),
                c"tmpfs".as_ptr(),
                0,
                std::ptr::null(),
            )
        } == 0
            && std::fs::write("/sys/devices/virtual/net/lo/address", FAKE).is_ok()
            && std::fs::read(PATH).is_ok_and(|b| b == FAKE);
        if !covered {
            eprintln!(
                "missing here: a tmpfs over /sys/devices/virtual/net/lo ({})",
                io::Error::last_os_error()
            );
            return 99;
        }
        if errno_of(openat_walked(
            sys,
            Path::new("class/net/lo/address"),
            READ_FLAGS,
            NO_CROSSING,
        )) != Some(libc::EXDEV)
        {
            return 12;
        }
        match text(PATH) {
            Ok(b) if b == FAKE => 13,
            Err(e)
                if e.kind() == io::ErrorKind::PermissionDenied
                    && e.to_string().contains("not the kernel's") =>
            {
                0
            }
            _ => 14,
        }
    }

    /// The errno of a failed open.
    fn errno_of(r: io::Result<File>) -> Option<i32> {
        r.err().and_then(|e| e.raw_os_error())
    }

    /// Lot 366: a walk asks a file system nothing once `judge` refuses it:
    /// the directory refused is judged before any name is looked up in it
    /// (the walk stops there, `PermissionDenied`: not verified), and so is
    /// the file reached. No symbolic link is followed unless asked; one
    /// followed is judged where it leads; a `..` of the caller's is
    /// refused. What the walk reached is the kernel's own identity of it.
    #[test]
    fn a_walk_judged_asks_nothing_of_a_file_system_it_refuses() {
        use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        std::fs::create_dir_all(r.join("a/b")).unwrap();
        std::fs::write(r.join("a/b/f"), b"x").unwrap();
        symlink("b", r.join("a/l")).unwrap();
        for d in [r.to_path_buf(), r.join("a"), r.join("a/b")] {
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        // as the owner's tree has them, whatever the test's umask
        std::fs::set_permissions(r.join("a/b/f"), std::fs::Permissions::from_mode(0o644)).unwrap();
        let root = File::open(r).unwrap();
        let ino = |p: &Path| std::fs::symlink_metadata(p).unwrap().ino();
        let (a, b, f) = (
            ino(&r.join("a")),
            ino(&r.join("a/b")),
            ino(&r.join("a/b/f")),
        );
        // every file system accepted: the file, the kernel's identity
        let mut asked = Vec::new();
        let w = walk_judged(&root, r, Path::new("a/b/f"), false, &mut |c| {
            asked.push(c.ino);
            true
        })
        .unwrap();
        let m = std::fs::metadata(r.join("a/b/f")).unwrap();
        assert_eq!((w.cached.ino, w.cached.is_file()), (m.ino(), true));
        assert_eq!(w.path, r.join("a/b/f"));
        assert!(w.owner_only, "the owner's tree, 0755");
        assert_eq!(
            asked,
            vec![ino(r), a, b, f],
            "each directory, then the file"
        );
        // `a` refused: nothing looked up in it — `b` never reached
        let mut asked = Vec::new();
        let e = walk_judged(&root, r, Path::new("a/b/f"), false, &mut |c| {
            asked.push(c.ino);
            c.ino != a
        })
        .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(asked, vec![ino(r), a]);
        // the start refused: nothing at all
        let e = walk_judged(&root, r, Path::new("a"), false, &mut |_| false).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        // the file itself refused
        let e = walk_judged(&root, r, Path::new("a/b/f"), false, &mut |c| c.ino != f).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        // a link on the way: refused, unless followed — and judged there
        let e = walk_judged(&root, r, Path::new("a/l/f"), false, &mut |_| true).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        let w = walk_judged(&root, r, Path::new("a/l/f"), true, &mut |_| true).unwrap();
        assert_eq!((w.cached.ino, w.path.clone()), (f, r.join("a/b/f")));
        let e = walk_judged(&root, r, Path::new("a/l/f"), true, &mut |c| c.ino != b).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        // a link's `..` goes back up, never above the walk's start; an
        // absolute one is walked from `/`, as the kernel walks it
        symlink("../a/b", r.join("a/up")).unwrap();
        let w = walk_judged(&root, r, Path::new("a/up/f"), true, &mut |_| true).unwrap();
        assert_eq!((w.cached.ino, w.path.clone()), (f, r.join("a/b/f")));
        symlink("../../../../../../../..", r.join("a/top")).unwrap();
        let w = walk_judged(&root, r, Path::new("a/top"), true, &mut |_| true).unwrap();
        assert_eq!((w.cached.ino, w.path.clone()), (ino(r), r.to_path_buf()));
        symlink(r.join("a/b"), r.join("a/abs")).unwrap();
        let w = walk_judged(&root, r, Path::new("a/abs/f"), true, &mut |_| true).unwrap();
        assert_eq!((w.cached.ino, w.path.clone()), (f, r.join("a/b/f")));
        // a `..` of the caller's
        let e = walk_judged(&root, r, Path::new("a/../a"), false, &mut |_| true).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::EINVAL));
        // a directory another may write: not the owner's only
        std::fs::set_permissions(r.join("a"), std::fs::Permissions::from_mode(0o775)).unwrap();
        let w = walk_judged(&root, r, Path::new("a/b/f"), false, &mut |_| true).unwrap();
        assert!(!w.owner_only);
    }

    /// Lot 366: a process's link is followed alone, and its target's
    /// identity is the kernel's cached one: this process's image, by
    /// `/proc/self/exe`, is the test binary (device, inode, a regular
    /// file); its root, `/`. A link that is not the path's last name is not
    /// followed (`/proc/self/root/etc`: nothing looked up beyond the link).
    #[test]
    fn a_process_link_is_followed_alone_and_read_from_the_cache() {
        use std::os::unix::fs::MetadataExt;
        let (_, c) = link_target(Path::new("/proc/self/exe")).unwrap();
        let m = std::fs::metadata(std::env::current_exe().unwrap()).unwrap();
        let dev = (u64::from(libc::major(m.dev())) << 20) | u64::from(libc::minor(m.dev()));
        assert_eq!((c.dev, c.ino, c.is_file()), (dev, m.ino(), true));
        assert!(c.mnt_id != 0, "the mount it was reached through");
        let (_, c) = link_target(Path::new("/proc/self/root")).unwrap();
        let m = std::fs::metadata("/").unwrap();
        assert_eq!((c.ino, c.is_dir()), (m.ino(), true));
        assert!(link_target(Path::new("/proc/self/root/etc")).is_err());
        assert!(link_target(Path::new("/proc/self/exe/x")).is_err());
    }
}
