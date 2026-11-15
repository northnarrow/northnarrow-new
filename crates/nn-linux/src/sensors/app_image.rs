//! Lot 355: a program of an AppImage is judged by its image, not by the
//! mount point under `/tmp` its runtime serves it at.
//!
//! An AppImage (type 2) is one file: a runtime and a squashfs image. Run,
//! the runtime forks a FUSE daemon that serves the image read-only at
//! `$TMPDIR/.mount_XXXXXX` (`/tmp` by default), then executes the image's
//! `AppRun` from there, which executes the program. Every exec of a desktop
//! user's AppImage was an exec from `/tmp`: R001 High, and CHAIN-002 or
//! CHAIN-005 Critical as soon as the program (or its zygote's child)
//! connected — the same program run from the home drew none of them. The
//! exec pump marks such an exec [`exe_flags::USER_IMAGE`] when the kernel's
//! state shows the program is the image's:
//!
//! - **tying** — the process executes a file on a FUSE filesystem in a
//!   staging directory, by the file the LSM program identified (dev, ino,
//!   the path from its dentry), in PID 1's mount namespace and root;
//!   - every mount of that filesystem ([`user_image_mount`]) is FUSE (not
//!     `fuseblk`), read-only in its superblock (`ro`: no mount of it
//!     writes), mounted by the exec's user (`user_id=`) and on a mount
//!     that is no FUSE mount itself (another FUSE mount stacked on the
//!     image's mount point is not the image);
//!   - the file the caller named (its string, not cut) lies under that
//!     mount point: a link that led the runtime's exec to another mount
//!     (a directory of the path replaced since the mount) is no match;
//!   - the same process (pid and start) executed, just before, a regular
//!     file of that user (its owner) outside the staging directories and
//!     the system trees, on no FUSE or memory filesystem, still linked and
//!     still at its path (same device and inode): the image file;
//!   - a daemon of that same image file (by device and inode, through its
//!     `exe` link) runs as that user in PID 1's mount namespace, started at
//!     or after that exec, is neither stopped, traced (`TracerPid:`) nor
//!     exited, and holds open `/dev/fuse` and the image file itself (by
//!     device and inode: the file a runtime's daemon serves stays open in
//!     it) and no other regular file a staged image could be served from —
//!     one under a staging directory, unlinked, on a memory or FUSE
//!     filesystem, of no mount of PID 1's table (a `memfd`): the runtime's
//!     FUSE daemon serving its own image. The runtime's documented
//!     `TARGET_APPIMAGE` makes a legit image serve another file: its daemon
//!     holds that file, not the image (the review of #564, F1).
//! - **tied** — a later exec of a file on that filesystem (`AppRun`'s exec
//!   of the program, a zygote's `/proc/self/exe`, a helper) by the same
//!   user, while the mount (its id and device) is still there and still such
//!   a mount and its daemon (its start) still serves it, as above.
//! - The LSM program's check of an exec (`ExecCheck`, which the posture's
//!   exec arm judges before the exec is done) is read the same way by the
//!   exec-check pump: the process's latest exec of an image read, not taken
//!   (its `/proc` start that exec's process's), a caller's string as long as
//!   the sensor's buffer taken for cut.
//!
//! What stays judged, as before: an exec on a writable FUSE filesystem, on
//! one whose daemon is not the image the process executed (`squashfuse` run
//! by hand over a file, whatever image runs meanwhile), on one mounted
//! over another FUSE mount; an AppImage itself run from `/tmp`, `/var/tmp`
//! or `/dev/shm` (its image is staged), or a legit one made to serve a
//! file staged there (`TARGET_APPIMAGE=/tmp/x.AppImage`); one another user
//! owns, one on a FUSE or memory filesystem; an AppImage extracted
//! (`--appimage-extract-and-run`, or no FUSE): a writable copy in `/tmp`;
//! tracepoint mode (no LSM identity). And whatever the program then does —
//! a credential read, a file staged and executed, persistence, a shell
//! with a socket — is judged as any user program's: the flag takes only
//! the staging directory away.
//!
//! Residual, said (the review of #564, F2): a malicious AppImage the user
//! runs is a user program, judged by its behaviour. The kernel ties no
//! FUSE mount to the process that serves it in a way `/proc` shows (the
//! connection's `/dev/fuse` file names no device), so the pump ties the
//! mount to its image through the exec that entered it and a daemon of the
//! image started since. No mount namespace is needed to swap what is
//! served: a user who stops its own AppImage's runtime after the mount,
//! unmounts it, mounts its own read-only squashfs there (`squashfuse`) and
//! starts the image again with `--appimage-mount` (a daemon of the image,
//! started since), then lets the runtime go on, gets its squashfs's
//! programs judged as the image's. So does a runtime made to serve a file
//! of the user's home (`TARGET_APPIMAGE` there, the image held as well):
//! programs it could run from its home, which it can write. The impact
//! stays the user's own: every fact is checked on the uid (the mount's
//! `user_id`, the image's owner, the daemon's real uid, the exec's), no
//! other user inherits the mark, and root's exec from `/tmp/.mount_*` is
//! still R009. A kernel record of the process the connection's file is
//! handed to (`security_file_receive`) would close the swap; it would not
//! have closed `TARGET_APPIMAGE`, whose daemon is the image's own — the
//! file the daemon holds does.

use std::collections::{BTreeMap, HashMap};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use common::wire::exe::{exe_flags, kernel_dev};
use nn_core::decision::rules::is_staging_path;
use nn_core::posture::lineage::in_system_tree;
use nn_model::Event;
use parking_lot::Mutex;

use crate::mountinfo::{is_fuse, MountEntry, MountTable};

/// The execs of possible images kept, one per process (its latest).
const RAN_MAX: usize = 4096;
/// The filesystems tied to their image at once.
const TIED_MAX: usize = 256;

/// An exec of a possible image file: the process's latest.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Ran {
    /// The process's start (the exec event's `start_ns`).
    start: u64,
    dev: u64,
    ino: u64,
    path: PathBuf,
    exec_ns: u64,
    /// The order it was noted in: the oldest is forgotten first.
    seq: u64,
}

/// A FUSE filesystem tied to its image, by its device.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Tied {
    mount_id: u64,
    uid: u32,
    image: (u64, u64),
    image_path: PathBuf,
    daemon: u32,
    daemon_ticks: u64,
}

/// The pump's record: the execs of possible images, the filesystems tied.
#[derive(Debug, Default)]
pub struct AppImages {
    /// By pid: the latest exec of a possible image of the process there.
    ran: HashMap<u32, Ran>,
    /// The pids of `ran` in the order noted: the oldest forgotten first.
    order: BTreeMap<u64, u32>,
    seq: u64,
    tied: HashMap<u64, Tied>,
}

/// The exec pump's record (one pump thread).
static PUMP: LazyLock<Mutex<AppImages>> = LazyLock::new(Default::default);

/// The exec pump's step: `event` read under `/proc`.
pub fn read(event: &mut Event) {
    PUMP.lock().note(Path::new("/proc"), event);
}

/// The flags of an identity whose path or file is not the kernel's plain
/// view of a linked file. (`TASK_ROOT` is the plain case of a file of the
/// root filesystem: the walk stopped at the task's root; a chroot is told
/// at the tie by the process's root, PID 1's or not.)
const NOT_PLAIN: u32 = exe_flags::TMPFS
    | exe_flags::MEMFD
    | exe_flags::DELETED
    | exe_flags::DEEP
    | exe_flags::UNRESOLVED;

impl AppImages {
    /// `event` noted — an exec (`ProcessSpawn`), or the LSM program's check
    /// of one before it runs (`ExecCheck`, which the posture's exec arm
    /// judges too) — and marked [`exe_flags::USER_IMAGE`] when its file is
    /// a tied image's, the processes under `proc_root`.
    pub fn note(&mut self, proc_root: &Path, event: &mut Event) {
        let (pid, uid, filename, exe, start_ns, exec_ns, cut) = match event {
            Event::ProcessSpawn {
                pid,
                uid,
                filename,
                exe,
                start_ns,
                timestamp_ns,
                filename_truncated,
                ..
            } => (
                *pid,
                *uid,
                filename.as_str(),
                exe,
                Some(*start_ns),
                *timestamp_ns,
                *filename_truncated,
            ),
            // the check carries no cut flag: a string as long as the
            // sensor's buffer may be cut
            Event::ExecCheck {
                pid,
                uid,
                filename,
                exe,
                ..
            } => {
                let cut = filename.len() >= common::wire::FILENAME_LEN - 1;
                (*pid, *uid, filename.as_str(), exe, None, 0, cut)
            }
            _ => return,
        };
        // the process's exec before this one, if it ran a possible image:
        // an exec replaces it (one at its pid, the same process's or not)
        let before = match start_ns {
            Some(start) => self.forget(pid).filter(|r| r.start == start),
            None => None,
        };
        if !exe.has(exe_flags::KNOWN)
            || start_ns == Some(0)
            || exe.flags & NOT_PLAIN != 0
            || exe.root != (0, 0)
            || !exe.path.starts_with('/')
        {
            return;
        }
        let path = PathBuf::from(&exe.path);
        if !is_staging_path(&exe.path) {
            if let Some(start) = start_ns.filter(|_| !in_system_tree(&exe.path)) {
                self.remember(
                    pid,
                    Ran {
                        start,
                        dev: exe.dev,
                        ino: exe.ino,
                        path,
                        exec_ns,
                        seq: 0,
                    },
                );
            }
            return;
        }
        // the review of #564 (F4): no more is read for a file that cannot
        // be a tied image's — FUSE's device is an anonymous one (major 0),
        // and a filesystem not yet tied needs the process's exec of an
        // image (a check reads it, not taken)
        if exe.dev >> 20 != 0 {
            return;
        }
        let tied = self.tied.contains_key(&exe.dev);
        let before = match before {
            None if !tied && start_ns.is_none() => self.ran_by(proc_root, pid),
            b => b,
        };
        if !tied && before.is_none() {
            return;
        }
        let Ok(table) = crate::mountinfo::read(&proc_root.join("1/mountinfo")) else {
            return;
        };
        let user = match self.tied.get(&exe.dev) {
            Some(t) => {
                let still = still_tied(proc_root, &table, exe.dev, uid, &path, t);
                if !still {
                    self.tied.remove(&exe.dev);
                }
                still
            }
            None => {
                let caller = (!cut).then_some(Path::new(filename));
                match before
                    .and_then(|b| tie(proc_root, &table, pid, uid, (exe.dev, &path), caller, &b))
                {
                    Some(t) => {
                        if self.tied.len() >= TIED_MAX {
                            self.tied.clear();
                        }
                        self.tied.insert(exe.dev, t);
                        true
                    }
                    None => false,
                }
            }
        };
        if user {
            exe.flags |= exe_flags::USER_IMAGE;
        }
    }

    /// The latest exec of a possible image of the process `pid` runs now
    /// (its `/proc` start that exec's process's), for its check.
    fn ran_by(&self, proc_root: &Path, pid: u32) -> Option<Ran> {
        let ran = self.ran.get(&pid)?;
        let stat =
            crate::state_read::read_state(proc_root.join(pid.to_string()).join("stat")).ok()?;
        let ticks = crate::response::proc_ref::stat_start_ticks(&stat)?;
        crate::response::proc_ref::started_at(ticks, ran.start).then(|| ran.clone())
    }

    /// `ran` noted as `pid`'s latest exec of a possible image; the oldest
    /// noted is forgotten first when the record is full.
    fn remember(&mut self, pid: u32, mut ran: Ran) {
        self.forget(pid);
        if self.ran.len() >= RAN_MAX {
            if let Some((_, oldest)) = self.order.pop_first() {
                self.ran.remove(&oldest);
            }
        }
        self.seq += 1;
        ran.seq = self.seq;
        self.order.insert(self.seq, pid);
        self.ran.insert(pid, ran);
    }

    /// `pid`'s exec taken from the record.
    fn forget(&mut self, pid: u32) -> Option<Ran> {
        let ran = self.ran.remove(&pid)?;
        self.order.remove(&ran.seq);
        Some(ran)
    }
}

/// The mounts of the filesystem `dev` when each is a user image's mount of
/// `uid` ([`user_image_mount`]); `None` when one is not, or there is none.
fn image_mounts(table: &MountTable, dev: u64, uid: u32) -> Option<Vec<&MountEntry>> {
    let mounts: Vec<&MountEntry> = table
        .entries
        .iter()
        .filter(|m| m.kernel_dev() == dev)
        .collect();
    (!mounts.is_empty() && mounts.iter().all(|m| user_image_mount(table, m, uid))).then_some(mounts)
}

/// `m` is a FUSE mount (not `fuseblk`) of a read-only superblock that
/// `uid` mounted, on a mount that is not FUSE.
fn user_image_mount(table: &MountTable, m: &MountEntry, uid: u32) -> bool {
    let t = m.fstype.as_bytes();
    (t == b"fuse" || t.starts_with(b"fuse."))
        && m.read_only_super()
        && m.super_option("user_id") == Some(uid.to_string().as_bytes())
        && table.parent_of(m).is_some_and(|p| !is_fuse(&p.fstype))
}

/// The mount of `mounts` whose root is the filesystem's and whose mount
/// point holds `path` below it.
fn mount_holding<'a>(mounts: &[&'a MountEntry], path: &Path) -> Option<&'a MountEntry> {
    mounts.iter().copied().find(|m| {
        m.root == Path::new("/") && path.starts_with(&m.mount_point) && path != m.mount_point
    })
}

/// The tie of the filesystem `dev` that `pid` executes `path` from to the
/// image `before` the same process executed: every rule of the module's
/// "tying" list.
fn tie(
    proc_root: &Path,
    table: &MountTable,
    pid: u32,
    uid: u32,
    (dev, path): (u64, &Path),
    caller: Option<&Path>,
    before: &Ran,
) -> Option<Tied> {
    let dir = proc_root.join(pid.to_string());
    if !(super::exec_facts::same_mount_namespace(proc_root, &dir)
        && super::exec_facts::same_root(proc_root, &dir))
    {
        return None;
    }
    let mounts = image_mounts(table, dev, uid)?;
    let m = mount_holding(&mounts, path)?;
    // the caller's string, read as it is: no `..` that could leave the
    // mount point it names
    let caller = caller?;
    if !(caller.starts_with(&m.mount_point) && caller != m.mount_point)
        || caller
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return None;
    }
    // the image file: still that file at its path, the user's, linked, a
    // regular file on no FUSE filesystem — and its path through no FUSE
    // mount (its daemon answers the lookup, or never: never `stat`ed)
    if table
        .entries
        .iter()
        .any(|e| is_fuse(&e.fstype) && before.path.starts_with(&e.mount_point))
    {
        return None;
    }
    let at = dir
        .join("root")
        .join(before.path.strip_prefix("/").unwrap_or(&before.path));
    let meta = std::fs::metadata(at).ok()?;
    if !(meta.is_file()
        && (kernel_dev(meta.dev()), meta.ino()) == (before.dev, before.ino)
        && meta.uid() == uid
        && meta.nlink() > 0)
        || table
            .entries
            .iter()
            .any(|e| e.kernel_dev() == before.dev && is_fuse(&e.fstype))
    {
        return None;
    }
    let (daemon, daemon_ticks) = find_daemon(proc_root, table, pid, uid, before)?;
    Some(Tied {
        mount_id: m.id,
        uid,
        image: (before.dev, before.ino),
        image_path: before.path.clone(),
        daemon,
        daemon_ticks,
    })
}

/// The filesystem `dev` is still tied as `t` says, for an exec of `path`
/// by `uid`: the same mount still there and still a user image's mount,
/// its daemon still serving.
fn still_tied(
    proc_root: &Path,
    table: &MountTable,
    dev: u64,
    uid: u32,
    path: &Path,
    t: &Tied,
) -> bool {
    if uid != t.uid {
        return false;
    }
    let Some(mounts) = image_mounts(table, dev, uid) else {
        return false;
    };
    if !mounts.iter().any(|m| m.id == t.mount_id) || mount_holding(&mounts, path).is_none() {
        return false;
    }
    let d = proc_root.join(t.daemon.to_string());
    daemon_facts(proc_root, table, &d, uid, t.image, &t.image_path)
        .is_some_and(|ticks| ticks == t.daemon_ticks)
}

/// A daemon of the image `before` for `pid`'s exec: a process (not `pid`)
/// that runs that image as `uid`, started at or after its exec, serving
/// ([`daemon_facts`]). Its pid and `/proc` start.
fn find_daemon(
    proc_root: &Path,
    table: &MountTable,
    pid: u32,
    uid: u32,
    before: &Ran,
) -> Option<(u32, u64)> {
    let image = (before.dev, before.ino);
    std::fs::read_dir(proc_root).ok()?.flatten().find_map(|e| {
        let d: u32 = e.file_name().to_str()?.parse().ok()?;
        if d == pid {
            return None;
        }
        let ticks = daemon_facts(proc_root, table, &e.path(), uid, image, &before.path)?;
        crate::response::proc_ref::started_since(ticks, before.exec_ns).then_some((d, ticks))
    })
}

/// The process `dir` (`/proc/<pid>`) runs the image `image` (its `exe`
/// link names `image_path`, and leads to that device and inode) as `uid`
/// (real), in PID 1's mount namespace, is neither stopped, traced
/// (`TracerPid:`) nor exited, and serves that image ([`serves_the_image`]):
/// its `/proc` start.
fn daemon_facts(
    proc_root: &Path,
    table: &MountTable,
    dir: &Path,
    uid: u32,
    image: (u64, u64),
    image_path: &Path,
) -> Option<u64> {
    // the link's text first: its target is then the image's directory's,
    // never a FUSE file to `stat`
    if std::fs::read_link(dir.join("exe")).ok()? != image_path {
        return None;
    }
    let meta = std::fs::metadata(dir.join("exe")).ok()?;
    if (kernel_dev(meta.dev()), meta.ino()) != image {
        return None;
    }
    let status = crate::state_read::read_state(dir.join("status")).ok()?;
    let field = |name: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(name))?
            .split_whitespace()
            .next()?
            .parse::<u32>()
            .ok()
    };
    // the review of #564 (F5): a tracer (`PTRACE_SEIZE` leaves the state as
    // it was) may run any code in it
    if field("Uid:")? != uid
        || field("TracerPid:")? != 0
        || !super::exec_facts::same_mount_namespace(proc_root, dir)
    {
        return None;
    }
    let stat = crate::state_read::read_state(dir.join("stat")).ok()?;
    let state = stat.rsplit_once(')')?.1.split_whitespace().next()?;
    if matches!(state, "T" | "t" | "Z" | "X" | "x") {
        return None;
    }
    let ticks = crate::response::proc_ref::stat_start_ticks(&stat)?;
    serves_the_image(table, dir, image).then_some(ticks)
}

/// The review of #564 (F1): the daemon `dir` holds `/dev/fuse` and the
/// image file `image` (device and inode) open, and no other regular file a
/// staged image could be served from. The runtime's daemon keeps open the
/// file it serves — its own image, or the file `TARGET_APPIMAGE` names (the
/// runtime's documented variable): a user's legit image made to serve a
/// squashfs staged in `/tmp` holds that file, not its image, or both (a
/// descriptor of the image inherited). Refused: a regular file under a
/// staging directory (its link's text), unlinked, on a memory filesystem,
/// on a FUSE filesystem, or of no mount of PID 1's table (a `memfd`,
/// another namespace's) — by the descriptor's `fdinfo` mount, so a FUSE
/// file is never `stat`ed. A pipe, a socket, a device are no image.
fn serves_the_image(table: &MountTable, dir: &Path, image: (u64, u64)) -> bool {
    let Ok(fds) = std::fs::read_dir(dir.join("fd")) else {
        return false;
    };
    let (mut fuse, mut held) = (false, false);
    for fd in fds.flatten() {
        // closed since the directory was read: nothing held
        let Ok(text) = std::fs::read_link(fd.path()) else {
            continue;
        };
        if text.as_os_str() == OsStr::new("/dev/fuse") {
            fuse = true;
            continue;
        }
        // `pipe:[…]`, `socket:[…]`, `anon_inode:…`: no file of a path
        if !text.as_os_str().as_bytes().starts_with(b"/") {
            continue;
        }
        let Some(m) = fd_mount(table, dir, fd.file_name().as_os_str()) else {
            return false;
        };
        if is_fuse(&m.fstype) {
            return false;
        }
        let Ok(meta) = std::fs::metadata(fd.path()) else {
            return false;
        };
        if !meta.is_file() {
            continue;
        }
        if (kernel_dev(meta.dev()), meta.ino()) == image {
            held = true;
        } else if meta.nlink() == 0
            || matches!(m.fstype.as_bytes(), b"tmpfs" | b"ramfs")
            || is_staging_path(&text.to_string_lossy())
        {
            return false;
        }
    }
    fuse && held
}

/// The mount of PID 1's table the descriptor `fd` of `dir` is a file of,
/// by its `fdinfo`'s `mnt_id:`.
fn fd_mount<'a>(table: &'a MountTable, dir: &Path, fd: &OsStr) -> Option<&'a MountEntry> {
    let info = crate::state_read::read_state(dir.join("fdinfo").join(fd)).ok()?;
    let id: u64 = info
        .lines()
        .find_map(|l| l.strip_prefix("mnt_id:"))?
        .trim()
        .parse()
        .ok()?;
    table.entries.iter().find(|e| e.id == id)
}

#[cfg(test)]
mod tests {
    //! Lot 355: the AppImage tie, on fixture `/proc` trees.

    use super::*;
    use std::os::unix::fs::symlink;

    const INIT_NS: &str = "mnt:[4026531841]";
    const MOUNT: &str = "/tmp/.mount_k355ab";
    /// The image's FUSE filesystem, `0:77` in the table.
    const FUSE_DEV: u64 = 77;
    const RUNTIME: u32 = 500;
    const DAEMON: u32 = 600;
    const START: u64 = 7_000;
    /// The image's exec: before any daemon start in the fixtures.
    const IMAGE_EXEC_NS: u64 = 1;
    /// A daemon's `/proc` start after it, whatever the host's suspended time
    /// (some years of clock ticks).
    const FRESH: u64 = 10_000_000_000;

    fn me() -> u32 {
        // SAFETY: getuid has no preconditions.
        unsafe { libc::getuid() }
    }

    struct Fixture {
        proc: tempfile::TempDir,
        _files: tempfile::TempDir,
        image: PathBuf,
    }

    /// `pid`'s `/proc` entry: its mount namespace, its root (`/`).
    fn process(root: &Path, pid: u32, ns: &str) -> PathBuf {
        let d = root.join(pid.to_string());
        std::fs::create_dir_all(d.join("ns")).unwrap();
        std::fs::create_dir_all(d.join("fd")).unwrap();
        let _ = std::fs::remove_file(d.join("ns/mnt"));
        symlink(ns, d.join("ns/mnt")).unwrap();
        if d.join("root").symlink_metadata().is_err() {
            symlink("/", d.join("root")).unwrap();
        }
        d
    }

    /// A daemon running `image` as `uid`, in `state`, started at `ticks`,
    /// holding `/dev/fuse` when `fuse`, and the image file it serves (on the
    /// table's root filesystem, mount 22).
    fn daemon(root: &Path, pid: u32, image: &Path, uid: u32, state: &str, ticks: u64, fuse: bool) {
        let d = process(root, pid, INIT_NS);
        let _ = std::fs::remove_file(d.join("exe"));
        symlink(image, d.join("exe")).unwrap();
        std::fs::write(
            d.join("status"),
            format!("Name:\tApp.AppImage\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nTracerPid:\t0\n"),
        )
        .unwrap();
        hold(root, pid, 4, image, 22);
        let mut fields = vec!["0"; 19];
        fields[0] = state;
        let ticks = ticks.to_string();
        fields.push(&ticks);
        std::fs::write(
            d.join("stat"),
            format!("{pid} (App.AppImage) {}\n", fields.join(" ")),
        )
        .unwrap();
        let _ = std::fs::remove_file(d.join("fd/3"));
        // (`/dev/null` in its place: a device of the root filesystem)
        hold(
            root,
            pid,
            3,
            Path::new(if fuse { "/dev/fuse" } else { "/dev/null" }),
            22,
        );
    }

    /// `pid` holds `target` open as its descriptor `fd`, a file of the
    /// table's mount `mnt_id` (its `fdinfo`).
    fn hold(root: &Path, pid: u32, fd: u32, target: &Path, mnt_id: u64) {
        let d = root.join(pid.to_string());
        std::fs::create_dir_all(d.join("fdinfo")).unwrap();
        let _ = std::fs::remove_file(d.join("fd").join(fd.to_string()));
        symlink(target, d.join("fd").join(fd.to_string())).unwrap();
        std::fs::write(
            d.join("fdinfo").join(fd.to_string()),
            format!("pos:\t0\nflags:\t0100000\nmnt_id:\t{mnt_id}\nino:\t1\n"),
        )
        .unwrap();
    }

    /// The table: `/`, `/tmp`, and the image's FUSE mount with `super_opts`
    /// on the mount `parent` (30: `/tmp`).
    fn table(root: &Path, id: u64, parent: u64, super_opts: &str) {
        let uid = me();
        let text = format!(
            "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n\
             30 22 0:30 / /tmp rw,nosuid - tmpfs tmpfs rw\n\
             45 30 0:40 / /tmp/sshfs rw,nosuid,nodev - fuse.sshfs h: rw,user_id={uid}\n\
             {id} {parent} 0:{FUSE_DEV} / {MOUNT} ro,nosuid,nodev - fuse.App.AppImage App.AppImage {super_opts}\n"
        );
        std::fs::write(root.join("1/mountinfo"), text).unwrap();
    }

    fn fixture() -> Fixture {
        let proc = tempfile::tempdir().unwrap();
        // the image beside the test's binary: no staging directory (a temporary
        // directory under `/tmp` is one)
        let exe = std::env::current_exe().unwrap();
        let files = tempfile::tempdir_in(exe.parent().unwrap()).unwrap();
        let image = files.path().join("App.AppImage");
        assert!(!is_staging_path(image.to_str().unwrap()), "{image:?}");
        std::fs::write(&image, b"\x7fELF runtime + squashfs").unwrap();
        process(proc.path(), 1, INIT_NS);
        let runtime = process(proc.path(), RUNTIME, INIT_NS);
        // its `/proc` start: its exec's process's (the fixtures' starts are a
        // few µs after boot)
        std::fs::write(
            runtime.join("stat"),
            format!("{RUNTIME} (App) S {}0\n", "0 ".repeat(18)),
        )
        .unwrap();
        table(
            proc.path(),
            61,
            30,
            &format!("ro,user_id={},group_id=0", me()),
        );
        daemon(proc.path(), DAEMON, &image, me(), "S", FRESH, true);
        Fixture {
            proc,
            _files: files,
            image,
        }
    }

    fn exec(
        pid: u32,
        uid: u32,
        path: &str,
        (dev, ino): (u64, u64),
        filename: &str,
        ts: u64,
    ) -> Event {
        Event::ProcessSpawn {
            pid,
            ppid: 1,
            uid,
            gid: uid,
            comm: "x".into(),
            filename: filename.into(),
            timestamp_ns: ts,
            argv: Vec::new(),
            parent_comm: String::new(),
            parent_start_ns: 0,
            start_ns: START + u64::from(pid),
            parent_is_kthread: false,
            exe: nn_model::ExeIdentity {
                path: path.into(),
                dev,
                ino,
                // the LSM program's: a file of the root filesystem walked up to the
                // task's root (`TASK_ROOT`), one of a FUSE mount up to its root and
                // mapped to its mount point by the pump
                flags: exe_flags::KNOWN
                    | if is_staging_path(path) {
                        0
                    } else {
                        exe_flags::TASK_ROOT
                    },
                ..Default::default()
            },
            argv_truncated: false,
            filename_truncated: false,
            stdio: Default::default(),
        }
    }

    fn id_of(p: &Path) -> (u64, u64) {
        let m = std::fs::metadata(p).unwrap();
        (kernel_dev(m.dev()), m.ino())
    }

    fn user_image(e: &Event) -> bool {
        match e {
            Event::ProcessSpawn { exe, .. } | Event::ExecCheck { exe, .. } => {
                exe.has(exe_flags::USER_IMAGE)
            }
            _ => unreachable!(),
        }
    }

    /// The runtime's two execs: the image file, then `AppRun` from its mount
    /// (the caller's string `apprun_caller`). Whether the second is the image's.
    fn run(images: &mut AppImages, f: &Fixture, uid: u32, apprun_caller: &str) -> bool {
        let image = f.image.to_str().unwrap();
        let mut first = exec(RUNTIME, uid, image, id_of(&f.image), image, IMAGE_EXEC_NS);
        images.note(f.proc.path(), &mut first);
        assert!(
            !user_image(&first),
            "the image file itself is no staging exec"
        );
        let apprun = format!("{MOUNT}/AppRun");
        let mut second = exec(RUNTIME, uid, &apprun, (FUSE_DEV, 2), apprun_caller, 50);
        images.note(f.proc.path(), &mut second);
        user_image(&second)
    }

    fn apprun() -> String {
        format!("{MOUNT}/AppRun")
    }

    /// Lot 355: an AppImage's runtime executes `AppRun` from its read-only
    /// mount under `/tmp`: the image's; then `AppRun` executes the program, the
    /// program its zygote by `/proc/self/exe`, the zygote's child a helper —
    /// each the image's while the mount and its daemon are there.
    #[test]
    fn an_appimage_program_is_its_image_s() {
        let f = fixture();
        let mut images = AppImages::default();
        assert!(run(&mut images, &f, me(), &apprun()));
        let program = format!("{MOUNT}/usr/bin/app");
        for (pid, caller) in [
            (RUNTIME, program.as_str()),
            (RUNTIME + 1, "/proc/self/exe"),
            (RUNTIME + 2, "./helper"),
        ] {
            let mut e = exec(pid, me(), &program, (FUSE_DEV, 9), caller, 60);
            images.note(f.proc.path(), &mut e);
            assert!(user_image(&e), "{pid} {caller}");
        }
        // a path of the device under no mount of it
        let mut e = exec(
            RUNTIME + 4,
            me(),
            "/tmp/elsewhere/app",
            (FUSE_DEV, 9),
            "x",
            70,
        );
        images.note(f.proc.path(), &mut e);
        assert!(!user_image(&e));
        // another user's exec of a file there is not the image's
        let mut other = exec(RUNTIME + 3, me() + 1, &program, (FUSE_DEV, 9), &program, 70);
        images.note(f.proc.path(), &mut other);
        assert!(!user_image(&other));
    }

    /// A writable FUSE filesystem, one the exec's user did not mount, one
    /// mounted over another FUSE mount: no image.
    #[test]
    fn a_writable_or_stacked_fuse_mount_is_not_an_image() {
        let uid = me();
        for (parent, opts) in [
            (30, format!("rw,user_id={uid}")),
            (30, format!("ro,user_id={}", uid + 1)),
            (30, "ro".to_string()),
            (45, format!("ro,user_id={uid}")),
        ] {
            let f = fixture();
            table(f.proc.path(), 61, parent, &opts);
            assert!(
                !run(&mut AppImages::default(), &f, uid, &apprun()),
                "{parent} {opts}"
            );
        }
        // the image's mount, and another mount of its filesystem on a FUSE mount
        let f = fixture();
        table_plus(
            f.proc.path(),
            &format!(
                "63 45 0:{FUSE_DEV} / /tmp/sshfs/m ro,nosuid - fuse.App.AppImage x ro,user_id={uid}"
            ),
        );
        assert!(
            !run(&mut AppImages::default(), &f, uid, &apprun()),
            "every mount"
        );
    }

    /// Lot 352's shape: a squashfs mounted by `squashfuse` (another program's
    /// daemon), its program run by a shell — whatever AppImage runs meanwhile.
    #[test]
    fn a_mount_whose_daemon_is_not_the_image_stays_staged() {
        let f = fixture();
        let squashfuse = f._files.path().join("squashfuse");
        std::fs::write(&squashfuse, b"\x7fELF").unwrap();
        // the daemon runs another program than the image the runtime ran
        daemon(f.proc.path(), DAEMON, &squashfuse, me(), "S", FRESH, true);
        assert!(!run(&mut AppImages::default(), &f, me(), &apprun()));
        // the image's daemon serves, but the exec's process ran a shell
        // (a system tree: no image) before it
        let f = fixture();
        let mut images = AppImages::default();
        let mut shell = exec(RUNTIME, me(), "/usr/bin/bash", (1, 1), "/bin/bash", 1);
        images.note(f.proc.path(), &mut shell);
        let mut e = exec(RUNTIME, me(), &apprun(), (FUSE_DEV, 2), &apprun(), 50);
        images.note(f.proc.path(), &mut e);
        assert!(!user_image(&e));
        // no exec seen before it at all
        let mut e = exec(RUNTIME + 9, me(), &apprun(), (FUSE_DEV, 2), &apprun(), 50);
        images.note(f.proc.path(), &mut e);
        assert!(!user_image(&e));
    }

    /// A daemon that is not serving the runtime's mount: started before the
    /// image's exec (another run of it), stopped or traced, exited, not
    /// holding `/dev/fuse`, another user's.
    #[test]
    fn a_daemon_that_is_not_the_runtime_s_is_no_tie() {
        for (state, ticks, fuse, uid) in [
            ("S", 0, true, me()),
            ("T", FRESH, true, me()),
            ("t", FRESH, true, me()),
            ("Z", FRESH, true, me()),
            ("S", FRESH, false, me()),
            ("S", FRESH, true, me() + 1),
        ] {
            let f = fixture();
            let image = f.image.clone();
            daemon(f.proc.path(), DAEMON, &image, uid, state, ticks, fuse);
            let mut images = AppImages::default();
            let image_s = image.to_str().unwrap();
            // the image ran long after the daemon's start when `ticks` is 0
            let ts = if ticks == 0 {
                u64::MAX / 4
            } else {
                IMAGE_EXEC_NS
            };
            let mut first = exec(RUNTIME, me(), image_s, id_of(&image), image_s, ts);
            images.note(f.proc.path(), &mut first);
            let mut e = exec(RUNTIME, me(), &apprun(), (FUSE_DEV, 2), &apprun(), ts);
            images.note(f.proc.path(), &mut e);
            assert!(!user_image(&e), "{state} {ticks} {fuse} {uid}");
        }
    }

    /// The caller's string leads elsewhere than the mount it executed: a link
    /// (a directory of the path replaced since the mount), a `..`, a string the
    /// sensor cut, a relative one.
    #[test]
    fn a_caller_path_outside_the_mount_point_is_no_match() {
        for caller in [
            "/tmp/link/.mount_k355ab/AppRun",
            "/tmp/.mount_k355ab/../.mount_k355ab/AppRun",
            "AppRun",
            MOUNT,
        ] {
            let f = fixture();
            assert!(
                !run(&mut AppImages::default(), &f, me(), caller),
                "{caller}"
            );
        }
        let f = fixture();
        let mut images = AppImages::default();
        let image = f.image.to_str().unwrap();
        let mut first = exec(RUNTIME, me(), image, id_of(&f.image), image, IMAGE_EXEC_NS);
        images.note(f.proc.path(), &mut first);
        let mut cut = exec(RUNTIME, me(), &apprun(), (FUSE_DEV, 2), &apprun(), 50);
        if let Event::ProcessSpawn {
            filename_truncated, ..
        } = &mut cut
        {
            *filename_truncated = true;
        }
        images.note(f.proc.path(), &mut cut);
        assert!(!user_image(&cut));
    }

    /// The image file: the user's own, still that file at its path, outside
    /// the staging directories; an image run from `/tmp` is staged itself.
    #[test]
    fn the_image_is_the_users_own_file_still_there() {
        // another user's image (the daemon and the mount that user's too)
        let f = fixture();
        let other = me() + 1;
        table(f.proc.path(), 61, 30, &format!("ro,user_id={other}"));
        daemon(f.proc.path(), DAEMON, &f.image, other, "S", FRESH, true);
        assert!(!run(&mut AppImages::default(), &f, other, &apprun()));
        // the image replaced at its path since its exec
        let f = fixture();
        let mut images = AppImages::default();
        let image = f.image.to_str().unwrap();
        let (dev, ino) = id_of(&f.image);
        let mut first = exec(RUNTIME, me(), image, (dev, ino + 1), image, IMAGE_EXEC_NS);
        images.note(f.proc.path(), &mut first);
        let mut e = exec(RUNTIME, me(), &apprun(), (FUSE_DEV, 2), &apprun(), 50);
        images.note(f.proc.path(), &mut e);
        assert!(!user_image(&e));
        // an image run from a staging directory is not remembered
        for staged in [
            "/tmp/App.AppImage",
            "/dev/shm/App.AppImage",
            "/var/tmp/App.AppImage",
        ] {
            let f = fixture();
            daemon(
                f.proc.path(),
                DAEMON,
                Path::new(staged),
                me(),
                "S",
                FRESH,
                true,
            );
            let mut images = AppImages::default();
            let mut first = exec(RUNTIME, me(), staged, (3, 3), staged, IMAGE_EXEC_NS);
            images.note(f.proc.path(), &mut first);
            let mut e = exec(RUNTIME, me(), &apprun(), (FUSE_DEV, 2), &apprun(), 50);
            images.note(f.proc.path(), &mut e);
            assert!(!user_image(&e), "{staged}");
        }
    }

    /// The runtime in a mount namespace or a root of its own; an identity the
    /// LSM program did not give (tracepoint mode) or not plain.
    #[test]
    fn only_the_kernel_s_plain_view_ties() {
        let f = fixture();
        process(f.proc.path(), RUNTIME, "mnt:[4026532999]");
        assert!(!run(&mut AppImages::default(), &f, me(), &apprun()));
        // a root of its own that shows the image at its path (a hard link)
        let f = fixture();
        let croot = tempfile::tempdir_in(f._files.path()).unwrap();
        let rel = f.image.strip_prefix("/").unwrap();
        std::fs::create_dir_all(croot.path().join(rel).parent().unwrap()).unwrap();
        std::fs::hard_link(&f.image, croot.path().join(rel)).unwrap();
        let r = f.proc.path().join(RUNTIME.to_string()).join("root");
        std::fs::remove_file(&r).unwrap();
        symlink(croot.path(), &r).unwrap();
        assert!(!run(&mut AppImages::default(), &f, me(), &apprun()));
        for (clear, set) in [
            (exe_flags::KNOWN, 0),
            (0, exe_flags::TMPFS),
            (0, exe_flags::DELETED),
            (0, exe_flags::DEEP),
            (0, exe_flags::UNRESOLVED),
        ] {
            let f = fixture();
            let mut images = AppImages::default();
            let image = f.image.to_str().unwrap();
            let mut first = exec(RUNTIME, me(), image, id_of(&f.image), image, IMAGE_EXEC_NS);
            images.note(f.proc.path(), &mut first);
            let mut e = exec(RUNTIME, me(), &apprun(), (FUSE_DEV, 2), &apprun(), 50);
            if let Event::ProcessSpawn { exe, .. } = &mut e {
                exe.flags = (exe.flags & !clear) | set;
            }
            images.note(f.proc.path(), &mut e);
            assert!(!user_image(&e), "{clear:#x} {set:#x}");
        }
    }

    /// A tie ends with its daemon (gone, or another process at its pid), its
    /// mount (unmounted, another mount of the device, made writable).
    #[test]
    fn a_tie_ends_with_its_daemon_or_its_mount() {
        let program = format!("{MOUNT}/usr/bin/app");
        let later = |images: &mut AppImages, f: &Fixture| {
            let mut e = exec(
                RUNTIME + 1,
                me(),
                &program,
                (FUSE_DEV, 9),
                "/proc/self/exe",
                60,
            );
            images.note(f.proc.path(), &mut e);
            user_image(&e)
        };
        let ends: [&dyn Fn(&Fixture); 4] = [
            &|f| std::fs::remove_dir_all(f.proc.path().join(DAEMON.to_string())).unwrap(),
            &|f| daemon(f.proc.path(), DAEMON, &f.image, me(), "S", FRESH + 1, true),
            &|f| table(f.proc.path(), 62, 30, &format!("ro,user_id={}", me())),
            &|f| table(f.proc.path(), 61, 30, &format!("rw,user_id={}", me())),
        ];
        for (i, end) in ends.iter().enumerate() {
            let f = fixture();
            let mut images = AppImages::default();
            assert!(run(&mut images, &f, me(), &apprun()), "{i}");
            assert!(later(&mut images, &f), "{i}");
            end(&f);
            assert!(!later(&mut images, &f), "{i}");
            // and it stays ended
            process(f.proc.path(), DAEMON, INIT_NS);
            daemon(f.proc.path(), DAEMON, &f.image, me(), "S", FRESH, true);
            table(f.proc.path(), 61, 30, &format!("ro,user_id={}", me()));
            assert!(!later(&mut images, &f), "{i}");
        }
    }

    /// The record stays bounded: the oldest exec is forgotten first, and an
    /// exec forgets its process's earlier one.
    #[test]
    fn the_record_is_bounded() {
        let mut images = AppImages::default();
        let ran = |n: u64| Ran {
            start: 1,
            dev: 1,
            ino: n,
            path: PathBuf::from("/home/u/x"),
            exec_ns: n,
            seq: 0,
        };
        for n in 0..(RAN_MAX as u64 + 10) {
            images.remember(n as u32, ran(n));
        }
        assert_eq!(images.ran.len(), RAN_MAX);
        assert_eq!(images.order.len(), RAN_MAX);
        assert!(!images.ran.contains_key(&0));
        assert!(images.ran.contains_key(&(RAN_MAX as u32 + 9)));
        // a process's later exec replaces its earlier one, and is the newest
        images.remember(5, ran(1));
        images.remember(5, ran(2));
        assert_eq!(images.ran.len(), RAN_MAX);
        assert_eq!(images.order.len(), RAN_MAX);
        assert_eq!(images.ran[&5].ino, 2);
        images.remember(u32::MAX, ran(3));
        assert!(images.ran.contains_key(&5), "not the oldest");
        // taken, it leaves the order too
        assert!(images.forget(5).is_some());
        assert_eq!(images.order.len(), images.ran.len());
    }

    fn check(pid: u32, path: &str, dev: u64, filename: &str) -> Event {
        Event::ExecCheck {
            pid,
            ppid: 1,
            uid: me(),
            comm: "x".into(),
            filename: filename.into(),
            timestamp_ns: 40,
            exe: nn_model::ExeIdentity {
                path: path.into(),
                dev,
                ino: 2,
                flags: exe_flags::KNOWN,
                ..Default::default()
            },
        }
    }

    /// The LSM program's check of the runtime's exec of `AppRun` (the posture's
    /// exec arm judges it, before the exec is done) ties as the exec does, the
    /// image read without being taken; a check of a later program is tied too.
    /// A check whose process is no longer the image's exec's (another start), a
    /// string the sensor may have cut, does not tie.
    #[test]
    fn the_check_of_an_exec_ties_as_the_exec() {
        let f = fixture();
        let mut images = AppImages::default();
        let image = f.image.to_str().unwrap();
        let mut first = exec(RUNTIME, me(), image, id_of(&f.image), image, IMAGE_EXEC_NS);
        images.note(f.proc.path(), &mut first);
        let mut c = check(RUNTIME, &apprun(), FUSE_DEV, &apprun());
        images.note(f.proc.path(), &mut c);
        assert!(user_image(&c));
        // the exec itself, after its check
        let mut e = exec(RUNTIME, me(), &apprun(), (FUSE_DEV, 2), &apprun(), 50);
        images.note(f.proc.path(), &mut e);
        assert!(user_image(&e));
        let program = format!("{MOUNT}/usr/bin/app");
        let mut c = check(RUNTIME + 1, &program, FUSE_DEV, "/proc/self/exe");
        images.note(f.proc.path(), &mut c);
        assert!(user_image(&c));
        // the process at the pid started later than the image's exec's
        let f = fixture();
        let mut images = AppImages::default();
        let mut first = exec(
            RUNTIME,
            me(),
            image_of(&f),
            id_of(&f.image),
            image_of(&f),
            IMAGE_EXEC_NS,
        );
        images.note(f.proc.path(), &mut first);
        let late = f.proc.path().join(RUNTIME.to_string()).join("stat");
        std::fs::write(
            &late,
            format!("{RUNTIME} (App) S {}{FRESH}\n", "0 ".repeat(18)),
        )
        .unwrap();
        let mut c = check(RUNTIME, &apprun(), FUSE_DEV, &apprun());
        images.note(f.proc.path(), &mut c);
        assert!(!user_image(&c));
        // a caller's string as long as the sensor's buffer
        let f = fixture();
        let mut images = AppImages::default();
        let mut first = exec(
            RUNTIME,
            me(),
            image_of(&f),
            id_of(&f.image),
            image_of(&f),
            IMAGE_EXEC_NS,
        );
        images.note(f.proc.path(), &mut first);
        let long = format!("{MOUNT}/{}", "a".repeat(common::wire::FILENAME_LEN));
        let mut c = check(RUNTIME, &apprun(), FUSE_DEV, &long);
        images.note(f.proc.path(), &mut c);
        assert!(!user_image(&c));
    }

    fn image_of(f: &Fixture) -> &str {
        f.image.to_str().unwrap()
    }

    /// The table with one more `line` after the fixture's mounts.
    fn table_plus(root: &Path, line: &str) {
        let mut t = std::fs::read_to_string(root.join("1/mountinfo")).unwrap();
        t.push_str(line);
        t.push('\n');
        std::fs::write(root.join("1/mountinfo"), t).unwrap();
    }

    /// No image: a `fuseblk` filesystem, one shown only by a mount of a
    /// directory of it, a file mounted as the mount point itself, an image
    /// file on a FUSE filesystem.
    #[test]
    fn only_a_fuse_mount_of_the_image_s_shape_ties() {
        let uid = me();
        let fuse = |fstype: &str, root: &str| {
            format!(
                "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n30 22 0:30 / /tmp rw - tmpfs tmpfs rw\n\
                 61 30 0:{FUSE_DEV} {root} {MOUNT} ro,nosuid - {fstype} x ro,user_id={uid}\n"
            )
        };
        for (fstype, root) in [("fuseblk", "/"), ("fuse.App.AppImage", "/sub")] {
            let f = fixture();
            std::fs::write(f.proc.path().join("1/mountinfo"), fuse(fstype, root)).unwrap();
            assert!(
                !run(&mut AppImages::default(), &f, uid, &apprun()),
                "{fstype} {root}"
            );
        }
        // the exec of the mount point itself (a file mounted there)
        let f = fixture();
        let mut images = AppImages::default();
        let image = image_of(&f);
        let mut first = exec(RUNTIME, uid, image, id_of(&f.image), image, IMAGE_EXEC_NS);
        images.note(f.proc.path(), &mut first);
        let mut e = exec(RUNTIME, uid, MOUNT, (FUSE_DEV, 1), &apprun(), 50);
        images.note(f.proc.path(), &mut e);
        assert!(!user_image(&e));
        // the image file on a FUSE filesystem (its device a FUSE mount's)
        let f = fixture();
        let (dev, _) = id_of(&f.image);
        table_plus(
            f.proc.path(),
            &format!(
                "70 22 {}:{} / /home/u/fuse rw,nosuid - fuse.sshfs h: rw,user_id={uid}",
                dev >> 20,
                dev & 0xf_ffff
            ),
        );
        assert!(!run(&mut AppImages::default(), &f, uid, &apprun()));
    }

    /// The daemon is the image by its `exe` link's text (never a file to
    /// `stat` first) and in PID 1's mount namespace: a link to the image by
    /// another path, a daemon in a namespace of its own, are not it.
    #[test]
    fn the_daemon_runs_the_image_at_its_path_in_pid_1_s_namespace() {
        let f = fixture();
        let alias = f._files.path().join("alias.AppImage");
        symlink(&f.image, &alias).unwrap();
        daemon(f.proc.path(), DAEMON, &alias, me(), "S", FRESH, true);
        assert!(!run(&mut AppImages::default(), &f, me(), &apprun()));
        let f = fixture();
        process(f.proc.path(), DAEMON, "mnt:[4026532999]");
        assert!(!run(&mut AppImages::default(), &f, me(), &apprun()));
    }

    /// The ties stay bounded: a full table is emptied before a new tie.
    #[test]
    fn the_ties_are_bounded() {
        let f = fixture();
        let mut images = AppImages::default();
        for d in 0..TIED_MAX as u64 {
            images.tied.insert(
                1_000 + d,
                Tied {
                    mount_id: d,
                    uid: 0,
                    image: (0, 0),
                    image_path: PathBuf::new(),
                    daemon: 0,
                    daemon_ticks: 0,
                },
            );
        }
        assert!(run(&mut images, &f, me(), &apprun()));
        assert_eq!(images.tied.len(), 1);
    }

    /// An exec with no start (an older record) or a path not yet mapped to
    /// the host's view is never tied, nor remembered as an image.
    #[test]
    fn an_exec_without_its_start_or_its_view_does_not_tie() {
        for case in 0..2 {
            let f = fixture();
            let mut images = AppImages::default();
            let image = image_of(&f);
            let mut first = exec(RUNTIME, me(), image, id_of(&f.image), image, IMAGE_EXEC_NS);
            images.note(f.proc.path(), &mut first);
            let mut e = exec(RUNTIME, me(), &apprun(), (FUSE_DEV, 2), &apprun(), 50);
            if let Event::ProcessSpawn { start_ns, exe, .. } = &mut e {
                if case == 0 {
                    *start_ns = 0;
                } else {
                    exe.root = (1, 1);
                }
            }
            images.note(f.proc.path(), &mut e);
            assert!(!user_image(&e), "{case}");
        }
        // an image exec with no start is not remembered
        let f = fixture();
        let mut images = AppImages::default();
        let image = image_of(&f);
        let mut first = exec(RUNTIME, me(), image, id_of(&f.image), image, IMAGE_EXEC_NS);
        if let Event::ProcessSpawn { start_ns, .. } = &mut first {
            *start_ns = 0;
        }
        images.note(f.proc.path(), &mut first);
        assert!(images.ran.is_empty());
    }

    /// The runtime is never its own daemon (a process that executed into
    /// the mount runs the mount's file, not the image), and a system tree's
    /// exec is never remembered as an image (the system's execs, root's).
    #[test]
    fn the_runtime_is_not_its_own_daemon_nor_a_system_file_an_image() {
        let f = fixture();
        std::fs::remove_dir_all(f.proc.path().join(DAEMON.to_string())).unwrap();
        daemon(f.proc.path(), RUNTIME, &f.image, me(), "S", FRESH, true);
        assert!(!run(&mut AppImages::default(), &f, me(), &apprun()));
        let mut images = AppImages::default();
        let mut e = exec(RUNTIME, me(), "/usr/bin/tool", (1, 1), "/usr/bin/tool", 1);
        images.note(f.proc.path(), &mut e);
        assert!(images.ran.is_empty());
    }

    /// The check reads the newest exec remembered for its pid: an older
    /// process at the same pid (another start) is not the one checked.
    #[test]
    fn the_check_reads_the_pid_s_newest_exec() {
        let f = fixture();
        let mut images = AppImages::default();
        let image = image_of(&f);
        let (dev, ino) = id_of(&f.image);
        images.remember(
            RUNTIME,
            Ran {
                start: 1_000_000_000_000,
                dev,
                ino,
                path: f.image.clone(),
                exec_ns: IMAGE_EXEC_NS,
                seq: 0,
            },
        );
        let mut first = exec(RUNTIME, me(), image, (dev, ino), image, IMAGE_EXEC_NS);
        images.note(f.proc.path(), &mut first);
        let mut c = check(RUNTIME, &apprun(), FUSE_DEV, &apprun());
        images.note(f.proc.path(), &mut c);
        assert!(user_image(&c));
        // an exec of another process at that pid (another start) does not
        // read the earlier process's image
        let f = fixture();
        let (dev, ino) = id_of(&f.image);
        let mut images = AppImages::default();
        images.remember(
            RUNTIME,
            Ran {
                start: 1_000_000_000_000,
                dev,
                ino,
                path: f.image.clone(),
                exec_ns: IMAGE_EXEC_NS,
                seq: 0,
            },
        );
        let mut e = exec(RUNTIME, me(), &apprun(), (FUSE_DEV, 2), &apprun(), 50);
        images.note(f.proc.path(), &mut e);
        assert!(!user_image(&e));
        assert!(images.ran.is_empty(), "taken");
    }

    /// The review of #564 (F1): the type-2 runtime serves the file its
    /// documented `TARGET_APPIMAGE` names, not its own image. A user's legit
    /// image run with `TARGET_APPIMAGE=/tmp/x.AppImage`: its daemon (`exe` the
    /// image, `/dev/fuse`) holds the staged squashfs, not the image — no tie,
    /// the AppImage in `/tmp` stays judged. Nor with the image held as well (a
    /// descriptor inherited) and another file a staged image could be served
    /// from: under a staging directory (the text, whatever the filesystem),
    /// unlinked, on a memory filesystem, on a FUSE filesystem (never
    /// `stat`ed), of no mount of PID 1's table (a `memfd`). A log in the home,
    /// a pipe, a device, held beside the image, are no image: the tie holds.
    #[test]
    fn a_daemon_serving_another_file_than_its_image_is_no_tie() {
        let staged_dir = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
        let staged = staged_dir.path().join("x.AppImage");
        std::fs::write(&staged, b"\x7fELF runtime + squashfs").unwrap();
        assert!(is_staging_path(staged.to_str().unwrap()));
        // TARGET_APPIMAGE: the staged file in place of the image (tmpfs /tmp,
        // and /tmp on the root filesystem)
        for mnt in [30, 22] {
            let f = fixture();
            hold(f.proc.path(), DAEMON, 4, &staged, mnt);
            assert!(
                !run(&mut AppImages::default(), &f, me(), &apprun()),
                "TARGET_APPIMAGE {mnt}"
            );
        }
        // the daemon serves another file of the home, not its image (nor
        // holds it): no tie either
        let f = fixture();
        hold(f.proc.path(), DAEMON, 4, &home_file(&f), 22);
        assert!(
            !run(&mut AppImages::default(), &f, me(), &apprun()),
            "TARGET_APPIMAGE in the home"
        );
        // the image held too, and a file a staged image could be served from
        let unlinked =
            tempfile::tempfile_in(std::env::current_exe().unwrap().parent().unwrap()).unwrap();
        let unlinked_fd = format!(
            "/proc/self/fd/{}",
            std::os::fd::AsRawFd::as_raw_fd(&unlinked)
        );
        // (the file, `None` for a log in the fixture's home; its mount)
        for (name, file, mnt) in [
            ("staged on /", Some(staged.clone()), 22),
            ("unlinked", Some(PathBuf::from(&unlinked_fd)), 22),
            ("memory", None, 40),
            ("fuse", None, 45),
            ("no mount", None, 999),
        ] {
            let f = fixture();
            table_plus(
                f.proc.path(),
                "40 22 0:41 / /run/user/1000 rw,nosuid,nodev - tmpfs tmpfs rw",
            );
            let target = file.unwrap_or_else(|| home_file(&f));
            hold(f.proc.path(), DAEMON, 5, &target, mnt);
            assert!(
                !run(&mut AppImages::default(), &f, me(), &apprun()),
                "{name}"
            );
        }
        // the image, beside a log in the home, a pipe, a device: the tie holds
        let f = fixture();
        hold(f.proc.path(), DAEMON, 1, &home_file(&f), 22);
        // (`/dev` a tmpfs, as in a container)
        table_plus(f.proc.path(), "41 22 0:5 / /dev rw,nosuid - tmpfs tmpfs rw");
        hold(f.proc.path(), DAEMON, 2, Path::new("/dev/null"), 41);
        symlink("pipe:[4242]", f.proc.path().join(format!("{DAEMON}/fd/0"))).unwrap();
        assert!(run(&mut AppImages::default(), &f, me(), &apprun()));
        // and the tie ends when the daemon no longer holds its image
        let mut images = AppImages::default();
        let f = fixture();
        assert!(run(&mut images, &f, me(), &apprun()));
        hold(f.proc.path(), DAEMON, 4, &staged, 30);
        let mut e = exec(
            RUNTIME + 1,
            me(),
            &apprun(),
            (FUSE_DEV, 2),
            "/proc/self/exe",
            60,
        );
        images.note(f.proc.path(), &mut e);
        assert!(!user_image(&e), "still tied");
    }

    /// A regular file in the fixture's home (beside the image).
    fn home_file(f: &Fixture) -> PathBuf {
        let p = f._files.path().join("app.log");
        std::fs::write(&p, b"log").unwrap();
        p
    }

    /// The review of #564 (F5): a daemon a tracer holds (`PTRACE_SEIZE`
    /// leaves it running, state `S`) is not the runtime's as it was: its
    /// tracer may run any code in it.
    #[test]
    fn a_traced_daemon_is_no_tie() {
        let f = fixture();
        let d = f.proc.path().join(DAEMON.to_string());
        let status = std::fs::read_to_string(d.join("status")).unwrap();
        std::fs::write(
            d.join("status"),
            status.replace("TracerPid:\t0", "TracerPid:\t4242"),
        )
        .unwrap();
        assert!(!run(&mut AppImages::default(), &f, me(), &apprun()));
        // no `TracerPid:` line at all: not known untraced
        std::fs::write(d.join("status"), status.replace("TracerPid:\t0\n", "")).unwrap();
        assert!(!run(&mut AppImages::default(), &f, me(), &apprun()));
    }

    /// The image's path is never read through a FUSE mount (a mount on one
    /// of its directories since its exec: its daemon answers the lookup, or
    /// never) — the file there is no longer the image anyway.
    #[test]
    fn the_image_s_path_is_never_read_through_a_fuse_mount() {
        let f = fixture();
        let uid = me();
        table_plus(
            f.proc.path(),
            &format!(
                "70 22 0:88 / {} rw,nosuid - fuse.sshfs h: rw,user_id={uid},allow_other",
                f._files.path().display()
            ),
        );
        assert!(!run(&mut AppImages::default(), &f, uid, &apprun()));
    }

    /// The review of #564 (F4): an exec of a file on no anonymous device
    /// (FUSE's device is one: a disk's is not) is never read further — the
    /// mount table is not read for it, even in the image's shape.
    #[test]
    fn only_an_anonymous_device_is_read_as_an_image() {
        let f = fixture();
        let uid = me();
        std::fs::write(
            f.proc.path().join("1/mountinfo"),
            format!(
                "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n30 22 0:30 / /tmp rw - tmpfs tmpfs rw\n\
                 61 30 8:{FUSE_DEV} / {MOUNT} ro,nosuid - fuse.App.AppImage x ro,user_id={uid}\n"
            ),
        )
        .unwrap();
        let mut images = AppImages::default();
        let image = image_of(&f);
        let mut first = exec(RUNTIME, uid, image, id_of(&f.image), image, IMAGE_EXEC_NS);
        images.note(f.proc.path(), &mut first);
        let dev = (8 << 20) | FUSE_DEV;
        let mut e = exec(RUNTIME, uid, &apprun(), (dev, 2), &apprun(), 50);
        images.note(f.proc.path(), &mut e);
        assert!(!user_image(&e));
        assert!(images.tied.is_empty());
    }
}
