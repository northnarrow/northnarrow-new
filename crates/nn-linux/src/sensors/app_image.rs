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
//!     or after that exec, holds `/dev/fuse` open and is neither stopped,
//!     traced nor exited: the runtime's FUSE daemon.
//! - **tied** — a later exec of a file on that filesystem (`AppRun`'s exec
//!   of the program, a zygote's `/proc/self/exe`, a helper) by the same
//!   user, while the mount (its id and device) is still there and still such
//!   a mount and its daemon (its start) still serves it, holding
//!   `/dev/fuse`, running that image.
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
//! or `/dev/shm` (its image is staged), one another user owns, one on a
//! FUSE or memory filesystem; an AppImage extracted (`--appimage-extract-
//! and-run`, or no FUSE): a writable copy in `/tmp`; tracepoint mode (no
//! LSM identity). And whatever the program then does — a credential read,
//! a file staged and executed, persistence, a shell with a socket — is
//! judged as any user program's: the flag takes only the staging
//! directory away.
//!
//! Residual, said: a malicious AppImage the user runs is a user program,
//! judged by its behaviour. The kernel ties no FUSE mount to the process
//! that serves it in a way `/proc` shows (the connection's `/dev/fuse`
//! file names no device), so the pump ties the mount to its image through
//! the exec that entered it and a daemon of the image started for it: a
//! user who stops its own AppImage's runtime after the mount, moves that
//! mount aside (from a mount namespace of its own) and mounts its own
//! read-only filesystem at the path the runtime then executes, gets that
//! filesystem's programs judged as the image's — as programs it could run
//! from its home, which it can write. A kernel record of the process the
//! connection's file is handed to (`security_file_receive`) would close it.

use std::collections::HashMap;
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
    ran: HashMap<(u32, u64), Ran>,
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
        // an exec replaces it; a check (its exec not done) reads it
        let before = match start_ns {
            Some(start) => self.ran.remove(&(pid, start)),
            None => self.ran_by(proc_root, pid),
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
                    (pid, start),
                    Ran {
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
        let (start, ran) = self
            .ran
            .iter()
            .filter(|((p, _), _)| *p == pid)
            .max_by_key(|(_, r)| r.seq)
            .map(|((_, s), r)| (*s, r.clone()))?;
        let stat =
            crate::state_read::read_state(proc_root.join(pid.to_string()).join("stat")).ok()?;
        let ticks = crate::response::proc_ref::stat_start_ticks(&stat)?;
        crate::response::proc_ref::started_at(ticks, start).then_some(ran)
    }

    fn remember(&mut self, key: (u32, u64), mut ran: Ran) {
        if !self.ran.contains_key(&key) && self.ran.len() >= RAN_MAX {
            if let Some(oldest) = self.ran.iter().min_by_key(|(_, r)| r.seq).map(|(k, _)| *k) {
                self.ran.remove(&oldest);
            }
        }
        self.seq += 1;
        ran.seq = self.seq;
        self.ran.insert(key, ran);
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
    // regular file on no FUSE filesystem
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
    let (daemon, daemon_ticks) = find_daemon(proc_root, pid, uid, before)?;
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
    daemon_facts(proc_root, &d, uid, t.image, &t.image_path)
        .is_some_and(|ticks| ticks == t.daemon_ticks)
}

/// A daemon of the image `before` for `pid`'s exec: a process (not `pid`)
/// that runs that image as `uid`, started at or after its exec, serving
/// ([`daemon_facts`]). Its pid and `/proc` start.
fn find_daemon(proc_root: &Path, pid: u32, uid: u32, before: &Ran) -> Option<(u32, u64)> {
    let image = (before.dev, before.ino);
    std::fs::read_dir(proc_root).ok()?.flatten().find_map(|e| {
        let d: u32 = e.file_name().to_str()?.parse().ok()?;
        if d == pid {
            return None;
        }
        let ticks = daemon_facts(proc_root, &e.path(), uid, image, &before.path)?;
        crate::response::proc_ref::started_since(ticks, before.exec_ns).then_some((d, ticks))
    })
}

/// The process `dir` (`/proc/<pid>`) runs the image `image` (its `exe`
/// link names `image_path`, and leads to that device and inode) as `uid`
/// (real), in PID 1's mount namespace, is not stopped, traced or exited,
/// and holds `/dev/fuse` open: its `/proc` start.
fn daemon_facts(
    proc_root: &Path,
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
    let real_uid: u32 = status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    if real_uid != uid || !super::exec_facts::same_mount_namespace(proc_root, dir) {
        return None;
    }
    let stat = crate::state_read::read_state(dir.join("stat")).ok()?;
    let state = stat.rsplit_once(')')?.1.split_whitespace().next()?;
    if matches!(state, "T" | "t" | "Z" | "X" | "x") {
        return None;
    }
    let ticks = crate::response::proc_ref::stat_start_ticks(&stat)?;
    let holds_fuse = std::fs::read_dir(dir.join("fd")).ok()?.flatten().any(|fd| {
        std::fs::read_link(fd.path()).is_ok_and(|t| t.as_os_str() == OsStr::new("/dev/fuse"))
    });
    holds_fuse.then_some(ticks)
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
    /// holding `/dev/fuse` when `fuse`.
    fn daemon(root: &Path, pid: u32, image: &Path, uid: u32, state: &str, ticks: u64, fuse: bool) {
        let d = process(root, pid, INIT_NS);
        let _ = std::fs::remove_file(d.join("exe"));
        symlink(image, d.join("exe")).unwrap();
        std::fs::write(
            d.join("status"),
            format!("Name:\tApp.AppImage\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"),
        )
        .unwrap();
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
        symlink(if fuse { "/dev/fuse" } else { "/dev/null" }, d.join("fd/3")).unwrap();
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
            dev: 1,
            ino: n,
            path: PathBuf::from("/home/u/x"),
            exec_ns: n,
            seq: 0,
        };
        for n in 0..(RAN_MAX as u64 + 10) {
            images.remember((n as u32, 1), ran(n));
        }
        assert_eq!(images.ran.len(), RAN_MAX);
        assert!(!images.ran.contains_key(&(0, 1)));
        assert!(images.ran.contains_key(&(RAN_MAX as u32 + 9, 1)));
        // a process's later exec replaces its earlier one, and is the newest
        images.remember((5, 1), ran(1));
        images.remember((5, 1), ran(2));
        assert_eq!(images.ran.len(), RAN_MAX);
        assert_eq!(images.ran[&(5, 1)].ino, 2);
        images.remember((u32::MAX, 1), ran(3));
        assert!(images.ran.contains_key(&(5, 1)), "not the oldest");
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
            (RUNTIME, 1_000_000_000_000),
            Ran {
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
    }
}
