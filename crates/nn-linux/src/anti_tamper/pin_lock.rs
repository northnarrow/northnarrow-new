//! Lot 359 (the re-check 3 of #567, N4): the lock of the agent's pin
//! directory.
//!
//! The mount guard judges an unmount by the subtree it reads at the hook
//! (`common::mount_guard::umount_below`). The hook runs before the kernel
//! takes the namespace lock, so that subtree can grow before the kernel
//! collects it (an rbind grafted meanwhile), and the walk reads only its
//! bound: a lazy unmount could still take the host's bpffs, and the pins
//! with it, in any namespace. The kernel's own rule closes the rbind
//! variants of both for the pins: `propagate_umount()` never takes a mount
//! that keeps a child that is not itself unmounted. So the pin directory
//! is bound onto itself, then made unbindable (which makes it private
//! too) — the lock — as the child of the host's bpffs in PID 1's mount
//! namespace: an rbind never copies an unbindable mount, and the host's
//! bpffs keeps that child whatever an rbind copy's unmount takes.
//! `/sys/fs/cgroup` has no such child: it stays behind the walk.
//!
//! Who makes it, and why there: the lock must be the host's bpffs's own
//! child (that is the mount the propagation would take), and the agent's
//! unit runs in a namespace of its own, without `CAP_SYS_ADMIN` or
//! `CAP_SYS_CHROOT` (no `setns(2)` into PID 1's namespace) and with
//! `mount(2)` refused by its system call filter — on purpose, for its whole
//! life. So the lock is a step of the unit's start, before the agent's
//! process exists: `ExecStartPre=-+…/northnarrow-agent --pin-lock` (`+`:
//! outside the sandbox, with full privileges — the step enters PID 1's
//! mount namespace itself, `setns(2)`, the unit's `LogNamespace=` giving
//! it the unit's own; `-`: its failure does not fail the start), before
//! the load writes a pin ([`step_main`]). It is
//! kept across restarts (one already in place, with the right flags, is
//! reused), gone at a reboot (the bpffs is new) and made again by the next
//! start. The integrity round makes it again when it is lost or changed,
//! through a transient unit running the same step ([`remake`]), a few
//! times within its deadline, then with a back-off over the rounds
//! ([`Keeper`]); and makes it when the start found none (the review of
//! #569, F3).
//!
//! It passes the mount guard only as its maker's own two steps in PID 1's
//! namespace (`common::mount_guard::lock_maker`, `lock_bind`,
//! `lock_step_at`: the self-bind, then `MS_UNBINDABLE` — never
//! `MS_PRIVATE`, which makes a lock in place bindable again); every other
//! mount, unmount, move or change of propagation of it, and a recursive
//! change above it in PID 1's namespace that would make it bindable, is
//! refused and signed High. The uninstaller and the signed
//! trusted-installer window unmount it before they remove the directory.
//!
//! What it does not cover, each signed at the next integrity round
//! (about 30 s), where it can be seen: `mount_setattr(2)` has no LSM hook,
//! so root can clear the lock's flags through it; a raw mount namespace
//! holds its own copy of the lock, and a move of its copy of `/sys` is
//! judged by its target only; the units' namespaces never have the lock.
//!
//! Fail-safe: a lock that cannot be made (a kernel without `open_tree(2)`,
//! an error) is a signed degradation of the start ([`at_start`]), and
//! #567's walk remains the defence.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::mountinfo::MountEntry;

/// The agent binary's argument that runs the step (the unit's
/// `ExecStartPre=-+`, the integrity round's transient unit).
pub const STEP_ARG: &str = "--pin-lock";

/// Where the host's bpffs is mounted.
pub const BPF_ROOT: &str = "/sys/fs/bpf";

/// The transient unit the integrity round runs the step in.
pub const REMAKE_UNIT: &str = "northnarrow-pin-lock";

/// What a degraded start lacks, for the signed degradation.
pub const ABSENT_EFFECT: &str = "the pin directory is not locked: an unmount racing the mount \
     guard's walk of its subtree (an rbind grafted while it waits on the namespace lock), or one \
     whose subtree is wider or deeper than the walk reads, can take the host's bpffs and the pins \
     with it; the walk (#567) remains the defence";

/// A mount `m` of the table `t` is the lock of the pin directory
/// `pin_root`: a bpffs at `pin_root` that is a bind of its parent's
/// directory onto itself (`mountinfo::is_self_bind`), its parent the bpffs
/// at [`BPF_ROOT`] whole — or another lock, stacked.
pub fn is_lock(t: &[MountEntry], m: &MountEntry, pin_root: &Path) -> bool {
    let mut cur = m;
    for _ in 0..=t.len() {
        if cur.mount_point != pin_root || cur.fstype.as_bytes() != b"bpf" {
            return false;
        }
        let Some(parent) = t.iter().find(|p| p.id == cur.parent && p.id != cur.id) else {
            return false;
        };
        if parent.fstype.as_bytes() != b"bpf" || !crate::mountinfo::is_self_bind(cur, parent) {
            return false;
        }
        if parent.mount_point == Path::new(BPF_ROOT) {
            return parent.root == Path::new("/");
        }
        cur = parent;
    }
    false
}

/// The lock as PID 1's table shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// In place: private, unbindable, the child of the bpffs at
    /// [`BPF_ROOT`] (its mount id).
    InPlace(u64),
    /// Not there (why).
    Missing(String),
    /// There, its propagation changed (its id, what the table shows).
    Propagation(u64, String),
    /// Something else is not the lock's: not a self-bind, a mount over it,
    /// no bpffs at [`BPF_ROOT`].
    Changed(String),
}

impl State {
    /// One sentence for a record.
    pub fn describe(&self) -> String {
        match self {
            State::InPlace(id) => format!("in place (mount {id}, private, unbindable)"),
            State::Missing(why) => format!("missing: {why}"),
            State::Propagation(id, now) => {
                format!(
                    "its propagation changed (mount {id}: \"{now}\", not private and unbindable)"
                )
            }
            State::Changed(why) => format!("changed: {why}"),
        }
    }
}

/// The lock of `pin_root` in the mount table `text` (PID 1's: a step run in
/// PID 1's namespace reads its own).
pub fn state_in(text: &[u8], pin_root: &Path) -> State {
    let t = crate::mountinfo::parse(text).entries;
    let Some(bpffs) = t.iter().rfind(|m| m.mount_point == Path::new(BPF_ROOT)) else {
        return State::Missing(format!("no mount at {BPF_ROOT}"));
    };
    if bpffs.fstype.as_bytes() != b"bpf" || bpffs.root != Path::new("/") {
        return State::Changed(format!(
            "the mount on top at {BPF_ROOT} is not a whole bpffs ({}, root {})",
            bpffs.fstype.to_string_lossy(),
            bpffs.root.display()
        ));
    }
    let Some(lock) = t
        .iter()
        .find(|m| m.parent == bpffs.id && m.mount_point == pin_root)
    else {
        return State::Missing(format!(
            "no mount at {} on the bpffs at {BPF_ROOT} (mount {})",
            pin_root.display(),
            bpffs.id
        ));
    };
    if !is_lock(&t, lock, pin_root) {
        return State::Changed(format!(
            "the mount at {} ({}, root {}) is not the directory bound onto itself",
            pin_root.display(),
            lock.fstype.to_string_lossy(),
            lock.root.display()
        ));
    }
    // a mount laid over it (anything but another lock)
    let mut top = lock;
    while let Some(over) = t
        .iter()
        .find(|m| m.parent == top.id && m.mount_point == pin_root)
    {
        if !is_lock(&t, over, pin_root) {
            return State::Changed(format!(
                "a mount over the lock at {} ({}, source {}, root {})",
                pin_root.display(),
                over.fstype.to_string_lossy(),
                over.source.to_string_lossy(),
                over.root.display()
            ));
        }
        top = over;
    }
    let attrs = crate::mount_attrs::attrs_of(text);
    let prop = attrs
        .get(&lock.id)
        .map(|(_, a)| a.propagation.clone())
        .unwrap_or_default();
    if propagation_is_locked(&prop) {
        State::InPlace(lock.id)
    } else {
        State::Propagation(lock.id, prop)
    }
}

/// A `mountinfo` line's optional fields name a private, unbindable mount:
/// `unbindable`, and no `shared:` or `master:` group.
pub fn propagation_is_locked(optional: &str) -> bool {
    let f: Vec<&str> = optional.split_whitespace().collect();
    f.contains(&"unbindable")
        && !f
            .iter()
            .any(|x| x.starts_with("shared:") || x.starts_with("master:"))
}

/// What a step did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// In place already, with the right flags: reused (its id).
    Reused(u64),
    /// Made now (its id).
    Made(u64),
    /// There with its propagation changed: made private and unbindable
    /// again (its id).
    Repaired(u64),
    /// Not made (why): the walk remains the defence.
    Failed(String),
}

impl Outcome {
    /// The step's one line (its journal line; the record's detail).
    pub fn line(&self) -> String {
        match self {
            Outcome::Reused(id) => format!("pin lock: reused (mount {id})"),
            Outcome::Made(id) => format!("pin lock: made (mount {id})"),
            Outcome::Repaired(id) => format!("pin lock: repaired (mount {id})"),
            Outcome::Failed(why) => format!("pin lock: NOT made: {why}"),
        }
    }

    /// The lock is in place after the step.
    pub fn in_place(&self) -> bool {
        !matches!(self, Outcome::Failed(_))
    }
}

/// `open_tree(2)`'s `OPEN_TREE_CLONE` (`include/uapi/linux/mount.h`).
const OPEN_TREE_CLONE: libc::c_uint = 1;
/// `move_mount(2)`'s `MOVE_MOUNT_F_EMPTY_PATH`.
const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x4;

fn cpath(p: &Path) -> io::Result<CString> {
    CString::new(p.as_os_str().as_bytes()).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

/// The directory `dir` bound onto itself, the new API's way: a clone of it
/// (`open_tree(OPEN_TREE_CLONE)`, not recursive, no symbolic link followed)
/// attached at `dir` (`move_mount(2)`) — what the guard compares by the
/// kernel's objects (`common::mount_guard::lock_bind`).
fn bind_onto_itself(dir: &Path) -> io::Result<()> {
    let c = cpath(dir)?;
    // SAFETY: a NUL-terminated path; the flags are the call's own.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_open_tree,
            libc::AT_FDCWD,
            c.as_ptr(),
            OPEN_TREE_CLONE
                | libc::O_CLOEXEC as libc::c_uint
                | libc::AT_SYMLINK_NOFOLLOW as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a new descriptor the kernel gave this call alone.
    let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    let empty = c"";
    // SAFETY: a live descriptor, two NUL-terminated paths.
    let r = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            fd.as_raw_fd(),
            empty.as_ptr(),
            libc::AT_FDCWD,
            c.as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `mount(NULL, dir, NULL, flags, NULL)`: a change of propagation of the
/// mount on top at `dir`.
fn propagation(dir: &Path, flags: u64) -> io::Result<()> {
    let c = cpath(dir)?;
    // SAFETY: a NUL-terminated path, no source, type or data.
    let r = unsafe {
        libc::mount(
            std::ptr::null(),
            c.as_ptr(),
            std::ptr::null(),
            flags as libc::c_ulong,
            std::ptr::null(),
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The mount namespace of `/proc/<pid>` (`ns/mnt`'s inode), beneath the
/// `/proc` root (`kernel_roots`).
fn mnt_ns(pid: &str) -> io::Result<u64> {
    use std::os::unix::fs::MetadataExt;
    Ok(antitamper_bpf::kernel_roots::metadata(format!("/proc/{pid}/ns/mnt"))?.ino())
}

/// This thread into PID 1's mount namespace (`setns(2)` of
/// `/proc/1/ns/mnt`, after `unshare(CLONE_FS)`: the kernel refuses a mount
/// namespace to a thread whose file-system information another shares).
fn enter_host_namespace() -> io::Result<()> {
    // SAFETY: no argument but the flag; this thread's own state.
    if unsafe { libc::unshare(libc::CLONE_FS) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let ns = antitamper_bpf::kernel_roots::open(
        Path::new("/proc/1/ns/mnt"),
        libc::O_RDONLY | libc::O_CLOEXEC,
    )?;
    // SAFETY: a live descriptor of a mount namespace.
    if unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNS) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// PID 1's mount table, as this process reads it (beneath the `/proc`
/// root, bounded: `mountinfo::read_bytes`).
fn host_table() -> io::Result<Vec<u8>> {
    crate::mountinfo::read_bytes(Path::new("/proc/1/mountinfo"))
}

/// The lock made, reused or repaired at `pin_root` — in PID 1's mount
/// namespace only, by a privileged process (the unit's `ExecStartPre=+`
/// step): the directory made if it is not there (mode 0700, never through
/// a symbolic link), then the self-bind, `MS_UNBINDABLE`, and the table
/// read again.
pub fn step(pin_root: &Path) -> Outcome {
    let (Ok(me), Ok(host)) = (mnt_ns("self"), mnt_ns("1")) else {
        return Outcome::Failed("the mount namespaces cannot be read".into());
    };
    if me != host {
        // the unit's own namespace (`LogNamespace=` gives the unit one
        // whatever the `+`): this thread enters PID 1's, as the unit's
        // privileged step may (lot 359's first lab round: `+` alone ran it
        // in the unit's namespace)
        if let Err(e) = enter_host_namespace() {
            return Outcome::Failed(format!(
                "not run in PID 1's mount namespace (this one: {me}, PID 1's: {host}), and it \
                 cannot be entered: {e} — the lock must be the host's bpffs's own child"
            ));
        }
        match mnt_ns("self") {
            Ok(now) if now == host => {}
            Ok(now) => {
                return Outcome::Failed(format!(
                    "PID 1's mount namespace entered, yet this one is {now} (PID 1's: {host})"
                ));
            }
            Err(e) => return Outcome::Failed(format!("/proc/self/ns/mnt: {e}")),
        }
    }
    let t = match host_table() {
        Ok(t) => t,
        Err(e) => return Outcome::Failed(format!("/proc/1/mountinfo: {e}")),
    };
    match state_in(&t, pin_root) {
        State::InPlace(id) => return Outcome::Reused(id),
        State::Changed(why) => return Outcome::Failed(why),
        State::Propagation(id, _) => {
            if let Err(e) = lock_flags(pin_root) {
                return Outcome::Failed(e);
            }
            return match host_table().map(|t| state_in(&t, pin_root)) {
                Ok(State::InPlace(now)) if now == id => Outcome::Repaired(id),
                Ok(s) => Outcome::Failed(format!("after the repair, {}", s.describe())),
                Err(e) => Outcome::Failed(format!("/proc/1/mountinfo: {e}")),
            };
        }
        State::Missing(_) => {}
    }
    if let Err(why) = pin_dir(pin_root) {
        return Outcome::Failed(why);
    }
    if let Err(e) = bind_onto_itself(pin_root) {
        let why = if e.raw_os_error() == Some(libc::ENOSYS) {
            "the kernel has no open_tree(2)/move_mount(2) (5.2 and later)".to_string()
        } else {
            format!("the self-bind of {}: {e}", pin_root.display())
        };
        return Outcome::Failed(why);
    }
    if let Err(e) = lock_flags(pin_root) {
        return Outcome::Failed(e);
    }
    match host_table().map(|t| state_in(&t, pin_root)) {
        Ok(State::InPlace(id)) => Outcome::Made(id),
        Ok(s) => Outcome::Failed(format!("after the bind, {}", s.describe())),
        Err(e) => Outcome::Failed(format!("/proc/1/mountinfo: {e}")),
    }
}

/// The lock's change of propagation: [`LOCK_FLAGS`] alone.
fn lock_flags(pin_root: &Path) -> Result<(), String> {
    propagation(pin_root, LOCK_FLAGS)
        .map_err(|e| format!("MS_UNBINDABLE on {}: {e}", pin_root.display()))
}

/// The one change of propagation the step makes: `MS_UNBINDABLE`, which
/// makes the mount private too (the kernel's `change_mnt_propagation()`
/// leaves its peer group and its master) — the review of #569 (F1c): no
/// `MS_PRIVATE` step, which clears `MNT_UNBINDABLE` of a lock in place. The
/// mount guard lets this one through for the maker only
/// (`common::mount_guard::lock_step`).
pub const LOCK_FLAGS: u64 = common::mount_guard::MS_UNBINDABLE;

/// The pin directory there to bind: made (0700) when absent, refused when
/// it is a symbolic link or not a directory, on a bpffs at [`BPF_ROOT`].
fn pin_dir(pin_root: &Path) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;
    if !is_bpffs(Path::new(BPF_ROOT)) {
        return Err(format!("{BPF_ROOT} is not a bpffs"));
    }
    match std::fs::symlink_metadata(pin_root) {
        Ok(m) if m.file_type().is_dir() => Ok(()),
        Ok(_) => Err(format!(
            "{} is not a directory (a symbolic link is never followed)",
            pin_root.display()
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => std::fs::DirBuilder::new()
            .mode(0o700)
            .create(pin_root)
            .map_err(|e| format!("making {}: {e}", pin_root.display())),
        Err(e) => Err(format!("{}: {e}", pin_root.display())),
    }
}

fn is_bpffs(p: &Path) -> bool {
    let Ok(c) = cpath(p) else {
        return false;
    };
    // SAFETY: `statfs` is plain old data, valid when zeroed.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: a NUL-terminated path and a writable buffer.
    let ok = unsafe { libc::statfs(c.as_ptr(), &mut st) } == 0;
    ok && st.f_type as u64 == u64::from(common::mount_guard::BPF_FS_MAGIC)
}

/// The step as the agent binary's one-shot mode ([`STEP_ARG`]): its line
/// on standard output (the unit's journal), exit 0 when the lock is in
/// place, 1 otherwise (the unit's `-` keeps the start going).
pub fn step_main() -> i32 {
    let out = step(Path::new(antitamper_bpf::DEFAULT_BPFFS_ROOT));
    println!("{}", out.line());
    i32::from(!out.in_place())
}

/// The lock as this start found it in PID 1's table (the step ran just
/// before the agent's process), for the integrity round: `Some(true)` it
/// was in place, `Some(false)` it was not (or the table was not read).
static AT_START: OnceLock<bool> = OnceLock::new();

/// The start's check of the lock: `None` when it is in place (recorded for
/// the integrity round), else the signed degradation's sentence.
pub fn at_start(host_table: &[u8], pin_root: &Path) -> Option<String> {
    let s = state_in(host_table, pin_root);
    let in_place = matches!(s, State::InPlace(_));
    let _ = AT_START.set(in_place);
    (!in_place).then(|| format!("pin lock: {} at the start ({ABSENT_EFFECT})", s.describe()))
}

/// The start could not read PID 1's table (a signed degradation): the
/// lock is not known to be in place.
pub fn at_start_unread() {
    let _ = AT_START.set(false);
}

/// The integrity round's finding kinds (High).
pub const MISSING: &str = "pin_lock_missing";
pub const CHANGED: &str = "pin_lock_changed";

/// Lot 367 (pre-alpha Phase 3-bis, F3b-6): the degradation source of a lock
/// the integrity round found lost or changed and could not make again — in
/// `nn-admin status` while it is not in place, withdrawn once a round finds
/// it in place (its signed findings stay in the chain).
pub const DEGRADATION_SOURCE: &str = "pin_lock";

/// The start's degradations of the lock (source `anti_tamper`) begin so:
/// withdrawn too once a round finds the lock in place.
pub const START_DEGRADATION_PREFIX: &str = "pin lock:";

/// What the status says of the lock after a round: `Some(line)` while the
/// round knows it is not in place (a degradation), `None` once a round found
/// it in place or made it again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusLine {
    /// The lock is not in place: the degradation's one stable line.
    NotInPlace(String),
    /// The lock is in place: the degradations of it withdrawn.
    InPlace,
    /// The round did not look (it does not watch the lock).
    Unwatched,
}

/// How many times one integrity round asks for the lock again, all within
/// [`REMAKE_DEADLINE`] (the review of #569: one failure no longer leaves it
/// missing until the next round).
pub const REMAKE_TRIES: u32 = 3;

/// The pause after a failed attempt, times its number (1 s, then 2 s).
pub const REMAKE_PAUSE: std::time::Duration = std::time::Duration::from_secs(1);

/// After rounds whose attempts all failed, the rounds left out before the
/// next attempt: 1, 3, then [`MAX_SKIP`] (an attempt about every 4 minutes)
/// — a persistent failure never holds every round.
pub const MAX_SKIP: u32 = 7;

/// The integrity round's keeper of the lock (lot 359; the review of #569,
/// F3 and F5): it watches the lock the start found in place, or the one it
/// made itself — and, in the agent's unit, one the start did not find (the
/// unit's step should have made it: a transient failure, a refusal). A lock
/// missing or changed is a finding (High) and asked for again
/// [`REMAKE_TRIES`] times within the round; every attempt's outcome is in
/// the signed finding. After a round whose attempts all failed, the next
/// rounds sign the same finding (it is not "cleared" while the lock is
/// still not in place) and the next attempt waits ([`MAX_SKIP`]).
#[derive(Debug, Default)]
pub struct Keeper {
    /// The lock was in place in a round since the start.
    seen: bool,
    /// Rounds in a row whose attempts all failed.
    failed: u32,
    /// Rounds still to leave out before the next attempt.
    skip: u32,
    /// The last failed round's finding, signed again while waiting.
    last: Option<(&'static str, String)>,
    /// Lot 1.1 (the re-check 1 of #569, (b)): the re-creations made in this
    /// run — named in each one's finding, so that each is a High of its
    /// own (the same text within NN-AUD-114's 600 s would be held back).
    remade: u32,
}

impl Keeper {
    /// Whether the round watches the lock: the start found it in place, or
    /// a round saw it since; or the start did not find it and the agent
    /// runs as its unit (`in_unit`), whose step makes it — never for an
    /// agent run by hand, where no step ran.
    pub fn watches(&self, in_unit: bool) -> bool {
        self.watches_after(AT_START.get().copied(), in_unit)
    }

    /// [`Keeper::watches`] after the start's check `at_start`.
    fn watches_after(&self, at_start: Option<bool>, in_unit: bool) -> bool {
        self.seen
            || match at_start {
                Some(true) => true,
                Some(false) => in_unit,
                None => false,
            }
    }

    /// Lot 367 (F3b-6): the status after the round just run — the lock not
    /// in place since a round whose attempts all failed (the same line each
    /// round, so the status keeps one), or in place. A lock lost and made
    /// again within one round is in place: its finding is signed, the
    /// status has nothing to keep.
    pub fn status_line(&self) -> StatusLine {
        match &self.last {
            Some((kind, _)) => StatusLine::NotInPlace(format!(
                "the lock of the pin directory {}: the integrity round could not make it again \
                 ({ABSENT_EFFECT}); signed as {kind}, asked for again at the next attempts",
                if *kind == MISSING {
                    "is missing"
                } else {
                    "changed"
                },
            )),
            None if self.seen => StatusLine::InPlace,
            None => StatusLine::Unwatched,
        }
    }

    /// One round: `None` while the lock is in place; else the finding's
    /// kind and detail, after `remake` was asked up to [`REMAKE_TRIES`]
    /// times (`pause` between two) — or, while waiting after failed
    /// rounds, the last finding again.
    pub fn round(
        &mut self,
        host_table: &[u8],
        pin_root: &Path,
        mut remake: impl FnMut() -> Outcome,
        mut pause: impl FnMut(std::time::Duration),
    ) -> Option<(&'static str, String)> {
        let s = state_in(host_table, pin_root);
        let kind = match &s {
            State::InPlace(_) => {
                *self = Keeper {
                    seen: true,
                    remade: self.remade,
                    ..Keeper::default()
                };
                return None;
            }
            State::Missing(_) => MISSING,
            State::Propagation(..) | State::Changed(_) => CHANGED,
        };
        if self.skip > 0 {
            if let Some(last) = &self.last {
                self.skip -= 1;
                return Some(last.clone());
            }
        }
        let mut tries = 0;
        let out = loop {
            tries += 1;
            let out = remake();
            if out.in_place() || tries >= REMAKE_TRIES {
                break out;
            }
            pause(REMAKE_PAUSE * tries);
        };
        let outcome = if out.in_place() {
            let remade = self.remade.saturating_add(1);
            *self = Keeper {
                seen: true,
                remade,
                ..Keeper::default()
            };
            format!(
                "made again: {} (attempt {tries} of {REMAKE_TRIES}), its re-creation {remade} in this run",
                out.line()
            )
        } else {
            self.failed = self.failed.saturating_add(1);
            self.skip = ((1u32 << self.failed.min(3)) - 1).min(MAX_SKIP);
            format!(
                "NOT made again after {tries} attempts: {}; the next attempt in {} rounds",
                out.line(),
                self.skip + 1
            )
        };
        let f = (
            kind,
            format!(
                "the lock of {} {} — an unmount racing the mount guard's walk could take the \
                 host's bpffs and the pins; {outcome}",
                pin_root.display(),
                s.describe(),
            ),
        );
        if !out.in_place() {
            self.last = Some(f.clone());
        }
        Some(f)
    }
}

/// How long the integrity round waits for the transient unit, all its
/// attempts together (each unit's own `RuntimeMaxSec=` is 20 s): a manager
/// that does not answer never holds the round.
pub const REMAKE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// `cmd` run, its standard output read once it exited, within `deadline`
/// (then killed: an error).
fn run_bounded(
    mut cmd: std::process::Command,
    deadline: std::time::Duration,
) -> io::Result<String> {
    use std::io::Read;
    let mut child = cmd.spawn()?;
    let start = std::time::Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            let mut out = String::new();
            if let Some(mut o) = child.stdout.take() {
                let _ = o.by_ref().take(64 << 10).read_to_string(&mut out);
            }
            return Ok(out);
        }
        if start.elapsed() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("no answer within {} s", deadline.as_secs()),
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// The step run again from the agent (the integrity round): the agent's
/// own binary as a transient unit's process (`systemd-run --wait`, PID 1's
/// child in PID 1's namespace, outside the agent's sandbox), waited for
/// until `until` at most, then PID 1's table read again.
pub fn remake(pin_root: &Path, until: std::time::Instant) -> Outcome {
    let left = until.saturating_duration_since(std::time::Instant::now());
    if left.is_zero() {
        return Outcome::Failed(format!(
            "no time left within the round's {} s",
            REMAKE_DEADLINE.as_secs()
        ));
    }
    let exe = match antitamper_bpf::kernel_roots::read_link("/proc/self/exe") {
        Ok(p) => p,
        Err(e) => return Outcome::Failed(format!("/proc/self/exe: {e}")),
    };
    if exe.as_os_str().as_bytes().ends_with(b" (deleted)") {
        return Outcome::Failed(format!(
            "the agent's binary {} was replaced since it started: the next start makes the lock",
            exe.display()
        ));
    }
    let run = match crate::trusted_bin::resolve("systemd-run") {
        Ok(b) => b,
        Err(e) => return Outcome::Failed(format!("{e}")),
    };
    let mut cmd = run.command();
    cmd.args([
        "--wait",
        "--collect",
        "--quiet",
        "--pipe",
        "--service-type=oneshot",
        "--property=RuntimeMaxSec=20",
        // lot 374: the units' UnsetEnvironment= (the loader's variables)
        &antitamper_bpf::start_check::systemd_run_unset(),
        &format!("--unit={REMAKE_UNIT}"),
        "--description=NorthNarrow pin directory lock",
    ])
    .arg(&exe)
    .arg(STEP_ARG)
    .stdin(std::process::Stdio::null())
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::null());
    let said = match run_bounded(cmd, left) {
        Ok(out) => out.trim().chars().take(300).collect::<String>(),
        Err(e) => return Outcome::Failed(format!("systemd-run: {e}")),
    };
    match host_table().map(|t| state_in(&t, pin_root)) {
        Ok(State::InPlace(id)) => Outcome::Made(id),
        Ok(s) => Outcome::Failed(format!("{} ({said})", s.describe())),
        Err(e) => Outcome::Failed(format!("/proc/1/mountinfo: {e}")),
    }
}

/// The path of the agent's pin directory.
pub fn pin_root() -> PathBuf {
    PathBuf::from(antitamper_bpf::DEFAULT_BPFFS_ROOT)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "/sys/fs/bpf/northnarrow";
    const BASE: &str = "1 0 252:1 / / rw shared:1 - ext4 /dev/vda1 rw\n\
                        20 1 0:20 / /sys rw shared:7 - sysfs sysfs rw\n\
                        30 20 0:30 / /sys/fs/bpf rw shared:9 - bpf bpf rw,mode=700\n";

    fn with(lines: &str) -> Vec<u8> {
        format!("{BASE}{lines}").into_bytes()
    }

    fn lock_line(prop: &str) -> String {
        let prop = if prop.is_empty() {
            String::new()
        } else {
            format!(" {prop}")
        };
        format!("90 30 0:30 /northnarrow {ROOT} rw,relatime{prop} - bpf bpf rw,mode=700\n")
    }

    /// Named test (lot 359): the lock is told from the table — in place
    /// (private, unbindable, the bpffs's child), missing, its propagation
    /// changed (shared, a slave, private but bindable), or not the lock (a
    /// tmpfs, another bpffs, another directory, a mount laid over it, no
    /// bpffs at `/sys/fs/bpf`).
    #[test]
    fn the_lock_is_in_place_only_private_unbindable_and_the_bpffs_child() {
        let root = Path::new(ROOT);
        assert_eq!(
            state_in(&with(&lock_line("unbindable")), root),
            State::InPlace(90)
        );
        assert!(matches!(state_in(BASE.as_bytes(), root), State::Missing(_)));
        for prop in [
            "shared:120",
            "master:9",
            "",
            "shared:120 unbindable",
            "master:9 unbindable",
        ] {
            assert_eq!(
                state_in(&with(&lock_line(prop)), root),
                State::Propagation(90, prop.to_string()),
                "{prop:?}"
            );
        }
        for (what, line) in [
            (
                "a tmpfs",
                format!("90 30 0:91 / {ROOT} rw - tmpfs tmpfs rw\n"),
            ),
            (
                "another bpffs",
                format!("90 30 0:92 / {ROOT} rw unbindable - bpf bpf rw\n"),
            ),
            (
                "another directory",
                format!("90 30 0:30 /other {ROOT} rw unbindable - bpf bpf rw\n"),
            ),
        ] {
            assert!(
                matches!(state_in(&with(&line), root), State::Changed(_)),
                "{what}"
            );
        }
        let over = format!(
            "{}91 90 0:93 / {ROOT} rw - tmpfs tmpfs rw\n",
            lock_line("unbindable")
        );
        assert!(
            matches!(state_in(&with(&over), root), State::Changed(w) if w.contains("over the lock"))
        );
        // a second lock on the first is still the lock
        let twice = format!(
            "{}91 90 0:30 /northnarrow {ROOT} rw unbindable - bpf bpf rw\n",
            lock_line("unbindable")
        );
        assert_eq!(state_in(&with(&twice), root), State::InPlace(90));
        let no_bpffs =
            "1 0 252:1 / / rw - ext4 /dev/vda1 rw\n30 1 0:30 / /sys/fs/bpf rw - tmpfs tmpfs rw\n";
        assert!(matches!(
            state_in(no_bpffs.as_bytes(), root),
            State::Changed(_)
        ));
        assert!(propagation_is_locked("unbindable"));
        assert!(!propagation_is_locked("shared:1 unbindable"));
        assert!(!propagation_is_locked(""));
    }

    /// Named test (lot 359): the lock is a mount over the pin root that the
    /// start and the integrity round take for the agent's own — and only
    /// the self-bind is.
    #[test]
    fn only_the_self_bind_of_the_pin_directory_is_the_lock() {
        let root = Path::new(ROOT);
        let t = crate::mountinfo::parse(&with(&lock_line("unbindable"))).entries;
        let lock = t.iter().find(|m| m.id == 90).unwrap();
        assert!(is_lock(&t, lock, root));
        assert!(!is_lock(&t, t.iter().find(|m| m.id == 30).unwrap(), root));
        let t = crate::mountinfo::parse(&with(&format!(
            "90 30 0:30 /other {ROOT} rw - bpf bpf rw\n"
        )))
        .entries;
        assert!(!is_lock(&t, t.iter().find(|m| m.id == 90).unwrap(), root));
        // a bind of a directory of the bpffs at /sys/fs/bpf, the "lock" below
        // it bound onto itself: not the bpffs's own child
        let t = crate::mountinfo::parse(
            format!(
                "1 0 252:1 / / rw - ext4 /dev/vda1 rw\n\
                 30 1 0:30 /sub /sys/fs/bpf rw - bpf bpf rw\n\
                 90 30 0:30 /sub/northnarrow {ROOT} rw unbindable - bpf bpf rw\n"
            )
            .as_bytes(),
        )
        .entries;
        assert!(!is_lock(&t, t.iter().find(|m| m.id == 90).unwrap(), root));
        // the agent's namespace: its copy, on its copy of the bpffs
        let own = "1 0 252:1 / / rw - ext4 /dev/vda1 rw\n\
                   520 1 0:30 / /sys/fs/bpf rw shared:300 master:9 - bpf bpf rw\n\
                   521 520 0:30 /northnarrow /sys/fs/bpf/northnarrow rw shared:301 - bpf bpf rw\n";
        let t = crate::mountinfo::parse(own.as_bytes()).entries;
        assert!(is_lock(&t, t.iter().find(|m| m.id == 521).unwrap(), root));
    }

    /// Named test (lot 359): the integrity round asks for the lock again
    /// when it is missing or changed — a High of its own kind, the result
    /// in its detail — and does nothing while it is in place.
    #[test]
    fn a_lost_or_changed_lock_is_a_finding_and_made_again() {
        let root = Path::new(ROOT);
        let mut asked = 0;
        assert!(
            Keeper::default()
                .round(
                    &with(&lock_line("unbindable")),
                    root,
                    || {
                        asked += 1;
                        Outcome::Made(1)
                    },
                    |_| {}
                )
                .is_none()
        );
        assert_eq!(asked, 0);
        let (kind, detail) = Keeper::default()
            .round(BASE.as_bytes(), root, || Outcome::Made(95), |_| {})
            .unwrap();
        assert_eq!(kind, MISSING);
        assert!(detail.contains("pin lock: made (mount 95)"), "{detail}");
        let (kind, detail) = Keeper::default()
            .round(
                &with(&lock_line("shared:120")),
                root,
                || Outcome::Repaired(90),
                |_| {},
            )
            .unwrap();
        assert_eq!(kind, CHANGED);
        assert!(
            detail.contains("propagation changed") && detail.contains("repaired"),
            "{detail}"
        );
        let (_, detail) = Keeper::default()
            .round(
                BASE.as_bytes(),
                root,
                || Outcome::Failed("systemd-run: no".into()),
                |_| {},
            )
            .unwrap();
        assert!(detail.contains("NOT made: systemd-run: no"), "{detail}");
    }

    /// Named test (the review of #569, F5 and the coordinator's fix 3): one
    /// failed attempt no longer leaves the lock missing until the next
    /// round — it is asked for again within the round, after a pause, and
    /// the signed finding says at which attempt it was made.
    #[test]
    fn one_failed_remake_is_retried_within_the_round() {
        let root = Path::new(ROOT);
        let mut asked = 0;
        let mut paused = Vec::new();
        let mut k = Keeper::default();
        let (kind, detail) = k
            .round(
                BASE.as_bytes(),
                root,
                || {
                    asked += 1;
                    if asked == 1 {
                        Outcome::Failed("Unit northnarrow-pin-lock.service already exists".into())
                    } else {
                        Outcome::Made(96)
                    }
                },
                |d| paused.push(d),
            )
            .unwrap();
        assert_eq!(kind, MISSING);
        assert_eq!(asked, 2);
        assert_eq!(paused, vec![REMAKE_PAUSE]);
        assert!(
            detail.contains("made again: pin lock: made (mount 96) (attempt 2 of 3)"),
            "{detail}"
        );
        // in place at the next round: nothing, and nothing asked
        assert!(
            k.round(
                &with(&lock_line("unbindable")),
                root,
                || unreachable!(),
                |_| {}
            )
            .is_none()
        );
    }

    /// Named test (lot 1.1, the re-check 1 of #569, (b)): each re-creation
    /// of the lock in a run is a finding of its own text — its count in the
    /// run — so a second loss and remake within NN-AUD-114's 600 s is a
    /// High of its own, not one held back as the same. Failed on main: the
    /// two details were the same text.
    #[test]
    fn each_re_creation_of_the_lock_is_a_finding_of_its_own() {
        let root = Path::new(ROOT);
        let gone = BASE.as_bytes();
        let mut k = Keeper {
            seen: true,
            ..Keeper::default()
        };
        let mut details = Vec::new();
        for _ in 0..2 {
            let (_, detail) = k
                .round(gone, root, || Outcome::Made(96), |_| {})
                .expect("a finding");
            details.push(detail);
        }
        assert!(details[0].contains("its re-creation 1 in this run"), "{}", details[0]);
        assert!(details[1].contains("its re-creation 2 in this run"), "{}", details[1]);
        assert_ne!(details[0], details[1]);
        // a round that finds it in place keeps the count
        let _ = k.round(gone, root, || Outcome::Made(97), |_| {});
        assert_eq!(k.remade, 3);
    }

    /// Named test (the review of #569, F5): a round whose attempts all fail
    /// signs it, with each attempt counted — bounded ([`REMAKE_TRIES`]) —
    /// and the next rounds sign the same finding (it is not "cleared" while
    /// the lock is not in place) and ask again only after a back-off
    /// (1, 3, then [`MAX_SKIP`] rounds left out); once it is made, the
    /// back-off is gone.
    #[test]
    fn a_round_whose_attempts_all_fail_signs_it_and_backs_off() {
        let root = Path::new(ROOT);
        let asked = std::cell::Cell::new(0);
        let fail = || {
            asked.set(asked.get() + 1);
            Outcome::Failed("systemd-run: no".into())
        };
        let mut k = Keeper::default();
        let mut paused = Vec::new();
        let first = k
            .round(BASE.as_bytes(), root, fail, |d| paused.push(d))
            .unwrap();
        assert_eq!(asked.get(), REMAKE_TRIES);
        assert_eq!(paused, vec![REMAKE_PAUSE, REMAKE_PAUSE * 2]);
        assert!(
            first.1.contains("NOT made again after 3 attempts")
                && first.1.contains("the next attempt in 2 rounds"),
            "{}",
            first.1
        );
        // left out: the same finding, nothing asked
        assert_eq!(k.round(BASE.as_bytes(), root, fail, |_| {}), Some(first));
        assert_eq!(asked.get(), REMAKE_TRIES);
        // asked again: fails again, a longer wait
        let second = k.round(BASE.as_bytes(), root, fail, |_| {}).unwrap();
        assert_eq!(asked.get(), 2 * REMAKE_TRIES);
        assert!(second.1.contains("in 4 rounds"), "{}", second.1);
        for _ in 0..3 {
            assert_eq!(
                k.round(BASE.as_bytes(), root, fail, |_| {}),
                Some(second.clone())
            );
        }
        assert_eq!(asked.get(), 2 * REMAKE_TRIES);
        let third = k.round(BASE.as_bytes(), root, fail, |_| {}).unwrap();
        assert!(third.1.contains("in 8 rounds"), "{}", third.1);
        for _ in 0..MAX_SKIP {
            k.round(BASE.as_bytes(), root, fail, |_| {});
        }
        let fourth = k.round(BASE.as_bytes(), root, fail, |_| {}).unwrap();
        assert_eq!(asked.get(), 4 * REMAKE_TRIES);
        assert!(fourth.1.contains("in 8 rounds"), "capped: {}", fourth.1);
        // made: the back-off is gone
        for _ in 0..MAX_SKIP {
            k.round(BASE.as_bytes(), root, fail, |_| {});
        }
        let made = k
            .round(BASE.as_bytes(), root, || Outcome::Made(97), |_| {})
            .unwrap();
        assert!(made.1.contains("made again"), "{}", made.1);
        let again = k
            .round(BASE.as_bytes(), root, || Outcome::Made(98), |_| {})
            .unwrap();
        assert!(again.1.contains("mount 98"), "asked at once: {}", again.1);
        // found in place after failed rounds: the back-off is gone too
        let mut k = Keeper::default();
        k.round(BASE.as_bytes(), root, fail, |_| {}).unwrap();
        assert!(
            k.round(&with(&lock_line("unbindable")), root, fail, |_| {})
                .is_none()
        );
        let after = k
            .round(BASE.as_bytes(), root, || Outcome::Made(99), |_| {})
            .unwrap();
        assert!(after.1.contains("mount 99"), "asked at once: {}", after.1);
    }

    /// Named test (lot 367, pre-alpha Phase 3-bis F3b-6): while the round
    /// cannot make the lock again, the status has one degradation line for
    /// it, the same each round; once a round finds it in place (or makes it
    /// again) the line is gone. A lock lost and made again in the same
    /// round leaves no line (its finding is signed).
    #[test]
    fn the_status_shows_the_lock_not_in_place_until_a_round_finds_it() {
        let root = Path::new(ROOT);
        let fail = || Outcome::Failed("systemd-run: no".into());
        let mut k = Keeper::default();
        assert_eq!(k.status_line(), StatusLine::Unwatched);
        k.round(BASE.as_bytes(), root, fail, |_| {}).unwrap();
        let StatusLine::NotInPlace(line) = k.status_line() else {
            panic!("{:?}", k.status_line())
        };
        assert!(
            line.contains("is missing") && line.contains(MISSING),
            "{line}"
        );
        // waiting, then asked again and failing: the same line
        k.round(BASE.as_bytes(), root, fail, |_| {}).unwrap();
        assert_eq!(k.status_line(), StatusLine::NotInPlace(line.clone()));
        k.round(BASE.as_bytes(), root, fail, |_| {}).unwrap();
        assert_eq!(k.status_line(), StatusLine::NotInPlace(line.clone()));
        // the rounds left out keep the line; the next attempt makes it:
        // in place, the line gone
        let mut made = false;
        for _ in 0..=MAX_SKIP {
            let f = k
                .round(BASE.as_bytes(), root, || Outcome::Made(97), |_| {})
                .unwrap();
            if f.1.contains("made again:") {
                made = true;
                break;
            }
            assert_eq!(k.status_line(), StatusLine::NotInPlace(line.clone()));
        }
        assert!(made);
        assert_eq!(k.status_line(), StatusLine::InPlace);
        // found in place by a round
        let mut k = Keeper::default();
        k.round(BASE.as_bytes(), root, fail, |_| {}).unwrap();
        assert!(matches!(k.status_line(), StatusLine::NotInPlace(_)));
        assert!(
            k.round(&with(&lock_line("unbindable")), root, fail, |_| {})
                .is_none()
        );
        assert_eq!(k.status_line(), StatusLine::InPlace);
        // lost and made again in one round: a finding, no line
        let mut k = Keeper::default();
        let f = k
            .round(BASE.as_bytes(), root, || Outcome::Made(5), |_| {})
            .unwrap();
        assert_eq!(f.0, MISSING);
        assert_eq!(k.status_line(), StatusLine::InPlace);
        // the mini-hunt: a lock whose propagation changed (shared), not made
        // again — its own line, "changed", not "missing"
        let mut k = Keeper::default();
        let f = k
            .round(&with(&lock_line("shared:120")), root, fail, |_| {})
            .unwrap();
        assert_eq!(f.0, CHANGED);
        let StatusLine::NotInPlace(line) = k.status_line() else {
            panic!("{:?}", k.status_line())
        };
        assert!(line.contains("changed") && line.contains(CHANGED), "{line}");
        assert!(!line.contains("is missing"), "{line}");
    }

    /// Named test (the review of #569, F3): a start that did not find the
    /// lock no longer leaves it unwatched for the whole run — in the
    /// agent's unit the round makes it (and watches it from then on); an
    /// agent run by hand (no step ran) is left as its start signed it.
    #[test]
    fn a_start_without_the_lock_has_it_made_by_the_round_in_its_unit() {
        let k = Keeper::default();
        assert!(k.watches_after(Some(true), false));
        assert!(k.watches_after(Some(true), true));
        assert!(k.watches_after(Some(false), true));
        assert!(!k.watches_after(Some(false), false), "run by hand");
        assert!(!k.watches_after(None, true), "no pin root: no lock");
        let mut k = Keeper::default();
        let (kind, detail) = k
            .round(
                BASE.as_bytes(),
                Path::new(ROOT),
                || Outcome::Made(99),
                |_| {},
            )
            .unwrap();
        assert_eq!(kind, MISSING);
        assert!(detail.contains("made again"), "{detail}");
        assert!(k.watches_after(Some(false), false), "watched once made");
    }

    /// Named test (the review of #569, F1c): the step's one change of
    /// propagation is `MS_UNBINDABLE` — the maker's step the guard lets
    /// through — and the step never asks for `MS_PRIVATE`, which made a
    /// lock in place bindable again (a repair included).
    #[test]
    fn the_step_makes_the_lock_unbindable_alone_never_private() {
        use common::mount_guard::{MS_PRIVATE, MS_UNBINDABLE, lock_step};
        assert_eq!(LOCK_FLAGS, MS_UNBINDABLE);
        assert!(lock_step(LOCK_FLAGS));
        let src = include_str!("pin_lock.rs");
        let code = &src[..src.find("#[cfg(test)]").unwrap()];
        assert!(!code.contains("MS_PRIVATE)"), "a step asks for MS_PRIVATE");
        assert!(!lock_step(MS_PRIVATE));
        let calls: Vec<&str> = code
            .match_indices("propagation(pin_root, ")
            .map(|(i, _)| &code[i..i + 40])
            .collect();
        assert!(!calls.is_empty());
        for c in calls {
            assert!(c.starts_with("propagation(pin_root, LOCK_FLAGS)"), "{c}");
        }
    }

    /// Named test (lot 359): the start that finds no lock signs a
    /// degradation, and its integrity round then does not ask for one.
    #[test]
    fn a_start_without_the_lock_is_a_degradation() {
        let why = at_start(BASE.as_bytes(), Path::new(ROOT)).unwrap();
        assert!(
            why.contains("missing") && why.contains("the walk (#567) remains"),
            "{why}"
        );
    }

    /// Named test (the review of #569, F5): a round's attempts share one
    /// deadline — each transient unit is waited for only for the time left
    /// until the round's `until`, and none is started once it has passed.
    #[test]
    fn the_remakes_of_a_round_share_one_deadline() {
        let past = std::time::Instant::now() - std::time::Duration::from_millis(1);
        // The failure text may carry the trusted-binary check's refused paths:
        // the messages name the expectation only, never the text itself.
        match remake(Path::new(ROOT), past) {
            Outcome::Failed(why) => assert!(
                why.contains("no time left"),
                "the remake past its deadline fails for the deadline"
            ),
            o => panic!(
                "expected Outcome::Failed, got {:?}",
                std::mem::discriminant(&o)
            ),
        }
        let src = include_str!("pin_lock.rs");
        let code = &src[..src.find("#[cfg(test)]").unwrap()];
        let body = &code[code.find("pub fn remake(").unwrap()..];
        let body = &body[..body.find("\n}\n").unwrap()];
        assert!(body.contains("until.saturating_duration_since(std::time::Instant::now())"));
        assert!(
            body.contains("run_bounded(cmd, left)"),
            "the time left only"
        );
        assert!(!body.contains("REMAKE_DEADLINE)"), "a deadline of its own");
    }

    /// Named test (lot 359): the transient unit is waited for within a
    /// deadline — a manager that does not answer never holds the integrity
    /// round; an answer is read whole.
    #[test]
    fn the_remake_is_waited_for_within_a_deadline() {
        let mut echo = std::process::Command::new("/bin/sh");
        echo.args(["-c", "echo pin lock: made"])
            .stdout(std::process::Stdio::piped());
        assert_eq!(
            run_bounded(echo, std::time::Duration::from_secs(10)).unwrap(),
            "pin lock: made\n"
        );
        let mut hang = std::process::Command::new("/bin/sh");
        hang.args(["-c", "sleep 30"])
            .stdout(std::process::Stdio::piped());
        let t = std::time::Instant::now();
        let e = run_bounded(hang, std::time::Duration::from_millis(300)).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert!(t.elapsed() < std::time::Duration::from_secs(10));
    }
}
