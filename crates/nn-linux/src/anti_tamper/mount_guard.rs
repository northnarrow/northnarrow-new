//! Lot 357: the mount guard's userland half — the protected points and the
//! host's namespaces written to the kernel, the four hooks attached.
//!
//! The kernel half (`agent-ebpf/src/mount_guard.rs`, the decision in
//! `common::mount_guard`) refuses, in PID 1's mount namespace — and in any
//! other whose target mount propagates into PID 1's — a mount on, over or
//! below the paths the agent depends on. This module resolves those
//! paths in PID 1's root (`/proc/1/root/<path>`: the host's mounts, not the
//! unit's sandbox) to the device and inode the hooks compare, registers
//! them with their kind ([`protected_points`]), arms the guard with PID 1's
//! mount and user namespaces, and attaches `sb_mount`, `move_mount`,
//! `sb_umount`, `sb_pivotroot` and `sb_remount`.
//!
//! The review of #567:
//! - F1: the mounts held are mounts, by their id — those the protected
//!   points resolve through in each guarded namespace's own table
//!   ([`held_in`]) — never their root's dentry (a backup's bind of `/`, a
//!   chroot's sysfs are other mounts);
//! - F2: the agent's own mount namespace ([`guard_own_namespace`], once its
//!   role is claimed: the role's liveness watch drops it at its exit) and
//!   the watchdog's ([`guard_watchdog`], from the watchdog refresh) are
//!   judged as PID 1's;
//! - F3: the super blocks those mounts are on are held (`MG_SB`): no
//!   reconfigure (`sb_remount`);
//! - the brainstorm's 3rd point: the mounts already there when the guard
//!   arms (fstab, `.mount` units, the initramfs) are judged against the
//!   canonical layout ([`not_canonical`]) — a signed degradation, and the
//!   integrity round's High.
//!
//! Fail-safe: a kernel without one of the hooks or the offsets they read,
//! a namespace that cannot be read, a load or attach that fails — the guard
//! (or the part of it) is not attached and the boot signs the degradation
//! ([`ABSENT_EFFECT`]); the start goes on. The by-path defences (the
//! anchored kernel views, the bounded readers) and the signed mount watch
//! (`self_integrity`'s `mount_over_protected`) remain.

use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use aya::maps::{Array as AyaArray, HashMap as AyaHashMap, MapData};
use aya::{Btf, Ebpf};
use common::mount_guard::{
    BPF_FS_MAGIC, CGROUP2_SUPER_MAGIC, CONF_PROPAGATED, GUARD_AGENT, GUARD_HOST, GUARD_WATCHDOG,
    HELD_NS_SHIFT, HELD_REFUSE, MG_HOLD, MG_LOCK, MG_LOCK_ABOVE, MG_NOTE, MG_ON, MG_OWN, MG_SB,
    MG_VIEW, NameKey, PLACE_ANY_GROUP, PROC_SUPER_MAGIC, STAGE_POINT, STAGE_PROPAGATE, SYSFS_MAGIC,
    TMPFS_MAGIC, guards_own_namespace, held_by_id, held_by_place, held_root, held_under,
};
use common::wire::InodeKey;
use tracing::{info, warn};

use super::filesystem::{
    AyaInodeKey, BINARY_AND_UNIT_PATHS, CONFIG_DIR, NOCREATE_UNIT_DIRS, STATE_DIR,
    stat_dev_to_kernel_dev,
};
use crate::mountinfo::MountEntry;
use std::os::unix::ffi::OsStrExt;

/// The five programs, by `(program, hook)`; pinned under the hook's name
/// like every LSM program of the pin root.
pub(crate) const PROGRAMS: [(&str, &str); 5] = [
    ("mount_guard_sb_mount", "sb_mount"),
    ("mount_guard_move_mount", "move_mount"),
    ("mount_guard_sb_umount", "sb_umount"),
    ("mount_guard_sb_pivotroot", "sb_pivotroot"),
    // the review of #567 (F3): a super block's reconfigure
    ("mount_guard_sb_remount", "sb_remount"),
];

/// The review of #567 (F3): the `fentry` that reads a reconfigure's new
/// flags for `sb_remount` (finalrd's `remount,exec /run` at shutdown is not
/// a read-only remount), pinned with the hooks.
const RECONF_PROGRAM: (&str, &str) = ("mount_guard_reconfigure", "reconfigure_super");

/// Lot 1.1 (F8b-1): the stages the split hooks' entries tail-call, by
/// `(program, hook, program array, slot)` — loaded for their hook, never
/// attached, each in its slot before the entry is attached. A stage the
/// kernel refuses leaves its hook unattached (a signed degradation), never
/// an entry that would let through what the stage judges.
pub(crate) const STAGES: [(&str, &str, &str, u32); 3] = [
    (
        "mount_guard_sb_mount_point",
        "sb_mount",
        SB_STAGES_MAP,
        STAGE_POINT,
    ),
    (
        "mount_guard_sb_mount_propagate",
        "sb_mount",
        SB_STAGES_MAP,
        STAGE_PROPAGATE,
    ),
    (
        "mount_guard_move_mount_point",
        "move_mount",
        MOVE_STAGES_MAP,
        STAGE_POINT,
    ),
];

/// Lot 1.1: `sb_mount`'s and `move_mount`'s program arrays (one per hook:
/// from 6.11 a tracing program tail-calls only a program of its own kernel
/// function), pinned at each start after the entries (a program array is
/// emptied when its last user reference goes) and held for the agent's
/// life ([`hold_stages`]).
const SB_STAGES_MAP: &str = "MOUNT_SB_STAGES";
const MOVE_STAGES_MAP: &str = "MOUNT_MOVE_STAGES";

/// Lot 1.1 (the review of #569, F1b): the `fentry` on the kernel's
/// `change_mnt_propagation()` that counts a propagation change of a
/// guarded mount as it is made — `mount_setattr(2)`'s, which no LSM hook
/// sees, among them (`agent-ebpf/src/mount_setattr.rs`); pinned with the
/// hooks.
const PROPAGATION_PROGRAM: (&str, &str) = ("mount_guard_propagation", "change_mnt_propagation");

/// What a start without [`PROPAGATION_PROGRAM`] lacks, for the signed
/// degradation.
pub const PROPAGATION_ABSENT_EFFECT: &str = "a change of propagation made through \
     mount_setattr(2) on a mount the guard holds is followed at the next refresh and signed at the \
     next integrity round (about 30 s), not at once";

/// The guard's hooks (each with its `DENY_FAIL_OPEN` slot).
pub const HOOKS: [&str; 5] = [
    "sb_mount",
    "move_mount",
    "sb_umount",
    "sb_pivotroot",
    "sb_remount",
];

/// What a boot without the guard (or part of it) lacks, for the signed
/// degradation.
pub const ABSENT_EFFECT: &str = "a mount on, over or below the agent's directories, binaries and \
     units, /proc, /sys, the cgroup root or the bpffs is not refused in the host's namespace — the \
     by-path defences (anchored views, bounded readers) and the signed mount watch \
     (mount_over_protected) remain";

const PROTECTED_MAP: &str = "MOUNT_PROTECTED";
const CONF_MAP: &str = "MOUNT_GUARD_CONF";
/// The review of #567 (F1): the mounts held, by their id.
const HELD_MAP: &str = "MOUNT_HELD";
/// The review of #567 (F2): the namespaces judged as PID 1's.
const NS_MAP: &str = "MOUNT_GUARD_NS";
/// The cross-model check: the peer groups that reach a guarded namespace.
const GROUPS_MAP: &str = "MOUNT_GROUPS";
/// `MOUNT_GUARD_CONF`'s slots of the agent's and the watchdog's mount
/// namespaces (what the eBPF `vacate` drops at their exit).
const CONF_AGENT_NS: u32 = 2;
const CONF_WATCHDOG_NS: u32 = 3;
/// The re-check of #567 (N1): `MOUNT_GUARD_CONF`'s count of the
/// propagation changes the hooks let through (the eBPF `CONF_REGROUP`).
const CONF_REGROUP: u32 = 4;
/// The maps the watchdog refresh opens by their pin (explicitly pinned at
/// each start, as `PROTECTED_PIDS`: a by-name pin is not made by the loader).
const PINNED_MAPS: [&str; 5] = [PROTECTED_MAP, CONF_MAP, HELD_MAP, NS_MAP, GROUPS_MAP];

/// The offsets the programs read: without every one the guard is not
/// attached.
const OFFSETS: [&str; 22] = [
    "PATH_MNT_OFFSET",
    "VFSMOUNT_MNT_ROOT_OFFSET",
    "MOUNT_MNT_OFFSET",
    "MOUNT_MNT_PARENT_OFFSET",
    "MOUNT_MNT_MOUNTPOINT_OFFSET",
    // the propagation into PID 1's namespace of a mount made elsewhere
    "MOUNT_MNT_NS_OFFSET",
    "MOUNT_MNT_SHARE_OFFSET",
    "MOUNT_MNT_SLAVE_LIST_OFFSET",
    "MOUNT_MNT_SLAVE_OFFSET",
    // the review of #567 (F1): the mounts held by their id
    "MOUNT_MNT_ID_OFFSET",
    "MOUNT_MNT_GROUP_ID_OFFSET",
    // the re-check 2 of #567 (N3): an unmount's subtree, mount by mount
    "MOUNT_MNT_MOUNTS_OFFSET",
    "MOUNT_MNT_CHILD_OFFSET",
    "TASK_STRUCT_NSPROXY_OFFSET",
    "NSPROXY_MNT_NS_OFFSET",
    "MNT_NAMESPACE_INUM_OFFSET",
    "TASK_STRUCT_CRED_OFFSET",
    "CRED_CAP_EFFECTIVE_OFFSET",
    "CRED_USER_NS_OFFSET",
    "USER_NAMESPACE_INUM_OFFSET",
    "SUPER_BLOCK_S_TYPE_OFFSET",
    "FILE_SYSTEM_TYPE_NAME_OFFSET",
];

/// The kernel views (on them a mount is refused, below them one that is
/// not the kernel's own), with the file systems each may be.
pub const VIEWS: [(&str, &[u32]); 5] = [
    ("/proc", &[PROC_SUPER_MAGIC]),
    ("/sys", &[SYSFS_MAGIC]),
    ("/sys/fs/cgroup", &[CGROUP2_SUPER_MAGIC, TMPFS_MAGIC]),
    // a hybrid host's unified hierarchy (absent on a unified one)
    ("/sys/fs/cgroup/unified", &[CGROUP2_SUPER_MAGIC]),
    ("/sys/fs/bpf", &[BPF_FS_MAGIC]),
];

/// The agent's own directories (no mount on or below them).
pub fn own_dirs(pin_root: Option<&Path>) -> Vec<String> {
    let mut out = vec![
        CONFIG_DIR.to_string(),
        STATE_DIR.to_string(),
        "/run/northnarrow".to_string(),
    ];
    if let Some(p) = pin_root {
        out.push(p.display().to_string());
    }
    out.extend(NOCREATE_UNIT_DIRS.iter().map(|d| d.to_string()));
    out
}

/// Every protected point by path, with its kind: the views, the agent's
/// directories, its binaries and units and the binaries' directories (no
/// mount on them), and every directory above any of them (a mount there
/// hides them as surely). Each one's mount is also held (no unmount, no
/// move away).
///
/// The review of #567 (F7): only the binaries and units that exist
/// (`exists`, in PID 1's root) — with the agent in `/usr/bin` (a
/// package), `/usr/local` and `/usr/local/bin` are no points, and an NFS or
/// automounted `/usr/local` (an HPC host) is the host's own business.
pub fn protected_points(
    pin_root: Option<&Path>,
    exists: &dyn Fn(&str) -> bool,
) -> Vec<(String, u8)> {
    let mut out: Vec<(String, u8)> = Vec::new();
    let add = |p: &str, flags: u8, out: &mut Vec<(String, u8)>| match out
        .iter_mut()
        .find(|(q, _)| q == p)
    {
        Some((_, f)) => *f |= flags,
        None => out.push((p.to_string(), flags)),
    };
    for (v, _) in VIEWS {
        add(v, MG_VIEW | MG_HOLD, &mut out);
    }
    let own = own_dirs(pin_root);
    for d in &own {
        add(d, MG_OWN | MG_HOLD, &mut out);
    }
    for p in BINARY_AND_UNIT_PATHS.iter().filter(|p| exists(p)) {
        add(p, MG_ON | MG_HOLD, &mut out);
    }
    // the directories above every one of them, `/` included (the binaries'
    // own directories, /usr/local/bin and /usr/bin, among them)
    let all: Vec<String> = out.iter().map(|(p, _)| p.clone()).collect();
    for p in all {
        let mut cur = Path::new(&p).parent();
        while let Some(a) = cur {
            add(&a.display().to_string(), MG_ON | MG_HOLD, &mut out);
            cur = a.parent();
        }
    }
    // Lot 359 (the re-check 3 of #567, N4): the pin directory is its lock's
    // root and place (`MG_LOCK`), the directories above it are where a
    // recursive `MS_SHARED` would reach the lock (`MG_LOCK_ABOVE`)
    if let Some(p) = pin_root {
        add(&p.display().to_string(), MG_LOCK, &mut out);
        let mut cur = p.parent();
        while let Some(a) = cur {
            add(&a.display().to_string(), MG_LOCK_ABOVE, &mut out);
            cur = a.parent();
        }
    }
    out
}

/// The directories of the shared libraries the agent has mapped (its
/// `/proc/self/maps`, a dynamic binary's `libc`, `libgcc_s`, the loader):
/// a mount over one swaps what a restart of the agent or the watchdog
/// loads (the cross-model check). System directories only — never a
/// pseudo file system's, a deleted file's or the agent's own binary's.
pub fn library_dirs(maps: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in maps.lines() {
        let Some(path) = line.split_whitespace().nth(5) else {
            continue;
        };
        if !path.starts_with('/') || line.ends_with("(deleted)") {
            continue;
        }
        let system = ["/usr/lib", "/lib", "/usr/lib64", "/lib64", "/usr/local/lib"]
            .iter()
            .any(|d| path.starts_with(&format!("{d}/")));
        if !system {
            continue;
        }
        if let Some(dir) = Path::new(path).parent().and_then(|d| d.to_str()) {
            if !out.iter().any(|o| o == dir) {
                out.push(dir.to_string());
            }
        }
    }
    out
}

/// Every protected point of this host now: [`protected_points`] with the
/// binaries and units that exist in PID 1's root, and the directories of
/// the agent's shared libraries ([`library_dirs`]).
pub fn points_in_host(pin_root: Option<&Path>) -> Vec<(String, u8)> {
    let mut pts = protected_points(pin_root, &|p: &str| {
        antitamper_bpf::kernel_roots::symlink_metadata(in_host(p)).is_ok()
    });
    let maps = antitamper_bpf::kernel_roots::read_to_string("/proc/self/maps").unwrap_or_default();
    let mut extra: Vec<String> = Vec::new();
    for d in library_dirs(&maps) {
        let mut cur = Some(Path::new(&d));
        while let Some(a) = cur {
            extra.push(a.display().to_string());
            cur = a.parent();
        }
    }
    for p in extra {
        match pts.iter_mut().find(|(q, _)| *q == p) {
            Some((_, f)) => *f |= MG_ON | MG_HOLD,
            None => pts.push((p, MG_ON | MG_HOLD)),
        }
    }
    pts
}

/// Why the guard is not attached on this kernel, or `None`. `absent` is the
/// boot's resolution's absent offsets (`None`: no resolution this boot).
pub(crate) fn offsets_refusal(absent: Option<&[&str]>) -> Option<String> {
    let Some(absent) = absent else {
        return Some(
            "no kernel BTF resolution this boot: the mount structures' offsets are unknown".into(),
        );
    };
    let missing: Vec<&str> = OFFSETS
        .iter()
        .copied()
        .filter(|o| absent.contains(o))
        .collect();
    (!missing.is_empty()).then(|| {
        format!(
            "the kernel's BTF lacks offsets the hooks read ({})",
            missing.join(", ")
        )
    })
}

/// How the guard's attach went.
#[derive(Debug, Default)]
pub(crate) struct Health {
    /// Hooks attached and armed.
    pub attached: usize,
    /// Signed degradations (each a sentence).
    pub degraded: Vec<String>,
    /// Protected points registered.
    pub points: usize,
}

/// A path in PID 1's root (`/proc/1/root<path>`).
fn in_host(path: &str) -> String {
    format!("/proc/1/root{path}")
}

/// Lot 359 (its mini-hunt): `dir` under the namespace root `prefix`
/// (`/proc/<pid>/root`) is that root itself — whose last component is the
/// magic link `root`, to be followed (a path's trailing `/` is no
/// component: `/proc/1/root/` read without following is the link, not
/// PID 1's `/`).
fn follows_root(prefix: &str, dir: &Path) -> bool {
    !prefix.is_empty() && dir == Path::new("/")
}

/// The metadata of the protected point `p` as the namespace root `prefix`
/// shows it: the point itself, never a link it is followed through (a
/// binary that is a symbolic link is the link) — but the root, whose link
/// is followed ([`follows_root`]).
fn point_metadata(prefix: &str, p: &str) -> std::io::Result<std::fs::Metadata> {
    let at = format!("{prefix}{p}");
    if follows_root(prefix, Path::new(p)) {
        antitamper_bpf::kernel_roots::metadata(&at)
    } else {
        antitamper_bpf::kernel_roots::symlink_metadata(&at)
    }
}

/// The file system magic of a path (`fstatfs(2)` of it opened `O_PATH`,
/// beneath the `/proc` root the start anchored for a path through
/// `/proc/1/root`: lot 357's item 5, no view walked by path).
fn magic_of(path: &str) -> Result<u64> {
    use std::os::fd::AsRawFd;
    let f = antitamper_bpf::kernel_roots::open(path, libc::O_PATH | libc::O_CLOEXEC)
        .with_context(|| format!("opening {path}"))?;
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: an open descriptor and a zeroed out-buffer of the right type.
    let rc = unsafe { libc::fstatfs(f.as_raw_fd(), &mut st) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("statfs {path}"));
    }
    Ok(st.f_type as u64)
}

/// `OVERLAYFS_SUPER_MAGIC` (`include/uapi/linux/magic.h`).
const OVERLAYFS_SUPER_MAGIC: u64 = 0x794c_7630;

/// The kernel's own file systems below `/sys` the agent reads (tracefs,
/// debugfs, securityfs): their super blocks are views' too, for a change
/// made in another namespace.
const VIEW_SB_EXTRA: [&str; 4] = [
    "/sys/kernel/tracing",
    "/sys/kernel/debug",
    "/sys/kernel/debug/tracing",
    "/sys/kernel/security",
];

/// The keys of the protected points that exist on this host, and the
/// degradations met (a view that is not its file system). Each view's
/// file system is also registered as `(device, 0)` (no inode is 0): a
/// mount from another namespace is below a view only on one of these.
fn resolve_points(points: &[(String, u8)]) -> (Vec<(InodeKey, u8, String)>, Vec<String>) {
    let mut keys = Vec::new();
    let mut degraded = Vec::new();
    for p in VIEW_SB_EXTRA {
        let host = in_host(p);
        if let (Ok(md), Ok(m)) = (
            antitamper_bpf::kernel_roots::metadata(&host),
            magic_of(&host),
        ) {
            if common::mount_guard::is_view_magic(m as u32) && m >> 32 == 0 {
                keys.push((
                    InodeKey {
                        dev: stat_dev_to_kernel_dev(md.dev()),
                        ino: 0,
                    },
                    MG_VIEW,
                    format!("{p} (its file system)"),
                ));
            }
        }
    }
    for (p, flags) in points {
        let host = in_host(p);
        // lot 359: `/` by the root PID 1's link names (MG_LOCK_ABOVE among
        // its kinds: `mount --make-rshared /` reaches the lock)
        let Ok(md) = point_metadata("/proc/1/root", p) else {
            continue;
        };
        if let Some((_, magics)) = VIEWS.iter().find(|(v, _)| v == p) {
            match magic_of(&host) {
                Ok(m) if magics.contains(&(m as u32)) && m >> 32 == 0 => {}
                // the unified hierarchy's directory of a unified host
                Ok(_) if *p == "/sys/fs/cgroup/unified" => continue,
                Ok(m) => {
                    degraded.push(format!(
                        "{p} is not the kernel's view (file system {m:#x}): not registered as one"
                    ));
                    continue;
                }
                Err(e) => {
                    degraded.push(format!("{p}: {e:#}"));
                    continue;
                }
            }
        }
        let dev = stat_dev_to_kernel_dev(md.dev());
        // The review of #567 (P3): on an overlay of layers on more than one
        // file system (without `xino`), `stat(2)` gives a file the layer's
        // pseudo device, while the hook reads the overlay's own (its
        // directories' device, which `stat(2)` gives them): the file's key
        // is registered with its directory's device too.
        if !md.is_dir() && magic_of(&host).ok() == Some(OVERLAYFS_SUPER_MAGIC) {
            if let Some(parent) = Path::new(&host).parent() {
                if let Ok(pmd) = antitamper_bpf::kernel_roots::metadata(parent) {
                    let odev = stat_dev_to_kernel_dev(pmd.dev());
                    if odev != dev {
                        keys.push((
                            InodeKey {
                                dev: odev,
                                ino: md.ino(),
                            },
                            *flags,
                            format!("{p} (by the overlay's device)"),
                        ));
                    }
                }
            }
        }
        if flags & MG_VIEW != 0 {
            keys.push((
                InodeKey { dev, ino: 0 },
                MG_VIEW,
                format!("{p} (its file system)"),
            ));
        }
        keys.push((InodeKey { dev, ino: md.ino() }, *flags, p.clone()));
    }
    (keys, degraded)
}

/// PID 1's mount and user namespaces (their `ns.inum`).
fn host_namespaces() -> Result<(u64, u64)> {
    let mnt = antitamper_bpf::kernel_roots::metadata("/proc/1/ns/mnt")
        .context("PID 1's mount namespace")?;
    let user = antitamper_bpf::kernel_roots::metadata("/proc/1/ns/user")
        .context("PID 1's user namespace")?;
    Ok((mnt.ino(), user.ino()))
}

/// The tracefs, debugfs and securityfs the agent reads (the tracepoint
/// formats, the kprobes switch, the lockdown state), by their canonical
/// point: an unmount of their mount is let through and recorded (the
/// review of #567, F6: they were let through unrecorded).
const NOTED_MOUNTS: [(&str, &str); 4] = [
    ("/sys/kernel/tracing", "tracefs"),
    ("/sys/kernel/debug", "debugfs"),
    ("/sys/kernel/debug/tracing", "tracefs"),
    ("/sys/kernel/security", "securityfs"),
];

/// Is `mp` the path or a directory above it?
fn on_path(mp: &Path, path: &Path) -> bool {
    mp == Path::new("/") || path.starts_with(mp)
}

/// The mounts a lookup of `path` crosses in a namespace's table, from its
/// root to the one it ends on: at each step the shallowest child of the
/// current mount on the path, of children at one mount point the last
/// listed (mounted on top) — the integrity round's resolution, by the
/// table alone (nothing is opened: a FUSE on the way cannot stall it).
fn chain<'a>(t: &'a [MountEntry], path: &Path) -> Vec<&'a MountEntry> {
    let ids: HashSet<u64> = t.iter().map(|m| m.id).collect();
    let Some(mut cur) = t
        .iter()
        .rfind(|m| m.mount_point == Path::new("/") && !ids.contains(&m.parent))
    else {
        return Vec::new();
    };
    let mut out = vec![cur];
    while out.len() <= t.len() {
        let next = t
            .iter()
            .filter(|m| {
                m.parent == cur.id
                    && m.id != cur.id
                    && m.mount_point.as_os_str().len() >= cur.mount_point.as_os_str().len()
                    && on_path(&m.mount_point, path)
            })
            .fold(None, |best: Option<&MountEntry>, m| match best {
                Some(b) if b.mount_point.as_os_str().len() < m.mount_point.as_os_str().len() => {
                    Some(b)
                }
                _ => Some(m),
            });
        match next {
            Some(n) if !out.iter().any(|c| c.id == n.id) => {
                out.push(n);
                cur = n;
            }
            _ => break,
        }
    }
    out
}

/// What one guarded namespace holds (the review of #567, F1 and F3).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct NsHeld {
    /// `MOUNT_HELD`'s entries: each held mount by its id, and by its
    /// parent's id and its root (a change propagated from elsewhere).
    pub entries: Vec<(InodeKey, u8)>,
    /// The super blocks of the held mounts (`s_dev`, the kernel's
    /// encoding): not reconfigured.
    pub sbs: Vec<u64>,
    /// The peer groups through which a change made elsewhere reaches this
    /// namespace's held mounts, views and the agent's directories: each
    /// one's own (`shared:N`) and its master's (`master:N`).
    pub groups: Vec<u32>,
}

/// A mount's peer groups, from its table line's optional fields: its own
/// (`shared:N`) and its master's (`master:N`), 0 for none.
pub(crate) type Groups = std::collections::HashMap<u64, (u32, u32)>;

/// [`Groups`] of a `mountinfo` text.
pub(crate) fn groups_of(text: &[u8]) -> Groups {
    let mut out = Groups::new();
    for line in text.split(|b| *b == b'\n') {
        let f: Vec<&[u8]> = line.split(|b| *b == b' ').collect();
        let Some(id) = f
            .first()
            .and_then(|x| std::str::from_utf8(x).ok()?.parse().ok())
        else {
            continue;
        };
        let (mut shared, mut master) = (0u32, 0u32);
        for opt in f.iter().skip(6).take_while(|x| **x != b"-") {
            let num = |p: &[u8]| -> u32 {
                std::str::from_utf8(&opt[p.len()..])
                    .ok()
                    .and_then(|n| n.parse().ok())
                    .unwrap_or(0)
            };
            if opt.starts_with(b"shared:") {
                shared = num(b"shared:");
            } else if opt.starts_with(b"master:") {
                master = num(b"master:");
            }
        }
        out.insert(id, (shared, master));
    }
    out
}

/// The mounts of a namespace's table (`t`) that its protected points
/// resolve through, by their id: no unmount, no move away (`HELD_REFUSE`);
/// the tracefs, debugfs and securityfs at their canonical points,
/// recorded (`MG_NOTE`); the super blocks of the held ones. And each held
/// one by its place, under its parent's own peer group and its master's
/// (`groups`): an unmount in a mount of either group at that place is
/// propagated onto it by the kernel. `dir_key` reads, in that namespace,
/// the key of a directory (the place's parent) — never below a FUSE (its
/// daemon could stall the read).
pub(crate) fn held_in(
    t: &[MountEntry],
    points: &[(String, u8)],
    guard: u8,
    groups: &Groups,
    dir_key: &dyn Fn(&Path) -> Option<(u64, u64)>,
) -> NsHeld {
    let tag = guard << HELD_NS_SHIFT;
    let mut held: Vec<&MountEntry> = Vec::new();
    for (p, _) in points {
        for m in chain(t, Path::new(p)) {
            if !held.iter().any(|h| h.id == m.id) {
                held.push(m);
            }
        }
    }
    let mut out = NsHeld::default();
    for m in &held {
        let (dev, ino) = held_by_id(m.id as u32);
        out.entries.push((InodeKey { dev, ino }, HELD_REFUSE | tag));
        // its place: the mountpoint's parent directory and its name, read
        // where the parent mount shows it (never below a FUSE)
        let parent = t.iter().find(|p| p.id == m.parent && p.id != m.id);
        if let (Some(parent), Some(name), Some(dir)) =
            (parent, m.mount_point.file_name(), m.mount_point.parent())
        {
            if !crate::mountinfo::is_fuse(&parent.fstype) {
                if let Some((ddev, dino)) = dir_key(dir) {
                    let name = NameKey::of_bytes(name.as_bytes());
                    let (shared, master) = groups.get(&parent.id).copied().unwrap_or((0, 0));
                    // the re-check of #567 (N1): and under the parent mount
                    // itself (`held_under`), for a parent regrouped after this
                    // read — the hook walks the parent's propagation for it
                    let groups = [shared, master].into_iter().filter(|g| *g != 0);
                    // — and under any group (`PLACE_ANY_GROUP`): asked of
                    // a parent when that walk is undecided (a copy of a
                    // held mount sits where it sits)
                    let keys = groups.map(|g| held_by_place(g, ddev, dino, &name)).chain([
                        held_under(parent.id as u32, ddev, dino, &name),
                        held_by_place(PLACE_ANY_GROUP, ddev, dino, &name),
                    ]);
                    for (dev, ino) in keys {
                        let k = InodeKey { dev, ino };
                        if !out.entries.iter().any(|(e, _)| *e == k) {
                            out.entries.push((k, HELD_REFUSE | tag));
                        }
                    }
                }
            }
        }
        // lot 1.1 (the review of #569, F2): and by its own peer group and
        // its root (`held_root`) — a peer copy of it moved away, in any
        // namespace, is refused (never read below a FUSE)
        let (own_group, _) = groups.get(&m.id).copied().unwrap_or((0, 0));
        if own_group != 0 && !crate::mountinfo::is_fuse(&m.fstype) {
            if let Some((rdev, rino)) = dir_key(&m.mount_point) {
                let (dev, ino) = held_root(own_group, rdev, rino);
                let k = InodeKey { dev, ino };
                if !out.entries.iter().any(|(e, _)| *e == k) {
                    out.entries.push((k, HELD_REFUSE | tag));
                }
            }
        }
        if !out.sbs.contains(&m.kernel_dev()) {
            out.sbs.push(m.kernel_dev());
        }
    }
    // the peer groups a change propagates into this namespace's held
    // mounts, its views and the agent's directories through
    let own: Vec<&str> = points
        .iter()
        .filter(|(_, f)| f & MG_OWN != 0)
        .map(|(p, _)| p.as_str())
        .collect();
    for m in t {
        let protected = held.iter().any(|h| h.id == m.id)
            || view_fs(m.fstype.as_bytes())
            || own.iter().any(|d| m.mount_point.starts_with(d));
        if !protected {
            continue;
        }
        let (shared, master) = groups.get(&m.id).copied().unwrap_or((0, 0));
        for g in [shared, master] {
            if g != 0 && !out.groups.contains(&g) {
                out.groups.push(g);
            }
        }
    }
    for (p, fstype) in NOTED_MOUNTS {
        let c = chain(t, Path::new(p));
        if let Some(m) = c.last().filter(|m| {
            m.mount_point == Path::new(p)
                && m.fstype.as_bytes() == fstype.as_bytes()
                && !held.iter().any(|h| h.id == m.id)
        }) {
            let (dev, ino) = held_by_id(m.id as u32);
            out.entries.push((InodeKey { dev, ino }, MG_NOTE | tag));
        }
    }
    out
}

/// The key of a directory, read in the namespace whose root `prefix` names
/// (`/proc/<pid>/root`, or "" for the caller's own): `O_PATH | O_NOFOLLOW
/// | O_DIRECTORY`, its device as the hooks read a dentry's (a btrfs
/// subvolume's own).
fn dir_key_in(prefix: &str, dir: &Path) -> Option<(u64, u64)> {
    let mut at = std::ffi::OsString::from(prefix);
    at.push(dir.as_os_str());
    // lot 359 (its mini-hunt): the root of a `/proc/<pid>/root` prefix is the
    // magic link itself — followed, or `O_NOFOLLOW` opened the link (no
    // directory) and every place under `/` (`/sys`, `/proc`, `/run`…) of
    // PID 1's and the watchdog's namespaces went unregistered
    let nofollow = if follows_root(prefix, dir) {
        0
    } else {
        libc::O_NOFOLLOW
    };
    // lot 357's item 5: through `/proc/<pid>/root`, beneath the `/proc` root
    // the start anchored
    let file = antitamper_bpf::kernel_roots::open(
        Path::new(&at),
        libc::O_PATH | nofollow | libc::O_DIRECTORY | libc::O_CLOEXEC,
    )
    .ok()?;
    let st = file.metadata().ok()?;
    Some((stat_dev_to_kernel_dev(st.dev()), st.ino()))
}

/// The file systems a view's mount is (the canonical layout), by its
/// point.
const VIEW_TYPES: [(&str, &[&str]); 6] = [
    ("/proc", &["proc"]),
    ("/sys", &["sysfs"]),
    ("/sys/fs/cgroup", &["cgroup2", "tmpfs"]),
    ("/sys/fs/cgroup/unified", &["cgroup2"]),
    ("/sys/fs/bpf", &["bpf"]),
    ("/run", &["tmpfs"]),
];

/// File systems that are never the canonical one over a directory that
/// holds the agent's paths (`/` aside, which may be any but a FUSE): what
/// lives in memory or in a user's daemon, and the stacking ones.
const NOT_CANONICAL_BELOW_ROOT: [&str; 8] = [
    "tmpfs", "ramfs", "overlay", "aufs", "squashfs", "erofs", "cramfs", "iso9660",
];

/// The re-check of #567 (N2): the overlays a host's own image tooling
/// merges at boot over a directory that holds the agent's paths, by point
/// and source — `systemd-sysext` over `/usr` and `/opt` (Flatcar: source
/// `sysext`), `systemd-confext` over `/etc` (`confext`), composefs over
/// `/usr` (Fedora Silverblue and CoreOS, bootc: `composefs`; over `/` any
/// file system but a FUSE is canonical already). A layout, not a proof:
/// root names a mount's source as it likes, and a runtime merge is refused
/// outside a window all the same.
const IMAGE_OVERLAYS: [(&str, &str); 4] = [
    ("/usr", "sysext"),
    ("/opt", "sysext"),
    ("/etc", "confext"),
    ("/usr", "composefs"),
];

/// [`IMAGE_OVERLAYS`]: an overlay at its point, with its tool's source.
fn image_overlay(m: &MountEntry) -> bool {
    m.fstype.as_bytes() == b"overlay"
        && IMAGE_OVERLAYS
            .iter()
            .any(|(p, src)| m.mount_point == Path::new(p) && m.source.as_bytes() == src.as_bytes())
}

/// The file systems whose mount shows a subvolume as its root (`/@`,
/// `/@var`): not a bind of another directory.
const SUBVOLUME_TYPES: [&str; 3] = ["btrfs", "bcachefs", "zfs"];

/// A view's file system (by magic: the kernel's own below it are judged
/// by the allow list).
fn view_fs(t: &[u8]) -> bool {
    matches!(
        t,
        b"proc" | b"sysfs" | b"cgroup2" | b"bpf" | b"tracefs" | b"debugfs" | b"securityfs"
    )
}

/// The brainstorm's 3rd point (the review of #567): the mounts of a
/// namespace's table that cover a protected point or lie below one of the
/// agent's directories or a view, and are not the canonical one there —
/// the mounts made before the guard attached (an fstab line, a `.mount`
/// unit, the initramfs, an early service), which the guard would
/// otherwise take for the host's own. By type, point and root:
/// - a view's point (and `/run`) holds its own type, whole;
/// - `/` holds anything but a FUSE;
/// - every other point (a directory above the agent's, its own, a binary)
///   holds no memory, FUSE or stacking file system, and no bind of another
///   directory (a subvolume's root, and a bind of a directory onto itself
///   — a unit's `ReadWritePaths=` — are canonical);
/// - below the agent's directories nothing is;
/// - below a view, the kernel's own pseudo-filesystems at their canonical
///   points only (`common::mount_guard::ALLOWED_KERNEL_MOUNT_PATHS`, a
///   hybrid host's v1 controllers, the tracefs below the debugfs).
///
/// Each finding names the mount: its point, type, source and root.
pub fn not_canonical(t: &[MountEntry], points: &[(String, u8)]) -> Vec<String> {
    not_canonical_in(t, points, &[])
}

/// [`not_canonical`] in a namespace one of our own units made: there, a
/// bind of exactly one of `sandbox`'s directories onto itself
/// ([`crate::mountinfo::is_self_bind`]) is the unit's own `ReadWritePaths=`
/// or `RuntimeDirectory=`, canonical even below one of the agent's
/// directories. Lot 377: the watchdog's `ReadWritePaths=` of the witness
/// directory, below the state directory, was a High at every start of the
/// watchdog. Another bind there (of another directory, or of a directory
/// the unit does not name, or below one it names) is still named.
pub fn not_canonical_in(
    t: &[MountEntry],
    points: &[(String, u8)],
    sandbox: &[String],
) -> Vec<String> {
    let mut out = Vec::new();
    let point_of = |mp: &Path| points.iter().find(|(p, _)| Path::new(p) == mp);
    let own: Vec<&str> = points
        .iter()
        .filter(|(_, f)| f & MG_OWN != 0)
        .map(|(p, _)| p.as_str())
        .collect();
    for m in t {
        let mp = m.mount_point.as_path();
        let ty = m.fstype.as_bytes();
        let parent = t.iter().find(|p| p.id == m.parent && p.id != m.id);
        let self_bind = parent.is_some_and(|p| crate::mountinfo::is_self_bind(m, p));
        let whole = m.root == Path::new("/");
        let why: Option<&str> = if let Some((p, _)) = point_of(mp) {
            if let Some((_, types)) = VIEW_TYPES.iter().find(|(v, _)| v == p) {
                if !types.iter().any(|t| t.as_bytes() == ty) {
                    Some("not the kernel's file system of that view")
                } else if !whole && !self_bind {
                    Some("a part of that file system, not its root")
                } else {
                    None
                }
            } else if mp == Path::new("/") {
                crate::mountinfo::is_fuse(&m.fstype).then_some("a FUSE as the root")
            } else if crate::mountinfo::is_fuse(&m.fstype) {
                Some("a FUSE over a directory that holds the agent's paths")
            } else if NOT_CANONICAL_BELOW_ROOT.iter().any(|t| t.as_bytes() == ty)
                && !self_bind
                && !image_overlay(m)
            {
                Some(
                    "a memory or stacking file system over a directory that holds the agent's paths",
                )
            } else if !whole && !self_bind && !SUBVOLUME_TYPES.iter().any(|t| t.as_bytes() == ty) {
                Some("a bind of another directory over one that holds the agent's paths")
            } else {
                None
            }
        } else if own.iter().any(|d| mp.starts_with(d) && mp != Path::new(d))
            && !(self_bind && sandbox.iter().any(|d| Path::new(d) == mp))
        {
            Some("below one of the agent's own directories")
        } else if VIEW_TYPES
            .iter()
            .any(|(v, _)| *v != "/run" && mp.starts_with(v))
            && parent.is_some_and(|p| view_fs(p.fstype.as_bytes()))
            && !kernel_mount_below_view(mp, ty)
        {
            Some("below a kernel view, and not the kernel's own pseudo-filesystem at its point")
        } else {
            None
        };
        if let Some(why) = why {
            out.push(format!(
                "{} ({}, source {}, root {}): {why}",
                mp.display(),
                m.fstype.to_string_lossy(),
                m.source.to_string_lossy(),
                m.root.display()
            ));
        }
    }
    out
}

/// A kernel pseudo-filesystem at its canonical point below a view.
fn kernel_mount_below_view(mp: &Path, ty: &[u8]) -> bool {
    let at = |p: &str, t: &str| mp == Path::new(p) && ty == t.as_bytes();
    common::mount_guard::ALLOWED_KERNEL_MOUNT_PATHS
        .iter()
        .zip(common::mount_guard::ALLOWED_KERNEL_MOUNT_TYPES)
        .any(|(p, t)| !p.contains('<') && at(p, t))
        || at("/sys/kernel/debug/tracing", "tracefs")
        // a hybrid host's v1 controllers, one level below the cgroup tmpfs
        || (ty == b"cgroup" && mp.parent() == Some(Path::new("/sys/fs/cgroup")))
}

/// Register the points (new keys first, then the stale ones of an earlier
/// start of this boot go: no window), the mounts held of PID 1's
/// namespace and the agent's own (the watchdog's are the refresh's), then
/// arm the guard on PID 1's namespace.
fn write_maps(
    ebpf: &mut Ebpf,
    keys: &[(InodeKey, u8, String)],
    held: &[(u8, &NsHeld)],
    ns: (u64, u64),
) -> Result<()> {
    let map = ebpf
        .map_mut(PROTECTED_MAP)
        .ok_or_else(|| anyhow!("map {PROTECTED_MAP} missing from the eBPF object"))?;
    let mut map: AyaHashMap<&mut MapData, AyaInodeKey, u8> = AyaHashMap::try_from(map)
        .with_context(|| format!("{PROTECTED_MAP} is not a HashMap<InodeKey, u8>"))?;
    // a key two paths share (a hard link, a bind, a super block) carries
    // every kind this start gives it — and no kind of an earlier start
    let mut merged: Vec<((u64, u64), u8, &str)> = Vec::new();
    for (key, flags, path) in keys {
        match merged.iter_mut().find(|(k, _, _)| *k == (key.dev, key.ino)) {
            Some((_, f, _)) => *f |= flags,
            None => merged.push(((key.dev, key.ino), *flags, path)),
        }
    }
    for ((dev, ino), flags, path) in &merged {
        map.insert(
            &AyaInodeKey(InodeKey {
                dev: *dev,
                ino: *ino,
            }),
            flags,
            0,
        )
        .with_context(|| format!("registering {path}"))?;
    }
    let keep: HashSet<(u64, u64)> = merged.iter().map(|(k, _, _)| *k).collect();
    let stale: Vec<AyaInodeKey> = map
        .keys()
        .filter_map(|k| k.ok())
        .filter(|k| !keep.contains(&(k.0.dev, k.0.ino)))
        .collect();
    for k in &stale {
        let _ = map.remove(k);
    }
    let hm = ebpf
        .map_mut(HELD_MAP)
        .ok_or_else(|| anyhow!("map {HELD_MAP} missing from the eBPF object"))?;
    let mut hm: AyaHashMap<&mut MapData, AyaInodeKey, u8> = AyaHashMap::try_from(hm)
        .with_context(|| format!("{HELD_MAP} is not a HashMap<InodeKey, u8>"))?;
    for (guard, h) in held {
        replace_held(&mut hm, *guard, h)?;
    }
    let gm = ebpf
        .map_mut(GROUPS_MAP)
        .ok_or_else(|| anyhow!("map {GROUPS_MAP} missing from the eBPF object"))?;
    let mut gm: AyaHashMap<&mut MapData, u32, u8> = AyaHashMap::try_from(gm)
        .with_context(|| format!("{GROUPS_MAP} is not a HashMap<u32, u8>"))?;
    for (guard, h) in held {
        replace_groups(&mut gm, *guard, &h.groups)?;
    }
    let nm = ebpf
        .map_mut(NS_MAP)
        .ok_or_else(|| anyhow!("map {NS_MAP} missing from the eBPF object"))?;
    let mut nm: AyaHashMap<&mut MapData, u64, u8> =
        AyaHashMap::try_from(nm).with_context(|| format!("{NS_MAP} is not a HashMap<u64, u8>"))?;
    set_guarded(&mut nm, ns.0, GUARD_HOST)?;
    let conf = ebpf
        .map_mut(CONF_MAP)
        .ok_or_else(|| anyhow!("map {CONF_MAP} missing from the eBPF object"))?;
    let mut conf: AyaArray<&mut MapData, u64> =
        AyaArray::try_from(conf).with_context(|| format!("{CONF_MAP} is not an Array<u64>"))?;
    conf.set(1, &ns.1, 0)?;
    conf.set(0, &ns.0, 0)?;
    Ok(())
}

/// One namespace's `MOUNT_HELD` entries replaced: the new ones first, then
/// that namespace's others go (another namespace's stay).
fn replace_held<T>(hm: &mut AyaHashMap<T, AyaInodeKey, u8>, guard: u8, h: &NsHeld) -> Result<()>
where
    T: std::borrow::Borrow<MapData> + std::borrow::BorrowMut<MapData>,
{
    for (k, v) in &h.entries {
        hm.insert(&AyaInodeKey(*k), v, 0)
            .with_context(|| format!("registering a held mount ({:#x})", k.dev))?;
    }
    let keep: HashSet<(u64, u64)> = h.entries.iter().map(|(k, _)| (k.dev, k.ino)).collect();
    let stale: Vec<AyaInodeKey> = hm
        .iter()
        .filter_map(|e| e.ok())
        .filter(|(k, v)| v >> HELD_NS_SHIFT == guard && !keep.contains(&(k.0.dev, k.0.ino)))
        .map(|(k, _)| k)
        .collect();
    for k in &stale {
        let _ = hm.remove(k);
    }
    Ok(())
}

/// One namespace's peer groups in `MOUNT_GROUPS` (a bit per namespace):
/// the new ones set first, then that namespace's bit cleared elsewhere (an
/// entry no namespace's bit holds goes).
fn replace_groups<T>(gm: &mut AyaHashMap<T, u32, u8>, guard: u8, groups: &[u32]) -> Result<()>
where
    T: std::borrow::Borrow<MapData> + std::borrow::BorrowMut<MapData>,
{
    let bit = 1u8 << guard;
    for g in groups {
        let have = gm.get(g, 0).unwrap_or(0);
        gm.insert(g, &(have | bit), 0)
            .with_context(|| format!("registering the peer group {g}"))?;
    }
    let stale: Vec<(u32, u8)> = gm
        .iter()
        .filter_map(|e| e.ok())
        .filter(|(g, v)| v & bit != 0 && !groups.contains(g))
        .collect();
    for (g, v) in stale {
        if v & !bit == 0 {
            let _ = gm.remove(&g);
        } else {
            let _ = gm.insert(&g, &(v & !bit), 0);
        }
    }
    Ok(())
}

/// `MOUNT_GUARD_NS[inum] = guard`, and any other namespace of that kind
/// gone (an earlier agent's or watchdog's, if its exit left it).
fn set_guarded<T>(nm: &mut AyaHashMap<T, u64, u8>, inum: u64, guard: u8) -> Result<()>
where
    T: std::borrow::Borrow<MapData> + std::borrow::BorrowMut<MapData>,
{
    nm.insert(&inum, &guard, 0)
        .with_context(|| format!("guarding the mount namespace {inum}"))?;
    let stale: Vec<u64> = nm
        .iter()
        .filter_map(|e| e.ok())
        .filter(|(k, v)| *v == guard && *k != inum)
        .map(|(k, _)| k)
        .collect();
    for k in &stale {
        let _ = nm.remove(k);
    }
    Ok(())
}

/// A prior start's pins of the guard go when this one does not attach it:
/// an older program must not stay attached with points no one refreshes.
fn purge_pins(pin_root: Option<&Path>) {
    if let Some(root) = pin_root {
        for (_, hook) in PROGRAMS
            .iter()
            .chain([&RECONF_PROGRAM, &PROPAGATION_PROGRAM])
        {
            let (prog, link) = antitamper_bpf::lsm_pin_paths(root, hook);
            antitamper_bpf::purge_stale_pin(&link);
            antitamper_bpf::purge_stale_pin(&prog);
        }
        // lot 1.1: and the stages' arrays (emptied once no one holds them)
        for array in [SB_STAGES_MAP, MOVE_STAGES_MAP] {
            antitamper_bpf::purge_stale_pin(&root.join(array));
        }
    }
}

/// Lot 1.1 (F8b-1): `hook`'s stages ([`STAGES`]) loaded and put in their
/// program array's slots — before its entry is attached. An error: the
/// entry must not be attached (it would let through what a stage judges).
fn load_stages(ebpf: &mut Ebpf, hook: &str, btf: &Btf) -> Result<()> {
    use aya::maps::ProgramArray;
    use aya::programs::Lsm;
    for (program, h, array, slot) in STAGES.iter().filter(|s| s.1 == hook) {
        if let Some(e) = injected_refusal(program) {
            return Err(e);
        }
        let prog: &mut Lsm = ebpf
            .program_mut(program)
            .ok_or_else(|| anyhow!("program {program} missing from the eBPF object"))?
            .try_into()
            .with_context(|| format!("program {program} is not an LSM program"))?;
        prog.load(h, btf)
            .with_context(|| format!("verifier rejected LSM program `{program}`"))?;
        let fd = prog
            .fd()
            .map_err(anyhow::Error::from)
            .and_then(|f| f.try_clone().map_err(anyhow::Error::from))
            .with_context(|| format!("the descriptor of `{program}`"))?;
        let map = ebpf
            .map_mut(array)
            .ok_or_else(|| anyhow!("map {array} missing from the eBPF object"))?;
        let mut pa: ProgramArray<&mut MapData> = ProgramArray::try_from(map)?;
        pa.set(*slot, &fd, 0)
            .with_context(|| format!("`{program}` into {array}[{slot}]"))?;
    }
    Ok(())
}

/// The program array of `hook`'s stages, if it has any.
fn stages_of(hook: &str) -> Option<&'static str> {
    STAGES.iter().find(|s| s.1 == hook).map(|s| s.2)
}

/// Lot 1.1: descriptors of the stages' program arrays, held for the
/// agent's life — a program array is emptied when its last user reference
/// goes (its pin removed or hidden, the bpffs's last mount gone), and an
/// entry's tail call then finds no stage.
static HELD_STAGES: std::sync::Mutex<Vec<std::os::fd::OwnedFd>> = std::sync::Mutex::new(Vec::new());

/// Lot 1.1: `array` held ([`HELD_STAGES`]) and, with a pin root, pinned
/// there in place of a prior start's — after this start's entry is
/// attached, whose purge retired the prior entry that used the prior array.
fn hold_stages(ebpf: &mut Ebpf, array: &str, pin_root: Option<&Path>) -> Result<()> {
    use std::os::fd::AsFd;
    let map = ebpf
        .map_mut(array)
        .ok_or_else(|| anyhow!("map {array} missing from the eBPF object"))?;
    let own = super::bpf_defense::map_data(map)
        .fd()
        .as_fd()
        .try_clone_to_owned()
        .with_context(|| format!("holding {array}"))?;
    if let Ok(mut h) = HELD_STAGES.lock() {
        h.push(own);
    }
    if let Some(root) = pin_root {
        let path = root.join(array);
        antitamper_bpf::purge_stale_pin(&path);
        map.pin(&path)
            .with_context(|| format!("pinning {array} to {}", path.display()))?;
    }
    Ok(())
}

/// The maps the watchdog refresh opens, pinned at this start's objects
/// (the loader makes no by-name pin: as `PROTECTED_PIDS`).
fn pin_maps(ebpf: &mut Ebpf, root: &Path) -> Result<()> {
    for name in PINNED_MAPS {
        let path = root.join(name);
        antitamper_bpf::purge_stale_pin(&path);
        ebpf.map_mut(name)
            .ok_or_else(|| anyhow!("map {name} missing from the eBPF object"))?
            .pin(&path)
            .with_context(|| format!("pinning {name} to {}", path.display()))?;
    }
    Ok(())
}

/// A namespace's table: `/proc/<pid>/mountinfo` (`pid` "1", "self" or a
/// number).
fn table_of(pid: &str) -> Result<(Vec<MountEntry>, Groups)> {
    let path = format!("/proc/{pid}/mountinfo");
    // lot 357's item 5: beneath the `/proc` root the start anchored, bounded
    let text = crate::mountinfo::read_bytes(Path::new(&path))
        .with_context(|| format!("reading {path}"))?;
    Ok((crate::mountinfo::parse(&text).entries, groups_of(&text)))
}

/// Every protected point now, in PID 1's root (the integrity round's view
/// of what the guard holds).
pub fn points_now() -> Vec<(String, u8)> {
    points_in_host(antitamper_bpf::prepare_pin_root())
}

/// Lot 379 (pre-alpha F8b-1, F7-2): the test builds' fault injection of a
/// verifier refusal — the guard's programs named here (comma-separated:
/// `mount_guard_sb_mount`, … `mount_guard_reconfigure`) are refused at
/// their load as a verifier refusal would refuse them, the rest of the
/// start untouched. Read only in a build with `test-privileged` (nn-linux's
/// test-only feature, the agent's privileged suites'; never in a release:
/// `xtask/tests/supply_chain.rs`, release.yml's `--build-features` check);
/// in any other build nothing reads it. A weakening variable
/// ([`refusal_weakens`]): a test build that honours it reports it.
pub const VERIFIER_REFUSE_ENV: &str = "NN_TEST_VERIFIER_REFUSE";

/// Whether [`VERIFIER_REFUSE_ENV`] set to `value` weakens this build: in a
/// test build (`test-privileged`), any program named.
pub fn refusal_weakens(value: &str) -> bool {
    cfg!(feature = "test-privileged") && value.split(',').any(|p| !p.trim().is_empty())
}

/// The verifier refusal [`VERIFIER_REFUSE_ENV`] injects for `program`, in a
/// test build: the error the load gives (`antitamper_bpf::reattach_fresh`'s
/// context over aya's `BPF_PROG_LOAD` failure), marked as injected.
#[cfg(feature = "test-privileged")]
fn injected_refusal(program: &str) -> Option<anyhow::Error> {
    let named = std::env::var(VERIFIER_REFUSE_ENV).ok()?;
    if !named.split(',').any(|p| p.trim() == program) {
        return None;
    }
    warn!(
        program,
        env = VERIFIER_REFUSE_ENV,
        "TEST FAULT INJECTION: the verifier's refusal of this program is simulated (a test \
         build only)"
    );
    Some(
        anyhow!(
            "the BPF_PROG_LOAD syscall failed. Verifier output: BPF program is too large. \
             Processed 1000001 insn (injected by {VERIFIER_REFUSE_ENV}, a test build)"
        )
        .context(format!("verifier rejected LSM program `{program}`")),
    )
}

#[cfg(not(feature = "test-privileged"))]
fn injected_refusal(_program: &str) -> Option<anyhow::Error> {
    None
}

/// One hook of the guard loaded (the verifier) and attached, pinned.
fn load_lsm(
    ebpf: &mut Ebpf,
    program: &str,
    hook: &str,
    btf: &Btf,
    pin_root: Option<&Path>,
) -> Result<()> {
    if let Some(e) = injected_refusal(program) {
        return Err(e);
    }
    super::reattach_fresh(ebpf, program, hook, btf, pin_root)
}

/// The reconfigure's `fentry` loaded and attached, pinned.
fn load_fentry(
    ebpf: &mut Ebpf,
    program: &str,
    target: &str,
    btf: &Btf,
    pin_root: Option<&Path>,
) -> Result<()> {
    if let Some(e) = injected_refusal(program) {
        return Err(e);
    }
    antitamper_bpf::reattach_fresh_fentry(ebpf, program, target, btf, pin_root)
}

/// Register, arm and attach the guard. Never fails the start: what is not
/// attached is a signed degradation.
pub(crate) fn attach(ebpf: &mut Ebpf, btf: &Btf, pin_root: Option<&Path>) -> Health {
    let mut health = Health::default();
    let absent: Option<Vec<&str>> =
        super::btf_revalidate::resolved().map(|r| r.absent.iter().map(|m| m.name).collect());
    if let Some(why) = offsets_refusal(absent.as_deref()) {
        warn!(reason = %why, effect = ABSENT_EFFECT, "anti-tamper mount guard: not attached");
        purge_pins(pin_root);
        health
            .degraded
            .push(format!("mount guard not attached: {why} ({ABSENT_EFFECT})"));
        return health;
    }
    let ns = match host_namespaces() {
        Ok(ns) => ns,
        Err(e) => {
            warn!(error = %format!("{e:#}"), "anti-tamper mount guard: not attached");
            purge_pins(pin_root);
            health
                .degraded
                .push(format!("mount guard not attached: {e:#} ({ABSENT_EFFECT})"));
            return health;
        }
    };
    let points = points_in_host(pin_root);
    let (mut keys, degraded) = resolve_points(&points);
    for d in degraded {
        health.degraded.push(format!("mount guard: {d}"));
    }
    // The review of #567 (F1, F3): the mounts held in PID 1's namespace
    // and the agent's own, and their super blocks; the brainstorm's 3rd
    // point: the mounts already there that are not the canonical ones.
    let mut held: Vec<(u8, NsHeld)> = Vec::new();
    for (guard, pid, prefix, whose) in [
        (GUARD_HOST, "1", "/proc/1/root", "PID 1's"),
        (GUARD_AGENT, "self", "", "the agent's own"),
    ] {
        match table_of(pid) {
            Ok((t, groups)) => {
                let h = held_in(&t, &points, guard, &groups, &|d| dir_key_in(prefix, d));
                for sb in &h.sbs {
                    keys.push((
                        InodeKey { dev: *sb, ino: 0 },
                        MG_SB,
                        format!("the super block {sb:#x}"),
                    ));
                }
                held.push((guard, h));
                for f in not_canonical(&t, &points) {
                    health.degraded.push(format!(
                        "mount guard: a mount made before it attached, in {whose} mount \
                         namespace, is not the canonical one there — {f}"
                    ));
                }
            }
            Err(e) => health.degraded.push(format!(
                "mount guard: {whose} mount namespace's mounts are not held (an unmount of one \
                 is not refused): {e:#}"
            )),
        }
    }
    let refs: Vec<(u8, &NsHeld)> = held.iter().map(|(g, h)| (*g, h)).collect();
    if let Err(e) = write_maps(ebpf, &keys, &refs, ns) {
        warn!(error = %format!("{e:#}"), "anti-tamper mount guard: not armed");
        purge_pins(pin_root);
        health
            .degraded
            .push(format!("mount guard not armed: {e:#} ({ABSENT_EFFECT})"));
        return health;
    }
    if let Some(root) = pin_root {
        if let Err(e) = pin_maps(ebpf, root) {
            health.degraded.push(format!(
                "mount guard: its maps are not pinned — the watchdog's mount namespace is not \
                 judged as PID 1's: {e:#}"
            ));
        }
    }
    health.points = keys.len();
    let mut missing = Vec::new();
    for (program, hook) in PROGRAMS {
        // lot 1.1 (F8b-1): a split hook's stages first, in their slots; the
        // entry attached only with every one (then their array pinned)
        let loaded = match stages_of(hook) {
            Some(array) => load_stages(ebpf, hook, btf).map(|()| Some(array)),
            None => Ok(None),
        };
        match loaded.and_then(|array| {
            load_lsm(ebpf, program, hook, btf, pin_root)?;
            if let Some(array) = array {
                if let Err(e) = hold_stages(ebpf, array, pin_root) {
                    health.degraded.push(format!(
                        "mount guard: {hook}'s stages are not pinned or held — after the \
                         agent's exit its entry finds no stage and lets the mounts through, \
                         counted ({e:#})"
                    ));
                }
            }
            Ok(())
        }) {
            Ok(()) => health.attached += 1,
            Err(e) => {
                let why = if super::filesystem::lsm_hook_absent(&e, hook) {
                    format!("{hook}: the kernel has no such LSM hook")
                } else {
                    format!("{hook}: {e:#}")
                };
                warn!(program, hook, error = %why, "anti-tamper mount guard: hook NOT attached");
                if let Some(root) = pin_root {
                    let (prog, link) = antitamper_bpf::lsm_pin_paths(root, hook);
                    antitamper_bpf::purge_stale_pin(&link);
                    antitamper_bpf::purge_stale_pin(&prog);
                }
                missing.push(why);
            }
        }
    }
    // the reconfigure's flags (without them every remount of a held super
    // block is refused, whatever it asks)
    if let Err(e) = load_fentry(ebpf, RECONF_PROGRAM.0, RECONF_PROGRAM.1, btf, pin_root) {
        warn!(error = %format!("{e:#}"), "anti-tamper mount guard: reconfigure flags not read");
        health.degraded.push(format!(
            "mount guard: a remount's new flags are not read ({e:#}): every remount of the file \
             systems the agent's paths are on is refused, a writable one too"
        ));
    }
    // lot 1.1 (the review of #569, F1b): a propagation change counted as
    // the kernel makes it — mount_setattr(2)'s among them
    if let Err(e) = load_fentry(
        ebpf,
        PROPAGATION_PROGRAM.0,
        PROPAGATION_PROGRAM.1,
        btf,
        pin_root,
    ) {
        warn!(error = %format!("{e:#}"), "anti-tamper mount guard: propagation changes not counted at once");
        health
            .degraded
            .push(format!("mount guard: {PROPAGATION_ABSENT_EFFECT} ({e:#})"));
    }
    if missing.is_empty() {
        info!(
            hooks = health.attached,
            points = health.points,
            host_mnt_ns = ns.0,
            "anti-tamper mount guard: attached — a mount on, over or below the agent's paths is \
             refused in the host's namespace"
        );
    } else {
        health.degraded.push(format!(
            "mount guard: {} of {} hooks attached ({}): {ABSENT_EFFECT}",
            health.attached,
            PROGRAMS.len(),
            missing.join("; ")
        ));
    }
    health
}

/// The mount namespace of a process (`/proc/<pid>/ns/mnt`'s inode).
fn mnt_ns_of(pid: &str) -> Result<u64> {
    let p = format!("/proc/{pid}/ns/mnt");
    Ok(antitamper_bpf::kernel_roots::metadata(&p)
        .with_context(|| p.clone())?
        .ino())
}

/// The review of #567 (F2): the agent's own mount namespace — its unit's
/// `ProtectSystem=strict`, the one it reads its paths through — judged as
/// PID 1's, once the agent holds its role (`ROLE_TGIDS`: the liveness
/// watch then drops the namespace at the agent's exit, before its number
/// can be another's). Called after the role is claimed; a signed
/// degradation when it cannot be.
pub(crate) fn guard_own_namespace(ebpf: &mut Ebpf) -> Option<String> {
    let me = std::process::id();
    let role = ebpf
        .map(antitamper_bpf::ROLE_TGIDS_MAP_NAME)
        .and_then(|m| AyaArray::<&MapData, u32>::try_from(m).ok())
        .and_then(|a| a.get(&antitamper_bpf::ROLE_SLOT_AGENT, 0).ok());
    if role != Some(me) {
        return Some(format!(
            "mount guard: the agent's own mount namespace is not judged as PID 1's (its role is \
             not held: the liveness watch that drops it at the agent's exit is not running) — a \
             mount made inside it is not refused ({ABSENT_EFFECT})"
        ));
    }
    let r = (|| -> Result<u64> {
        let inum = mnt_ns_of("self")?;
        let own = {
            let conf = ebpf
                .map_mut(CONF_MAP)
                .ok_or_else(|| anyhow!("map {CONF_MAP} missing from the eBPF object"))?;
            let mut conf: AyaArray<&mut MapData, u64> = AyaArray::try_from(conf)?;
            // lot 1.1 (the re-check 2 of #569, N3): an agent run by hand in
            // PID 1's namespace never takes PID 1's entry as its own (nor
            // hands it to `vacate` at its exit)
            let own = guards_own_namespace(inum, conf.get(&0, 0)?);
            conf.set(CONF_AGENT_NS, &(if own { inum } else { 0 }), 0)?;
            own
        };
        if own {
            let nm = ebpf
                .map_mut(NS_MAP)
                .ok_or_else(|| anyhow!("map {NS_MAP} missing from the eBPF object"))?;
            let mut nm: AyaHashMap<&mut MapData, u64, u8> = AyaHashMap::try_from(nm)?;
            set_guarded(&mut nm, inum, GUARD_AGENT)?;
        }
        Ok(inum)
    })();
    match r {
        Ok(inum) => {
            info!(
                agent_mnt_ns = inum,
                "anti-tamper mount guard: the agent's own mount namespace is judged as PID 1's"
            );
            None
        }
        Err(e) => Some(format!(
            "mount guard: the agent's own mount namespace is not judged as PID 1's: {e:#}"
        )),
    }
}

/// The review of #567 (the cross-model check): PID 1's namespace's and the
/// agent's own held mounts, their super blocks and the peer groups that
/// reach them, read again — from the agent's watchdog refresh, by the
/// maps' pins (the watchdog's by [`guard_watchdog`]). What changed since
/// the start is followed: a propagation change (a new peer group), the
/// tracefs or debugfs automounted since, a mount a window left over a
/// protected path (signed by the integrity round, held from now on).
pub fn refresh(bpffs_root: &Path) -> Result<usize> {
    use aya::maps::Map;
    let open = |name: &str| -> Result<MapData> {
        let path = bpffs_root.join(name);
        MapData::from_pin(&path).with_context(|| format!("opening pinned {name}"))
    };
    let points = points_in_host(Some(bpffs_root));
    let mut hm: AyaHashMap<MapData, AyaInodeKey, u8> =
        AyaHashMap::try_from(Map::HashMap(open(HELD_MAP)?))?;
    let mut gm: AyaHashMap<MapData, u32, u8> =
        AyaHashMap::try_from(Map::HashMap(open(GROUPS_MAP)?))?;
    let mut pm: AyaHashMap<MapData, AyaInodeKey, u8> =
        AyaHashMap::try_from(Map::HashMap(open(PROTECTED_MAP)?))?;
    let mut n = 0;
    for (guard, pid, prefix) in [(GUARD_HOST, "1", "/proc/1/root"), (GUARD_AGENT, "self", "")] {
        let (t, groups) = table_of(pid)?;
        let h = held_in(&t, &points, guard, &groups, &|d| dir_key_in(prefix, d));
        replace_held(&mut hm, guard, &h)?;
        replace_groups(&mut gm, guard, &h.groups)?;
        for sb in &h.sbs {
            let k = AyaInodeKey(InodeKey { dev: *sb, ino: 0 });
            let have = pm.get(&k, 0).unwrap_or(0);
            if have & MG_SB == 0 {
                pm.insert(&k, &(have | MG_SB), 0)?;
            }
        }
        n += h.entries.len();
    }
    Ok(n)
}

/// The re-check of #567 (N1): the propagation changes the hooks let through
/// since the last look — `mount(2)`'s `MS_SHARED`, `MS_PRIVATE`,
/// `MS_SLAVE`, `MS_UNBINDABLE` on a mount of a guarded namespace or of a
/// peer group `MOUNT_GROUPS` holds, a `move_mount(2)` of a mount in a peer
/// group into a guarded namespace (`MOVE_MOUNT_SET_GROUP` among them). Each
/// may give a guarded mount a group the map does not hold yet (the hook
/// walks one it does not): the agent looks each second and refreshes the
/// maps when the count moved ([`refresh_now`]).
pub struct RegroupWatch {
    conf: AyaArray<MapData, u64>,
    seen: u64,
    /// Lot 1.1: [`CONF_PROPAGATED`] at the last look.
    seen_made: u64,
}

impl RegroupWatch {
    /// The count, by the maps' pins (the guard attached at this start).
    pub fn open(bpffs_root: &Path) -> Result<RegroupWatch> {
        use aya::maps::Map;
        let path = bpffs_root.join(CONF_MAP);
        let data =
            MapData::from_pin(&path).with_context(|| format!("opening pinned {CONF_MAP}"))?;
        let conf: AyaArray<MapData, u64> = AyaArray::try_from(Map::Array(data))?;
        let seen = conf.get(&CONF_REGROUP, 0)?;
        let seen_made = conf.get(&CONF_PROPAGATED, 0).unwrap_or(0);
        Ok(RegroupWatch {
            conf,
            seen,
            seen_made,
        })
    }

    /// Lot 1.1 (the review of #569, F1b): a propagation change was made on
    /// a mount the guard holds, of a held group, or on the pin directory's
    /// lock, since the last look — `mount_setattr(2)`'s among them, which no
    /// hook refuses (the `change_mnt_propagation()` fentry's count,
    /// [`CONF_PROPAGATED`]): what the integrity round compares (the lock's
    /// flags, the mounts' attributes) is worth reading now rather than at
    /// its next round.
    pub fn propagated(&mut self) -> bool {
        match self.conf.get(&CONF_PROPAGATED, 0) {
            Ok(n) if n != self.seen_made => {
                self.seen_made = n;
                true
            }
            _ => false,
        }
    }

    /// The count moved since the last look (an unreadable slot: not).
    pub fn moved(&mut self) -> bool {
        match self.conf.get(&CONF_REGROUP, 0) {
            Ok(n) if n != self.seen => {
                self.seen = n;
                true
            }
            _ => false,
        }
    }
}

/// Lot 359 (the re-check 3 of #567, N4): the regroup watch woken — the
/// count it follows (`MOUNT_GUARD_CONF`'s [`CONF_REGROUP`]) moved by one, by
/// the map's pin — so that every guarded namespace's held mounts are read
/// again within a second ([`refresh_now`], under the watch's one refresh
/// handle): the pin directory's lock, made again by the integrity round, is
/// held by its new id.
pub fn wake_refresh(bpffs_root: &Path) -> Result<()> {
    use aya::maps::Map;
    let path = bpffs_root.join(CONF_MAP);
    let data = MapData::from_pin(&path).with_context(|| format!("opening pinned {CONF_MAP}"))?;
    let mut conf: AyaArray<MapData, u64> = AyaArray::try_from(Map::Array(data))?;
    let n = conf.get(&CONF_REGROUP, 0)?;
    conf.set(CONF_REGROUP, &n.wrapping_add(1), 0)?;
    Ok(())
}

/// The re-check of #567 (N1): every guarded namespace's held mounts and
/// peer groups read again now — PID 1's and the agent's ([`refresh`]), and
/// the watchdog's, the holder of its role ([`guard_watchdog`]; its errors
/// are the watchdog refresh's to report). The caller holds the agent's one
/// refresh handle (the watchdog refresh's lock: each refresh replaces a
/// namespace's entries, new ones first, then the stale ones go).
pub fn refresh_now(bpffs_root: &Path) -> Result<usize> {
    use aya::maps::Map;
    let n = refresh(bpffs_root)?;
    let roles: AyaArray<MapData, u32> = AyaArray::try_from(Map::Array(MapData::from_pin(
        bpffs_root.join(antitamper_bpf::ROLE_TGIDS_MAP_NAME),
    )?))?;
    if let Ok(pid) = roles.get(&antitamper_bpf::ROLE_SLOT_WATCHDOG, 0) {
        if pid != 0 {
            let _ = guard_watchdog(bpffs_root, pid);
        }
    }
    Ok(n)
}

/// [`not_canonical_in`] the watchdog's mount namespace (`t`): its own
/// unit's sandbox binds, read from the shipped unit as the integrity round
/// reads them (`MountSource::Watchdog`), are canonical there (lot 377).
pub fn watchdog_not_canonical(t: &[MountEntry], points: &[(String, u8)]) -> Vec<String> {
    not_canonical_in(
        t,
        points,
        &crate::self_integrity::watchdog_unit_sandbox_dirs(),
    )
}

/// What a watchdog's registration found: the mounts of its namespace that
/// are not the canonical ones (each a signed High of the refresh).
#[derive(Debug, Default)]
pub struct WatchdogGuard {
    pub mnt_ns: u64,
    pub not_canonical: Vec<String>,
}

/// The review of #567 (F2): the verified watchdog's mount namespace judged
/// as PID 1's, and its held mounts registered — from the agent's watchdog
/// refresh (by the maps' pins), once the watchdog holds its role
/// (`ROLE_TGIDS` slot 0: the liveness watch drops the namespace at its
/// exit). A watchdog that does not hold it is not guarded (an error).
pub fn guard_watchdog(bpffs_root: &Path, pid: u32) -> Result<WatchdogGuard> {
    use aya::maps::Map;
    let open = |name: &str| -> Result<MapData> {
        let path = bpffs_root.join(name);
        MapData::from_pin(&path).with_context(|| format!("opening pinned {name}"))
    };
    let roles: AyaArray<MapData, u32> =
        AyaArray::try_from(Map::Array(open(antitamper_bpf::ROLE_TGIDS_MAP_NAME)?))?;
    let holder = roles.get(&antitamper_bpf::ROLE_SLOT_WATCHDOG, 0).ok();
    if holder != Some(pid) {
        return Err(anyhow!(
            "the watchdog {pid} does not hold its role (the role's holder: {holder:?}) — its \
             mount namespace is not judged as PID 1's"
        ));
    }
    let who = pid.to_string();
    let inum = mnt_ns_of(&who)?;
    let (t, groups) = table_of(&who)?;
    let points = points_in_host(Some(bpffs_root));
    let prefix = format!("/proc/{pid}/root");
    let h = held_in(&t, &points, GUARD_WATCHDOG, &groups, &|d| {
        dir_key_in(&prefix, d)
    });
    let mut hm: AyaHashMap<MapData, AyaInodeKey, u8> =
        AyaHashMap::try_from(Map::HashMap(open(HELD_MAP)?))?;
    replace_held(&mut hm, GUARD_WATCHDOG, &h)?;
    let mut gm: AyaHashMap<MapData, u32, u8> =
        AyaHashMap::try_from(Map::HashMap(open(GROUPS_MAP)?))?;
    replace_groups(&mut gm, GUARD_WATCHDOG, &h.groups)?;
    let mut pm: AyaHashMap<MapData, AyaInodeKey, u8> =
        AyaHashMap::try_from(Map::HashMap(open(PROTECTED_MAP)?))?;
    for sb in &h.sbs {
        let k = AyaInodeKey(InodeKey { dev: *sb, ino: 0 });
        let have = pm.get(&k, 0).unwrap_or(0);
        if have & MG_SB == 0 {
            pm.insert(&k, &(have | MG_SB), 0)?;
        }
    }
    let mut conf: AyaArray<MapData, u64> = AyaArray::try_from(Map::Array(open(CONF_MAP)?))?;
    let mut nm: AyaHashMap<MapData, u64, u8> = AyaHashMap::try_from(Map::HashMap(open(NS_MAP)?))?;
    // lot 1.1 (the re-check 2 of #569, N3): a watchdog run by hand in PID
    // 1's namespace is judged there as PID 1's: its entry kept
    if guards_own_namespace(inum, conf.get(&0, 0)?) {
        conf.set(CONF_WATCHDOG_NS, &inum, 0)?;
        set_guarded(&mut nm, inum, GUARD_WATCHDOG)?;
    } else {
        conf.set(CONF_WATCHDOG_NS, &0, 0)?;
    }
    Ok(WatchdogGuard {
        mnt_ns: inum,
        not_canonical: watchdog_not_canonical(&t, &points),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flags(points: &[(String, u8)], p: &str) -> u8 {
        points
            .iter()
            .find(|(q, _)| q == p)
            .map(|(_, f)| *f)
            .unwrap_or(0)
    }

    /// The brief's protected roots, each with its kind, and its mount held.
    #[test]
    fn every_path_the_agent_depends_on_is_a_protected_point() {
        let pts = protected_points(Some(Path::new("/sys/fs/bpf/northnarrow")), &|_| true);
        for v in [
            "/proc",
            "/sys",
            "/sys/fs/cgroup",
            "/sys/fs/cgroup/unified",
            "/sys/fs/bpf",
        ] {
            assert_eq!(
                flags(&pts, v) & (MG_VIEW | MG_HOLD),
                MG_VIEW | MG_HOLD,
                "{v}"
            );
        }
        for d in [
            "/etc/northnarrow",
            "/run/northnarrow",
            "/var/lib/northnarrow",
            "/sys/fs/bpf/northnarrow",
            "/etc/systemd/system/northnarrow-agent.service.d",
        ] {
            assert_eq!(flags(&pts, d) & (MG_OWN | MG_HOLD), MG_OWN | MG_HOLD, "{d}");
        }
        for b in [
            "/usr/local/bin",
            "/usr/bin",
            "/usr/local/bin/northnarrow-agent",
            "/usr/bin/northnarrow-watchdog",
            "/etc/systemd/system/northnarrow-agent.service",
        ] {
            assert_ne!(flags(&pts, b) & MG_ON, 0, "{b}");
        }
        // a tmpfs over /var/lib, an overlay over /etc, a bind over / or
        // /run: the directories above
        for a in [
            "/",
            "/etc",
            "/var",
            "/var/lib",
            "/run",
            "/usr",
            "/usr/local",
            "/etc/systemd/system",
        ] {
            assert_eq!(flags(&pts, a) & (MG_ON | MG_HOLD), MG_ON | MG_HOLD, "{a}");
        }
        // the coordinator's ancestors point: by the directory's own identity,
        // never a prefix — another subdirectory of an ancestor is no point
        for other in [
            "/var/lib/docker",
            "/run/user",
            "/run/user/1000",
            "/etc/ssh",
            "/var/log",
            "/usr/share",
        ] {
            assert_eq!(flags(&pts, other), 0, "{other}");
        }
        // every point is held
        assert!(pts.iter().all(|(_, f)| f & MG_HOLD != 0));
        // the views' own directories are no "directory above": below a
        // view only the kernel's own mounts pass, by the views' magic
        assert_eq!(flags(&pts, "/sys") & MG_OWN, 0);
        assert_eq!(flags(&pts, "/sys/fs/bpf") & MG_OWN, 0);
        // no point twice
        let mut seen = HashSet::new();
        assert!(pts.iter().all(|(p, _)| seen.insert(p.clone())));
    }

    /// Named test (lot 359, its mini-hunt): the root of a namespace, read
    /// through `/proc/<pid>/root`, is the directory the link names — read
    /// without following (`/proc/1/root/`: the trailing `/` is no
    /// component), it was the link itself, and `/` was never a point (its
    /// `MG_LOCK_ABOVE`: `mount --make-rshared /` let through in the lab),
    /// nor any place under it held.
    #[test]
    fn the_root_through_proc_pid_root_is_the_namespace_root() {
        let me = "/proc/self/root";
        let root = std::fs::metadata("/").unwrap();
        let md = point_metadata(me, "/").unwrap();
        assert!(md.is_dir());
        assert_eq!((md.dev(), md.ino()), (root.dev(), root.ino()));
        // what was read before: the link
        let link = antitamper_bpf::kernel_roots::symlink_metadata(format!("{me}/")).unwrap();
        assert!(
            link.file_type().is_symlink(),
            "the trailing / is no component"
        );
        // another point keeps its own kind (a link stays a link)
        let etc = std::fs::symlink_metadata("/etc").unwrap();
        let p = point_metadata(me, "/etc").unwrap();
        assert_eq!((p.dev(), p.ino()), (etc.dev(), etc.ino()));
        // a place under `/`: its directory's key is the root's
        assert_eq!(
            dir_key_in(me, Path::new("/")),
            Some((stat_dev_to_kernel_dev(root.dev()), root.ino()))
        );
        assert_eq!(
            dir_key_in("", Path::new("/")),
            Some((stat_dev_to_kernel_dev(root.dev()), root.ino()))
        );
        assert!(!follows_root("", Path::new("/")));
        assert!(!follows_root(me, Path::new("/etc")));
    }

    /// Named test (lot 359): the pin directory is its lock's root and place
    /// (`MG_LOCK`), every directory above it is where a recursive shared
    /// change reaches the lock (`MG_LOCK_ABOVE`) — and nothing else is
    /// either; without a pin root, no point is.
    #[test]
    fn the_pin_directory_is_the_locks_point_and_its_ancestors_above_it() {
        let pts = protected_points(Some(Path::new("/sys/fs/bpf/northnarrow")), &|_| true);
        assert_ne!(flags(&pts, "/sys/fs/bpf/northnarrow") & MG_LOCK, 0);
        assert_eq!(flags(&pts, "/sys/fs/bpf/northnarrow") & MG_LOCK_ABOVE, 0);
        for a in ["/", "/sys", "/sys/fs", "/sys/fs/bpf"] {
            assert_ne!(flags(&pts, a) & MG_LOCK_ABOVE, 0, "{a}");
            assert_eq!(flags(&pts, a) & MG_LOCK, 0, "{a}");
        }
        for (p, f) in &pts {
            if ![
                "/",
                "/sys",
                "/sys/fs",
                "/sys/fs/bpf",
                "/sys/fs/bpf/northnarrow",
            ]
            .contains(&p.as_str())
            {
                assert_eq!(f & (MG_LOCK | MG_LOCK_ABOVE), 0, "{p}");
            }
        }
        let none = protected_points(None, &|_| true);
        assert!(none.iter().all(|(_, f)| f & (MG_LOCK | MG_LOCK_ABOVE) == 0));
    }

    #[test]
    fn the_guard_is_not_attached_without_the_offsets_it_reads() {
        assert!(offsets_refusal(None).is_some());
        assert!(offsets_refusal(Some(&[])).is_none());
        assert!(offsets_refusal(Some(&["TP_SCHED_EXEC_FILENAME_OFFSET"])).is_none());
        for o in OFFSETS {
            let why = offsets_refusal(Some(&[o])).expect(o);
            assert!(why.contains(o), "{why}");
        }
    }

    /// Every offset the programs read is an optional entry of the boot's
    /// resolution (absent on a kernel: the guard is not attached, the
    /// start goes on).
    #[test]
    fn the_guards_offsets_are_optional_entries() {
        for o in OFFSETS {
            let spec = common::btf_offsets::REVALIDATE
                .iter()
                .find(|s| s.name == o)
                .unwrap_or_else(|| panic!("{o} is not revalidated"));
            assert!(spec.optional, "{o}");
        }
    }

    /// The programs are the four hooks, each with a fail-open slot.
    #[test]
    fn the_guards_hooks_have_fail_open_slots() {
        for (i, (_, hook)) in PROGRAMS.iter().enumerate() {
            assert_eq!(HOOKS[i], *hook);
            assert!(common::fail_open::FAIL_OPEN_HOOKS.contains(hook), "{hook}");
        }
    }

    /// Lot 379 (F8b-1): the injected verifier refusal of a test build names
    /// the program as the real load refuses it, only for the programs the
    /// variable names, and is a weakening the test build reports.
    #[cfg(feature = "test-privileged")]
    #[test]
    fn a_test_build_injects_the_verifier_refusal_it_is_asked_for() {
        let program = PROGRAMS[0].0;
        // SAFETY: no other test of nn-linux touches NN_TEST_VERIFIER_REFUSE;
        // its one reader, `injected_refusal`, runs in the guard's load, which
        // no unit test reaches.
        unsafe {
            std::env::set_var(
                VERIFIER_REFUSE_ENV,
                format!("{program}, {}", RECONF_PROGRAM.0),
            )
        };
        let e = injected_refusal(program).expect("injected");
        let text = format!("{e:#}");
        assert!(
            text.starts_with(&format!("verifier rejected LSM program `{program}`: ")),
            "{text}"
        );
        assert!(
            text.contains("injected by NN_TEST_VERIFIER_REFUSE"),
            "{text}"
        );
        assert!(injected_refusal(RECONF_PROGRAM.0).is_some());
        for (other, _) in &PROGRAMS[1..] {
            assert!(injected_refusal(other).is_none(), "{other}");
        }
        // lot 1.1: a stage, and the propagation fentry, are refused alike
        for (stage, ..) in STAGES {
            assert!(injected_refusal(stage).is_none(), "{stage}");
        }
        assert!(injected_refusal(PROPAGATION_PROGRAM.0).is_none());
        // SAFETY: as above.
        unsafe { std::env::remove_var(VERIFIER_REFUSE_ENV) };
        assert!(injected_refusal(program).is_none());
        assert!(refusal_weakens(program));
        assert!(!refusal_weakens(" , "));
    }

    /// Lot 379 (F8b-1): a build without `test-privileged` — every release —
    /// reads nothing: the variable set, every program loads as it would.
    #[cfg(not(feature = "test-privileged"))]
    #[test]
    fn a_build_without_the_test_feature_injects_nothing() {
        // SAFETY: no other test of nn-linux touches NN_TEST_VERIFIER_REFUSE;
        // its one reader, `injected_refusal`, runs in the guard's load, which
        // no unit test reaches.
        unsafe { std::env::set_var(VERIFIER_REFUSE_ENV, PROGRAMS[0].0) };
        for (program, _) in PROGRAMS.iter().chain([&RECONF_PROGRAM]) {
            assert!(injected_refusal(program).is_none(), "{program}");
        }
        assert!(!refusal_weakens(PROGRAMS[0].0));
        // SAFETY: as above.
        unsafe { std::env::remove_var(VERIFIER_REFUSE_ENV) };
    }

    fn table(text: &str) -> Vec<MountEntry> {
        crate::mountinfo::parse(text.as_bytes()).entries
    }

    /// A host: `/` on ext4, `/run`, `/proc`, `/sys`, the cgroup root, the
    /// bpffs, the tracefs; then a backup's bind of `/` at /mnt/snap, a
    /// chroot's sysfs, `--bind /run` and cgroup2 (debootstrap, pbuilder,
    /// schroot, arch-chroot), and a container's /proc.
    const HOST: &str = "\
1 0 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
22 1 0:22 / /run rw,nosuid,nodev shared:5 - tmpfs tmpfs rw,mode=755
23 1 0:23 / /proc rw,nosuid,nodev,noexec shared:12 - proc proc rw
24 1 0:24 / /sys rw,nosuid,nodev,noexec shared:2 - sysfs sysfs rw
25 24 0:25 / /sys/fs/cgroup rw,nosuid shared:3 - cgroup2 cgroup2 rw
26 24 0:26 / /sys/fs/bpf rw,nosuid shared:4 - bpf bpf rw,mode=700
27 24 0:12 / /sys/kernel/tracing rw shared:6 - tracefs tracefs rw
28 24 0:7 / /sys/kernel/debug rw shared:7 - debugfs debugfs rw
40 1 8:1 / /mnt/snap rw,relatime shared:1 - ext4 /dev/sda1 rw
41 1 0:24 / /srv/chroot/sys rw,relatime shared:2 - sysfs sysfs rw
42 1 0:22 / /srv/chroot/run rw,relatime shared:5 - tmpfs tmpfs rw
43 41 0:25 / /srv/chroot/sys/fs/cgroup rw shared:3 - cgroup2 cgroup2 rw
44 1 0:23 / /srv/chroot/proc rw shared:12 - proc proc rw
";

    fn points() -> Vec<(String, u8)> {
        protected_points(Some(Path::new("/sys/fs/bpf/northnarrow")), &|_| true)
    }

    fn ids(h: &NsHeld, flag: u8) -> Vec<u64> {
        let mut v: Vec<u64> = h
            .entries
            .iter()
            .filter(|(k, f)| k.dev & common::mount_guard::HELD_BY_ID != 0 && f & flag != 0)
            .map(|(k, _)| k.dev & 0xffff_ffff)
            .collect();
        v.sort_unstable();
        v
    }

    /// Named test (lot 1.1, the review of #569, F2): each held mount in a
    /// peer group is keyed by its own group and its root (`held_root`) —
    /// the key a peer copy of it has in any namespace (the chroot's copy of
    /// `/sys` at `/srv/chroot/sys`: the same group, the same root dentry),
    /// so the move of that copy is refused; a slave-only mount has no such
    /// key, nor a group no held mount is in. Failed on main: no such key.
    #[test]
    fn a_held_mount_is_keyed_by_its_group_and_its_root() {
        let t = table(HOST);
        let g = groups_of(HOST.as_bytes());
        // the root's key read where the mount point resolves
        let h = held_in(&t, &points(), GUARD_HOST, &g, &|d| {
            Some((0x801, d.as_os_str().len() as u64))
        });
        let root = |group: u32, at: &str| {
            let (d, i) = held_root(group, 0x801, at.len() as u64);
            h.entries
                .iter()
                .any(|(k, f)| (k.dev, k.ino) == (d, i) && f & HELD_REFUSE != 0)
        };
        for (group, at) in [
            (1, "/"),
            (5, "/run"),
            (12, "/proc"),
            (2, "/sys"),
            (3, "/sys/fs/cgroup"),
            (4, "/sys/fs/bpf"),
        ] {
            assert!(root(group, at), "{at} in shared:{group}");
        }
        // the tracefs is not held, a group no held mount is in has no key
        assert!(!root(6, "/sys/kernel/tracing"));
        assert!(!root(1, "/run"));
        // the agent's unit's namespace: each of its mounts a slave of the
        // host's and shared again — keyed by its own group only (a change
        // made in a slave never reaches its master)
        let unit = "\
300 299 8:1 / / ro,relatime shared:90 master:1 - ext4 /dev/sda1 rw
301 300 0:22 / /run rw,nosuid master:5 - tmpfs tmpfs rw
";
        let u = held_in(
            &table(unit),
            &points(),
            GUARD_AGENT,
            &groups_of(unit.as_bytes()),
            &|d| Some((0x801, d.as_os_str().len() as u64)),
        );
        let has = |group: u32, at: &str| {
            let (d, i) = held_root(group, 0x801, at.len() as u64);
            u.entries.iter().any(|(k, _)| (k.dev, k.ino) == (d, i))
        };
        assert!(has(90, "/"));
        assert!(!has(1, "/"));
        assert!(!has(5, "/run"));
        // a mount in no peer group of its own (`/run` here) has no such key,
        // under no group either
        assert!(
            !u.entries
                .iter()
                .any(|(k, _)| k.dev == common::mount_guard::HELD_ROOT),
            "a key under group 0"
        );
        // a mount whose root cannot be read has no such key
        let none = held_in(&t, &points(), GUARD_HOST, &g, &|_| None);
        assert!(
            !none
                .entries
                .iter()
                .any(|(k, _)| k.dev & common::mount_guard::HELD_ROOT
                    == common::mount_guard::HELD_ROOT)
        );
    }

    /// Named test (lot 1.1, F8b-1): the split hooks' stages — each in a
    /// slot of its own hook's array (an array per hook), and only for the
    /// two split hooks.
    #[test]
    fn each_split_hooks_stages_are_in_its_own_array() {
        let mut slots = std::collections::HashSet::new();
        for (program, hook, array, slot) in STAGES {
            assert!(HOOKS.contains(&hook), "{program}");
            assert!(
                program.starts_with(&format!("mount_guard_{hook}_")),
                "{program}"
            );
            assert_eq!(stages_of(hook), Some(array), "{program}");
            assert!(slot < common::mount_guard::STAGE_SLOTS);
            assert!(slots.insert((array, slot)), "{array}[{slot}] twice");
        }
        assert_ne!(stages_of("sb_mount"), stages_of("move_mount"));
        for hook in ["sb_umount", "sb_pivotroot", "sb_remount"] {
            assert_eq!(stages_of(hook), None);
        }
    }

    /// The review of #567 (F1): the mounts held are those the protected
    /// points resolve through, by their id — `/`, `/run`, `/proc`, `/sys`,
    /// the cgroup root, the bpffs — never a copy of one (a backup's bind
    /// of `/`, a chroot's sysfs, its `--bind /run`, its cgroup2 or its
    /// proc), whose unmount is the caller's own.
    #[test]
    fn a_copy_of_a_held_mount_is_never_held() {
        let t = table(HOST);
        let g = groups_of(HOST.as_bytes());
        let h = held_in(&t, &points(), GUARD_HOST, &g, &|d| {
            Some((0x801, d.as_os_str().len() as u64))
        });
        assert_eq!(ids(&h, HELD_REFUSE), vec![1, 22, 23, 24, 25, 26]);
        for copy in [40, 41, 42, 43, 44] {
            assert!(
                !h.entries.iter().any(|(k, _)| k.dev & 0xffff_ffff == copy
                    && k.dev & common::mount_guard::HELD_BY_ID != 0),
                "{copy}"
            );
        }
        // the tracefs and the debugfs the agent reads: recorded, not held
        assert_eq!(ids(&h, MG_NOTE), vec![27, 28]);
        // the cross-model check: the peer groups a change made elsewhere
        // reaches them through (one look-up in the hook, no walk): the held
        // mounts' and the views' own groups (the chroot's copies share them)
        let mut groups = h.groups.clone();
        groups.sort_unstable();
        assert_eq!(groups, vec![1, 2, 3, 4, 5, 6, 7, 12]);
        // each entry says its namespace
        assert!(
            h.entries
                .iter()
                .all(|(_, f)| f >> HELD_NS_SHIFT == GUARD_HOST)
        );
        // the super blocks of the held ones, a copy's none of its own
        let mut sbs = h.sbs.clone();
        sbs.sort_unstable();
        let mut want: Vec<u64> = [(8, 1), (0, 22), (0, 23), (0, 24), (0, 25), (0, 26)]
            .iter()
            .map(|(a, b)| (a << 20) | b)
            .collect();
        want.sort_unstable();
        assert_eq!(sbs, want);
        // by place, for an unmount propagated there: /run at the root's
        // "run" under /'s peer group (shared:1); /sys/fs/cgroup at sysfs's
        // "fs"'s "cgroup" under /sys's (shared:2); a copy's place (the
        // chroot's /srv/chroot/sys) is none
        let place = |g, dir: &str, n: &str| {
            let (d, i) = held_by_place(g, 0x801, dir.len() as u64, &NameKey::of(n));
            h.entries.iter().any(|(k, _)| (k.dev, k.ino) == (d, i))
        };
        assert!(place(1, "/", "run"));
        assert!(place(2, "/sys/fs", "cgroup"));
        assert!(!place(2, "/sys", "fs"));
        assert!(!place(1, "/srv/chroot", "sys"));
        assert!(
            !place(5, "/", "run"),
            "a group no held mount's parent is in"
        );
        // the agent's namespace (its unit's sandbox: each mount a slave of
        // the host's, shared again): its held mounts by place under their
        // parent's own group and its master's — an unmount in a host mount
        // at that place reaches them too
        let unit = "\
300 299 8:1 / / ro,relatime shared:90 master:1 - ext4 /dev/sda1 rw
301 300 0:22 / /run rw,nosuid shared:91 master:5 - tmpfs tmpfs rw
302 301 0:22 /northnarrow /run/northnarrow rw shared:92 master:5 - tmpfs tmpfs rw
";
        let ut = table(unit);
        let ug = groups_of(unit.as_bytes());
        let u = held_in(&ut, &points(), GUARD_AGENT, &ug, &|d| {
            Some((0x801, d.as_os_str().len() as u64))
        });
        let uplace = |g, dir: &str, n: &str| {
            let (d, i) = held_by_place(g, 0x801, dir.len() as u64, &NameKey::of(n));
            u.entries.iter().any(|(k, _)| (k.dev, k.ino) == (d, i))
        };
        assert!(uplace(91, "/run", "northnarrow"), "its parent's own group");
        assert!(
            uplace(5, "/run", "northnarrow"),
            "its parent's master's group"
        );
        assert!(uplace(1, "/", "run") && uplace(90, "/", "run"));
        // and its groups: each mount's own and its master's
        let mut ugroups = u.groups.clone();
        ugroups.sort_unstable();
        assert_eq!(ugroups, vec![1, 5, 90, 91, 92]);
        assert!(ids(&u, HELD_REFUSE).contains(&302));
        // the agent's namespace, the same table: its own tag
        let a = held_in(&t, &points(), GUARD_AGENT, &g, &|_| None);
        assert!(
            a.entries
                .iter()
                .all(|(_, f)| f >> HELD_NS_SHIFT == GUARD_AGENT)
        );
        assert_eq!(ids(&a, HELD_REFUSE), vec![1, 22, 23, 24, 25, 26]);
    }

    /// A FUSE on the way is held by its id, but never read for its root.
    #[test]
    fn a_fuse_on_the_way_is_never_read() {
        let t = table(&format!(
            "{HOST}50 1 0:50 / /var rw shared:9 - fuse.x x rw\n51 50 8:5 / /var/lib rw shared:10 - ext4 /dev/sda5 rw\n"
        ));
        let read = std::cell::RefCell::new(Vec::new());
        let h = held_in(&t, &points(), GUARD_HOST, &groups_of(b""), &|d| {
            read.borrow_mut().push(d.to_path_buf());
            None
        });
        assert!(ids(&h, HELD_REFUSE).contains(&50));
        assert!(ids(&h, HELD_REFUSE).contains(&51));
        // /var/lib's place is on the FUSE: never read
        assert!(
            !read.borrow().iter().any(|d| d == Path::new("/var")),
            "{:?}",
            read.borrow()
        );
    }

    /// The review of #567 (F7): with the agent's binaries in /usr/bin (a
    /// package), /usr/local and /usr/local/bin are no points — an NFS or
    /// automounted /usr/local is the host's own business; with them in
    /// /usr/local/bin, they are.
    #[test]
    fn only_the_binaries_that_exist_are_points() {
        let pkg = protected_points(None, &|p: &str| !p.starts_with("/usr/local/"));
        let has = |pts: &[(String, u8)], p: &str| pts.iter().any(|(q, _)| q == p);
        for p in [
            "/usr/local",
            "/usr/local/bin",
            "/usr/local/bin/northnarrow-agent",
        ] {
            assert!(!has(&pkg, p), "{p}");
        }
        assert!(has(&pkg, "/usr/bin/northnarrow-agent"));
        assert!(has(&pkg, "/usr/bin"));
        let local = protected_points(None, &|p: &str| p.starts_with("/usr/local/"));
        assert!(has(&local, "/usr/local/bin/northnarrow-agent"));
        assert!(has(&local, "/usr/local"));
        assert!(!has(&local, "/usr/bin/northnarrow-agent"));
        // the views and the agent's directories whatever exists
        for p in [
            "/proc",
            "/sys/fs/cgroup",
            "/etc/northnarrow",
            "/run/northnarrow",
        ] {
            assert!(has(&pkg, p) && has(&local, p), "{p}");
        }
    }

    /// The brainstorm's 3rd point: the mounts made before the guard (an
    /// fstab line, a `.mount` unit, the initramfs) that are not the
    /// canonical ones over the agent's paths are named; the host's own
    /// layout, a unit's self-binds, a subvolume root, the kernel's own
    /// mounts below the views and the copies elsewhere are not.
    #[test]
    fn a_mount_made_before_the_guard_that_is_not_canonical_is_named() {
        let pts = points();
        assert!(
            not_canonical(&table(HOST), &pts).is_empty(),
            "{:?}",
            not_canonical(&table(HOST), &pts)
        );
        let canonical = format!(
            "{HOST}\
60 1 8:3 / /var rw shared:9 - ext4 /dev/sda3 rw
61 1 0:40 /@usr /usr rw shared:10 - btrfs /dev/sda4 rw
62 1 8:1 /etc/northnarrow /etc/northnarrow rw shared:1 - ext4 /dev/sda1 rw
63 23 0:41 / /proc/sys/fs/binfmt_misc rw - binfmt_misc binfmt_misc rw
64 28 0:12 / /sys/kernel/debug/tracing rw - tracefs tracefs rw
65 24 0:42 / /sys/fs/fuse/connections rw - fusectl fusectl rw
66 22 0:43 / /run/user/1000 rw - tmpfs tmpfs rw
67 1 0:44 / /var/lib/docker/overlay2/x/merged rw - overlay overlay rw
"
        );
        assert!(
            not_canonical(&table(&canonical), &pts).is_empty(),
            "{:?}",
            not_canonical(&table(&canonical), &pts)
        );
        for (line, words) in [
            ("70 1 0:70 / /var/lib tmpfs tmpfs rw", "/var/lib (tmpfs"),
            ("70 1 0:70 / /etc overlay overlay rw", "/etc (overlay"),
            (
                "70 1 0:70 / /etc/northnarrow fuse.sshfs x rw",
                "a FUSE over",
            ),
            (
                "70 1 8:1 /srv/fake /var/lib/northnarrow ext4 /dev/sda1 rw",
                "a bind of another directory",
            ),
            ("70 23 0:70 / /proc/sys fuse.x x rw", "below a kernel view"),
            (
                "70 25 0:70 / /sys/fs/cgroup/system.slice tmpfs tmpfs rw",
                "below a kernel view",
            ),
            (
                "70 1 0:70 / /proc tmpfs tmpfs rw",
                "not the kernel's file system of that view",
            ),
            (
                "70 1 0:70 / /run fuse.x x rw",
                "not the kernel's file system of that view",
            ),
            ("70 1 0:70 / / fuse.x x rw", "a FUSE as the root"),
            (
                "70 62 0:70 / /etc/northnarrow/keys tmpfs tmpfs rw",
                "below one of the agent's own",
            ),
        ] {
            let mut f: Vec<&str> = line.splitn(6, ' ').collect();
            let rest = f.pop().unwrap().to_string();
            let l = format!("{} rw - {rest}\n", f.join(" "));
            let found = not_canonical(
                &table(&format!(
                    "{HOST}62 1 8:1 /etc/northnarrow /etc/northnarrow rw - ext4 /dev/sda1 rw\n{l}"
                )),
                &pts,
            );
            assert!(found.iter().any(|x| x.contains(words)), "{line}: {found:?}");
        }
    }

    /// The cross-model check: the directories of the agent's shared
    /// libraries are points (a mount over one swaps what a restart loads);
    /// a pseudo file system's, a deleted file's or a home's are not.
    #[test]
    fn the_agents_library_directories_are_points() {
        let maps = "\
55d0c0a00000-55d0c0b00000 r-xp 00000000 08:01 1234 /usr/local/bin/northnarrow-agent
7f0000000000-7f0000100000 r-xp 00000000 08:01 2345 /usr/lib/x86_64-linux-gnu/libc.so.6
7f0000200000-7f0000210000 r-xp 00000000 08:01 2346 /usr/lib/x86_64-linux-gnu/libgcc_s.so.1
7f0000300000-7f0000310000 r-xp 00000000 08:01 2347 /usr/lib64/ld-linux-x86-64.so.2
7f0000400000-7f0000410000 rw-s 00000000 00:01 99 /memfd:x (deleted)
7f0000500000-7f0000510000 r-xp 00000000 08:01 77 /home/u/lib/evil.so
7f0000600000-7f0000610000 r-xp 00000000 08:01 78 /usr/lib/old/gone.so (deleted)
7ffd00000000-7ffd00021000 rw-p 00000000 00:00 0 [stack]
";
        assert_eq!(
            library_dirs(maps),
            vec![
                "/usr/lib/x86_64-linux-gnu".to_string(),
                "/usr/lib64".to_string()
            ]
        );
    }

    /// Mutation N21: only the kernel's own type at a noted point is noted
    /// (a debugfs mounted at /sys/kernel/tracing is not the tracefs); N34:
    /// a unit's bind of a memory file system's directory onto itself (its
    /// `RuntimeDirectory=` on /run) is canonical.
    #[test]
    fn a_noted_mount_is_the_kernels_type_and_a_tmpfs_self_bind_is_canonical() {
        let t = table(&HOST.replace(
            "27 24 0:12 / /sys/kernel/tracing rw shared:6 - tracefs tracefs rw",
            "27 24 0:7 / /sys/kernel/tracing rw shared:6 - debugfs debugfs rw",
        ));
        let h = held_in(&t, &points(), GUARD_HOST, &groups_of(b""), &|_| None);
        assert_eq!(
            ids(&h, MG_NOTE),
            vec![28],
            "the debugfs at its own point only"
        );
        let unit = "\
300 299 8:1 / / ro,relatime shared:90 master:1 - ext4 /dev/sda1 rw
301 300 0:22 / /run rw,nosuid shared:91 master:5 - tmpfs tmpfs rw
302 301 0:22 /northnarrow /run/northnarrow rw shared:92 master:5 - tmpfs tmpfs rw
303 300 8:1 /etc/northnarrow /etc/northnarrow rw shared:93 master:1 - ext4 /dev/sda1 rw
";
        assert!(
            not_canonical(&table(unit), &points()).is_empty(),
            "{:?}",
            not_canonical(&table(unit), &points())
        );
        // the same tmpfs mounted over the directory, not a bind of it onto itself
        let over = format!("{unit}304 301 0:23 / /run/northnarrow rw - tmpfs tmpfs rw\n");
        assert!(!not_canonical(&table(&over), &points()).is_empty());
    }

    /// Lot 377: in the watchdog's namespace systemd binds the witness
    /// directory (its unit's `ReadWritePaths=`, below the state directory)
    /// onto itself — canonical there, never a High at the watchdog's start;
    /// any other mount below the agent's directories stays named: a self-bind
    /// of a directory the unit does not name, one below the witness
    /// directory, a bind of another directory, another file system or a
    /// tmpfs at the witness directory. And only in the watchdog's namespace:
    /// in another the same bind is named.
    #[test]
    fn the_watchdog_s_own_witness_bind_is_canonical_and_a_foreign_one_is_not() {
        let sandbox = crate::self_integrity::watchdog_unit_sandbox_dirs();
        assert!(
            sandbox.iter().any(|d| d == "/var/lib/northnarrow/witness"),
            "the shipped watchdog unit binds the witness directory: {sandbox:?}"
        );
        let ns = "\
300 299 8:1 / / ro,relatime shared:90 master:1 - ext4 /dev/sda1 rw
301 300 0:22 / /run rw,nosuid shared:91 master:5 - tmpfs tmpfs rw
302 301 0:22 /northnarrow /run/northnarrow rw shared:92 master:5 - tmpfs tmpfs rw
";
        let own = format!(
            "{ns}303 300 8:1 /var/lib/northnarrow/witness /var/lib/northnarrow/witness rw,relatime \
             shared:93 master:1 - ext4 /dev/sda1 rw\n"
        );
        let found = watchdog_not_canonical(&table(&own), &points());
        assert!(found.is_empty(), "{found:?}");
        // the same bind outside the watchdog's namespace: named
        let elsewhere = not_canonical(&table(&own), &points());
        assert!(
            elsewhere
                .iter()
                .any(|f| f.starts_with("/var/lib/northnarrow/witness (")),
            "{elsewhere:?}"
        );
        for (line, point) in [
            // a self-bind of a directory the unit does not name
            (
                "304 300 8:1 /var/lib/northnarrow/state /var/lib/northnarrow/state rw - ext4 /dev/sda1 rw",
                "/var/lib/northnarrow/state",
            ),
            // a self-bind below the one it names
            (
                "304 303 8:1 /var/lib/northnarrow/witness/x /var/lib/northnarrow/witness/x rw - ext4 /dev/sda1 rw",
                "/var/lib/northnarrow/witness/x",
            ),
            // another directory bound over it
            (
                "304 303 8:1 /tmp/w /var/lib/northnarrow/witness rw - ext4 /dev/sda1 rw",
                "/var/lib/northnarrow/witness",
            ),
            // another file system, with the root that a self-bind would have
            (
                "304 303 8:2 /var/lib/northnarrow/witness /var/lib/northnarrow/witness rw - ext4 /dev/sda2 rw",
                "/var/lib/northnarrow/witness",
            ),
            // a memory file system over it
            (
                "304 303 0:40 / /var/lib/northnarrow/witness rw - tmpfs tmpfs rw",
                "/var/lib/northnarrow/witness",
            ),
        ] {
            let found = watchdog_not_canonical(&table(&format!("{own}{line}\n")), &points());
            assert!(
                found.iter().any(|f| f.starts_with(&format!("{point} ("))
                    && f.ends_with("below one of the agent's own directories")),
                "{line}: {found:?}"
            );
        }
    }

    /// The re-check of #567 (N1): each held mount's place is also keyed
    /// under its parent mount itself (`held_under`) — the hook finds there,
    /// along a regrouped parent's propagation, the place its other keys
    /// hold under the old group, and that of a parent in no group then; a
    /// chroot's own sysfs (the host's dentries, another mount) holds none.
    #[test]
    fn a_held_mounts_place_is_keyed_under_its_parent_mount_too() {
        let key = |d: &Path| Some((0x801, d.as_os_str().len() as u64));
        let h = held_in(
            &table(HOST),
            &points(),
            GUARD_HOST,
            &groups_of(HOST.as_bytes()),
            &key,
        );
        let under = |h: &NsHeld, parent: u32, dir: &str, n: &str| {
            let (d, i) = held_under(parent, 0x801, dir.len() as u64, &NameKey::of(n));
            h.entries
                .iter()
                .any(|(k, f)| (k.dev, k.ino) == (d, i) && f & HELD_REFUSE != 0)
        };
        assert!(under(&h, 1, "/", "run"));
        assert!(under(&h, 24, "/sys/fs", "cgroup"));
        assert!(under(&h, 24, "/sys/fs", "bpf"));
        assert!(!under(&h, 41, "/sys/fs", "cgroup"), "the chroot's sysfs");
        assert!(!under(&h, 1, "/srv/chroot", "sys"), "a copy's place");
        assert!(!under(&h, 24, "/sys", "fs"), "no mount there");
        // and under any group: a copy of a held mount sits where it sits
        let any = |h: &NsHeld, dir: &str, n: &str| {
            let (d, i) = held_by_place(PLACE_ANY_GROUP, 0x801, dir.len() as u64, &NameKey::of(n));
            h.entries.iter().any(|(k, _)| (k.dev, k.ino) == (d, i))
        };
        assert!(
            any(&h, "/", "sys"),
            "the host's /sys (a raw copy sits there too)"
        );
        assert!(!any(&h, "/srv/chroot", "sys"), "a chroot's sysfs");
        // a host whose `/` was private at the read
        let private = "\
1 0 8:1 / / rw - ext4 /dev/sda1 rw
22 1 0:22 / /run rw,nosuid - tmpfs tmpfs rw
";
        let p = held_in(
            &table(private),
            &points(),
            GUARD_HOST,
            &groups_of(private.as_bytes()),
            &key,
        );
        assert!(under(&p, 1, "/", "run"));
    }

    /// The re-check of #567 (N2): the overlays a host's image tooling
    /// merges at boot — systemd-sysext over `/usr` (Flatcar), confext over
    /// `/etc`, composefs over `/usr` — are the canonical layout at the
    /// start; another overlay there, the tool's name on another file
    /// system, or its overlay over another point are named.
    #[test]
    fn an_image_tools_overlay_is_canonical_and_another_is_not() {
        let pts = points();
        for line in [
            "70 1 0:70 / /usr ro,nodev - overlay sysext ro,lowerdir=/run/systemd/sysext/meta/usr:/usr",
            "70 1 0:70 / /etc ro - overlay confext ro,lowerdir=/run/systemd/confext/meta/etc:/etc",
            "70 1 0:70 / /usr ro - overlay composefs ro,metacopy=on",
        ] {
            let found = not_canonical(&table(&format!("{HOST}{line}\n")), &pts);
            assert!(found.is_empty(), "{line}: {found:?}");
        }
        for (line, words) in [
            ("70 1 0:70 / /usr ro - overlay overlay ro", "/usr (overlay"),
            ("70 1 0:70 / /usr ro - tmpfs sysext rw", "/usr (tmpfs"),
            ("70 1 0:70 / /etc ro - overlay sysext ro", "/etc (overlay"),
            (
                "70 1 0:70 / /var/lib ro - overlay sysext ro",
                "/var/lib (overlay",
            ),
        ] {
            let found = not_canonical(&table(&format!("{HOST}{line}\n")), &pts);
            assert!(found.iter().any(|x| x.contains(words)), "{line}: {found:?}");
        }
    }
}
