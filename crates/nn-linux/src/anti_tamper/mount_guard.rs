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
//! `sb_umount` and `sb_pivotroot`.
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

use anyhow::{anyhow, Context, Result};
use aya::maps::{Array as AyaArray, HashMap as AyaHashMap, MapData};
use aya::{Btf, Ebpf};
use common::mount_guard::{
    BPF_FS_MAGIC, CGROUP2_SUPER_MAGIC, MG_HOLD, MG_ON, MG_OWN, MG_VIEW, PROC_SUPER_MAGIC,
    SYSFS_MAGIC, TMPFS_MAGIC,
};
use common::wire::InodeKey;
use tracing::{info, warn};

use super::filesystem::{
    stat_dev_to_kernel_dev, AyaInodeKey, BINARY_AND_UNIT_PATHS, CONFIG_DIR, NOCREATE_UNIT_DIRS,
    STATE_DIR,
};

/// The four programs, by `(program, hook)`; pinned under the hook's name
/// like every LSM program of the pin root.
pub(crate) const PROGRAMS: [(&str, &str); 4] = [
    ("mount_guard_sb_mount", "sb_mount"),
    ("mount_guard_move_mount", "move_mount"),
    ("mount_guard_sb_umount", "sb_umount"),
    ("mount_guard_sb_pivotroot", "sb_pivotroot"),
];

/// The guard's hooks (each with its `DENY_FAIL_OPEN` slot).
pub const HOOKS: [&str; 4] = ["sb_mount", "move_mount", "sb_umount", "sb_pivotroot"];

/// What a boot without the guard (or part of it) lacks, for the signed
/// degradation.
pub const ABSENT_EFFECT: &str = "a mount on, over or below the agent's directories, binaries and \
     units, /proc, /sys, the cgroup root or the bpffs is not refused in the host's namespace — the \
     by-path defences (anchored views, bounded readers) and the signed mount watch \
     (mount_over_protected) remain";

const PROTECTED_MAP: &str = "MOUNT_PROTECTED";
const CONF_MAP: &str = "MOUNT_GUARD_CONF";

/// The offsets the programs read: without every one the guard is not
/// attached.
const OFFSETS: [&str; 18] = [
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
pub fn protected_points(pin_root: Option<&Path>) -> Vec<(String, u8)> {
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
    for p in BINARY_AND_UNIT_PATHS {
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
    out
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

/// The file system magic of a path (`statfs(2)`).
fn magic_of(path: &str) -> Result<u64> {
    let c = std::ffi::CString::new(path)?;
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: a NUL-terminated path and a zeroed out-buffer of the right type.
    let rc = unsafe { libc::statfs(c.as_ptr(), &mut st) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("statfs {path}"));
    }
    Ok(st.f_type as u64)
}

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
        if let (Ok(md), Ok(m)) = (std::fs::metadata(&host), magic_of(&host)) {
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
        let Ok(md) = std::fs::symlink_metadata(&host) else {
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
    let mnt = std::fs::metadata("/proc/1/ns/mnt").context("PID 1's mount namespace")?;
    let user = std::fs::metadata("/proc/1/ns/user").context("PID 1's user namespace")?;
    Ok((mnt.ino(), user.ino()))
}

/// Register the points (new keys first, then the stale ones of an earlier
/// start of this boot go: no window), then arm the guard.
fn write_maps(ebpf: &mut Ebpf, keys: &[(InodeKey, u8, String)], ns: (u64, u64)) -> Result<()> {
    let map = ebpf
        .map_mut(PROTECTED_MAP)
        .ok_or_else(|| anyhow!("map {PROTECTED_MAP} missing from the eBPF object"))?;
    let mut map: AyaHashMap<&mut MapData, AyaInodeKey, u8> = AyaHashMap::try_from(map)
        .with_context(|| format!("{PROTECTED_MAP} is not a HashMap<InodeKey, u8>"))?;
    let mut keep: HashSet<(u64, u64)> = HashSet::new();
    for (key, flags, path) in keys {
        // a key two paths share (a hard link, a bind) carries both kinds
        let have = map.get(&AyaInodeKey(*key), 0).unwrap_or(0);
        map.insert(AyaInodeKey(*key), have | flags, 0)
            .with_context(|| format!("registering {path}"))?;
        keep.insert((key.dev, key.ino));
    }
    let stale: Vec<AyaInodeKey> = map
        .keys()
        .filter_map(|k| k.ok())
        .filter(|k| !keep.contains(&(k.0.dev, k.0.ino)))
        .collect();
    for k in &stale {
        let _ = map.remove(k);
    }
    let conf = ebpf
        .map_mut(CONF_MAP)
        .ok_or_else(|| anyhow!("map {CONF_MAP} missing from the eBPF object"))?;
    let mut conf: AyaArray<&mut MapData, u64> =
        AyaArray::try_from(conf).with_context(|| format!("{CONF_MAP} is not an Array<u64>"))?;
    conf.set(1, ns.1, 0)?;
    conf.set(0, ns.0, 0)?;
    Ok(())
}

/// A prior start's pins of the guard go when this one does not attach it:
/// an older program must not stay attached with points no one refreshes.
fn purge_pins(pin_root: Option<&Path>) {
    if let Some(root) = pin_root {
        for (_, hook) in PROGRAMS {
            let (prog, link) = antitamper_bpf::lsm_pin_paths(root, hook);
            antitamper_bpf::purge_stale_pin(&link);
            antitamper_bpf::purge_stale_pin(&prog);
        }
    }
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
    let (keys, degraded) = resolve_points(&protected_points(pin_root));
    for d in degraded {
        health.degraded.push(format!("mount guard: {d}"));
    }
    if let Err(e) = write_maps(ebpf, &keys, ns) {
        warn!(error = %format!("{e:#}"), "anti-tamper mount guard: not armed");
        purge_pins(pin_root);
        health
            .degraded
            .push(format!("mount guard not armed: {e:#} ({ABSENT_EFFECT})"));
        return health;
    }
    health.points = keys.len();
    let mut missing = Vec::new();
    for (program, hook) in PROGRAMS {
        match super::reattach_fresh(ebpf, program, hook, btf, pin_root) {
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
    if missing.is_empty() {
        info!(
            hooks = health.attached,
            points = health.points,
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
        let pts = protected_points(Some(Path::new("/sys/fs/bpf/northnarrow")));
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
}
