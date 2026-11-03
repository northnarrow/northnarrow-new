//! Lot 273: the cgroups of the protected units, as `PROTECTED_INODES`
//! entries — shared by the agent (its own unit and the watchdog's) and the
//! watchdog (its own, at its start).
//!
//! The kernel ends or stops every process of a cgroup without a signal
//! from userland — a write to `cgroup.kill` (5.14+), to `cgroup.freeze` —
//! and systemd 257 and later answer `systemctl kill -s SIGKILL` with the
//! first once the main process refused the signal. The `task_kill` hook
//! never sees it. The entries computed here put the unit's cgroup under
//! the existing inode deny hooks:
//!
//! | entry | flags | refused outside a trusted-installer window |
//! |---|---|---|
//! | the unit's directory | `MUTATE`, `NOCREATE`, `INIT_RMDIR` | `rmdir` (but PID 1's, see [`common::wire::FS_PROTECT_INIT_RMDIR`]), a child cgroup, `chown` / `chmod`, a rename, an xattr |
//! | its `cgroup.kill` | `MUTATE`, `WRITE`, `CGROUP_KILL` | a write-open (signed `cgroup_kill`) |
//! | its `cgroup.freeze` | `MUTATE`, `WRITE`, `CGROUP_FREEZE` | a write-open (signed `cgroup_freeze`) |
//! | its `cgroup.procs`, `cgroup.threads` | `MUTATE` | `chown` / `chmod` (a delegation); writes stay open: systemd attaches the unit's processes there |
//! | each ancestor slice's `cgroup.kill` / `cgroup.freeze` | as the unit's | a kill or freeze of the whole slice, which kills or freezes the unit with it |
//!
//! Not entered: the unit's `cgroup.subtree_control` (systemd rewrites it at
//! every realisation of the unit; the unit has processes, so no domain
//! controller can be enabled below it anyway) and the resource files
//! (`memory.max`, `cpu.max`, `cpu.idle`, `pids.max`, ...: systemd applies
//! the unit's properties there as PID 1). Not refusing them is an open
//! residual, lot 273b's scope: a low `memory.max` is an OOM kill inside the
//! write, `cpu.max` / `cpu.idle` / `pids.max` starve the agent like a
//! freeze; a change the agent survives is reported as `integrity_drift`.
//! A move of a protected process out of the cgroup is refused by the
//! `cgroup_move_*` programs, not by an entry.
//!
//! Only a systemd *service* cgroup is protected (`…/<name>.slice/…/<unit>.service`):
//! the agent started by hand or by a privileged test runs in a login
//! scope, whose cgroup is not the agent's to defend. Only cgroup v2: a v1
//! hierarchy root mounts later (the v1 `freezer` is mountable on a pure v2
//! host too) is not covered yet (lot 273b).

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use aya::maps::{HashMap as AyaHashMap, Map as AyaMap, MapData};
use common::wire::{
    InodeKey, FS_PROTECT_CGROUP_FREEZE, FS_PROTECT_CGROUP_KILL, FS_PROTECT_INIT_RMDIR,
    FS_PROTECT_MUTATE, FS_PROTECT_NOCREATE, FS_PROTECT_WRITE,
};

/// Name of the pinned `PROTECTED_INODES` map (mirrors the `#[map]` in
/// `agent-ebpf/src/inode_protect.rs`).
pub const PROTECTED_INODES_MAP_NAME: &str = "PROTECTED_INODES";

/// Where the cgroup v2 hierarchy is mounted: the unified layout, then the
/// hybrid one.
pub const CGROUP2_MOUNTS: &[&str] = &["/sys/fs/cgroup", "/sys/fs/cgroup/unified"];

/// `CGROUP2_SUPER_MAGIC` (include/uapi/linux/magic.h).
pub const CGROUP2_SUPER_MAGIC: i64 = 0x6367_7270;

/// The flags of the unit's directory.
pub const UNIT_DIR_FLAGS: u8 = FS_PROTECT_MUTATE | FS_PROTECT_NOCREATE | FS_PROTECT_INIT_RMDIR;
/// The flags of a protected `cgroup.kill`.
pub const KILL_FLAGS: u8 = FS_PROTECT_MUTATE | FS_PROTECT_WRITE | FS_PROTECT_CGROUP_KILL;
/// The flags of a protected `cgroup.freeze`.
pub const FREEZE_FLAGS: u8 = FS_PROTECT_MUTATE | FS_PROTECT_WRITE | FS_PROTECT_CGROUP_FREEZE;
/// The flags of the unit's `cgroup.procs` / `cgroup.threads`.
pub const MEMBERS_FLAGS: u8 = FS_PROTECT_MUTATE;

/// One inode to protect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupEntry {
    pub path: PathBuf,
    pub key: InodeKey,
    pub flags: u8,
}

/// What the cgroup of a process is to the guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnitCgroup {
    /// A systemd service's cgroup: `cgroup` (as `/proc/<pid>/cgroup` names
    /// it) and the entries to register.
    Service {
        cgroup: String,
        entries: Vec<CgroupEntry>,
    },
    /// Not a systemd service's cgroup (a login scope, the root): nothing
    /// to protect.
    NotAService { cgroup: String },
    /// No cgroup v2 membership or hierarchy, or the cgroup could not be
    /// read: the guard cannot protect it.
    Unavailable { why: String },
}

impl UnitCgroup {
    /// The entries to register (none unless [`UnitCgroup::Service`]).
    pub fn entries(&self) -> &[CgroupEntry] {
        match self {
            UnitCgroup::Service { entries, .. } => entries,
            _ => &[],
        }
    }
}

/// `stat(2)`'s device number in the kernel's `s_dev` encoding, the form the
/// eBPF deny hooks read (`MKDEV(major, minor)`; see the agent's
/// `filesystem::stat_dev_to_kernel_dev`, which is this).
pub fn stat_dev_to_kernel_dev(st_dev: u64) -> u64 {
    let major = libc::major(st_dev) as u64;
    let minor = libc::minor(st_dev) as u64;
    (major << 20) | minor
}

/// The cgroup v2 path of `/proc/<pid>/cgroup`'s text: the `0::<path>`
/// line. `None` without one (a cgroup v1-only host).
pub fn v2_path(proc_cgroup: &str) -> Option<&str> {
    proc_cgroup
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(str::trim_end)
}

/// The components of `cgroup` when it is a systemd service's cgroup:
/// slices, then the service — each a plain name (no `.`, `..`, empty or
/// NUL component). `Err` names why it is not one.
pub fn service_components(cgroup: &str) -> std::result::Result<Vec<&str>, String> {
    let rest = cgroup
        .strip_prefix('/')
        .ok_or_else(|| format!("{cgroup:?} is not an absolute cgroup path"))?;
    if rest.is_empty() {
        return Err("the root cgroup".into());
    }
    let parts: Vec<&str> = rest.split('/').collect();
    for p in &parts {
        if p.is_empty() || *p == "." || *p == ".." || p.contains('\0') {
            return Err(format!("{cgroup:?} has a component {p:?}"));
        }
    }
    let (leaf, slices) = parts.split_last().expect("at least one component");
    if !leaf.ends_with(".service") || leaf.len() == ".service".len() {
        return Err(format!("{cgroup:?} is not a systemd service's cgroup"));
    }
    if let Some(s) = slices.iter().find(|s| !s.ends_with(".slice")) {
        return Err(format!("{cgroup:?}: {s:?} is not a slice"));
    }
    Ok(parts)
}

/// The cgroup v2 mount point among [`CGROUP2_MOUNTS`].
pub fn cgroup2_root() -> Option<PathBuf> {
    CGROUP2_MOUNTS
        .iter()
        .map(PathBuf::from)
        .find(|p| is_cgroup2(p))
}

fn is_cgroup2(p: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(p.as_os_str().as_bytes()) else {
        return false;
    };
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a valid NUL-terminated path, `s` a writable statfs.
    let rc = unsafe { libc::statfs(c.as_ptr(), &mut s) };
    rc == 0 && s.f_type as i64 == CGROUP2_SUPER_MAGIC
}

/// [`UnitCgroup`] of process `pid`, on this host's cgroup v2 mount.
pub fn unit_cgroup_of(pid: u32) -> UnitCgroup {
    let text = match std::fs::read_to_string(format!("/proc/{pid}/cgroup")) {
        Ok(t) => t,
        Err(e) => {
            return UnitCgroup::Unavailable {
                why: format!("/proc/{pid}/cgroup: {e}"),
            }
        }
    };
    let Some(cgroup) = v2_path(&text) else {
        return UnitCgroup::Unavailable {
            why: format!("process {pid} is in no cgroup v2 (a cgroup v1 hierarchy)"),
        };
    };
    let Some(root) = cgroup2_root() else {
        return UnitCgroup::Unavailable {
            why: "no cgroup v2 hierarchy mounted at /sys/fs/cgroup".into(),
        };
    };
    unit_cgroup_at(&root, cgroup)
}

/// [`UnitCgroup`] of `cgroup` under the hierarchy mounted at `root`. A
/// file the kernel does not have (`cgroup.kill` before 5.14) is left out;
/// the unit's directory itself must be there.
pub fn unit_cgroup_at(root: &Path, cgroup: &str) -> UnitCgroup {
    let parts = match service_components(cgroup) {
        Ok(p) => p,
        Err(_) => {
            return UnitCgroup::NotAService {
                cgroup: cgroup.to_string(),
            }
        }
    };
    let mut entries = Vec::new();
    let mut dir = root.to_path_buf();
    let last = parts.len() - 1;
    for (i, part) in parts.iter().enumerate() {
        dir.push(part);
        let files: &[(&str, u8)] = if i == last {
            &[
                ("cgroup.kill", KILL_FLAGS),
                ("cgroup.freeze", FREEZE_FLAGS),
                ("cgroup.procs", MEMBERS_FLAGS),
                ("cgroup.threads", MEMBERS_FLAGS),
            ]
        } else {
            &[("cgroup.kill", KILL_FLAGS), ("cgroup.freeze", FREEZE_FLAGS)]
        };
        if i == last {
            match entry_of(&dir, UNIT_DIR_FLAGS, true) {
                Ok(Some(e)) => entries.push(e),
                Ok(None) => {
                    return UnitCgroup::Unavailable {
                        why: format!("{} is gone", dir.display()),
                    }
                }
                Err(why) => return UnitCgroup::Unavailable { why },
            }
        }
        for (name, flags) in files {
            match entry_of(&dir.join(name), *flags, false) {
                Ok(Some(e)) => entries.push(e),
                Ok(None) => {}
                Err(why) => return UnitCgroup::Unavailable { why },
            }
        }
    }
    UnitCgroup::Service {
        cgroup: cgroup.to_string(),
        entries,
    }
}

/// The entry of `path` (`lstat`, never a link's target): `Ok(None)` when
/// it does not exist, `Err` when it is not the kind it must be.
fn entry_of(path: &Path, flags: u8, dir: bool) -> std::result::Result<Option<CgroupEntry>, String> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let ft = meta.file_type();
    if (dir && !ft.is_dir()) || (!dir && !ft.is_file()) {
        return Err(format!(
            "{} is not a cgroup {}",
            path.display(),
            if dir { "directory" } else { "file" }
        ));
    }
    Ok(Some(CgroupEntry {
        path: path.to_path_buf(),
        key: InodeKey {
            dev: stat_dev_to_kernel_dev(meta.dev()),
            ino: meta.ino(),
        },
        flags,
    }))
}

/// `PROTECTED_INODES`'s key, as the map stores it.
#[repr(transparent)]
#[derive(Clone, Copy)]
struct Key(InodeKey);
// SAFETY: `InodeKey` is `#[repr(C)]`, two `u64`, no padding.
unsafe impl aya::Pod for Key {}

/// Register the cgroup of process `pid` in the pinned `PROTECTED_INODES`
/// under `bpffs_root` (the watchdog's own, at its start; the agent's,
/// before its eBPF load; the watchdog's, from the agent's refresh). An
/// entry that is there already is overwritten. The outcome says what was
/// found; `Err` only when an entry could not be written.
pub fn protect_unit_cgroup(bpffs_root: &Path, pid: u32) -> Result<UnitCgroup> {
    let unit = unit_cgroup_of(pid);
    if unit.entries().is_empty() {
        return Ok(unit);
    }
    let pin = bpffs_root.join(PROTECTED_INODES_MAP_NAME);
    let data = MapData::from_pin(&pin).with_context(|| {
        format!(
            "opening pinned {PROTECTED_INODES_MAP_NAME} at {}",
            pin.display()
        )
    })?;
    let mut map: AyaHashMap<MapData, Key, u8> = AyaHashMap::try_from(AyaMap::HashMap(data))
        .with_context(|| format!("{PROTECTED_INODES_MAP_NAME} is not a HashMap<InodeKey, u8>"))?;
    for e in unit.entries() {
        map.insert(Key(e.key), e.flags, 0).with_context(|| {
            format!(
                "registering {} in {PROTECTED_INODES_MAP_NAME}",
                e.path.display()
            )
        })?;
    }
    Ok(unit)
}

/// Remove `keys` from the pinned `PROTECTED_INODES` (a former watchdog's
/// cgroup, best effort: a key already gone is fine).
pub fn release_keys(bpffs_root: &Path, keys: &[InodeKey]) -> Result<()> {
    let pin = bpffs_root.join(PROTECTED_INODES_MAP_NAME);
    let data = MapData::from_pin(&pin).with_context(|| {
        format!(
            "opening pinned {PROTECTED_INODES_MAP_NAME} at {}",
            pin.display()
        )
    })?;
    let mut map: AyaHashMap<MapData, Key, u8> = AyaHashMap::try_from(AyaMap::HashMap(data))
        .with_context(|| format!("{PROTECTED_INODES_MAP_NAME} is not a HashMap<InodeKey, u8>"))?;
    for k in keys {
        let _ = map.remove(&Key(*k));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_v2_line_is_read_and_nothing_else() {
        assert_eq!(
            v2_path("0::/system.slice/northnarrow-agent.service\n"),
            Some("/system.slice/northnarrow-agent.service")
        );
        assert_eq!(
            v2_path("12:freezer:/x\n1:name=systemd:/system.slice/a.service\n0::/system.slice/a.service\n"),
            Some("/system.slice/a.service")
        );
        assert_eq!(v2_path("1:name=systemd:/system.slice/a.service\n"), None);
        assert_eq!(v2_path(""), None);
    }

    #[test]
    fn only_a_service_under_slices_is_a_unit() {
        assert_eq!(
            service_components("/system.slice/northnarrow-agent.service").unwrap(),
            vec!["system.slice", "northnarrow-agent.service"]
        );
        assert_eq!(
            service_components("/a.slice/a-b.slice/x.service").unwrap(),
            vec!["a.slice", "a-b.slice", "x.service"]
        );
        for not in [
            "/",
            "",
            "system.slice/x.service",
            "/user.slice/user-1000.slice/session-3.scope",
            "/system.slice",
            "/system.slice/.service",
            "/system.slice/x.service/child",
            "/init.scope/x.service",
            "/system.slice//x.service",
            "/system.slice/../x.service",
        ] {
            assert!(service_components(not).is_err(), "{not:?}");
        }
        // a service at the root, under no slice: still a service
        assert_eq!(service_components("/x.service").unwrap(), vec!["x.service"]);
    }

    /// The entries of a unit, on a directory tree shaped like the
    /// hierarchy: the unit's directory and four files, each ancestor
    /// slice's kill and freeze, a missing `cgroup.kill` left out.
    #[test]
    fn the_entries_follow_the_unit_and_its_slices() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        let unit = root.join("system.slice/northnarrow-agent.service");
        std::fs::create_dir_all(&unit).unwrap();
        for f in [
            "cgroup.kill",
            "cgroup.freeze",
            "cgroup.procs",
            "cgroup.threads",
            "memory.max",
        ] {
            std::fs::write(unit.join(f), b"").unwrap();
        }
        // the slice: freeze only (a kernel without cgroup.kill)
        std::fs::write(root.join("system.slice/cgroup.freeze"), b"").unwrap();
        std::fs::write(root.join("system.slice/cgroup.procs"), b"").unwrap();
        let u = unit_cgroup_at(root, "/system.slice/northnarrow-agent.service");
        let got: Vec<(String, u8)> = u
            .entries()
            .iter()
            .map(|e| {
                (
                    e.path.strip_prefix(root).unwrap().display().to_string(),
                    e.flags,
                )
            })
            .collect();
        assert_eq!(
            got,
            vec![
                ("system.slice/cgroup.freeze".to_string(), FREEZE_FLAGS),
                (
                    "system.slice/northnarrow-agent.service".to_string(),
                    UNIT_DIR_FLAGS
                ),
                (
                    "system.slice/northnarrow-agent.service/cgroup.kill".to_string(),
                    KILL_FLAGS
                ),
                (
                    "system.slice/northnarrow-agent.service/cgroup.freeze".to_string(),
                    FREEZE_FLAGS
                ),
                (
                    "system.slice/northnarrow-agent.service/cgroup.procs".to_string(),
                    MEMBERS_FLAGS
                ),
                (
                    "system.slice/northnarrow-agent.service/cgroup.threads".to_string(),
                    MEMBERS_FLAGS
                ),
            ]
        );
        // each key is the file's own
        let m = std::fs::metadata(unit.join("cgroup.kill")).unwrap();
        let k = u
            .entries()
            .iter()
            .find(|e| e.path.ends_with("cgroup.kill"))
            .unwrap();
        assert_eq!(k.key.ino, m.ino());
        assert_eq!(k.key.dev, stat_dev_to_kernel_dev(m.dev()));
    }

    #[test]
    fn a_scope_a_missing_unit_and_a_link_are_not_protected() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        assert!(matches!(
            unit_cgroup_at(root, "/user.slice/user-1000.slice/session-2.scope"),
            UnitCgroup::NotAService { .. }
        ));
        assert!(matches!(
            unit_cgroup_at(root, "/system.slice/gone.service"),
            UnitCgroup::Unavailable { .. }
        ));
        std::fs::create_dir_all(root.join("system.slice/elsewhere")).unwrap();
        std::os::unix::fs::symlink(
            root.join("system.slice/elsewhere"),
            root.join("system.slice/linked.service"),
        )
        .unwrap();
        assert!(matches!(
            unit_cgroup_at(root, "/system.slice/linked.service"),
            UnitCgroup::Unavailable { .. }
        ));
        // a link where a control file is: refused, not followed
        let unit = root.join("system.slice/a.service");
        std::fs::create_dir_all(&unit).unwrap();
        std::fs::write(root.join("target"), b"").unwrap();
        std::os::unix::fs::symlink(root.join("target"), unit.join("cgroup.kill")).unwrap();
        assert!(matches!(
            unit_cgroup_at(root, "/system.slice/a.service"),
            UnitCgroup::Unavailable { .. }
        ));
    }

    /// The flags of each entry: what the deny hooks test.
    #[test]
    fn the_entry_flags_are_the_protection_the_table_states() {
        use common::wire::{
            fs_protect_denied_op, fs_protect_init_may, fs_protect_required, FS_OP_CGROUP_FREEZE,
            FS_OP_CGROUP_KILL, FS_OP_MKDIR, FS_OP_RMDIR, FS_OP_SETATTR, FS_OP_WRITE,
        };
        let refused = |op: u8, flags: u8| flags & fs_protect_required(op) != 0;
        // the unit's directory: no rmdir but PID 1's, no child, no chown
        assert!(refused(FS_OP_RMDIR, UNIT_DIR_FLAGS));
        assert!(fs_protect_init_may(FS_OP_RMDIR, UNIT_DIR_FLAGS, 1));
        assert!(!fs_protect_init_may(FS_OP_RMDIR, UNIT_DIR_FLAGS, 4242));
        assert!(refused(FS_OP_MKDIR, UNIT_DIR_FLAGS));
        assert!(refused(FS_OP_SETATTR, UNIT_DIR_FLAGS));
        // kill and freeze: no write-open, signed by their effect
        assert!(refused(FS_OP_WRITE, KILL_FLAGS));
        assert!(refused(FS_OP_WRITE, FREEZE_FLAGS));
        assert_eq!(
            fs_protect_denied_op(FS_OP_WRITE, KILL_FLAGS),
            FS_OP_CGROUP_KILL
        );
        assert_eq!(
            fs_protect_denied_op(FS_OP_WRITE, FREEZE_FLAGS),
            FS_OP_CGROUP_FREEZE
        );
        assert!(!fs_protect_init_may(FS_OP_WRITE, KILL_FLAGS, 1));
        // the members: writable (systemd attaches the unit's processes),
        // not re-owned
        assert!(!refused(FS_OP_WRITE, MEMBERS_FLAGS));
        assert!(refused(FS_OP_SETATTR, MEMBERS_FLAGS));
    }

    #[test]
    fn the_device_is_the_kernel_encoding() {
        // /dev/sda2: stat 0x802 → s_dev (8 << 20) | 2
        assert_eq!(stat_dev_to_kernel_dev(0x802), 0x80_0002);
        // an anonymous device (cgroupfs): major 0
        assert_eq!(stat_dev_to_kernel_dev(0x1f), 0x1f);
    }
}
