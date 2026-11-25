//! The re-check 2 of #567 (point 2): the packaged `systemd-journald`, whose
//! refused reads of the agent's processes (`/proc/<pid>/exe` for the
//! metadata of every line it takes, all day: about 2,880 Low records a day
//! per target with a dedup by process and minute) are not recorded. They
//! stay refused (`agent-ebpf/src/ptrace_check.rs`); only the record goes
//! (`northnarrow_common::ptrace_read::quiet`).
//!
//! Its identity is two facts, both needed:
//!
//! - its image: the file at its install path ([`JOURNALD_PATHS`]) that root
//!   owns and no one else may write, in a directory root owns and no one
//!   else may write (`ROOT_DIR`), that the package database does not disown
//!   — the kernel's `(dev, ino)`, as `mm->exe_file` gives it — read again
//!   every 10 s with lot 310's `systemd-executor` identities, each read
//!   replacing the set (an upgrade's new inode in, the old one out);
//! - its unit's cgroup ([`JOURNALD_CGROUPS`]: `systemd-journald.service`,
//!   and the namespace instance the agent's and the watchdog's units log
//!   to, `systemd-journald@northnarrow.service` (`LogNamespace=northnarrow`:
//!   it reads the agent's `/proc/<pid>/exe` for every line the agent
//!   writes) — by id, the directory's inode on cgroup v2: the kernel
//!   compares it with the caller's (`bpf_get_current_cgroup_id`). No
//!   cgroup v2: no identity, every read recorded.
//!
//! Root running that binary in that cgroup loses the record of its reads,
//! never their refusal. Nothing else is exempt: PID 1, logind or polkit
//! read nothing of the agent's that was measured, and an exemption with no
//! measured need is only a place to hide.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

use crate::systemd_executor::Owned;

/// Where the distributions install journald (merged `/usr` makes the two
/// one file).
pub const JOURNALD_PATHS: &[&str] = &[
    "/usr/lib/systemd/systemd-journald",
    "/lib/systemd/systemd-journald",
];

/// journald's units' cgroups, under the cgroup v2 root: the system
/// instance, and the namespace instance the agent's units log to, in its
/// template's slice as systemd places an instance (`system-systemd\x2d
/// journald.slice`, the lab's guests; no other instance:
/// `systemd-journald@<other>.service` is not ours to quiet).
pub const JOURNALD_CGROUPS: &[&str] = &[
    "system.slice/systemd-journald.service",
    "system.slice/system-systemd\\x2djournald.slice/systemd-journald@northnarrow.service",
];

/// A directory `owner` owns that no one else may write.
fn dir_owned_by(dir: &Path, owner: u32) -> bool {
    antitamper_bpf::kernel_roots::metadata(dir)
        .is_ok_and(|m| m.is_dir() && m.uid() == owner && m.mode() & 0o022 == 0)
}

/// The cgroup id of the cgroup v2 directory `dir` (its inode number).
fn cgroup_id(dir: &Path) -> Option<u64> {
    antitamper_bpf::kernel_roots::metadata(dir)
        .ok()
        .filter(|m| m.is_dir())
        .map(|m| m.ino())
        .filter(|id| *id != 0)
}

/// journald's images under `root` (`/` on the host, a test's tree), each
/// with the id of each of its units' cgroups under `cgroup_root` (the
/// cgroup v2 root; `None`: none) — `owner` the files' owner (0), `owned`
/// the package database. Sorted, without duplicates; empty without a
/// cgroup.
pub fn quiet_under(
    root: &Path,
    cgroup_root: Option<&Path>,
    owner: u32,
    owned: Owned,
) -> Vec<((u64, u64), u64)> {
    let cgroups: Vec<u64> = JOURNALD_CGROUPS
        .iter()
        .filter_map(|c| cgroup_root.and_then(|r| cgroup_id(&r.join(c))))
        .collect();
    if cgroups.is_empty() {
        return Vec::new();
    }
    let in_root_dirs: Vec<&str> = JOURNALD_PATHS
        .iter()
        .copied()
        .filter(|p| {
            Path::new(p)
                .parent()
                .is_some_and(|d| dir_owned_by(&root.join(d.strip_prefix("/").unwrap_or(d)), owner))
        })
        .collect();
    let mut ids: Vec<((u64, u64), u64)> =
        crate::systemd_executor::packaged(&in_root_dirs, root, owner, owned)
            .into_iter()
            .flat_map(|id| cgroups.iter().map(move |c| (id, *c)))
            .collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// The host's ([`quiet_under`] of `/`, the cgroup v2 root, root's files,
/// the package database of the host).
fn quiet_now() -> Vec<((u64, u64), u64)> {
    let owners =
        nn_core::impact::trust::ProgramOwners::<crate::chain_host_linux::LinuxHost>::new("/");
    let cgroups = antitamper_bpf::cgroup_guard::cgroup2_root();
    quiet_under(Path::new("/"), cgroups.as_deref(), 0, &|p| owners.owned(p))
}

/// The eBPF map `PTRACE_READ_QUIET` (`common::ptrace_read::quiet_key` →
/// 1), once the ptrace guard is attached.
type KernelMap = aya::maps::HashMap<aya::maps::MapData, [u64; 3], u8>;

/// The kernel's copy of the identities, and the last ones read (written
/// when the map is installed after a read).
struct Kernel {
    map: Option<KernelMap>,
    ids: Vec<((u64, u64), u64)>,
}

static KERNEL: parking_lot::Mutex<Kernel> = parking_lot::Mutex::new(Kernel {
    map: None,
    ids: Vec::new(),
});

/// The ptrace guard's `PTRACE_READ_QUIET` map, given by the anti-tamper
/// load once the hook is attached: the identities read now go in.
pub fn install_kernel_map(map: KernelMap) {
    let ids = quiet_now();
    let mut guard = KERNEL.lock();
    let k = &mut *guard;
    k.map = Some(map);
    k.ids = ids;
    publish(&mut k.map, &k.ids);
}

/// `ids` in place of the map's: the ones gone removed first, then the new.
fn publish(map: &mut Option<KernelMap>, ids: &[((u64, u64), u64)]) {
    let Some(map) = map.as_mut() else {
        return;
    };
    let keys: Vec<[u64; 3]> = ids
        .iter()
        .map(|((dev, ino), cgroup)| common::ptrace_read::quiet_key(*dev, *ino, *cgroup))
        .collect();
    let old: Vec<_> = map.keys().filter_map(Result::ok).collect();
    for k in old {
        if !keys.contains(&k) {
            let _ = map.remove(&k);
        }
    }
    for k in keys {
        if let Err(e) = map.insert(&k, &1, 0) {
            tracing::warn!(error = %e, dev = k[0], ino = k[1], cgroup = k[2], "PTRACE_READ_QUIET: journald's identity not written to the kernel");
        }
    }
}

/// Read the identities again (every 10 s, with `systemd_executor`'s) and
/// write them to the kernel when they changed; `true` then.
pub fn refresh() -> bool {
    let ids = quiet_now();
    let mut guard = KERNEL.lock();
    let k = &mut *guard;
    if k.ids == ids {
        return false;
    }
    k.ids = ids;
    publish(&mut k.map, &k.ids);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn me() -> u32 {
        // SAFETY: getuid has no preconditions.
        unsafe { libc::getuid() }
    }

    fn no_db(_: &Path) -> Option<bool> {
        None
    }

    fn file(path: &Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"journald").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// The re-check 2 of #567 (point 2): journald's identity is its
    /// packaged image (root's file, in root's directory, not disowned) and
    /// its unit's cgroup — an upgrade's new inode replaces the old one; no
    /// cgroup, a file named so elsewhere, a directory others may write, a
    /// file others may write, another owner, a disowned file: no identity.
    #[test]
    fn journalds_identity_is_its_packaged_image_and_its_units_cgroup() {
        let root = tempfile::tempdir().unwrap();
        let cg = tempfile::tempdir().unwrap();
        let r = root.path();
        let exe = r.join("usr/lib/systemd/systemd-journald");
        file(&exe);
        let unit = cg.path().join(JOURNALD_CGROUPS[0]);
        std::fs::create_dir_all(&unit).unwrap();
        let id = std::fs::metadata(&unit).unwrap().ino();
        let md = std::fs::metadata(&exe).unwrap();
        let kernel_dev = crate::anti_tamper::filesystem::stat_dev_to_kernel_dev(md.dev());
        let got = quiet_under(r, Some(cg.path()), me(), &no_db);
        assert_eq!(got, vec![((kernel_dev, md.ino()), id)]);
        // the namespace instance the agent's units log to, and no other
        let ns = cg.path().join(JOURNALD_CGROUPS[1]);
        std::fs::create_dir_all(&ns).unwrap();
        std::fs::create_dir_all(
            cg.path().join(
                "system.slice/system-systemd\\x2djournald.slice/systemd-journald@other.service",
            ),
        )
        .unwrap();
        // not the flat place an instance is not put in
        std::fs::create_dir_all(
            cg.path()
                .join("system.slice/systemd-journald@northnarrow.service"),
        )
        .unwrap();
        let ns_id = std::fs::metadata(&ns).unwrap().ino();
        let mut want = vec![
            ((kernel_dev, md.ino()), id),
            ((kernel_dev, md.ino()), ns_id),
        ];
        want.sort_unstable();
        assert_eq!(quiet_under(r, Some(cg.path()), me(), &no_db), want);
        std::fs::remove_dir(&ns).unwrap();
        // no cgroup v2 root, or no unit cgroup: nothing is quiet
        assert!(quiet_under(r, None, me(), &no_db).is_empty());
        let empty = tempfile::tempdir().unwrap();
        assert!(quiet_under(r, Some(empty.path()), me(), &no_db).is_empty());
        // an upgrade: the new file renamed over the old one
        let new_file = r.join("usr/lib/systemd/systemd-journald.dpkg-new");
        file(&new_file);
        std::fs::rename(&new_file, &exe).unwrap();
        let ino = std::fs::metadata(&exe).unwrap().ino();
        assert_eq!(quiet_under(r, Some(cg.path()), me(), &no_db)[0].0.1, ino);
        assert_ne!(ino, md.ino());
        // a file named so elsewhere is never looked at
        let opt = r.join("opt/x/systemd-journald");
        file(&opt);
        assert_eq!(quiet_under(r, Some(cg.path()), me(), &no_db).len(), 1);
        // disowned, another owner, others may write the file or its directory
        assert!(quiet_under(r, Some(cg.path()), me(), &|_| Some(false)).is_empty());
        assert!(quiet_under(r, Some(cg.path()), me().wrapping_add(1), &no_db).is_empty());
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o757)).unwrap();
        assert!(quiet_under(r, Some(cg.path()), me(), &no_db).is_empty());
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        let dir = r.join("usr/lib/systemd");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(
            quiet_under(r, Some(cg.path()), me(), &no_db).is_empty(),
            "a directory others may write: no ROOT_DIR"
        );
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(quiet_under(r, Some(cg.path()), me(), &no_db).len(), 1);
    }

    /// Named test (fix round 3 of #567, the lab's 6.8 round): journald's
    /// identity is in the kernel before the ptrace guard attaches — after
    /// it, one of journald's reads (for the attach's own log lines) was
    /// recorded in between.
    #[test]
    fn journalds_identity_is_in_the_kernel_before_the_hook_attaches() {
        let at = include_str!("anti_tamper/mod.rs");
        let install = at
            .find("Ok(map) => crate::journald_identity::install_kernel_map(map),")
            .expect("the install");
        let attach = at
            .find("reattach_fresh(ebpf, PTRACE_PROGRAM, PTRACE_HOOK, &btf, pin_root)")
            .expect("the ptrace attach");
        assert!(
            install < attach,
            "the identity is installed after the attach"
        );
    }
}
