//! The exec policy's kernel objects (lab PR 226): the configuration written
//! once and frozen, the maps the controller refreshes (the slices, the
//! images, the guarded mount roots when the exec quarantine is off), the
//! ring and the counters.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use aya::maps::{Array, HashMap, MapData, PerCpuArray, RingBuf};
use aya::Ebpf;
use common::wire::execpol::{conf_slot, counter, image_role, slice_slot};
use common::wire::execq::ExecqKey;

use crate::execq::kernel::AyaKey;

/// What the controller holds.
pub struct Kernel {
    pub ring: RingBuf<MapData>,
    pub images: HashMap<MapData, AyaKey, u32>,
    pub slices: Array<MapData, u64>,
    pub counters: PerCpuArray<MapData, u64>,
    /// `EXECQ_ROOTS`, when the exec quarantine (which refreshes it
    /// otherwise) is off.
    pub roots: Option<HashMap<MapData, AyaKey, u32>>,
    pub(crate) reject: crate::sensors::reject::RejectThrottle,
}

impl std::fmt::Debug for Kernel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Kernel").finish_non_exhaustive()
    }
}

/// Write `EXECPOL_CONF` and freeze it: from here no process, root
/// included, can change the policy the kernel applies. Written with
/// `mode::OFF` too, so the policy cannot be turned on behind the agent.
pub fn write_conf(ebpf: &mut Ebpf, words: &[u64; conf_slot::SLOTS as usize]) -> Result<()> {
    let map = ebpf
        .map_mut("EXECPOL_CONF")
        .ok_or_else(|| anyhow!("EXECPOL_CONF missing from the eBPF object"))?;
    let mut arr: Array<&mut MapData, u64> = Array::try_from(map).context("EXECPOL_CONF")?;
    // Mode last: the tables are in place before anything reads them.
    for (i, w) in words.iter().enumerate() {
        if i as u32 != conf_slot::MODE {
            arr.set(i as u32, *w, 0)?;
        }
    }
    arr.set(conf_slot::MODE, words[conf_slot::MODE as usize], 0)?;
    let map = ebpf
        .map("EXECPOL_CONF")
        .ok_or_else(|| anyhow!("EXECPOL_CONF missing from the eBPF object"))?;
    let aya::maps::Map::Array(data) = map else {
        return Err(anyhow!("EXECPOL_CONF is not an array"));
    };
    crate::execq::kernel::freeze(data).context("BPF_MAP_FREEZE on EXECPOL_CONF")
}

/// Take the policy's maps and ring out of the object (`EXECQ_ROOTS` too
/// when `take_roots`).
pub fn take(ebpf: &mut Ebpf, take_roots: bool) -> Result<Kernel> {
    let mut take = |name: &str| {
        ebpf.take_map(name)
            .ok_or_else(|| anyhow!("{name} missing from the eBPF object"))
    };
    let roots = if take_roots {
        Some(HashMap::try_from(take("EXECQ_ROOTS")?).context("EXECQ_ROOTS")?)
    } else {
        None
    };
    Ok(Kernel {
        ring: RingBuf::try_from(take("EXECPOL_EVENTS")?).context("EXECPOL_EVENTS")?,
        images: HashMap::try_from(take("EXECPOL_IMAGES")?).context("EXECPOL_IMAGES")?,
        slices: Array::try_from(take("EXECPOL_SLICES")?).context("EXECPOL_SLICES")?,
        counters: PerCpuArray::try_from(take("EXECPOL_COUNTERS")?).context("EXECPOL_COUNTERS")?,
        roots,
        reject: crate::sensors::reject::RejectThrottle::new(),
    })
}

impl Kernel {
    /// The per-CPU counters summed, `counter::*` order.
    pub fn counters(&self) -> [u64; counter::SLOTS as usize] {
        let mut out = [0u64; counter::SLOTS as usize];
        for (i, slot) in out.iter_mut().enumerate() {
            if let Ok(v) = self.counters.get(&(i as u32), 0) {
                *slot = v.iter().copied().fold(0u64, u64::wrapping_add);
            }
        }
        out
    }

    pub fn set_slices(&mut self, system: u64, user: u64) {
        let _ = self.slices.set(slice_slot::SYSTEM, system, 0);
        let _ = self.slices.set(slice_slot::USER, user, 0);
    }

    /// Replace the image roles with `entries`.
    pub fn set_images(&mut self, entries: &[(ExecqKey, u32)]) {
        let old: Vec<AyaKey> = self.images.keys().filter_map(|k| k.ok()).collect();
        for k in old {
            if !entries.iter().any(|(e, _)| *e == k.0) {
                let _ = self.images.remove(&k);
            }
        }
        for (k, v) in entries {
            let _ = self.images.insert(AyaKey(*k), *v, 0);
        }
    }

    /// Replace the guarded mount roots (only when this side owns them).
    pub fn set_roots(&mut self, roots: &[(ExecqKey, u32)]) {
        let Some(map) = self.roots.as_mut() else {
            return;
        };
        let old: Vec<AyaKey> = map.keys().filter_map(|k| k.ok()).collect();
        for k in old {
            if !roots.iter().any(|(r, _)| *r == k.0) {
                let _ = map.remove(&k);
            }
        }
        for (k, v) in roots {
            let _ = map.insert(AyaKey(*k), *v, 0);
        }
    }
}

/// The cgroup v2 mount point in a `mountinfo` text (`/sys/fs/cgroup`, or
/// `/sys/fs/cgroup/unified` on a hybrid host).
pub fn cgroup2_mount(mountinfo: &str) -> Option<String> {
    mountinfo.lines().find_map(|line| {
        let (pre, post) = line.split_once(" - ")?;
        let fstype = post.split(' ').next()?;
        if fstype != "cgroup2" {
            return None;
        }
        pre.split(' ')
            .nth(4)
            .map(crate::sensors::open_sensor::unescape_octal)
    })
}

/// The cgroup ids of `system.slice` and `user.slice` under the cgroup v2
/// mount `root` (a cgroup's id is its directory's inode number on
/// cgroup2); 0 for a slice that does not exist (yet).
pub fn slice_ids(root: &Path) -> (u64, u64) {
    let id = |name: &str| std::fs::metadata(root.join(name)).map_or(0, |m| m.ino());
    (id("system.slice"), id("user.slice"))
}

/// The elevation binaries whose image in a root caller's lineage is one
/// of the admin tier's signals (the paths that exist on this host count).
pub const ELEVATION_IMAGES: [&str; 12] = [
    "/usr/bin/sudo",
    "/bin/sudo",
    "/usr/bin/sudoedit",
    "/usr/bin/su",
    "/bin/su",
    "/usr/bin/doas",
    "/usr/bin/pkexec",
    "/usr/bin/run0",
    // Ubuntu 25.10: sudo-rs and the uutils su behind alternatives.
    "/usr/lib/cargo/bin/sudo",
    "/usr/lib/cargo/bin/su",
    "/usr/bin/sudo-rs",
    "/usr/bin/su-rs",
];

/// `(dev, ino)` of a root-owned image nobody else can write; `None` for a
/// missing file, or one whose owner or mode would let another account
/// change what it vouches for.
pub fn trusted_image_key(path: &Path) -> Option<ExecqKey> {
    let m = std::fs::metadata(path).ok()?;
    if !m.is_file() || m.uid() != 0 || m.permissions().mode() & 0o022 != 0 {
        return None;
    }
    Some(ExecqKey {
        dev: crate::anti_tamper::filesystem::stat_dev_to_kernel_dev(m.dev()),
        ino: m.ino(),
    })
}

/// The `EXECPOL_IMAGES` entries: elevation binaries, the policy's exempt
/// images, and init's own image (the child init forks has not exec'd yet:
/// systemd ≥ 255 runs its executor from a descriptor pinned at start,
/// unlinked after an upgrade). `skipped`: exempt paths not used (missing,
/// or writable by another account).
pub fn image_entries(
    exempt: &[(PathBuf, u32)],
    proc_root: &Path,
    skipped: &mut Vec<String>,
) -> Vec<(ExecqKey, u32)> {
    let mut out: Vec<(ExecqKey, u32)> = Vec::new();
    let mut add = |k: ExecqKey, v: u32| match out.iter_mut().find(|(e, _)| *e == k) {
        Some((_, old)) => *old |= v,
        None => out.push((k, v)),
    };
    for p in ELEVATION_IMAGES {
        if let Some(k) = trusted_image_key(Path::new(p)) {
            add(k, image_role::ELEVATION);
        }
    }
    for (p, classes) in exempt {
        match trusted_image_key(p) {
            Some(k) => add(k, classes & image_role::EXEMPT_MASK),
            None if p.exists() => skipped.push(format!(
                "{}: not root-owned, or writable by group or others",
                p.display()
            )),
            None => {}
        }
    }
    // init's image: `/proc/1/exe` names it even once unlinked.
    if let Ok(m) = std::fs::metadata(proc_root.join("1/exe")) {
        add(
            ExecqKey {
                dev: crate::anti_tamper::filesystem::stat_dev_to_kernel_dev(m.dev()),
                ino: m.ino(),
            },
            crate::execpol::policy::EXEMPT_DEFAULT_CLASSES,
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cgroup2_mount() {
        let unified = "24 1 0:22 / /sys/fs/cgroup rw,nosuid shared:9 - cgroup2 cgroup2 rw\n";
        assert_eq!(cgroup2_mount(unified).as_deref(), Some("/sys/fs/cgroup"));
        let hybrid = "24 1 0:22 / /sys/fs/cgroup ro shared:9 - tmpfs tmpfs ro\n\
                      25 24 0:23 / /sys/fs/cgroup/unified rw shared:10 - cgroup2 cgroup2 rw\n\
                      26 24 0:24 / /sys/fs/cgroup/systemd rw shared:11 - cgroup cgroup rw,name=systemd\n";
        assert_eq!(
            cgroup2_mount(hybrid).as_deref(),
            Some("/sys/fs/cgroup/unified")
        );
        assert_eq!(
            cgroup2_mount("26 24 0:24 / /sys/fs/cgroup/systemd rw - cgroup cgroup rw\n"),
            None,
            "v1 only: no tiers"
        );
    }

    #[test]
    fn slice_ids_are_directory_inodes() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("system.slice")).unwrap();
        let (sys, user) = slice_ids(d.path());
        assert_eq!(
            sys,
            std::fs::metadata(d.path().join("system.slice"))
                .unwrap()
                .ino()
        );
        assert_eq!(user, 0, "user.slice not there yet");
    }

    /// An exemption vouches for a caller's image: a file another account
    /// can rewrite is not used.
    #[test]
    fn only_root_owned_images_are_trusted() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("rt");
        std::fs::write(&f, b"x").unwrap();
        // the test runs as a user: the file is not root's
        if nix_uid() != 0 {
            assert_eq!(trusted_image_key(&f), None);
            let mut skipped = Vec::new();
            let e = image_entries(&[(f.clone(), 1)], d.path(), &mut skipped);
            assert!(e
                .iter()
                .all(|(_, v)| *v & 1 == 0 || *v & image_role::ELEVATION != 0));
            assert_eq!(skipped.len(), 1, "{skipped:?}");
        }
        assert_eq!(trusted_image_key(&d.path().join("missing")), None);
        // a root-owned system binary, where the host has one
        if let Some(k) = trusted_image_key(Path::new("/bin/sh")) {
            assert!(k.ino != 0);
        }
    }

    fn nix_uid() -> u32 {
        // SAFETY: getuid cannot fail.
        unsafe { libc::getuid() }
    }

    #[test]
    fn init_image_is_exempt_for_memfd_and_deleted() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("1")).unwrap();
        std::fs::write(d.path().join("1/exe"), b"init").unwrap();
        let mut skipped = Vec::new();
        let e = image_entries(&[], d.path(), &mut skipped);
        let ino = std::fs::metadata(d.path().join("1/exe")).unwrap().ino();
        let init = e.iter().find(|(k, _)| k.ino == ino).expect("init entry");
        assert_eq!(init.1, crate::execpol::policy::EXEMPT_DEFAULT_CLASSES);
    }
}
