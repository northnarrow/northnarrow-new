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

use crate::execq::kernel::{AyaKey, RootsRefused};

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
    /// `debug-trigger` builds (lot 325, R5's e2e): the exec guards'
    /// per-task maps, to fill and empty on request.
    #[cfg(feature = "debug-trigger")]
    pub(crate) debug: debug_fill::Maps,
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
        #[cfg(feature = "debug-trigger")]
        debug: debug_fill::Maps::open(ebpf),
    })
}

/// `debug-trigger` builds only (lot 325, the re-check of #546, R5): fill the
/// exec sensor's per-task walk map (`EXEC_SCRATCH`) — and the environment's
/// (`EXECPOL_ENV`) — with entries no task has (start time near `u64::MAX`),
/// as a flood of execs in flight would, and empty them again: the e2e's
/// fork-bomb shape, bounded and deterministic.
#[cfg(feature = "debug-trigger")]
pub(crate) mod debug_fill {
    use std::os::fd::AsFd;

    use aya::maps::{HashMap, Map, MapData};
    use aya::Ebpf;
    use common::wire::exe::ExeIdentityRaw;
    use common::wire::execpol::ENV_ENTRY_BYTES;

    const WALK_BYTES: usize = std::mem::size_of::<ExeIdentityRaw>();

    /// The two maps, through their own descriptors (the object keeps its).
    pub(crate) struct Maps {
        walk: Option<HashMap<MapData, [u8; 16], [u8; WALK_BYTES]>>,
        env: Option<HashMap<MapData, [u8; 16], [u8; ENV_ENTRY_BYTES]>>,
        filled: Vec<[u8; 16]>,
    }

    fn dup(ebpf: &Ebpf, name: &str) -> Option<MapData> {
        let Some(Map::HashMap(d)) = ebpf.map(name) else {
            return None;
        };
        let fd = d.fd().as_fd().try_clone_to_owned().ok()?;
        MapData::from_fd(fd).ok()
    }

    /// A key no task has: `TaskKey { start_ns: u64::MAX - i, tid: u32::MAX }`.
    fn key(i: u64) -> [u8; 16] {
        let mut k = [0u8; 16];
        k[..8].copy_from_slice(&(u64::MAX - i).to_le_bytes());
        k[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        k
    }

    impl Maps {
        pub(crate) fn open(ebpf: &Ebpf) -> Self {
            Maps {
                walk: dup(ebpf, "EXEC_SCRATCH")
                    .and_then(|d| HashMap::try_from(Map::HashMap(d)).ok()),
                env: dup(ebpf, "EXECPOL_ENV").and_then(|d| HashMap::try_from(Map::HashMap(d)).ok()),
                filled: Vec::new(),
            }
        }

        /// Fill the walk map (and, with `env`, the environment's) until the
        /// kernel refuses an entry; the entries made.
        pub(crate) fn fill(&mut self, env: bool) -> usize {
            let mut n = 0;
            for i in 0..crate::execpol::kernel::debug_fill::LIMIT {
                let k = key(i);
                let mut made = false;
                if let Some(m) = self.walk.as_mut() {
                    made |= m.insert(k, [0u8; WALK_BYTES], 0).is_ok();
                }
                if env {
                    if let Some(m) = self.env.as_mut() {
                        made |= m.insert(k, [0u8; ENV_ENTRY_BYTES], 0).is_ok();
                    }
                }
                if !made {
                    break;
                }
                self.filled.push(k);
                n += 1;
            }
            n
        }

        /// Remove every entry [`Maps::fill`] made; how many.
        pub(crate) fn empty(&mut self) -> usize {
            let n = self.filled.len();
            for k in self.filled.drain(..) {
                if let Some(m) = self.walk.as_mut() {
                    let _ = m.remove(&k);
                }
                if let Some(m) = self.env.as_mut() {
                    let _ = m.remove(&k);
                }
            }
            n
        }
    }

    /// The most entries a fill makes (the maps hold 2048 each).
    pub(crate) const LIMIT: u64 = 4096;
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

    pub fn set_slices(&mut self, system: u64, user: u64, ours: u64) {
        let _ = self.slices.set(slice_slot::SYSTEM, system, 0);
        let _ = self.slices.set(slice_slot::USER, user, 0);
        let _ = self.slices.set(slice_slot::OURS, ours, 0);
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

    /// Replace the guarded mount roots (only when this side owns them);
    /// what the kernel's map refused (lot 311, the review of #538, F3, G2:
    /// ranked, [`crate::execq::kernel::publish_ranked`]).
    pub fn set_roots(&mut self, roots: &[(ExecqKey, u32)]) -> RootsRefused {
        let Some(map) = self.roots.as_mut() else {
            return RootsRefused::default();
        };
        crate::execq::kernel::publish_ranked(map, roots)
    }
}

/// The cgroup v2 mount point in a mount table (`/sys/fs/cgroup`, or
/// `/sys/fs/cgroup/unified` on a hybrid host); lot 311: the table read as
/// bytes ([`nn_linux::mountinfo`]).
pub fn cgroup2_mount(table: &nn_linux::mountinfo::MountTable) -> Option<std::path::PathBuf> {
    table
        .entries
        .iter()
        .find(|m| m.fstype == "cgroup2")
        .map(|m| m.mount_point.clone())
}

/// The cgroup ids of `system.slice`, `user.slice` and (lot 273d, NB5)
/// the units' own `northnarrow.slice` under the cgroup v2 mount `root` (a
/// cgroup's id is its directory's inode number on cgroup2); 0 for a slice
/// that does not exist (yet).
pub fn slice_ids(root: &Path) -> (u64, u64, u64) {
    let id = |name: &str| std::fs::metadata(root.join(name)).map_or(0, |m| m.ino());
    (
        id("system.slice"),
        id("user.slice"),
        id("northnarrow.slice"),
    )
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
        let t = |text: &str| nn_linux::mountinfo::parse(text.as_bytes());
        let unified = "24 1 0:22 / /sys/fs/cgroup rw,nosuid shared:9 - cgroup2 cgroup2 rw\n";
        assert_eq!(
            cgroup2_mount(&t(unified)).as_deref(),
            Some(std::path::Path::new("/sys/fs/cgroup"))
        );
        let hybrid = "24 1 0:22 / /sys/fs/cgroup ro shared:9 - tmpfs tmpfs ro\n\
                      25 24 0:23 / /sys/fs/cgroup/unified rw shared:10 - cgroup2 cgroup2 rw\n\
                      26 24 0:24 / /sys/fs/cgroup/systemd rw shared:11 - cgroup cgroup rw,name=systemd\n";
        assert_eq!(
            cgroup2_mount(&t(hybrid)).as_deref(),
            Some(std::path::Path::new("/sys/fs/cgroup/unified"))
        );
        assert_eq!(
            cgroup2_mount(&t(
                "26 24 0:24 / /sys/fs/cgroup/systemd rw - cgroup cgroup rw\n"
            )),
            None,
            "v1 only: no tiers"
        );
    }

    #[test]
    fn slice_ids_are_directory_inodes() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("system.slice")).unwrap();
        let (sys, user, ours) = slice_ids(d.path());
        assert_eq!(
            sys,
            std::fs::metadata(d.path().join("system.slice"))
                .unwrap()
                .ino()
        );
        assert_eq!(user, 0, "user.slice not there yet");
        // the short re-check of #497 (NB5): the units' own slice is read
        // (a service tier in the kernel, as system.slice was for them)
        assert_eq!(ours, 0);
        std::fs::create_dir(d.path().join("northnarrow.slice")).unwrap();
        assert_eq!(
            slice_ids(d.path()).2,
            std::fs::metadata(d.path().join("northnarrow.slice"))
                .unwrap()
                .ino()
        );
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
