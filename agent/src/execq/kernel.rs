//! The exec quarantine's kernel objects (lab PR 223): the configuration
//! written once and frozen, and the maps and ring the controller owns.

use std::os::fd::{AsFd, AsRawFd};
#[cfg(test)]
use std::os::unix::fs::MetadataExt;

use anyhow::{anyhow, Context, Result};
use aya::maps::{Array, HashMap, MapData, PerCpuArray, RingBuf};
use aya::Ebpf;
use common::wire::execq::{conf_slot, counter, root_kind, ExecqKey, ExecqKnown, ExecqStopped};

/// `ExecqKey` for aya (its own `Pod` marker; the orphan rule forbids
/// implementing it on the `common` type).
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AyaKey(pub ExecqKey);
// SAFETY: `#[repr(C)]` over two u64, no padding; transparent wrapper.
unsafe impl aya::Pod for AyaKey {}

#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AyaKnown(pub ExecqKnown);
// SAFETY: `#[repr(C)]`, two i64 then two u32, no padding.
unsafe impl aya::Pod for AyaKnown {}

#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AyaStopped(pub ExecqStopped);
// SAFETY: `#[repr(C)]` over two u64.
unsafe impl aya::Pod for AyaStopped {}

/// What the controller holds.
pub struct Kernel {
    pub ring: RingBuf<MapData>,
    pub known: HashMap<MapData, AyaKey, AyaKnown>,
    pub stopped: HashMap<MapData, u32, AyaStopped>,
    pub alive: Array<MapData, u64>,
    pub roots: HashMap<MapData, AyaKey, u32>,
    pub counters: PerCpuArray<MapData, u64>,
    pub(crate) reject: crate::sensors::reject::RejectThrottle,
}

impl std::fmt::Debug for Kernel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Kernel").finish_non_exhaustive()
    }
}

/// `BPF_MAP_FREEZE`, from the one copy of the uapi numbers (lab PR 215,
/// `common::bpf_cmd`).
const BPF_MAP_FREEZE_CMD: libc::c_long = common::bpf_cmd::BPF_MAP_FREEZE as libc::c_long;

/// `BPF_MAP_FREEZE` on `map` (the exec policy freezes its own
/// configuration the same way).
pub(crate) fn freeze(map: &MapData) -> Result<()> {
    #[repr(C)]
    struct FreezeAttr {
        map_fd: u32,
    }
    let attr = FreezeAttr {
        map_fd: map.fd().as_fd().as_raw_fd() as u32,
    };
    // SAFETY: bpf(BPF_MAP_FREEZE) with a valid attr of its exact size.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_FREEZE_CMD,
            &attr as *const FreezeAttr as *const libc::c_void,
            std::mem::size_of::<FreezeAttr>() as u32,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error()).context("BPF_MAP_FREEZE on EXECQ_CONF");
    }
    Ok(())
}

/// Write `EXECQ_CONF` (mode, guarded classes, heartbeat bound) and freeze
/// it: from here no process, root included, can change the mode the
/// kernel applies. Called with `mode::OFF` too, so the guard cannot be
/// turned on behind the agent's back.
pub fn write_conf(ebpf: &mut Ebpf, mode: u64, classes: u32, heartbeat_max_ns: u64) -> Result<()> {
    let map = ebpf
        .map_mut("EXECQ_CONF")
        .ok_or_else(|| anyhow!("EXECQ_CONF missing from the eBPF object"))?;
    let mut arr: Array<&mut MapData, u64> = Array::try_from(map).context("EXECQ_CONF")?;
    arr.set(conf_slot::CLASSES, u64::from(classes), 0)?;
    arr.set(conf_slot::HEARTBEAT_MAX_NS, heartbeat_max_ns, 0)?;
    arr.set(conf_slot::MODE, mode, 0)?;
    let map = ebpf
        .map("EXECQ_CONF")
        .ok_or_else(|| anyhow!("EXECQ_CONF missing from the eBPF object"))?;
    let aya::maps::Map::Array(data) = map else {
        return Err(anyhow!("EXECQ_CONF is not an array"));
    };
    freeze(data)
}

/// Take the guard's maps and ring out of the object.
pub fn take(ebpf: &mut Ebpf) -> Result<Kernel> {
    let mut take = |name: &str| {
        ebpf.take_map(name)
            .ok_or_else(|| anyhow!("{name} missing from the eBPF object"))
    };
    Ok(Kernel {
        ring: RingBuf::try_from(take("EXECQ_EVENTS")?).context("EXECQ_EVENTS")?,
        known: HashMap::try_from(take("EXECQ_KNOWN")?).context("EXECQ_KNOWN")?,
        stopped: HashMap::try_from(take("EXECQ_STOPPED")?).context("EXECQ_STOPPED")?,
        alive: Array::try_from(take("EXECQ_ALIVE")?).context("EXECQ_ALIVE")?,
        roots: HashMap::try_from(take("EXECQ_ROOTS")?).context("EXECQ_ROOTS")?,
        counters: PerCpuArray::try_from(take("EXECQ_COUNTERS")?).context("EXECQ_COUNTERS")?,
        reject: crate::sensors::reject::RejectThrottle::new(),
    })
}

/// `CLOCK_MONOTONIC` now, in ns — `bpf_ktime_get_ns`'s clock.
pub fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: a valid clock id and a timespec to fill.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

impl Kernel {
    /// The heartbeat a stop needs (0: the kernel stops nothing).
    pub fn beat(&mut self, ns: u64) {
        let _ = self.alive.set(0, ns, 0);
    }

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

    /// Replace the guarded mount roots with `roots` (ranked:
    /// [`guarded_roots`]); what the kernel's map refused (lot 311, the
    /// review of #538, F3 and G2: [`publish_ranked`]).
    pub fn set_roots(&mut self, roots: &[(ExecqKey, u32)]) -> RootsRefused {
        publish_ranked(&mut self.roots, roots)
    }
}

/// Lot 311 (the review of #538, G2): the guarded roots the kernel's map
/// (`EXECQ_ROOTS`, 64 entries) refused, the FUSE ones apart. A FUSE root
/// left out is classed by its file system's magic all the same (lot 318:
/// the exec hooks close a FUSE file whose device is not in the map), so
/// only `other` is a loss.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RootsRefused {
    pub other: usize,
    pub fuse: usize,
}

impl RootsRefused {
    /// The refusals of `roots` past the first `kept` (a map that keeps the
    /// ranked list's head).
    pub fn of_tail(roots: &[(ExecqKey, u32)], kept: usize) -> Self {
        let mut r = RootsRefused::default();
        for (k, _) in roots.iter().skip(kept) {
            if k.ino == FUSE_BY_DEVICE {
                r.fuse += 1;
            } else {
                r.other += 1;
            }
        }
        r
    }
}

/// A map of guarded roots: the kernel's (`EXECQ_ROOTS`), a test's.
pub trait RootsMap {
    /// The keys it holds.
    fn held(&self) -> Vec<ExecqKey>;
    /// Removed (it held it).
    fn remove(&mut self, key: &ExecqKey) -> bool;
    /// Inserted or updated (`false`: refused — the map is full).
    fn insert(&mut self, key: ExecqKey, value: u32) -> bool;
}

impl RootsMap for HashMap<MapData, AyaKey, u32> {
    fn held(&self) -> Vec<ExecqKey> {
        self.keys().filter_map(|k| k.ok()).map(|k| k.0).collect()
    }
    fn remove(&mut self, key: &ExecqKey) -> bool {
        HashMap::remove(self, &AyaKey(*key)).is_ok()
    }
    fn insert(&mut self, key: ExecqKey, value: u32) -> bool {
        HashMap::insert(self, AyaKey(key), value, 0).is_ok()
    }
}

/// Lot 311 (the review of #538, G2): publish `roots`, ranked (the
/// non-FUSE roots first: [`guarded_roots`]), into a map of bounded size.
/// The keys `roots` no longer holds leave first; then each root in rank
/// order is inserted, and when the map is full the lowest-ranked root it
/// holds gives way — so the roots a user can multiply (FUSE mounts,
/// `mount_max` is 1000) never keep out a system root mounted after them
/// (a `/run/user/<uid>` at another user's login, a `/home` automounted).
pub fn publish_ranked(map: &mut impl RootsMap, roots: &[(ExecqKey, u32)]) -> RootsRefused {
    let mut held: std::collections::HashSet<ExecqKey> = std::collections::HashSet::new();
    for k in map.held() {
        if roots.iter().any(|(r, _)| *r == k) {
            held.insert(k);
        } else {
            map.remove(&k);
        }
    }
    // the roots at `floor` and past it are not in the map (given way, or
    // never in): the lowest-ranked one held is found below it
    let mut floor = roots.len();
    for (i, (k, v)) in roots.iter().enumerate() {
        let mut placed = map.insert(*k, *v);
        while !placed && floor > i + 1 {
            floor -= 1;
            let low = roots[floor].0;
            if held.contains(&low) && map.remove(&low) {
                held.remove(&low);
                placed = map.insert(*k, *v);
            }
        }
        if placed {
            held.insert(*k);
        }
    }
    let mut refused = RootsRefused::default();
    for (k, _) in roots.iter().filter(|(k, _)| !held.contains(k)) {
        if k.ino == FUSE_BY_DEVICE {
            refused.fuse += 1;
        } else {
            refused.other += 1;
        }
    }
    refused
}

/// Mount points whose filesystem the guard watches as a whole: a separate
/// `/home`, `/tmp`, `/var/tmp`, `/root`, `/dev/shm`, `/run/user/<uid>`, or
/// a mount below them.
pub fn guarded_mount_point(mp: &str) -> bool {
    const GUARDED: &[&str] = &[
        "/tmp",
        "/var/tmp",
        "/home",
        "/root",
        "/dev/shm",
        "/run/user",
    ];
    GUARDED
        .iter()
        .any(|g| mp == *g || mp.strip_prefix(g).is_some_and(|r| r.starts_with('/')))
}

/// Lab PR 226: which guarded point `mp` is at ([`root_kind`]), so a file
/// on that filesystem gets the point's class (a tmpfs `/tmp` is `tmp`, a
/// separate `/home` is `home`).
pub fn root_kind_of(mp: &str) -> u32 {
    let under = |g: &str| mp == g || mp.strip_prefix(g).is_some_and(|r| r.starts_with('/'));
    let mut k = root_kind::GUARDED;
    if under("/tmp") {
        k |= root_kind::TMP;
    } else if under("/var/tmp") {
        k |= root_kind::VAR_TMP;
    } else if under("/dev/shm") {
        k |= root_kind::DEV_SHM;
    } else if under("/home") || under("/root") {
        k |= root_kind::HOME;
    }
    k
}

/// The roots of the guarded mounts in a mount table (read as bytes, lot
/// 311: [`nn_linux::mountinfo`]), with the point's kind ([`root_kind_of`]):
///
/// - a mount of a filesystem's own root (field 4 is `/`) at a guarded
///   mount point, keyed by its root ([`nn_linux::mountinfo::MountEntry::
///   root_key`]: read without following a link, and only while the mount
///   point shows the mount's device — a user who swapped the point for a
///   link to another filesystem's root does not get that root published);
/// - lot 311 (bug hunt 1.4, BUG-108, the userland half): a mount of a
///   directory of a filesystem none of whose mounts is its root — a btrfs
///   subvolume (`/home` on Fedora and openSUSE: `subvol=/home`, field 4
///   `/home`); a bind mount of a directory of a filesystem mounted at its
///   root elsewhere (`/srv/data` bound at `/home`) is not a root the
///   kernel's walk ends on, and is left out as before;
/// - lot 311 (N8, and the review of #538, F1): every FUSE mount, wherever
///   it is mounted — classed by its type, never by its root's inode, which
///   its daemon (the user) names and changes at will: keyed by its device
///   alone, `(dev, FUSE_BY_DEVICE)`. The kernel's half (lot 318) tells a
///   FUSE file by its superblock's magic and looks its device up so.
///
/// A mount point that is not UTF-8 is classed by its text with the bytes
/// replaced. The list is ranked, the FUSE roots last (the review of #538,
/// G2).
pub fn guarded_roots(table: &nn_linux::mountinfo::MountTable) -> Vec<(ExecqKey, u32)> {
    let mut out: Vec<(ExecqKey, u32)> = Vec::new();
    for m in &table.entries {
        let mp = m.mount_point.to_string_lossy();
        let key = if nn_linux::mountinfo::is_fuse(&m.fstype) {
            ExecqKey {
                dev: m.kernel_dev(),
                ino: FUSE_BY_DEVICE,
            }
        } else {
            let own_root = m.root == std::path::Path::new("/");
            // lot 318 (BUG108): a directory of a filesystem mounted at its
            // root elsewhere, bound at a guarded point or a home, is a
            // root too — the kernel finds it among the ancestors of the
            // files under it, whichever path names them; bound deeper in
            // a user's tree (`/usr` into `~/jail/usr`) it is not
            if !own_root
                && table
                    .entries
                    .iter()
                    .any(|o| o.same_dev(m) && o.root == std::path::Path::new("/"))
                && !bind_home_point(&mp)
            {
                continue;
            }
            if !guarded_mount_point(&mp) {
                continue;
            }
            let Some((dev, ino)) = m.root_key() else {
                continue;
            };
            ExecqKey { dev, ino }
        };
        if !out.iter().any(|(k, _)| *k == key) {
            out.push((key, root_kind_of(&mp)));
        }
    }
    // the review of #538 (G2): ranked — the roots a user cannot multiply
    // first, the FUSE ones (a user mounts up to `mount_max`) after them, in
    // the table's order within each: the kernel's map keeps the head
    // ([`publish_ranked`])
    out.sort_by_key(|(k, _)| k.ino == FUSE_BY_DEVICE);
    out
}

/// What the controllers publish in `EXECQ_ROOTS`: the guarded mounts'
/// roots ([`guarded_roots`]), and (lot 318, the review of #545, F2) the
/// guarded points themselves by their identity ([`point_roots`]), wherever
/// they live — `/var/tmp` in openSUSE's `@/var` subvolume, `/home` (a link
/// to `var/home`) and `/var/tmp` in an ostree deployment's `/var` bind: no
/// mount is at those points, and the walk of a file under them ends on a
/// root no guarded mount names. A point that is a mount's root keeps the
/// mount's entry; the points rank with the mounts, before the FUSE roots.
pub fn published_roots(table: &nn_linux::mountinfo::MountTable) -> Vec<(ExecqKey, u32)> {
    let mut out = guarded_roots(table);
    let first_fuse = out
        .iter()
        .position(|(k, _)| k.ino == FUSE_BY_DEVICE)
        .unwrap_or(out.len());
    let mut points: Vec<(ExecqKey, u32)> =
        point_roots(GUARDED_POINTS.iter().map(|p| (std::path::Path::new(p), *p)))
            .into_iter()
            .filter(|(key, _)| !out.iter().any(|(k, _)| k == key))
            .collect();
    let tail = out.split_off(first_fuse);
    out.append(&mut points);
    out.extend(tail);
    out
}

/// Lot 318 (the review of #545, F2): the guarded points whose own identity
/// is published — the path classes of the kernel's names.
pub const GUARDED_POINTS: [&str; 5] = ["/tmp", "/var/tmp", "/home", "/root", "/dev/shm"];

/// The keys of guarded points, `(path to stat, the point it is)`: `stat()`
/// follows a link (ostree's `/home` → `var/home`) and gives a btrfs
/// subvolume's own device, as the kernel's walk reads each level. The kind
/// is the point's path class without [`root_kind::GUARDED`]: a point is not
/// a guarded mount (`guarded_mount` stays the mounts' class); a point
/// without a path class, or that does not exist, is left out.
pub fn point_roots<'a>(
    points: impl Iterator<Item = (&'a std::path::Path, &'a str)>,
) -> Vec<(ExecqKey, u32)> {
    let mut out = Vec::new();
    for (path, point) in points {
        let kind = root_kind_of(point) & !root_kind::GUARDED;
        if kind == 0 {
            continue;
        }
        let Ok(st) = std::fs::metadata(path) else {
            continue;
        };
        if !st.is_dir() {
            continue;
        }
        let key = ExecqKey {
            dev: crate::anti_tamper::filesystem::stat_dev_to_kernel_dev(st.dev()),
            ino: st.ino(),
        };
        if !out.iter().any(|(k, _)| *k == key) {
            out.push((key, kind));
        }
    }
    out
}

/// Tests: the mount line of this host's `/tmp` with its own device (lot 311:
/// a root is published only while its mount point shows the line's
/// device), mount id `id`.
#[cfg(test)]
pub(crate) fn tmp_mount_line(id: u32) -> String {
    let dev = std::fs::metadata("/tmp").unwrap().dev();
    format!(
        "{id} 1 {}:{} / /tmp rw - tmpfs tmpfs rw\n",
        libc::major(dev),
        libc::minor(dev)
    )
}

/// Lot 311 (the review of #538, F1): the inode of a FUSE filesystem's key
/// in `EXECQ_ROOTS` — no inode is 0: the key names the device alone.
pub const FUSE_BY_DEVICE: u64 = 0;

/// Lot 318 (BUG108): where a bind of a directory is a guarded root — a
/// guarded point itself (`/home`, `/root`, `/tmp`, `/var/tmp`, `/dev/shm`)
/// or one home below `/home` or `/run/user` (`/home/<user>`).
pub fn bind_home_point(mp: &str) -> bool {
    const POINTS: &[&str] = &["/tmp", "/var/tmp", "/home", "/root", "/dev/shm"];
    if POINTS.contains(&mp) {
        return true;
    }
    ["/home/", "/run/user/"].iter().any(|p| {
        mp.strip_prefix(p)
            .is_some_and(|rest| !rest.is_empty() && !rest.contains('/'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guarded_mount_points() {
        for yes in [
            "/home",
            "/tmp",
            "/var/tmp",
            "/root",
            "/dev/shm",
            "/run/user/1000",
            "/home/u/data",
        ] {
            assert!(guarded_mount_point(yes), "{yes}");
        }
        for no in ["/", "/usr", "/homes", "/tmpfoo", "/run", "/var", "/dev"] {
            assert!(!guarded_mount_point(no), "{no}");
        }
    }

    #[test]
    fn only_filesystem_roots_at_guarded_points_are_kept() {
        // an unguarded mount is ignored, and a bind mount of a directory
        // deeper than a home (lot 318); /tmp itself exists on every host
        let text = format!(
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n\
             {}\
             3 1 8:1 /usr /home/u/jail/usr rw - ext4 /dev/sda1 rw\n\
             4 1 0:6 / /usr rw - tmpfs tmpfs rw\n",
            tmp_mount_line(2)
        );
        let roots = guarded_roots(&nn_linux::mountinfo::parse(text.as_bytes()));
        assert_eq!(roots.len(), 1, "{roots:?}");
        let m = std::fs::metadata("/tmp").unwrap();
        assert_eq!(roots[0].0.ino, m.ino());
        // lab PR 226: the kind of point it is mounted at
        assert_eq!(roots[0].1, root_kind::GUARDED | root_kind::TMP);
    }

    /// The `major:minor` of `path`'s device, as a mount table writes it.
    fn dev_field(path: &str) -> String {
        let d = std::fs::metadata(path).unwrap().dev();
        format!("{}:{}", libc::major(d), libc::minor(d))
    }

    fn key_of(path: &std::path::Path) -> ExecqKey {
        let st = std::fs::metadata(path).unwrap();
        ExecqKey {
            dev: crate::anti_tamper::filesystem::stat_dev_to_kernel_dev(st.dev()),
            ino: st.ino(),
        }
    }

    /// Lot 318 (external bug hunt BUG108): a directory of a filesystem
    /// mounted at its root elsewhere, bound at a guarded point, is a
    /// guarded root — the kernel finds it among the ancestors of the files
    /// under it, whichever path names them (lot 311's rule left it out: the
    /// walk ended on the filesystem's root, which no guarded mount names).
    /// Bound deeper in a user's tree it is not (`/usr` in a chroot).
    #[test]
    fn a_directory_bound_at_a_guarded_point_is_a_guarded_root() {
        // /var/tmp exists on every host: the bind's mount point, keyed by
        // its own device as `root_key` checks
        let dev = dev_field("/var/tmp");
        let text = format!(
            "1 0 {dev} / / rw - ext4 /dev/sda1 rw\n\
             2 1 {dev} /srv/data /var/tmp rw - ext4 /dev/sda1 rw\n"
        );
        let roots = guarded_roots(&nn_linux::mountinfo::parse(text.as_bytes()));
        assert_eq!(
            roots,
            vec![(
                key_of(std::path::Path::new("/var/tmp")),
                root_kind::GUARDED | root_kind::VAR_TMP
            )],
            "the bind at /var/tmp"
        );
        for yes in [
            "/home",
            "/tmp",
            "/var/tmp",
            "/root",
            "/dev/shm",
            "/home/u",
            "/run/user/1000",
        ] {
            assert!(bind_home_point(yes), "{yes}");
        }
        for no in [
            "/home/u/jail/usr",
            "/home/",
            "/run/user",
            "/run/user/1000/doc",
            "/tmp/x",
            "/usr",
        ] {
            assert!(!bind_home_point(no), "{no}");
        }
    }

    /// Lot 318 (BUG108): a mount of a directory of a filesystem none of
    /// whose mounts is its root (a btrfs subvolume) is a guarded root at
    /// any depth below a guarded point; a directory of a filesystem
    /// mounted at its root elsewhere, bound at the same depth, is not.
    #[test]
    fn a_subvolume_below_a_guarded_point_is_a_guarded_root_and_a_bind_there_is_not() {
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        let mp = dir.path().to_str().unwrap().to_string();
        assert!(guarded_mount_point(&mp) && !bind_home_point(&mp), "{mp}");
        let subvol = format!(
            "1 0 0:35 /root / rw - btrfs /dev/vda3 rw,subvol=/root\n\
             2 1 0:35 /sv {mp} rw - btrfs /dev/vda3 rw,subvol=/sv\n"
        );
        let roots = guarded_roots(&nn_linux::mountinfo::parse(subvol.as_bytes()));
        assert_eq!(
            roots,
            vec![(key_of(dir.path()), root_kind::GUARDED | root_kind::TMP)]
        );
        let dev = dev_field(&mp);
        let bind = format!(
            "1 0 {dev} / / rw - ext4 /dev/sda1 rw\n\
             2 1 {dev} /usr {mp} rw - ext4 /dev/sda1 rw\n"
        );
        assert_eq!(
            guarded_roots(&nn_linux::mountinfo::parse(bind.as_bytes())),
            vec![],
            "a bind deep below /tmp"
        );
    }

    /// Lot 318 (the review of #545, F2): the guarded points are published by
    /// their own identity, whatever is mounted where. openSUSE's default:
    /// `/` a snapshot subvolume, `/var` the `@/var` subvolume — `/var/tmp`
    /// a plain directory of it, no mount at it. ostree (Silverblue, CoreOS):
    /// `/var` a bind of the deployment's `var`, `/home` a link to
    /// `var/home`. Each point's key is its directory's (the link followed),
    /// its kind the point's path class without `GUARDED`: a point is not a
    /// guarded mount. A point that does not exist is left out.
    #[test]
    fn the_guarded_points_are_published_by_identity_on_opensuse_and_ostree() {
        let root = tempfile::tempdir().unwrap();
        let r = root.path();
        // openSUSE: @/var holds tmp
        std::fs::create_dir_all(r.join("var/tmp")).unwrap();
        // ostree: home -> var/home
        std::fs::create_dir_all(r.join("var/home")).unwrap();
        std::os::unix::fs::symlink("var/home", r.join("home")).unwrap();
        let points = [
            (r.join("var/tmp"), "/var/tmp"),
            (r.join("home"), "/home"),
            (r.join("absent"), "/root"),
            (r.join("var"), "/run/user/1000"),
        ];
        let got = point_roots(points.iter().map(|(p, n)| (p.as_path(), *n)));
        assert_eq!(
            got,
            vec![
                (key_of(&r.join("var/tmp")), root_kind::VAR_TMP),
                (key_of(&r.join("var/home")), root_kind::HOME),
            ],
            "the points, the link followed, no GUARDED bit"
        );
        // the host's own points are among what the controllers publish,
        // ranked before the FUSE roots; a point that is a mount's root
        // keeps the mount's entry (its GUARDED bit)
        let text = format!(
            "{}57 1 0:44 / /home/u/mnt rw,nosuid,nodev - fuse.x x rw,user_id=1000\n",
            tmp_mount_line(30)
        );
        let published = published_roots(&nn_linux::mountinfo::parse(text.as_bytes()));
        let vt = key_of(std::path::Path::new("/var/tmp"));
        let at = |k: &ExecqKey| published.iter().position(|(x, _)| x == k);
        let fuse = ExecqKey {
            dev: 44,
            ino: FUSE_BY_DEVICE,
        };
        assert!(at(&vt).unwrap() < at(&fuse).unwrap(), "{published:?}");
        assert_eq!(
            published
                .iter()
                .find(|(k, _)| *k == key_of(std::path::Path::new("/tmp"))),
            Some(&(
                key_of(std::path::Path::new("/tmp")),
                root_kind::GUARDED | root_kind::TMP
            )),
            "/tmp's mount entry kept: {published:?}"
        );
    }

    /// Lab PR 226: a file on a filesystem mounted at a guarded point gets
    /// that point's class.
    #[test]
    fn root_kinds() {
        assert_eq!(root_kind_of("/tmp"), root_kind::GUARDED | root_kind::TMP);
        assert_eq!(
            root_kind_of("/var/tmp"),
            root_kind::GUARDED | root_kind::VAR_TMP
        );
        assert_eq!(
            root_kind_of("/dev/shm"),
            root_kind::GUARDED | root_kind::DEV_SHM
        );
        assert_eq!(root_kind_of("/home"), root_kind::GUARDED | root_kind::HOME);
        assert_eq!(
            root_kind_of("/home/u/data"),
            root_kind::GUARDED | root_kind::HOME
        );
        assert_eq!(root_kind_of("/root"), root_kind::GUARDED | root_kind::HOME);
        assert_eq!(root_kind_of("/run/user/1000"), root_kind::GUARDED);
        assert_eq!(root_kind_of("/tmpx"), root_kind::GUARDED);
    }

    /// Lot 311 (bug hunt 1.4, BUG-108, the userland half; the kernel half —
    /// the walk ends on the btrfs top-level root, which no mount names — is
    /// lot 9's): Fedora Workstation's layout, `/` and `/home` subvolumes of
    /// one btrfs (field 4 the subvolume, not `/`). The mount at `/home` is
    /// a guarded mount whose root is published.
    #[test]
    fn a_btrfs_home_subvolume_is_a_guarded_root() {
        let text = "29 1 0:35 /root / rw,relatime shared:1 - btrfs /dev/vda3 rw,subvol=/root\n\
             41 29 0:35 /home /home rw,relatime shared:2 - btrfs /dev/vda3 rw,subvol=/home\n";
        let roots = guarded_roots(&nn_linux::mountinfo::parse(text.as_bytes()));
        let home = std::fs::metadata("/home").unwrap();
        assert!(
            roots
                .iter()
                .any(|(k, v)| k.ino == home.ino() && v & root_kind::HOME != 0),
            "the /home subvolume is not a guarded root: {roots:?}"
        );
    }

    /// Lot 311 (N8, and the review of #538, F1 and F2): a FUSE mount — a
    /// user's, root cannot `stat` it (no `allow_other`), and its daemon
    /// names its root's inode at will — is classed by its type and keyed by
    /// its device alone, wherever it is mounted; one whose source is `-`
    /// (`fsname=-`) or empty too. A mount point that is not UTF-8 is read
    /// by its bytes; another mount whose point does not show its device is
    /// left out.
    #[test]
    fn a_fuse_mount_is_keyed_by_its_device_whatever_its_root_or_source() {
        let text = b"57 1 0:44 / /home/u/nn-lot311-absent/\xffmnt rw,nosuid,nodev - fuse.sshfs u@h:/ rw,user_id=1000\n\
             58 1 0:45 / /tmp/nn-lot311-absent rw - ext4 /dev/vdb rw\n\
             59 1 0:46 / /run/lock/u rw,nosuid,nodev - fuse.x - rw,user_id=1000\n\
             60 1 0:47 / /tmp/nn-lot311-y rw,nosuid,nodev - fuse  rw,user_id=1000\n";
        let table = nn_linux::mountinfo::parse(text);
        assert!(table.malformed.is_empty(), "{:?}", table.malformed);
        let roots = guarded_roots(&table);
        assert_eq!(
            roots,
            vec![
                (
                    ExecqKey {
                        dev: 44,
                        ino: FUSE_BY_DEVICE
                    },
                    root_kind::GUARDED | root_kind::HOME
                ),
                (
                    ExecqKey {
                        dev: 46,
                        ino: FUSE_BY_DEVICE
                    },
                    root_kind::GUARDED
                ),
                (
                    ExecqKey {
                        dev: 47,
                        ino: FUSE_BY_DEVICE
                    },
                    root_kind::GUARDED | root_kind::TMP
                ),
            ],
            "every FUSE mount by its device, the unreadable ext4 root left out"
        );
    }

    /// Lot 311 (BUG-108, the lab's check): the mount at
    /// `NN_LOT311_GUARDED_MP` (a btrfs subvolume or a FUSE mount the lab
    /// made at a guarded point) is among the guarded roots read from this
    /// process's own mount table. A no-op without the variable.
    #[test]
    #[ignore = "lab: a mount at a guarded point named by NN_LOT311_GUARDED_MP"]
    fn a_real_guarded_mount_is_a_guarded_root() {
        let Some(mp) = std::env::var_os("NN_LOT311_GUARDED_MP") else {
            return;
        };
        let table =
            nn_linux::mountinfo::read(std::path::Path::new("/proc/self/mountinfo")).unwrap();
        let entry = table
            .entries
            .iter()
            .find(|m| m.mount_point.as_os_str() == mp)
            .unwrap_or_else(|| panic!("{mp:?} is not a mount point"));
        let roots = guarded_roots(&table);
        let key = if nn_linux::mountinfo::is_fuse(&entry.fstype) {
            ExecqKey {
                dev: entry.kernel_dev(),
                ino: FUSE_BY_DEVICE,
            }
        } else {
            let (dev, ino) = entry.root_key().expect("the mount's root key");
            ExecqKey { dev, ino }
        };
        println!(
            "mount {mp:?}: root {:?} fstype {:?} key {key:?}; guarded roots {roots:?}",
            entry.root, entry.fstype
        );
        assert!(
            roots.iter().any(|(k, _)| *k == key),
            "{mp:?} ({:?} of {:?}) is not a guarded root",
            entry.root,
            entry.fstype
        );
    }

    /// A bounded map of roots, as the kernel's (`EXECQ_ROOTS`).
    struct Bounded {
        cap: usize,
        held: Vec<(ExecqKey, u32)>,
    }

    impl RootsMap for Bounded {
        fn held(&self) -> Vec<ExecqKey> {
            self.held.iter().map(|(k, _)| *k).collect()
        }
        fn remove(&mut self, key: &ExecqKey) -> bool {
            let before = self.held.len();
            self.held.retain(|(k, _)| k != key);
            self.held.len() < before
        }
        fn insert(&mut self, key: ExecqKey, value: u32) -> bool {
            if let Some(e) = self.held.iter_mut().find(|(k, _)| *k == key) {
                e.1 = value;
                return true;
            }
            if self.held.len() >= self.cap {
                return false;
            }
            self.held.push((key, value));
            true
        }
    }

    /// Lot 311 (the review of #538, G2): seventy FUSE mounts of a user's
    /// fill the kernel's map (64 entries); a system root mounted after them
    /// — a directory of `/tmp`'s file system here, standing for another
    /// user's `/run/user/<uid>` at login — still gets in: the roots are
    /// ranked (the FUSE ones last), and a FUSE root the map holds gives
    /// way. Before: the map kept the table's first 64, the system root
    /// refused.
    #[test]
    fn seventy_fuse_mounts_never_keep_a_later_system_root_out_of_the_map() {
        let d = tempfile::tempdir_in("/tmp").unwrap();
        let sys = d.path().join("sys");
        std::fs::create_dir(&sys).unwrap();
        let m = std::fs::metadata(&sys).unwrap();
        let fuse = |n: u32| {
            (0..n)
                .map(|i| {
                    format!(
                        "{} 1 0:{} / /home/u/m{i} rw,nosuid,nodev - fuse.x - rw,user_id=1000\n",
                        100 + i,
                        200 + i
                    )
                })
                .collect::<String>()
        };
        let mut map = Bounded {
            cap: 64,
            held: Vec::new(),
        };
        let first = format!("{}{}", tmp_mount_line(30), fuse(70));
        let roots = guarded_roots(&nn_linux::mountinfo::parse(first.as_bytes()));
        assert_eq!(
            publish_ranked(&mut map, &roots),
            RootsRefused { other: 0, fuse: 7 }
        );
        assert_eq!(map.held.len(), 64);
        let later = format!(
            "{first}400 1 {}:{} / {} rw - tmpfs sys rw\n",
            libc::major(m.dev()),
            libc::minor(m.dev()),
            sys.display()
        );
        let roots = guarded_roots(&nn_linux::mountinfo::parse(later.as_bytes()));
        let key = ExecqKey {
            dev: roots[1].0.dev,
            ino: m.ino(),
        };
        assert_eq!(roots[1].0, key, "ranked before every FUSE root: {roots:?}");
        assert_eq!(
            publish_ranked(&mut map, &roots),
            RootsRefused { other: 0, fuse: 8 }
        );
        assert_eq!(map.held.len(), 64);
        assert!(
            map.held.iter().any(|(k, _)| *k == key),
            "the later system root is in"
        );
        let tmp = std::fs::metadata("/tmp").unwrap();
        assert!(map
            .held
            .iter()
            .any(|(k, _)| k.ino == tmp.ino() && k.ino != FUSE_BY_DEVICE));
        // a map with room for the system roots only: every FUSE root left out
        map.cap = 2;
        map.held.clear();
        assert_eq!(
            publish_ranked(&mut map, &roots),
            RootsRefused { other: 0, fuse: 70 }
        );
        // and none at all: the system roots are the loss
        map.cap = 0;
        map.held.clear();
        assert_eq!(
            publish_ranked(&mut map, &roots),
            RootsRefused { other: 2, fuse: 70 }
        );
    }
}
