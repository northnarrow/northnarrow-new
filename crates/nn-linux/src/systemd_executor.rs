//! Lot 310 (external bug hunt, edition 1.4: BUG-103): the identities of
//! systemd's packaged executor, for R004.
//!
//! systemd ≥ 254 launches every unit by `fexecve()` of `systemd-executor`,
//! which each manager (PID 1, every `systemd --user`) opened at its start
//! and keeps until its re-exec. An upgrade replaces the file on disk: until
//! then a manager launches units from the old, unlinked image — an exec of
//! an unlinked file through a descriptor, R004's fileless shape. R004 tells
//! it apart by the file's identity, `(st_dev, st_ino)`, never by its name
//! (BUG-103: a file named `systemd-executor` under `/opt/app/` was exempt):
//!
//! - [`seed`] at the agent's start and [`refresh`] every 10 s: the files at
//!   the install paths, and the executor each systemd manager holds open
//!   (`/proc/<pid>/fd/<n>`, which `stat(2)` follows to the open file,
//!   unlinked or not) — an agent started between an upgrade and the
//!   managers' re-exec knows the old image too. Lot 310 (the review of
//!   #539, finding 3): each read **replaces** the set — an identity no
//!   install path links and no manager holds any more is gone, since its
//!   inode is free and its number may be a user's next file's. While held,
//!   an inode cannot be freed. Residual: a release is seen at the next read
//!   (10 s); the LSM program reports `(dev, ino)` only, no generation.
//!
//! The re-check of #539 (N1): a user could make a "manager" in a user
//! namespace of its own (`unshare -Urm`: `/bin/sleep` bound over
//! `/usr/lib/systemd/systemd`, its own file over the executor's path, held,
//! then removed) whose links read as systemd's: its file joined the set,
//! and R004 exempted its exec. The identities come from three sources only
//! ([`live_under`]), each a file root owns and no one else may write:
//!
//! - the packaged executor at its install path, in the agent's own mount
//!   namespace, listed by the package database where there is one
//!   (dpkg's lists, `rpm -qf`);
//! - the copies the host's PID 1 holds (`/proc/1/fd`);
//! - the copies a `systemd --user` manager holds, when its image is the
//!   packaged manager's (the binary at its install path, or PID 1's image)
//!   and it runs in PID 1's mount namespace — never a process told by the
//!   text of its links.
//!
//! The manager's identities ([`ExecutorImages::replace_managers`]) go to
//! R004 too: a user manager forks the executor's launches, and is told by
//! its image.
//!
//! The re-check 4 of #539: the kernel tells the executor's exec too —
//! [`carriers`] (the packaged file's identities and PID 1's copies, never a
//! user manager's) go to the eBPF map `EXECUTOR_IDS` at each read
//! ([`install_kernel_map`]): an exec of one leaves the process's fork
//! record to its next exec, the unit's own program
//! (`northnarrow_common::fork_record`).

use std::os::unix::fs::MetadataExt;
use std::path::Path;

use nn_core::decision::rules::ExecutorImages;

/// Where the distributions install the executor.
pub const EXECUTOR_PATHS: &[&str] = &[
    "/usr/lib/systemd/systemd-executor",
    "/lib/systemd/systemd-executor",
];

/// Where they install the manager (PID 1, `systemd --user`).
const MANAGER_PATHS: &[&str] = &["/usr/lib/systemd/systemd", "/lib/systemd/systemd"];

/// The file `path` names (followed), as the exec sensor reports a file:
/// its device in the kernel's form (`MKDEV`, the superblock's `s_dev`, what
/// the LSM program reads), not `stat(2)`'s encoding — the lab's first round
/// on Ubuntu 26.04 recorded `64769` (stat's 253:1) where the exec carried
/// `265289729`, and the unlinked executor's launch was killed.
fn file_id(path: &Path) -> Option<(u64, u64)> {
    std::fs::metadata(path).ok().map(|m| {
        (
            crate::anti_tamper::filesystem::stat_dev_to_kernel_dev(m.dev()),
            m.ino(),
        )
    })
}

/// [`file_id`] of a file `owner` owns that no one else may write (`0` on
/// the host; a test's own uid in its tree).
fn trusted_file_id(path: &Path, owner: u32) -> Option<(u64, u64)> {
    let m = std::fs::metadata(path).ok()?;
    (m.is_file() && m.uid() == owner && m.mode() & 0o022 == 0).then(|| {
        (
            crate::anti_tamper::filesystem::stat_dev_to_kernel_dev(m.dev()),
            m.ino(),
        )
    })
}

/// A link's target as a path of the host under `root` (`/`, or a test's
/// tree), without the ` (deleted)` the kernel adds to an unlinked file:
/// `/usr/lib/systemd/systemd-executor`.
fn link_target(path: &Path, root: &Path) -> Option<String> {
    let t = std::fs::read_link(path).ok()?;
    let t = t.to_string_lossy();
    let t = t.strip_suffix(" (deleted)").unwrap_or(&t);
    let rel = Path::new(t).strip_prefix(root).ok()?;
    Some(format!("/{}", rel.to_string_lossy()))
}

/// The package database's answer for `path` (`None`: no database to ask).
type Owned<'a> = &'a dyn Fn(&Path) -> Option<bool>;

/// The packaged files at `paths` under `root`: root's (`owner`'s), written
/// by no one else, and not disowned by the package database.
fn packaged(paths: &[&str], root: &Path, owner: u32, owned: Owned) -> Vec<(u64, u64)> {
    paths
        .iter()
        .filter(|p| owned(Path::new(p)) != Some(false))
        .filter_map(|p| trusted_file_id(&root.join(p.trim_start_matches('/')), owner))
        .collect()
}

/// What [`live_under`] reads: the executor's identities, and the manager's.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Live {
    pub executors: Vec<(u64, u64)>,
    pub managers: Vec<(u64, u64)>,
    /// The executors the host's PID 1 holds (also in `executors`): exempt
    /// by identity alone (re-check 3, decision 1).
    pub pid1_held: Vec<(u64, u64)>,
    /// The packaged executor's files at the install paths (also in
    /// `executors`).
    pub packaged: Vec<(u64, u64)>,
}

/// The re-check 4 of #539: the identities whose exec leaves its fork
/// record to the next exec, in the kernel (`EXECUTOR_IDS`) — the packaged
/// file's and PID 1's copies; a user manager's copies are not among them
/// (its units are judged: decision 4). Sorted, deduplicated, without
/// `(0, 0)`, at most `EXECUTOR_IDS_MAX`.
pub fn carriers(live: &Live) -> Vec<(u64, u64)> {
    let mut ids: Vec<(u64, u64)> = live
        .packaged
        .iter()
        .chain(&live.pid1_held)
        .copied()
        .filter(|id| *id != (0, 0))
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids.truncate(common::fork_record::EXECUTOR_IDS_MAX as usize);
    ids
}

/// The eBPF map `EXECUTOR_IDS`, once the fork record is attached.
type KernelIds =
    aya::maps::HashMap<aya::maps::MapData, crate::anti_tamper::filesystem::AyaInodeKey, u32>;

/// The kernel's copy of [`carriers`], and the last carriers read (written
/// to the map when it is installed after the start's read).
struct Kernel {
    map: Option<KernelIds>,
    ids: Vec<(u64, u64)>,
}

static KERNEL: parking_lot::Mutex<Kernel> = parking_lot::Mutex::new(Kernel {
    map: None,
    ids: Vec::new(),
});

/// The fork record's executor map (`EXECUTOR_IDS`), given by the sensors
/// once the record is attached: the carriers read so far go in now, each
/// later read's at that read.
pub fn install_kernel_map(map: KernelIds) {
    let mut guard = KERNEL.lock();
    let k = &mut *guard;
    k.map = Some(map);
    publish(&mut k.map, &k.ids);
}

/// `ids` in place of the kernel map's: the ones gone removed first (an
/// inode freed may be a user's next file's), then the new ones.
fn publish(map: &mut Option<KernelIds>, ids: &[(u64, u64)]) {
    let Some(map) = map.as_mut() else {
        return;
    };
    let old: Vec<_> = map.keys().filter_map(Result::ok).collect();
    for k in old {
        if !ids.contains(&(k.0.dev, k.0.ino)) {
            let _ = map.remove(&k);
        }
    }
    for (dev, ino) in ids {
        let key = crate::anti_tamper::filesystem::AyaInodeKey(common::wire::InodeKey {
            dev: *dev,
            ino: *ino,
        });
        if let Err(e) = map.insert(key, 1, 0) {
            tracing::warn!(error = %e, dev, ino, "EXECUTOR_IDS: an executor identity not written to the kernel");
        }
    }
}

/// [`carriers`] of `live` to the kernel (kept for a map installed later).
fn carry(live: &Live) {
    let mut guard = KERNEL.lock();
    let k = &mut *guard;
    k.ids = carriers(live);
    publish(&mut k.map, &k.ids);
}

/// The executor's identities now, from the three sources (the module's
/// head), and the manager's: under `root` (`/` on the host, a test's tree)
/// and `proc_root` (`/proc`); `owner` the files' owner (0), `owned` the
/// package database.
pub fn live_under(root: &Path, proc_root: &Path, owner: u32, owned: Owned) -> Live {
    let packaged_executors = packaged(EXECUTOR_PATHS, root, owner, owned);
    let mut executors = packaged_executors.clone();
    let mut managers = packaged(MANAGER_PATHS, root, owner, owned);
    let init = proc_root.join("1");
    // PID 1's image: the manager every user manager runs until a re-exec
    if let Some(id) = trusted_file_id(&init.join("exe"), owner) {
        managers.push(id);
    }
    let pid1_held = held_executors(&init, root, owner);
    executors.extend(pid1_held.iter().copied());
    executors.extend(held_by_user_managers(root, proc_root, owner, &managers));
    Live {
        executors,
        managers,
        pid1_held,
        packaged: packaged_executors,
    }
}

/// The host's executor sources ([`live_under`] of `/` and `/proc`, root's
/// files, the package database of the host).
fn live() -> Live {
    let owners =
        nn_core::impact::trust::ProgramOwners::<crate::chain_host_linux::LinuxHost>::new("/");
    live_under(Path::new("/"), Path::new("/proc"), 0, &|p| owners.owned(p))
}

/// Replace `images` with the identities now ([`live_under`]); `true` when
/// the set changed.
pub fn refresh_under(
    images: &ExecutorImages,
    root: &Path,
    proc_root: &Path,
    owner: u32,
    owned: Owned,
) -> bool {
    apply(images, live_under(root, proc_root, owner, owned))
}

fn apply(images: &ExecutorImages, live: Live) -> bool {
    let executors = images.replace(live.executors);
    let managers = images.replace_managers(live.managers);
    let pid1 = images.replace_pid1_held(live.pid1_held);
    executors || managers || pid1
}

/// [`refresh_under`] the host's root and `/proc`, every 10 s; the
/// [`carriers`] to the kernel.
pub fn refresh(images: &ExecutorImages) -> bool {
    let live = live();
    carry(&live);
    apply(images, live)
}

/// At the start: [`refresh`]; how many identities the executor has now.
pub fn seed(images: &ExecutorImages) -> usize {
    refresh(images);
    images.len()
}

/// The executors process `pid_dir` holds open (its descriptors whose link
/// names an install path, ` (deleted)` or not), read through the
/// descriptor: files root owns that no one else may write.
fn held_executors(pid_dir: &Path, root: &Path, owner: u32) -> Vec<(u64, u64)> {
    let Ok(fds) = std::fs::read_dir(pid_dir.join("fd")) else {
        return Vec::new();
    };
    fds.flatten()
        .map(|fd| fd.path())
        .filter(|held| {
            link_target(held, root).is_some_and(|t| EXECUTOR_PATHS.contains(&t.as_str()))
        })
        .filter_map(|held| trusted_file_id(&held, owner))
        .collect()
}

/// The executors the `systemd --user` managers hold: a process other than
/// PID 1 whose image is one of `managers` (by identity, never by its
/// link's text) and that runs in PID 1's mount namespace.
fn held_by_user_managers(
    root: &Path,
    proc_root: &Path,
    owner: u32,
    managers: &[(u64, u64)],
) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let ns = |d: &Path| std::fs::read_link(d.join("ns/mnt")).ok();
    let Some(init_ns) = ns(&proc_root.join("1")) else {
        return out;
    };
    let Ok(dir) = std::fs::read_dir(proc_root) else {
        return out;
    };
    for entry in dir.flatten() {
        let name = entry.file_name();
        if name == "1"
            || !name
                .to_str()
                .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit()))
        {
            continue;
        }
        let pid_dir = entry.path();
        let is_manager = file_id(&pid_dir.join("exe")).is_some_and(|id| managers.contains(&id))
            && ns(&pid_dir).is_some_and(|n| n == init_ns);
        if is_manager {
            out.extend(held_executors(&pid_dir, root, owner));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    /// The test's uid: its tree's files are "root's" here.
    fn me() -> u32 {
        // SAFETY: getuid has no preconditions.
        unsafe { libc::getuid() }
    }

    /// No package database: every file is one a package may have installed.
    fn no_db(_: &Path) -> Option<bool> {
        None
    }

    fn file(path: &Path, body: &[u8]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// The install paths' files: an upgrade (the new file renamed over the
    /// old) replaces the identity — the old one, held by no manager, is gone
    /// (finding 3: its inode is free); a file named so elsewhere is never
    /// looked at; the device in the kernel's form. The re-check of #539
    /// (N1): a file the package database disowns, one another user owns,
    /// one others may write, is no executor.
    #[test]
    fn an_upgrade_replaces_the_identity_no_manager_holds() {
        let root = tempfile::tempdir().unwrap();
        let none = root.path().join("no-proc");
        let lib = root.path().join("usr/lib/systemd");
        let exe = lib.join("systemd-executor");
        file(&exe, b"v1");
        let images = ExecutorImages::default();
        assert!(refresh_under(&images, root.path(), &none, me(), &no_db));
        assert!(
            !refresh_under(&images, root.path(), &none, me(), &no_db),
            "unchanged"
        );
        let old = file_id(&exe).unwrap();
        assert!(images.contains(old));
        // dpkg: the new file renamed over the old one
        let new_file = lib.join("systemd-executor.dpkg-new");
        file(&new_file, b"v2");
        std::fs::rename(&new_file, &exe).unwrap();
        assert!(refresh_under(&images, root.path(), &none, me(), &no_db));
        assert!(!images.contains(old), "held by no one: gone");
        assert!(images.contains(file_id(&exe).unwrap()));
        assert_eq!(images.len(), 1);
        // the kernel's form of the device, as the exec sensor reports it
        let md = std::fs::metadata(&exe).unwrap();
        let kernel = crate::anti_tamper::filesystem::stat_dev_to_kernel_dev(md.dev());
        assert!(images.contains((kernel, md.ino())));
        if kernel != md.dev() {
            assert!(!images.contains((md.dev(), md.ino())), "stat's encoding");
        }
        // a file named so elsewhere is never looked at
        let opt = root.path().join("opt/app/systemd-executor");
        file(&opt, b"x");
        refresh_under(&images, root.path(), &none, me(), &no_db);
        assert!(!images.contains(file_id(&opt).unwrap()));
        // disowned by the package database, another owner, others may write
        let disowned = |_: &Path| Some(false);
        refresh_under(&images, root.path(), &none, me(), &disowned);
        assert!(images.is_empty(), "no package installed it");
        refresh_under(&images, root.path(), &none, me().wrapping_add(1), &no_db);
        assert!(images.is_empty(), "another owner");
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o757)).unwrap();
        refresh_under(&images, root.path(), &none, me(), &no_db);
        assert!(images.is_empty(), "writable by others");
    }

    /// A manager's held executor is read through its descriptor (whose `stat`
    /// is the open file's, unlinked or not: the kernel's magic link; here a
    /// link to a file of that name): PID 1's, kept while held, gone once
    /// released. The re-check of #539 (N1), the reviewer's probe: a user
    /// manager counts when its image is the packaged manager's and it runs
    /// in PID 1's mount namespace — a "manager" in a namespace of its own,
    /// or whose image is another file (`/bin/sleep` bound over
    /// `/usr/lib/systemd/systemd`: the path says systemd, the identity
    /// says sleep), adds nothing, whatever its descriptors' links say.
    #[test]
    fn a_held_executor_counts_from_pid_1_and_genuine_managers_only() {
        const INIT_NS: &str = "mnt:[4026531841]";
        let root = tempfile::tempdir().unwrap();
        let proc_root = tempfile::tempdir().unwrap();
        let r = root.path();
        let manager = r.join("usr/lib/systemd/systemd");
        file(&manager, b"systemd");
        let sleep = r.join("usr/bin/sleep");
        file(&sleep, b"sleep");
        let exe = r.join("usr/lib/systemd/systemd-executor");
        file(&exe, b"new");
        // the old image a manager holds, unlinked: the kernel shows its
        // link as the install path `(deleted)`
        let held = r.join("usr/lib/systemd/systemd-executor (deleted)");
        file(&held, b"old");
        let held_id = file_id(&held).unwrap();
        let make = |pid: &str, image: &Path, ns: &str, fd: Option<&Path>| {
            let d = proc_root.path().join(pid);
            std::fs::create_dir_all(d.join("fd")).unwrap();
            std::fs::create_dir_all(d.join("ns")).unwrap();
            symlink(image, d.join("exe")).unwrap();
            symlink(ns, d.join("ns/mnt")).unwrap();
            if let Some(f) = fd {
                symlink(f, d.join("fd/9")).unwrap();
            }
        };
        let live = |owner: u32| live_under(r, proc_root.path(), owner, &no_db);
        // PID 1 holds it
        make("1", &manager, INIT_NS, Some(&held));
        let l = live(me());
        assert!(l.executors.contains(&held_id) && l.executors.contains(&file_id(&exe).unwrap()));
        assert!(l.managers.contains(&file_id(&manager).unwrap()));
        assert_eq!(l.pid1_held, vec![held_id], "PID 1's own copy, apart");
        // the re-check 4 of #539: the kernel's carriers — the packaged
        // file's and PID 1's copy
        let mut both = vec![held_id, file_id(&exe).unwrap()];
        both.sort_unstable();
        assert_eq!(l.packaged, vec![file_id(&exe).unwrap()]);
        assert_eq!(carriers(&l), both);
        // released by PID 1: only a genuine user manager keeps it counted
        std::fs::remove_file(proc_root.path().join("1/fd/9")).unwrap();
        assert!(!live(me()).executors.contains(&held_id), "released: gone");
        // the reviewer's fake manager: sleep's image, a namespace of its own
        make("3001", &sleep, "mnt:[4026532999]", Some(&held));
        // the packaged image, but another namespace; sleep's image in PID 1's
        make("3002", &manager, "mnt:[4026532999]", Some(&held));
        make("3003", &sleep, INIT_NS, Some(&held));
        // not a manager at all
        make("4242", &r.join("usr/bin/bash"), INIT_NS, Some(&held));
        assert!(
            !live(me()).executors.contains(&held_id),
            "no genuine manager holds it"
        );
        // a genuine user manager
        make("2001", &manager, INIT_NS, Some(&held));
        let l = live(me());
        assert!(l.executors.contains(&held_id), "a user's manager");
        assert!(
            l.pid1_held.is_empty(),
            "not PID 1's: no exemption by identity alone"
        );
        assert_eq!(
            carriers(&l),
            vec![file_id(&exe).unwrap()],
            "a user manager's copy carries no fork record in the kernel"
        );
        // files a user owns (the production owner is root): nothing counts
        let l = live(me().wrapping_add(1));
        assert!(l.executors.is_empty() && l.managers.is_empty(), "{l:?}");
        // the refresh sets both
        let images = ExecutorImages::default();
        assert!(refresh_under(&images, r, proc_root.path(), me(), &no_db));
        assert!(images.contains(held_id));
        assert!(images.is_manager(file_id(&manager).unwrap()));
        assert!(!images.is_manager(file_id(&sleep).unwrap()));
    }
}
