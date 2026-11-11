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
//! The managers are told by their own executable (`/proc/<pid>/exe`), not by
//! their name.

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

/// The executor's identities now: its files at the install paths under
/// `root` (`/` on the host, a test's tree), and the ones systemd's managers
/// hold open under `proc_root` (`/proc`).
pub fn live_under(root: &Path, proc_root: &Path) -> Vec<(u64, u64)> {
    let mut ids: Vec<(u64, u64)> = EXECUTOR_PATHS
        .iter()
        .filter_map(|p| file_id(&root.join(p.trim_start_matches('/'))))
        .collect();
    ids.extend(held_by_managers(root, proc_root));
    ids
}

/// Replace `images` with the executor's identities now ([`live_under`]);
/// `true` when the set changed.
pub fn refresh_under(images: &ExecutorImages, root: &Path, proc_root: &Path) -> bool {
    images.replace(live_under(root, proc_root))
}

/// [`refresh_under`] the host's root and `/proc`, every 10 s.
pub fn refresh(images: &ExecutorImages) -> bool {
    refresh_under(images, Path::new("/"), Path::new("/proc"))
}

/// At the start: [`refresh`]; how many identities the executor has now.
pub fn seed(images: &ExecutorImages) -> usize {
    let ids = live_under(Path::new("/"), Path::new("/proc"));
    images.replace(ids);
    images.len()
}

/// The executors systemd's managers hold open (their descriptors whose link
/// names an install path, ` (deleted)` or not), read through the
/// descriptor.
fn held_by_managers(root: &Path, proc_root: &Path) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let Ok(dir) = std::fs::read_dir(proc_root) else {
        return out;
    };
    for entry in dir.flatten() {
        let name = entry.file_name();
        if !name
            .to_str()
            .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit()))
        {
            continue;
        }
        let pid_dir = entry.path();
        let is_manager = link_target(&pid_dir.join("exe"), root)
            .is_some_and(|exe| MANAGER_PATHS.contains(&exe.as_str()));
        if !is_manager {
            continue;
        }
        let Ok(fds) = std::fs::read_dir(pid_dir.join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let held = fd.path();
            let is_executor =
                link_target(&held, root).is_some_and(|t| EXECUTOR_PATHS.contains(&t.as_str()));
            if let Some(id) = file_id(&held).filter(|_| is_executor) {
                out.push(id);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    /// The install paths' files: an upgrade (the new file renamed over the
    /// old) replaces the identity — the old one, held by no manager, is gone
    /// (finding 3: its inode is free); a file named so elsewhere is never
    /// looked at; the device in the kernel's form.
    #[test]
    fn an_upgrade_replaces_the_identity_no_manager_holds() {
        let root = tempfile::tempdir().unwrap();
        let none = root.path().join("no-proc");
        let lib = root.path().join("usr/lib/systemd");
        std::fs::create_dir_all(&lib).unwrap();
        let exe = lib.join("systemd-executor");
        std::fs::write(&exe, b"v1").unwrap();
        let images = ExecutorImages::default();
        assert!(refresh_under(&images, root.path(), &none));
        assert!(!refresh_under(&images, root.path(), &none), "unchanged");
        let old = file_id(&exe).unwrap();
        assert!(images.contains(old));
        // dpkg: the new file renamed over the old one
        let new_file = lib.join("systemd-executor.dpkg-new");
        std::fs::write(&new_file, b"v2").unwrap();
        std::fs::rename(&new_file, &exe).unwrap();
        assert!(refresh_under(&images, root.path(), &none));
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
        let opt = root.path().join("opt/app");
        std::fs::create_dir_all(&opt).unwrap();
        std::fs::write(opt.join("systemd-executor"), b"x").unwrap();
        refresh_under(&images, root.path(), &none);
        assert!(!images.contains(file_id(&opt.join("systemd-executor")).unwrap()));
    }

    /// A manager's held executor is read through its descriptor (whose `stat`
    /// is the open file's, unlinked or not: the kernel's magic link; here a
    /// link to a file of that name): kept while held, gone once released; a
    /// process that is not systemd's manager is not looked at, whatever it
    /// holds, nor a manager's descriptor of another file.
    #[test]
    fn a_held_executor_is_kept_while_held_and_dropped_once_released() {
        let root = tempfile::tempdir().unwrap();
        let proc_root = tempfile::tempdir().unwrap();
        let r = root.path();
        let lib = r.join("usr/lib/systemd");
        std::fs::create_dir_all(&lib).unwrap();
        let exe = lib.join("systemd-executor");
        std::fs::write(&exe, b"new").unwrap();
        // the old image PID 1 holds, unlinked: the kernel shows its link as
        // the install path `(deleted)`
        let held = lib.join("systemd-executor (deleted)");
        std::fs::write(&held, b"old").unwrap();
        let held_id = file_id(&held).unwrap();
        let elsewhere = r.join("opt/app");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("systemd-executor"), b"x").unwrap();
        let fake_id = file_id(&elsewhere.join("systemd-executor")).unwrap();
        let make = |pid: &str, exe: &str, fd_target: &Path| {
            let d = proc_root.path().join(pid);
            std::fs::create_dir_all(d.join("fd")).unwrap();
            symlink(r.join(exe.trim_start_matches('/')), d.join("exe")).unwrap();
            symlink(fd_target, d.join("fd/9")).unwrap();
        };
        make("1", "/usr/lib/systemd/systemd", &held);
        make("4242", "/usr/bin/bash", &held);
        make(
            "4343",
            "/usr/lib/systemd/systemd",
            &elsewhere.join("systemd-executor"),
        );
        assert_eq!(held_by_managers(r, proc_root.path()), vec![held_id]);
        let images = ExecutorImages::default();
        refresh_under(&images, r, proc_root.path());
        assert!(images.contains(held_id) && images.contains(file_id(&exe).unwrap()));
        assert!(!images.contains(fake_id));
        // a process that is not systemd's manager, alone holding it
        let others = tempfile::tempdir().unwrap();
        let d = others.path().join("4242");
        std::fs::create_dir_all(d.join("fd")).unwrap();
        symlink(r.join("usr/bin/bash"), d.join("exe")).unwrap();
        symlink(&held, d.join("fd/9")).unwrap();
        assert!(held_by_managers(r, others.path()).is_empty());
        // PID 1 re-executed: it holds the old executor no more
        std::fs::remove_file(proc_root.path().join("1/fd/9")).unwrap();
        assert!(refresh_under(&images, r, proc_root.path()));
        assert!(!images.contains(held_id), "released: gone");
        assert_eq!(images.len(), 1);
    }
}
