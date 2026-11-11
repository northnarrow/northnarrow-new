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
//! - [`seed`], at the agent's start: the files at the install paths, and the
//!   executor each systemd manager holds open (`/proc/<pid>/fd/<n>`, which
//!   `stat(2)` follows to the open file, unlinked or not) — an agent started
//!   between an upgrade and the managers' re-exec knows the old image too;
//! - [`refresh`], every minute: the files at the install paths, so the image
//!   an upgrade is about to unlink was seen while it was linked.
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

/// Record the executor's files at its install paths (`root`: `/` on the
/// host, a temporary tree in tests). Returns how many were new.
pub fn refresh_under(images: &ExecutorImages, root: &Path) -> usize {
    EXECUTOR_PATHS
        .iter()
        .filter_map(|p| file_id(&root.join(p.trim_start_matches('/'))))
        .filter(|id| images.record(*id))
        .count()
}

/// [`refresh_under`] the host's root.
pub fn refresh(images: &ExecutorImages) -> usize {
    refresh_under(images, Path::new("/"))
}

/// Record the files at the install paths under `root`, and the executors
/// systemd's managers hold open under `proc_root` (`/proc` on the host).
/// Returns how many identities were new.
pub fn seed_under(images: &ExecutorImages, root: &Path, proc_root: &Path) -> usize {
    refresh_under(images, root) + held_by_managers(images, root, proc_root)
}

/// The executors systemd's managers hold open (their descriptors whose link
/// names an install path, ` (deleted)` or not), recorded through the
/// descriptor; how many were new.
fn held_by_managers(images: &ExecutorImages, root: &Path, proc_root: &Path) -> usize {
    let mut new = 0;
    let Ok(dir) = std::fs::read_dir(proc_root) else {
        return new;
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
            if is_executor && file_id(&held).is_some_and(|id| images.record(id)) {
                new += 1;
            }
        }
    }
    new
}

/// [`seed_under`] the host's root and `/proc`.
pub fn seed(images: &ExecutorImages) -> usize {
    seed_under(images, Path::new("/"), Path::new("/proc"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    /// The install paths' files are recorded once each; a replaced file (an
    /// upgrade) adds its new identity and keeps the old one.
    #[test]
    fn the_install_paths_are_recorded_and_an_upgrade_adds_its_image() {
        let root = tempfile::tempdir().unwrap();
        let lib = root.path().join("usr/lib/systemd");
        std::fs::create_dir_all(&lib).unwrap();
        let exe = lib.join("systemd-executor");
        std::fs::write(&exe, b"v1").unwrap();
        let images = ExecutorImages::default();
        assert_eq!(refresh_under(&images, root.path()), 1);
        assert_eq!(refresh_under(&images, root.path()), 0);
        let old = file_id(&exe).unwrap();
        // dpkg: the new file renamed over the old one
        let new_file = lib.join("systemd-executor.dpkg-new");
        std::fs::write(&new_file, b"v2").unwrap();
        std::fs::rename(&new_file, &exe).unwrap();
        assert_eq!(refresh_under(&images, root.path()), 1);
        assert!(images.contains(old));
        assert!(images.contains(file_id(&exe).unwrap()));
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
        assert!(!images.contains(file_id(&opt.join("systemd-executor")).unwrap()));
    }

    /// A manager's held executor is recorded through its descriptor (whose
    /// `stat` is the open file's, unlinked or not: the kernel's magic link;
    /// a symlink to the file here); a process whose executable is not
    /// systemd's manager is not looked at, whatever it holds, nor a
    /// manager's descriptor of another file.
    #[test]
    fn a_managers_held_executor_is_recorded_by_its_descriptor() {
        let root = tempfile::tempdir().unwrap();
        let proc_root = tempfile::tempdir().unwrap();
        let r = root.path();
        let lib = r.join("usr/lib/systemd");
        std::fs::create_dir_all(&lib).unwrap();
        // the image the manager opened, then an upgrade renamed the new one
        // in: its descriptor still names the install path
        let exe = lib.join("systemd-executor");
        std::fs::write(&exe, b"old").unwrap();
        let held = r.join("held-by-pid-1");
        std::fs::hard_link(&exe, &held).unwrap();
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
        make("1", "/usr/lib/systemd/systemd", &exe);
        make("4242", "/usr/bin/bash", &exe);
        make(
            "4343",
            "/usr/lib/systemd/systemd",
            &elsewhere.join("systemd-executor"),
        );
        // through the descriptors alone: pid 1's, not bash's nor the
        // descriptor of a file named so elsewhere
        let images = ExecutorImages::default();
        assert_eq!(held_by_managers(&images, r, proc_root.path()), 1);
        assert!(images.contains(held_id));
        assert!(!images.contains(fake_id));
        // with the install paths, once
        let images = ExecutorImages::default();
        assert_eq!(seed_under(&images, r, proc_root.path()), 1);
        // a process that is not systemd's manager is not looked at, even
        // when it alone holds the executor
        let others = tempfile::tempdir().unwrap();
        let d = others.path().join("4242");
        std::fs::create_dir_all(d.join("fd")).unwrap();
        symlink(r.join("usr/bin/bash"), d.join("exe")).unwrap();
        symlink(&exe, d.join("fd/9")).unwrap();
        let images = ExecutorImages::default();
        assert_eq!(held_by_managers(&images, r, others.path()), 0);
        // no `/proc`: the install paths still count
        let images = ExecutorImages::default();
        assert_eq!(seed_under(&images, r, &r.join("no-proc")), 1);
        assert_eq!(held_by_managers(&images, r, &r.join("no-proc")), 0);
    }
}
