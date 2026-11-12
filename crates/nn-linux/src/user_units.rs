//! Lot 310b (decided 12/11/2026, folded into lot 310): a process that is a
//! packaged user unit's own — what a user's service manager (`systemd
//! --user`) vouches for in the ransomware signal's and the copy guard's
//! lineage judgement (`nn_core::impact::trust::manager_vouches_for_its_unit`).
//!
//! The manager runs what its user asks (`systemd-run --user`, units and
//! drop-ins in `~/.config/systemd/user`), so it vouches for nothing of
//! that; but it also starts the desktop's terminal emulator and its
//! session's services from unit files root installed. A process is such a
//! unit's when:
//!
//! - its cgroup (`/proc/<pid>/cgroup`, the unified hierarchy's line) is a
//!   `.service` directly under the manager's `user@<uid>.service` tree;
//! - that unit's file (or its template's, `name@.service`) is in
//!   `/usr/lib/systemd/user` or `/etc/systemd/user`, root's and written by
//!   no one else, and not disowned by the package database;
//! - the user has no unit or drop-in of that name in any directory the
//!   manager reads from the user's side: `~/.config/systemd/user` and its
//!   `.control`, `~/.local/share/systemd/user`, `/run/user/<uid>/systemd/…`
//!   (transient `systemd-run --user` units, runtime drop-ins, generators).
//!
//! The manager's FORK of the process (the kernel's record) is checked by
//! the judgement, not here. Residual, said: a user relocating the
//! manager's configuration (`XDG_CONFIG_HOME` in its own environment at
//! login) is not followed; an environment the user sets for its units
//! (`systemctl --user set-environment`, `environment.d`) is the exec pump's
//! business for an interpreter, CM-25's for a binary.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Where packages and the administrator put user units.
const PACKAGED_DIRS: &[&str] = &["usr/lib/systemd/user", "etc/systemd/user"];

/// Where the user's side puts units and drop-ins, relative to its home.
const HOME_DIRS: &[&str] = &[
    ".config/systemd/user",
    ".config/systemd/user.control",
    ".local/share/systemd/user",
];

/// …and under `/run/user/<uid>/systemd`.
const RUNTIME_DIRS: &[&str] = &[
    "user",
    "user.control",
    "transient",
    "generator",
    "generator.early",
    "generator.late",
];

/// The host's answer: [`packaged_user_unit_under`] of `/` and `/proc`,
/// root's files, the host's package database.
pub fn packaged_user_unit(pid: u32) -> bool {
    let owners =
        nn_core::impact::trust::ProgramOwners::<crate::chain_host_linux::LinuxHost>::new("/");
    packaged_user_unit_under(Path::new("/"), Path::new("/proc"), pid, 0, &|p| {
        owners.owned(p)
    })
}

/// `pid`'s cgroup is a packaged user unit (the module's head), under
/// `root` and `proc_root`; `owner` the unit files' owner (0 on the host),
/// `owned` the package database (`None`: none to ask).
pub fn packaged_user_unit_under(
    root: &Path,
    proc_root: &Path,
    pid: u32,
    owner: u32,
    owned: &dyn Fn(&Path) -> Option<bool>,
) -> bool {
    // a failed read vouches for nothing (the stricter side)
    let Ok(cgroup) = crate::state_read::read_state(proc_root.join(pid.to_string()).join("cgroup"))
    else {
        return false;
    };
    let Some((uid, unit)) = user_unit_of(&cgroup) else {
        return false;
    };
    let names = unit_names(&unit);
    let in_packaged_dir = PACKAGED_DIRS.iter().any(|d| {
        names.iter().any(|n| {
            let logical = Path::new("/").join(d).join(n);
            trusted_file(&root.join(d).join(n), owner) && owned(&logical) != Some(false)
        })
    });
    in_packaged_dir && !users_side_has(root, uid, &names)
}

/// The user unit a cgroup file names: the unified hierarchy's line (`0::`),
/// a `.service` whose parent chain is `…/user@<uid>.service/…` — the uid
/// and the unit's name.
fn user_unit_of(cgroup: &str) -> Option<(u32, String)> {
    let path = cgroup.lines().find_map(|l| l.strip_prefix("0::"))?;
    let mut parts = path.trim_end().split('/').filter(|p| !p.is_empty());
    let uid = parts.by_ref().find_map(|p| {
        p.strip_prefix("user@")
            .and_then(|r| r.strip_suffix(".service"))
            .and_then(|u| u.parse::<u32>().ok())
    })?;
    let unit = parts.last()?;
    (unit.ends_with(".service") && !unit.contains("..")).then(|| (uid, unit.to_string()))
}

/// A unit's file names: its own, and its template's for an instance
/// (`org.gnome.Shell@wayland.service` → `org.gnome.Shell@.service`).
fn unit_names(unit: &str) -> Vec<String> {
    let mut names = vec![unit.to_string()];
    if let Some((prefix, _)) = unit.split_once('@') {
        names.push(format!("{prefix}@.service"));
    }
    names
}

/// A file `owner` owns that no one else may write (a symlink followed).
fn trusted_file(path: &Path, owner: u32) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.uid() == owner && m.mode() & 0o022 == 0)
}

/// The user's side holds a unit or a drop-in directory of one of `names`.
fn users_side_has(root: &Path, uid: u32, names: &[String]) -> bool {
    let mut dirs: Vec<PathBuf> = RUNTIME_DIRS
        .iter()
        .map(|d| root.join(format!("run/user/{uid}/systemd")).join(d))
        .collect();
    match home_of(root, uid) {
        Some(home) => dirs.extend(
            HOME_DIRS
                .iter()
                .map(|d| root.join(home.trim_start_matches('/')).join(d)),
        ),
        // a user whose home cannot be found: no unit is known to be free of
        // theirs
        None => return true,
    }
    dirs.iter().any(|d| {
        names.iter().any(|n| {
            d.join(n).symlink_metadata().is_ok()
                || d.join(format!("{n}.d")).symlink_metadata().is_ok()
        })
    })
}

/// The home directory of `uid` in `root`'s `/etc/passwd`.
fn home_of(root: &Path, uid: u32) -> Option<String> {
    let passwd = std::fs::read_to_string(root.join("etc/passwd")).ok()?;
    passwd.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() >= 7 && f[2].parse::<u32>().ok() == Some(uid)).then(|| f[5].to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn me() -> u32 {
        // SAFETY: getuid has no preconditions.
        unsafe { libc::getuid() }
    }

    fn file(path: &Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"[Service]\n").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    /// A fixture host: a user 1000 whose home is `/home/u`, a process 4100
    /// in `cgroup`'s unit.
    fn host(cgroup: &str) -> (tempfile::TempDir, tempfile::TempDir) {
        let root = tempfile::tempdir().unwrap();
        let proc = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("etc")).unwrap();
        std::fs::write(
            root.path().join("etc/passwd"),
            "root:x:0:0::/root:/bin/bash\nu:x:1000:1000::/home/u:/bin/bash\n",
        )
        .unwrap();
        std::fs::create_dir_all(proc.path().join("4100")).unwrap();
        std::fs::write(proc.path().join("4100/cgroup"), cgroup).unwrap();
        (root, proc)
    }

    const TERMINAL: &str = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/gnome-terminal-server.service\n";

    /// The desktop's terminal emulator, a packaged user unit: yes; its unit
    /// overridden by the user (a unit, a drop-in, a runtime drop-in), a
    /// transient `systemd-run --user` unit, a scope, a file others may
    /// write or the package database disowns: no.
    #[test]
    fn a_packaged_user_unit_and_what_the_user_can_change() {
        let none = |_: &Path| None;
        let (root, proc) = host(TERMINAL);
        let r = root.path();
        let unit = r.join("usr/lib/systemd/user/gnome-terminal-server.service");
        file(&unit);
        let yes = |owned: &dyn Fn(&Path) -> Option<bool>| {
            packaged_user_unit_under(r, proc.path(), 4100, me(), owned)
        };
        assert!(yes(&none), "the terminal's packaged unit");
        assert!(!yes(&|_| Some(false)), "disowned by the package database");
        assert!(!packaged_user_unit_under(
            r,
            proc.path(),
            4100,
            me().wrapping_add(1),
            &none
        ));
        for (k, side) in [
            "home/u/.config/systemd/user/gnome-terminal-server.service",
            "home/u/.config/systemd/user/gnome-terminal-server.service.d",
            "home/u/.local/share/systemd/user/gnome-terminal-server.service",
            "run/user/1000/systemd/user.control/gnome-terminal-server.service.d",
        ]
        .into_iter()
        .enumerate()
        {
            let p = r.join(side);
            if side.ends_with(".d") {
                std::fs::create_dir_all(&p).unwrap();
            } else {
                file(&p);
            }
            assert!(!yes(&none), "{k}: {side}");
            if side.ends_with(".d") {
                std::fs::remove_dir_all(&p).unwrap();
            } else {
                std::fs::remove_file(&p).unwrap();
            }
        }
        assert!(yes(&none), "back to the packaged unit");
        std::fs::set_permissions(&unit, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(!yes(&none), "writable by others");
        // a transient unit (`systemd-run --user`), a scope, a system unit
        for cg in [
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/run-u12.service\n",
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-x-123.scope\n",
            "0::/system.slice/cron.service\n",
        ] {
            let (root, proc) = host(cg);
            file(&root.path().join("usr/lib/systemd/user/run-u12.service"));
            file(
                &root
                    .path()
                    .join("run/user/1000/systemd/transient/run-u12.service"),
            );
            assert!(
                !packaged_user_unit_under(root.path(), proc.path(), 4100, me(), &none),
                "{cg}"
            );
        }
    }

    /// An instance's template: `org.gnome.Shell@wayland.service` from
    /// `org.gnome.Shell@.service`; the user's override of the template
    /// counts too.
    #[test]
    fn an_instance_is_read_through_its_template() {
        let none = |_: &Path| None;
        let (root, proc) = host(
            "0::/user.slice/user-1000.slice/user@1000.service/session.slice/org.gnome.Shell@wayland.service\n",
        );
        let r = root.path();
        file(&r.join("usr/lib/systemd/user/org.gnome.Shell@.service"));
        assert!(packaged_user_unit_under(r, proc.path(), 4100, me(), &none));
        std::fs::create_dir_all(r.join("home/u/.config/systemd/user/org.gnome.Shell@.service.d"))
            .unwrap();
        assert!(!packaged_user_unit_under(r, proc.path(), 4100, me(), &none));
        assert_eq!(
            user_unit_of(TERMINAL),
            Some((1000, "gnome-terminal-server.service".to_string()))
        );
        assert_eq!(
            user_unit_of("0::/user.slice/user-1000.slice/session-2.scope\n"),
            None
        );
    }
}
