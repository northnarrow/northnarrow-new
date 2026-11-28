//! Lot 2.3b (D5, the design's section 3, "Code planted before the
//! window"): before it arms a window per process tree, the agent compares
//! the package managers' hook and plugin directories and the loader's
//! configuration with the package database — dpkg's `md5sums` and the
//! conffiles' digests of its `status`, rpm's file digests (the agent's
//! [`PackageTrust`]). A file there that no package owns, or whose content
//! differs from the database's, is foreign: the window is refused, naming
//! each with its SHA-256, unless the signed request accepts that digest
//! (`nn-admin window-run --accept-foreign`). The check is only as strong
//! as the database, which root can also edit (declared until S12).

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

use md5::Md5;
use sha2::{Digest, Sha256};

use crate::execq::pkgtrust::{PackageTrust, PkgOutcome};

/// The directories whose every file is checked (relative to the root).
pub(in crate::admin) const CHECKED_DIRS: &[&str] = &[
    "etc/apt/apt.conf.d",
    "etc/dpkg/dpkg.cfg.d",
    "etc/ld.so.conf.d",
    "etc/dnf/plugins",
    "etc/yum/pluginconf.d",
    "etc/rpm",
    "usr/lib/rpm/macros.d",
];

/// The single files checked when they exist.
pub(in crate::admin) const CHECKED_FILES: &[&str] = &[
    "etc/ld.so.preload",
    "etc/ld.so.conf",
    // the package managers' main configuration (a hook or a plugin path)
    "etc/apt/apt.conf",
    "etc/dpkg/dpkg.cfg",
    "etc/dnf/dnf.conf",
    "etc/yum.conf",
];

/// The most files the check reads (a directory flooded with entries is
/// itself foreign: the excess is named, not read).
pub(in crate::admin) const MAX_CHECKED: usize = 2048;

/// The largest file hashed; a larger one is foreign.
const MAX_BYTES: u64 = 1 << 20;

/// One file the database does not vouch for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::admin) struct Foreign {
    pub path: String,
    pub sha256: [u8; 32],
    pub why: &'static str,
}

/// What the check found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(in crate::admin) struct PregrantReport {
    pub checked: usize,
    pub foreign: Vec<Foreign>,
    pub millis: u64,
}

/// How a file is judged: the package database's verdict on `path`, whose
/// content `file` holds.
pub(in crate::admin) trait Vouch {
    fn vouch(&self, path: &str, file: &File) -> PkgOutcome;
}

/// The host's package database: [`PackageTrust`] (dpkg's `md5sums`, rpm),
/// and dpkg's conffiles, which `md5sums` does not list (their digests are
/// in `/var/lib/dpkg/status`).
pub(in crate::admin) struct HostDatabase {
    trust: PackageTrust,
    conffiles: HashMap<String, [u8; 16]>,
}

impl HostDatabase {
    /// The database under `root` (a test's tree), the host's with `None`.
    /// A `status` that cannot be read lists no conffile: each is then
    /// judged owned by no package, and the window refused (fails closed).
    pub(in crate::admin) fn open(root: Option<&Path>) -> Self {
        let status = match std::fs::read(host_path(root, "var/lib/dpkg/status")) {
            Ok(s) => String::from_utf8_lossy(&s).into_owned(),
            Err(_) => String::new(),
        };
        Self {
            trust: match root {
                Some(r) => PackageTrust::new(r, true),
                None => PackageTrust::default(),
            },
            conffiles: dpkg_conffiles(&status),
        }
    }
}

/// `rel` under `root` (a test's tree), or the host's absolute path.
fn host_path(root: Option<&Path>, rel: &str) -> PathBuf {
    match root {
        Some(r) => r.join(rel),
        None => PathBuf::from(format!("/{rel}")),
    }
}

impl Vouch for HostDatabase {
    fn vouch(&self, path: &str, file: &File) -> PkgOutcome {
        match self.trust.check(path, file) {
            PkgOutcome::NotOwned => match self.conffiles.get(path) {
                Some(want) => match digest::<Md5>(file) {
                    Some(got) if got.as_slice() == want => PkgOutcome::Trusted { manager: "dpkg" },
                    _ => PkgOutcome::Modified { manager: "dpkg" },
                },
                None => PkgOutcome::NotOwned,
            },
            other => other,
        }
    }
}

/// dpkg's conffiles and their MD5, from `status`'s `Conffiles:` fields
/// (` <path> <md5>` lines; an `obsolete` or `remove-on-upgrade` one too).
pub(in crate::admin) fn dpkg_conffiles(status: &str) -> HashMap<String, [u8; 16]> {
    let mut out = HashMap::new();
    let mut inside = false;
    for line in status.lines() {
        if line.starts_with("Conffiles:") {
            inside = true;
            continue;
        }
        if !line.starts_with(' ') {
            inside = false;
            continue;
        }
        if !inside {
            continue;
        }
        let mut f = line.split_whitespace();
        let (Some(path), Some(sum)) = (f.next(), f.next()) else {
            continue;
        };
        let Ok(bytes) = hex::decode(sum) else {
            continue;
        };
        if let (true, Ok(md5)) = (path.starts_with('/'), <[u8; 16]>::try_from(bytes.as_slice())) {
            out.insert(path.to_string(), md5);
        }
    }
    out
}

fn digest<D: Digest>(file: &File) -> Option<Vec<u8>> {
    let mut h = D::new();
    let mut buf = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut buf).ok()?;
    if buf.len() as u64 > MAX_BYTES {
        return None;
    }
    h.update(&buf);
    Some(h.finalize().to_vec())
}

/// The check under `root` (`/`), judged by `db`: every regular file of
/// [`CHECKED_DIRS`] (followed: an alternatives link is judged on its
/// target) and each of [`CHECKED_FILES`]; foreign are those the database
/// does not vouch for, and those not read (larger than the bound, past
/// [`MAX_CHECKED`]).
pub(in crate::admin) fn check(root: Option<&Path>, db: &dyn Vouch) -> PregrantReport {
    let started = Instant::now();
    let mut paths: Vec<PathBuf> = Vec::new();
    for d in CHECKED_DIRS {
        if let Ok(entries) = std::fs::read_dir(host_path(root, d)) {
            let mut v: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
            v.sort();
            paths.extend(v);
        }
    }
    for f in CHECKED_FILES {
        let p = host_path(root, f);
        if std::fs::symlink_metadata(&p).is_ok() {
            paths.push(p);
        }
    }
    let shown_of = |p: &Path| match root {
        Some(r) => format!("/{}", p.strip_prefix(r).unwrap_or(p).display()),
        None => p.display().to_string(),
    };
    let mut report = PregrantReport::default();
    for (i, p) in paths.iter().enumerate() {
        let shown = shown_of(p);
        if i >= MAX_CHECKED {
            report.foreign.push(Foreign {
                path: shown,
                sha256: [0; 32],
                why: "past the check's bound",
            });
            continue;
        }
        let Ok(file) = File::open(p) else {
            continue;
        };
        match file.metadata() {
            Ok(m) if m.is_file() => {}
            // a directory inside a hook directory is not read by its tool
            _ => continue,
        }
        report.checked += 1;
        let Some(sha) = digest::<Sha256>(&file).and_then(|d| <[u8; 32]>::try_from(d).ok()) else {
            report.foreign.push(Foreign {
                path: shown,
                sha256: [0; 32],
                why: "larger than the check reads",
            });
            continue;
        };
        // the database names the file by its own path: the link's target
        let real = std::fs::canonicalize(p)
            .ok()
            .map(|r| shown_of(&r))
            .unwrap_or_else(|| shown.clone());
        let Ok(file) = File::open(p) else {
            continue;
        };
        let why = match db.vouch(&real, &file) {
            PkgOutcome::Trusted { .. } => continue,
            PkgOutcome::Modified { .. } => "differs from the package database",
            PkgOutcome::NotOwned => "owned by no package",
            PkgOutcome::Skipped => "no package database to judge it",
        };
        report.foreign.push(Foreign {
            path: shown,
            sha256: sha,
            why,
        });
    }
    report.millis = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Db(HashMap<String, PkgOutcome>);

    impl Vouch for Db {
        fn vouch(&self, path: &str, _file: &File) -> PkgOutcome {
            self.0.get(path).cloned().unwrap_or(PkgOutcome::NotOwned)
        }
    }

    /// Lot 2.3b (D5): a hook the database vouches for passes; one owned by
    /// no package, one modified, and the loader's preload file are named
    /// with their digest.
    #[test]
    fn the_pre_grant_check_names_what_the_database_does_not_vouch_for() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let apt = root.join("etc/apt/apt.conf.d");
        std::fs::create_dir_all(&apt).unwrap();
        std::fs::write(apt.join("01autoremove"), b"APT::x;").unwrap();
        std::fs::write(apt.join("99planted"), b"DPkg::Post-Invoke {\"x\";};").unwrap();
        std::fs::write(apt.join("50edited"), b"edited").unwrap();
        std::fs::create_dir_all(apt.join("sub")).unwrap();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("etc/ld.so.preload"), b"/tmp/x.so\n").unwrap();
        let db = Db(HashMap::from([
            ("/etc/apt/apt.conf.d/01autoremove".to_string(), PkgOutcome::Trusted { manager: "dpkg" }),
            ("/etc/apt/apt.conf.d/50edited".to_string(), PkgOutcome::Modified { manager: "dpkg" }),
        ]));
        let r = check(Some(root), &db);
        assert_eq!(r.checked, 4);
        let named: Vec<(&str, &str)> = r.foreign.iter().map(|f| (f.path.as_str(), f.why)).collect();
        assert_eq!(
            named,
            [
                ("/etc/apt/apt.conf.d/50edited", "differs from the package database"),
                ("/etc/apt/apt.conf.d/99planted", "owned by no package"),
                ("/etc/ld.so.preload", "owned by no package"),
            ]
        );
        let want: [u8; 32] = Sha256::digest(b"/tmp/x.so\n").into();
        assert_eq!(r.foreign[2].sha256, want);
    }

    /// Lot 2.3b: dpkg's conffiles are read from `status` (`md5sums` does
    /// not list them), each with its MD5; other fields are not.
    #[test]
    fn dpkg_s_conffiles_are_read_from_its_status() {
        let status = "Package: apt\nStatus: install ok installed\nConffiles:\n \
                      /etc/apt/apt.conf.d/01autoremove 2b3fe0d1d8bbd4de8a1cd03c4b1f84b3\n \
                      /etc/cron.daily/apt-compat 1400ab07a4a2905b04c33e3e93d42b7b obsolete\n\
                      Description: x\n /usr/share/doc/x d41d8cd98f00b204e9800998ecf8427e\n";
        let c = dpkg_conffiles(status);
        assert_eq!(c.len(), 2);
        assert_eq!(
            hex::encode(c["/etc/apt/apt.conf.d/01autoremove"]),
            "2b3fe0d1d8bbd4de8a1cd03c4b1f84b3"
        );
        assert!(c.contains_key("/etc/cron.daily/apt-compat"));
    }
}
