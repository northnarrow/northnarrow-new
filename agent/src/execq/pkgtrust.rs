//! Trust by the package database (lab PR 223): a file a package installed
//! is trusted when its content is still the package's — the digest the
//! database recorded for it, not only its path.
//!
//! - dpkg: `/var/lib/dpkg/info/*.md5sums` (MD5, the only digest dpkg
//!   keeps; trusting a file needs a second preimage of a package's file,
//!   which MD5 still resists — its collisions need both files chosen). The
//!   index is read on the first lookup that needs one, and again when
//!   `/var/lib/dpkg/status` changes.
//! - rpm: `rpm -qf` (the system directories' `rpm`, `crate::trusted_bin`)
//!   for the file's recorded digest and algorithm (SHA-256 on current
//!   distributions).
//!
//! Package managers install nothing under the directories the guard
//! watches most (`/tmp`, `/var/tmp`, `/dev/shm`, `/home`, `/root`,
//! `/run/user`): those paths skip the lookup. A memfd or an unlinked file
//! has no path to look up.

use std::collections::HashMap;
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use md5::Md5;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};

/// Where no package installs.
pub const NEVER_PACKAGED: &[&str] = &[
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/home/",
    "/root/",
    "/run/user/",
];

/// Largest file hashed for the comparison (the scanner bounds its own).
const MAX_HASH: u64 = 1 << 30;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PkgOutcome {
    /// A package lists the file and the content matches.
    Trusted { manager: &'static str },
    /// A package lists the file and the content differs: modified after
    /// installation (judged like any other file).
    Modified { manager: &'static str },
    /// No package lists it.
    NotOwned,
    /// No lookup: a path no package uses, no database, no path.
    Skipped,
}

type DpkgIndex = Arc<HashMap<String, [u8; 16]>>;

pub struct PackageTrust {
    /// `/` in production; a fixture tree in tests.
    root: PathBuf,
    dpkg: Mutex<Option<(Option<SystemTime>, DpkgIndex)>>,
    /// Ask rpm (production) or not (tests).
    rpm: bool,
}

impl Default for PackageTrust {
    fn default() -> Self {
        Self::new("/", true)
    }
}

impl PackageTrust {
    pub fn new(root: impl Into<PathBuf>, rpm: bool) -> Self {
        Self {
            root: root.into(),
            dpkg: Mutex::new(None),
            rpm,
        }
    }

    /// Is `path` (absolute, on the host), whose content `file` holds, a
    /// package's unmodified file?
    pub fn check(&self, path: &str, file: &File) -> PkgOutcome {
        if path.is_empty()
            || !path.starts_with('/')
            || NEVER_PACKAGED.iter().any(|p| path.starts_with(p))
        {
            return PkgOutcome::Skipped;
        }
        if self.root.join("var/lib/dpkg/info").is_dir() {
            let Some(index) = self.dpkg_index() else {
                return PkgOutcome::Skipped;
            };
            let want = index
                .get(path)
                .or_else(|| index.get(&usr_alias(path)))
                .copied();
            return match want {
                None => PkgOutcome::NotOwned,
                Some(want) => match digest::<Md5>(file) {
                    Some(got) if got.as_slice() == want => PkgOutcome::Trusted { manager: "dpkg" },
                    _ => PkgOutcome::Modified { manager: "dpkg" },
                },
            };
        }
        if self.rpm
            && (self.root.join("var/lib/rpm").is_dir()
                || self.root.join("usr/lib/sysimage/rpm").is_dir())
        {
            return match rpm_digest(path) {
                None => PkgOutcome::NotOwned,
                Some((algo, want)) => {
                    let got = match algo {
                        RpmAlgo::Sha256 => digest::<Sha256>(file),
                        RpmAlgo::Md5 => digest::<Md5>(file),
                    };
                    match got {
                        Some(g) if hex::encode(&g) == want => {
                            PkgOutcome::Trusted { manager: "rpm" }
                        }
                        _ => PkgOutcome::Modified { manager: "rpm" },
                    }
                }
            };
        }
        PkgOutcome::Skipped
    }

    fn dpkg_index(&self) -> Option<DpkgIndex> {
        let status = std::fs::metadata(self.root.join("var/lib/dpkg/status"))
            .and_then(|m| m.modified())
            .ok();
        let mut cache = self.dpkg.lock();
        if cache.as_ref().is_none_or(|(at, _)| *at != status) {
            *cache = Some((
                status,
                Arc::new(read_md5sums(&self.root.join("var/lib/dpkg/info"))),
            ));
        }
        cache.as_ref().map(|(_, i)| Arc::clone(i))
    }
}

/// `/usr/bin/x` ↔ `/bin/x` (merged-`/usr`: the kernel names one, the
/// package may list the other).
fn usr_alias(path: &str) -> String {
    match path.strip_prefix("/usr") {
        Some(rest)
            if ["/bin/", "/sbin/", "/lib/", "/lib64/"]
                .iter()
                .any(|d| rest.starts_with(d)) =>
        {
            rest.to_string()
        }
        _ => format!("/usr{path}"),
    }
}

/// Every `<md5>  <path>` line of the `.md5sums` files, path made absolute.
fn read_md5sums(info: &Path) -> HashMap<String, [u8; 16]> {
    let mut out = HashMap::new();
    let Ok(dir) = std::fs::read_dir(info) else {
        return out;
    };
    for entry in dir.flatten() {
        if entry.path().extension().is_none_or(|e| e != "md5sums") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        for line in text.lines() {
            let Some((sum, path)) = line.split_once("  ") else {
                continue;
            };
            let Ok(bytes) = hex::decode(sum.trim()) else {
                continue;
            };
            let Ok(md5) = <[u8; 16]>::try_from(bytes.as_slice()) else {
                continue;
            };
            out.insert(format!("/{}", path.trim_start_matches('/')), md5);
        }
    }
    out
}

fn digest<D: Digest>(file: &File) -> Option<Vec<u8>> {
    let len = file.metadata().ok()?.len();
    if len > MAX_HASH {
        return None;
    }
    let mut h = D::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut off = 0u64;
    loop {
        let n = file.read_at(&mut buf, off).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        off += n as u64;
        if off > MAX_HASH {
            return None;
        }
    }
    Some(h.finalize().to_vec())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RpmAlgo {
    Md5,
    Sha256,
}

/// The digest rpm recorded for `path`: `(algorithm, hex)`.
fn rpm_digest(path: &str) -> Option<(RpmAlgo, String)> {
    let rpm = crate::trusted_bin::resolve("rpm").ok()?;
    let out = rpm
        .command()
        .args([
            "-qf",
            "--qf",
            "[%{FILENAMES}\\t%{FILEDIGESTALGO}\\t%{FILEDIGESTS}\\n]",
            "--",
            path,
        ])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_rpm_digest(&String::from_utf8_lossy(&out.stdout), path)
}

/// The line of `rpm -qf --qf '[%{FILENAMES}\t%{FILEDIGESTALGO}\t%{FILEDIGESTS}\n]'`
/// output naming `path`. Algorithms: 1 MD5, 8 SHA-256 (RFC 4880 ids).
fn parse_rpm_digest(text: &str, path: &str) -> Option<(RpmAlgo, String)> {
    text.lines().find_map(|l| {
        let mut f = l.split('\t');
        let (name, algo, sum) = (f.next()?, f.next()?, f.next()?);
        if name != path || sum.is_empty() {
            return None;
        }
        let algo = match algo.trim() {
            "1" => RpmAlgo::Md5,
            "8" => RpmAlgo::Sha256,
            _ => return None,
        };
        Some((algo, sum.trim().to_ascii_lowercase()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tree(lines: &str) -> tempfile::TempDir {
        let t = tempfile::tempdir().unwrap();
        let info = t.path().join("var/lib/dpkg/info");
        std::fs::create_dir_all(&info).unwrap();
        std::fs::write(t.path().join("var/lib/dpkg/status"), "Package: x\n").unwrap();
        std::fs::write(info.join("tool.md5sums"), lines).unwrap();
        std::fs::write(info.join("tool.list"), "/opt/tool/bin/tool\n").unwrap();
        t
    }

    fn file_with(content: &[u8]) -> (tempfile::NamedTempFile, File) {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(content).unwrap();
        let h = File::open(f.path()).unwrap();
        (f, h)
    }

    fn md5_hex(b: &[u8]) -> String {
        hex::encode(Md5::digest(b))
    }

    #[test]
    fn a_package_file_with_its_content_is_trusted() {
        let content = b"#!/bin/sh\necho packaged\n";
        let t = tree(&format!(
            "{}  opt/tool/bin/tool\n{}  usr/bin/other\n",
            md5_hex(content),
            md5_hex(b"x")
        ));
        let trust = PackageTrust::new(t.path(), false);
        let (_keep, f) = file_with(content);
        assert_eq!(
            trust.check("/opt/tool/bin/tool", &f),
            PkgOutcome::Trusted { manager: "dpkg" }
        );
        // merged /usr: the kernel's /usr/bin/other, the package's usr/bin/other
        let (_k2, other) = file_with(b"x");
        assert_eq!(
            trust.check("/bin/other", &other),
            PkgOutcome::Trusted { manager: "dpkg" }
        );
    }

    #[test]
    fn a_modified_or_foreign_file_is_not() {
        let t = tree(&format!("{}  opt/tool/bin/tool\n", md5_hex(b"original")));
        let trust = PackageTrust::new(t.path(), false);
        let (_keep, f) = file_with(b"replaced by an attacker");
        assert_eq!(
            trust.check("/opt/tool/bin/tool", &f),
            PkgOutcome::Modified { manager: "dpkg" }
        );
        assert_eq!(trust.check("/opt/other", &f), PkgOutcome::NotOwned);
        // where no package installs, and without a path: no lookup
        for p in ["/tmp/x", "/home/u/bin/x", "/dev/shm/x", "", "relative"] {
            assert_eq!(trust.check(p, &f), PkgOutcome::Skipped, "{p}");
        }
    }

    #[test]
    fn the_index_follows_the_status_file() {
        let t = tree(&format!("{}  opt/a\n", md5_hex(b"a")));
        let trust = PackageTrust::new(t.path(), false);
        let (_k, f) = file_with(b"b");
        assert_eq!(trust.check("/opt/b", &f), PkgOutcome::NotOwned);
        let info = t.path().join("var/lib/dpkg/info");
        std::fs::write(
            info.join("b.md5sums"),
            format!("{}  opt/b\n", md5_hex(b"b")),
        )
        .unwrap();
        // a package transaction rewrites the status file
        let status = t.path().join("var/lib/dpkg/status");
        let later = SystemTime::now() + std::time::Duration::from_secs(5);
        std::fs::File::options()
            .write(true)
            .open(&status)
            .unwrap()
            .set_modified(later)
            .unwrap();
        assert_eq!(
            trust.check("/opt/b", &f),
            PkgOutcome::Trusted { manager: "dpkg" }
        );
    }

    #[test]
    fn no_database_is_skipped_and_rpm_output_is_parsed() {
        let t = tempfile::tempdir().unwrap();
        let trust = PackageTrust::new(t.path(), false);
        let (_k, f) = file_with(b"x");
        assert_eq!(trust.check("/opt/x", &f), PkgOutcome::Skipped);
        let out = "/usr/bin/a\t8\tABCD\n/usr/bin/b\t1\t0123\n/usr/bin/c\t8\t\n";
        assert_eq!(
            parse_rpm_digest(out, "/usr/bin/a"),
            Some((RpmAlgo::Sha256, "abcd".into()))
        );
        assert_eq!(
            parse_rpm_digest(out, "/usr/bin/b"),
            Some((RpmAlgo::Md5, "0123".into()))
        );
        assert_eq!(
            parse_rpm_digest(out, "/usr/bin/c"),
            None,
            "no digest (a directory)"
        );
        assert_eq!(parse_rpm_digest(out, "/usr/bin/z"), None);
    }
}
