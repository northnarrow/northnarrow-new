//! External audit ATP-014 (NN-AUD-262): the system binaries the agent runs.
//!
//! COMBAT's isolation (`iptables-restore`, `iptables` and their v6 pair),
//! the per-process egress block (`nft`) and R018's module provenance
//! (`rpm`) ran a bare name, so the search followed the `PATH` the agent
//! inherited. The unit set none, and systemd's default for a service starts
//! with `/usr/local/sbin:/usr/local/bin` — directories the FIM list does not
//! watch and the anti-tamper hooks leave open (lab PR 152). An
//! `iptables-restore` planted there that exits 0 turned every COMBAT
//! isolation into a no-op the agent logged as "network isolated".
//!
//! A binary is now looked up by name in [`SYSTEM_BIN_DIRS`] only, in that
//! order, whatever the environment says, and run only when the file it
//! resolves to (the whole symbolic-link chain followed: `iptables-restore`
//! is a link to `xtables-nft-multi` through `/etc/alternatives`):
//! - lies in one of those directories;
//! - is a regular file, executable, owned by root and writable by nobody
//!   else (no group or other write bit);
//! - sits in directories that are root's and writable by nobody else, from
//!   `/` down (a directory another user could write would let them swap
//!   the file).
//!
//! What runs is that verified file, with `argv[0]` set to the name asked
//! for: a multi-call binary picks its personality from it, exactly as when
//! the name was searched on `PATH`. A candidate refused on these grounds
//! is reported and the next directory is tried.

use std::fmt;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

/// The directories a binary the agent runs is looked up in, in order
/// (merged `/usr` first). Never `/usr/local`: systemd's default service
/// `PATH` puts it first, and nothing there is the distribution's.
pub const SYSTEM_BIN_DIRS: [&str; 4] = ["/usr/sbin", "/usr/bin", "/sbin", "/bin"];

/// A system binary the agent may run: found by name in
/// [`SYSTEM_BIN_DIRS`] and verified (see the module documentation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemBin {
    name: String,
    found: PathBuf,
    exe: PathBuf,
}

impl SystemBin {
    /// A command running the verified file, `argv[0]` the name looked up.
    pub fn command(&self) -> Command {
        let mut cmd = Command::new(&self.exe);
        cmd.arg0(&self.name);
        cmd
    }

    /// The name looked up (`iptables-restore`).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Where it was found (`/usr/sbin/iptables-restore`).
    pub fn found(&self) -> &Path {
        &self.found
    }

    /// The file that runs (`/usr/sbin/xtables-nft-multi`).
    pub fn exe(&self) -> &Path {
        &self.exe
    }
}

/// Why a binary is not run: none in the system directories, or each one
/// found was refused (`refused`, one reason per candidate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotTrusted {
    pub name: String,
    pub refused: Vec<String>,
}

impl NotTrusted {
    /// No candidate at all (as opposed to candidates refused).
    pub fn is_missing(&self) -> bool {
        self.refused.is_empty()
    }
}

impl fmt::Display for NotTrusted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dirs = SYSTEM_BIN_DIRS.join(", ");
        if self.refused.is_empty() {
            write!(f, "no `{}` in {dirs}", self.name)
        } else {
            write!(
                f,
                "no trusted `{}` in {dirs}: {}",
                self.name,
                self.refused.join("; ")
            )
        }
    }
}

impl std::error::Error for NotTrusted {}

/// Look `name` up on this host: [`Lookup::system`].
pub fn resolve(name: &str) -> Result<SystemBin, NotTrusted> {
    Lookup::system().resolve(name)
}

/// Where and against which owner binaries are looked up: the host's `/`
/// and root in production, a fixture tree and its owner in tests (and in
/// `nn-admin host-check` over a tree).
#[derive(Debug, Clone)]
pub struct Lookup {
    root: PathBuf,
    owner: u32,
}

impl Lookup {
    /// The host: `/`, every file and directory root's.
    pub fn system() -> Self {
        Self {
            root: PathBuf::from("/"),
            owner: 0,
        }
    }

    /// The tree at `root`, whose files and directories must belong to
    /// `owner`.
    pub fn new(root: impl Into<PathBuf>, owner: u32) -> Self {
        Self {
            root: root.into(),
            owner,
        }
    }

    /// The tree at `root`, judged against the owner of `root` itself (root
    /// for the host's `/`).
    pub fn under(root: &Path) -> Self {
        let owner = fs::metadata(root).map(|m| m.uid()).unwrap_or(0);
        Self::new(root, owner)
    }

    /// Find `name` in [`SYSTEM_BIN_DIRS`] under the root and verify it.
    pub fn resolve(&self, name: &str) -> Result<SystemBin, NotTrusted> {
        let not_trusted = |refused| NotTrusted {
            name: name.to_string(),
            refused,
        };
        if !plain_name(name) {
            return Err(not_trusted(vec![format!(
                "`{name}` is not a plain file name"
            )]));
        }
        let root = match fs::canonicalize(&self.root) {
            Ok(r) => r,
            Err(e) => return Err(not_trusted(vec![format!("{}: {e}", self.root.display())])),
        };
        let dirs: Vec<PathBuf> = SYSTEM_BIN_DIRS
            .iter()
            .filter_map(|d| fs::canonicalize(self.host_path(d)).ok())
            .filter(|d| d.starts_with(&root))
            .collect();
        let mut refused = Vec::new();
        let mut searched: Vec<PathBuf> = Vec::new();
        for dir in SYSTEM_BIN_DIRS {
            // merged `/usr`: `/sbin` is `/usr/sbin`, searched once
            if let Ok(canon) = fs::canonicalize(self.host_path(dir)) {
                if searched.contains(&canon) {
                    continue;
                }
                searched.push(canon);
            }
            let found = self.host_path(dir).join(name);
            match fs::symlink_metadata(&found) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    refused.push(format!("{}: {e}", found.display()));
                    continue;
                }
                Ok(_) => {}
            }
            match self.verify(&found, &root, &dirs) {
                Ok(exe) => {
                    for why in &refused {
                        tracing::warn!(
                            binary = name,
                            using = %exe.display(),
                            refused = %why,
                            "a system binary was refused (external audit ATP-014); a later \
                             system directory's copy runs instead"
                        );
                    }
                    return Ok(SystemBin {
                        name: name.to_string(),
                        found,
                        exe,
                    });
                }
                Err(why) => refused.push(format!("{}: {why}", found.display())),
            }
        }
        Err(not_trusted(refused))
    }

    /// `/usr/sbin` under the root.
    fn host_path(&self, abs: &str) -> PathBuf {
        self.root.join(abs.trim_start_matches('/'))
    }

    /// The verified file `found` resolves to, or why it is refused.
    fn verify(&self, found: &Path, root: &Path, dirs: &[PathBuf]) -> Result<PathBuf, String> {
        let exe = fs::canonicalize(found).map_err(|e| format!("does not resolve: {e}"))?;
        let parent = exe
            .parent()
            .ok_or_else(|| format!("resolves to {}", exe.display()))?;
        if !dirs.iter().any(|d| d == parent) {
            return Err(format!(
                "resolves to {}, outside the system directories",
                exe.display()
            ));
        }
        let meta = fs::metadata(&exe).map_err(|e| format!("{}: {e}", exe.display()))?;
        if !meta.is_file() {
            return Err(format!("{} is not a regular file", exe.display()));
        }
        if meta.mode() & 0o111 == 0 {
            return Err(format!("{} is not executable", exe.display()));
        }
        self.owned_and_closed(&exe, &meta)?;
        // the file's directories, then the one it was found in (a link in
        // `/sbin` to a file in `/usr/bin`), each up to the root
        let found_dir = found
            .parent()
            .and_then(|d| fs::canonicalize(d).ok())
            .unwrap_or_else(|| parent.to_path_buf());
        for start in [parent, found_dir.as_path()] {
            let mut dir = start;
            loop {
                let meta = fs::metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
                self.owned_and_closed(dir, &meta)?;
                if dir == root {
                    break;
                }
                match dir.parent() {
                    Some(up) if up.starts_with(root) => dir = up,
                    _ => break,
                }
            }
        }
        Ok(exe)
    }

    fn owned_and_closed(&self, path: &Path, meta: &fs::Metadata) -> Result<(), String> {
        if meta.uid() != self.owner {
            return Err(format!(
                "{} is owned by uid {}, not {}",
                path.display(),
                meta.uid(),
                self.owner
            ));
        }
        if meta.mode() & 0o022 != 0 {
            return Err(format!(
                "{} is writable by group or others (mode {:o})",
                path.display(),
                meta.mode() & 0o7777
            ));
        }
        Ok(())
    }
}

/// A single path component: no `/`, not `.` or `..`, not empty.
fn plain_name(name: &str) -> bool {
    let mut parts = Path::new(name).components();
    matches!(
        (parts.next(), parts.next()),
        (Some(Component::Normal(_)), None)
    ) && !name.contains('/')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn me() -> u32 {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() }
    }

    fn exe(path: &Path, mode: u32) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    /// A tree with the four system directories (merged `/usr`: `sbin` and
    /// `bin` links into `usr`) and `/usr/local/{sbin,bin}`, all 0755.
    fn tree() -> tempfile::TempDir {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        fs::set_permissions(r, fs::Permissions::from_mode(0o755)).unwrap();
        for d in [
            "usr/sbin",
            "usr/bin",
            "usr/local/sbin",
            "usr/local/bin",
            "etc/alternatives",
        ] {
            fs::create_dir_all(r.join(d)).unwrap();
        }
        for d in [
            "usr",
            "usr/sbin",
            "usr/bin",
            "usr/local",
            "usr/local/sbin",
            "usr/local/bin",
            "etc",
            "etc/alternatives",
        ] {
            fs::set_permissions(r.join(d), fs::Permissions::from_mode(0o755)).unwrap();
        }
        symlink("usr/sbin", r.join("sbin")).unwrap();
        symlink("usr/bin", r.join("bin")).unwrap();
        t
    }

    /// NN-AUD-262: a binary planted in `/usr/local/sbin` — first on
    /// systemd's default service `PATH` — is never the one run; the
    /// system directory's is, and without one the lookup fails instead of
    /// falling back to `PATH`.
    #[test]
    fn trusted_bin_refuses_usr_local() {
        let t = tree();
        let r = t.path();
        let lookup = Lookup::new(r, me());
        exe(&r.join("usr/local/sbin/iptables-restore"), 0o755);
        let err = lookup.resolve("iptables-restore").unwrap_err();
        assert!(err.is_missing(), "{err}");
        assert!(
            err.to_string().contains("/usr/sbin, /usr/bin, /sbin, /bin"),
            "{err}"
        );
        exe(&r.join("usr/sbin/xtables-nft-multi"), 0o755);
        symlink(
            r.join("usr/sbin/xtables-nft-multi"),
            r.join("etc/alternatives/iptables-restore"),
        )
        .unwrap();
        symlink(
            r.join("etc/alternatives/iptables-restore"),
            r.join("usr/sbin/iptables-restore"),
        )
        .unwrap();
        let bin = lookup.resolve("iptables-restore").unwrap();
        assert_eq!(bin.found(), r.join("usr/sbin/iptables-restore"));
        assert_eq!(
            bin.exe(),
            fs::canonicalize(r.join("usr/sbin/xtables-nft-multi")).unwrap(),
            "the alternatives chain is followed to the real file"
        );
        assert_eq!(bin.name(), "iptables-restore");
        // a link from a system directory into /usr/local is refused
        symlink(
            r.join("usr/local/sbin/iptables-restore"),
            r.join("usr/sbin/nft"),
        )
        .unwrap();
        let err = lookup.resolve("nft").unwrap_err();
        assert!(!err.is_missing());
        assert!(
            err.to_string().contains("outside the system directories"),
            "{err}"
        );
    }

    /// NN-AUD-262: the absolute file found in a system directory is what
    /// runs, with `argv[0]` the name looked up (a multi-call binary picks
    /// its personality from it).
    #[test]
    fn trusted_bin_resolves_absolute() {
        let t = tree();
        let r = t.path();
        let lookup = Lookup::new(r, me());
        let multi = r.join("usr/sbin/multi");
        fs::write(&multi, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&multi, fs::Permissions::from_mode(0o755)).unwrap();
        symlink("multi", r.join("usr/sbin/ip6tables")).unwrap();
        let bin = lookup.resolve("ip6tables").unwrap();
        assert!(bin.exe().is_absolute());
        assert_eq!(bin.exe(), fs::canonicalize(&multi).unwrap());
        let cmd = bin.command();
        assert_eq!(cmd.get_program(), bin.exe().as_os_str());
        // /usr/bin after /usr/sbin; /sbin and /bin (links here) add nothing
        exe(&r.join("usr/bin/rpm"), 0o755);
        assert_eq!(
            lookup.resolve("rpm").unwrap().found(),
            r.join("usr/bin/rpm")
        );
        // the real host: the shell every Linux has
        let sh = resolve("sh").expect("/usr/bin/sh or /bin/sh");
        assert!(SYSTEM_BIN_DIRS.iter().any(|d| sh.found().starts_with(d)));
        let out = sh
            .command()
            .args(["-c", "echo $0"])
            .output()
            .expect("run sh");
        assert!(out.status.success());
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            "sh\n",
            "argv[0] is the name"
        );
    }

    /// The file's owner and mode, and its directories', are checked; a
    /// refused candidate gives way to the next system directory's.
    #[test]
    fn trusted_bin_checks_owner_and_mode() {
        let t = tree();
        let r = t.path();
        let lookup = Lookup::new(r, me());
        exe(&r.join("usr/sbin/nft"), 0o775);
        let err = lookup.resolve("nft").unwrap_err();
        assert!(
            err.to_string().contains("writable by group or others"),
            "{err}"
        );
        exe(&r.join("usr/bin/nft"), 0o755);
        assert_eq!(
            lookup.resolve("nft").unwrap().found(),
            r.join("usr/bin/nft"),
            "the next system directory's copy"
        );
        exe(&r.join("usr/sbin/rpm"), 0o644);
        assert!(lookup
            .resolve("rpm")
            .unwrap_err()
            .to_string()
            .contains("not executable"));
        fs::create_dir(r.join("usr/sbin/iptables")).unwrap();
        assert!(lookup
            .resolve("iptables")
            .unwrap_err()
            .to_string()
            .contains("not a regular file"));
        // a directory others can write: the file could be swapped
        exe(&r.join("usr/sbin/ip6tables"), 0o755);
        fs::set_permissions(r.join("usr/sbin"), fs::Permissions::from_mode(0o777)).unwrap();
        let err = lookup.resolve("ip6tables").unwrap_err();
        fs::set_permissions(r.join("usr/sbin"), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(err.to_string().contains("usr/sbin is writable"), "{err}");
        // another owner
        let other = Lookup::new(r, me().wrapping_add(1));
        assert!(other
            .resolve("ip6tables")
            .unwrap_err()
            .to_string()
            .contains("is owned by uid"));
        // not a plain name
        for bad in [
            "",
            ".",
            "..",
            "../usr/local/sbin/nft",
            "/usr/sbin/nft",
            "a/b",
        ] {
            assert!(lookup.resolve(bad).is_err(), "{bad:?}");
        }
    }
}
