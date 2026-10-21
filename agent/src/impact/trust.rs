//! Lab PR 225: which writers the ransomware signal judges — the trust
//! filter, and the actor a writer's signals are counted against.
//!
//! A writer's trust is established by what the kernel executed — the
//! process's `/proc/<pid>/exe` (or the script an interpreter runs) and the
//! same for every ancestor on the ordered lineage walk of
//! [`AuthSessionTracker`](crate::posture::lineage::AuthSessionTracker) (POS-003) — and by who installed it, never by
//! `comm` or by a name list. A writer is **trusted**, and none of its bursts
//! counts toward the combination, when:
//!
//! - it belongs to a package transaction run by root
//!   ([`in_package_transaction`](crate::posture::lineage::AuthSessionTracker::in_package_transaction), the posture's and the
//!   FIM rules' own test): `apt install`, `dnf upgrade`, their maintainer
//!   scripts; or
//! - it is a **packaged program** — its executable (for an interpreter, the
//!   script it runs, by an absolute path) is listed by the host's package
//!   database ([`ProgramOwners`]) — **and** no hop of its lineage is foreign
//!   ([`is_foreign`]): every ancestor up to PID 1 is a program root
//!   installed or an installed interpreter running no named script (an
//!   interactive shell, `sh -c`). `rsync`, `tar`, `git`, `cp`, a compiler,
//!   a package-installed backup agent or database, started by a person or a
//!   unit, are trusted this way; the same programs started by a script from
//!   a home directory or `/tmp`, by a dropped binary or by a deleted
//!   executable are not.
//!
//! Everything else is judged: a binary no package installed (`/root/x`,
//! `/opt/x`, `/usr/local/bin/x`, `/tmp/x`), an interpreter running an
//! inline program (`python3 -c`) or a script no package installed
//! (`python3 /srv/sim.py`, `bash ./enc.sh`), a packaged tool started by such
//! a program, and a lineage the walk cannot read (fail toward counting).
//!
//! A writer's shapes add up under its own process, or under the payload
//! whose forked workers it is (a foreign or unpackaged program and the
//! copies of itself it forks): two processes never add up otherwise — two
//! packaged tools a user's script runs one after the other are two bursts.
//! The **actor** a kill targets is the nearest foreign hop of the lineage
//! (itself included) — the script that drives a packaged tool, the payload
//! — or the writer itself.
//!
//! This is the trust model of copy on first write (lab PR 222,
//! `cow/trust.rs`), with the package database in place of its list of
//! editors: the copy is cheap, so that guard copies for anything it does not
//! know; a kill is not, so this signal judges only writers no package vouches
//! for. Residual, said in `docs/design/RANSOMWARE_DECISIVE.md`: an intruder
//! with an interactive session who encrypts with packaged tools only
//! (`openssl`, `gpg`) from that session is a trusted writer here; each burst
//! still raises what it raised before (the mass-write arm of the posture,
//! NN-L-FIM-010 on watched paths).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use parking_lot::Mutex;

use crate::posture::lineage::{in_system_tree, is_interpreter, ExecIdentity};

/// Why a writer's bursts do not count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trusted {
    /// A package transaction run by root.
    PackageTransaction,
    /// A packaged program with a lineage of installed programs: its program.
    PackagedProgram(String),
}

impl Trusted {
    pub fn describe(&self) -> String {
        match self {
            Trusted::PackageTransaction => "package transaction run by root".to_string(),
            Trusted::PackagedProgram(p) => {
                format!("packaged program {p} started by installed programs only")
            }
        }
    }
}

/// The filter's verdict on one writer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Judged {
    Trusted(Trusted),
    /// Judged. Its shapes add up under `key` (a pid: the writer, or the
    /// payload whose forked workers it is); `actor` is the process a kill
    /// targets — the nearest foreign program of the lineage, which runs
    /// `program`. `why` says why the writer is not trusted.
    Untrusted {
        actor: u32,
        key: u32,
        program: String,
        why: String,
    },
}

/// The program an identity names, for the record: the script an
/// interpreter runs, else the executable.
pub fn program_of(id: &ExecIdentity) -> String {
    match &id.script {
        Some(s) => s.clone(),
        None => id.exe.to_string_lossy().into_owned(),
    }
}

/// A hop that vouches for nothing below it: neither a program root
/// installed nor an installed interpreter running no named script (the
/// test of lab PR 222's `cow::trust::is_foreign`).
pub fn is_foreign(id: &ExecIdentity) -> bool {
    if id.is_installed_program() {
        return false;
    }
    let exe = id.exe.to_string_lossy();
    !(id.script.is_none() && is_interpreter(&id.exe) && in_system_tree(&exe))
}

/// The writer's own program is packaged: its executable, or for an
/// interpreter the script it runs (an absolute path), is one a package
/// installed. `owned` answers from the package database (`None`: no
/// database to ask — a root-owned system tree stands in). An interpreter
/// running nothing named (`python3 -c`, a module) is never packaged.
fn packaged(id: &ExecIdentity, owned: &dyn Fn(&Path) -> Option<bool>) -> bool {
    let file = if is_interpreter(&id.exe) {
        match &id.script {
            Some(s) if s.starts_with('/') => PathBuf::from(s),
            _ => return false,
        }
    } else {
        id.exe.clone()
    };
    let text = file.to_string_lossy();
    if text.ends_with(" (deleted)") || text.contains("/../") {
        return false;
    }
    match owned(&file) {
        Some(o) => o,
        None => in_system_tree(&text),
    }
}

/// The pure decision. `lineage`: the writer's identity at index 0, then
/// its ancestors nearest first (`None`: unknown). `pid`: the writer.
/// `package_tx`: the writer belongs to a root package transaction.
pub fn judge(
    pid: u32,
    lineage: Option<&[(u32, ExecIdentity)]>,
    package_tx: bool,
    owned: &dyn Fn(&Path) -> Option<bool>,
) -> Judged {
    if package_tx {
        return Judged::Trusted(Trusted::PackageTransaction);
    }
    let Some(hops) = lineage.filter(|h| !h.is_empty()) else {
        return Judged::Untrusted {
            actor: pid,
            key: pid,
            program: "(lineage unknown)".to_string(),
            why: "its lineage could not be read".to_string(),
        };
    };
    let (_, writer) = &hops[0];
    if let Some(i) = hops.iter().position(|(_, id)| is_foreign(id)) {
        let (actor, id) = &hops[topmost_same(hops, i)];
        // A foreign writer's shapes add up with its forked workers'; a
        // packaged tool's under a foreign program count for that tool's
        // process alone: two tools a user's script runs one after the
        // other (`tar x` deleting, `rsync --inplace` rewriting) are not one
        // burst. The kill reaches the foreign program either way.
        let key = if i == 0 { *actor } else { hops[0].0 };
        let why = if i == 0 {
            "no package installed it".to_string()
        } else {
            format!(
                "{} was started by {}, which no package installed",
                program_of(writer),
                program_of(id)
            )
        };
        return Judged::Untrusted {
            actor: *actor,
            key,
            program: program_of(id),
            why,
        };
    }
    if packaged(writer, owned) {
        return Judged::Trusted(Trusted::PackagedProgram(program_of(writer)));
    }
    let (actor, _) = &hops[topmost_same(hops, 0)];
    Judged::Untrusted {
        actor: *actor,
        key: *actor,
        program: program_of(writer),
        why: if is_interpreter(&writer.exe) {
            "an interpreter running an inline program or an unpackaged script".to_string()
        } else {
            "no package installed it".to_string()
        },
    }
}

/// The hop above `i` up to which every ancestor runs the program `i` runs:
/// a payload's forked workers count against the payload.
fn topmost_same(hops: &[(u32, ExecIdentity)], i: usize) -> usize {
    let mut top = i;
    while top + 1 < hops.len() && hops[top + 1].1 == hops[i].1 {
        top += 1;
    }
    top
}

/// Who installed a program file: the host's package database. On Debian
/// and its family the `.list` files of `/var/lib/dpkg/info`, searched for
/// the path and remembered until `/var/lib/dpkg/status` changes; on the RPM
/// family `rpm -qf` (the system directories' `rpm`,
/// [`crate::trusted_bin`]). `/snap/` and `/nix/store/` are read-only images
/// their package manager mounted: owned by construction. Paths are compared
/// with `/usr` dropped (merged `/usr`). The model is R018's
/// [`crate::decision::rules::module_provenance`], for executables.
pub struct ProgramOwners {
    /// `/` in production; a fixture tree in tests.
    root: PathBuf,
    /// Answers by path, and the dpkg status mtime they were read at.
    cache: Mutex<OwnersCache>,
}

/// The answers by path, and the dpkg status mtime they were read at.
type OwnersCache = (Option<SystemTime>, HashMap<String, Option<bool>>);

/// Cached answers before the cache starts over.
const OWNERS_CACHE_CAP: usize = 1024;

impl Default for ProgramOwners {
    fn default() -> Self {
        Self::new("/")
    }
}

impl ProgramOwners {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            cache: Mutex::new((None, HashMap::new())),
        }
    }

    /// `Some(true)` when a package installed `path`, `Some(false)` when
    /// none did, `None` when the host has no package database to ask.
    pub fn owned(&self, path: &Path) -> Option<bool> {
        let text = path.to_string_lossy();
        if ["/snap/", "/var/lib/snapd/snap/", "/nix/store/"]
            .iter()
            .any(|p| text.starts_with(p))
        {
            return Some(true);
        }
        let key = without_usr(&text);
        let status = std::fs::metadata(self.root.join("var/lib/dpkg/status"))
            .and_then(|m| m.modified())
            .ok();
        {
            let mut c = self.cache.lock();
            if c.0 != status {
                *c = (status, HashMap::new());
            }
            if let Some(v) = c.1.get(&key) {
                return *v;
            }
        }
        let answer = crate::runtime::off_the_runtime(|| self.lookup(&text, &key));
        let mut c = self.cache.lock();
        if c.1.len() >= OWNERS_CACHE_CAP {
            c.1.clear();
        }
        c.1.insert(key, answer);
        answer
    }

    fn lookup(&self, path: &str, key: &str) -> Option<bool> {
        let info = self.root.join("var/lib/dpkg/info");
        if info.is_dir() {
            return Some(dpkg_lists(&info, key));
        }
        if self.root.join("var/lib/rpm").is_dir() || self.root.join("usr/lib/sysimage/rpm").is_dir()
        {
            return rpm_owns(path);
        }
        None
    }
}

/// A `.list` file of `info` names `key` (`/usr` dropped on both sides).
fn dpkg_lists(info: &Path, key: &str) -> bool {
    let Ok(dir) = std::fs::read_dir(info) else {
        return false;
    };
    for entry in dir.flatten() {
        if entry.path().extension().is_none_or(|e| e != "list") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        if text.lines().any(|l| without_usr(l) == key) {
            return true;
        }
    }
    false
}

/// `rpm -qf --quiet PATH`, as R018 asks it.
fn rpm_owns(path: &str) -> Option<bool> {
    let rpm = crate::trusted_bin::resolve("rpm").ok()?;
    let status = rpm
        .command()
        .args(["-qf", "--quiet", path])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .ok()?;
    Some(status.success())
}

/// `/usr/bin/x` → `/bin/x`.
fn without_usr(path: &str) -> String {
    path.strip_prefix("/usr").unwrap_or(path).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(exe: &str, script: Option<&str>) -> ExecIdentity {
        ExecIdentity {
            exe: PathBuf::from(exe),
            script: script.map(str::to_string),
        }
    }

    /// A package database that installed `/usr/bin/*` and `/usr/sbin/*`.
    fn distro(p: &Path) -> Option<bool> {
        let s = p.to_string_lossy();
        Some(
            s.starts_with("/usr/bin/") || s.starts_with("/usr/sbin/") || s.starts_with("/usr/lib/"),
        )
    }

    #[test]
    fn packaged_bulk_tools_from_a_person_or_a_unit_are_trusted() {
        for tool in [
            "/usr/bin/rsync",
            "/usr/bin/tar",
            "/usr/bin/git",
            "/usr/bin/cp",
            "/usr/lib/postgresql/16/bin/postgres",
        ] {
            let l = [
                (300, id(tool, None)),
                (200, id("/usr/bin/bash", None)),
                (150, id("/usr/sbin/sshd", None)),
            ];
            assert!(
                matches!(judge(300, Some(&l), false, &distro), Judged::Trusted(_)),
                "{tool}"
            );
        }
        // A packaged Python program (unattended-upgrade, borg).
        let l = [(300, id("/usr/bin/python3", Some("/usr/bin/borg")))];
        assert!(matches!(
            judge(300, Some(&l), false, &distro),
            Judged::Trusted(Trusted::PackagedProgram(p)) if p == "/usr/bin/borg"
        ));
        // A package transaction, whatever it runs.
        let l = [(300, id("/tmp/postinst-helper", None))];
        assert_eq!(
            judge(300, Some(&l), true, &distro),
            Judged::Trusted(Trusted::PackageTransaction)
        );
    }

    #[test]
    fn encryptors_and_their_children_are_judged_against_the_actor() {
        // A dropped binary, wherever root put it.
        for exe in [
            "/root/locker",
            "/opt/x/locker",
            "/usr/local/bin/locker",
            "/tmp/.x",
        ] {
            let l = [(300, id(exe, None)), (200, id("/usr/bin/bash", None))];
            match judge(300, Some(&l), false, &distro) {
                Judged::Untrusted { actor, program, .. } => {
                    assert_eq!((actor, program.as_str()), (300, exe))
                }
                other => panic!("{exe}: {other:?}"),
            }
        }
        // A script's `mv` and `rm`: counted against the script.
        let l = [
            (400, id("/usr/bin/mv", None)),
            (300, id("/usr/bin/bash", Some("/root/enc.sh"))),
            (200, id("/usr/bin/bash", None)),
        ];
        assert!(matches!(
            judge(400, Some(&l), false, &distro),
            Judged::Untrusted { actor: 300, key: 400, ref program, .. } if program == "/root/enc.sh"
        ));
        // The lab's simulator: python running a script from /srv.
        let l = [(
            300,
            id("/usr/bin/python3", Some("/srv/nn-malsim/ransom-sim.py")),
        )];
        assert!(matches!(
            judge(300, Some(&l), false, &distro),
            Judged::Untrusted { actor: 300, .. }
        ));
        // An inline program is no packaged program.
        let l = [
            (300, id("/usr/bin/python3", None)),
            (200, id("/usr/bin/bash", None)),
        ];
        assert!(matches!(
            judge(300, Some(&l), false, &distro),
            Judged::Untrusted { actor: 300, .. }
        ));
        // A lineage that cannot be read counts.
        assert!(matches!(
            judge(300, None, false, &distro),
            Judged::Untrusted { actor: 300, .. }
        ));
        // A payload's forked workers count against the payload.
        let l = [
            (302, id("/usr/local/bin/locker", None)),
            (300, id("/usr/local/bin/locker", None)),
            (200, id("/usr/bin/bash", None)),
        ];
        assert!(matches!(
            judge(302, Some(&l), false, &distro),
            Judged::Untrusted {
                actor: 300,
                key: 300,
                ..
            }
        ));
    }

    #[test]
    fn identity_not_name_decides() {
        // `rsync` copied to /usr/local/bin by root: no package installed it.
        let l = [(300, id("/usr/local/bin/rsync", None))];
        assert!(matches!(
            judge(300, Some(&l), false, &distro),
            Judged::Untrusted { .. }
        ));
        // A deleted binary.
        let l = [(300, id("/usr/bin/tar (deleted)", None))];
        assert!(matches!(
            judge(300, Some(&l), false, &distro),
            Judged::Untrusted { .. }
        ));
        // No package database: a root-owned system tree stands in.
        let none = |_: &Path| None;
        let l = [(300, id("/usr/bin/tar", None))];
        assert!(matches!(
            judge(300, Some(&l), false, &none),
            Judged::Trusted(_)
        ));
        let l = [(300, id("/srv/tar", None))];
        assert!(matches!(
            judge(300, Some(&l), false, &none),
            Judged::Untrusted { .. }
        ));
    }

    #[test]
    fn owners_read_the_dpkg_lists() {
        let t = tempfile::TempDir::new().unwrap();
        let info = t.path().join("var/lib/dpkg/info");
        std::fs::create_dir_all(&info).unwrap();
        std::fs::write(t.path().join("var/lib/dpkg/status"), "Package: rsync\n").unwrap();
        std::fs::write(
            info.join("rsync.list"),
            "/.\n/usr\n/usr/bin\n/usr/bin/rsync\n",
        )
        .unwrap();
        std::fs::write(info.join("tar.list"), "/bin/tar\n").unwrap();
        let o = ProgramOwners::new(t.path());
        assert_eq!(o.owned(Path::new("/usr/bin/rsync")), Some(true));
        assert_eq!(
            o.owned(Path::new("/usr/bin/tar")),
            Some(true),
            "merged /usr"
        );
        assert_eq!(o.owned(Path::new("/usr/local/bin/locker")), Some(false));
        assert_eq!(o.owned(Path::new("/snap/core22/1/usr/bin/x")), Some(true));
        let bare = tempfile::TempDir::new().unwrap();
        assert_eq!(
            ProgramOwners::new(bare.path()).owned(Path::new("/usr/bin/x")),
            None
        );
    }
}
