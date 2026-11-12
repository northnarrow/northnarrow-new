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
//!   script it runs as well, by an absolute path) is listed by the host's
//!   package database ([`ProgramOwners`]) — **and** every hop of its lineage
//!   vouches for it ([`vouches`], lot 292, BUG-49): every ancestor up to
//!   PID 1 above the writer and its forked copies is a program a package
//!   installed, or an interpreter a package installed running no program
//!   at all (an interactive shell), and none is foreign ([`is_foreign`]).
//!   Lot 310 (BUG-49, the decision of 11/11/2026): an interpreter running
//!   an inline program (`sh -c`, `python3 -c`, `perl -e`) or its standard
//!   input (`sh -s`) vouches for nothing ([`Runs::Code`]): that program is
//!   the caller's, and a webshell's `sh -c 'openssl enc …'` made the
//!   packaged `openssl` a trusted writer. A package transaction stays
//!   trusted as before (its own test, above). `rsync`, `tar`, `git`, `cp`, a compiler, a
//!   package-installed backup agent or database, started by a person or a
//!   unit, are trusted this way; the same programs started by a script from
//!   a home directory or `/tmp`, by a binary in `/opt` or `/usr/local` no
//!   package installed, by an interpreter whose arguments do not tell what
//!   it runs (lot 292, BUG-44) or by a deleted executable are not.
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
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use parking_lot::Mutex;

use crate::decision::host::DecisionHost;
use crate::posture::lineage::{in_system_tree, is_interpreter, ExecIdentity, Runs};

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

/// What a writer whose lineage could not be read is recorded as.
pub const LINEAGE_UNKNOWN: &str = "(lineage unknown)";

/// The program an identity names, for the record: the script an
/// interpreter runs, else the executable ([`ExecIdentity::program`]).
pub fn program_of(id: &ExecIdentity) -> String {
    id.program()
}

/// A hop that vouches for nothing below it: neither a program root
/// installed nor an installed interpreter running no program at all (the
/// test of lab PR 222's copy on first write, which calls this one). Lot 292
/// (BUG-44): an interpreter whose options could not be read
/// ([`Runs::Unknown`]) is one; lot 310 (BUG-49): so is one running an
/// inline program or its standard input ([`Runs::Code`]).
pub fn is_foreign(id: &ExecIdentity) -> bool {
    if id.is_installed_program() {
        return false;
    }
    let exe = id.exe.to_string_lossy();
    !(id.runs == Runs::Inline && is_interpreter(&id.exe) && in_system_tree(&exe))
}

/// `file` is one a package installed. `owned` answers from the package
/// database (`None`: no database to ask — a root-owned system tree stands
/// in); a deleted or replaced file, or one named through `..`, is not.
fn owned_file(file: &Path, owned: &dyn Fn(&Path) -> Option<bool>) -> bool {
    let text = file.to_string_lossy();
    if text.ends_with(" (deleted)") || text.contains("/../") {
        return false;
    }
    match owned(file) {
        Some(o) => o,
        None => in_system_tree(&text),
    }
}

/// The program is packaged: its executable is one a package installed and,
/// for an interpreter, so is the script it runs (an absolute path). An
/// interpreter running nothing named (`python3 -c`, a module) is never
/// packaged, nor one whose options could not be read (lot 292).
fn packaged(id: &ExecIdentity, owned: &dyn Fn(&Path) -> Option<bool>) -> bool {
    if !owned_file(&id.exe, owned) {
        return false;
    }
    if !id.interprets() {
        return true;
    }
    match id.script() {
        Some(s) if s.starts_with('/') => owned_file(Path::new(s), owned),
        _ => false,
    }
}

/// Lot 292 (BUG-49): an ancestor vouches for what it starts when a package
/// installed its program ([`packaged`]), or when it is an interpreter a
/// package installed running no program at all (an interactive shell).
/// Lying in a root-owned tree (`/opt/x`, `/usr/local/bin/x`) is not being
/// installed by a package, an interpreter whose options could not be read
/// vouches for nothing, and (lot 310) nor does one running an inline
/// program (`sh -c`) or its standard input ([`Runs::Code`]).
pub fn vouches(id: &ExecIdentity, owned: &dyn Fn(&Path) -> Option<bool>) -> bool {
    packaged(id, owned)
        || (id.runs == Runs::Inline && is_interpreter(&id.exe) && owned_file(&id.exe, owned))
}

/// Lot 310 (the review of #539, finding 7): hop `n` of `hops` is a
/// `systemd --user` manager — the manager's program at a pid other than 1,
/// started by PID 1 (or of a parent not known) — which vouches for nothing
/// it starts: the user chooses what it runs (`systemd-run --user
/// /usr/bin/openssl enc …` was a lineage of installed programs end to end,
/// no inline program in it). PID 1 runs units from root's unit files and an
/// administrator's `systemd-run`, and still vouches; so does a container's
/// systemd (its parent a container runtime, judged as every hop is).
pub fn is_user_manager(hops: &[(u32, ExecIdentity)], n: usize) -> bool {
    const MANAGERS: &[&str] = &["/usr/lib/systemd/systemd", "/lib/systemd/systemd"];
    let Some((pid, id)) = hops.get(n) else {
        return false;
    };
    *pid != 1
        && id.runs == Runs::Inline
        && MANAGERS.iter().any(|m| id.exe == Path::new(m))
        && hops.get(n + 1).is_none_or(|(parent, _)| *parent == 1)
}

/// Lot 310 (the re-check of #539, N2; lot 310b): what the kernel and the
/// host say of one hop of a lineage beyond its identity.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HopFacts {
    /// The process that FORKED it, when its exec was the first since that
    /// fork (the kernel's record at `sched_process_fork`, never the parent
    /// at exec time); 0 when not known.
    pub fork_parent: u32,
    /// Its cgroup is a user unit whose unit file is root's and a package's
    /// (`/usr/lib/systemd/user`, `/etc/systemd/user`), with no unit or
    /// drop-in of the user's (`~/.config/systemd/user`, a transient
    /// `systemd-run --user` unit) — the host's `DecisionHost::
    /// packaged_user_unit`.
    pub packaged_user_unit: bool,
}

/// Lot 310 (the re-check of #539; lot 310b): the [`HopFacts`] of `hops`
/// (the lineage of `pid` as of `as_of`): the lineage's fork parents, and
/// for the hop a user's manager started (the hop below one),
/// `packaged_user_unit(its pid)` — asked of no other hop.
pub fn hop_facts<H: crate::posture::host::PostureHost>(
    lineage: &crate::posture::lineage::AuthSessionTracker<H>,
    pid: u32,
    as_of: crate::posture::lineage::AsOf,
    hops: &[(u32, ExecIdentity)],
    packaged_user_unit: &dyn Fn(u32) -> bool,
) -> Vec<HopFacts> {
    let forks = lineage.lineage_fork_parents(pid, as_of);
    (0..hops.len())
        .map(|n| HopFacts {
            fork_parent: forks.get(n).copied().unwrap_or(0),
            packaged_user_unit: is_user_manager(hops, n + 1) && packaged_user_unit(hops[n].0),
        })
        .collect()
}

/// Lot 310, the review of #539 (finding 7, the coordinator's refinement once
/// the lab measured a new Critical record): hop `n` of `hops` is a shell (or
/// interpreter) a package installed running an inline program that PID 1
/// started — a unit's `ExecStart=/bin/sh -c '…'` from a unit file only root
/// writes, or root's `systemd-run`: it inherits PID 1's vouching. The
/// re-check of #539 (N2): "PID 1 started it" is the kernel's record of who
/// FORKED it, for its first exec ([`HopFacts::fork_parent`]) — a webshell's
/// double-forked orphan, which PID 1 reaps before its `sh -c`, was forked
/// by the webshell. A user's manager, cron (its jobs carry no owner in this
/// judgement) and sshd's `bash -c` do not.
pub fn started_by_pid1(
    hops: &[(u32, ExecIdentity)],
    facts: &[HopFacts],
    n: usize,
    owned: &dyn Fn(&Path) -> Option<bool>,
) -> bool {
    let Some((_, id)) = hops.get(n) else {
        return false;
    };
    id.runs == Runs::Code
        && is_interpreter(&id.exe)
        && owned_file(&id.exe, owned)
        && facts.get(n).is_some_and(|f| f.fork_parent == 1)
}

/// Lot 310b (decided 12/11/2026): the user's manager at hop `n` vouches for
/// the process it started (hop `n - 1`) when that process is the unit's
/// own — the manager FORKED it, for its first exec — and the unit's file is
/// root's and a package's ([`HopFacts::packaged_user_unit`]): the desktop's
/// terminal emulator, its session's services. Never a transient
/// `systemd-run --user` unit, never a unit or drop-in of the user's.
pub fn manager_vouches_for_its_unit(
    hops: &[(u32, ExecIdentity)],
    facts: &[HopFacts],
    n: usize,
) -> bool {
    let (Some((manager, _)), Some(child)) =
        (hops.get(n), n.checked_sub(1).and_then(|c| facts.get(c)))
    else {
        return false;
    };
    child.fork_parent == *manager && child.packaged_user_unit
}

/// Why a hop that is not trusted is not: what it runs is not known, it runs
/// the caller's inline program (lot 310), or no package installed it.
fn not_installed(id: &ExecIdentity) -> &'static str {
    match id.runs {
        Runs::Unknown(_) => "its arguments do not tell what it runs",
        Runs::Code => "it runs an inline program",
        _ => "no package installed it",
    }
}

/// The pure decision. `lineage`: the writer's identity at index 0, then
/// its ancestors nearest first (`None`: unknown). `pid`: the writer.
/// `package_tx`: the writer belongs to a root package transaction. No
/// [`HopFacts`]: no hop is known to be PID 1's or a packaged user unit's
/// ([`judge_with`]).
pub fn judge(
    pid: u32,
    lineage: Option<&[(u32, ExecIdentity)]>,
    package_tx: bool,
    owned: &dyn Fn(&Path) -> Option<bool>,
) -> Judged {
    judge_with(pid, lineage, &[], package_tx, owned)
}

/// [`judge`] with each hop's [`HopFacts`] (`facts[n]` for `lineage[n]`; a
/// hop without any knows nothing): the kernel's fork parents and the
/// host's packaged user units.
pub fn judge_with(
    pid: u32,
    lineage: Option<&[(u32, ExecIdentity)]>,
    facts: &[HopFacts],
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
            program: LINEAGE_UNKNOWN.to_string(),
            why: "its lineage could not be read".to_string(),
        };
    };
    let (_, writer) = &hops[0];
    // BUG-49: the writer and the copies of itself that forked it are judged
    // below ([`packaged`]); every ancestor above them must vouch for it.
    let own = topmost_same(hops, 0);
    if let Some(i) = hops.iter().enumerate().position(|(n, (_, id))| {
        let by_pid1 = n > own && started_by_pid1(hops, facts, n, owned);
        (is_foreign(id) && !by_pid1)
            || (n > own
                && ((!vouches(id, owned) && !by_pid1)
                    || (is_user_manager(hops, n) && !manager_vouches_for_its_unit(hops, facts, n))))
    }) {
        // lot 310: a user's service manager is not what to kill (its whole
        // session's services with it): the unit's process it started is.
        // Its own parent runs the same file (PID 1's systemd), so the hop
        // is taken as is, never climbed to the copies above it.
        let manager = i > 0 && is_user_manager(hops, i);
        let (actor, id) = if manager {
            (hops[i - 1].0, &hops[i].1)
        } else {
            let (a, id) = &hops[topmost_same(hops, i)];
            (*a, id)
        };
        // A foreign writer's shapes add up with its forked workers'; a
        // packaged tool's under a foreign program count for that tool's
        // process alone: two tools a user's script runs one after the
        // other (`tar x` deleting, `rsync --inplace` rewriting) are not one
        // burst. The kill reaches the foreign program either way.
        let key = if i == 0 { actor } else { hops[0].0 };
        let why = if i == 0 {
            not_installed(id).to_string()
        } else if matches!(id.runs, Runs::Unknown(_)) {
            format!(
                "{} was started by {}, whose arguments do not tell what it runs",
                program_of(writer),
                program_of(id)
            )
        } else if manager {
            format!(
                "{} was started by a user's service manager ({}), which runs what the user asks",
                program_of(writer),
                program_of(id)
            )
        } else if id.runs == Runs::Code {
            format!(
                "{} was started by {}, which runs an inline program",
                program_of(writer),
                program_of(id)
            )
        } else {
            format!(
                "{} was started by {}, which no package installed",
                program_of(writer),
                program_of(id)
            )
        };
        return Judged::Untrusted {
            actor,
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
        why: if writer.interprets() {
            "an interpreter running an inline program or an unpackaged script".to_string()
        } else {
            not_installed(writer).to_string()
        },
    }
}

/// The hop above `i` up to which every ancestor runs the program `i` runs:
/// a payload's forked workers count against the payload.
pub fn topmost_same(hops: &[(u32, ExecIdentity)], i: usize) -> usize {
    let mut top = i;
    while top + 1 < hops.len() && hops[top + 1].1 == hops[i].1 {
        top += 1;
    }
    top
}

/// Who installed a program file: the host's package database. On Debian
/// and its family the `.list` files of `/var/lib/dpkg/info`, searched for
/// the path and remembered until `/var/lib/dpkg/status` changes; on the RPM
/// family `rpm -qf` (the system directories' `rpm`, the host's: the agent's
/// `trusted_bin`). `/snap/` and `/nix/store/` are read-only images
/// their package manager mounted: owned by construction. Paths are compared
/// with `/usr` dropped (merged `/usr`). The model is R018's
/// [`crate::decision::rules::module_provenance`], for executables.
///
/// R08b (lab PR 251): `H` is the host whose `rpm` it asks and whose work
/// it keeps off the async runtime ([`DecisionHost`]; the agent's is
/// `LinuxHost`).
pub struct ProgramOwners<H: DecisionHost> {
    /// `/` in production; a fixture tree in tests.
    root: PathBuf,
    /// Answers by path, and the dpkg status mtime they were read at.
    cache: Mutex<OwnersCache>,
    host: PhantomData<fn() -> H>,
}

/// The answers by path, and the dpkg status mtime they were read at.
type OwnersCache = (Option<SystemTime>, HashMap<String, Option<bool>>);

/// Cached answers before the cache starts over.
const OWNERS_CACHE_CAP: usize = 1024;

impl<H: DecisionHost> Default for ProgramOwners<H> {
    fn default() -> Self {
        Self::new(H::HOST_ROOT)
    }
}

impl<H: DecisionHost> ProgramOwners<H> {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            cache: Mutex::new((None, HashMap::new())),
            host: PhantomData,
        }
    }

    /// The root whose package database it reads (lot 282: the replays
    /// give the security-tool detector the same fixture).
    pub fn root(&self) -> &Path {
        &self.root
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
        let answer = H::off_the_runtime(|| self.lookup(&text, &key));
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
            return rpm_owns::<H>(path);
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
        // lot 311 (bug hunt 1.4, F4, BUG-105's sibling): read as bytes — a
        // package that ships one file whose name is not UTF-8 had its whole
        // list skipped, every file of it unowned
        let Ok(text) = std::fs::read(entry.path()).map(crate::posture::host::state_text) else {
            continue;
        };
        if text.lines().any(|l| without_usr(l) == key) {
            return true;
        }
    }
    false
}

/// `rpm -qf --quiet PATH`, as R018 asks it.
fn rpm_owns<H: DecisionHost>(path: &str) -> Option<bool> {
    H::rpm_owns(path).ok().flatten()
}

/// `/usr/bin/x` → `/bin/x`.
fn without_usr(path: &str) -> String {
    path.strip_prefix("/usr").unwrap_or(path).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    // R08b (lab PR 251): on the portable test host.
    use crate::posture::host::testing::TestHost as H;
    type ProgramOwners = super::ProgramOwners<H>;

    fn id(exe: &str, script: Option<&str>) -> ExecIdentity {
        ExecIdentity {
            exe: PathBuf::from(exe),
            runs: script.map_or(Runs::Inline, |s| Runs::Script(s.into())),
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

    // ── Lot 292 (external bug hunt, editions 1.2/1.3): BUG-49, and what
    // BUG-42/BUG-44 feed ───────────────────────────────────────────────

    /// BUG-49: `openssl` started by a binary no package installed, in `/opt`
    /// or `/usr/local` (the module doc: "a packaged tool started by such a
    /// program" is judged), counts against that binary.
    #[test]
    fn packaged_tool_under_unpackaged_opt_binary_is_judged() {
        let mut wrong = Vec::new();
        for dropped in ["/opt/x/locker", "/usr/local/bin/locker"] {
            let l = [
                (400, id("/usr/bin/openssl", None)),
                (300, id(dropped, None)),
                (200, id("/usr/bin/bash", None)),
                (100, id("/usr/sbin/sshd", None)),
            ];
            let got = judge(400, Some(&l), false, &distro);
            if !matches!(
                &got,
                Judged::Untrusted {
                    actor: 300,
                    key: 400,
                    program,
                    ..
                } if program == dropped
            ) {
                wrong.push(format!("{dropped}: {got:?}"));
            }
        }
        // and a script from /usr/local that drives `mv`
        let l = [
            (400, id("/usr/bin/mv", None)),
            (300, id("/usr/bin/bash", Some("/usr/local/bin/enc.sh"))),
            (200, id("/usr/bin/bash", None)),
        ];
        let got = judge(400, Some(&l), false, &distro);
        if !matches!(
            &got,
            Judged::Untrusted {
                actor: 300,
                key: 400,
                ..
            }
        ) {
            wrong.push(format!("/usr/local/bin/enc.sh: {got:?}"));
        }
        assert!(wrong.is_empty(), "{wrong:?}");
    }

    /// Lot 310, the review of #539 (finding 7): a user's service manager
    /// (`systemd --user`, the systemd file at a pid other than 1) runs what
    /// the user asks — `systemd-run --user /usr/bin/openssl enc …` was a
    /// lineage of installed programs end to end. It vouches for nothing; the
    /// process it started is the actor (never the manager, never PID 1 above
    /// it, which runs the same file), and PID 1's units still vouch.
    #[test]
    fn a_user_s_service_manager_vouches_for_nothing() {
        let systemd = || id("/usr/lib/systemd/systemd", None);
        let l = [
            (500, id("/usr/bin/openssl", None)),
            (1200, systemd()),
            (1, systemd()),
        ];
        match judge(500, Some(&l), false, &distro) {
            Judged::Untrusted {
                actor,
                key,
                program,
                why,
            } => {
                assert_eq!((actor, key), (500, 500));
                assert_eq!(program, "/usr/lib/systemd/systemd");
                assert!(why.contains("a user's service manager"), "{why}");
            }
            other => panic!("{other:?}"),
        }
        // its forked workers: the topmost copy of the program it started
        let l = [
            (502, id("/usr/bin/openssl", None)),
            (500, id("/usr/bin/openssl", None)),
            (1200, systemd()),
            (1, systemd()),
        ];
        assert!(matches!(
            judge(502, Some(&l), false, &distro),
            Judged::Untrusted {
                actor: 500,
                key: 502,
                ..
            }
        ));
        // `/lib/systemd/systemd` (a split `/usr`) is the same manager
        let l = [
            (500, id("/usr/bin/openssl", None)),
            (1200, id("/lib/systemd/systemd", None)),
            (1, id("/lib/systemd/systemd", None)),
        ];
        assert!(matches!(
            judge(500, Some(&l), false, &distro),
            Judged::Untrusted { actor: 500, .. }
        ));
        // PID 1's unit
        let l = [(500, id("/usr/bin/openssl", None)), (1, systemd())];
        assert_eq!(
            judge(500, Some(&l), false, &distro),
            Judged::Trusted(Trusted::PackagedProgram("/usr/bin/openssl".into()))
        );
        let under_pid1 = |id: ExecIdentity| [(1200, id), (1, systemd())];
        assert!(is_user_manager(&under_pid1(systemd()), 0));
        assert!(!is_user_manager(&under_pid1(systemd()), 1), "PID 1");
        assert!(!is_user_manager(&under_pid1(id("/usr/bin/bash", None)), 0));
        assert!(!is_user_manager(
            &under_pid1(id("/usr/lib/systemd/systemd", Some("/tmp/x"))),
            0
        ));
        assert!(
            is_user_manager(&[(1200, systemd())], 0),
            "a parent not known"
        );
        assert!(is_user_manager(
            &under_pid1(id("/lib/systemd/systemd", None)),
            0
        ));
        // a container's systemd: its parent a container runtime, which is
        // judged as every hop is (here installed: the lineage vouches)
        let l = [
            (500, id("/usr/bin/openssl", None)),
            (1200, systemd()),
            (1100, id("/usr/bin/conmon", None)),
            (1, systemd()),
        ];
        assert!(!is_user_manager(&l, 1));
        assert!(matches!(
            judge(500, Some(&l), false, &distro),
            Judged::Trusted(_)
        ));
    }

    /// Lot 310, the review of #539 (the refinement the lab's measure called
    /// for): a unit's `ExecStart=/bin/sh -c 'tar …'` — the inline shell PID 1
    /// started — vouches as PID 1 does; the same shell under a user's
    /// manager, under cron or sshd, or a shell no package installed, does
    /// not; the shell as the writer is judged.
    #[test]
    fn an_inline_shell_pid_1_started_inherits_its_vouching() {
        let sh = || {
            ExecIdentity::of_exec(
                "/usr/bin/dash",
                &["sh".to_string(), "-c".into(), "tar czf x y".into()],
            )
        };
        let systemd = || id("/usr/lib/systemd/systemd", None);
        let l = [(400, id("/usr/bin/tar", None)), (300, sh()), (1, systemd())];
        // the re-check of #539 (N2): PID 1 FORKED the shell, the kernel's
        // record of its first exec
        let forked = |by: u32| {
            [
                HopFacts::default(),
                HopFacts {
                    fork_parent: by,
                    ..HopFacts::default()
                },
            ]
        };
        assert_eq!(
            judge_with(400, Some(&l), &forked(1), false, &distro),
            Judged::Trusted(Trusted::PackagedProgram("/usr/bin/tar".into()))
        );
        assert!(started_by_pid1(&l, &forked(1), 1, &distro));
        // the reviewer's double fork: the webshell's `sh -c '(sleep 1; exec
        // sh -c "openssl enc …") & exit'` — PID 1 reaps the orphan before
        // its exec, but the webshell forked it; and a fork not known
        for by in [250, 0] {
            assert!(
                matches!(
                    judge_with(400, Some(&l), &forked(by), false, &distro),
                    Judged::Untrusted { actor: 300, .. }
                ),
                "forked by {by}"
            );
        }
        assert!(matches!(
            judge(400, Some(&l), false, &distro),
            Judged::Untrusted { actor: 300, .. }
        ));
        // the shell's own writes: judged
        assert!(matches!(
            judge_with(300, Some(&l[1..]), &forked(1)[1..], false, &distro),
            Judged::Untrusted { actor: 300, .. }
        ));
        for l in [
            // a user's manager
            vec![
                (400, id("/usr/bin/tar", None)),
                (300, sh()),
                (1200, systemd()),
                (1, systemd()),
            ],
            // cron (a user's crontab or the system's: no owner here)
            vec![
                (400, id("/usr/bin/tar", None)),
                (300, sh()),
                (250, id("/usr/sbin/cron", None)),
                (200, id("/usr/sbin/cron", None)),
                (1, systemd()),
            ],
            // sshd's bash -c
            vec![
                (400, id("/usr/bin/tar", None)),
                (300, sh()),
                (250, id("/usr/sbin/sshd", None)),
                (1, systemd()),
            ],
            // a shell no package installed
            vec![
                (400, id("/usr/bin/tar", None)),
                (
                    300,
                    ExecIdentity::of_exec(
                        "/opt/x/sh",
                        &["sh".to_string(), "-c".into(), "x".into()],
                    ),
                ),
                (1, systemd()),
            ],
        ] {
            assert!(
                matches!(
                    // the shell forked by its parent there (cron's child,
                    // sshd, a user's manager, PID 1 for the unpackaged one)
                    judge_with(400, Some(&l), &forked(l[2].0), false, &distro),
                    Judged::Untrusted { actor: 300, .. }
                ),
                "{l:?}"
            );
        }
    }

    /// Lot 310b (folded into lot 310): the desktop's cascade. A user's
    /// manager vouches for the process it FORKED for a packaged user unit
    /// (the kernel's record, and the unit's file root's and a package's):
    /// the GNOME terminal's server, then the interactive shell in it, then
    /// the user's `tar` — trusted, as before the decision. The same chain
    /// with a transient `systemd-run --user` unit or the user's own unit
    /// (not packaged), or a server the manager did not fork for its first
    /// exec (not known: a session older than the agent), is judged; the
    /// actor is the process the manager started.
    #[test]
    fn a_user_s_manager_vouches_for_its_packaged_units_only() {
        let systemd = || id("/usr/lib/systemd/systemd", None);
        let bash_i = ExecIdentity::of_exec("/usr/bin/bash", &["bash".to_string()]);
        let l = [
            (500, id("/usr/bin/tar", None)),
            (450, bash_i),
            (400, id("/usr/libexec/gnome-terminal-server", None)),
            (1200, systemd()),
            (1, systemd()),
        ];
        let facts = |forker: u32, packaged: bool| {
            vec![
                HopFacts::default(),
                HopFacts {
                    fork_parent: 400,
                    ..HopFacts::default()
                },
                HopFacts {
                    fork_parent: forker,
                    packaged_user_unit: packaged,
                },
            ]
        };
        let owned = |p: &Path| {
            Some(
                p.starts_with("/usr/bin")
                    || p.starts_with("/usr/lib")
                    || p.starts_with("/usr/libexec"),
            )
        };
        assert_eq!(
            judge_with(500, Some(&l), &facts(1200, true), false, &owned),
            Judged::Trusted(Trusted::PackagedProgram("/usr/bin/tar".into()))
        );
        assert!(manager_vouches_for_its_unit(&l, &facts(1200, true), 3));
        for (forker, packaged) in [(1200, false), (0, true), (450, true)] {
            assert!(
                matches!(
                    judge_with(500, Some(&l), &facts(forker, packaged), false, &owned),
                    Judged::Untrusted { actor: 400, .. }
                ),
                "forked by {forker}, packaged {packaged}"
            );
        }
        // `systemd-run --user /usr/bin/openssl enc …`: a transient unit
        let l = [
            (500, id("/usr/bin/openssl", None)),
            (1200, systemd()),
            (1, systemd()),
        ];
        let f = [HopFacts {
            fork_parent: 1200,
            packaged_user_unit: false,
        }];
        assert!(matches!(
            judge_with(500, Some(&l), &f, false, &owned),
            Judged::Untrusted { actor: 500, .. }
        ));
    }

    /// Lot 310 (BUG-49, the decision of 11/11/2026): an interpreter running
    /// an inline program or its standard input vouches for nothing — the
    /// LOTL ransomware of the triage, a webshell's `sh -c 'openssl enc …'`,
    /// is judged, and the kill reaches the inline shell. A package
    /// transaction stays trusted, as before.
    #[test]
    fn an_inline_program_vouches_for_nothing() {
        let inline = |exe: &str, a: &[&str]| {
            ExecIdentity::of_exec(exe, &a.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        };
        for (shell, program) in [
            (
                inline("/usr/bin/dash", &["sh", "-c", "openssl enc -in x"]),
                "/usr/bin/dash",
            ),
            (
                inline("/usr/bin/bash", &["bash", "-ec", "gpg -c x"]),
                "/usr/bin/bash",
            ),
            (inline("/usr/bin/bash", &["bash", "-s"]), "/usr/bin/bash"),
            (
                inline("/usr/bin/python3.12", &["python3", "-c", "import os"]),
                "/usr/bin/python3.12",
            ),
            (
                inline("/usr/bin/perl", &["perl", "-e", "system 1"]),
                "/usr/bin/perl",
            ),
            (
                inline("/usr/bin/node", &["node", "--eval=x"]),
                "/usr/bin/node",
            ),
            (inline("/bin/busybox", &["sh", "-c", "x"]), "/bin/busybox"),
        ] {
            assert!(is_foreign(&shell), "{shell:?}");
            assert!(!vouches(&shell, &distro), "{shell:?}");
            let l = [
                (400, id("/usr/bin/openssl", None)),
                (300, shell.clone()),
                (250, id("/usr/sbin/php-fpm8.2", None)),
                (1, id("/usr/lib/systemd/systemd", None)),
            ];
            // (the messages name what was expected, not the verdict: CodeQL's
            // cleartext-logging query reads a `Trusted` value as sensitive)
            let got = judge(400, Some(&l), false, &distro);
            assert!(
                matches!(
                    &got,
                    Judged::Untrusted { actor: 300, key: 400, program: p, why }
                        if p == program && why.ends_with("which runs an inline program")
                ),
                "{shell:?}: expected judged, actor 300 (the inline shell), key 400"
            );
            // the inline shell itself as the writer
            assert!(matches!(
                judge(300, Some(&l[1..]), false, &distro),
                Judged::Untrusted { actor: 300, .. }
            ));
            // a package transaction is trusted, as before
            assert_eq!(
                judge(400, Some(&l), true, &distro),
                Judged::Trusted(Trusted::PackageTransaction)
            );
        }
    }

    /// BUG-49, what keeps vouching: an interactive shell a package
    /// installed, a packaged daemon, a packaged script; and with no package
    /// database to ask, a root-owned tree, as before. An interpreter no
    /// package installed vouches for nothing, even running no script. Lot
    /// 310: `bash -c x` left this list (the decision of 11/11/2026, below:
    /// [`an_inline_program_vouches_for_nothing`]); a login shell (`-bash`,
    /// `bash -l`, `bash -i`) stays in it.
    #[test]
    fn an_installed_shell_and_packaged_programs_still_vouch() {
        for shell in [
            id("/usr/bin/bash", None),
            id("/usr/bin/dash", None),
            ExecIdentity::of_exec("/usr/bin/bash", &["-bash".to_string()]),
            ExecIdentity::of_exec("/usr/bin/bash", &["bash".to_string(), "-l".into()]),
            ExecIdentity::of_exec("/usr/bin/bash", &["bash".to_string(), "-i".into()]),
        ] {
            let l = [
                (400, id("/usr/bin/openssl", None)),
                (300, shell.clone()),
                (200, id("/usr/sbin/sshd", None)),
                (1, id("/usr/lib/systemd/systemd", None)),
            ];
            assert_eq!(
                judge(400, Some(&l), false, &distro),
                Judged::Trusted(Trusted::PackagedProgram("/usr/bin/openssl".into())),
                "{shell:?}"
            );
        }
        let l = [
            (400, id("/usr/bin/tar", None)),
            (300, id("/usr/bin/python3", Some("/usr/lib/borg/backup.py"))),
            (1, id("/usr/lib/systemd/systemd", None)),
        ];
        assert!(matches!(
            judge(400, Some(&l), false, &distro),
            Judged::Trusted(_)
        ));
        // no package database: a root-owned tree stands in, as before
        let none = |_: &Path| None;
        let l = [
            (400, id("/usr/bin/openssl", None)),
            (300, id("/opt/x/locker", None)),
        ];
        assert!(matches!(
            judge(400, Some(&l), false, &none),
            Judged::Trusted(_)
        ));
        // a shell no package installed
        let l = [
            (400, id("/usr/bin/openssl", None)),
            (300, id("/usr/local/bin/bash", None)),
            (200, id("/usr/sbin/sshd", None)),
        ];
        assert!(matches!(
            judge(400, Some(&l), false, &distro),
            Judged::Untrusted {
                actor: 300,
                key: 400,
                ..
            }
        ));
        // a payload's forked copies are its own program, not ancestors
        let l = [
            (402, id("/usr/bin/tar", None)),
            (401, id("/usr/bin/tar", None)),
            (300, id("/usr/bin/bash", None)),
        ];
        assert!(matches!(
            judge(402, Some(&l), false, &distro),
            Judged::Trusted(_)
        ));
    }

    /// BUG-42 downstream: a script run under errexit (`bash -e /tmp/enc.sh`,
    /// identity as the exec event builds it) names its script and vouches
    /// for none of the packaged tools it drives.
    #[test]
    fn errexit_script_does_not_vouch_for_its_tools() {
        let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let l = [
            (400, id("/usr/bin/openssl", None)),
            (
                300,
                ExecIdentity::of_exec("/usr/bin/bash", &args(&["bash", "-e", "/tmp/enc.sh"])),
            ),
            (200, id("/usr/bin/bash", None)),
        ];
        let got = judge(400, Some(&l), false, &distro);
        // (the messages name what was expected, not the verdict: CodeQL's
        // cleartext-logging query reads a `Trusted` value as sensitive)
        assert!(
            matches!(&got, Judged::Untrusted { actor: 300, program, .. } if program == "/tmp/enc.sh"),
            "openssl under `bash -e /tmp/enc.sh` is judged against the script"
        );
    }

    /// BUG-44 downstream: `python3 -O /tmp/enc.py /usr/bin/tar` — the
    /// writer's identity is the script it runs, not a packaged file it
    /// names; and one whose options cannot be read is no packaged program
    /// and vouches for nothing.
    #[test]
    fn python_dash_o_writer_is_not_a_packaged_program() {
        let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let l = [
            (
                300,
                ExecIdentity::of_exec(
                    "/usr/bin/python3",
                    &args(&["python3", "-O", "/tmp/enc.py", "/usr/bin/tar"]),
                ),
            ),
            (200, id("/usr/bin/bash", None)),
            (150, id("/usr/sbin/sshd", None)),
        ];
        let got = judge(300, Some(&l), false, &distro);
        assert!(
            matches!(&got, Judged::Untrusted { actor: 300, .. }),
            "`python3 -O /tmp/enc.py /usr/bin/tar` is judged"
        );
        let unknown = ExecIdentity::of_exec(
            "/usr/bin/python3",
            &args(&["python3", "-Z", "/usr/bin/tar"]),
        );
        let l = [(300, unknown.clone()), (200, id("/usr/bin/bash", None))];
        match judge(300, Some(&l), false, &distro) {
            Judged::Untrusted { actor, why, .. } => {
                assert_eq!(
                    (actor, why.as_str()),
                    (300, "its arguments do not tell what it runs")
                )
            }
            Judged::Trusted(_) => panic!("an unread writer is judged"),
        }
        let l = [
            (400, id("/usr/bin/openssl", None)),
            (300, unknown),
            (200, id("/usr/bin/bash", None)),
        ];
        match judge(400, Some(&l), false, &distro) {
            Judged::Untrusted {
                actor, key, why, ..
            } => {
                assert_eq!((actor, key), (300, 400));
                assert!(
                    why.contains("whose arguments do not tell what it runs"),
                    "the reason names the unread ancestor"
                );
            }
            Judged::Trusted(_) => panic!("a tool under an unread ancestor is judged"),
        }
    }

    /// Lot 311 (F4): a package whose list names one file that is not UTF-8
    /// still owns its other files (on main the whole list was skipped).
    #[test]
    fn a_list_with_a_non_utf8_name_still_owns_its_other_files() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(
            d.path().join("pkg.list"),
            b"/usr/share/doc/pkg/caf\xe9.txt\n/usr/bin/pkgtool\n",
        )
        .unwrap();
        assert!(dpkg_lists(d.path(), "/bin/pkgtool"));
        assert!(!dpkg_lists(d.path(), "/bin/other"));
    }
}
