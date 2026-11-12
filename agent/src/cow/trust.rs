//! Which writers the guard copies for: the trust filter.
//!
//! A writer's trust is established by what the kernel executed — the
//! process's `/proc/<pid>/exe` (or the script an interpreter runs) and the
//! same for every ancestor on the ordered lineage walk of
//! [`crate::posture::lineage::AuthSessionTracker`] — never by `comm`, which
//! a process sets for itself. A writer is trusted, and its opens are not
//! copied, when:
//!
//! - it belongs to a package transaction run by root
//!   ([`AuthSessionTracker::in_package_transaction`], the posture's and the
//!   FIM rules' own test), or
//! - it is a trusted writer — an entry of [`BUILTIN_TRUSTED_WRITERS`] or of
//!   the signed overlay's `trusted_writer` lines, matched by
//!   [`ExecIdentity::is_client`] (exe in a root-owned system tree) — **and**
//!   every ancestor up to PID 1 vouches for it
//!   ([`crate::impact::trust::vouches`], lot 292, BUG-49): a program a
//!   package installed (the host's package database, as the ransomware
//!   signal asks it; without one, a root-owned system tree stands in), or an
//!   interpreter a package installed running no program at all (an
//!   interactive shell). Lot 310 (BUG-49): one running an inline program
//!   (`sh -c`) or its standard input vouches for nothing — the ransomware
//!   signal's one test ([`crate::impact::trust::is_foreign`]), the twin this
//!   file kept until then. An editor started by a script from a home
//!   directory, by a binary from `/tmp`, `/opt` or `/usr/local` that no
//!   package installed, by an interpreter whose options could not be read
//!   (lot 292, BUG-44) or by a deleted executable is not trusted: what
//!   started it is not known to be the user's own hand. The copies of the
//!   writer itself that forked it are its own program, not ancestors.
//!
//! Everything else is untrusted, including a lineage the walk cannot read
//! (fail toward copying). Interpreters are refused as trusted writers:
//! `python3` with no script would trust every `python3 -c`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use parking_lot::Mutex;

use crate::impact::trust::{
    is_user_manager, started_by_pid1, topmost_same, vouches, HopFacts, ProgramOwners,
};
use crate::posture::lineage::{
    in_system_tree, is_interpreter, AsOf, AuthSessionTracker, ExecIdentity,
};

/// Editors and the version-control client: programs a person runs to
/// change their own files. Generic tools (`cp`, `dd`, `tar`, `rsync`,
/// `openssl`, `gpg`, `sed`) are not: they are what an intruder rewrites
/// files with. An operator adds a program in `cow-guard.local`
/// (`trusted_writer = name`), knowing that its writes are then not copied.
pub const BUILTIN_TRUSTED_WRITERS: &[&str] = &[
    "vim",
    "vim.basic",
    "vim.tiny",
    "vim.gtk3",
    "nvim",
    "nano",
    "emacs",
    "gedit",
    "gnome-text-editor",
    "kate",
    "mousepad",
    "soffice.bin",
    "git",
];

/// Entry shape of `trusted_writer`: a program name (no `/`, one token, not
/// an interpreter) or an absolute tree ending in `/` inside a root-owned
/// system tree that only that program installs.
pub fn validate_writer(entry: &str) -> Result<()> {
    if entry.is_empty() || entry.split_whitespace().count() != 1 {
        return Err(anyhow!(
            "a trusted writer is one whitespace-free token (got `{entry}`)"
        ));
    }
    if entry.contains('/') {
        if !(entry.ends_with('/') && in_system_tree(entry)) {
            return Err(anyhow!(
                "a trusted writer is a program name or a system tree ending in `/` \
                 (/usr/, /opt/, …) — got `{entry}`"
            ));
        }
        return Ok(());
    }
    if is_interpreter(Path::new(entry)) {
        return Err(anyhow!(
            "`{entry}` is an interpreter: what it writes is decided by its arguments \
             (name the script instead)"
        ));
    }
    Ok(())
}

/// Why a writer is trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trusted {
    /// A package transaction run by root.
    PackageTransaction,
    /// A trusted writer with a lineage of installed programs; its program.
    Writer(String),
}

/// Why a writer is not trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Untrusted {
    /// Not a trusted writer (its program).
    NotATrustedWriter(String),
    /// A trusted writer started, directly or not, by a foreign program.
    ForeignAncestor { writer: String, ancestor: String },
    /// The lineage could not be read (the process or a parent exited
    /// before its exec event was read, or `/proc` refused).
    LineageUnknown,
}

/// The filter's verdict on one writer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trust {
    Trusted(Trusted),
    Untrusted(Untrusted),
}

impl Trust {
    pub fn is_trusted(&self) -> bool {
        matches!(self, Trust::Trusted(_))
    }

    /// One line for the journal and the index.
    pub fn describe(&self) -> String {
        match self {
            Trust::Trusted(Trusted::PackageTransaction) => "package transaction".into(),
            Trust::Trusted(Trusted::Writer(p)) => format!("trusted writer {p}"),
            Trust::Untrusted(Untrusted::NotATrustedWriter(p)) => {
                format!("not a trusted writer ({p})")
            }
            Trust::Untrusted(Untrusted::ForeignAncestor { writer, ancestor }) => {
                format!("{writer} started by {ancestor}")
            }
            Trust::Untrusted(Untrusted::LineageUnknown) => "lineage unknown".into(),
        }
    }
}

/// The program an identity names, for the record: the script an
/// interpreter runs, else the executable ([`ExecIdentity::program`]).
pub fn program_of(id: &ExecIdentity) -> String {
    id.program()
}

/// A hop that vouches for nothing below it: the ransomware signal's test
/// ([`crate::impact::trust::is_foreign`]; lot 310: this file's twin of it
/// is gone). Lot 292 (BUG-44): an interpreter whose options could not be
/// read is one; lot 310 (BUG-49): so is one running an inline program.
pub use crate::impact::trust::is_foreign;

/// The pure decision. `lineage`: the writer's identity at index 0, then its
/// ancestors nearest first (`None`: unknown). `writers`: the trusted-writer
/// entries. `package_tx`: the writer belongs to a root package transaction.
/// `owned`: who installed a file, from the package database (`None`: no
/// database to ask).
pub fn judge(
    lineage: Option<&[(u32, ExecIdentity)]>,
    writers: &[&str],
    package_tx: bool,
    owned: &dyn Fn(&Path) -> Option<bool>,
) -> Trust {
    judge_with(lineage, &[], writers, package_tx, owned)
}

/// [`judge`] with each hop's facts (lot 310: the kernel's fork parents —
/// `crate::impact::trust::HopFacts`; a hop without any knows nothing).
pub fn judge_with(
    lineage: Option<&[(u32, ExecIdentity)]>,
    facts: &[HopFacts],
    writers: &[&str],
    package_tx: bool,
    owned: &dyn Fn(&Path) -> Option<bool>,
) -> Trust {
    if package_tx {
        return Trust::Trusted(Trusted::PackageTransaction);
    }
    let Some(hops) = lineage else {
        return Trust::Untrusted(Untrusted::LineageUnknown);
    };
    let Some((_, writer)) = hops.first() else {
        return Trust::Untrusted(Untrusted::LineageUnknown);
    };
    let program = program_of(writer);
    if !writer.is_client(writers) {
        return Trust::Untrusted(Untrusted::NotATrustedWriter(program));
    }
    // BUG-49: the copies of the writer that forked it are its own program;
    // every ancestor above them must vouch for it.
    let own = topmost_same(hops, 0);
    if let Some((_, foreign)) = hops
        .iter()
        .enumerate()
        .skip(1)
        .find(|(n, (_, id))| {
            let by_pid1 = *n > own && started_by_pid1(hops, facts, *n, owned);
            (is_foreign(id) && !by_pid1)
                || (*n > own && ((!vouches(id, owned) && !by_pid1) || is_user_manager(hops, *n)))
        })
        .map(|(_, hop)| hop)
    {
        return Trust::Untrusted(Untrusted::ForeignAncestor {
            writer: program,
            ancestor: program_of(foreign),
        });
    }
    Trust::Trusted(Trusted::Writer(program))
}

/// A process, as the journal names it: its pid and its start (field 22 of
/// `/proc/<pid>/stat`, clock ticks since boot; 0 when unknown).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct ProcId {
    pub pid: u32,
    pub start: u64,
}

/// What the filter knows about a writer: its verdict, its program and its
/// lineage as process identities (writer first).
#[derive(Debug, Clone)]
pub struct WriterInfo {
    pub trust: Trust,
    pub program: String,
    pub lineage: Vec<ProcId>,
}

/// A verdict's cache key: the process and the executable it runs.
type CacheKey = (ProcId, PathBuf);

/// Cache lifetime of a verdict.
const CACHE_TTL: Duration = Duration::from_secs(10);
/// Cache size bound.
const CACHE_CAP: usize = 4096;

/// The production filter: the built-in and configured writers, the lineage
/// tracker the agent feeds from exec events, and a short cache keyed by the
/// process identity and its executable (an exec keeps the start time).
pub struct TrustFilter {
    writers: Vec<String>,
    tracker: AuthSessionTracker,
    /// Lot 292 (BUG-49): who installed an ancestor's program.
    owners: ProgramOwners,
    proc_root: PathBuf,
    cache: Mutex<HashMap<CacheKey, (Instant, std::sync::Arc<WriterInfo>)>>,
}

impl TrustFilter {
    pub fn new(extra: &[String], tracker: AuthSessionTracker) -> Self {
        let mut writers: Vec<String> = BUILTIN_TRUSTED_WRITERS
            .iter()
            .map(|s| s.to_string())
            .collect();
        writers.extend(extra.iter().cloned());
        Self {
            writers,
            tracker,
            owners: ProgramOwners::default(),
            proc_root: PathBuf::from("/proc"),
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// The package database of `owners` in place of the host's (tests).
    #[cfg(test)]
    fn with_owners(mut self, owners: ProgramOwners) -> Self {
        self.owners = owners;
        self
    }

    /// The trusted-writer entries in force.
    pub fn writers(&self) -> &[String] {
        &self.writers
    }

    /// Judge process `tgid` (start `start`). Reads the spawn cache and
    /// `/proc` only.
    pub fn evaluate(&self, tgid: u32, start: u64) -> std::sync::Arc<WriterInfo> {
        let exe = std::fs::read_link(self.proc_root.join(tgid.to_string()).join("exe"))
            .unwrap_or_default();
        let key = (ProcId { pid: tgid, start }, exe);
        let now = Instant::now();
        if let Some((at, info)) = self.cache.lock().get(&key) {
            if now.duration_since(*at) < CACHE_TTL {
                return std::sync::Arc::clone(info);
            }
        }
        // The fanotify reader judges the writer now, at its open (no event
        // of the bus: `AsOf::Now`, `/proc` on a cache miss).
        let lineage = self.tracker.lineage_identities(tgid, AsOf::Now);
        let writers: Vec<&str> = self.writers.iter().map(String::as_str).collect();
        let owned = |p: &Path| self.owners.owned(p);
        // lot 310: the kernel's fork parents
        let facts = lineage.as_deref().map_or_else(Vec::new, |hops| {
            crate::impact::trust::hop_facts(&self.tracker, tgid, AsOf::Now, hops)
        });
        let trust = judge_with(
            lineage.as_deref(),
            &facts,
            &writers,
            self.tracker.in_package_transaction(tgid, AsOf::Now),
            &owned,
        );
        let program = lineage
            .as_ref()
            .and_then(|l| l.first())
            .map(|(_, id)| program_of(id))
            .unwrap_or_else(|| key.1.to_string_lossy().into_owned());
        let mut ids = vec![ProcId { pid: tgid, start }];
        if let Some(l) = &lineage {
            ids.extend(l.iter().skip(1).map(|(pid, _)| ProcId {
                pid: *pid,
                start: proc_start_ticks(&self.proc_root, *pid).unwrap_or(0),
            }));
        }
        let info = std::sync::Arc::new(WriterInfo {
            trust,
            program,
            lineage: ids,
        });
        let mut cache = self.cache.lock();
        if cache.len() >= CACHE_CAP {
            cache.retain(|_, (at, _)| now.duration_since(*at) < CACHE_TTL);
            if cache.len() >= CACHE_CAP {
                cache.clear();
            }
        }
        cache.insert(key, (now, std::sync::Arc::clone(&info)));
        info
    }
}

/// `starttime`, field 22 of `/proc/<pid>/stat` (after the `(comm)` field,
/// which may hold spaces or parentheses).
pub fn proc_start_ticks(proc_root: &Path, pid: u32) -> Option<u64> {
    // lot 311 (N6; the re-check of #542): read as bytes — a writer's `comm`
    // is its own choice; read strictly, a writer named `\xff\xfe` was "not
    // alive" and the in-place restore ran while it still wrote. The one
    // conversion, `nn_linux::state_read::read_state`'s own: this module is
    // in nn-core's layer (`xtask/tests/module_map.rs`), so not through
    // nn-linux
    let stat = std::fs::read(proc_root.join(pid.to_string()).join("stat"))
        .map(nn_core::posture::host::state_text)
        .ok()?;
    parse_stat_start(&stat)
}

/// Field 22 of a `/proc/<pid>/stat` body.
pub fn parse_stat_start(stat: &str) -> Option<u64> {
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::posture::lineage::Runs;

    fn id(exe: &str, script: Option<&str>) -> ExecIdentity {
        ExecIdentity {
            exe: PathBuf::from(exe),
            runs: script.map_or(Runs::Inline, |s| Runs::Script(s.into())),
        }
    }

    /// A package database that installed `/usr/bin/*`, `/usr/sbin/*` and
    /// `/usr/lib/*`.
    fn distro(p: &Path) -> Option<bool> {
        let s = p.to_string_lossy();
        Some(
            s.starts_with("/usr/bin/") || s.starts_with("/usr/sbin/") || s.starts_with("/usr/lib/"),
        )
    }

    fn writers() -> Vec<&'static str> {
        BUILTIN_TRUSTED_WRITERS.to_vec()
    }

    #[test]
    fn an_editor_from_a_login_shell_is_trusted() {
        let l = [
            (300, id("/usr/bin/vim.basic", None)),
            (200, id("/usr/bin/bash", None)),
            (150, id("/usr/sbin/sshd", None)),
        ];
        assert_eq!(
            judge(Some(&l), &writers(), false, &distro),
            Trust::Trusted(Trusted::Writer("/usr/bin/vim.basic".into()))
        );
        // through sudo and a shell running no program (`sudo -s`); lot 310:
        // `sh -c` vouches for nothing
        // (`an_inline_shell_or_a_misread_bash_does_not_vouch_for_an_editor`)
        let l = [
            (300, id("/usr/bin/git", None)),
            (250, id("/usr/bin/dash", None)),
            (200, id("/usr/bin/sudo", None)),
            (150, id("/usr/bin/bash", None)),
        ];
        assert!(judge(Some(&l), &writers(), false, &distro).is_trusted());
    }

    #[test]
    fn a_tool_that_is_not_a_trusted_writer_is_copied() {
        for exe in [
            "/usr/bin/dd",
            "/usr/bin/openssl",
            "/usr/bin/cp",
            "/usr/bin/bash",
        ] {
            let l = [(300, id(exe, None)), (200, id("/usr/bin/bash", None))];
            assert_eq!(
                judge(Some(&l), &writers(), false, &distro),
                Trust::Untrusted(Untrusted::NotATrustedWriter(exe.into())),
                "{exe}"
            );
        }
        // python running a user's script
        let l = [(300, id("/usr/bin/python3", Some("/home/u/sim.py")))];
        assert!(!judge(Some(&l), &writers(), false, &distro).is_trusted());
    }

    #[test]
    fn a_trusted_writer_started_by_a_foreign_program_is_not_trusted() {
        for (exe, script) in [
            ("/usr/bin/python3", Some("/home/u/ransom.py")),
            ("/usr/bin/bash", Some("./encrypt.sh")),
            ("/tmp/dropper", None),
            ("/home/u/.local/bin/tool", None),
            ("/usr/bin/vim.basic (deleted)", None),
        ] {
            let l = [
                (300, id("/usr/bin/vim.basic", None)),
                (250, id(exe, script)),
                (200, id("/usr/bin/bash", None)),
            ];
            match judge(Some(&l), &writers(), false, &distro) {
                Trust::Untrusted(Untrusted::ForeignAncestor { ancestor, .. }) => {
                    assert_eq!(ancestor, script.unwrap_or(exe))
                }
                other => panic!("{exe}: {other:?}"),
            }
        }
    }

    #[test]
    fn identity_not_comm_decides() {
        // a copy of vim outside the system trees
        let l = [(300, id("/tmp/vim", None))];
        assert!(!judge(Some(&l), &writers(), false, &distro).is_trusted());
        // the lineage cannot be read: copied
        assert_eq!(
            judge(None, &writers(), false, &distro),
            Trust::Untrusted(Untrusted::LineageUnknown)
        );
        assert_eq!(
            judge(Some(&[]), &writers(), false, &distro),
            Trust::Untrusted(Untrusted::LineageUnknown)
        );
    }

    #[test]
    fn a_package_transaction_is_trusted_and_an_operator_entry_counts() {
        let l = [(300, id("/usr/bin/cp", None))];
        assert_eq!(
            judge(Some(&l), &writers(), true, &distro),
            Trust::Trusted(Trusted::PackageTransaction)
        );
        assert_eq!(
            judge(None, &writers(), true, &distro),
            Trust::Trusted(Trusted::PackageTransaction)
        );
        let mut w = writers();
        w.push("rsync");
        let l = [(300, id("/usr/bin/rsync", None))];
        assert!(judge(Some(&l), &w, false, &distro).is_trusted());
        w.push("/opt/editor/");
        let l = [(300, id("/opt/editor/bin/ed2", None))];
        assert!(judge(Some(&l), &w, false, &distro).is_trusted());
    }

    #[test]
    fn foreign_hops() {
        assert!(!is_foreign(&id("/usr/sbin/sshd", None)));
        assert!(!is_foreign(&id("/usr/bin/bash", None)), "interactive shell");
        assert!(!is_foreign(&id(
            "/usr/bin/python3",
            Some("/usr/lib/python3/dist-packages/x.py")
        )));
        assert!(is_foreign(&id("/usr/bin/python3", Some("x.py"))));
        assert!(is_foreign(&id("/home/u/bash", None)));
        assert!(is_foreign(&id("/memfd:x (deleted)", None)));
    }

    #[test]
    fn writer_entries() {
        for ok in [
            "vim",
            "soffice.bin",
            "/opt/editor/",
            "/usr/lib/libreoffice/",
        ] {
            validate_writer(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
        for bad in [
            "",
            "a b",
            "/tmp/x/",
            "/usr/bin/vim",
            "python3",
            "bash",
            "sh",
            "perl5.36",
        ] {
            assert!(validate_writer(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn stat_start() {
        let stat =
            "4242 (a) b (c)) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1 2";
        assert_eq!(parse_stat_start(stat), Some(987654));
        assert_eq!(parse_stat_start("garbage"), None);
    }

    #[test]
    fn the_tracker_walk_gives_the_lineage() {
        let tmp = tempfile::TempDir::new().unwrap();
        let t = AuthSessionTracker::new(tmp.path());
        t.ingest_exec(200, 1, "/usr/bin/bash", &["bash".into()], 10, 5, 1000);
        t.ingest_exec(
            300,
            200,
            "/usr/bin/python3",
            &["python3".into(), "/home/u/sim.py".into()],
            20,
            15,
            1000,
        );
        let l = t.lineage_identities(300, AsOf::Now).unwrap();
        assert_eq!(l.len(), 2);
        assert_eq!(l[0].0, 300);
        assert_eq!(l[0].1.script(), Some("/home/u/sim.py"));
        assert_eq!(l[1].0, 200);
        let f = TrustFilter::new(&[], t.clone());
        let info = f.evaluate(300, 0);
        assert!(!info.trust.is_trusted());
        assert_eq!(info.program, "/home/u/sim.py");
        assert_eq!(info.lineage.len(), 2);
        assert_eq!(info.lineage[1].pid, 200);
    }

    // ── Lot 292 (external bug hunt, editions 1.2/1.3): BUG-42, BUG-44,
    // BUG-49 in the copy guard's filter ──────────────────────────────────

    /// BUG-44: a script that names an editor after itself
    /// (`python3 -O /tmp/enc.py /usr/bin/vim.basic`), or whose options
    /// cannot be read, is no trusted writer: its opens are copied.
    #[test]
    fn a_skipped_script_is_not_a_trusted_writer() {
        let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        for argv in [
            &["python3", "-O", "/tmp/enc.py", "/usr/bin/vim.basic"][..],
            &["perl", "-X", "/tmp/enc.pl", "/usr/bin/vim.basic"],
            &["python3", "-Z", "/usr/bin/vim.basic"],
        ] {
            let exe = if argv[0] == "perl" {
                "/usr/bin/perl"
            } else {
                "/usr/bin/python3"
            };
            let l = [
                (300, ExecIdentity::of_exec(exe, &args(argv))),
                (200, id("/usr/bin/bash", None)),
            ];
            assert!(
                matches!(
                    judge(Some(&l), &writers(), false, &distro),
                    Trust::Untrusted(Untrusted::NotATrustedWriter(_))
                ),
                "{argv:?}"
            );
        }
    }

    /// BUG-42 and BUG-44: an editor started by a script run under errexit
    /// (`bash -e /tmp/enc.sh`) or by an interpreter whose options cannot be
    /// read is started by a foreign program.
    #[test]
    fn an_errexit_script_does_not_vouch_for_an_editor() {
        let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        for (exe, argv, ancestor) in [
            (
                "/usr/bin/bash",
                &["bash", "-e", "/tmp/enc.sh"][..],
                "/tmp/enc.sh",
            ),
            (
                "/usr/bin/bash",
                &["bash", "-euo", "pipefail", "/tmp/enc.sh"],
                "/tmp/enc.sh",
            ),
            (
                "/usr/bin/zsh",
                &["zsh", "-T", "/usr/bin/x", "/tmp/enc.sh"],
                "/usr/bin/zsh /usr/bin/x (options not understood)",
            ),
        ] {
            let l = [
                (300, id("/usr/bin/vim.basic", None)),
                (250, ExecIdentity::of_exec(exe, &args(argv))),
                (200, id("/usr/bin/bash", None)),
            ];
            assert_eq!(
                judge(Some(&l), &writers(), false, &distro),
                Trust::Untrusted(Untrusted::ForeignAncestor {
                    writer: "/usr/bin/vim.basic".into(),
                    ancestor: ancestor.into(),
                }),
                "{argv:?}"
            );
        }
        // an interactive shell still vouches (lot 310: `sh -ec 'vim x'` no
        // longer does, the decision of 11/11/2026 on BUG-49:
        // `an_inline_shell_or_a_misread_bash_does_not_vouch_for_an_editor`)
        let l = [
            (300, id("/usr/bin/vim.basic", None)),
            (
                250,
                ExecIdentity::of_exec("/usr/bin/bash", &args(&["-bash"])),
            ),
            (200, id("/usr/sbin/sshd", None)),
        ];
        assert!(judge(Some(&l), &writers(), false, &distro).is_trusted());
    }

    /// Lot 310, the twin of the ransomware signal's tests: an editor
    /// started by an inline shell (BUG-49, the decision of 11/11/2026), or
    /// by a bash whose one-hyphen long option was read as letters (BUG-97:
    /// `-noprofile`'s two `o` took two arguments and the identity became
    /// `/usr/bin/aws`, an installed program that vouched), or by `zsh -ovi`
    /// (BUG-100) or `node --eval=` (BUG-99), is started by a foreign
    /// program: its writes are copied.
    #[test]
    fn an_inline_shell_or_a_misread_bash_does_not_vouch_for_an_editor() {
        let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        for (exe, argv, ancestor) in [
            (
                "/usr/bin/dash",
                &["sh", "-ec", "vim x"][..],
                "/usr/bin/dash",
            ),
            ("/usr/bin/bash", &["bash", "-s"], "/usr/bin/bash"),
            (
                "/usr/bin/bash",
                &["bash", "-noprofile", "/tmp/steal.sh", "x", "/usr/bin/aws"],
                "/tmp/steal.sh",
            ),
            (
                "/usr/bin/bash",
                &["bash", "-rcfile", "/etc/x", "/tmp/steal.sh"],
                "/tmp/steal.sh",
            ),
            (
                "/usr/bin/zsh",
                &["zsh", "-ovi", "/tmp/steal.zsh", "/usr/bin/aws"],
                "/tmp/steal.zsh",
            ),
            (
                "/usr/bin/node",
                &["node", "--eval=x()", "/usr/bin/aws"],
                "/usr/bin/node",
            ),
            (
                "/usr/bin/node",
                &["node", "--run", "build", "/usr/bin/aws"],
                "/usr/bin/node",
            ),
        ] {
            let l = [
                (300, id("/usr/bin/vim.basic", None)),
                (250, ExecIdentity::of_exec(exe, &args(argv))),
                (200, id("/usr/sbin/sshd", None)),
            ];
            assert_eq!(
                judge(Some(&l), &writers(), false, &distro),
                Trust::Untrusted(Untrusted::ForeignAncestor {
                    writer: "/usr/bin/vim.basic".into(),
                    ancestor: ancestor.into(),
                }),
                "{argv:?}"
            );
        }
    }

    /// Lot 310, the review of #539 (finding 7): an editor a user's service
    /// manager started (`systemd-run --user vim x`: a lineage of installed
    /// programs end to end) is started by a foreign program; one of PID 1's
    /// units is not.
    #[test]
    fn a_user_s_service_manager_does_not_vouch_for_an_editor() {
        let systemd = || id("/usr/lib/systemd/systemd", None);
        let l = [
            (300, id("/usr/bin/vim.basic", None)),
            (1200, systemd()),
            (1, systemd()),
        ];
        assert_eq!(
            judge(Some(&l), &writers(), false, &distro),
            Trust::Untrusted(Untrusted::ForeignAncestor {
                writer: "/usr/bin/vim.basic".into(),
                ancestor: "/usr/lib/systemd/systemd".into(),
            }),
        );
        let l = [(300, id("/usr/bin/vim.basic", None)), (1, systemd())];
        assert!(judge(Some(&l), &writers(), false, &distro).is_trusted());
        // a unit's `sh -c` PID 1 started inherits its vouching; the same
        // shell under the user's manager does not
        let sh = || {
            ExecIdentity::of_exec(
                "/usr/bin/dash",
                &["sh".to_string(), "-c".into(), "vim x".into()],
            )
        };
        let l = [
            (300, id("/usr/bin/vim.basic", None)),
            (250, sh()),
            (1, systemd()),
        ];
        // PID 1 FORKED it (the kernel's record; the re-check of #539, N2)
        let by_pid1 = [
            crate::impact::trust::HopFacts::default(),
            crate::impact::trust::HopFacts { fork_parent: 1 },
        ];
        assert!(judge_with(Some(&l), &by_pid1, &writers(), false, &distro).is_trusted());
        // a shell PID 1 reaped before its exec, another forked: not
        assert!(!judge(Some(&l), &writers(), false, &distro).is_trusted());
        let l = [
            (300, id("/usr/bin/vim.basic", None)),
            (250, sh()),
            (1200, systemd()),
            (1, systemd()),
        ];
        assert!(!judge(Some(&l), &writers(), false, &distro).is_trusted());
    }

    /// BUG-49: an editor started by a binary no package installed, in
    /// `/opt` or `/usr/local`, is started by a foreign program; with no
    /// package database to ask, a root-owned tree stands in, as before.
    #[test]
    fn an_editor_under_an_unpackaged_opt_binary_is_not_trusted() {
        for dropped in ["/opt/x/launcher", "/usr/local/bin/launcher"] {
            let l = [
                (300, id("/usr/bin/vim.basic", None)),
                (250, id(dropped, None)),
                (200, id("/usr/bin/bash", None)),
            ];
            assert_eq!(
                judge(Some(&l), &writers(), false, &distro),
                Trust::Untrusted(Untrusted::ForeignAncestor {
                    writer: "/usr/bin/vim.basic".into(),
                    ancestor: dropped.into(),
                }),
            );
            let none = |_: &Path| None;
            assert!(judge(Some(&l), &writers(), false, &none).is_trusted());
        }
        // an operator's editor tree: its own forked copies are no ancestors
        let w = ["/opt/editor/"];
        let l = [
            (302, id("/opt/editor/bin/ed2", None)),
            (301, id("/opt/editor/bin/ed2", None)),
            (200, id("/usr/bin/bash", None)),
        ];
        assert!(judge(Some(&l), &w, false, &distro).is_trusted());
    }

    /// BUG-49 through the production filter: it asks the package database
    /// it is given (dpkg's lists of a fixture root) for the ancestors.
    #[test]
    fn the_filter_asks_the_package_database_for_the_ancestors() {
        let root = tempfile::TempDir::new().unwrap();
        let info = root.path().join("var/lib/dpkg/info");
        std::fs::create_dir_all(&info).unwrap();
        std::fs::write(root.path().join("var/lib/dpkg/status"), "Package: vim\n").unwrap();
        std::fs::write(info.join("vim.list"), "/usr/bin/vim.basic\n").unwrap();
        std::fs::write(info.join("bash.list"), "/bin/bash\n").unwrap();
        let proc = tempfile::TempDir::new().unwrap();
        let t = AuthSessionTracker::new(proc.path());
        t.ingest_exec(200, 1, "/usr/bin/bash", &["bash".into()], 10, 5, 1000);
        t.ingest_exec(
            250,
            200,
            "/opt/x/launcher",
            &["launcher".into()],
            20,
            15,
            1000,
        );
        t.ingest_exec(
            300,
            250,
            "/usr/bin/vim.basic",
            &["vim".into()],
            30,
            25,
            1000,
        );
        t.ingest_exec(
            400,
            200,
            "/usr/bin/vim.basic",
            &["vim".into()],
            40,
            35,
            1000,
        );
        let f = TrustFilter::new(&[], t).with_owners(ProgramOwners::new(root.path()));
        assert_eq!(
            f.evaluate(300, 0).trust,
            Trust::Untrusted(Untrusted::ForeignAncestor {
                writer: "/usr/bin/vim.basic".into(),
                ancestor: "/opt/x/launcher".into(),
            })
        );
        assert!(f.evaluate(400, 0).trust.is_trusted());
    }

    /// Lot 311 (the re-check of #542): a writer whose `comm` is not UTF-8
    /// (`\xff\xfe`, the name of the file it executed) has its start read
    /// and is alive for the restore — read strictly, its `stat` was refused
    /// and the writer "not alive": the in-place restore ran under it. Its
    /// `stat` in a fixture `/proc` the same, and a gone one is none.
    #[test]
    fn a_writer_whose_comm_is_not_utf8_has_its_start_and_is_alive() {
        let p = nn_linux::state_read::testing::sleeper_with_non_utf8_comm(30);
        let pid = p.pid();
        let comm = std::fs::read(format!("/proc/{pid}/comm")).unwrap();
        assert!(std::str::from_utf8(&comm).is_err(), "the fixture's comm");
        let start = proc_start_ticks(Path::new("/proc"), pid).expect("its start");
        assert!(super::super::store::alive(ProcId { pid, start }));
        let root = tempfile::tempdir().unwrap();
        nn_linux::state_read::testing::write_non_utf8_proc(root.path(), 4242, 1, 1000, 777);
        assert_eq!(proc_start_ticks(root.path(), 4242), Some(777));
        assert_eq!(proc_start_ticks(root.path(), 4243), None, "gone");
    }
}
