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
//!   no ancestor is foreign: every hop up to PID 1 is a program root
//!   installed ([`ExecIdentity::is_installed_program`]) or an installed
//!   interpreter running no named script (an interactive shell, `sh -c`).
//!   An editor started by a script from a home directory, by a binary from
//!   `/tmp` or by a deleted executable is not trusted: what started it is
//!   not known to be the user's own hand.
//!
//! Everything else is untrusted, including a lineage the walk cannot read
//! (fail toward copying). Interpreters are refused as trusted writers:
//! `python3` with no script would trust every `python3 -c`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use parking_lot::Mutex;

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
/// interpreter runs, else the executable.
pub fn program_of(id: &ExecIdentity) -> String {
    match &id.script {
        Some(s) => s.clone(),
        None => id.exe.to_string_lossy().into_owned(),
    }
}

/// A hop that vouches for nothing below it: neither a program root
/// installed nor an installed interpreter running no named script.
pub fn is_foreign(id: &ExecIdentity) -> bool {
    if id.is_installed_program() {
        return false;
    }
    let exe = id.exe.to_string_lossy();
    !(id.script.is_none() && is_interpreter(&id.exe) && in_system_tree(&exe))
}

/// The pure decision. `lineage`: the writer's identity at index 0, then its
/// ancestors nearest first (`None`: unknown). `writers`: the trusted-writer
/// entries. `package_tx`: the writer belongs to a root package transaction.
pub fn judge(lineage: Option<&[(u32, ExecIdentity)]>, writers: &[&str], package_tx: bool) -> Trust {
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
    if let Some((_, foreign)) = hops[1..].iter().find(|(_, id)| is_foreign(id)) {
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
            proc_root: PathBuf::from("/proc"),
            cache: Mutex::new(HashMap::new()),
        }
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
        let trust = judge(
            lineage.as_deref(),
            &writers,
            self.tracker.in_package_transaction(tgid, AsOf::Now),
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
    let stat = std::fs::read_to_string(proc_root.join(pid.to_string()).join("stat")).ok()?;
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

    fn id(exe: &str, script: Option<&str>) -> ExecIdentity {
        ExecIdentity {
            exe: PathBuf::from(exe),
            script: script.map(str::to_string),
        }
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
            judge(Some(&l), &writers(), false),
            Trust::Trusted(Trusted::Writer("/usr/bin/vim.basic".into()))
        );
        // through sudo and `sh -c`
        let l = [
            (300, id("/usr/bin/git", None)),
            (250, id("/usr/bin/dash", None)),
            (200, id("/usr/bin/sudo", None)),
            (150, id("/usr/bin/bash", None)),
        ];
        assert!(judge(Some(&l), &writers(), false).is_trusted());
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
                judge(Some(&l), &writers(), false),
                Trust::Untrusted(Untrusted::NotATrustedWriter(exe.into())),
                "{exe}"
            );
        }
        // python running a user's script
        let l = [(300, id("/usr/bin/python3", Some("/home/u/sim.py")))];
        assert!(!judge(Some(&l), &writers(), false).is_trusted());
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
            match judge(Some(&l), &writers(), false) {
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
        assert!(!judge(Some(&l), &writers(), false).is_trusted());
        // the lineage cannot be read: copied
        assert_eq!(
            judge(None, &writers(), false),
            Trust::Untrusted(Untrusted::LineageUnknown)
        );
        assert_eq!(
            judge(Some(&[]), &writers(), false),
            Trust::Untrusted(Untrusted::LineageUnknown)
        );
    }

    #[test]
    fn a_package_transaction_is_trusted_and_an_operator_entry_counts() {
        let l = [(300, id("/usr/bin/cp", None))];
        assert_eq!(
            judge(Some(&l), &writers(), true),
            Trust::Trusted(Trusted::PackageTransaction)
        );
        assert_eq!(
            judge(None, &writers(), true),
            Trust::Trusted(Trusted::PackageTransaction)
        );
        let mut w = writers();
        w.push("rsync");
        let l = [(300, id("/usr/bin/rsync", None))];
        assert!(judge(Some(&l), &w, false).is_trusted());
        w.push("/opt/editor/");
        let l = [(300, id("/opt/editor/bin/ed2", None))];
        assert!(judge(Some(&l), &w, false).is_trusted());
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
        assert_eq!(l[0].1.script.as_deref(), Some("/home/u/sim.py"));
        assert_eq!(l[1].0, 200);
        let f = TrustFilter::new(&[], t.clone());
        let info = f.evaluate(300, 0);
        assert!(!info.trust.is_trusted());
        assert_eq!(info.program, "/home/u/sim.py");
        assert_eq!(info.lineage.len(), 2);
        assert_eq!(info.lineage[1].pid, 200);
    }
}
