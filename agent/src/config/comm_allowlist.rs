//! Tappa 10.5 (D1) — per-family process/network comm allowlists.
//!
//! Two operator-tunable allowlist families share the generic
//! `.v1`/`.local` overlay loader (`config/overlay.rs`), each holding
//! BARE PROCESS COMM NAMES (basenames, `TASK_COMM_LEN`-truncated as
//! the kernel reports them) rather than paths:
//!
//! - **`process-comm-allowlist`** — comms exempt from the Tappa 10.5
//!   process detection rules (R011..). A site that legitimately runs
//!   a flagged tool from automation adds its comm here (via `.local`)
//!   to silence the rule without a code change.
//! - **`netflow-comm-allowlist`** — the trusted-actor comms the
//!   network rules (NN-L-NET-006/007/009 + the Tappa 10.5 additions)
//!   suppress on. The `.v1` default is seeded from the inline
//!   `const` sets previously hard-coded in
//!   `decision/rules/net.rs` (§13 Q3 externalisation) so behaviour
//!   is unchanged on upgrade; D4 swaps the rules over to read this.
//!
//! Per §13 Q3 the format is per-FAMILY (not per-rule): one flat file
//! per family, mirroring the Tappa 9 C7 `fim-paths.{v1,local}` shape
//! operators already know. The `.local` overlay supports `+add` /
//! `-disable` with the same boot-WARN-on-disabled-default lock-in.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{anyhow, Result};

use crate::config::overlay::{self, DefaultsSource, OverlayLoad};
use crate::config::overlay_auth::Verified;

/// Deploy location of the process-comm allowlist default + overlay.
pub const PROCESS_COMM_ALLOWLIST_V1: &str = "/etc/northnarrow/process-comm-allowlist.v1";
pub const PROCESS_COMM_ALLOWLIST_LOCAL: &str = "/etc/northnarrow/process-comm-allowlist.local";

/// Deploy location of the netflow-comm allowlist default + overlay.
pub const NETFLOW_COMM_ALLOWLIST_V1: &str = "/etc/northnarrow/netflow-comm-allowlist.v1";
pub const NETFLOW_COMM_ALLOWLIST_LOCAL: &str = "/etc/northnarrow/netflow-comm-allowlist.local";

/// External audit LLMR-016: the shipped default lists, built in — used
/// when the `.v1` on disk cannot be read.
pub const BUILTIN_PROCESS_COMM_ALLOWLIST_V1: &str =
    include_str!("../../../configs/process-comm-allowlist.v1");
pub const BUILTIN_NETFLOW_COMM_ALLOWLIST_V1: &str =
    include_str!("../../../configs/netflow-comm-allowlist.v1");

/// An immutable set of allowlisted comms. Built once at boot from a
/// family's `.v1` + `.local` files; the rule layer queries it with
/// [`CommAllowlist::contains`] on the hot path.
#[derive(Debug, Clone, Default)]
pub struct CommAllowlist {
    entries: BTreeSet<String>,
    /// External audit NET-010 (NN-AUD-006): where [`Self::judge`] reads
    /// what the kernel executed. `None` (tests, legacy callers): the
    /// entries match `comm`, as before.
    identity: Option<crate::posture::lineage::AuthSessionTracker>,
    /// Where the defaults came from (external audit LLMR-016).
    defaults: DefaultsSource,
}

impl PartialEq for CommAllowlist {
    fn eq(&self, other: &Self) -> bool {
        self.entries == other.entries
    }
}
impl Eq for CommAllowlist {}

/// External audit NET-010 (NN-AUD-006): how the allowlist applies to a
/// process, judged on what the kernel executed rather than on `comm`,
/// which any process sets for itself with `prctl(PR_SET_NAME)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Judgement {
    /// The process's exec identity is an allowlisted program: no verdict.
    Allowed,
    /// Its `comm` names an allowlisted program but its exec identity
    /// cannot be read (it exited before its exec event was): the verdict
    /// is recorded, not acted on.
    Unverified,
    /// Not allowlisted. `claimed`: its `comm` names an allowlisted program
    /// that its exec identity is not.
    Denied { claimed: bool },
}

impl Judgement {
    /// Shape the verdict a rule built for a process that is not
    /// [`Judgement::Allowed`].
    pub fn apply(self, mut v: common::Verdict, comm: &str) -> common::Verdict {
        match self {
            Judgement::Unverified => {
                v.action = common::ResponseAction::Log;
                v.reasoning = format!(
                    "{} [named '{comm}', an allowlisted program, but its exec could not be \
                     read: recorded, not acted on]",
                    v.reasoning
                );
            }
            Judgement::Denied { claimed: true } => {
                v.reasoning = format!(
                    "{} [named '{comm}', an allowlisted program, but the kernel ran \
                     something else]",
                    v.reasoning
                );
            }
            Judgement::Allowed | Judgement::Denied { claimed: false } => {}
        }
        v
    }
}

impl CommAllowlist {
    /// Build directly from a set of comms (test + in-memory use).
    pub fn from_iter_owned(it: impl IntoIterator<Item = String>) -> Self {
        Self {
            entries: it.into_iter().collect(),
            identity: None,
            defaults: DefaultsSource::Disk,
        }
    }

    /// Where the defaults came from: [`DefaultsSource::BuiltIn`] when the
    /// `.v1` could not be read (the caller records it).
    pub fn defaults(&self) -> &DefaultsSource {
        &self.defaults
    }

    /// External audit NET-010: judge entries on exec identity read from
    /// `tracker` (production). An entry is then a program name (the exe's
    /// or script's basename) or a tree ending in `/`, inside a root-owned
    /// system tree ([`crate::posture::lineage::ExecIdentity::is_client`]).
    pub fn with_identity(mut self, tracker: crate::posture::lineage::AuthSessionTracker) -> Self {
        self.identity = Some(tracker);
        self
    }

    /// [`Self::judge`] for an exec event's own process, whose identity the
    /// event carries ([`crate::posture::lineage::ExecIdentity::of_exec`]):
    /// no lookup, so never [`Judgement::Unverified`]. `comm` only says
    /// whether the process claimed an allowlisted name.
    pub fn judge_exec(&self, id: &crate::posture::lineage::ExecIdentity, comm: &str) -> Judgement {
        let entries: Vec<&str> = self.entries.iter().map(String::as_str).collect();
        if id.is_client(&entries) {
            Judgement::Allowed
        } else {
            Judgement::Denied {
                claimed: self.entries.contains(comm),
            }
        }
    }

    /// [`Self::judge`] with a rule's built-in clients, `known`: program
    /// names matched on the executable alone
    /// ([`crate::posture::lineage::ExecIdentity::is_known_binary`]), and on
    /// `comm` when the identity cannot be read.
    pub fn judge_with(&self, pid: u32, comm: &str, known: &[&str]) -> Judgement {
        let named = self.entries.contains(comm) || known.contains(&comm);
        let Some(tracker) = &self.identity else {
            return if named {
                Judgement::Allowed
            } else {
                Judgement::Denied { claimed: false }
            };
        };
        let entries: Vec<&str> = self.entries.iter().map(String::as_str).collect();
        match tracker.exec_identity(pid) {
            Some(id) if id.is_client(&entries) || id.is_known_binary(known) => Judgement::Allowed,
            Some(_) => Judgement::Denied { claimed: named },
            None if named => Judgement::Unverified,
            None => Judgement::Denied { claimed: false },
        }
    }

    /// How the allowlist applies to process `pid` named `comm`
    /// ([`Judgement`]). Without an identity source, `comm` decides.
    pub fn judge(&self, pid: u32, comm: &str) -> Judgement {
        self.judge_with(pid, comm, &[])
    }

    /// `true` if `comm` is allowlisted. The kernel-reported comm is
    /// already a bare basename, so this is an exact-match lookup.
    pub fn contains(&self, comm: &str) -> bool {
        self.entries.contains(comm)
    }

    /// Number of allowlisted comms.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` if no comms are allowlisted.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Deterministic iteration over the allowlisted comms (boot logs
    /// + status CLIs).
    pub fn iter(&self) -> impl Iterator<Item = &String> {
        self.entries.iter()
    }
}

/// Load a comm allowlist family from its `.v1` (or `builtin`, the copy
/// built into the agent, when it cannot be read) and its `.local` overlay
/// as the signed-overlay gate verified it. `label` names the family in
/// boot logs — see [`overlay::load_flat_list`]. (The convenience loaders
/// that read both default paths themselves are gone: they read the
/// overlay without the gate — external audit LLMR-013.)
pub fn load_comm_allowlist(
    label: &str,
    v1_path: &Path,
    builtin: &str,
    local: &Verified,
) -> Result<CommAllowlist> {
    let OverlayLoad {
        effective,
        defaults,
        ..
    } = overlay::load_flat_list(label, v1_path, builtin, local, &validate_comm)?;
    Ok(CommAllowlist {
        entries: effective,
        identity: None,
        defaults,
    })
}

/// Entry shape rule for a comm allowlist: a bare process basename —
/// non-empty, no path separator, a single whitespace-free token.
pub(crate) fn validate_comm(entry: &str) -> Result<()> {
    if entry.is_empty() {
        return Err(anyhow!("comm entries must be non-empty"));
    }
    if entry.contains('/') {
        return Err(anyhow!(
            "comm entries are bare process names, not paths (got `{entry}`)"
        ));
    }
    if entry.split_whitespace().count() != 1 {
        return Err(anyhow!(
            "comm entries must be a single whitespace-free token (got `{entry}`)"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// D1: the SHIPPED default `.v1` files (the repo `configs/`
    /// copies `install.sh` drops to `/etc/northnarrow/`) parse
    /// clean for every family — a malformed default (stray
    /// directive, a path where a comm belongs) fails the build's
    /// test gate rather than at an operator's boot.
    #[test]
    fn per_family_allowlist_files_load_clean() {
        let configs = concat!(env!("CARGO_MANIFEST_DIR"), "/../configs");
        for (label, file, builtin) in [
            (
                "process-comm-allowlist",
                "process-comm-allowlist.v1",
                BUILTIN_PROCESS_COMM_ALLOWLIST_V1,
            ),
            (
                "netflow-comm-allowlist",
                "netflow-comm-allowlist.v1",
                BUILTIN_NETFLOW_COMM_ALLOWLIST_V1,
            ),
        ] {
            let v1 = Path::new(configs).join(file);
            // Overlay absent in the repo (operator-curated): the
            // v1-only path.
            let out = load_comm_allowlist(label, &v1, builtin, &Verified::Missing)
                .unwrap_or_else(|e| panic!("{label}: shipped {file} must parse clean: {e}"));
            assert!(
                !out.is_empty(),
                "{label}: shipped {file} should ship a non-empty default set"
            );
            assert_eq!(out.defaults(), &DefaultsSource::Disk);
            assert_eq!(std::fs::read_to_string(&v1).unwrap(), builtin);
            // External audit LLMR-016: without the file, the same list.
            let without = load_comm_allowlist(
                label,
                &v1.with_extension("missing"),
                builtin,
                &Verified::Missing,
            )
            .unwrap();
            assert_eq!(without, out);
            assert!(matches!(without.defaults(), DefaultsSource::BuiltIn(_)));
        }
    }

    /// D1: a default file with a path-shaped entry is rejected (comm
    /// allowlists hold bare basenames, not paths).
    #[test]
    fn comm_validator_rejects_path_entries() {
        let err = validate_comm("/usr/bin/curl").expect_err("paths must be rejected");
        assert!(
            err.to_string().contains("bare process names"),
            "expected bare-name diagnostic, got: {err}"
        );
    }

    /// D1: the typed wrapper drops the overlay bookkeeping and
    /// exposes only the merged set via `contains`.
    #[test]
    fn comm_allowlist_contains_after_load() {
        use tempfile::TempDir;
        let dir = TempDir::new().unwrap();
        let v1 = dir.path().join("c.v1");
        std::fs::write(&v1, "sshd\nnginx\n").unwrap();
        let local = Verified::Content {
            path: dir.path().join("c.local"),
            text: "+rsync\n-nginx\n".to_string(),
        };
        let al = load_comm_allowlist("test", &v1, "", &local).expect("load");
        assert!(al.contains("sshd"));
        assert!(al.contains("rsync"));
        assert!(!al.contains("nginx"), "disabled default must be absent");
        assert!(!al.contains("curl"));
        assert_eq!(al.len(), 2);
        assert!(!al.is_empty());
    }

    // ── external audit NETR-003 class — exec identity ──

    fn identity(exe: &str, argv: &[&str]) -> crate::posture::lineage::ExecIdentity {
        let argv: Vec<String> = argv.iter().map(|a| a.to_string()).collect();
        crate::posture::lineage::ExecIdentity::of_exec(exe, &argv)
    }

    #[test]
    fn judge_exec_reads_what_the_kernel_executed() {
        let al = CommAllowlist::from_iter_owned(["apt".to_string(), "unattended-upgr".to_string()]);
        assert_eq!(
            al.judge_exec(&identity("/usr/bin/apt", &["apt"]), "apt"),
            Judgement::Allowed
        );
        // the shipped 15-character entry covers the script it was cut from
        assert_eq!(
            al.judge_exec(
                &identity(
                    "/usr/bin/python3.12",
                    &["/usr/bin/python3", "/usr/bin/unattended-upgrade"]
                ),
                "unattended-upgr"
            ),
            Judgement::Allowed
        );
        // a copy named apt, and python calling itself apt
        assert_eq!(
            al.judge_exec(&identity("/tmp/apt", &["apt"]), "apt"),
            Judgement::Denied { claimed: true }
        );
        assert_eq!(
            al.judge_exec(
                &identity("/usr/bin/python3.12", &["python3", "-c", "x"]),
                "apt"
            ),
            Judgement::Denied { claimed: true }
        );
        assert_eq!(
            al.judge_exec(&identity("/usr/bin/curl", &["curl"]), "curl"),
            Judgement::Denied { claimed: false }
        );
    }

    #[test]
    fn judge_with_falls_back_on_comm_only_without_an_identity() {
        let tmp = tempfile::TempDir::new().unwrap();
        let t = crate::posture::lineage::AuthSessionTracker::new(tmp.path());
        t.ingest_spawn_with_argv(10, 1, "/usr/sbin/nginx", &["nginx".to_string()], 1);
        t.ingest_spawn_with_argv(11, 1, "/tmp/nginx", &["nginx".to_string()], 1);
        let known = ["nginx"];
        // no tracker (tests, tools): comm decides, as before
        let bare = CommAllowlist::default();
        assert_eq!(bare.judge_with(11, "nginx", &known), Judgement::Allowed);
        assert_eq!(
            bare.judge_with(11, "evil", &known),
            Judgement::Denied { claimed: false }
        );
        let al = CommAllowlist::default().with_identity(t);
        assert_eq!(al.judge_with(10, "nginx", &known), Judgement::Allowed);
        assert_eq!(
            al.judge_with(11, "nginx", &known),
            Judgement::Denied { claimed: true }
        );
        // gone before it was seen: named, so recorded rather than acted on
        assert_eq!(al.judge_with(12, "nginx", &known), Judgement::Unverified);
        assert_eq!(
            al.judge_with(12, "evil", &known),
            Judgement::Denied { claimed: false }
        );
    }
}
