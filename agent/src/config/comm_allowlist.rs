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

use crate::config::overlay::{self, OverlayLoad};

/// Deploy location of the process-comm allowlist default + overlay.
pub const PROCESS_COMM_ALLOWLIST_V1: &str = "/etc/northnarrow/process-comm-allowlist.v1";
pub const PROCESS_COMM_ALLOWLIST_LOCAL: &str = "/etc/northnarrow/process-comm-allowlist.local";

/// Deploy location of the netflow-comm allowlist default + overlay.
pub const NETFLOW_COMM_ALLOWLIST_V1: &str = "/etc/northnarrow/netflow-comm-allowlist.v1";
pub const NETFLOW_COMM_ALLOWLIST_LOCAL: &str = "/etc/northnarrow/netflow-comm-allowlist.local";

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
        }
    }

    /// External audit NET-010: judge entries on exec identity read from
    /// `tracker` (production). An entry is then a program name (the exe's
    /// or script's basename) or a tree ending in `/`, inside a root-owned
    /// system tree ([`crate::posture::lineage::ExecIdentity::is_client`]).
    pub fn with_identity(mut self, tracker: crate::posture::lineage::AuthSessionTracker) -> Self {
        self.identity = Some(tracker);
        self
    }

    /// How the allowlist applies to process `pid` named `comm`
    /// ([`Judgement`]). Without an identity source, `comm` decides.
    pub fn judge(&self, pid: u32, comm: &str) -> Judgement {
        let named = self.entries.contains(comm);
        let Some(tracker) = &self.identity else {
            return if named {
                Judgement::Allowed
            } else {
                Judgement::Denied { claimed: false }
            };
        };
        let entries: Vec<&str> = self.entries.iter().map(String::as_str).collect();
        match tracker.exec_identity(pid) {
            Some(id) if id.is_client(&entries) => Judgement::Allowed,
            Some(_) => Judgement::Denied { claimed: named },
            None if named => Judgement::Unverified,
            None => Judgement::Denied { claimed: false },
        }
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

/// Load a comm allowlist family from its `.v1` + `.local` files.
/// `label` names the family in boot logs. Missing files are
/// tolerated (empty allowlist) — see [`overlay::load_flat_list`].
pub fn load_comm_allowlist(
    label: &str,
    v1_path: &Path,
    local_path: &Path,
) -> Result<CommAllowlist> {
    let OverlayLoad { effective, .. } =
        overlay::load_flat_list(label, v1_path, local_path, &validate_comm)?;
    Ok(CommAllowlist {
        entries: effective,
        identity: None,
    })
}

/// Convenience: load the process-comm allowlist from its default
/// deploy locations.
pub fn load_process_comm_allowlist() -> Result<CommAllowlist> {
    load_comm_allowlist(
        "process-comm-allowlist",
        Path::new(PROCESS_COMM_ALLOWLIST_V1),
        Path::new(PROCESS_COMM_ALLOWLIST_LOCAL),
    )
}

/// Convenience: load the netflow-comm allowlist from its default
/// deploy locations.
pub fn load_netflow_comm_allowlist() -> Result<CommAllowlist> {
    load_comm_allowlist(
        "netflow-comm-allowlist",
        Path::new(NETFLOW_COMM_ALLOWLIST_V1),
        Path::new(NETFLOW_COMM_ALLOWLIST_LOCAL),
    )
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
        for (label, file) in [
            ("process-comm-allowlist", "process-comm-allowlist.v1"),
            ("netflow-comm-allowlist", "netflow-comm-allowlist.v1"),
        ] {
            let v1 = Path::new(configs).join(file);
            // Overlay absent in the repo (operator-curated) — point
            // at a sibling that doesn't exist so we exercise the
            // v1-only path.
            let local = Path::new(configs).join(format!("{file}.nonexistent.local"));
            let out = load_comm_allowlist(label, &v1, &local)
                .unwrap_or_else(|e| panic!("{label}: shipped {file} must parse clean: {e}"));
            assert!(
                !out.is_empty(),
                "{label}: shipped {file} should ship a non-empty default set"
            );
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
        let local = dir.path().join("c.local");
        std::fs::write(&v1, "sshd\nnginx\n").unwrap();
        std::fs::write(&local, "+rsync\n-nginx\n").unwrap();
        let al = load_comm_allowlist("test", &v1, &local).expect("load");
        assert!(al.contains("sshd"));
        assert!(al.contains("rsync"));
        assert!(!al.contains("nginx"), "disabled default must be absent");
        assert!(!al.contains("curl"));
        assert_eq!(al.len(), 2);
        assert!(!al.is_empty());
    }
}
