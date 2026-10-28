//! A refused start (Wave 4 restructure, R11b, lab PR 262; lab PR 218's
//! `record_refused_boot`, for every gate now).
//!
//! A boot gate that refuses the start leaves the refusal in a signed chain
//! before the process exits, so root cannot quietly remove the trace (lab
//! PR 21): the rows lab PR 218 wrote — the rollback floor, the identity, a
//! `subsystem_degraded` when the gate has one, then the `agent_boot` with
//! `result: refused` and `refused_by` naming the gate. They go
//!
//! 1. into the audit log — the one the integrity phase opened before the
//!    load, once it did, otherwise opened here;
//! 2. when the audit log cannot take them (it is the gate: not writable,
//!    its chain broken, its write failed), into a chain of the same format,
//!    signed with the same key, beside `--pid-file` ([`FALLBACK_FILE_NAME`];
//!    `/run/northnarrow` in the unit);
//! 3. nowhere but the journal when neither can be written (no key, no
//!    `--pid-file`): the line says so.
//!
//! Then the start's registration in the pinned `PROTECTED_PIDS` — the
//! previous agent's map, written before the bootstraps (EBPF-015), or this
//! boot's once the attach registered it — is withdrawn, so a refused start
//! leaves no protected pid behind for a recycled pid to inherit, and the
//! process exits 78 (`EX_CONFIG`: the unit lands `failed`).
//!
//! Every gate before the load refuses through [`Context::refuse`] — the
//! eBPF object, the state directory, the BTF offsets (the preflight's three,
//! found before the identity is read, refuse at the start of the integrity
//! phase), the demo rules, the capabilities, the install manifest, the
//! audit log, the BPF LSM — and so do those that need the loaded object:
//! the sensors' load and attach, the deny hooks, the deny self-test, the
//! boot's own `agent_boot` row.

use std::path::{Path, PathBuf};

use northnarrow_agent::agent_id::AgentIdentity;
use northnarrow_agent::audit::{AgentSigningKey, AuditLog};
use northnarrow_agent::config::overlay_auth::OverlayGate;
use tracing::{debug, error, info, warn};

use super::cli::Cli;

/// The exit status of a refused start (sysexits.h `EX_CONFIG`): a non-zero
/// status systemd shows as a `failed` unit (`Restart=no`).
pub(crate) const EX_CONFIG: i32 = 78;

/// The chain beside `--pid-file` that holds the refusals the audit log
/// could not take.
pub(crate) const FALLBACK_FILE_NAME: &str = "boot-refusals.jsonl";

/// The `binary_integrity` and `install_provenance` of a refusal before the
/// install manifest was checked.
pub(crate) const UNCHECKED: (&str, &str) = ("unchecked", "none");

/// A boot gate's refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Refusal {
    /// The gate (`refused_by`).
    pub(crate) gate: &'static str,
    /// What it found (the row's `detail`).
    pub(crate) detail: String,
    /// A `subsystem_degraded` signed before the refusal: its source.
    pub(crate) degraded: Option<&'static str>,
}

impl Refusal {
    pub(crate) fn new(gate: &'static str, detail: impl Into<String>) -> Self {
        Refusal {
            gate,
            detail: detail.into(),
            degraded: None,
        }
    }

    /// The refusal with a signed `subsystem_degraded` of `source` (its
    /// detail the refusal's), as lab PR 218's gates wrote it.
    pub(crate) fn degraded(mut self, source: &'static str) -> Self {
        self.degraded = Some(source);
        self
    }
}

/// What the start has to sign a refusal with when it refuses.
pub(crate) struct Context<'a> {
    pub(crate) cli: &'a Cli,
    pub(crate) identity: &'a AgentIdentity,
    pub(crate) overlay_gate: &'a OverlayGate,
    /// The install manifest's verdict and provenance ([`UNCHECKED`] before
    /// it ran).
    pub(crate) integrity: (&'a str, &'a str),
}

impl Context<'_> {
    /// Refuse the start: sign the refusal ([`sign`]) — in `audit`, the audit
    /// log the integrity phase opened, once it did —, withdraw the start's
    /// registration in the pinned `PROTECTED_PIDS`, exit [`EX_CONFIG`]. The
    /// gate has logged what it found.
    pub(crate) fn refuse(&self, audit: Option<&mut AuditLog>, refusal: Refusal) -> ! {
        let gate = refusal.gate;
        match sign(self, audit, &refusal) {
            Signed::AuditLog { entry_hash } => {
                info!(entry_hash = %entry_hash, gate, "refused boot recorded in the audit chain")
            }
            Signed::Fallback {
                path,
                entry_hash,
                audit_log,
            } => error!(
                path = %path.display(),
                entry_hash = %entry_hash,
                gate,
                audit_log = %audit_log,
                "refused boot recorded in the fallback chain: the audit log cannot take it \
                 (nn-admin audit verify --from <path>)"
            ),
            Signed::Unsigned(why) => error!(
                gate,
                why = %why,
                "could not record the refused boot in a signed chain — the journal holds it alone"
            ),
        }
        withdraw_registration(Path::new(
            northnarrow_agent::anti_tamper::DEFAULT_BPFFS_ROOT,
        ));
        error!(gate, exit = EX_CONFIG, "start refused");
        std::process::exit(EX_CONFIG)
    }
}

/// Where a refusal was signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Signed {
    /// In the audit log: the `agent_boot` row's hash.
    AuditLog { entry_hash: String },
    /// In the fallback chain at `path` (the audit log could not take it:
    /// why).
    Fallback {
        path: PathBuf,
        entry_hash: String,
        audit_log: String,
    },
    /// Nowhere: why.
    Unsigned(String),
}

/// Sign `refusal`: in the audit log (`audit`, the one opened before the
/// load, or the file opened now), else in the fallback chain beside
/// `--pid-file`, else nowhere (why).
pub(crate) fn sign(ctx: &Context<'_>, audit: Option<&mut AuditLog>, refusal: &Refusal) -> Signed {
    let Context {
        cli,
        identity,
        overlay_gate,
        integrity,
    } = *ctx;
    // 1. the audit log: the one opened before the load, or opened now
    let audit_log = match audit {
        Some(log) => write_refusal(log, identity, Some(overlay_gate), integrity, refusal),
        None => match AgentSigningKey::load_or_bootstrap(&cli.signing_key_file) {
            Ok(key) => match AuditLog::open(&cli.audit_log_file, key, identity.id) {
                Ok(mut log) => {
                    write_refusal(&mut log, identity, Some(overlay_gate), integrity, refusal)
                }
                Err(e) => Err(format!("{e:#}")),
            },
            Err(e) => {
                return Signed::Unsigned(format!("the agent's signing key cannot be loaded: {e:#}"))
            }
        },
    };
    let audit_log = match audit_log {
        Ok(entry_hash) => return Signed::AuditLog { entry_hash },
        Err(why) => why,
    };
    // 2. the fallback chain
    let Some(path) = fallback_path(cli) else {
        return Signed::Unsigned(format!(
            "the audit log cannot take it ({audit_log}), and without --pid-file there is no \
             fallback chain"
        ));
    };
    let key = match AgentSigningKey::load_or_bootstrap(&cli.signing_key_file) {
        Ok(key) => key,
        Err(e) => {
            return Signed::Unsigned(format!(
                "the audit log cannot take it ({audit_log}); the agent's signing key cannot be \
                 loaded: {e:#}"
            ))
        }
    };
    let mut fallback = match AuditLog::open(&path, key, identity.id) {
        Ok(log) => log,
        Err(e) => {
            return Signed::Unsigned(format!(
                "the audit log cannot take it ({audit_log}); nor can {}: {e:#}",
                path.display()
            ))
        }
    };
    match write_refusal(&mut fallback, identity, None, integrity, refusal) {
        Ok(entry_hash) => Signed::Fallback {
            path,
            entry_hash,
            audit_log,
        },
        Err(why) => Signed::Unsigned(format!(
            "the audit log cannot take it ({audit_log}); nor can {}: {why}",
            path.display()
        )),
    }
}

/// The refusal's rows in `log`: the rollback floor (the audit log only:
/// `floor`), the identity (EVD-020), the `subsystem_degraded`, the
/// `agent_boot` `refused` — its hash, or why it could not be written.
fn write_refusal(
    log: &mut AuditLog,
    identity: &AgentIdentity,
    floor: Option<&OverlayGate>,
    (integrity, provenance): (&str, &str),
    refusal: &Refusal,
) -> Result<String, String> {
    if let Some(gate) = floor {
        gate.attest_floor(log);
    }
    // External audit EVD-020: a refused boot records its identity too.
    if let Err(e) = log.attest_identity(identity) {
        warn!(error = format!("{e:#}"), "agent identity not recorded");
    }
    if let Some(source) = refusal.degraded {
        northnarrow_agent::boot::degradation::sign_into(log, source, &refusal.detail, true);
    }
    log.boot_refused_by(
        refusal.gate,
        integrity,
        provenance,
        &refusal.detail,
        &northnarrow_agent::build_info::agent_build(),
    )
    .map(|e| e.entry_hash)
    .map_err(|e| format!("{e:#}"))
}

/// The fallback chain's path: [`FALLBACK_FILE_NAME`] beside `--pid-file`
/// (the unit's `/run/northnarrow`, its `RuntimeDirectory`); none without
/// `--pid-file`, as for the BPF program-id list (DEP-006).
pub(crate) fn fallback_path(cli: &Cli) -> Option<PathBuf> {
    cli.pid_file
        .as_deref()
        .and_then(Path::parent)
        .map(|dir| dir.join(FALLBACK_FILE_NAME))
}

/// Withdraw this process from the pinned `PROTECTED_PIDS` under
/// `bpffs_root`: the previous agent's map it registered in before the
/// bootstraps (EBPF-015), or this boot's once the attach registered it. A
/// refused start must not leave a protected pid behind — a recycled pid
/// would inherit the immunity to kill and ptrace and the exemption from the
/// deny hooks until the next start's stale-pid scan. No pinned map: nothing
/// to withdraw.
pub(crate) fn withdraw_registration(bpffs_root: &Path) {
    if !bpffs_root
        .join(northnarrow_agent::anti_tamper::PROTECTED_PIDS_MAP_NAME)
        .exists()
    {
        debug!("anti-tamper: no pinned PROTECTED_PIDS, no registration to withdraw");
        return;
    }
    match northnarrow_agent::anti_tamper::evict_protected_pid(Some(bpffs_root), std::process::id())
    {
        Ok(()) => info!(
            pid = std::process::id(),
            "anti-tamper: the refused start's pid withdrawn from the pinned PROTECTED_PIDS"
        ),
        Err(e) => warn!(
            error = format!("{e:#}"),
            pid = std::process::id(),
            "anti-tamper: the refused start's pid NOT withdrawn from the pinned PROTECTED_PIDS — \
             the next start's stale-pid scan evicts it"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn cli(dir: &Path, audit_log: &Path) -> Cli {
        let _env = super::super::cli::TEST_ENV.lock();
        let arg = |p: &Path| p.to_string_lossy().into_owned();
        Cli::try_parse_from([
            "northnarrow-agent".to_string(),
            "--agent-id-file".to_string(),
            arg(&dir.join("agent_id")),
            "--admin-pub".to_string(),
            arg(&dir.join("admin.pub")),
            "--signing-key-file".to_string(),
            arg(&dir.join("agent.sig.key")),
            "--audit-log-file".to_string(),
            arg(audit_log),
            "--pid-file".to_string(),
            arg(&dir.join("run/agent.pid")),
        ])
        .expect("a command line with the test's paths")
    }

    fn identity(dir: &Path) -> AgentIdentity {
        northnarrow_agent::agent_id::resolve(&dir.join("agent_id"))
    }

    fn gate(dir: &Path, id: [u8; 16]) -> OverlayGate {
        OverlayGate::new(
            &dir.join("admin.pub"),
            id,
            northnarrow_agent::config::overlay_floor::RollbackFloor::scan(
                &dir.join("audit.log"),
                &dir.join("agent.sig.key"),
            ),
        )
    }

    fn rows(path: &Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn pk(dir: &Path) -> ed25519_dalek::VerifyingKey {
        northnarrow_agent::keys::boot_verifying_key(&dir.join("agent.sig.key")).expect("the key")
    }

    fn verifies(path: &Path, dir: &Path) {
        let report = northnarrow_agent::audit::verify_chain_file(path, &pk(dir), None).unwrap();
        assert!(report.broken.is_none(), "{report:?}");
    }

    /// The refusal is signed in the audit log, its last row the
    /// `agent_boot` `refused` naming the gate, with the degradation before
    /// it; the chain verifies.
    #[test]
    fn a_refusal_is_signed_in_the_audit_log() {
        let dir = tempfile::tempdir().unwrap();
        let audit = dir.path().join("audit.log");
        let cli = cli(dir.path(), &audit);
        let id = identity(dir.path());
        let gate_ = gate(dir.path(), id.id);
        let ctx = Context {
            cli: &cli,
            identity: &id,
            overlay_gate: &gate_,
            integrity: UNCHECKED,
        };
        let r = Refusal::new("capabilities", "CAP_KILL missing").degraded("capabilities");
        let signed = sign(&ctx, None, &r);
        let Signed::AuditLog { entry_hash } = signed else {
            panic!("{signed:?}")
        };
        let rows = rows(&audit);
        let last = rows.last().unwrap();
        assert_eq!(last["op"], "agent_boot");
        assert_eq!(last["result"], "refused");
        assert_eq!(last["extra"]["refused_by"], "capabilities");
        assert_eq!(last["extra"]["detail"], "CAP_KILL missing");
        assert_eq!(last["extra"]["binary_integrity"], "unchecked");
        assert_eq!(last["entry_hash"], entry_hash.as_str());
        let before = &rows[rows.len() - 2];
        assert_eq!(before["extra"]["kind"], "subsystem_degraded");
        assert_eq!(before["extra"]["source"], "capabilities");
        verifies(&audit, dir.path());
        assert!(!fallback_path(&cli).unwrap().exists(), "no fallback");
    }

    /// The audit log open before the load takes the refusal: one writer,
    /// one chain.
    #[test]
    fn a_refusal_goes_into_the_log_already_open() {
        let dir = tempfile::tempdir().unwrap();
        let audit = dir.path().join("audit.log");
        let cli = cli(dir.path(), &audit);
        let id = identity(dir.path());
        let gate_ = gate(dir.path(), id.id);
        let key = AgentSigningKey::load_or_bootstrap(&dir.path().join("agent.sig.key")).unwrap();
        let mut log = AuditLog::open(&audit, key, id.id).unwrap();
        let ctx = Context {
            cli: &cli,
            identity: &id,
            overlay_gate: &gate_,
            integrity: ("verified", "source-tree"),
        };
        let signed = sign(
            &ctx,
            Some(&mut log),
            &Refusal::new("bpf_lsm", "bpf not active").degraded("bpf_lsm"),
        );
        assert!(matches!(signed, Signed::AuditLog { .. }), "{signed:?}");
        // the same writer goes on: the chain is one
        log.boot_probe(
            None,
            "verified",
            "source-tree",
            &northnarrow_agent::build_info::agent_build(),
        )
        .unwrap();
        verifies(&audit, dir.path());
        let rows = rows(&audit);
        assert_eq!(rows[rows.len() - 2]["extra"]["refused_by"], "bpf_lsm");
        assert_eq!(
            rows[rows.len() - 2]["extra"]["binary_integrity"],
            "verified"
        );
    }

    /// An audit log that cannot take the refusal (a directory there): the
    /// fallback chain beside --pid-file holds it, signed with the same key.
    #[test]
    fn an_unwritable_audit_log_sends_the_refusal_to_the_fallback_chain() {
        let dir = tempfile::tempdir().unwrap();
        let audit = dir.path().join("audit.log");
        std::fs::create_dir(&audit).unwrap();
        std::fs::create_dir(dir.path().join("run")).unwrap();
        let cli = cli(dir.path(), &audit);
        let id = identity(dir.path());
        let gate_ = gate(dir.path(), id.id);
        let ctx = Context {
            cli: &cli,
            identity: &id,
            overlay_gate: &gate_,
            integrity: ("verified", "source-tree"),
        };
        let signed = sign(
            &ctx,
            None,
            &Refusal::new("audit_log", "audit.log: Is a directory"),
        );
        let Signed::Fallback {
            path, entry_hash, ..
        } = signed
        else {
            panic!("{signed:?}")
        };
        assert_eq!(path, dir.path().join("run").join(FALLBACK_FILE_NAME));
        let fb = rows(&path);
        let last = fb.last().unwrap();
        assert_eq!(last["op"], "agent_boot");
        assert_eq!(last["result"], "refused");
        assert_eq!(last["extra"]["refused_by"], "audit_log");
        assert_eq!(last["entry_hash"], entry_hash.as_str());
        verifies(&path, dir.path());
    }

    /// A log that opened but cannot take the row (its write fails): the
    /// fallback chain.
    #[test]
    fn a_failed_write_sends_the_refusal_to_the_fallback_chain() {
        let dir = tempfile::tempdir().unwrap();
        let audit = dir.path().join("audit.log");
        std::fs::create_dir(dir.path().join("run")).unwrap();
        let cli = cli(dir.path(), &audit);
        let id = identity(dir.path());
        let gate_ = gate(dir.path(), id.id);
        let key = AgentSigningKey::load_or_bootstrap(&dir.path().join("agent.sig.key")).unwrap();
        let mut log = AuditLog::open(&audit, key, id.id).unwrap();
        // a directory where the log goes, after the open (which creates no
        // file): every append fails
        std::fs::create_dir(&audit).unwrap();
        let ctx = Context {
            cli: &cli,
            identity: &id,
            overlay_gate: &gate_,
            integrity: UNCHECKED,
        };
        let signed = sign(
            &ctx,
            Some(&mut log),
            &Refusal::new("audit_log", "write failed"),
        );
        assert!(matches!(signed, Signed::Fallback { .. }), "{signed:?}");
    }

    /// Without --pid-file and with an audit log that cannot take it, the
    /// refusal is in the journal alone, and says why.
    #[test]
    fn without_a_fallback_the_refusal_is_unsigned_and_says_why() {
        let dir = tempfile::tempdir().unwrap();
        let audit = dir.path().join("audit.log");
        std::fs::create_dir(&audit).unwrap();
        let mut cli = cli(dir.path(), &audit);
        cli.pid_file = None;
        let id = identity(dir.path());
        let gate_ = gate(dir.path(), id.id);
        let ctx = Context {
            cli: &cli,
            identity: &id,
            overlay_gate: &gate_,
            integrity: UNCHECKED,
        };
        let signed = sign(
            &ctx,
            None,
            &Refusal::new("audit_log", "audit.log: Is a directory"),
        );
        assert!(
            matches!(&signed, Signed::Unsigned(why) if why.contains("--pid-file")),
            "{signed:?}"
        );
    }

    /// No pinned map: nothing to withdraw, nothing touched.
    #[test]
    fn no_pinned_map_no_withdrawal() {
        let dir = tempfile::tempdir().unwrap();
        withdraw_registration(dir.path());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}
