//! Tamper-evident audit log (Tappa 8 design §9, sub-sprint B
//! commit B1 / table row A11).
//!
//! Every admin operation the agent processes — success or failure —
//! appends a single JSONL line to `/etc/northnarrow/audit.log`. Each
//! record is bound to the previous record by a SHA-256 hash chain
//! (`entry_hash = SHA-256(prev_hash || serialised record minus
//! entry_hash + agent_sig)`) and signed by an agent-owned Ed25519
//! key, so off-host auditors can verify the chain end-to-end with
//! nothing more than the agent binary's embedded public key
//! (forthcoming sub-sprint B commits ship the `nn-admin audit
//! verify` reader).
//!
//! ## What this commit (B1) ships
//!
//! - [`AgentSigningKey::load_or_bootstrap`] — mirrors the
//!   [`crate::agent_id::load_or_bootstrap`] policy: existing file →
//!   parse, missing file → mint via `OsRng` + atomic persist,
//!   corrupted file → hard error (no silent regen). On-disk mode is
//!   `0400` — the agent's own boot user (root) is the only reader,
//!   and the file is the LSM-protected `agent.sig.key` whose
//!   protection ships in commit A14 / sub-sprint B's LSM widening.
//! - [`AuditEntry`] — the on-disk JSON record per §9.1.
//! - [`AuditLog::open`] — opens the log in `O_APPEND` mode and
//!   walks the existing chain to recover `prev_hash`. An empty or
//!   absent file starts the chain at the canonical genesis
//!   ([`GENESIS_PREV_HASH`]).
//! - [`AuditLog::append`] — atomically computes `entry_hash`,
//!   signs it, and appends one `\n`-terminated JSON line. The
//!   in-memory `prev_hash` advances on success.
//! - [`verify_chain`] — replays a sequence of [`AuditEntry`]s,
//!   recomputing `entry_hash` and checking `agent_sig` against a
//!   supplied verifying key. The verifier of `nn-admin audit verify`
//!   and `nn-admin chain verify` (`AuditLog::open` does not call it; the
//!   boot verification is the overlay floor scan, and lab PR 160's row
//!   numbers and head anchor, `crate::chain_anchor`).
//!
//! ## What this commit (B1) deliberately does NOT ship
//!
//! - **No CLI surface.** `nn-admin audit read / audit verify` is
//!   commit A12 (sub-sprint B's next commit). B1 is a foundation
//!   primitive: tested in isolation, no wire-protocol changes, no
//!   admin-socket dispatch changes.
//! - **No `admin_socket::dispatch` integration.** The agent does
//!   not yet log operations to the audit log; the dispatch
//!   integration lands in a later sub-sprint B commit so this
//!   commit stays a small additive module with no behaviour
//!   change for existing admin ops.
//! - **No LSM widening of `/etc/northnarrow/`.** The
//!   `agent.sig.key` and `audit.log` files live under
//!   `/etc/northnarrow/` and become tamper-evident only when the
//!   Tappa 7 FS-LSM hooks extend to that directory in commit A14.
//!   B1 ships the files with the right modes; A14 enforces them
//!   against root.
//! - **No rotation.** Append-only file grows forever in B1. The
//!   rotation policy is RFC item §14 Q9 and tracked for sub-sprint
//!   B's `audit-rotate` commit (or deferred to V1.1 per the design).
//!
//! ## Test surface
//!
//! Eight tests per the design table A11:
//!
//! 1. Signing-key fresh-gen creates the file with mode `0400`.
//! 2. Signing-key reuse-existing returns the same key bytes.
//! 3. Signing-key load on corrupted file errors (no silent regen).
//! 4. `AuditLog::open` on a missing file initialises with the
//!    genesis prev_hash.
//! 5. `AuditLog::append` writes a JSONL line with the correct
//!    chain link + a signature that verifies against the key's
//!    pubkey.
//! 6. Two sequential `append` calls chain correctly
//!    (`second.prev_hash == first.entry_hash`).
//! 7. `verify_chain` rejects an entry whose payload field was
//!    tampered with after writing.
//! 8. `verify_chain` rejects an entry whose signature was
//!    flipped.

use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use rand::rngs::SysRng;
use rand::TryRng;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// Default location of the tamper-evident audit log. Mirrors the
/// `/etc/northnarrow/` install layout (`admin.pub`, `agent_id`).
/// The directory is LSM-protected by commit A14; the file is `0640`
/// ([`AUDIT_LOG_FILE_MODE`], external audit EVD-019).
pub const DEFAULT_AUDIT_LOG_PATH: &str = "/etc/northnarrow/audit.log";

/// Default location of the agent's audit-log signing key. Stored
/// as exactly 32 lowercase-hex bytes + `\n` so an operator can
/// inspect it with `cat` (cf. the agent_id encoding) without the
/// risk of a base64 padding mismatch.
pub const DEFAULT_SIGNING_KEY_PATH: &str = "/etc/northnarrow/agent.sig.key";

/// Genesis chain anchor: 32 zero bytes hex-encoded. The first
/// entry's `prev_hash` is exactly this value, so a verifier
/// replaying the chain from scratch starts with a known
/// well-formed seed regardless of when the log was first written.
pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Owner-read-only — only the boot user (root) loads or rotates
/// it. The file is the LSM-protected signing-key root-of-trust;
/// `0400` keeps a curious non-root admin tool from accidentally
/// reading it before the LSM widening lands.
const SIGNING_KEY_FILE_MODE: u32 = 0o400;

/// `0640`, set when the file is created. External audit EVD-019
/// (NN-AUD-281): it was `0644` in the world-readable `/etc/northnarrow/`,
/// and any local user read key fingerprints, callers' pid/uid/comm,
/// drift details and which sensor was in a `telemetry_gap`. Root and the
/// file's group read it: `install.sh --audit-group GROUP` gives a log
/// shipper the group and closes an existing log (the agent never chmods
/// a log it did not create). Also the mode of the head anchor
/// ([`crate::chain_anchor::HEADS_FILE_MODE`]). Append-only is enforced
/// by `O_APPEND` in this module and by the FS-LSM hooks in commit A14.
pub const AUDIT_LOG_FILE_MODE: u32 = 0o640;

/// Parent directory mode. Conventional `/etc/<vendor>/` layout —
/// root writes, world reads (`admin.pub`, `agent_id` and `agent.sig.pub`
/// are meant to be read; the log is closed by its own mode).
const PARENT_DIR_MODE: u32 = 0o755;

/// Strict pre-decode length check: an Ed25519 secret key is
/// exactly 32 bytes ⇒ exactly 64 hex chars on disk.
const SIGNING_KEY_HEX_LEN: usize = SECRET_KEY_LENGTH * 2;

// ── agent signing key ───────────────────────────────────────────────

/// Agent-owned Ed25519 keypair that signs audit-log entries. The
/// key is **internal** to the agent install — not an admin key,
/// not user-facing — and is rotated only by re-installing the
/// agent. Off-host verifiers consume the pubkey via
/// [`AgentSigningKey::verifying_key`] which the future
/// `nn-admin audit verify` command will accept on the CLI.
///
/// Wrapping `SigningKey` (not transparent newtype) so the
/// secret bytes never accidentally leak through `Debug` or
/// `Display` derives. `Drop` zeroisation is owned by
/// `ed25519-dalek`'s `zeroize` feature in its standard build.
pub struct AgentSigningKey {
    inner: SigningKey,
}

// Manual Debug: never print the secret bytes. We expose the
// public verifying key's fingerprint instead so logs + test
// failure output stay informative without leaking secrets.
impl std::fmt::Debug for AgentSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pk = self.inner.verifying_key().to_bytes();
        write!(f, "AgentSigningKey(pubkey_fp={})", hex::encode(&pk[..4]))
    }
}

impl AgentSigningKey {
    /// Open `path` if it exists, else mint a fresh keypair via
    /// `OsRng` and persist it atomically. Returns the loaded /
    /// minted key.
    ///
    /// Errors are the same shape as
    /// [`crate::agent_id::load_or_bootstrap`]:
    /// - corrupted file (wrong length, non-hex) → hard error,
    ///   operator must investigate. Silent regeneration is
    ///   forbidden because a new key would silently invalidate
    ///   every signature in the existing audit log.
    /// - I/O refused (`EROFS`, `ENOSPC`, missing parent we
    ///   can't create) → propagated with context.
    pub fn load_or_bootstrap(path: &Path) -> Result<Self> {
        match fs::read_to_string(path) {
            Ok(content) => {
                let key = parse_signing_key(&content).with_context(|| {
                    format!(
                        "agent signing key {} present but corrupted — refuse to \
                         silently regenerate; remove the file deliberately if you \
                         intend to mint a new key (note: every existing audit-log \
                         signature stops verifying)",
                        path.display()
                    )
                })?;
                info!(
                    target: "audit.signing_key",
                    path = %path.display(),
                    "reusing existing agent signing key"
                );
                let key = Self { inner: key };
                key.publish_verifying_key(path);
                Ok(key)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key = mint_signing_key()?;
                persist_signing_key_atomically(path, &key)?;
                info!(
                    target: "audit.signing_key",
                    path = %path.display(),
                    "bootstrapped fresh agent signing key"
                );
                let key = Self { inner: key };
                key.publish_verifying_key(path);
                Ok(key)
            }
            Err(e) => Err(anyhow!(e).context(format!("reading {}", path.display()))),
        }
    }

    /// Public verifying key for off-host auditors. Embeds in the
    /// agent binary at build time so `nn-admin audit verify`
    /// doesn't need a separate key distribution step.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.inner.verifying_key()
    }

    /// External audit EVD-001: write the public half next to the key
    /// (`agent.sig.key` → `agent.sig.pub`, 64 hex chars, mode 0444) unless
    /// it already says the same. The private key is closed to every reader
    /// outside the agent's family, root included; `nn-admin audit verify`
    /// and any auditor read this instead. Best effort: a failure is logged.
    pub fn publish_verifying_key(&self, key_path: &Path) {
        let pub_path = verifying_key_path(key_path);
        let want = format!("{}\n", hex::encode(self.verifying_key().to_bytes()));
        if fs::read_to_string(&pub_path).is_ok_and(|have| have == want) {
            return;
        }
        let tmp = pub_path.with_extension("pub.tmp");
        let written = (|| -> std::io::Result<()> {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let _ = fs::remove_file(&tmp);
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o444)
                .open(&tmp)?;
            f.write_all(want.as_bytes())?;
            f.sync_all()?;
            fs::rename(&tmp, &pub_path)
        })();
        match written {
            Ok(()) => info!(
                target: "audit.signing_key",
                path = %pub_path.display(),
                "agent signing key's public half published"
            ),
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                warn!(
                    target: "audit.signing_key",
                    path = %pub_path.display(),
                    error = %e,
                    "could not publish the agent signing key's public half"
                );
            }
        }
    }

    /// Sign `msg` with the agent signing key. Used by
    /// [`AuditLog::append`] to sign `entry_hash`; exposed for
    /// tests + the future `audit verify` reader.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.inner.sign(msg)
    }
}

fn mint_signing_key() -> Result<SigningKey> {
    let mut secret = [0u8; SECRET_KEY_LENGTH];
    SysRng.try_fill_bytes(&mut secret).map_err(|e| {
        anyhow!("the OS random source failed to provide entropy for signing key: {e}")
    })?;
    Ok(SigningKey::from_bytes(&secret))
}

/// External audit EVD-001: where the public half of the signing key at
/// `key_path` lives (`agent.sig.key` → `agent.sig.pub`).
pub fn verifying_key_path(key_path: &Path) -> std::path::PathBuf {
    key_path.with_extension("pub")
}

/// The verifying key `publish_verifying_key` wrote at `path`.
pub fn read_verifying_key(path: &Path) -> Result<VerifyingKey> {
    let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let bytes = hex::decode(raw.trim()).map_err(|e| anyhow!("{}: not hex: {e}", path.display()))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("{}: not 32 bytes", path.display()))?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| anyhow!("{}: not an Ed25519 key: {e}", path.display()))
}

/// The private key at `path`, read and parsed — never minted (legacy
/// verification on a host without `agent.sig.pub`).
pub fn read_signing_key(path: &Path) -> Result<AgentSigningKey> {
    let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(AgentSigningKey {
        inner: parse_signing_key(&raw)?,
    })
}

fn parse_signing_key(raw: &str) -> Result<SigningKey> {
    let trimmed = raw.strip_suffix('\n').unwrap_or(raw);
    if trimmed.contains('\n') || trimmed.contains('\r') {
        return Err(anyhow!(
            "signing key file has embedded newline — expected single-line hex"
        ));
    }
    if trimmed.len() != SIGNING_KEY_HEX_LEN {
        return Err(anyhow!(
            "signing key has {} hex chars (expected {SIGNING_KEY_HEX_LEN})",
            trimmed.len()
        ));
    }
    let bytes = hex::decode(trimmed).map_err(|e| anyhow!("signing key is not valid hex: {e}"))?;
    let mut secret = [0u8; SECRET_KEY_LENGTH];
    secret.copy_from_slice(&bytes);
    Ok(SigningKey::from_bytes(&secret))
}

fn persist_signing_key_atomically(path: &Path, key: &SigningKey) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::DirBuilder::new()
                .mode(PARENT_DIR_MODE)
                .recursive(true)
                .create(parent)
                .with_context(|| format!("creating signing-key parent dir {}", parent.display()))?;
        }
    }
    let tmp_path = tmp_path_for(path);
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(SIGNING_KEY_FILE_MODE)
            .open(&tmp_path)
            .with_context(|| format!("creating signing-key tmpfile {}", tmp_path.display()))?;
        let mut line = hex::encode(key.to_bytes());
        line.push('\n');
        f.write_all(line.as_bytes())
            .with_context(|| format!("writing signing-key bytes to {}", tmp_path.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync {}", tmp_path.display()))?;
    }
    fs::rename(&tmp_path, path)
        .with_context(|| format!("renaming {} → {}", tmp_path.display(), path.display()))?;
    Ok(())
}

fn tmp_path_for(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

// ── audit entry on-disk shape ───────────────────────────────────────

/// One on-disk JSONL record per §9.1. Field order MATTERS for the
/// `entry_hash` computation: we serialise via `serde_json` with
/// the struct's declared field order (`preserve_order` is not
/// needed because `serde_json` already preserves struct order).
/// Re-ordering fields here is a chain-format break — bump
/// [`AUDIT_LOG_FORMAT_VERSION`] if you must.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// ISO-8601 UTC timestamp, microsecond resolution.
    pub ts: String,
    /// Hex of the 16-byte agent install UUID (see
    /// [`crate::agent_id`]).
    pub agent_id: String,
    /// Operation code, e.g. `"unlock"`, `"shutdown"`,
    /// `"force_posture"`. Matches the §4 operation list.
    pub op: String,
    /// Free-form op-specific extra context. JSON value preserves
    /// the wire `*Extra` shape without forcing a strongly-typed
    /// dispatch here.
    pub extra: serde_json::Value,
    /// Hex fingerprint of the primary signer's pubkey (first 8
    /// hex chars of the ed25519 pubkey, same shape `AdminAuth`
    /// uses in log lines).
    pub key_fp: String,
    /// Hex fingerprints of any cosigners (empty for single-sig
    /// ops; non-empty for the §3.3 quorum path).
    pub cosigner_fps: Vec<String>,
    /// `"success"` or `"failure: <reason>"` — the latter is
    /// what the agent logs when it rejected the op (bad sig,
    /// role denied, skew, etc.).
    pub result: String,
    /// PID of the connecting client (`SO_PEERCRED`).
    pub client_pid: u32,
    /// UID of the connecting client (`SO_PEERCRED`).
    pub client_uid: u32,
    /// Comm of the connecting client (best-effort read from
    /// `/proc/<pid>/comm`). Self-reported (external audit ASK-013,
    /// NN-AUD-239): the name the peer gave itself (`prctl(PR_SET_NAME)`,
    /// or the name of whatever it executed) — any process can call itself
    /// `nn-admin`. The operator's identity is the key fingerprint;
    /// [`Self::client_exe`] is the kernel's record of the program.
    pub client_comm: String,
    /// External audit ASK-013 (NN-AUD-239): the executable of the
    /// connecting client, `/proc/<pid>/exe` as the kernel resolves it, read
    /// while the peer was known to be alive (a pidfd checked after the
    /// read). Absent on rows the agent writes for itself, on rows written
    /// before lab PR 179 (which keep their bytes and their pre-image) and
    /// when the link could not be read (a peer gone, a kernel thread).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_exe: Option<String>,
    /// External audit NN-AUD-108: the row's 0-based position in the log.
    /// Absent on rows written before lab PR 160, which keep their exact
    /// bytes and their untagged pre-image; present on every row after,
    /// whose pre-image is prefixed with
    /// [`crate::chain_anchor::AUDIT_DOMAIN_V2`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    /// Hex of the prior entry's `entry_hash`. First record uses
    /// [`GENESIS_PREV_HASH`].
    pub prev_hash: String,
    /// Hex of `SHA-256(prev_hash_bytes || canonical_json_of_entry_minus(entry_hash,agent_sig))`.
    pub entry_hash: String,
    /// Base64-`STANDARD` encoded Ed25519 signature over the raw
    /// 32 bytes of `entry_hash` (hex-decoded). Base64 over the
    /// signature, hex over the hash — both choices match what
    /// the rest of the agent uses for the same primitive types.
    pub agent_sig: String,
}

/// Bumped when the on-disk schema or hash-input bytes change.
/// Verifiers consult this to refuse a chain they were not built
/// to read.
pub const AUDIT_LOG_FORMAT_VERSION: u32 = 1;

/// Fields the user provides to [`AuditLog::append`]. The chain
/// fields (`prev_hash`, `entry_hash`, `agent_sig`) are computed
/// by `append`, never supplied by the caller — that's exactly
/// the property the chain enforces.
#[derive(Debug, Clone)]
pub struct AuditEntryDraft {
    pub op: String,
    pub extra: serde_json::Value,
    pub key_fp: String,
    pub cosigner_fps: Vec<String>,
    pub result: String,
    pub client_pid: u32,
    pub client_uid: u32,
    pub client_comm: String,
    /// The admin socket's peers only (external audit ASK-013).
    pub client_exe: Option<String>,
}

// ── audit log writer ────────────────────────────────────────────────

/// Append-only writer for the audit log. Holds the
/// [`AgentSigningKey`] in memory and tracks the tail-hash so each
/// `append` produces a well-chained next entry. Cheap to keep
/// open for the lifetime of the agent — the underlying file is
/// `O_APPEND`, so a concurrent reader (auditor) sees consistent
/// records without taking a lock.
/// How the previous agent run ended, read from the audit chain at open.
///
/// Every run writes `agent_boot` when it starts and `agent_stop` when it
/// leaves its event loop (SIGTERM from systemd, SIGINT/SIGHUP, signed admin
/// shutdown, sensor exit). A boot with no stop after it means the process
/// was not allowed to finish: SIGKILL (including `systemctl kill` and a
/// write to the unit's `cgroup.kill`, which bypass the `task_kill` hook),
/// the OOM killer, a crash or a power loss. The next boot says so in its
/// own `agent_boot` entry (`previous_run`), so the death is signed evidence
/// even when nothing could refuse it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreviousRun {
    /// No earlier `agent_boot` in this chain.
    None,
    /// The last lifecycle entry is an `agent_stop`.
    Clean { stopped_at: String, reason: String },
    /// The last lifecycle entry is an `agent_boot` with no `agent_stop`.
    Abrupt {
        booted_at: String,
        last_entry_at: String,
    },
}

impl PreviousRun {
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            PreviousRun::None => serde_json::json!({ "ended": "none" }),
            PreviousRun::Clean { stopped_at, reason } => {
                serde_json::json!({ "ended": "clean", "stopped_at": stopped_at, "reason": reason })
            }
            PreviousRun::Abrupt {
                booted_at,
                last_entry_at,
            } => serde_json::json!({
                "ended": "abrupt",
                "booted_at": booted_at,
                "last_entry_at": last_entry_at,
            }),
        }
    }
}

pub struct AuditLog {
    path: PathBuf,
    /// `path` anchored to the directory fd taken at open (review entry 44):
    /// appends cannot be diverted by a later mount over the directory.
    io_path: PathBuf,
    /// How the run before this one ended (from the chain at open).
    previous_run: PreviousRun,
    /// External audit ATP-004: the chain holds a successful
    /// `rotate_keys_add` — the one-key bootstrap is over for good. The
    /// log is never rotated (module doc); a rotation must carry this.
    second_key_added: bool,
    key: AgentSigningKey,
    agent_id: [u8; 16],
    last_hash: String,
    /// External audit NN-AUD-108: rows in the log, the `seq` of the next.
    rows: u64,
    /// A numbered row is already in the log.
    numbered: bool,
    /// The first row-number break the open found, reported once.
    seq_break: Option<String>,
    /// The chain holds the row recording that numbering and head anchoring
    /// started ([`crate::chain_anchor::NUMBERING_STARTED_OP`]).
    anchoring_started: bool,
    /// External audit EVD-020: the `agent_id` of the chain's last row when
    /// it was opened (`None` for an empty chain), compared once by
    /// [`Self::attest_identity`].
    previous_agent_id: Option<String>,
    identity_attested: bool,
}

impl AuditLog {
    /// Open `path` for append + walk any existing entries to
    /// recover `last_hash`. A missing file is treated as empty
    /// (starts the chain at [`GENESIS_PREV_HASH`] — A14's LSM
    /// widening will assert presence at install time).
    ///
    /// Walks but does NOT verify signatures on open — the agent's
    /// hot path must boot quickly even with a long log;
    /// `nn-admin audit verify` (later commit) is the
    /// signature-checking reader.
    pub fn open(path: &Path, key: AgentSigningKey, agent_id: [u8; 16]) -> Result<Self> {
        // External audit EVD-005: a last write cut short (crash, power
        // loss) left a fragment that `read_tail` refused, and the agent
        // would not start again in enforce mode. Only that fragment is
        // repaired — and attested below; a bad line before the end is
        // corruption and still refuses the log, untouched.
        let repair = crate::chainlog::repair_torn_tail(path, |l| {
            serde_json::from_slice::<AuditEntry>(l).is_ok()
        })?;
        let tail = read_tail(path)?;
        // Ensure the parent directory exists with the canonical
        // mode so the first append never fails on a missing
        // `/etc/northnarrow/` install.
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                fs::DirBuilder::new()
                    .mode(PARENT_DIR_MODE)
                    .recursive(true)
                    .create(parent)
                    .with_context(|| {
                        format!("creating audit-log parent dir {}", parent.display())
                    })?;
            }
        }
        let mut log = Self {
            path: path.to_path_buf(),
            io_path: crate::anchored::anchor(path),
            key,
            agent_id,
            last_hash: tail.last_hash,
            previous_run: tail.previous_run,
            second_key_added: tail.second_key_added,
            rows: tail.seq.rows(),
            numbered: tail.seq.numbered(),
            seq_break: tail.seq_break,
            anchoring_started: tail.anchoring_started,
            previous_agent_id: tail.last_agent_id,
            identity_attested: false,
        };
        if let Some(r) = repair {
            log.attest_tail_repair(path, &r)?;
        }
        Ok(log)
    }

    /// Record in the signed chain that `file`'s torn last write was
    /// repaired ([`crate::chainlog::repair_torn_tail`]): what was dropped
    /// is fingerprinted, so a boot repair can be told from tampering.
    pub fn attest_tail_repair(
        &mut self,
        file: &Path,
        repair: &crate::chainlog::TailRepair,
    ) -> Result<()> {
        tracing::warn!(
            file = %file.display(),
            detail = %repair.describe(),
            "chain log: torn last write repaired"
        );
        self.append(AuditEntryDraft {
            op: CHAIN_TAIL_REPAIRED_OP.to_string(),
            extra: serde_json::json!({
                "file": file.display().to_string(),
                "detail": repair.describe(),
            }),
            key_fp: "agent-self".to_string(),
            cosigner_fps: Vec::new(),
            result: "repaired".to_string(),
            client_pid: std::process::id(),
            client_uid: 0,
            client_comm: "northnarrow-agent".to_string(),
            client_exe: None,
        })
        .map(|_| ())
        .context("audit log: chain_tail_repaired entry")
    }

    /// Record in the signed chain that `file` holds lines that could not
    /// be read and were skipped (external audit DEC-006: the subsystem
    /// keeps working on the readable ones instead of switching off).
    pub fn attest_skipped_lines(&mut self, file: &Path, skipped: usize) -> Result<()> {
        tracing::error!(
            file = %file.display(),
            skipped,
            "chain log: unreadable lines skipped — corruption or tampering"
        );
        self.append(AuditEntryDraft {
            op: crate::self_integrity::AUDIT_OP.to_string(),
            extra: serde_json::json!({
                "kind": "chain_lines_unreadable",
                "detail": format!("{}: {skipped} unreadable line(s) skipped at boot", file.display()),
                "at_boot": true,
            }),
            key_fp: "agent-self".to_string(),
            cosigner_fps: Vec::new(),
            result: "detected".to_string(),
            client_pid: std::process::id(),
            client_uid: 0,
            client_comm: "northnarrow-agent".to_string(),
            client_exe: None,
        })
        .map(|_| ())
        .context("audit log: chain_lines_unreadable entry")
    }

    /// How the previous run ended (see [`PreviousRun`]).
    pub fn previous_run(&self) -> &PreviousRun {
        &self.previous_run
    }

    /// External audit ATP-004: a second admin key was added at some point
    /// (a signed `rotate_keys_add` success in the chain).
    pub fn second_key_added(&self) -> bool {
        self.second_key_added
    }

    /// External audit NN-AUD-108: the log already holds a numbered row
    /// (written by lab PR 160 or later).
    pub fn numbered(&self) -> bool {
        self.numbered
    }

    /// Rows in the log: the `seq` the next row carries.
    pub fn rows(&self) -> u64 {
        self.rows
    }

    /// The chain records that head anchoring started (lab PR 160).
    pub fn anchoring_started(&self) -> bool {
        self.anchoring_started
    }

    /// What the open found wrong with the row numbers, for the caller to
    /// attest once: rows removed or inserted before the end.
    pub fn take_open_findings(&mut self, file: &Path) -> Vec<crate::chain_anchor::ChainFinding> {
        self.seq_break
            .take()
            .map(|why| {
                crate::chain_anchor::ChainFinding::new("audit", file, "chain_sequence_broken", why)
            })
            .into_iter()
            .collect()
    }

    /// External audit EVD-020 (NN-AUD-282) and MAIN-009 (NN-AUD-251): the
    /// identity this boot signs as, in the signed chain, once per open.
    ///
    /// - minted ([`IdentitySource::Minted`]): an `agent_id_minted` row;
    /// - unusable ([`IdentitySource::Unavailable`]): `integrity_drift`
    ///   `subsystem_degraded` naming the reason and the per-boot id;
    /// - an id other than the one the chain's last row carries (the file
    ///   removed and re-minted, replaced, or unusable while the agent was
    ///   not running): ERROR and `integrity_drift` `agent_id_changed` with
    ///   `from` and `to`, signed with the agent key that signed the rows
    ///   before — the link between the two identities.
    ///
    /// An unchanged identity loaded from the file adds nothing.
    ///
    /// [`IdentitySource::Minted`]: crate::agent_id::IdentitySource::Minted
    /// [`IdentitySource::Unavailable`]: crate::agent_id::IdentitySource::Unavailable
    pub fn attest_identity(&mut self, identity: &crate::agent_id::AgentIdentity) -> Result<()> {
        use crate::agent_id::IdentitySource;
        if std::mem::replace(&mut self.identity_attested, true) {
            return Ok(());
        }
        let file = identity.path.display().to_string();
        let to = hex::encode(self.agent_id);
        let from = self.previous_agent_id.clone();
        let self_row = |op: &str, extra: serde_json::Value, result: &str| AuditEntryDraft {
            op: op.to_string(),
            extra,
            key_fp: "agent-self".to_string(),
            cosigner_fps: Vec::new(),
            result: result.to_string(),
            client_pid: std::process::id(),
            client_uid: 0,
            client_comm: "northnarrow-agent".to_string(),
            client_exe: None,
        };
        match &identity.source {
            IdentitySource::Loaded => {}
            IdentitySource::Minted => {
                self.append(self_row(
                    AGENT_ID_MINTED_OP,
                    serde_json::json!({
                        "file": file,
                        "agent_id": to,
                        "previous": from,
                    }),
                    "success",
                ))
                .context("audit log: agent_id_minted entry")?;
            }
            IdentitySource::Unavailable(reason) => {
                self.append(self_row(
                    crate::self_integrity::AUDIT_OP,
                    serde_json::json!({
                        "kind": "subsystem_degraded",
                        "detail": format!(
                            "agent_id unavailable ({file}: {reason}): this boot signs as the \
                             per-boot id {to}, never written; signed admin requests and overlays \
                             made for the install's id are refused until the file is repaired"
                        ),
                        "at_boot": true,
                    }),
                    "detected",
                ))
                .context("audit log: agent_id subsystem_degraded entry")?;
            }
        }
        if let Some(from) = from.filter(|f| *f != to) {
            let source = identity.source.label();
            let how = match &identity.source {
                IdentitySource::Loaded => "replaced",
                IdentitySource::Minted => "removed and minted again",
                IdentitySource::Unavailable(_) => "unusable",
            };
            tracing::error!(
                from = %common::log_escape::Escaped(&from),
                to = %to,
                source,
                path = %file,
                "AGENT IDENTITY CHANGED — the audit chain's last row was signed as another \
                 agent_id: the file was {how} while the agent was not running; admin \
                 signatures and overlays made for the old id no longer verify"
            );
            self.append(self_row(
                crate::self_integrity::AUDIT_OP,
                serde_json::json!({
                    "kind": AGENT_ID_CHANGED_KIND,
                    "from": from,
                    "to": to,
                    "source": source,
                    "file": file,
                    "detail": format!(
                        "the chain's last row was signed as {from}, this boot signs as {to}: \
                         {file} was {how} while the agent was not running"
                    ),
                    "at_boot": true,
                }),
                "detected",
            ))
            .context("audit log: agent_id_changed entry")?;
        }
        Ok(())
    }

    /// `agent_stop` entry: the event loop is over and the process is about
    /// to exit on its own terms. `reason` is the path out of the loop.
    pub fn stop_entry(&mut self, reason: &str, uptime_secs: u64) -> Result<AuditEntry> {
        self.append(AuditEntryDraft {
            op: "agent_stop".to_string(),
            extra: serde_json::json!({ "reason": reason, "uptime_secs": uptime_secs }),
            key_fp: "agent-self".to_string(),
            cosigner_fps: Vec::new(),
            result: "success".to_string(),
            client_pid: std::process::id(),
            client_uid: 0,
            client_comm: "northnarrow-agent".to_string(),
            client_exe: None,
        })
        .context("audit log stop entry (agent_stop)")
    }

    /// Append one record. Computes timestamp + chain hash +
    /// signature, writes one `\n`-terminated JSON line via
    /// `O_APPEND` (atomic for writes under PIPE_BUF on Linux,
    /// and JSONL lines on the agent's hot path are well under
    /// 4 KiB — typical entry is <500 bytes). On success advances
    /// the in-memory tail hash and returns the entry as
    /// persisted.
    pub fn append(&mut self, draft: AuditEntryDraft) -> Result<AuditEntry> {
        let entry = build_signed_entry(
            &draft,
            &self.key,
            &self.agent_id,
            &self.last_hash,
            self.rows,
        )?;
        let mut line =
            serde_json::to_string(&entry).map_err(|e| anyhow!("serialising audit entry: {e}"))?;
        line.push('\n');
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(AUDIT_LOG_FILE_MODE)
            .open(&self.io_path)
            .with_context(|| format!("opening audit log {} for append", self.path.display()))?;
        f.write_all(line.as_bytes())
            .with_context(|| format!("appending audit entry to {}", self.path.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync {}", self.path.display()))?;
        self.last_hash = entry.entry_hash.clone();
        self.rows += 1;
        self.numbered = true;
        // External audit ATP-004 / NN-AUD-108: the head anchor carries this
        // flag; it must not wait for the next open to be seen.
        if entry.op == "rotate_keys_add" && entry.result == "success" {
            self.second_key_added = true;
        }
        if entry.op == crate::chain_anchor::NUMBERING_STARTED_OP {
            self.anchoring_started = true;
        }
        Ok(entry)
    }

    /// Tail hash an auditor would chain the NEXT entry off. Test
    /// helper + future-proofing for the off-host reader.
    pub fn last_hash(&self) -> &str {
        &self.last_hash
    }

    /// A boot the agent REFUSES because the install-manifest check
    /// failed: the refusal is written into the signed chain before the
    /// process exits, so a tampered binary leaves a trace that root
    /// cannot quietly remove (lab PR 21). `result` is `refused`.
    pub fn boot_refused(
        &mut self,
        integrity: &str,
        provenance: &str,
        detail: &str,
    ) -> Result<AuditEntry> {
        self.boot_refused_by("install_manifest", integrity, provenance, detail)
    }

    /// Lab PR 218: [`Self::boot_refused`] for any boot gate — `refused_by`
    /// names it (`install_manifest`, `bpf_lsm`, `deny_self_test`).
    pub fn boot_refused_by(
        &mut self,
        gate: &str,
        integrity: &str,
        provenance: &str,
        detail: &str,
    ) -> Result<AuditEntry> {
        self.append(AuditEntryDraft {
            op: "agent_boot".to_string(),
            extra: serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "refused_by": gate,
                "binary_integrity": integrity,
                "install_provenance": provenance,
                "detail": detail,
            }),
            key_fp: "agent-self".to_string(),
            cosigner_fps: Vec::new(),
            result: "refused".to_string(),
            client_pid: std::process::id(),
            client_uid: 0,
            client_comm: "northnarrow-agent".to_string(),
            client_exe: None,
        })
    }

    /// Boot-time write probe (review `etc-readonly-audit-1`): append a
    /// signed `agent_boot` entry so an unwritable audit log is found at
    /// startup, not at the first COMBAT transition. The entry doubles
    /// as a useful chain marker (boot pid, binary version, mode).
    ///
    /// `integrity` / `provenance` come from the install-manifest check
    /// (`crate::install_manifest`): what the installer could verify about
    /// the release and whether the binaries running now still match it.
    /// `detect_only`: where detect-only mode came from (`--detect-only` or
    /// `NAME=value` of the variable), `None` when the agent enforces.
    pub fn boot_probe(
        &mut self,
        detect_only: Option<&str>,
        integrity: &str,
        provenance: &str,
    ) -> Result<AuditEntry> {
        self.append(AuditEntryDraft {
            op: "agent_boot".to_string(),
            extra: serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "detect_only": detect_only.is_some(),
                // External audit MAIN-008: the source, not only the bool.
                "detect_only_source": detect_only,
                "binary_integrity": integrity,
                "install_provenance": provenance,
                "previous_run": self.previous_run.to_json(),
                // External audit ATP-009: what the build is and how the BPF
                // guard runs — a debug-trigger build only observes.
                "build_features": build_features(),
                "bpf_guard": if crate::anti_tamper::bpf_defense::enforce_mode() {
                    "enforce"
                } else {
                    "observe"
                },
            }),
            key_fp: "agent-self".to_string(),
            cosigner_fps: Vec::new(),
            result: "success".to_string(),
            client_pid: std::process::id(),
            client_uid: 0,
            client_comm: "northnarrow-agent".to_string(),
            client_exe: None,
        })
        .context("audit log boot probe (agent_boot entry)")
    }
}

/// External audit ATP-009: the test and debug features this binary was
/// built with — none in a release build. Also printed by
/// `northnarrow-agent --build-features`, which the range bootstrap checks
/// before it installs a binary (external audit NN-AUD-211) and the release
/// workflow checks on every artefact it builds (external audit PROC-015).
pub fn build_features() -> Vec<&'static str> {
    LAB_FEATURES
        .iter()
        .filter(|(_, built)| *built)
        .map(|(name, _)| *name)
        .collect()
}

/// External audit PROC-015 (NN-AUD-302): every cargo feature of this crate
/// (`agent/Cargo.toml`), with whether this binary was built with it. All
/// of them are test, debug or demo features, none is a default, and
/// `agent/tests/build_features_cli.rs` holds this list to the manifest, so
/// a new feature cannot be added without [`build_features`] naming it.
pub const LAB_FEATURES: &[(&str, bool)] = &[
    ("debug-trigger", cfg!(feature = "debug-trigger")),
    ("demo-tappa5", cfg!(feature = "demo-tappa5")),
    // POS-013, WDG-R02: builds `examples/posture_demo.rs` only.
    ("posture-demo", cfg!(feature = "posture-demo")),
    ("test-privileged", cfg!(feature = "test-privileged")),
];

/// Audit op recording a repaired torn tail of a chain log.
pub const CHAIN_TAIL_REPAIRED_OP: &str = "chain_tail_repaired";

/// External audit EVD-020: the agent minted its identity
/// ([`AuditLog::attest_identity`]).
pub const AGENT_ID_MINTED_OP: &str = "agent_id_minted";

/// External audit EVD-020: the `integrity_drift` kind of an identity other
/// than the one the chain's last row carries.
pub const AGENT_ID_CHANGED_KIND: &str = "agent_id_changed";

/// Escape hatch: run with an unwritable / unopenable audit log.
pub const AUDIT_ALLOW_UNWRITABLE_ENV: &str = "NN_AUDIT_ALLOW_UNWRITABLE";

/// Lab PR 218 (external review G-09 / Q11-03): whether the audit log can be
/// written, checked before anything attaches. The signed `agent_boot` after
/// the attach still proves it with a row; this finds a read-only mount, an
/// immutable file or a missing directory while the host is untouched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditPreflight {
    /// Opened for append (no byte written), or its directory is writable.
    Writable,
    /// Refused with a permission error while the previous agent's pinned
    /// hooks may close it to this process (its early registration failed):
    /// the boot probe after the attach decides.
    Deferred(String),
    /// Cannot be written.
    Unwritable(String),
}

/// [`AuditPreflight`] for `path`; `closed_by_previous_hooks`: the early
/// registration in the pinned `PROTECTED_PIDS` failed.
pub fn preflight_writable(path: &Path, closed_by_previous_hooks: bool) -> AuditPreflight {
    let refused = |e: &std::io::Error| {
        if closed_by_previous_hooks && e.kind() == std::io::ErrorKind::PermissionDenied {
            AuditPreflight::Deferred(format!(
                "{}: {e} (the previous agent's hooks close it to an unregistered process)",
                path.display()
            ))
        } else {
            AuditPreflight::Unwritable(format!("{}: {e}", path.display()))
        }
    };
    match OpenOptions::new().append(true).open(path) {
        Ok(_) => AuditPreflight::Writable,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Created at the first append: its directory must take it.
            let dir = match path.parent() {
                Some(d) if !d.as_os_str().is_empty() => d,
                _ => Path::new("."),
            };
            match dir_writable(dir) {
                Ok(()) => AuditPreflight::Writable,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // `AuditLog::open` creates a missing directory: its
                    // nearest existing ancestor must take it.
                    match dir.ancestors().skip(1).find(|a| a.exists()) {
                        Some(a) => match dir_writable(a) {
                            Ok(()) => AuditPreflight::Writable,
                            Err(e) => refused(&e),
                        },
                        None => refused(&e),
                    }
                }
                Err(e) => refused(&e),
            }
        }
        Err(e) => refused(&e),
    }
}

/// `access(dir, W_OK)`: `EROFS` on a read-only mount.
fn dir_writable(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(dir.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    // SAFETY: a NUL-terminated path and a mode constant.
    if unsafe { libc::access(c.as_ptr(), libc::W_OK) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Is an audit-log failure at boot fatal? Yes unless the operator set the
/// explicit override: an audit chain that silently stops is a silently
/// absent control (same posture as the LSM deny-hook shortfall,
/// `ebpf-lsm-1`). External audit MAIN-008: detect-only no longer implies
/// the override — one variable used to disarm the response and lift this
/// gate together.
pub fn audit_failure_is_fatal(allow_env: Option<&str>) -> bool {
    allow_env != Some("1")
}

/// External audit DEP-009: does the chain at `path` hold a successful
/// `agent_boot` whose binaries matched the install manifest
/// (`binary_integrity` = `verified`)? Then this host was installed with a
/// manifest, and a missing one was removed. A missing or empty file is a
/// fresh chain (`false`); a line that does not parse is an error — the
/// caller cannot tell. Read-only, without the torn-tail repair of
/// [`AuditLog::open`].
pub fn verified_boot_recorded(path: &Path) -> Result<bool> {
    Ok(read_tail(path)?.verified_boot)
}

/// What [`read_tail`] recovers from the log.
struct TailState {
    last_hash: String,
    previous_run: PreviousRun,
    second_key_added: bool,
    seq: crate::chain_anchor::RowSeq,
    /// The first row-number break (NN-AUD-108), as a sentence.
    seq_break: Option<String>,
    anchoring_started: bool,
    /// External audit DEP-009, see [`verified_boot_recorded`].
    verified_boot: bool,
    /// External audit EVD-020: the last row's `agent_id`.
    last_agent_id: Option<String>,
}

/// Read the final `entry_hash` from `path`, or
/// [`GENESIS_PREV_HASH`] if the file is missing / empty. Errors
/// on a malformed final line — that is exactly the corruption
/// signal A12's verify-on-read flow surfaces, but for the
/// agent's write path the early failure is preferable to
/// chaining off garbage.
///
/// External audit NN-AUD-108: the walk also checks the row numbers (no
/// signature work: a missing or extra row before the end is found at
/// every open) and counts the rows, the `seq` of the next one.
fn read_tail(path: &Path) -> Result<TailState> {
    let mut seq = crate::chain_anchor::RowSeq::default();
    let mut seq_break = None;
    let f = match OpenOptions::new().read(true).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(TailState {
                last_hash: GENESIS_PREV_HASH.to_string(),
                previous_run: PreviousRun::None,
                second_key_added: false,
                seq,
                seq_break,
                anchoring_started: false,
                verified_boot: false,
                last_agent_id: None,
            });
        }
        Err(e) => return Err(anyhow!(e).context(format!("reading {}", path.display()))),
    };
    let reader = BufReader::new(f);
    let mut last: Option<String> = None;
    let mut last_ts = String::new();
    let mut previous = PreviousRun::None;
    let mut second_key_added = false;
    let mut verified_boot = false;
    let mut anchoring_started = false;
    let mut last_agent_id = None;
    for line in reader.lines() {
        let line = line.with_context(|| format!("reading line from {}", path.display()))?;
        if line.is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_str(&line)
            .with_context(|| format!("parsing audit-log line: {line}"))?;
        if entry.op == crate::chain_anchor::NUMBERING_STARTED_OP {
            anchoring_started = true;
        }
        if let Err(b) = seq.push(entry.seq) {
            seq_break.get_or_insert_with(|| format!("{}: {b}", path.display()));
        }
        match entry.op.as_str() {
            "agent_boot" => {
                if entry.result == "success"
                    && entry.extra.get("binary_integrity").and_then(|v| v.as_str())
                        == Some("verified")
                {
                    verified_boot = true;
                }
                previous = PreviousRun::Abrupt {
                    booted_at: entry.ts.clone(),
                    last_entry_at: entry.ts.clone(),
                }
            }
            "agent_stop" => {
                previous = PreviousRun::Clean {
                    stopped_at: entry.ts.clone(),
                    reason: entry
                        .extra
                        .get("reason")
                        .and_then(|r| r.as_str())
                        .unwrap_or("unknown")
                        .to_string(),
                }
            }
            "rotate_keys_add" if entry.result == "success" => second_key_added = true,
            _ => {}
        }
        last_ts = entry.ts.clone();
        last = Some(entry.entry_hash);
        last_agent_id = Some(entry.agent_id);
    }
    if let PreviousRun::Abrupt { last_entry_at, .. } = &mut previous {
        *last_entry_at = last_ts;
    }
    Ok(TailState {
        last_hash: last.unwrap_or_else(|| GENESIS_PREV_HASH.to_string()),
        previous_run: previous,
        second_key_added,
        seq,
        seq_break,
        anchoring_started,
        verified_boot,
        last_agent_id,
    })
}

/// Pure helper: compute `entry_hash` + signature for a draft
/// against a given `prev_hash` and signing key. Extracted from
/// [`AuditLog::append`] so [`verify_chain`] can recompute the
/// same bytes for cross-check.
fn build_signed_entry(
    draft: &AuditEntryDraft,
    key: &AgentSigningKey,
    agent_id: &[u8; 16],
    prev_hash: &str,
    seq: u64,
) -> Result<AuditEntry> {
    let ts = format_ts(Utc::now());
    let mut entry = AuditEntry {
        ts,
        agent_id: hex::encode(agent_id),
        op: draft.op.clone(),
        extra: draft.extra.clone(),
        key_fp: draft.key_fp.clone(),
        cosigner_fps: draft.cosigner_fps.clone(),
        result: draft.result.clone(),
        client_pid: draft.client_pid,
        client_uid: draft.client_uid,
        client_comm: draft.client_comm.clone(),
        client_exe: draft.client_exe.clone(),
        seq: Some(seq),
        prev_hash: prev_hash.to_string(),
        // Filled below — empty here so they are excluded from the
        // hashed pre-image.
        entry_hash: String::new(),
        agent_sig: String::new(),
    };
    let entry_hash = compute_entry_hash(&entry)?;
    entry.entry_hash = hex::encode(entry_hash);
    let sig = key.sign(&entry_hash);
    entry.agent_sig = B64.encode(sig.to_bytes());
    Ok(entry)
}

/// Compute `entry_hash` over the canonical pre-image:
/// `SHA-256(prev_hash_bytes || canonical_json(entry minus
/// entry_hash + agent_sig))`. Both `entry_hash` and `agent_sig`
/// MUST be empty strings at call time so the JSON pre-image
/// stays free of those fields' eventual contents — verifiers
/// reproduce the same bytes by clearing those fields before
/// recomputing.
///
/// External audit NN-AUD-108 / NN-AUD-174: a numbered row (`seq` set)
/// prefixes the pre-image with [`crate::chain_anchor::AUDIT_DOMAIN_V2`];
/// a row without `seq` keeps the pre-image it was signed with.
///
/// External audit EVD-023 (NN-AUD-427, lab PR 204): an entry that still
/// carries `entry_hash` or `agent_sig` is an error in every build.
pub(crate) fn compute_entry_hash(entry: &AuditEntry) -> Result<[u8; 32]> {
    crate::chain_anchor::check_unsealed(&entry.entry_hash, &entry.agent_sig)?;
    let body =
        serde_json::to_vec(entry).map_err(|e| anyhow!("serialising audit pre-image: {e}"))?;
    let domain = entry.seq.map(|_| crate::chain_anchor::AUDIT_DOMAIN_V2);
    crate::chain_anchor::flat_digest(domain, &entry.prev_hash, &body)
}

/// External audit NN-AUD-108: whether one raw line is a genuine audit row
/// (decodes, its hash recomputes, its signature verifies). External audit
/// EVD-007 (lab PR 204): a numbered row must also be in its canonical bytes.
pub fn row_is_genuine(line: &[u8], pubkey: &VerifyingKey) -> bool {
    serde_json::from_slice::<AuditEntry>(line).is_ok_and(|e| {
        verify_entry(0, &e, pubkey).is_ok()
            && (e.seq.is_none() || crate::chain_anchor::is_canonical(&e, line))
    })
}

pub(crate) fn format_ts(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
}

// ── off-host verifier ───────────────────────────────────────────────

/// Outcome of one [`verify_chain`] run on a tampered chain.
/// Carrying the 0-based index lets the operator pinpoint the
/// first broken entry without re-running the verifier.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuditVerifyError {
    #[error("entry {idx}: prev_hash {got} does not match expected {expected}")]
    PrevHashMismatch {
        idx: usize,
        got: String,
        expected: String,
    },
    #[error("entry {idx}: entry_hash mismatch (recomputed {recomputed}, stored {stored})")]
    EntryHashMismatch {
        idx: usize,
        recomputed: String,
        stored: String,
    },
    #[error("entry {idx}: agent_sig invalid")]
    SignatureInvalid { idx: usize },
    #[error("entry {idx}: malformed field — {reason}")]
    MalformedField { idx: usize, reason: String },
    /// External audit NN-AUD-108: a numbered row out of place.
    #[error("entry {idx}: {reason}")]
    Sequence {
        idx: usize,
        reason: crate::chain_anchor::SeqBreak,
    },
    /// External audit EVD-007 (NN-AUD-273, lab PR 204): a numbered row whose
    /// hash and signature verify, but whose bytes on disk are not its
    /// canonical serialisation (a key added, keys reordered, a value spelled
    /// another way): the signature does not cover those bytes.
    #[error(
        "entry {idx}: a numbered row not in its canonical form (the bytes on disk are not what \
         the agent wrote: a key added, reordered or re-spelled)"
    )]
    NonCanonical { idx: usize },
    /// External audit MAIN-014 (NN-AUD-256, lab PR 190): a line of the file
    /// that is not an audit row — cut, not JSON, not UTF-8, or over the line
    /// cap ([`crate::verify_lines::MAX_VERIFY_LINE_BYTES`]). The chain is
    /// broken there; `line` is 1-based in the file, `verified` the rows
    /// before it that verified. It was an I/O-style error (exit 1).
    #[error("line {line}: not an audit row ({reason}); {verified} row(s) verified before it")]
    UnreadableLine {
        line: u64,
        verified: usize,
        reason: String,
    },
}

/// External audit MAIN-014 (NN-AUD-256, lab PR 190): the audit chain
/// verified one row at a time, in file order — [`verify_chain`] over a
/// slice, [`verify_chain_file`] over a file without keeping its rows. What
/// it keeps is the last `entry_hash`, the row-number state and counters.
pub struct ChainVerifier<'k> {
    pubkey: &'k VerifyingKey,
    prev: String,
    seq: crate::chain_anchor::RowSeq,
    rows: usize,
    first_numbered: Option<usize>,
    last_seq: Option<u64>,
    non_canonical_legacy: usize,
}

impl<'k> ChainVerifier<'k> {
    /// A chain that starts at [`GENESIS_PREV_HASH`].
    pub fn new(pubkey: &'k VerifyingKey) -> Self {
        Self {
            pubkey,
            prev: GENESIS_PREV_HASH.to_string(),
            seq: crate::chain_anchor::RowSeq::default(),
            rows: 0,
            first_numbered: None,
            last_seq: None,
            non_canonical_legacy: 0,
        }
    }

    /// The next row: its number, its link to the row before, its hash and
    /// signature. On `Err` the chain is broken at this row and the verifier
    /// must not be fed further.
    pub fn push(&mut self, entry: &AuditEntry) -> Result<(), AuditVerifyError> {
        self.push_checked(entry, None)
    }

    /// [`Self::push`] for a row read from a file: `raw` is its line as on
    /// disk (without the newline). External audit EVD-007 (NN-AUD-273, lab
    /// PR 204): a numbered row must be its canonical serialisation
    /// ([`AuditVerifyError::NonCanonical`]); a row without `seq` that is not
    /// is counted ([`Self::non_canonical_legacy`]).
    pub fn push_line(&mut self, entry: &AuditEntry, raw: &[u8]) -> Result<(), AuditVerifyError> {
        self.push_checked(entry, Some(raw))
    }

    fn push_checked(
        &mut self,
        entry: &AuditEntry,
        raw: Option<&[u8]>,
    ) -> Result<(), AuditVerifyError> {
        let idx = self.rows;
        self.seq
            .push(entry.seq)
            .map_err(|reason| AuditVerifyError::Sequence { idx, reason })?;
        if entry.prev_hash != self.prev {
            return Err(AuditVerifyError::PrevHashMismatch {
                idx,
                got: entry.prev_hash.clone(),
                expected: self.prev.clone(),
            });
        }
        verify_entry(idx, entry, self.pubkey)?;
        if let Some(raw) = raw {
            if !crate::chain_anchor::is_canonical(entry, raw) {
                if entry.seq.is_some() {
                    return Err(AuditVerifyError::NonCanonical { idx });
                }
                self.non_canonical_legacy += 1;
            }
        }
        self.prev.clone_from(&entry.entry_hash);
        if entry.seq.is_some() {
            self.first_numbered.get_or_insert(idx);
            self.last_seq = entry.seq;
        }
        self.rows += 1;
        Ok(())
    }

    /// Rows verified.
    pub fn rows(&self) -> usize {
        self.rows
    }

    /// Position of the first numbered row (rows before it are in the format
    /// from before lab PR 160).
    pub fn first_numbered(&self) -> Option<usize> {
        self.first_numbered
    }

    /// `seq` of the last numbered row verified.
    pub fn last_seq(&self) -> Option<u64> {
        self.last_seq
    }

    /// Rows without `seq` (the format from before lab PR 160) whose bytes
    /// are not their canonical serialisation: they verify as they always
    /// did; the signature does not cover those bytes.
    pub fn non_canonical_legacy(&self) -> usize {
        self.non_canonical_legacy
    }
}

/// Replay `entries` in order, recomputing each `entry_hash` and
/// checking each `agent_sig` against `pubkey`. Returns `Ok(())` on
/// a fully-intact chain. `nn-admin audit verify` and `nn-admin chain
/// verify` read the file through [`verify_chain_file`], the same
/// [`ChainVerifier`] (`AuditLog::open` does not call it).
///
/// External audit NN-AUD-108: rows without `seq` (written before lab PR
/// 160) verify as before; from the first numbered row on, every row must
/// carry its position (`seq == idx`), so a row removed or inserted before
/// the end breaks the chain even where the hashes would still link.
pub fn verify_chain(entries: &[AuditEntry], pubkey: &VerifyingKey) -> Result<(), AuditVerifyError> {
    let mut v = ChainVerifier::new(pubkey);
    for entry in entries {
        v.push(entry)?;
    }
    Ok(())
}

/// What [`verify_chain_file`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainFileReport {
    /// Rows verified: all of them when `broken` is `None`, those before the
    /// break otherwise.
    pub rows: usize,
    /// Position of the first numbered row.
    pub first_numbered: Option<usize>,
    /// `seq` of the last numbered row verified.
    pub last_seq: Option<u64>,
    /// External audit EVD-007 (lab PR 204): rows without `seq` not in their
    /// canonical bytes ([`ChainVerifier::non_canonical_legacy`]).
    pub non_canonical_legacy: usize,
    /// The `entry_hash` asked for is one of the rows verified.
    pub head_seen: bool,
    /// Where and why the chain is broken (the first break; the file is not
    /// read past it).
    pub broken: Option<AuditVerifyError>,
}

/// External audit MAIN-014 (NN-AUD-256, lab PR 190): verify the audit chain
/// in `path` in one pass, one bounded line in memory at a time
/// ([`crate::verify_lines`]); `head`: an `entry_hash` whose presence is
/// reported in [`ChainFileReport::head_seen`]. A missing file is an empty
/// chain. A line that is not a row breaks the chain there
/// ([`AuditVerifyError::UnreadableLine`]), like a row that does not
/// verify. `Err` only when the file cannot be read.
pub fn verify_chain_file(
    path: &Path,
    pubkey: &VerifyingKey,
    head: Option<&str>,
) -> std::io::Result<ChainFileReport> {
    let mut report = ChainFileReport {
        rows: 0,
        first_numbered: None,
        last_seq: None,
        non_canonical_legacy: 0,
        head_seen: false,
        broken: None,
    };
    let f = match OpenOptions::new().read(true).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(report),
        Err(e) => return Err(e),
    };
    let mut v = ChainVerifier::new(pubkey);
    let mut lines = crate::verify_lines::VerifyLines::new(BufReader::new(f));
    while let Some(line) = lines.next_line()? {
        if line.is_empty() {
            continue;
        }
        let entry = line.text().and_then(|t| {
            serde_json::from_str::<AuditEntry>(t).map_err(|e| {
                if line.newline {
                    format!("not a row: {e}")
                } else {
                    format!("the last line, cut short (no newline): {e}")
                }
            })
        });
        let pushed = match entry {
            Ok(entry) => v
                .push_line(&entry, line.text().unwrap_or_default().as_bytes())
                .map(|()| head == Some(entry.entry_hash.as_str())),
            Err(reason) => Err(AuditVerifyError::UnreadableLine {
                line: line.number,
                verified: v.rows(),
                reason,
            }),
        };
        match pushed {
            Ok(seen) => report.head_seen |= seen,
            Err(e) => {
                report.broken = Some(e);
                break;
            }
        }
    }
    report.rows = v.rows();
    report.first_numbered = v.first_numbered();
    report.last_seq = v.last_seq();
    report.non_canonical_legacy = v.non_canonical_legacy();
    Ok(report)
}

/// One entry on its own (external audit LLMR-014): its `entry_hash`
/// recomputed from its content and `prev_hash`, its `agent_sig` checked
/// against `pubkey`. The link to the entry before is the caller's
/// ([`verify_chain`]); `idx` only labels the error.
pub fn verify_entry(
    idx: usize,
    entry: &AuditEntry,
    pubkey: &VerifyingKey,
) -> Result<(), AuditVerifyError> {
    // Recompute against a "stripped" copy with both chain-output fields
    // cleared, matching the pre-image build_signed_entry hashed.
    let mut stripped = entry.clone();
    stripped.entry_hash.clear();
    stripped.agent_sig.clear();
    let recomputed =
        compute_entry_hash(&stripped).map_err(|e| AuditVerifyError::MalformedField {
            idx,
            reason: e.to_string(),
        })?;
    let recomputed_hex = hex::encode(recomputed);
    if recomputed_hex != entry.entry_hash {
        return Err(AuditVerifyError::EntryHashMismatch {
            idx,
            recomputed: recomputed_hex,
            stored: entry.entry_hash.clone(),
        });
    }
    let sig_bytes = B64
        .decode(&entry.agent_sig)
        .map_err(|e| AuditVerifyError::MalformedField {
            idx,
            reason: format!("agent_sig base64 decode: {e}"),
        })?;
    if sig_bytes.len() != 64 {
        return Err(AuditVerifyError::MalformedField {
            idx,
            reason: format!("agent_sig length {} (expected 64)", sig_bytes.len()),
        });
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);
    // External audit NN-AUD-292 (FIMP-013): strict — a small-order key or
    // `R` is refused; every signature the agent made passes.
    if pubkey.verify_strict(&recomputed, &sig).is_err() {
        return Err(AuditVerifyError::SignatureInvalid { idx });
    }
    Ok(())
}

// ── tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// External audit EVD-001: the agent publishes the public half next to
    /// its key (0444), rewrites it when it says something else, and a
    /// reader gets the same verifying key from it.
    #[test]
    fn the_public_half_is_published_next_to_the_key() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::TempDir::new().unwrap();
        let key_path = dir.path().join("agent.sig.key");
        let key = AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let pub_path = verifying_key_path(&key_path);
        assert_eq!(pub_path, dir.path().join("agent.sig.pub"));
        assert_eq!(read_verifying_key(&pub_path).unwrap(), key.verifying_key());
        let mode = fs::metadata(&pub_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o444);
        // a wrong public half is replaced at the next load
        fs::remove_file(&pub_path).unwrap();
        fs::write(&pub_path, "00".repeat(32)).unwrap();
        let again = AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        assert_eq!(
            read_verifying_key(&pub_path).unwrap(),
            again.verifying_key()
        );
    }
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn fresh_paths() -> (TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().expect("create tempdir");
        let key_path = dir.path().join("agent.sig.key");
        let log_path = dir.path().join("audit.log");
        (dir, key_path, log_path)
    }

    /// External audit EVD-005: a torn last write no longer keeps the
    /// agent from starting — it is cut off and attested; a bad complete
    /// line before the end still refuses the log, which stays untouched.
    #[test]
    fn a_torn_last_write_is_repaired_and_attested_mid_file_corruption_is_not() {
        let (_d, key_path, log_path) = fresh_paths();
        let key = || AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let mut log = AuditLog::open(&log_path, key(), [0u8; 16]).unwrap();
        log.append(sample_draft(1)).unwrap();
        log.append(sample_draft(2)).unwrap();
        let good = fs::read(&log_path).unwrap();
        // a crash in the middle of the third append
        let mut torn = good.clone();
        torn.extend_from_slice(br#"{"ts":"2026-10-13T00:00:00Z","agent_id":"00","op":"x"#);
        fs::write(&log_path, &torn).unwrap();
        let log = AuditLog::open(&log_path, key(), [0u8; 16]).expect("opens after a torn write");
        let body = fs::read_to_string(&log_path).unwrap();
        assert!(body.starts_with(std::str::from_utf8(&good).unwrap()));
        let last = body.lines().last().unwrap();
        assert!(last.contains(CHAIN_TAIL_REPAIRED_OP), "{last}");
        assert!(last.contains("sha256"), "{last}");
        drop(log);
        // the chain still links: every line's prev_hash is the line before's hash
        let entries: Vec<AuditEntry> = body
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        for w in entries.windows(2) {
            assert_eq!(w[1].prev_hash, w[0].entry_hash);
        }

        // a complete garbage line mid-file: refused, file untouched
        let mut mid = good.clone();
        mid.extend_from_slice(b"not an entry\n");
        mid.extend_from_slice(&good[..good.iter().position(|&c| c == b'\n').unwrap() + 1]);
        fs::write(&log_path, &mid).unwrap();
        assert!(AuditLog::open(&log_path, key(), [0u8; 16]).is_err());
        assert_eq!(fs::read(&log_path).unwrap(), mid);
    }

    /// External audit ATP-004: a successful `rotate_keys_add` in the chain
    /// marks the one-key bootstrap as over, at every later open.
    #[test]
    fn a_second_key_in_the_chain_is_remembered() {
        let (_d, key_path, log_path) = fresh_paths();
        let key = || AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let mut log = AuditLog::open(&log_path, key(), [0u8; 16]).unwrap();
        assert!(!log.second_key_added());
        let mut refused = sample_draft(1);
        refused.op = "rotate_keys_add".to_string();
        refused.result = "quorum_not_met".to_string();
        log.append(refused).unwrap();
        assert!(!AuditLog::open(&log_path, key(), [0u8; 16])
            .unwrap()
            .second_key_added());
        let mut added = sample_draft(2);
        added.op = "rotate_keys_add".to_string();
        added.result = "success".to_string();
        log.append(added).unwrap();
        assert!(AuditLog::open(&log_path, key(), [0u8; 16])
            .unwrap()
            .second_key_added());
    }

    #[test]
    fn previous_run_none_abrupt_clean() {
        let (_d, key_path, log_path) = fresh_paths();
        let key = || AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        // first boot: nothing before it
        let mut log = AuditLog::open(&log_path, key(), [0u8; 16]).unwrap();
        assert_eq!(log.previous_run(), &PreviousRun::None);
        let boot = log.boot_probe(None, "verified", "source-tree").unwrap();
        assert_eq!(boot.extra["previous_run"]["ended"], "none");
        log.append(sample_draft(1)).unwrap();
        // killed: reopen without a stop entry
        let mut log = AuditLog::open(&log_path, key(), [0u8; 16]).unwrap();
        match log.previous_run() {
            PreviousRun::Abrupt {
                booted_at,
                last_entry_at,
            } => {
                assert_eq!(booted_at, &boot.ts);
                assert!(last_entry_at >= booted_at);
            }
            other => panic!("expected Abrupt, got {other:?}"),
        }
        let boot2 = log.boot_probe(None, "verified", "source-tree").unwrap();
        assert_eq!(boot2.extra["previous_run"]["ended"], "abrupt");
        log.stop_entry("sigterm", 42).unwrap();
        // clean stop
        let log = AuditLog::open(&log_path, key(), [0u8; 16]).unwrap();
        match log.previous_run() {
            PreviousRun::Clean { reason, .. } => assert_eq!(reason, "sigterm"),
            other => panic!("expected Clean, got {other:?}"),
        }
        assert!(verify_chain_ok(&log_path));
    }

    /// Lab PR 218 (external review G-09): the audit log's writability is
    /// read without writing — a missing file in a writable directory, an
    /// existing file, a directory that cannot take it; a permission error
    /// is left to the boot probe only while the previous hooks may cause it.
    #[test]
    fn the_audit_preflight_writes_nothing_and_finds_an_unwritable_log() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.log");
        assert_eq!(preflight_writable(&log, false), AuditPreflight::Writable);
        assert!(!log.exists(), "nothing created");
        assert_eq!(
            preflight_writable(&dir.path().join("etc/northnarrow/audit.log"), false),
            AuditPreflight::Writable,
            "the open creates the directory"
        );
        std::fs::write(&log, b"").unwrap();
        assert_eq!(preflight_writable(&log, false), AuditPreflight::Writable);
        assert_eq!(std::fs::read(&log).unwrap(), b"", "no byte written");
        // A directory in place of the file cannot be opened for append.
        let not_a_file = dir.path().join("dir.log");
        std::fs::create_dir(&not_a_file).unwrap();
        assert!(matches!(
            preflight_writable(&not_a_file, false),
            AuditPreflight::Unwritable(_)
        ));
        assert!(
            matches!(
                preflight_writable(&not_a_file, true),
                AuditPreflight::Unwritable(_)
            ),
            "not a permission error: never deferred"
        );
    }

    /// Lab PR 218: a refused boot names the gate that refused it.
    #[test]
    fn a_refused_boot_names_its_gate() {
        let (_d, key_path, log_path) = fresh_paths();
        let key = AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let mut log = AuditLog::open(&log_path, key, [0u8; 16]).unwrap();
        let e = log
            .boot_refused_by("bpf_lsm", "verified", "checksums", "anti-tamper: no bpf")
            .unwrap();
        assert_eq!(e.result, "refused");
        assert_eq!(e.extra["refused_by"], "bpf_lsm");
        let e = log.boot_refused("mismatch", "source-tree", "x").unwrap();
        assert_eq!(e.extra["refused_by"], "install_manifest");
        assert!(!verified_boot_recorded(&log_path).unwrap());
    }

    /// External audit DEP-009: only a successful boot whose binaries matched
    /// the install manifest marks the install as verified — not a boot
    /// without a manifest, not a refused one, not another entry naming it.
    #[test]
    fn verified_boot_is_found_in_the_chain() {
        let (_d, key_path, log_path) = fresh_paths();
        let key = || AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        assert!(!verified_boot_recorded(&log_path).unwrap(), "no file yet");
        let mut log = AuditLog::open(&log_path, key(), [0u8; 16]).unwrap();
        log.boot_probe(None, "no-manifest", "none").unwrap();
        log.boot_probe(None, "not-applicable", "none").unwrap();
        log.boot_refused("mismatch", "source-tree", "nn-admin: expected 00 got 11")
            .unwrap();
        let mut other = sample_draft(1);
        other.extra = serde_json::json!({ "binary_integrity": "verified" });
        log.append(other).unwrap();
        assert!(!verified_boot_recorded(&log_path).unwrap());
        log.boot_probe(None, "verified", "source-tree").unwrap();
        log.stop_entry("sigterm", 1).unwrap();
        assert!(verified_boot_recorded(&log_path).unwrap());
        // a corrupt line: the caller cannot tell
        std::fs::write(&log_path, b"{not json}\n").unwrap();
        assert!(verified_boot_recorded(&log_path).is_err());
    }

    fn verify_chain_ok(path: &Path) -> bool {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .filter(|l| !l.is_empty())
            .all(|l| serde_json::from_str::<AuditEntry>(l).is_ok())
    }

    fn sample_draft(seq: u32) -> AuditEntryDraft {
        AuditEntryDraft {
            op: format!("test_op_{seq}"),
            extra: serde_json::json!({ "seq": seq }),
            key_fp: format!("{seq:08x}"),
            cosigner_fps: vec![],
            result: "success".to_string(),
            client_pid: 12345,
            client_uid: 0,
            client_comm: "nn-admin".to_string(),
            client_exe: None,
        }
    }

    // ── Test 1 (design A11 #1): fresh-gen signing key on disk has
    //                            mode 0400.
    #[test]
    fn signing_key_fresh_gen_writes_mode_0400() {
        let (_dir, key_path, _) = fresh_paths();
        let _key = AgentSigningKey::load_or_bootstrap(&key_path)
            .expect("bootstrap should succeed on missing path");
        let meta = fs::metadata(&key_path).expect("file should exist");
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o400,
            "signing key file should be mode 0400"
        );
        let raw = fs::read_to_string(&key_path).unwrap();
        let trimmed = raw.strip_suffix('\n').unwrap_or(&raw);
        assert_eq!(trimmed.len(), SIGNING_KEY_HEX_LEN);
        assert!(trimmed.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ── Test 2 (design A11 #2): reuse-existing returns same key
    //                            (round-trips via the disk file).
    #[test]
    fn signing_key_reuses_existing_file() {
        let (_dir, key_path, _) = fresh_paths();
        let first = AgentSigningKey::load_or_bootstrap(&key_path).expect("first bootstrap");
        let second = AgentSigningKey::load_or_bootstrap(&key_path).expect("second load");
        assert_eq!(
            first.inner.to_bytes(),
            second.inner.to_bytes(),
            "second load must return the persisted key bytes"
        );
    }

    // ── Test 3 (design A11 #3): corrupted file is a hard error
    //                            (NO silent regeneration).
    #[test]
    fn signing_key_corrupted_file_errors_without_regen() {
        let (_dir, key_path, _) = fresh_paths();
        fs::write(&key_path, "definitely not hex\n").unwrap();
        let err = AgentSigningKey::load_or_bootstrap(&key_path)
            .expect_err("corrupted file must hard-error");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("corrupted") || msg.contains("not valid hex") || msg.contains("hex chars"),
            "error must mention corruption / hex problem; got: {msg}"
        );
        // The corrupted file must remain untouched — no silent
        // regeneration that would invalidate the audit log.
        let after = fs::read_to_string(&key_path).unwrap();
        assert_eq!(after, "definitely not hex\n");
    }

    // ── Test 4 (design A11 #4): open on missing file initialises
    //                            with the genesis prev_hash.
    #[test]
    fn open_missing_log_starts_at_genesis() {
        let (_dir, key_path, log_path) = fresh_paths();
        let key = AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let log = AuditLog::open(&log_path, key, [0u8; 16]).expect("open missing file");
        assert_eq!(log.last_hash(), GENESIS_PREV_HASH);
        // open() must NOT create the file itself — first append
        // does. That keeps "open then never write" cheap.
        assert!(!log_path.exists());
    }

    /// External audit EVD-019 (NN-AUD-281): the log the first append
    /// creates is closed to other users (0640), and a later append keeps
    /// the mode and group an installer set.
    #[test]
    fn audit_log_is_created_closed_to_other_users() {
        let (_dir, key_path, log_path) = fresh_paths();
        let key = AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let mut log = AuditLog::open(&log_path, key, [0u8; 16]).unwrap();
        log.append(sample_draft(1)).unwrap();
        let mode = fs::metadata(&log_path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o640, "audit.log mode {mode:o}");
        assert_eq!(mode & 0o007, 0, "no access for other users");
        // an installer's choice (here: owner only) survives the next append
        fs::set_permissions(&log_path, fs::Permissions::from_mode(0o600)).unwrap();
        log.append(sample_draft(2)).unwrap();
        assert_eq!(
            fs::metadata(&log_path).unwrap().permissions().mode() & 0o7777,
            0o600
        );
    }

    // ── Test 5 (design A11 #5): append produces a JSONL line whose
    //                            entry_hash + signature both verify.
    #[test]
    fn append_writes_signed_jsonl_line() {
        let (_dir, key_path, log_path) = fresh_paths();
        let key = AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let pubkey = key.verifying_key();
        let mut log = AuditLog::open(&log_path, key, [0u8; 16]).unwrap();
        let entry = log.append(sample_draft(1)).expect("first append");
        // File contents are exactly one JSONL line.
        let raw = fs::read_to_string(&log_path).unwrap();
        assert!(raw.ends_with('\n'));
        assert_eq!(raw.lines().count(), 1);
        // Round-trip parses cleanly.
        let parsed: AuditEntry = serde_json::from_str(raw.trim_end()).unwrap();
        assert_eq!(parsed, entry);
        // Chain link starts at genesis.
        assert_eq!(parsed.prev_hash, GENESIS_PREV_HASH);
        // verify_chain accepts this single-entry log.
        verify_chain(&[parsed], &pubkey).expect("single-entry chain must verify");
    }

    // ── Test 6 (design A11 #6): two appends chain (second.prev_hash
    //                            == first.entry_hash).
    #[test]
    fn second_append_chains_off_first_entry() {
        let (_dir, key_path, log_path) = fresh_paths();
        let key = AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let pubkey = key.verifying_key();
        let mut log = AuditLog::open(&log_path, key, [0u8; 16]).unwrap();
        let first = log.append(sample_draft(1)).unwrap();
        let second = log.append(sample_draft(2)).unwrap();
        assert_eq!(
            second.prev_hash, first.entry_hash,
            "second.prev_hash must chain off first.entry_hash"
        );
        // Read both lines back and verify the full chain.
        let raw = fs::read_to_string(&log_path).unwrap();
        let entries: Vec<AuditEntry> = raw
            .lines()
            .map(|l| serde_json::from_str(l).expect("parse"))
            .collect();
        assert_eq!(entries.len(), 2);
        verify_chain(&entries, &pubkey).expect("two-entry chain must verify");
    }

    // ── Test 7 (design A11 #7): verify_chain rejects a payload
    //                            field tampered post-write.
    #[test]
    fn verify_chain_detects_payload_tamper() {
        let (_dir, key_path, log_path) = fresh_paths();
        let key = AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let pubkey = key.verifying_key();
        let mut log = AuditLog::open(&log_path, key, [0u8; 16]).unwrap();
        let _ = log.append(sample_draft(1)).unwrap();
        let _ = log.append(sample_draft(2)).unwrap();
        let raw = fs::read_to_string(&log_path).unwrap();
        let mut entries: Vec<AuditEntry> = raw
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        // Attacker rewrites the first record's `result` field but
        // leaves the chain hashes alone — entry_hash recomputation
        // catches the divergence on entry 0.
        entries[0].result = "failure: attacker covered tracks".to_string();
        let err = verify_chain(&entries, &pubkey).expect_err("tampered chain must fail");
        assert!(
            matches!(err, AuditVerifyError::EntryHashMismatch { idx: 0, .. }),
            "expected EntryHashMismatch on entry 0; got: {err:?}"
        );
    }

    // ── Test 8 (design A11 #8): verify_chain rejects a flipped
    //                            signature.
    #[test]
    fn verify_chain_detects_signature_tamper() {
        let (_dir, key_path, log_path) = fresh_paths();
        let key = AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let pubkey = key.verifying_key();
        let mut log = AuditLog::open(&log_path, key, [0u8; 16]).unwrap();
        let _ = log.append(sample_draft(1)).unwrap();
        let raw = fs::read_to_string(&log_path).unwrap();
        let mut entries: Vec<AuditEntry> = raw
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        // Flip one byte in the signature. Decode-encode round-trip
        // keeps the base64 length intact and exercises the
        // verify path, not the parser.
        let mut sig_bytes = B64.decode(&entries[0].agent_sig).unwrap();
        sig_bytes[0] ^= 0x01;
        entries[0].agent_sig = B64.encode(sig_bytes);
        let err = verify_chain(&entries, &pubkey).expect_err("flipped sig must fail");
        assert!(
            matches!(err, AuditVerifyError::SignatureInvalid { idx: 0 }),
            "expected SignatureInvalid on entry 0; got: {err:?}"
        );
    }
    #[test]
    fn boot_probe_appends_signed_agent_boot_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let key = AgentSigningKey::load_or_bootstrap(&dir.path().join("agent.sig.key")).unwrap();
        let mut log = AuditLog::open(&path, key, [7u8; 16]).unwrap();
        let e = log.boot_probe(None, "verified", "attested").expect("probe");
        assert_eq!(e.op, "agent_boot");
        assert_eq!(e.key_fp, "agent-self");
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("\"agent_boot\""));
        assert_eq!(body.lines().count(), 1);
    }

    #[test]
    fn boot_probe_fails_on_unwritable_path() {
        let dir = tempfile::tempdir().unwrap();
        // A directory where the "file" should be → open(O_CREAT|O_APPEND) fails.
        let path = dir.path().join("audit.log");
        std::fs::create_dir(&path).unwrap();
        let key = AgentSigningKey::load_or_bootstrap(&dir.path().join("agent.sig.key")).unwrap();
        let mut log = match AuditLog::open(&path, key, [7u8; 16]) {
            Ok(l) => l,
            Err(_) => return, // open itself refusing is the same signal
        };
        assert!(log.boot_probe(None, "verified", "attested").is_err());
    }

    #[test]
    fn audit_failure_policy() {
        assert!(audit_failure_is_fatal(None));
        assert!(audit_failure_is_fatal(Some("0")));
        assert!(audit_failure_is_fatal(Some("yes")));
        assert!(!audit_failure_is_fatal(Some("1")));
    }

    #[test]
    fn boot_probe_records_where_detect_only_came_from() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let key = AgentSigningKey::load_or_bootstrap(&dir.path().join("agent.sig.key")).unwrap();
        let mut log = AuditLog::open(&path, key, [7u8; 16]).unwrap();
        let e = log
            .boot_probe(Some("NN_DETECT_ONLY=yes"), "verified", "attested")
            .unwrap();
        assert_eq!(e.extra["detect_only"], true);
        assert_eq!(e.extra["detect_only_source"], "NN_DETECT_ONLY=yes");
        let e = log.boot_probe(None, "verified", "attested").unwrap();
        assert_eq!(e.extra["detect_only"], false);
        assert!(e.extra["detect_only_source"].is_null());
    }

    // ── External audit NN-AUD-108 (lab PR 160) ──────────────────────

    /// Rows as the code before lab PR 160 wrote them: no `seq`, untagged
    /// pre-image (`SHA-256(prev ‖ row)`), same bytes on disk.
    fn write_legacy_rows(path: &Path, key: &AgentSigningKey, n: u32) -> String {
        let mut prev = GENESIS_PREV_HASH.to_string();
        let mut body = String::new();
        for i in 0..n {
            let mut e = build_signed_entry(&sample_draft(i), key, &[0u8; 16], &prev, 0).unwrap();
            e.seq = None;
            e.entry_hash.clear();
            e.agent_sig.clear();
            let h = compute_entry_hash(&e).unwrap();
            e.entry_hash = hex::encode(h);
            e.agent_sig = B64.encode(key.sign(&h).to_bytes());
            let line = serde_json::to_string(&e).unwrap();
            let v: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert!(v.get("seq").is_none(), "a legacy row has no seq field");
            body.push_str(&line);
            body.push('\n');
            prev = e.entry_hash;
        }
        fs::write(path, &body).unwrap();
        prev
    }

    fn rows(path: &Path) -> Vec<AuditEntry> {
        fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    /// External audit NN-AUD-292 (FIMP-013): every row the agent signs —
    /// rows from before lab PR 160 (no `seq`, untagged pre-image) and
    /// numbered ones — passes the strict check, through both verifiers.
    #[test]
    fn strict_accepts_every_signed_row() {
        let (_d, key_path, log_path) = fresh_paths();
        let key = AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let pk = key.verifying_key();
        write_legacy_rows(&log_path, &key, 24);
        let mut log = AuditLog::open(&log_path, key, [0u8; 16]).unwrap();
        for i in 0..40 {
            log.append(sample_draft(100 + i)).unwrap();
        }
        let all = rows(&log_path);
        assert_eq!(all.len(), 64);
        verify_chain(&all, &pk).expect("strict accepts the agent's rows");
        let report = verify_chain_file(&log_path, &pk, None).unwrap();
        assert_eq!((report.rows, report.broken), (64, None));
    }

    /// External audit NN-AUD-292 (FIMP-013): a chain whose rows carry a
    /// small-order signature, under a small-order key, verified with the
    /// lax `verify` — whatever the rows said. The strict check refuses the
    /// first row.
    #[test]
    fn verify_chain_rejects_small_order_signature() {
        use crate::chain_anchor::small_order;
        let (_d, key_path, log_path) = fresh_paths();
        let key = AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        write_legacy_rows(&log_path, &key, 2);
        let mut log = AuditLog::open(&log_path, key, [0u8; 16]).unwrap();
        log.append(sample_draft(10)).unwrap();
        let first = rows(&log_path).remove(0);
        small_order::assert_premise(&hex::decode(&first.entry_hash).unwrap());
        let forged = small_order::forge(&fs::read_to_string(&log_path).unwrap());
        fs::write(&log_path, forged).unwrap();
        assert!(matches!(
            verify_chain(&rows(&log_path), &small_order::key()),
            Err(AuditVerifyError::SignatureInvalid { idx: 0 })
        ));
        let report = verify_chain_file(&log_path, &small_order::key(), None).unwrap();
        assert_eq!(report.rows, 0);
        assert!(matches!(
            report.broken,
            Some(AuditVerifyError::SignatureInvalid { idx: 0 })
        ));
    }

    /// An existing chain (no `seq`) still verifies; numbering starts at
    /// its row count and the whole chain verifies with both formats.
    #[test]
    fn legacy_rows_without_seq_verify_and_new_rows_are_numbered_after_them() {
        let (_d, key_path, log_path) = fresh_paths();
        let key = AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let pk = key.verifying_key();
        let legacy_tail = write_legacy_rows(&log_path, &key, 3);
        let before = fs::read(&log_path).unwrap();
        verify_chain(&rows(&log_path), &pk).expect("legacy chain verifies as before");
        let mut log = AuditLog::open(&log_path, key, [0u8; 16]).unwrap();
        assert!(!log.numbered());
        assert_eq!(log.rows(), 3);
        let first = log.append(sample_draft(10)).unwrap();
        log.append(sample_draft(11)).unwrap();
        assert_eq!(first.seq, Some(3));
        assert_eq!(first.prev_hash, legacy_tail);
        assert!(
            fs::read(&log_path).unwrap().starts_with(&before),
            "old rows untouched"
        );
        let all = rows(&log_path);
        verify_chain(&all, &pk).expect("old rows then numbered rows verify");
        assert_eq!(
            all.iter().map(|r| r.seq).collect::<Vec<_>>(),
            [None, None, None, Some(3), Some(4)]
        );
        assert!(AuditLog::open(
            &log_path,
            AgentSigningKey::load_or_bootstrap(&key_path).unwrap(),
            [0u8; 16]
        )
        .unwrap()
        .take_open_findings(&log_path)
        .is_empty());
    }

    /// External audit ASK-013 (NN-AUD-239, lab PR 179): an admin peer's
    /// executable is signed with its row, right after `client_comm`; a row
    /// without one (the agent's own, every row written before) has no
    /// `client_exe` key — the bytes and pre-image it always had — and both
    /// kinds verify in one chain. Changing the recorded program breaks it.
    #[test]
    fn client_exe_is_signed_and_rows_without_it_keep_their_bytes() {
        let (_d, key_path, log_path) = fresh_paths();
        let key = AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let pk = key.verifying_key();
        let mut log = AuditLog::open(&log_path, key, [0u8; 16]).unwrap();
        log.append(sample_draft(0)).unwrap();
        let mut with_exe = sample_draft(1);
        with_exe.client_exe = Some("/usr/local/bin/nn-admin".to_string());
        log.append(with_exe).unwrap();
        let body = fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert!(!lines[0].contains("client_exe"), "{}", lines[0]);
        assert!(
            lines[1].contains(
                r#""client_comm":"nn-admin","client_exe":"/usr/local/bin/nn-admin","seq":1,"#
            ),
            "{}",
            lines[1]
        );
        let mut all = rows(&log_path);
        verify_chain(&all, &pk).expect("rows with and without client_exe verify");
        all[1].client_exe = Some("/tmp/nn-admin".to_string());
        assert!(matches!(
            verify_chain(&all, &pk),
            Err(AuditVerifyError::EntryHashMismatch { idx: 1, .. })
        ));
    }

    /// External audit NN-AUD-108: a row removed before the end, or an
    /// old-format row inserted after numbered ones, fails `verify_chain`
    /// and is reported at the next open — where the hashes alone would
    /// pass if the attacker re-linked them with the key.
    #[test]
    fn seq_gap_or_regression_fails_verify_chain_and_is_reported_at_open() {
        let (_d, key_path, log_path) = fresh_paths();
        let key = AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let pk = key.verifying_key();
        let mut log = AuditLog::open(&log_path, key, [0u8; 16]).unwrap();
        for i in 0..4 {
            log.append(sample_draft(i)).unwrap();
        }
        let intact = rows(&log_path);
        let mut all = intact.clone();
        all.remove(1);
        assert!(matches!(
            verify_chain(&all, &pk),
            Err(AuditVerifyError::Sequence { idx: 1, .. })
        ));
        // the file itself, row 1 removed: the open names the break
        let body = fs::read_to_string(&log_path).unwrap();
        let kept: String = body
            .lines()
            .enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(_, l)| format!("{l}\n"))
            .collect();
        fs::write(&log_path, kept).unwrap();
        let mut reopened = AuditLog::open(
            &log_path,
            AgentSigningKey::load_or_bootstrap(&key_path).unwrap(),
            [0u8; 16],
        )
        .unwrap();
        let found = reopened.take_open_findings(&log_path);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, "chain_sequence_broken");
        // an old-format row after numbered ones
        let mut all = intact;
        all[2].seq = None;
        assert!(matches!(
            verify_chain(&all, &pk),
            Err(AuditVerifyError::Sequence { idx: 2, .. })
        ));
    }

    /// External audit MAIN-014 (NN-AUD-256, lab PR 190): the streaming file
    /// verifier (`audit verify`, `chain verify`) and [`verify_chain`] over a
    /// slice are the same [`ChainVerifier`]: on a chain of rows from before
    /// lab PR 160 then numbered rows, and on each kind of break, they
    /// return the same result, and the file verifier counts the rows before
    /// the break. The file is only read.
    #[test]
    fn the_file_verifier_agrees_with_verify_chain_on_every_break() {
        let (_d, key_path, log_path) = fresh_paths();
        let key = AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let pk = key.verifying_key();
        write_legacy_rows(&log_path, &key, 3);
        let mut log = AuditLog::open(&log_path, key, [0u8; 16]).unwrap();
        for i in 0..3 {
            log.append(sample_draft(10 + i)).unwrap();
        }
        drop(log);
        let intact = rows(&log_path);
        let before = fs::read(&log_path).unwrap();
        let r = verify_chain_file(&log_path, &pk, Some(&intact[5].entry_hash)).unwrap();
        assert_eq!(
            r,
            ChainFileReport {
                rows: 6,
                first_numbered: Some(3),
                last_seq: Some(5),
                non_canonical_legacy: 0,
                head_seen: true,
                broken: None,
            }
        );
        assert_eq!(fs::read(&log_path).unwrap(), before, "read only");
        assert!(
            !verify_chain_file(&log_path, &pk, Some("00"))
                .unwrap()
                .head_seen
        );

        type Tamper = fn(&mut Vec<AuditEntry>);
        let tampers: [(&str, Tamper); 5] = [
            ("legacy row removed", |v| {
                v.remove(1);
            }),
            ("numbered row removed", |v| {
                v.remove(4);
            }),
            ("payload changed", |v| {
                v[2].result = "failure: rewritten".into()
            }),
            ("signature of another row", |v| {
                v[5].agent_sig = v[4].agent_sig.clone();
            }),
            ("numbered row without seq", |v| v[4].seq = None),
        ];
        let damaged = log_path.with_extension("damaged");
        for (what, tamper) in tampers {
            let mut v = intact.clone();
            tamper(&mut v);
            let body: String = v
                .iter()
                .map(|e| format!("{}\n", serde_json::to_string(e).unwrap()))
                .collect();
            fs::write(&damaged, body).unwrap();
            let want = verify_chain(&v, &pk).expect_err(what);
            let got = verify_chain_file(&damaged, &pk, None).unwrap();
            assert_eq!(got.broken.as_ref(), Some(&want), "{what}");
            let at = match want {
                AuditVerifyError::PrevHashMismatch { idx, .. }
                | AuditVerifyError::EntryHashMismatch { idx, .. }
                | AuditVerifyError::SignatureInvalid { idx }
                | AuditVerifyError::MalformedField { idx, .. }
                | AuditVerifyError::Sequence { idx, .. }
                | AuditVerifyError::NonCanonical { idx } => idx,
                AuditVerifyError::UnreadableLine { .. } => unreachable!("{what}"),
            };
            assert_eq!(got.rows, at, "{what}: rows verified before the break");
        }
        // A missing file is an empty chain.
        let none = verify_chain_file(&log_path.with_extension("none"), &pk, None).unwrap();
        assert_eq!((none.rows, none.broken), (0, None));
    }

    /// External audit NN-AUD-108 / NN-AUD-174: a numbered row's hash is
    /// domain-tagged; the same row hashed without the tag (or with another
    /// chain's) does not verify.
    #[test]
    fn a_numbered_row_hashed_for_another_domain_is_rejected() {
        let (_d, key_path, _log_path) = fresh_paths();
        let key = AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let pk = key.verifying_key();
        let good =
            build_signed_entry(&sample_draft(1), &key, &[0u8; 16], GENESIS_PREV_HASH, 0).unwrap();
        verify_chain(std::slice::from_ref(&good), &pk).unwrap();
        for domain in [None, Some(crate::chain_anchor::CANARY_ACCESS_DOMAIN_V2)] {
            let mut e = good.clone();
            e.entry_hash.clear();
            e.agent_sig.clear();
            let body = serde_json::to_vec(&e).unwrap();
            let h = crate::chain_anchor::flat_digest(domain, &e.prev_hash, &body).unwrap();
            e.entry_hash = hex::encode(h);
            e.agent_sig = B64.encode(key.sign(&h).to_bytes());
            assert!(matches!(
                verify_chain(&[e], &pk),
                Err(AuditVerifyError::EntryHashMismatch { idx: 0, .. })
            ));
        }
    }

    // ── External audit EVD-020 / MAIN-009: the identity in the chain ──

    fn identity(
        id: [u8; 16],
        source: crate::agent_id::IdentitySource,
    ) -> crate::agent_id::AgentIdentity {
        crate::agent_id::AgentIdentity {
            id,
            source,
            path: PathBuf::from("/etc/northnarrow/agent_id"),
        }
    }

    fn drifts<'a>(rows: &'a [AuditEntry], kind: &str) -> Vec<&'a AuditEntry> {
        rows.iter()
            .filter(|r| {
                r.op == crate::self_integrity::AUDIT_OP
                    && r.extra.get("kind").and_then(|k| k.as_str()) == Some(kind)
            })
            .collect()
    }

    fn whole_chain_verifies(path: &Path, key: &AgentSigningKey) {
        let all = rows(path);
        verify_chain(&all, &key.verifying_key()).expect("the whole chain verifies");
    }

    /// EVD-020: the file replaced while the agent was down — the chain's
    /// last row carries A, this boot loads B. One signed `agent_id_changed`
    /// row binds the two (same agent key as the rows before), once; the
    /// next boot with B is quiet.
    #[test]
    fn a_chain_last_signed_as_another_id_reports_the_change_once() {
        use crate::agent_id::IdentitySource;
        let (_d, key_path, log_path) = fresh_paths();
        let key = || AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let (a, b) = ([0xAAu8; 16], [0xBBu8; 16]);
        let mut log = AuditLog::open(&log_path, key(), a).unwrap();
        log.append(sample_draft(1)).unwrap();
        drop(log);

        let mut log = AuditLog::open(&log_path, key(), b).unwrap();
        log.attest_identity(&identity(b, IdentitySource::Loaded))
            .unwrap();
        log.attest_identity(&identity(b, IdentitySource::Loaded))
            .unwrap();
        drop(log);
        let all = rows(&log_path);
        let changed = drifts(&all, AGENT_ID_CHANGED_KIND);
        assert_eq!(changed.len(), 1, "{all:#?}");
        let x = &changed[0].extra;
        assert_eq!(x["from"], hex::encode(a));
        assert_eq!(x["to"], hex::encode(b));
        assert_eq!(x["source"], "loaded");
        assert_eq!(x["at_boot"], true);
        assert_eq!(changed[0].agent_id, hex::encode(b));
        assert_eq!(changed[0].result, "detected");
        assert!(all.iter().all(|r| r.op != AGENT_ID_MINTED_OP));
        whole_chain_verifies(&log_path, &key());

        let mut log = AuditLog::open(&log_path, key(), b).unwrap();
        log.attest_identity(&identity(b, IdentitySource::Loaded))
            .unwrap();
        drop(log);
        assert_eq!(
            rows(&log_path).len(),
            all.len(),
            "an unchanged id adds nothing"
        );
    }

    /// EVD-020: a first start (empty chain) records the mint, no drift.
    #[test]
    fn a_fresh_chain_with_a_minted_id_records_the_mint_and_no_drift() {
        use crate::agent_id::IdentitySource;
        let (_d, key_path, log_path) = fresh_paths();
        let key = || AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let id = [0x42u8; 16];
        let mut log = AuditLog::open(&log_path, key(), id).unwrap();
        log.attest_identity(&identity(id, IdentitySource::Minted))
            .unwrap();
        drop(log);
        let all = rows(&log_path);
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].op, AGENT_ID_MINTED_OP);
        assert_eq!(all[0].extra["agent_id"], hex::encode(id));
        assert!(all[0].extra["previous"].is_null());
        assert_eq!(all[0].extra["file"], "/etc/northnarrow/agent_id");
        assert!(drifts(&all, AGENT_ID_CHANGED_KIND).is_empty());
        whole_chain_verifies(&log_path, &key());
    }

    /// EVD-020: `agent_id` removed while the agent was down — the boot
    /// mints B over a chain last signed as A: the mint and the change.
    #[test]
    fn a_mint_over_an_existing_chain_records_the_mint_and_the_change() {
        use crate::agent_id::IdentitySource;
        let (_d, key_path, log_path) = fresh_paths();
        let key = || AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let (a, b) = ([0x0Au8; 16], [0x0Bu8; 16]);
        let mut log = AuditLog::open(&log_path, key(), a).unwrap();
        log.append(sample_draft(1)).unwrap();
        drop(log);
        let mut log = AuditLog::open(&log_path, key(), b).unwrap();
        log.attest_identity(&identity(b, IdentitySource::Minted))
            .unwrap();
        drop(log);
        let all = rows(&log_path);
        let minted: Vec<_> = all.iter().filter(|r| r.op == AGENT_ID_MINTED_OP).collect();
        assert_eq!(minted.len(), 1);
        assert_eq!(minted[0].extra["previous"], hex::encode(a));
        let changed = drifts(&all, AGENT_ID_CHANGED_KIND);
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].extra["source"], "minted");
        assert!(changed[0].extra["detail"]
            .as_str()
            .unwrap()
            .contains("removed and minted again"));
        whole_chain_verifies(&log_path, &key());
    }

    /// MAIN-009: an unusable file is a signed `subsystem_degraded` naming
    /// the reason and the per-boot id; over a chain signed as A it is a
    /// change too.
    #[test]
    fn an_unusable_identity_is_a_signed_degradation() {
        use crate::agent_id::IdentitySource;
        let (_d, key_path, log_path) = fresh_paths();
        let key = || AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let (a, per_boot) = ([0x0Au8; 16], [0x77u8; 16]);
        let mut log = AuditLog::open(&log_path, key(), a).unwrap();
        log.append(sample_draft(1)).unwrap();
        drop(log);
        let mut log = AuditLog::open(&log_path, key(), per_boot).unwrap();
        log.attest_identity(&identity(
            per_boot,
            IdentitySource::Unavailable("agent_id is all zeros".into()),
        ))
        .unwrap();
        drop(log);
        let all = rows(&log_path);
        let degraded = drifts(&all, "subsystem_degraded");
        assert_eq!(degraded.len(), 1);
        let detail = degraded[0].extra["detail"].as_str().unwrap();
        assert!(detail.contains("agent_id is all zeros"), "{detail}");
        assert!(detail.contains(&hex::encode(per_boot)), "{detail}");
        let changed = drifts(&all, AGENT_ID_CHANGED_KIND);
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].extra["source"], "unavailable");
        whole_chain_verifies(&log_path, &key());
    }

    /// Format: the identity rows are ordinary numbered rows; a chain whose
    /// rows predate `seq` (lab PR 160) and the `agent_id` of the old zero
    /// fallback keeps verifying, and the first boot with the real id names
    /// the change.
    #[test]
    fn legacy_rows_keep_verifying_and_an_old_zero_fallback_is_named() {
        use crate::agent_id::IdentitySource;
        let (_d, key_path, log_path) = fresh_paths();
        let key = || AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        // write_legacy_rows signs as the all-zero id, as the old fallback did
        write_legacy_rows(&log_path, &key(), 3);
        let before = fs::read(&log_path).unwrap();
        let id = [0x5Cu8; 16];
        let mut log = AuditLog::open(&log_path, key(), id).unwrap();
        log.attest_identity(&identity(id, IdentitySource::Loaded))
            .unwrap();
        drop(log);
        let after = fs::read(&log_path).unwrap();
        assert_eq!(
            &after[..before.len()],
            &before[..],
            "old rows keep their bytes"
        );
        let all = rows(&log_path);
        let changed = drifts(&all, AGENT_ID_CHANGED_KIND);
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].extra["from"], hex::encode([0u8; 16]));
        assert_eq!(changed[0].seq, Some(3));
        whole_chain_verifies(&log_path, &key());
    }

    // ── External audit, Wave 3, lab PR 204 ─────────────────────────────

    /// `"injected":"x"` before the closing brace of a row.
    fn inject_key(line: &str) -> String {
        format!("{},\"injected\":\"x\"}}", line.strip_suffix('}').unwrap())
    }

    /// EVD-007 (NN-AUD-273): a numbered row rewritten with a key the type
    /// does not have, keys reordered, whitespace or an escaped spelling
    /// decodes to the same entry — its hash and signature verify — but the
    /// bytes are not what the agent wrote: `audit verify`, `chain verify`
    /// and the head check refuse it. A row without `seq` (before lab PR
    /// 160) keeps its old check and is counted. On the starting code every
    /// one of these rewrites verified.
    #[test]
    fn a_numbered_row_not_in_canonical_form_is_refused_a_legacy_row_is_counted() {
        let (_d, key_path, log_path) = fresh_paths();
        let key = AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let pk = key.verifying_key();
        write_legacy_rows(&log_path, &key, 2);
        let mut log = AuditLog::open(&log_path, key, [0u8; 16]).unwrap();
        for i in 0..3 {
            log.append(sample_draft(10 + i)).unwrap();
        }
        drop(log);
        let pristine = fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = pristine.lines().collect();
        let r = verify_chain_file(&log_path, &pk, None).unwrap();
        assert_eq!((r.rows, r.non_canonical_legacy, r.broken), (5, 0, None));
        let row3 = lines[3];
        assert!(row_is_genuine(row3.as_bytes(), &pk));
        let reordered = {
            let e: AuditEntry = serde_json::from_str(row3).unwrap();
            let rest = row3.replacen(&format!("{{\"ts\":\"{}\",", e.ts), "{", 1);
            format!("{},\"ts\":\"{}\"}}", rest.strip_suffix('}').unwrap(), e.ts)
        };
        let rewrites = [
            ("an injected key", inject_key(row3)),
            ("keys reordered", reordered),
            ("whitespace", row3.replacen("\"op\":", "\"op\": ", 1)),
            (
                "an escaped spelling",
                row3.replacen("test_op_", "\\u0074est_op_", 1),
            ),
        ];
        for (what, forged) in rewrites {
            assert_ne!(forged, row3, "{what}");
            let e: AuditEntry = serde_json::from_str(&forged).unwrap();
            assert!(
                verify_entry(3, &e, &pk).is_ok(),
                "{what}: the entry still verifies"
            );
            assert!(
                !row_is_genuine(forged.as_bytes(), &pk),
                "{what}: head check"
            );
            let mut body: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
            body[3] = forged;
            fs::write(&log_path, body.join("\n") + "\n").unwrap();
            let r = verify_chain_file(&log_path, &pk, None).unwrap();
            assert_eq!(
                r.broken,
                Some(AuditVerifyError::NonCanonical { idx: 3 }),
                "{what}"
            );
            assert_eq!(r.rows, 3, "{what}: rows verified before it");
        }
        // The same on a legacy row: verifies, counted.
        let mut body: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
        body[1] = inject_key(lines[1]);
        fs::write(&log_path, body.join("\n") + "\n").unwrap();
        let r = verify_chain_file(&log_path, &pk, None).unwrap();
        assert_eq!((r.rows, r.non_canonical_legacy, r.broken), (5, 1, None));
        assert!(row_is_genuine(body[1].as_bytes(), &pk));
    }

    /// EVD-023 (NN-AUD-427): `compute_entry_hash` relied on empty
    /// `entry_hash`/`agent_sig` through `debug_assert!` — a release build
    /// hashed an entry that carried them. It is an error in every build; the
    /// rows written before keep their hashes (the legacy-row tests).
    #[test]
    fn compute_entry_hash_refuses_an_entry_that_carries_its_seal() {
        let (_d, key_path, _log) = fresh_paths();
        let key = AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let e =
            build_signed_entry(&sample_draft(1), &key, &[0u8; 16], GENESIS_PREV_HASH, 0).unwrap();
        let err = compute_entry_hash(&e).unwrap_err();
        assert!(err.to_string().contains("carries its own"), "{err}");
        let mut only_sig = e.clone();
        only_sig.entry_hash.clear();
        assert!(compute_entry_hash(&only_sig).is_err());
        let mut stripped = e.clone();
        stripped.entry_hash.clear();
        stripped.agent_sig.clear();
        assert_eq!(
            hex::encode(compute_entry_hash(&stripped).unwrap()),
            e.entry_hash
        );
    }

    /// EVD-007, round trip: every row `AuditLog::append` writes — `extra`
    /// with nested objects, arrays, floats, escapes, control characters,
    /// non-ASCII and astral text, `client_exe` set or not — is its own
    /// canonical serialisation and verifies with the canonical check.
    #[test]
    fn every_row_the_writer_produces_round_trips_byte_exactly() {
        use rand::{RngExt, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x204a);
        let text = |rng: &mut rand::rngs::StdRng| -> String {
            const POOL: &[char] = &[
                'a',
                '0',
                ' ',
                '"',
                '\\',
                '/',
                '\n',
                '\t',
                '\u{0}',
                '\u{1f}',
                '\u{7f}',
                '\u{e9}',
                '\u{2028}',
                '\u{1d11e}',
                '{',
                '}',
            ];
            let n = rng.random_range(0..16);
            (0..n)
                .map(|_| POOL[rng.random_range(0..POOL.len())])
                .collect()
        };
        let (_d, key_path, log_path) = fresh_paths();
        let key = AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let pk = key.verifying_key();
        let mut log = AuditLog::open(&log_path, key, [7u8; 16]).unwrap();
        for _ in 0..150 {
            let f = loop {
                let f = f64::from_bits(rng.random());
                if f.is_finite() {
                    break f;
                }
            };
            let k1 = text(&mut rng);
            let draft = AuditEntryDraft {
                op: text(&mut rng),
                extra: serde_json::json!({
                    k1: text(&mut rng),
                    "f": f,
                    "n": rng.random::<i64>(),
                    "u": rng.random::<u64>(),
                    "nested": { "list": [text(&mut rng), null, true, f], "z": {} },
                }),
                key_fp: text(&mut rng),
                cosigner_fps: vec![text(&mut rng)],
                result: text(&mut rng),
                client_pid: rng.random(),
                client_uid: rng.random(),
                client_comm: text(&mut rng),
                client_exe: rng.random_bool(0.5).then(|| text(&mut rng)),
            };
            log.append(draft).unwrap();
        }
        drop(log);
        for line in fs::read_to_string(&log_path).unwrap().lines() {
            let e: AuditEntry = serde_json::from_str(line).unwrap();
            assert_eq!(serde_json::to_string(&e).unwrap(), line);
            assert!(row_is_genuine(line.as_bytes(), &pk));
        }
        let r = verify_chain_file(&log_path, &pk, None).unwrap();
        assert_eq!((r.rows, r.broken), (150, None));
    }
}
