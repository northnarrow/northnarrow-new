//! Signed operator overlays (Tappa 10.8).
//!
//! The `*.local` overlays in `/etc/northnarrow` change what the agent
//! detects: an allowlist overlay exempts a comm, a FIM overlay stops
//! watching a path, a posture overlay carves writers out of the mass-write
//! arm. They used to be read at boot as plain files, so root could create
//! one (`+evil-implant`) and the next restart applied it. Now an overlay is
//! loaded only if it comes with `<overlay>.sig`: an admin-signed statement
//! that binds the overlay kind to the SHA-256 and length of its exact
//! content, signed by a key that carries `config-manage` in `admin.pub`
//! (the private key is meant to live off the host), for this agent's
//! `agent_id`, and not older than the last signature the audit chain
//! accepted for that kind (no rollback to a retired exemption) — a floor
//! read from the verified chain, and reset when its history is gone
//! ([`super::overlay_floor`], external audit LLMR-014).
//!
//! An overlay without a valid signature is not loaded — the agent boots on
//! the shipped defaults (`.v1`) for that kind — and the refusal is an
//! ERROR plus a signed `integrity_drift` (`unauthorized_overlay`) entry.
//! `nn-admin config overlay set` stores an overlay and its signature
//! through the agent; `nn-admin config overlay sign` signs one offline
//! (what `install.sh --upgrade` uses to adopt existing overlays). The
//! escape hatch `NN_OVERLAY_ALLOW_UNSIGNED=1` loads unsigned overlays
//! anyway, still reported, and is itself a weakening-environment finding.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use anyhow::{anyhow, Context, Result};
use nn_proto::admin_signed_payload::{
    OperationCode, OperationExtra, OverlayKind, Role, SignedPayload,
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{error, info, warn};

use super::overlay_floor::RollbackFloor;
use crate::anti_tamper::admin_auth::AdminAuth;
use crate::audit::{AuditEntryDraft, AuditLog};

/// Suffix of the signature file next to an overlay.
pub const SIG_SUFFIX: &str = ".sig";
/// Escape hatch: load unsigned overlays (still reported).
pub const ALLOW_UNSIGNED_ENV: &str = "NN_OVERLAY_ALLOW_UNSIGNED";
/// Audit op of an overlay accepted at boot with a content not yet in the chain.
pub const AUDIT_OP_ACCEPTED: &str = "config_overlay_accepted";
/// Audit op of an overlay stored through `nn-admin config overlay set`.
pub const AUDIT_OP_SET: &str = "config_overlay_set";
/// Largest overlay the gate reads: an overlay is a list of lines; a larger
/// file is refused rather than read whole into memory.
pub const MAX_OVERLAY_BYTES: u64 = 4 << 20;

/// `<overlay>.sig` on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlaySignature {
    pub v: u8,
    pub kind: String,
    pub payload: SignedPayload,
    /// Ed25519 signatures, hex.
    pub signatures: Vec<String>,
}

impl OverlaySignature {
    pub fn new(payload: SignedPayload, signatures: &[[u8; 64]]) -> Result<Self> {
        let kind = match &payload.extra {
            OperationExtra::ConfigOverlaySet(e) => e.kind.keyword().to_string(),
            _ => return Err(anyhow!("payload is not a config-overlay payload")),
        };
        Ok(Self {
            v: 1,
            kind,
            payload,
            signatures: signatures.iter().map(|s| hex(s)).collect(),
        })
    }

    pub fn signatures(&self) -> Result<Vec<[u8; 64]>> {
        self.signatures
            .iter()
            .map(|h| {
                let bytes = unhex(h).ok_or_else(|| anyhow!("signature is not hex"))?;
                <[u8; 64]>::try_from(bytes.as_slice())
                    .map_err(|_| anyhow!("signature is not 64 bytes"))
            })
            .collect()
    }

    pub fn to_json(&self) -> Result<String> {
        let mut s = serde_json::to_string_pretty(self).context("serialising overlay signature")?;
        s.push('\n');
        Ok(s)
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Overlay paths as configured for this boot (CLI flags can move them);
/// recorded by [`OverlayGate::verified`] so `config overlay set` writes
/// where the next boot will read.
static CONFIGURED: OnceLock<parking_lot::Mutex<HashMap<OverlayKind, PathBuf>>> = OnceLock::new();

fn remember_path(kind: OverlayKind, path: &Path) {
    CONFIGURED
        .get_or_init(|| parking_lot::Mutex::new(HashMap::new()))
        .lock()
        .insert(kind, path.to_path_buf());
}

/// Where the agent reads overlay `kind` (the configured path, or
/// `<config_dir>/<kind>.local`).
pub fn configured_path(kind: OverlayKind, config_dir: &Path) -> PathBuf {
    CONFIGURED
        .get()
        .and_then(|m| m.lock().get(&kind).cloned())
        .unwrap_or_else(|| config_dir.join(kind.file_name()))
}

/// Store an overlay and its signature (`nn-admin config overlay set`,
/// after the request was verified): both written to a temporary file in
/// the same directory, fsynced and renamed into place — the agent is a
/// protected pid, so the inode guard lets it; then both new inodes are
/// registered in PROTECTED_INODES (unlink/rename/setattr denied).
pub fn store(path: &Path, content: &str, sig: &OverlaySignature) -> Result<PathBuf> {
    let sig_file = sig_path(path);
    let sig_json = sig.to_json()?;
    for (target, body) in [
        (path.to_path_buf(), content.to_string()),
        (sig_file.clone(), sig_json),
    ] {
        let old_key = inode_key(&target);
        let dir = target
            .parent()
            .ok_or_else(|| anyhow!("{} has no parent", target.display()))?;
        let name = target
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow!("bad file name {}", target.display()))?;
        // External audit AUT-003: never through a link planted at the
        // temporary name (the agent writes where nobody else may).
        crate::atomic_file::replace(&target, body.as_bytes(), 0o644)
            .with_context(|| format!("replacing {} in {}", name, dir.display()))?;
        if let Err(e) = crate::anti_tamper::filesystem::reregister_protected_file(
            crate::anti_tamper::prepare_pin_root(),
            &target,
            old_key,
            common::wire::FS_PROTECT_MUTATE,
        ) {
            warn!(error = ?e, path = %target.display(), "overlay store: protecting the new inode FAILED — unprotected until the next agent start");
        }
    }
    Ok(sig_file)
}

fn inode_key(path: &Path) -> Option<common::wire::InodeKey> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path).ok()?;
    Some(common::wire::InodeKey {
        dev: crate::anti_tamper::filesystem::stat_dev_to_kernel_dev(m.dev()),
        ino: m.ino(),
    })
}

/// `<overlay>.sig`.
pub fn sig_path(overlay: &Path) -> PathBuf {
    let mut s = overlay.as_os_str().to_os_string();
    s.push(SIG_SUFFIX);
    PathBuf::from(s)
}

/// SHA-256 of an overlay's bytes.
pub fn content_sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Parse `text` with the same rules the loader of `kind` applies; any
/// malformed entry is an error (the loaders drop a bad overlay whole or
/// skip bad lines — a signature must never cover such content).
pub fn validate_content(kind: OverlayKind, text: &str) -> Result<()> {
    use crate::config::overlay::parse_overlay_text;
    let label = kind.file_name();
    match kind {
        OverlayKind::FimPaths => {
            parse_overlay_text(
                &label,
                text,
                &crate::fim::paths_config::validate_absolute_path,
            )?;
        }
        OverlayKind::ProcessCommAllowlist | OverlayKind::NetflowCommAllowlist => {
            parse_overlay_text(&label, text, &crate::config::comm_allowlist::validate_comm)?;
        }
        OverlayKind::CanaryReaders => {
            parse_overlay_text(&label, text, &crate::canary::readers::validate_reader)?;
        }
        // Lab PR 222: the guard's own strict parser.
        OverlayKind::CowGuard => {
            crate::cow::config::CowConfig::validate(text)?;
        }
        OverlayKind::NetflowBlocklist => {
            crate::net::blocklist::parse_blocklist_overlay_text(&label, text)?;
        }
        OverlayKind::NetflowJa3Blocklist => {
            crate::net::blocklist::parse_ja3_overlay_text(&label, text)?;
        }
        // External audit POS-010 (lab PR 198): the loader's own line
        // rules, a too-broad entry included, named with its line.
        OverlayKind::MassWriteCarveout => {
            let (_, refused) = crate::posture::mass_write_overlay::parse_text(text);
            if let Some((lineno, why)) = refused.first() {
                return Err(anyhow!("{label}:{lineno}: {why}"));
            }
        }
        OverlayKind::EscalationAllow => {
            let (_, errors) = crate::posture::escalation_allow::EscalationAllowList::parse(text);
            if let Some(e) = errors.first() {
                return Err(anyhow!("{label}: {e}"));
            }
        }
        // External audit ATP-001 / DEP-003: a signed ruleset must still
        // isolate; a signed carve-out must parse whole.
        OverlayKind::CombatRulesV4 | OverlayKind::CombatRulesV6 => {
            crate::anti_tamper::network_isolate::validate_ruleset(text)
                .map_err(|e| anyhow!("{label}: {e}"))?;
        }
        OverlayKind::CombatAllow => {
            let load = crate::anti_tamper::combat_allow::parse_allow_text(text);
            if let Some(w) = load.warnings.first() {
                return Err(anyhow!("{label}: {w}"));
            }
        }
        // Lab PR 223: every line a `block`/`allow` entry, no digest twice.
        OverlayKind::ExecqHashes => {
            common::execq::parse_hash_list(text).map_err(|e| anyhow!("{label}: {e}"))?;
        }
        // Lab PR 226: every line an exec, audit, preload, map, exempt or
        // profile line (over either profile: the base does not change
        // what parses).
        OverlayKind::ExecPolicy => {
            crate::execpol::policy::parse(text, crate::execpol::Profile::Server)
                .map_err(|e| anyhow!("{label}: {e}"))?;
        }
        // Lab PR 236: any bad line refuses the per-rule policy whole.
        OverlayKind::RulePolicy => {
            crate::decision::rule_policy::parse(text).map_err(|e| anyhow!("{label}: {e}"))?;
        }
    }
    Ok(())
}

/// External audit ATP-001 / DEP-003: content of `kind` that needs no
/// signature because it is what the agent was built with — the shipped
/// COMBAT rulesets and carve-out. The `.local` overlays have none.
pub fn shipped_default(kind: OverlayKind) -> Option<&'static str> {
    use crate::anti_tamper::network_isolate as ni;
    match kind {
        OverlayKind::CombatRulesV4 => Some(ni::BUILTIN_RULES_V4),
        OverlayKind::CombatRulesV6 => Some(ni::BUILTIN_RULES_V6),
        OverlayKind::CombatAllow => Some(ni::BUILTIN_ALLOW),
        _ => None,
    }
}

/// Outcome of the boot check for one overlay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// No overlay file: nothing to load, nothing to check.
    Absent,
    /// Signed, matching, not a rollback. `new` = content not yet recorded
    /// in the audit chain for this kind.
    Accepted {
        sha256: String,
        signed_ts: u64,
        key_fps: Vec<String>,
        new: bool,
    },
    /// Present but not loadable: why.
    Refused {
        reason: String,
        sha256: Option<String>,
    },
}

/// What the loader of an overlay gets from [`OverlayGate::verified`]
/// (external audit LLMR-013). The gate used to hand over a path, and every
/// loader read the file again after the gate had verified its own read: a
/// root process able to pause the agent's `open()` could serve the gate
/// the signed bytes and the loader others. The loaders now take this, and
/// only the gate makes one: the text is the one the decision was made on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verified {
    /// No overlay at the path: the shipped defaults only.
    Missing,
    /// The file is the content the agent was built with (the COMBAT files).
    ShippedDefault,
    /// Present but refused (logged and recorded by the gate): the shipped
    /// defaults only.
    Refused,
    /// The text to apply: signed, or loaded through the escape hatch.
    Content { path: PathBuf, text: String },
}

impl Verified {
    /// The overlay's text, when there is one to apply.
    pub fn text(&self) -> Option<&str> {
        match self {
            Verified::Content { text, .. } => Some(text),
            _ => None,
        }
    }

    /// Where the applied text was read (for the loaders' logs).
    pub fn source(&self) -> Option<&Path> {
        match self {
            Verified::Content { path, .. } => Some(path),
            _ => None,
        }
    }
}

/// One read of an overlay, as [`OverlayGate::verified`] decides on it.
enum Read {
    Missing,
    ShippedDefault,
    /// Present but not usable as text (unreadable, not UTF-8, too large…).
    Unusable,
    Text(String),
}

/// External audit LLMR-013: an overlay is read once, without following a
/// link (the last component), without blocking on a FIFO planted at its
/// name, and at most [`MAX_OVERLAY_BYTES`]. So is a shipped default list
/// (`.v1`, LLMR-015).
pub(crate) fn read_overlay(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| {
            if e.raw_os_error() == Some(libc::ELOOP) {
                std::io::Error::other("a symbolic link (not read through one)")
            } else {
                e
            }
        })?;
    if !f.metadata()?.file_type().is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    let mut bytes = Vec::new();
    f.take(MAX_OVERLAY_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_OVERLAY_BYTES {
        return Err(std::io::Error::other(format!(
            "larger than {MAX_OVERLAY_BYTES} bytes"
        )));
    }
    Ok(bytes)
}

/// Boot-time gate for every overlay the agent reads.
pub struct OverlayGate {
    auth: Option<AdminAuth>,
    /// External audit LLMR-014: the newest signature per kind the verified
    /// chain shows, and the floor's reset if its history was gone.
    floor: RollbackFloor,
    allow_unsigned: bool,
    audit_log: Mutex<Option<Arc<Mutex<AuditLog>>>>,
    /// The floor's own entries (reset, anchor), first in the chain.
    floor_pending: Mutex<Vec<AuditEntryDraft>>,
    /// Entries made before the audit log was attached.
    pending: Mutex<Vec<AuditEntryDraft>>,
}

impl std::fmt::Debug for OverlayGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OverlayGate")
            .field("allow_unsigned", &self.allow_unsigned)
            .finish_non_exhaustive()
    }
}

impl OverlayGate {
    /// `admin_pub` is read once here (an overlay is only as trusted as the
    /// key set at boot); `floor` is what the verified audit chain says about
    /// the signatures already accepted ([`RollbackFloor::scan`]), to refuse
    /// a rollback.
    pub fn new(admin_pub: &Path, agent_id: [u8; 16], floor: RollbackFloor) -> Self {
        let auth = match AdminAuth::load_with_agent_id(admin_pub, agent_id) {
            Ok(a) => Some(a),
            Err(e) => {
                warn!(error = format!("{e:#}"), path = %admin_pub.display(), "overlay gate: admin.pub unreadable — no overlay can be verified this boot");
                None
            }
        };
        let allow_unsigned = std::env::var(ALLOW_UNSIGNED_ENV)
            .map(|v| v == "1")
            .unwrap_or(false);
        if let Some(why) = floor.reset() {
            error!(
                reason = %why,
                not_before = ?floor.not_before(),
                "OVERLAY ROLLBACK FLOOR RESET — no overlay signed before this boot is loaded, now or \
                 later: sign them again (`nn-admin config overlay set`); recorded as integrity_drift \
                 {}",
                super::overlay_floor::DRIFT_KIND
            );
        }
        Self {
            auth,
            floor_pending: Mutex::new(floor.entries()),
            floor,
            allow_unsigned,
            audit_log: Mutex::new(None),
            pending: Mutex::new(Vec::new()),
        }
    }

    /// The boot decision for `kind` read from `path` — a report (what a
    /// loader applies comes from [`Self::verified`], on its own read).
    pub fn check(&self, kind: OverlayKind, path: &Path) -> Decision {
        self.read_and_check(kind, path).0
    }

    /// One read of `path`, and the decision made on those bytes.
    fn read_and_check(&self, kind: OverlayKind, path: &Path) -> (Decision, Read) {
        let bytes = match read_overlay(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return (Decision::Absent, Read::Missing)
            }
            Err(e) => {
                let refused = Decision::Refused {
                    reason: format!("unreadable: {e}"),
                    sha256: None,
                };
                return (refused, Read::Unusable);
            }
        };
        // The shipped COMBAT files are the defaults themselves.
        if shipped_default(kind).is_some_and(|d| d.as_bytes() == bytes.as_slice()) {
            return (Decision::Absent, Read::ShippedDefault);
        }
        let digest = content_sha256(&bytes);
        let sha_hex = hex(&digest);
        let decision = self.decide(kind, path, bytes.len(), digest, sha_hex.clone());
        match String::from_utf8(bytes) {
            Ok(text) => (decision, Read::Text(text)),
            Err(_) => {
                let refused = Decision::Refused {
                    reason: "not UTF-8 text".to_string(),
                    sha256: Some(sha_hex),
                };
                (refused, Read::Unusable)
            }
        }
    }

    /// The signature check of the overlay at `path`, `len` bytes with
    /// SHA-256 `digest`.
    fn decide(
        &self,
        kind: OverlayKind,
        path: &Path,
        len: usize,
        digest: [u8; 32],
        sha_hex: String,
    ) -> Decision {
        let refuse = |reason: String| Decision::Refused {
            reason,
            sha256: Some(sha_hex.clone()),
        };
        let sig_file = sig_path(path);
        let sig: OverlaySignature = match std::fs::read_to_string(&sig_file) {
            Ok(s) => match serde_json::from_str(&s) {
                Ok(v) => v,
                Err(e) => {
                    return refuse(format!(
                        "malformed signature file {}: {e}",
                        sig_file.display()
                    ))
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return refuse(format!("no signature file {}", sig_file.display()))
            }
            Err(e) => return refuse(format!("signature file unreadable: {e}")),
        };
        let OperationExtra::ConfigOverlaySet(extra) = &sig.payload.extra else {
            return refuse("signature is not for a config overlay".to_string());
        };
        if extra.kind != kind {
            return refuse(format!("signature is for `{}`", extra.kind.keyword()));
        }
        if extra.sha256 != digest || extra.len as usize != len {
            return refuse(
                "content does not match its signature (edited after signing)".to_string(),
            );
        }
        let Some(auth) = &self.auth else {
            return refuse("admin.pub unavailable".to_string());
        };
        let sigs = match sig.signatures() {
            Ok(s) => s,
            Err(e) => return refuse(format!("{e:#}")),
        };
        let key_fps = match auth.verify_stored_payload(
            &sig.payload,
            &sigs,
            1,
            &[Role::ConfigManage],
            OperationCode::ConfigOverlaySet,
        ) {
            Ok(fps) => fps,
            Err(e) => return refuse(format!("signature rejected: {e}")),
        };
        if let Some(not_before) = self.floor.not_before() {
            if sig.payload.ts < not_before {
                return refuse(format!(
                    "signed at {} — before {not_before}, when the rollback floor was reset (the \
                     audit chain's history was found gone or broken): sign it again",
                    sig.payload.ts
                ));
            }
        }
        let mut new = true;
        if let Some((hash, ts)) = self.floor.recorded(kind) {
            if sig.payload.ts < *ts {
                return refuse(format!(
                    "signed at {} — older than the signature accepted at {ts} (rollback)",
                    sig.payload.ts
                ));
            }
            new = *hash != sha_hex;
        }
        Decision::Accepted {
            sha256: sha_hex,
            signed_ts: sig.payload.ts,
            key_fps,
            new,
        }
    }

    /// What the loader of `kind` applies (external audit LLMR-013): the
    /// text of the one read the decision was made on — signed, or loaded
    /// through the escape hatch — else nothing, and the loader runs on the
    /// shipped defaults. Every decision is logged and recorded.
    pub fn verified(&self, kind: OverlayKind, path: &Path) -> Verified {
        remember_path(kind, path);
        let (decision, read) = self.read_and_check(kind, path);
        let out = match (&decision, read) {
            (_, Read::Missing) => Verified::Missing,
            (_, Read::ShippedDefault) => Verified::ShippedDefault,
            (
                Decision::Accepted {
                    sha256, key_fps, ..
                },
                Read::Text(text),
            ) => {
                info!(overlay = kind.keyword(), path = %path.display(), sha256 = %sha256, keys = ?key_fps, "signed overlay accepted — the bytes verified are the bytes applied");
                Verified::Content {
                    path: path.to_path_buf(),
                    text,
                }
            }
            (Decision::Refused { reason, sha256 }, Read::Text(text)) if self.allow_unsigned => {
                error!(overlay = kind.keyword(), path = %path.display(), reason = %reason, sha256 = ?sha256, "UNSIGNED OVERLAY LOADED — {ALLOW_UNSIGNED_ENV}=1 is set");
                Verified::Content {
                    path: path.to_path_buf(),
                    text,
                }
            }
            (Decision::Refused { reason, .. }, _) => {
                error!(
                    overlay = kind.keyword(),
                    path = %path.display(),
                    reason = %reason,
                    "UNAUTHORIZED OVERLAY — not loaded, booting on the shipped defaults for this list \
                     (sign it with `nn-admin config overlay set|sign`)"
                );
                Verified::Refused
            }
            // An unusable read always comes with a refusal, text never
            // with an absent decision.
            _ => Verified::Refused,
        };
        if decision != Decision::Absent {
            self.record(kind, path, decision);
        }
        out
    }

    /// External audit LLMR-016: a shipped default list (`.v1`) could not be
    /// read and the copy built into the agent is in force — a signed
    /// `integrity_drift` (`default_list_unavailable`), like a refused
    /// overlay: the host no longer runs on the list it was installed with.
    pub fn report_default_unavailable(&self, list: &str, path: &Path, reason: &str) {
        self.record_entry(drift_entry(serde_json::json!({
            "kind": "default_list_unavailable",
            "detail": format!("{list} ({}): {reason}", path.display()),
            "at_boot": true,
        })));
    }

    /// External audit LLMR-015 (NN-AUD-327): a shipped default list (`.v1`)
    /// is no list NorthNarrow shipped — edited while the agent was not
    /// running — and the copy built into the agent is in force (or, with
    /// [`ALLOW_UNSIGNED_ENV`], the file was applied anyway): a signed
    /// `integrity_drift` (`default_list_modified`) with both SHA-256, at
    /// every boot the file is still there. It used to be applied silently.
    pub fn report_default_modified(
        &self,
        list: &str,
        path: &Path,
        sha256: &str,
        builtin_sha256: &str,
        loaded_anyway: bool,
    ) {
        let outcome = if loaded_anyway {
            format!("applied anyway ({ALLOW_UNSIGNED_ENV}=1)")
        } else {
            "not applied, the copy built into the agent is in force".to_string()
        };
        self.record_entry(drift_entry(serde_json::json!({
            "kind": "default_list_modified",
            "detail": format!(
                "{list} ({}): no list NorthNarrow shipped (edited by hand?) — {outcome}",
                path.display()
            ),
            "sha256": sha256,
            "builtin_sha256": builtin_sha256,
            "loaded_anyway": loaded_anyway,
            "at_boot": true,
        })));
    }

    /// External audit LLMR-014: write the floor's entries (its reset, an
    /// anchor) as soon as the log opens, before this boot's `agent_boot`: a
    /// log cut back to any entry of this boot still carries them.
    pub fn attest_floor(&self, log: &mut AuditLog) {
        let floor: Vec<_> = std::mem::take(&mut *self.floor_pending.lock());
        for draft in floor {
            if let Err(e) = log.append(draft) {
                warn!(
                    error = format!("{e:#}"),
                    "overlay gate: rollback-floor entry failed"
                );
            }
        }
    }

    /// Attach the signed audit log: pending entries are written now (the
    /// floor's first, if [`Self::attest_floor`] did not), later ones (FIM
    /// recompute, COMBAT engage) as they happen.
    pub fn attach_audit_log(&self, log: Option<Arc<Mutex<AuditLog>>>) {
        let Some(log) = log else { return };
        *self.audit_log.lock() = Some(Arc::clone(&log));
        let floor: Vec<_> = std::mem::take(&mut *self.floor_pending.lock());
        let pending: Vec<_> = std::mem::take(&mut *self.pending.lock());
        for draft in floor.into_iter().chain(pending) {
            append(&log, draft);
        }
    }

    fn record(&self, kind: OverlayKind, path: &Path, d: Decision) {
        if let Some(draft) = decision_entry(kind, path, &d, self.allow_unsigned) {
            self.record_entry(draft);
        }
    }

    fn record_entry(&self, draft: AuditEntryDraft) {
        let log = self.audit_log.lock().clone();
        match log {
            Some(l) => append(&l, draft),
            None => self.pending.lock().push(draft),
        }
    }

    /// A signed audit row of the gate's (lab PR 236: `rule_policy_loaded`,
    /// the per-rule policy in force at boot), written now or when the log
    /// is attached.
    pub fn record_note(&self, op: &str, result: &str, extra: serde_json::Value) {
        self.record_entry(entry(op, result, extra));
    }

    /// True when `path` (an overlay of `kind`) carries a valid signature
    /// for its current content — used by the integrity check to tell a
    /// legitimate `set` from an edit.
    pub fn is_signed(&self, kind: OverlayKind, path: &Path) -> bool {
        matches!(self.check(kind, path), Decision::Accepted { .. })
    }
}

/// The audit entry a decision makes, if any: a newly accepted signature, or
/// a refusal.
fn decision_entry(
    kind: OverlayKind,
    path: &Path,
    d: &Decision,
    allowed: bool,
) -> Option<AuditEntryDraft> {
    match d {
        Decision::Absent | Decision::Accepted { new: false, .. } => None,
        Decision::Accepted {
            sha256,
            signed_ts,
            key_fps,
            new: true,
        } => Some(entry(
            AUDIT_OP_ACCEPTED,
            "success",
            serde_json::json!({
                "kind": kind.keyword(),
                "path": path.display().to_string(),
                "sha256": sha256,
                "signed_ts": signed_ts,
                "key_fps": key_fps,
            }),
        )),
        Decision::Refused { reason, sha256 } => Some(drift_entry(serde_json::json!({
            "kind": "unauthorized_overlay",
            "detail": format!("{} ({}): {reason}", kind.keyword(), path.display()),
            "sha256": sha256,
            "loaded_anyway": allowed,
            "at_boot": true,
        }))),
    }
}

/// A signed `integrity_drift` entry.
pub(crate) fn drift_entry(extra: serde_json::Value) -> AuditEntryDraft {
    entry(crate::self_integrity::AUDIT_OP, "detected", extra)
}

pub(crate) fn entry(op: &str, result: &str, extra: serde_json::Value) -> AuditEntryDraft {
    AuditEntryDraft {
        op: op.to_string(),
        extra,
        key_fp: "agent-self".to_string(),
        cosigner_fps: Vec::new(),
        result: result.to_string(),
        client_pid: std::process::id(),
        client_uid: 0,
        client_comm: "northnarrow-agent".to_string(),
        client_exe: None,
    }
}

fn append(log: &Arc<Mutex<AuditLog>>, draft: AuditEntryDraft) {
    if let Err(e) = log.lock().append(draft) {
        warn!(error = format!("{e:#}"), "overlay gate: audit entry failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use nn_proto::admin_signed_payload::sign;

    const AGENT: [u8; 16] = [3; 16];

    fn setup(roles: &str) -> (tempfile::TempDir, SigningKey, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[0x21; 32]);
        let pub_hex = hex(key.verifying_key().as_bytes());
        let admin_pub = dir.path().join("admin.pub");
        std::fs::write(&admin_pub, format!("{pub_hex} {roles}\n")).unwrap();
        (dir, key, admin_pub)
    }

    /// The agent's own signed chain in `dir`: `audit.log` holding the
    /// accepted signatures of `accepted` (kind, signed ts), and the
    /// signing key that verifies it.
    fn chain(dir: &Path, accepted: &[(OverlayKind, u64)]) -> (PathBuf, PathBuf) {
        let audit = dir.join("audit.log");
        let key = dir.join("agent.sig.key");
        let signing = crate::audit::AgentSigningKey::load_or_bootstrap(&key).unwrap();
        let mut log = AuditLog::open(&audit, signing, AGENT).unwrap();
        for (kind, ts) in accepted {
            log.append(entry(
                AUDIT_OP_ACCEPTED,
                "success",
                serde_json::json!({ "kind": kind.keyword(), "sha256": "aa", "signed_ts": ts }),
            ))
            .unwrap();
        }
        (audit, key)
    }

    fn unix_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn write_signed(
        dir: &Path,
        key: &SigningKey,
        kind: OverlayKind,
        body: &str,
        ts: u64,
    ) -> PathBuf {
        let p = dir.join(kind.file_name());
        std::fs::write(&p, body).unwrap();
        let payload = SignedPayload::new_config_overlay_set(
            [9; 32],
            ts,
            AGENT,
            kind,
            content_sha256(body.as_bytes()),
            body.len() as u32,
        );
        let s = sign(&payload, key).unwrap();
        std::fs::write(
            sig_path(&p),
            OverlaySignature::new(payload, &[s])
                .unwrap()
                .to_json()
                .unwrap(),
        )
        .unwrap();
        p
    }

    #[test]
    fn signed_overlay_is_accepted_and_edits_are_refused() {
        let (dir, key, admin_pub) = setup("config-manage");
        let p = write_signed(
            dir.path(),
            &key,
            OverlayKind::ProcessCommAllowlist,
            "+backupd\n",
            100,
        );
        let gate = OverlayGate::new(&admin_pub, AGENT, RollbackFloor::default());
        match gate.check(OverlayKind::ProcessCommAllowlist, &p) {
            Decision::Accepted { new, signed_ts, .. } => assert!(new && signed_ts == 100),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            gate.verified(OverlayKind::ProcessCommAllowlist, &p),
            Verified::Content {
                path: p.clone(),
                text: "+backupd\n".to_string()
            }
        );
        std::fs::write(&p, "+backupd\n+evil-implant\n").unwrap();
        assert!(matches!(
            gate.check(OverlayKind::ProcessCommAllowlist, &p),
            Decision::Refused { .. }
        ));
        assert_eq!(
            gate.verified(OverlayKind::ProcessCommAllowlist, &p),
            Verified::Refused
        );
        assert_eq!(
            gate.verified(OverlayKind::ProcessCommAllowlist, &dir.path().join("none")),
            Verified::Missing
        );
    }

    /// External audit LLMR-013: the loader applies the text the gate
    /// verified — rewriting the file once the gate has read it changes
    /// nothing (every loader used to read the path again).
    #[test]
    fn the_loader_applies_the_bytes_the_gate_verified() {
        let (dir, key, admin_pub) = setup("config-manage");
        let p = write_signed(
            dir.path(),
            &key,
            OverlayKind::ProcessCommAllowlist,
            "+backupd\n",
            100,
        );
        let gate = OverlayGate::new(&admin_pub, AGENT, RollbackFloor::default());
        let verified = gate.verified(OverlayKind::ProcessCommAllowlist, &p);
        std::fs::write(&p, "+backupd\n+evil-implant\n").unwrap();
        let list = crate::config::comm_allowlist::load_comm_allowlist(
            "process-comm-allowlist",
            &dir.path().join("process-comm-allowlist.v1"),
            crate::config::overlay::Shipped::new("", &[]),
            &verified,
        )
        .unwrap();
        assert!(list.contains("backupd"));
        assert!(!list.contains("evil-implant"));
    }

    /// External audit LLMR-013: an overlay is not read through a link (its
    /// target is not what was signed into place), and a FIFO planted at its
    /// name is refused, not waited on.
    #[test]
    fn an_overlay_behind_a_link_or_a_fifo_is_refused() {
        let (dir, key, admin_pub) = setup("config-manage");
        let signed = write_signed(
            dir.path(),
            &key,
            OverlayKind::ProcessCommAllowlist,
            "+backupd\n",
            100,
        );
        let gate = OverlayGate::new(&admin_pub, AGENT, RollbackFloor::default());
        let link = dir.path().join("link.local");
        std::os::unix::fs::symlink(&signed, &link).unwrap();
        std::fs::copy(sig_path(&signed), sig_path(&link)).unwrap();
        assert!(
            matches!(gate.check(OverlayKind::ProcessCommAllowlist, &link), Decision::Refused { reason, .. } if reason.contains("symbolic link"))
        );
        let fifo = dir.path().join("fifo.local");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path; mkfifo has no other preconditions.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(
            matches!(gate.check(OverlayKind::ProcessCommAllowlist, &fifo), Decision::Refused { reason, .. } if reason.contains("not a regular file"))
        );
        assert_eq!(
            gate.verified(OverlayKind::ProcessCommAllowlist, &fifo),
            Verified::Refused
        );
    }

    /// External audit LLMR-016: a default list replaced by the built-in copy
    /// is a signed record, queued until the audit log is attached.
    #[test]
    fn an_unavailable_default_list_is_recorded() {
        let (dir, _key, admin_pub) = setup("config-manage");
        let gate = OverlayGate::new(&admin_pub, AGENT, RollbackFloor::default());
        gate.report_default_unavailable(
            "fim paths-config",
            &dir.path().join("fim-paths.v1"),
            "No such file or directory (os error 2)",
        );
        let pending = gate.pending.lock();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].op, crate::self_integrity::AUDIT_OP);
        assert_eq!(pending[0].extra["kind"], "default_list_unavailable");
    }

    /// External audit LLMR-015: an edited default list is a signed record
    /// naming the file and both SHA-256.
    #[test]
    fn a_modified_default_list_is_recorded() {
        let (dir, _key, admin_pub) = setup("config-manage");
        let gate = OverlayGate::new(&admin_pub, AGENT, RollbackFloor::default());
        let v1 = dir.path().join("process-comm-allowlist.v1");
        gate.report_default_modified("process-comm-allowlist", &v1, "aa", "bb", false);
        let pending = gate.pending.lock();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].op, crate::self_integrity::AUDIT_OP);
        assert_eq!(pending[0].result, "detected");
        let extra = &pending[0].extra;
        assert_eq!(extra["kind"], "default_list_modified");
        assert_eq!(extra["sha256"], "aa");
        assert_eq!(extra["builtin_sha256"], "bb");
        assert_eq!(extra["loaded_anyway"], false);
        let detail = extra["detail"].as_str().unwrap();
        assert!(detail.contains("process-comm-allowlist.v1"), "{detail}");
        assert!(detail.contains("not applied"), "{detail}");
    }

    /// External audit ATP-001 / DEP-003: the shipped COMBAT files need no
    /// signature; a change does, and must still isolate to be signed.
    #[test]
    fn combat_files_are_trusted_as_shipped_or_signed() {
        use crate::anti_tamper::network_isolate::{BUILTIN_RULES_V4, BUILTIN_RULES_V6};
        let (dir, key, admin_pub) = setup("config-manage");
        let gate = OverlayGate::new(&admin_pub, AGENT, RollbackFloor::default());
        let v4 = dir.path().join(OverlayKind::CombatRulesV4.file_name());
        std::fs::write(&v4, BUILTIN_RULES_V4).unwrap();
        assert_eq!(
            gate.check(OverlayKind::CombatRulesV4, &v4),
            Decision::Absent
        );
        std::fs::write(&v4, "*filter\nCOMMIT\n").unwrap();
        assert!(matches!(
            gate.check(OverlayKind::CombatRulesV4, &v4),
            Decision::Refused { .. }
        ));
        assert!(validate_content(OverlayKind::CombatRulesV4, "*filter\nCOMMIT\n").is_err());
        assert!(validate_content(OverlayKind::CombatRulesV6, BUILTIN_RULES_V6).is_ok());
        let allow = write_signed(
            dir.path(),
            &key,
            OverlayKind::CombatAllow,
            "10.0.0.0/8\n",
            5,
        );
        assert!(matches!(
            gate.check(OverlayKind::CombatAllow, &allow),
            Decision::Accepted { .. }
        ));
        assert!(validate_content(OverlayKind::CombatAllow, "not-a-cidr\n").is_err());
        assert_eq!(
            OverlayKind::from_keyword("combat-allow.cidrs"),
            Some(OverlayKind::CombatAllow)
        );
        assert_eq!(
            OverlayKind::from_keyword("combat-rules-v6"),
            Some(OverlayKind::CombatRulesV6)
        );
    }

    #[test]
    fn unsigned_wrong_kind_wrong_role_wrong_agent_are_refused() {
        let (dir, key, admin_pub) = setup("unlock,audit-read");
        // wrong role
        let p = write_signed(
            dir.path(),
            &key,
            OverlayKind::NetflowCommAllowlist,
            "+x\n",
            1,
        );
        let gate = OverlayGate::new(&admin_pub, AGENT, RollbackFloor::default());
        assert!(
            matches!(gate.check(OverlayKind::NetflowCommAllowlist, &p), Decision::Refused { reason, .. } if reason.contains("rejected"))
        );
        // wrong kind: the signature names another overlay
        let (dir2, key2, admin_pub2) = setup("config-manage");
        let p2 = write_signed(dir2.path(), &key2, OverlayKind::FimPaths, "+/srv/app\n", 1);
        let gate2 = OverlayGate::new(&admin_pub2, AGENT, RollbackFloor::default());
        assert!(
            matches!(gate2.check(OverlayKind::ProcessCommAllowlist, &p2), Decision::Refused { reason, .. } if reason.contains("fim-paths"))
        );
        // wrong agent: same files, another agent_id
        let gate3 = OverlayGate::new(&admin_pub2, [4; 16], RollbackFloor::default());
        assert!(matches!(
            gate3.check(OverlayKind::FimPaths, &p2),
            Decision::Refused { .. }
        ));
        // unsigned
        let u = dir2.path().join("netflow-blocklist.local");
        std::fs::write(&u, "+203.0.113.7\n").unwrap();
        assert!(
            matches!(gate2.check(OverlayKind::NetflowBlocklist, &u), Decision::Refused { reason, .. } if reason.contains("no signature"))
        );
        // absent
        assert_eq!(
            gate2.check(
                OverlayKind::EscalationAllow,
                &dir2.path().join("nope.local")
            ),
            Decision::Absent
        );
    }

    /// External audit LLMR-014: the floor read from the agent's signed
    /// chain still refuses a rollback, and lets a newer signature through.
    #[test]
    fn verified_floor_still_blocks_rollback() {
        let (dir, key, admin_pub) = setup("config-manage");
        // the chain already accepted a signature made at ts 500
        let (audit, agent_key) = chain(dir.path(), &[(OverlayKind::ProcessCommAllowlist, 500)]);
        let floor = RollbackFloor::scan(&audit, &agent_key);
        assert_eq!(floor.reset(), None);
        let gate = OverlayGate::new(&admin_pub, AGENT, floor);
        let p = write_signed(
            dir.path(),
            &key,
            OverlayKind::ProcessCommAllowlist,
            "+old-exemption\n",
            400,
        );
        assert!(
            matches!(gate.check(OverlayKind::ProcessCommAllowlist, &p), Decision::Refused { reason, .. } if reason.contains("rollback"))
        );
        let p = write_signed(
            dir.path(),
            &key,
            OverlayKind::ProcessCommAllowlist,
            "+new\n",
            600,
        );
        assert!(matches!(
            gate.check(OverlayKind::ProcessCommAllowlist, &p),
            Decision::Accepted { new: true, .. }
        ));
    }

    /// External audit LLMR-014: the log removed while the agent's key stays
    /// gave no floor, and the retired signature was loaded. Now the floor
    /// is reset: refused, recorded, and a signature made after it loads.
    #[test]
    fn missing_log_refuses_present_overlay() {
        let (dir, key, admin_pub) = setup("config-manage");
        let (audit, agent_key) = chain(dir.path(), &[(OverlayKind::ProcessCommAllowlist, 500)]);
        std::fs::remove_file(&audit).unwrap();
        let gate = OverlayGate::new(&admin_pub, AGENT, RollbackFloor::scan(&audit, &agent_key));
        let p = write_signed(
            dir.path(),
            &key,
            OverlayKind::ProcessCommAllowlist,
            "+old-exemption\n",
            400,
        );
        assert!(
            matches!(gate.check(OverlayKind::ProcessCommAllowlist, &p), Decision::Refused { reason, .. } if reason.contains("rollback floor was reset"))
        );
        assert_eq!(
            gate.verified(OverlayKind::ProcessCommAllowlist, &p),
            Verified::Refused
        );
        let resigned = write_signed(
            dir.path(),
            &key,
            OverlayKind::ProcessCommAllowlist,
            "+old-exemption\n",
            unix_now() + 5,
        );
        assert!(matches!(
            gate.check(OverlayKind::ProcessCommAllowlist, &resigned),
            Decision::Accepted { .. }
        ));
    }

    /// External audit LLMR-014: a floor entry edited offline breaks the
    /// chain — the floor is reset, the old signature refused.
    #[test]
    fn edited_floor_entry_breaks_chain_and_refuses() {
        let (dir, key, admin_pub) = setup("config-manage");
        let (audit, agent_key) = chain(dir.path(), &[(OverlayKind::ProcessCommAllowlist, 500)]);
        let body = std::fs::read_to_string(&audit).unwrap();
        std::fs::write(&audit, body.replace("\"signed_ts\":500", "\"signed_ts\":1")).unwrap();
        let floor = RollbackFloor::scan(&audit, &agent_key);
        assert!(floor.reset().is_some_and(|r| r.contains("does not verify")));
        let gate = OverlayGate::new(&admin_pub, AGENT, floor);
        let p = write_signed(
            dir.path(),
            &key,
            OverlayKind::ProcessCommAllowlist,
            "+old-exemption\n",
            400,
        );
        assert!(matches!(
            gate.check(OverlayKind::ProcessCommAllowlist, &p),
            Decision::Refused { .. }
        ));
    }

    /// The floor's reset is the first entry this boot writes — before
    /// `agent_boot` — and is written once.
    #[test]
    fn the_floor_is_attested_before_the_boot_entry() {
        let (dir, _key, admin_pub) = setup("config-manage");
        let (audit, agent_key) = chain(dir.path(), &[(OverlayKind::ProcessCommAllowlist, 500)]);
        std::fs::remove_file(&audit).unwrap();
        let gate = OverlayGate::new(&admin_pub, AGENT, RollbackFloor::scan(&audit, &agent_key));
        let signing = crate::audit::AgentSigningKey::load_or_bootstrap(&agent_key).unwrap();
        let mut log = AuditLog::open(&audit, signing, AGENT).unwrap();
        gate.attest_floor(&mut log);
        log.boot_probe(
            None,
            "verified",
            "installed",
            &crate::build_info::agent_build(),
        )
        .unwrap();
        gate.attach_audit_log(Some(Arc::new(Mutex::new(log))));
        let ops: Vec<(String, String)> = std::fs::read_to_string(&audit)
            .unwrap()
            .lines()
            .map(|l| {
                let e: crate::audit::AuditEntry = serde_json::from_str(l).unwrap();
                let kind = e.extra["kind"].as_str().unwrap_or("").to_string();
                (e.op, kind)
            })
            .collect();
        assert_eq!(
            ops,
            [
                (
                    crate::self_integrity::AUDIT_OP.to_string(),
                    super::super::overlay_floor::DRIFT_KIND.to_string()
                ),
                (
                    super::super::overlay_floor::AUDIT_OP_ANCHOR.to_string(),
                    String::new()
                ),
                ("agent_boot".to_string(), String::new()),
            ]
        );
    }

    #[test]
    fn content_validation_uses_the_loader_rules() {
        assert!(validate_content(OverlayKind::FimPaths, "+/etc/app.conf\n-/etc/motd\n").is_ok());
        assert!(validate_content(OverlayKind::FimPaths, "+relative/path\n").is_err());
        assert!(validate_content(OverlayKind::NetflowBlocklist, "+203.0.113.0/24\n").is_ok());
        assert!(validate_content(OverlayKind::NetflowJa3Blocklist, "+not-a-hash\n").is_err());
        assert!(validate_content(OverlayKind::MassWriteCarveout, "+/srv/build/\n").is_ok());
        assert!(validate_content(OverlayKind::MassWriteCarveout, "-/srv\n").is_err());
        // External audit POS-010 / POS-011: a too-broad entry is refused
        // before it is signed or stored, named with its line.
        let e = validate_content(OverlayKind::MassWriteCarveout, "+/srv/build/\n+/home/\n")
            .unwrap_err()
            .to_string();
        assert!(e.contains(":2:") && e.contains("`/home/`"), "{e}");
        let e = validate_content(OverlayKind::EscalationAllow, "exfil * 0.0.0.0/0 443\n")
            .unwrap_err()
            .to_string();
        assert!(e.contains("line 1") && e.contains("/0"), "{e}");
        assert!(validate_content(
            OverlayKind::EscalationAllow,
            "exfil * 140.82.112.0/20 443\n"
        )
        .is_ok());
        assert!(
            validate_content(OverlayKind::ProcessCommAllowlist, "# comment\n+backupd\n").is_ok()
        );
    }

    /// Lab PR 236: the per-rule policy is an overlay like the others — a
    /// `config-manage` signature over its exact bytes is in force; an
    /// edit, another role's key, another agent, no signature leave the
    /// built-in defaults; a signed file that does not parse is refused by
    /// the content check (`overlay set`) and, at boot, leaves the defaults
    /// with a degradation.
    #[test]
    fn the_rule_policy_is_signed_like_every_overlay() {
        use crate::decision::rule_policy::{boot_policy, Mode};
        const IMP: &str = "NN-L-IMP-001_RansomwareEncryption";
        let body = "enforce NN-L-IMP-001\nexempt R020 uid 998\n";
        let boot = |gate: &OverlayGate, p: &Path| match gate.verified(OverlayKind::RulePolicy, p) {
            Verified::Content { path, text } => boot_policy(Some((&path, &text))),
            _ => boot_policy(None),
        };
        let (dir, key, admin_pub) = setup("config-manage");
        let p = write_signed(dir.path(), &key, OverlayKind::RulePolicy, body, 100);
        assert_eq!(p.file_name().unwrap(), "rule-policy.local");
        let gate = OverlayGate::new(&admin_pub, AGENT, RollbackFloor::default());
        let b = boot(&gate, &p);
        assert_eq!(b.degraded, None);
        assert_eq!(b.policy.mode(IMP), Some(Mode::Enforce));
        // Edited after signing: the defaults.
        std::fs::write(&p, "enforce NN-L-IMP-001\nenforce R020\n").unwrap();
        assert!(boot(&gate, &p).policy.is_builtin());
        // Signed by a key without config-manage: the defaults.
        let (dir2, key2, admin_pub2) = setup("unlock,audit-read");
        let p2 = write_signed(dir2.path(), &key2, OverlayKind::RulePolicy, body, 100);
        let gate2 = OverlayGate::new(&admin_pub2, AGENT, RollbackFloor::default());
        assert!(
            matches!(gate2.check(OverlayKind::RulePolicy, &p2), Decision::Refused { reason, .. } if reason.contains("rejected"))
        );
        assert!(boot(&gate2, &p2).policy.is_builtin());
        // Another agent's signature: the defaults.
        let (dir3, key3, admin_pub3) = setup("config-manage");
        let p3 = write_signed(dir3.path(), &key3, OverlayKind::RulePolicy, body, 100);
        let gate3 = OverlayGate::new(&admin_pub3, [4; 16], RollbackFloor::default());
        assert!(boot(&gate3, &p3).policy.is_builtin());
        // A signature of another kind over the same bytes: refused.
        let p4 = write_signed(dir3.path(), &key3, OverlayKind::ExecPolicy, body, 100);
        std::fs::rename(&p4, dir3.path().join("x.local")).unwrap();
        std::fs::rename(sig_path(&p4), sig_path(&p3)).unwrap();
        let gate4 = OverlayGate::new(&admin_pub3, AGENT, RollbackFloor::default());
        assert!(
            matches!(gate4.check(OverlayKind::RulePolicy, &p3), Decision::Refused { reason, .. } if reason.contains("exec-policy"))
        );
        // Unsigned: refused.
        let u = dir3.path().join("unsigned-rule-policy.local");
        std::fs::write(&u, body).unwrap();
        assert!(boot(&gate4, &u).policy.is_builtin());
        // Signed but not parsing: `overlay set` refuses it; at boot, the
        // defaults and a degradation.
        let bad = "enforce NN-L-IMP-001\nexempt R020 comm sshd\n";
        let e = validate_content(OverlayKind::RulePolicy, bad)
            .unwrap_err()
            .to_string();
        assert!(e.contains("rule-policy.local: line 2"), "{e}");
        assert!(validate_content(OverlayKind::RulePolicy, body).is_ok());
        let (dir5, key5, admin_pub5) = setup("config-manage");
        let p5 = write_signed(dir5.path(), &key5, OverlayKind::RulePolicy, bad, 100);
        let gate5 = OverlayGate::new(&admin_pub5, AGENT, RollbackFloor::default());
        let b = boot(&gate5, &p5);
        assert!(b.policy.is_builtin());
        assert!(b.degraded.unwrap().contains("line 2"));
    }

    /// Lab PR 230 (D0 of the dependency plan): an overlay signed before the
    /// ed25519-dalek 3 / sha2 0.11 bump, stored as `nn-admin config overlay
    /// set` stores it (`agent/tests/fixtures/overlay-v1/`: the overlay, its
    /// `.sig`, the `admin.pub` line of the seed `[0x42; 32]`). Signature
    /// recomputed outside the repository (OpenSSL).
    mod crypto_vectors {
        use super::*;

        const FIXTURE_PUB: &str = include_str!(concat!(
            env!("NN_REPO_ROOT"),
            "/agent/tests/fixtures/overlay-v1/admin.pub"
        ));
        const FIXTURE_BODY: &str = include_str!(concat!(
            env!("NN_REPO_ROOT"),
            "/agent/tests/fixtures/overlay-v1/process-comm-allowlist.local"
        ));
        const FIXTURE_SIG: &str = include_str!(concat!(
            env!("NN_REPO_ROOT"),
            "/agent/tests/fixtures/overlay-v1/process-comm-allowlist.local.sig"
        ));
        const SIGNED_TS: u64 = 1_792_540_800;
        /// SHA-256 of the overlay (`+backupd\n`).
        const BODY_SHA256: &str =
            "19ede2fd3fc149f229d9cd15f9b1b86ee1c45885965955e2d36c6b2f62e377bc";
        /// The first 4 bytes of the SHA-256 of the key `2152f8…db12`.
        const KEY_FP: &str = "3097e2de";

        fn fixture_dir() -> (tempfile::TempDir, PathBuf, PathBuf) {
            let dir = tempfile::tempdir().unwrap();
            let p = dir
                .path()
                .join(OverlayKind::ProcessCommAllowlist.file_name());
            std::fs::write(&p, FIXTURE_BODY).unwrap();
            std::fs::write(sig_path(&p), FIXTURE_SIG).unwrap();
            let admin_pub = dir.path().join("admin.pub");
            std::fs::write(&admin_pub, FIXTURE_PUB).unwrap();
            (dir, p, admin_pub)
        }

        /// Protects: an overlay signed before the bump must still load after it.
        #[test]
        fn an_overlay_signed_before_the_bump_is_accepted() {
            let (_dir, p, admin_pub) = fixture_dir();
            let gate = OverlayGate::new(&admin_pub, AGENT, RollbackFloor::default());
            assert_eq!(
                gate.check(OverlayKind::ProcessCommAllowlist, &p),
                Decision::Accepted {
                    sha256: BODY_SHA256.to_string(),
                    signed_ts: SIGNED_TS,
                    key_fps: vec![KEY_FP.to_string()],
                    new: true,
                }
            );
            // an edit is still refused
            std::fs::write(&p, "+backupd\n+evil-implant\n").unwrap();
            assert!(matches!(
                gate.check(OverlayKind::ProcessCommAllowlist, &p),
                Decision::Refused { .. }
            ));
        }

        /// Protects: the overlay fixture is what the signing code writes today, byte for byte.
        #[test]
        fn the_stored_overlay_signature_is_pinned() {
            let key = SigningKey::from_bytes(&[0x42; 32]);
            assert_eq!(
                format!("{} config-manage\n", hex(key.verifying_key().as_bytes())),
                FIXTURE_PUB
            );
            let payload = SignedPayload::new_config_overlay_set(
                [9; 32],
                SIGNED_TS,
                AGENT,
                OverlayKind::ProcessCommAllowlist,
                content_sha256(FIXTURE_BODY.as_bytes()),
                FIXTURE_BODY.len() as u32,
            );
            let s = sign(&payload, &key).unwrap();
            assert_eq!(
                OverlaySignature::new(payload, &[s])
                    .unwrap()
                    .to_json()
                    .unwrap(),
                FIXTURE_SIG
            );
        }
    }
}
