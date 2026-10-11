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
//! accepted for that kind (no rollback to a retired exemption).
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
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use anyhow::{anyhow, Context, Result};
use common::wire::admin_signed_payload::{
    OperationCode, OperationExtra, OverlayKind, Role, SignedPayload,
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{error, info, warn};

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
/// Path a refused overlay is replaced with (reads as empty: defaults only).
pub const EMPTY_OVERLAY: &str = "/dev/null";

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
/// recorded by [`OverlayGate::effective`] so `config overlay set` writes
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
        let tmp = dir.join(format!(".{name}.tmp-{}", std::process::id()));
        {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp)
                .with_context(|| format!("creating {}", tmp.display()))?;
            f.write_all(body.as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &target)
            .with_context(|| format!("renaming {} → {}", tmp.display(), target.display()))?;
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
        OverlayKind::NetflowBlocklist => {
            crate::net::blocklist::parse_blocklist_overlay_text(&label, text)?;
        }
        OverlayKind::NetflowJa3Blocklist => {
            crate::net::blocklist::parse_ja3_overlay_text(&label, text)?;
        }
        OverlayKind::MassWriteCarveout => {
            for (i, raw) in text.lines().enumerate() {
                let line = raw.split('#').next().unwrap_or("").trim();
                if line.is_empty() {
                    continue;
                }
                if line.starts_with('-') {
                    return Err(anyhow!(
                        "{label}:{}: `-` has no effect in this overlay",
                        i + 1
                    ));
                }
                let entry = line.strip_prefix('+').unwrap_or(line).trim();
                if !entry.starts_with('/') {
                    return Err(anyhow!(
                        "{label}:{}: entry must be an absolute path prefix",
                        i + 1
                    ));
                }
            }
        }
        OverlayKind::EscalationAllow => {
            let (_, errors) = crate::posture::escalation_allow::EscalationAllowList::parse(text);
            if let Some(e) = errors.first() {
                return Err(anyhow!("{label}: {e}"));
            }
        }
    }
    Ok(())
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

/// Boot-time gate for every overlay the agent reads.
pub struct OverlayGate {
    auth: Option<AdminAuth>,
    /// kind → (sha256 hex, signed ts) of the newest signature the audit
    /// chain recorded (accepted at a boot, or stored by `set`).
    recorded: HashMap<OverlayKind, (String, u64)>,
    allow_unsigned: bool,
    audit_log: Mutex<Option<Arc<Mutex<AuditLog>>>>,
    /// Decisions made before the audit log was attached.
    pending: Mutex<Vec<(OverlayKind, PathBuf, Decision)>>,
}

impl OverlayGate {
    /// `admin_pub` is read once here (an overlay is only as trusted as the
    /// key set at boot); `audit_log` is scanned for the signatures already
    /// accepted, to refuse a rollback.
    pub fn new(admin_pub: &Path, agent_id: [u8; 16], audit_log: &Path) -> Self {
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
        Self {
            auth,
            recorded: recorded_signatures(audit_log),
            allow_unsigned,
            audit_log: Mutex::new(None),
            pending: Mutex::new(Vec::new()),
        }
    }

    /// The boot decision for `kind` read from `path`.
    pub fn check(&self, kind: OverlayKind, path: &Path) -> Decision {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Decision::Absent,
            Err(e) => {
                return Decision::Refused {
                    reason: format!("unreadable: {e}"),
                    sha256: None,
                }
            }
        };
        let digest = content_sha256(&bytes);
        let sha_hex = hex(&digest);
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
        if extra.sha256 != digest || extra.len as usize != bytes.len() {
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
        let mut new = true;
        if let Some((hash, ts)) = self.recorded.get(&kind) {
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

    /// The path the loader of `kind` should read: `path` when the overlay
    /// is signed (or absent), [`EMPTY_OVERLAY`] when it is refused (unless
    /// the escape hatch is set). Every decision is logged and recorded.
    pub fn effective(&self, kind: OverlayKind, path: &Path) -> PathBuf {
        remember_path(kind, path);
        let decision = self.check(kind, path);
        let out = match &decision {
            Decision::Absent => path.to_path_buf(),
            Decision::Accepted {
                sha256, key_fps, ..
            } => {
                info!(overlay = kind.keyword(), path = %path.display(), sha256 = %&sha256[..16], keys = ?key_fps, "signed overlay accepted");
                path.to_path_buf()
            }
            Decision::Refused { reason, .. } if self.allow_unsigned => {
                error!(overlay = kind.keyword(), path = %path.display(), reason = %reason, "UNSIGNED OVERLAY LOADED — {ALLOW_UNSIGNED_ENV}=1 is set");
                path.to_path_buf()
            }
            Decision::Refused { reason, .. } => {
                error!(
                    overlay = kind.keyword(),
                    path = %path.display(),
                    reason = %reason,
                    "UNAUTHORIZED OVERLAY — not loaded, booting on the shipped defaults for this list \
                     (sign it with `nn-admin config overlay set|sign`)"
                );
                PathBuf::from(EMPTY_OVERLAY)
            }
        };
        if decision != Decision::Absent {
            self.record(kind, path, decision);
        }
        out
    }

    /// Attach the signed audit log: pending decisions are written now,
    /// later ones (FIM recompute) as they happen.
    pub fn attach_audit_log(&self, log: Option<Arc<Mutex<AuditLog>>>) {
        let Some(log) = log else { return };
        *self.audit_log.lock() = Some(Arc::clone(&log));
        let pending: Vec<_> = std::mem::take(&mut *self.pending.lock());
        for (kind, path, d) in pending {
            write_audit(&log, kind, &path, &d, self.allow_unsigned);
        }
    }

    fn record(&self, kind: OverlayKind, path: &Path, d: Decision) {
        let log = self.audit_log.lock().clone();
        match log {
            Some(l) => write_audit(&l, kind, path, &d, self.allow_unsigned),
            None => self.pending.lock().push((kind, path.to_path_buf(), d)),
        }
    }

    /// True when `path` (an overlay of `kind`) carries a valid signature
    /// for its current content — used by the integrity check to tell a
    /// legitimate `set` from an edit.
    pub fn is_signed(&self, kind: OverlayKind, path: &Path) -> bool {
        matches!(self.check(kind, path), Decision::Accepted { .. })
    }
}

fn write_audit(
    log: &Arc<Mutex<AuditLog>>,
    kind: OverlayKind,
    path: &Path,
    d: &Decision,
    allowed: bool,
) {
    let (op, result, extra) = match d {
        Decision::Absent => return,
        Decision::Accepted { new: false, .. } => return,
        Decision::Accepted {
            sha256,
            signed_ts,
            key_fps,
            new: true,
        } => (
            AUDIT_OP_ACCEPTED,
            "success",
            serde_json::json!({
                "kind": kind.keyword(),
                "path": path.display().to_string(),
                "sha256": sha256,
                "signed_ts": signed_ts,
                "key_fps": key_fps,
            }),
        ),
        Decision::Refused { reason, sha256 } => (
            crate::self_integrity::AUDIT_OP,
            "detected",
            serde_json::json!({
                "kind": "unauthorized_overlay",
                "detail": format!("{} ({}): {reason}", kind.keyword(), path.display()),
                "sha256": sha256,
                "loaded_anyway": allowed,
                "at_boot": true,
            }),
        ),
    };
    let draft = AuditEntryDraft {
        op: op.to_string(),
        extra,
        key_fp: "agent-self".to_string(),
        cosigner_fps: Vec::new(),
        result: result.to_string(),
        client_pid: std::process::id(),
        client_uid: 0,
        client_comm: "northnarrow-agent".to_string(),
    };
    if let Err(e) = log.lock().append(draft) {
        warn!(error = format!("{e:#}"), "overlay gate: audit entry failed");
    }
}

/// Newest signature per kind already in the audit chain (accepted at a
/// boot or stored by `set`): `(sha256 hex, signed ts)`.
fn recorded_signatures(audit_log: &Path) -> HashMap<OverlayKind, (String, u64)> {
    let mut out: HashMap<OverlayKind, (String, u64)> = HashMap::new();
    let Ok(body) = std::fs::read_to_string(audit_log) else {
        return out;
    };
    for line in body.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let op = v.get("op").and_then(|o| o.as_str()).unwrap_or("");
        if (op != AUDIT_OP_ACCEPTED && op != AUDIT_OP_SET)
            || v.get("result").and_then(|r| r.as_str()) != Some("success")
        {
            continue;
        }
        let extra = &v["extra"];
        let (Some(kind), Some(sha), Some(ts)) = (
            extra
                .get("kind")
                .and_then(|k| k.as_str())
                .and_then(OverlayKind::from_keyword),
            extra.get("sha256").and_then(|s| s.as_str()),
            extra.get("signed_ts").and_then(|t| t.as_u64()),
        ) else {
            continue;
        };
        if out.get(&kind).map(|(_, t)| ts >= *t).unwrap_or(true) {
            out.insert(kind, (sha.to_string(), ts));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::wire::admin_signed_payload::sign;
    use ed25519_dalek::SigningKey;

    const AGENT: [u8; 16] = [3; 16];

    fn setup(roles: &str) -> (tempfile::TempDir, SigningKey, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[0x21; 32]);
        let pub_hex = hex(key.verifying_key().as_bytes());
        let admin_pub = dir.path().join("admin.pub");
        std::fs::write(&admin_pub, format!("{pub_hex} {roles}\n")).unwrap();
        let audit = dir.path().join("audit.log");
        (dir, key, admin_pub, audit)
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
        let (dir, key, admin_pub, audit) = setup("config-manage");
        let p = write_signed(
            dir.path(),
            &key,
            OverlayKind::ProcessCommAllowlist,
            "+backupd\n",
            100,
        );
        let gate = OverlayGate::new(&admin_pub, AGENT, &audit);
        match gate.check(OverlayKind::ProcessCommAllowlist, &p) {
            Decision::Accepted { new, signed_ts, .. } => assert!(new && signed_ts == 100),
            other => panic!("{other:?}"),
        }
        assert_eq!(gate.effective(OverlayKind::ProcessCommAllowlist, &p), p);
        std::fs::write(&p, "+backupd\n+evil-implant\n").unwrap();
        assert!(matches!(
            gate.check(OverlayKind::ProcessCommAllowlist, &p),
            Decision::Refused { .. }
        ));
        assert_eq!(
            gate.effective(OverlayKind::ProcessCommAllowlist, &p),
            PathBuf::from(EMPTY_OVERLAY)
        );
    }

    #[test]
    fn unsigned_wrong_kind_wrong_role_wrong_agent_are_refused() {
        let (dir, key, admin_pub, audit) = setup("unlock,audit-read");
        // wrong role
        let p = write_signed(
            dir.path(),
            &key,
            OverlayKind::NetflowCommAllowlist,
            "+x\n",
            1,
        );
        let gate = OverlayGate::new(&admin_pub, AGENT, &audit);
        assert!(
            matches!(gate.check(OverlayKind::NetflowCommAllowlist, &p), Decision::Refused { reason, .. } if reason.contains("rejected"))
        );
        // wrong kind: the signature names another overlay
        let (dir2, key2, admin_pub2, audit2) = setup("config-manage");
        let p2 = write_signed(dir2.path(), &key2, OverlayKind::FimPaths, "+/srv/app\n", 1);
        let gate2 = OverlayGate::new(&admin_pub2, AGENT, &audit2);
        assert!(
            matches!(gate2.check(OverlayKind::ProcessCommAllowlist, &p2), Decision::Refused { reason, .. } if reason.contains("fim-paths"))
        );
        // wrong agent: same files, another agent_id
        let gate3 = OverlayGate::new(&admin_pub2, [4; 16], &audit2);
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

    #[test]
    fn rollback_to_an_older_signature_is_refused() {
        let (dir, key, admin_pub, audit) = setup("config-manage");
        // the chain already accepted a signature made at ts 500
        std::fs::write(
            &audit,
            "{\"op\":\"config_overlay_accepted\",\"result\":\"success\",\"extra\":{\"kind\":\"process-comm-allowlist\",\"sha256\":\"aa\",\"signed_ts\":500}}\n",
        )
        .unwrap();
        let p = write_signed(
            dir.path(),
            &key,
            OverlayKind::ProcessCommAllowlist,
            "+old-exemption\n",
            400,
        );
        let gate = OverlayGate::new(&admin_pub, AGENT, &audit);
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

    #[test]
    fn content_validation_uses_the_loader_rules() {
        assert!(validate_content(OverlayKind::FimPaths, "+/etc/app.conf\n-/etc/motd\n").is_ok());
        assert!(validate_content(OverlayKind::FimPaths, "+relative/path\n").is_err());
        assert!(validate_content(OverlayKind::NetflowBlocklist, "+203.0.113.0/24\n").is_ok());
        assert!(validate_content(OverlayKind::NetflowJa3Blocklist, "+not-a-hash\n").is_err());
        assert!(validate_content(OverlayKind::MassWriteCarveout, "+/srv/build/\n").is_ok());
        assert!(validate_content(OverlayKind::MassWriteCarveout, "-/srv\n").is_err());
        assert!(
            validate_content(OverlayKind::ProcessCommAllowlist, "# comment\n+backupd\n").is_ok()
        );
    }
}
