//! The admin key set and the quorum rule (Tappa 8 A5/A6), shared by the
//! agent and the watchdog.
//!
//! `/etc/northnarrow/admin.pub` holds one Ed25519 key per line with the
//! roles it carries: `<hex64-pubkey> [<role,role,...>]`. The agent
//! verifies every signed admin operation against it. Since external audit
//! WDG-001 the watchdog verifies the shutdown quorum the same way before
//! it stands down (`crate::shutdown_marker`), so the parser and the rule
//! live here once.

use alloc::{format, string::String, vec, vec::Vec};

use ed25519_dalek::{Signature, VerifyingKey};

use crate::wire::admin_signed_payload::Role;

/// Hex length of an Ed25519 public key (32 bytes × 2 nibbles).
pub const PUBKEY_HEX_LEN: usize = 64;

/// One `admin.pub` line: a key and the operations its operator may
/// authorise.
#[derive(Debug, Clone)]
pub struct AdminKey {
    pub key: VerifyingKey,
    pub roles: Vec<Role>,
}

impl AdminKey {
    /// `true` iff the key may authorise an operation whose required
    /// role is `required`. [`Role::All`] is the break-glass super-role
    /// and satisfies any required role (design §3.2 "break-glass key
    /// (kept offline)" pattern).
    ///
    /// Tappa 9.0.c role gradient: [`Role::Triage`] SUBSUMES
    /// [`Role::TelemetryRead`] — a triage key can read the detections it
    /// triages. The subsumption is one-directional (read does NOT imply
    /// triage).
    pub fn authorizes(&self, required: Role) -> bool {
        self.roles.iter().any(|r| {
            *r == required
                || *r == Role::All
                || (required == Role::TelemetryRead && *r == Role::Triage)
        })
    }
}

/// Roles of an `admin.pub` line that omits the role token: `unlock` (the
/// legacy baseline — every key could unlock before A5) and `audit-read`
/// (design §3.2 "on-call minimum").
pub fn default_roles() -> Vec<Role> {
    vec![Role::Unlock, Role::AuditRead]
}

/// Parse a whole `admin.pub`: blank lines and `#` comments skipped, every
/// other line a key ([`parse_admin_line`]). An error names the line.
pub fn parse_admin_pub(content: &str) -> Result<Vec<AdminKey>, String> {
    let mut keys = Vec::new();
    for (idx, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        keys.push(parse_admin_line(line).map_err(|e| format!("line {}: {e}", idx + 1))?);
    }
    Ok(keys)
}

/// External audit AUT-004: an `admin.pub` read key by key — what
/// [`parse_admin_pub_lenient`] returns.
#[derive(Debug, Default)]
pub struct AdminPubParse {
    /// The keys of the lines that parse.
    pub keys: Vec<AdminKey>,
    /// `(line number, reason)` of each line that does not.
    pub skipped: Vec<(usize, String)>,
}

/// Parse `admin.pub` keeping every line that parses and naming the others.
/// One malformed line used to refuse the whole file — the agent then ran
/// without its admin socket, the watchdog without a key to verify a
/// shutdown with. Skipping a line never adds authority: it only loses the
/// key that line would have held.
pub fn parse_admin_pub_lenient(content: &str) -> AdminPubParse {
    let mut out = AdminPubParse::default();
    for (idx, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_admin_line(line) {
            Ok(k) => out.keys.push(k),
            Err(e) => out.skipped.push((idx + 1, e)),
        }
    }
    out
}

/// Parse one already-trimmed, non-comment, non-blank `admin.pub` line.
/// Whitespace-tokenised: the first token is the hex public key, the
/// optional second token the comma-separated role list. A third token is
/// an error (catches the common operator mistake of forgetting the comma
/// between roles, e.g. `<hex>  unlock audit-read`).
pub fn parse_admin_line(line: &str) -> Result<AdminKey, String> {
    let mut parts = line.split_whitespace();
    let hex_token = parts
        .next()
        .ok_or_else(|| String::from("line is empty after trimming (should have been skipped)"))?;
    if hex_token.len() != PUBKEY_HEX_LEN {
        return Err(format!(
            "pub key must be {PUBKEY_HEX_LEN} hex chars (got {})",
            hex_token.len()
        ));
    }
    let raw = hex::decode(hex_token).map_err(|e| format!("invalid hex: {e}"))?;
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&raw);
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| format!("not a valid Ed25519 pubkey: {e}"))?;
    let roles = match parts.next() {
        None => default_roles(),
        Some(role_list) => parse_role_list(role_list)?,
    };
    if parts.next().is_some() {
        return Err(String::from(
            "unexpected token after role list — roles must be \
             comma-separated within a single token (no spaces)",
        ));
    }
    Ok(AdminKey { key, roles })
}

/// Parse a comma-separated role list (e.g. `"unlock,audit-read"`). An
/// empty list, or an empty entry (leading, trailing or double comma), is
/// an error — the canonical writer emits a tight list. Duplicates are
/// dropped.
pub fn parse_role_list(s: &str) -> Result<Vec<Role>, String> {
    if s.is_empty() {
        return Err(String::from("role list is empty"));
    }
    let mut out: Vec<Role> = Vec::new();
    for token in s.split(',') {
        if token.is_empty() {
            return Err(String::from(
                "role list has empty entry (leading/trailing/double comma)",
            ));
        }
        let role = parse_role_keyword(token)?;
        if !out.contains(&role) {
            out.push(role);
        }
    }
    Ok(out)
}

/// Parse one role keyword as written in `admin.pub`.
pub fn parse_role_keyword(s: &str) -> Result<Role, String> {
    Ok(match s {
        "unlock" => Role::Unlock,
        "shutdown" => Role::Shutdown,
        "force-posture" => Role::ForcePosture,
        "rotate-keys" => Role::RotateKeys,
        "audit-read" => Role::AuditRead,
        "fim-manage" => Role::FimManage,
        "fim-read" => Role::FimRead,
        "canary-read" => Role::CanaryRead,
        "canary-manage" => Role::CanaryManage,
        // Tappa 10 (N1) — network observability split-role pair.
        "net-read" => Role::NetRead,
        "net-manage" => Role::NetManage,
        "trusted-installer" => Role::TrustedInstaller,
        // Tappa 9.0.b — low-privilege read-only telemetry role.
        "telemetry-read" => Role::TelemetryRead,
        // Tappa 9.0.c — triage role (subsumes telemetry-read).
        "triage" => Role::Triage,
        // Tappa 10.8 — signed operator overlays.
        "config-manage" => Role::ConfigManage,
        // External audit CMB-016 — undo a response (release, restore).
        "response-manage" => Role::ResponseManage,
        "all" => Role::All,
        other => {
            return Err(format!(
                "unknown role `{other}` — expected one of: \
                 unlock, shutdown, force-posture, rotate-keys, audit-read, \
                 fim-manage, fim-read, canary-read, canary-manage, \
                 net-read, net-manage, trusted-installer, telemetry-read, \
                 triage, config-manage, response-manage, all"
            ))
        }
    })
}

/// Which key each of `signatures` verifies against over `message` (`None`:
/// no key), with `verify_strict`. Every signature is checked against
/// every key with no early exit, so the cost is `signatures × keys`
/// whichever signatures verify; a signature matching two keys (the same
/// key listed twice) keeps the last.
pub fn match_signatures(
    keys: &[AdminKey],
    message: &[u8],
    signatures: &[[u8; 64]],
) -> Vec<Option<usize>> {
    signatures
        .iter()
        .map(|sig_bytes| {
            let sig = Signature::from_bytes(sig_bytes);
            let mut this_match: Option<usize> = None;
            for (idx, entry) in keys.iter().enumerate() {
                if entry.key.verify_strict(message, &sig).is_ok() {
                    this_match = Some(idx);
                }
            }
            this_match
        })
        .collect()
}

/// Outcome of [`quorum_decision`]: the distinct-key tally, threshold and
/// role check of a multi-signature submission, with the cryptography
/// already done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuorumDecision {
    Accept,
    /// A non-empty submission in which no signature matched any key —
    /// the attack signal (rate-limited by the agent).
    NoValidSignature,
    QuorumNotMet {
        required: u8,
        provided: u8,
    },
    /// `role` is carried by no matched key; `first` is the first matched
    /// key in submission order (the audit breadcrumb).
    RoleDenied {
        role: Role,
        first: usize,
    },
}

/// The quorum rule, separated from the signature checks so it can be
/// proved (Kani, `kani_proofs` below).
///
/// `per_signature[i]` is the index of the key the i-th signature verified
/// against (`None`: no key). A key counts once however many of its
/// signatures were submitted. Accepts only when at least
/// `max(min_distinct, 1)` distinct keys matched and every role in
/// `role_requirements` is carried by one of them: a `min_distinct` of 0
/// never accepts a submission without a signature. Allocation-free.
pub fn quorum_decision(
    per_signature: &[Option<usize>],
    authorizes: impl Fn(usize, Role) -> bool,
    min_distinct: u8,
    role_requirements: &[Role],
) -> QuorumDecision {
    let first_seen = |i: usize| match per_signature[i] {
        Some(key) => !per_signature[..i].contains(&Some(key)),
        None => false,
    };
    let distinct = (0..per_signature.len()).filter(|&i| first_seen(i)).count();
    if distinct == 0 && !per_signature.is_empty() {
        return QuorumDecision::NoValidSignature;
    }
    let provided = distinct.min(u8::MAX as usize) as u8;
    let required = min_distinct.max(1);
    if provided < required {
        return QuorumDecision::QuorumNotMet { required, provided };
    }
    for &role in role_requirements {
        if !per_signature
            .iter()
            .flatten()
            .any(|&key| authorizes(key, role))
        {
            let first = per_signature.iter().flatten().next().copied().unwrap_or(0);
            return QuorumDecision::RoleDenied { role, first };
        }
    }
    QuorumDecision::Accept
}

/// Distinct matched key indices in first-seen order (audit fingerprints).
pub fn distinct_matches(per_signature: &[Option<usize>]) -> Vec<usize> {
    let mut out: Vec<usize> = Vec::new();
    for key in per_signature.iter().flatten() {
        if !out.contains(key) {
            out.push(*key);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// External audit AUT-004: lines 2 and 6 parse; line 3 (65 hex chars)
    /// and line 5 (roles not comma-separated) are named, not fatal.
    #[test]
    fn parse_admin_pub_reports_skipped_lines_and_keeps_the_rest() {
        let k = |b: u8| {
            let sk = SigningKey::from_bytes(&[b; 32]);
            hex::encode(sk.verifying_key().to_bytes())
        };
        let content = format!(
            "# admins\n{} unlock,audit-read\n{}x unlock\n\n{} unlock audit-read\n{}\n",
            k(1),
            k(2),
            k(3),
            k(4)
        );
        let p = parse_admin_pub_lenient(&content);
        assert_eq!(p.keys.len(), 2);
        assert_eq!(
            p.skipped.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
            vec![3, 5]
        );
    }

    fn key(seed: u8, roles: &[Role]) -> (SigningKey, AdminKey) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let entry = AdminKey {
            key: sk.verifying_key(),
            roles: roles.to_vec(),
        };
        (sk, entry)
    }

    #[test]
    fn parse_admin_pub_reads_keys_roles_and_names_the_bad_line() {
        let a = hex::encode(SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes());
        let b = hex::encode(SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes());
        let keys = parse_admin_pub(&format!("# admins\n\n{a}\n{b} shutdown,all\n")).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].roles, default_roles());
        assert_eq!(keys[1].roles, vec![Role::Shutdown, Role::All]);
        let err = parse_admin_pub(&format!("{a}\n{b} shutdown audit-read\n")).unwrap_err();
        assert!(err.starts_with("line 2:"), "{err}");
        assert!(parse_role_list("unlock,,shutdown").is_err());
        assert!(parse_role_keyword("root").is_err());
    }

    #[test]
    fn match_signatures_finds_each_signer() {
        let (sk1, k1) = key(1, &[Role::Shutdown]);
        let (sk2, k2) = key(2, &[Role::Unlock]);
        let (sk3, _) = key(3, &[]);
        let msg = b"digest";
        let sigs = [
            sk2.sign(msg).to_bytes(),
            sk3.sign(msg).to_bytes(),
            sk1.sign(msg).to_bytes(),
            sk1.sign(b"other").to_bytes(),
        ];
        let m = match_signatures(&[k1, k2], msg, &sigs);
        assert_eq!(m, vec![Some(1), None, Some(0), None]);
    }

    #[test]
    fn quorum_counts_distinct_keys_and_required_roles() {
        let carries = |k: usize, r: Role| (k == 0 && r == Role::Shutdown) || r == Role::Unlock;
        assert_eq!(
            quorum_decision(&[Some(0), Some(1)], carries, 2, &[Role::Shutdown]),
            QuorumDecision::Accept
        );
        assert_eq!(
            quorum_decision(&[Some(0), Some(0)], carries, 2, &[Role::Shutdown]),
            QuorumDecision::QuorumNotMet {
                required: 2,
                provided: 1
            }
        );
        assert_eq!(
            quorum_decision(&[Some(1), Some(2)], carries, 2, &[Role::Shutdown]),
            QuorumDecision::RoleDenied {
                role: Role::Shutdown,
                first: 1
            }
        );
        assert_eq!(
            quorum_decision(&[None, None], carries, 2, &[]),
            QuorumDecision::NoValidSignature
        );
        assert_eq!(
            quorum_decision(&[], carries, 0, &[]),
            QuorumDecision::QuorumNotMet {
                required: 1,
                provided: 0
            }
        );
    }
}

/// Kani proof of the quorum rule (`.github/workflows/kani.yml`). The
/// signature checks are abstracted away: any key index (or none) for each
/// submitted signature, any role assignment for each key.
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    const SIGS: usize = 4;
    const KEYS: usize = 3;
    const ROLES: [Role; 2] = [Role::Unlock, Role::TrustedInstaller];

    #[kani::proof]
    #[kani::unwind(6)]
    fn quorum_accepts_only_enough_distinct_keys_carrying_every_role() {
        let n: usize = kani::any();
        kani::assume(n <= SIGS);
        let mut per_sig = [None; SIGS];
        for slot in per_sig.iter_mut() {
            let m: Option<u8> = kani::any();
            *slot = m.map(|k| (k as usize) % KEYS);
        }
        let per_sig = &per_sig[..n];
        let carries: [[bool; 2]; KEYS] = kani::any();
        let role_index = |r: Role| if r == ROLES[0] { 0 } else { 1 };
        let min_distinct: u8 = kani::any();
        let req_n: usize = kani::any();
        kani::assume(req_n <= 2);
        let reqs = &ROLES[..req_n];

        let decision = quorum_decision(
            per_sig,
            |k, r| carries[k][role_index(r)],
            min_distinct,
            reqs,
        );

        // Ground truth, computed per key rather than per signature.
        let mut distinct = 0u8;
        let mut matched = [false; KEYS];
        for (k, m) in matched.iter_mut().enumerate() {
            *m = per_sig.contains(&Some(k));
            if *m {
                distinct += 1;
            }
        }
        match decision {
            QuorumDecision::Accept => {
                assert!(distinct >= min_distinct.max(1));
                for &r in reqs {
                    assert!((0..KEYS).any(|k| matched[k] && carries[k][role_index(r)]));
                }
            }
            QuorumDecision::NoValidSignature => {
                assert!(n > 0 && distinct == 0);
            }
            QuorumDecision::QuorumNotMet { required, provided } => {
                assert!(provided == distinct && provided < required);
                assert!(required == min_distinct.max(1));
            }
            QuorumDecision::RoleDenied { role, first } => {
                assert!(matched[first]);
                assert!(!(0..KEYS).any(|k| matched[k] && carries[k][role_index(role)]));
            }
        }
    }
}
