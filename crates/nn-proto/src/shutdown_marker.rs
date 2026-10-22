//! The shutdown-authorisation marker (Tappa 8 A7, design §10.3) and its
//! verification by the watchdog (external audit WDG-001, EVD-021,
//! TST-003).
//!
//! When an admin quorum authorises a shutdown, the agent writes
//! `/run/northnarrow/agent.shutdown_authorised` and exits; the watchdog,
//! woken by the agent's pidfd, reads it to tell an authorised exit (stand
//! down, no respawn) from a death (respawn). The marker used to carry an
//! opaque hash and a deadline, and the watchdog checked only their shape:
//! any root process could write one and switch the agent off for good.
//!
//! The marker now carries what the admins signed — the payload's
//! canonical CBOR and the signatures — and [`verify`] checks it the way
//! the agent did, against `admin.pub`, whose private keys are not on the
//! host. A marker is honoured only when it is:
//!
//! - a shutdown for this install (`agent_id`), signed by
//!   [`SHUTDOWN_QUORUM`] distinct admin keys, one carrying `shutdown`,
//!   with no more than [`admin_quorum::MAX_SUBMITTED_SIGNATURES`]
//!   signatures (external audit AUT-005; the agent refuses more);
//! - recent: signed no later than [`MAX_SKEW_SECS`] ahead of the
//!   watchdog's clock, and acted on within the skew plus the requested
//!   grace (at most [`MAX_GRACE_SECS`]) after it was signed;
//! - signed while the agent that died was running (its start time);
//! - written by the agent that died (`agent_pid`);
//! - not honoured before: the watchdog keeps the nonces it honoured
//!   ([`honoured_line`], [`was_honoured`]).
//!
//! Anything else is a forgery or a replay: the watchdog respawns the agent
//! and reports it.

use alloc::{format, string::String, vec::Vec};
use core::fmt;

use serde::{Deserialize, Serialize};

use crate::admin_quorum::{self, AdminKey, QuorumDecision};
use crate::wire::admin_signed_payload::{
    decode_cbor, encode_cbor, signing_digest, OperationCode, OperationExtra, Role, SignedPayload,
    SignedPayloadError,
};

/// Where the agent leaves the marker (`RuntimeDirectory=northnarrow`,
/// mode 0700: root only).
pub const MARKER_PATH: &str = "/run/northnarrow/agent.shutdown_authorised";

/// Where the watchdog records the markers it refused, one JSON line each
/// ([`RejectedRecord`]), for the agent's signed audit chain at its next
/// start.
pub const REJECTED_PATH: &str = "/run/northnarrow/agent.shutdown_rejected";

/// The watchdog's record of the authorisations it honoured
/// ([`honoured_line`]).
pub const HONOURED_PATH: &str = "/run/northnarrow/watchdog.honoured";

/// Marker format written by this version of the agent.
pub const MARKER_VERSION: u32 = 2;

/// Distinct admin keys a shutdown needs (design §3.3, 2-of-N).
pub const SHUTDOWN_QUORUM: u8 = 2;

/// The agent accepts a signed payload within ±60 s of its clock
/// (`MAX_TIMESTAMP_SKEW_SECS`, design §6.4 layer 2).
pub const MAX_SKEW_SECS: u64 = 60;

/// Longest grace the watchdog grants between the signature and the
/// agent's exit, whatever the request asked for: the agent exits right
/// after it replies.
pub const MAX_GRACE_SECS: u64 = 300;

/// What the agent leaves for the watchdog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShutdownMarker {
    /// [`MARKER_VERSION`].
    pub version: u32,
    /// Hex of the signed payload's canonical CBOR.
    pub payload: String,
    /// Hex of each 64-byte signature, as submitted.
    pub signatures: Vec<String>,
    /// The pid of the agent that verified the request and is exiting.
    pub agent_pid: u32,
}

impl ShutdownMarker {
    pub fn new(
        payload: &SignedPayload,
        signatures: &[[u8; 64]],
        agent_pid: u32,
    ) -> Result<Self, SignedPayloadError> {
        Ok(Self {
            version: MARKER_VERSION,
            payload: hex::encode(encode_cbor(payload)?),
            signatures: signatures.iter().map(hex::encode).collect(),
            agent_pid,
        })
    }

    /// The marker as the single JSON line the agent writes.
    pub fn to_line(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Parse the marker file's content.
    pub fn parse(raw: &str) -> Result<Self, Rejection> {
        serde_json::from_str(raw.trim())
            .map_err(|e| Rejection::Malformed(format!("not a v{MARKER_VERSION} marker: {e}")))
    }
}

/// What the watchdog knows about the agent that died.
#[derive(Debug, Clone)]
pub struct Expectation<'a> {
    /// `admin.pub`.
    pub keys: &'a [AdminKey],
    /// `/etc/northnarrow/agent_id`.
    pub agent_id: [u8; 16],
    /// The pid the watchdog saw exit.
    pub agent_pid: u32,
    /// When that process started (unix seconds), when known.
    pub agent_started: Option<u64>,
    /// The watchdog's clock (unix seconds).
    pub now: u64,
}

/// A verified authorisation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorised {
    pub nonce: [u8; 32],
    pub ts: u64,
    pub grace_secs: u64,
    /// Indices into the key set of the keys that signed.
    pub signers: Vec<usize>,
}

/// Why a marker was not honoured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejection {
    Malformed(String),
    UnsupportedVersion(u32),
    NotAShutdown,
    OtherAgent,
    WrongPid {
        marker: u32,
        died: u32,
    },
    SignedBeforeAgentStarted {
        ts: u64,
        started: u64,
    },
    FromTheFuture {
        ts: u64,
        now: u64,
    },
    Expired {
        ts: u64,
        now: u64,
        grace_secs: u64,
    },
    Quorum(QuorumDecision),
    /// External audit AUT-005: this many signatures, more than
    /// [`admin_quorum::MAX_SUBMITTED_SIGNATURES`]; none was checked.
    TooManySignatures(usize),
    Replayed,
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Rejection::Malformed(m) => write!(f, "malformed marker: {m}"),
            Rejection::UnsupportedVersion(v) => write!(f, "marker version {v} is not supported"),
            Rejection::NotAShutdown => write!(f, "the signed payload is not a shutdown"),
            Rejection::OtherAgent => write!(f, "the shutdown was signed for another install"),
            Rejection::WrongPid { marker, died } => write!(
                f,
                "the marker names agent pid {marker}, but pid {died} is the one that exited"
            ),
            Rejection::SignedBeforeAgentStarted { ts, started } => write!(
                f,
                "signed at {ts}, before the agent that exited started ({started})"
            ),
            Rejection::FromTheFuture { ts, now } => {
                write!(f, "signed at {ts}, ahead of the watchdog's clock ({now})")
            }
            Rejection::Expired {
                ts,
                now,
                grace_secs,
            } => write!(
                f,
                "signed at {ts}, too long before the exit ({now}; skew {MAX_SKEW_SECS} s + grace {grace_secs} s)"
            ),
            Rejection::Quorum(d) => write!(f, "the admin signatures do not authorise it ({d:?})"),
            Rejection::TooManySignatures(submitted) => write!(
                f,
                "the marker carries {submitted} signatures, at most {} are accepted",
                admin_quorum::MAX_SUBMITTED_SIGNATURES
            ),
            Rejection::Replayed => write!(f, "this authorisation was already honoured (replay)"),
        }
    }
}

/// Verify `marker` against `exp`. `honoured` answers whether a nonce was
/// honoured before ([`was_honoured`] over the watchdog's record).
pub fn verify(
    marker: &ShutdownMarker,
    exp: &Expectation<'_>,
    honoured: impl Fn(&[u8; 32]) -> bool,
) -> Result<Authorised, Rejection> {
    if marker.version != MARKER_VERSION {
        return Err(Rejection::UnsupportedVersion(marker.version));
    }
    // External audit AUT-005: bounded before anything is decoded or checked.
    admin_quorum::check_submission_size(marker.signatures.len())
        .map_err(|e| Rejection::TooManySignatures(e.submitted))?;
    let cbor = hex::decode(&marker.payload)
        .map_err(|e| Rejection::Malformed(format!("payload is not hex: {e}")))?;
    let payload =
        decode_cbor(&cbor).map_err(|e| Rejection::Malformed(format!("payload: {e:?}")))?;
    let mut signatures: Vec<[u8; 64]> = Vec::with_capacity(marker.signatures.len());
    for s in &marker.signatures {
        let raw = hex::decode(s).map_err(|e| Rejection::Malformed(format!("signature: {e}")))?;
        let sig: [u8; 64] = raw
            .try_into()
            .map_err(|_| Rejection::Malformed(String::from("signature is not 64 bytes")))?;
        signatures.push(sig);
    }
    let grace_secs = match (&payload.op, &payload.extra) {
        (OperationCode::Shutdown, OperationExtra::Shutdown(s)) => {
            u64::from(s.grace_secs).min(MAX_GRACE_SECS)
        }
        _ => return Err(Rejection::NotAShutdown),
    };
    if payload.agent_id != exp.agent_id {
        return Err(Rejection::OtherAgent);
    }
    if marker.agent_pid != exp.agent_pid {
        return Err(Rejection::WrongPid {
            marker: marker.agent_pid,
            died: exp.agent_pid,
        });
    }
    let ts = payload.ts;
    if ts > exp.now.saturating_add(MAX_SKEW_SECS) {
        return Err(Rejection::FromTheFuture { ts, now: exp.now });
    }
    if exp.now > ts.saturating_add(MAX_SKEW_SECS + grace_secs) {
        return Err(Rejection::Expired {
            ts,
            now: exp.now,
            grace_secs,
        });
    }
    if let Some(started) = exp.agent_started {
        if ts.saturating_add(MAX_SKEW_SECS) < started {
            return Err(Rejection::SignedBeforeAgentStarted { ts, started });
        }
    }
    // The signatures cover the digest of the payload's canonical encoding,
    // recomputed from the decoded values: no byte of the marker's own
    // encoding is trusted.
    let digest =
        signing_digest(&payload).map_err(|e| Rejection::Malformed(format!("digest: {e:?}")))?;
    let per_signature = admin_quorum::match_signatures(exp.keys, &digest, &signatures)
        .map_err(|e| Rejection::TooManySignatures(e.submitted))?;
    match admin_quorum::quorum_decision(
        &per_signature,
        |idx, role| exp.keys[idx].authorizes(role),
        SHUTDOWN_QUORUM,
        &[Role::Shutdown],
    ) {
        QuorumDecision::Accept => {}
        other => return Err(Rejection::Quorum(other)),
    }
    if honoured(&payload.nonce) {
        return Err(Rejection::Replayed);
    }
    Ok(Authorised {
        nonce: payload.nonce,
        ts,
        grace_secs,
        signers: admin_quorum::distinct_matches(&per_signature),
    })
}

/// One marker the watchdog refused, as it records it at [`REJECTED_PATH`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectedRecord {
    /// Unix seconds of the refusal.
    pub at: u64,
    /// The pid of the agent that exited.
    pub agent_pid: u32,
    /// [`Rejection`]'s text.
    pub reason: String,
    /// SHA-256 of the marker file as found (hex).
    pub sha256: String,
}

/// SHA-256 (hex) of a marker file as found, for [`RejectedRecord`].
pub fn marker_sha256(raw: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(raw))
}

/// Parse `/etc/northnarrow/agent_id`: 32 hex characters and an
/// optional single trailing newline (the format `agent_id.rs` writes).
pub fn parse_agent_id(raw: &str) -> Result<[u8; 16], String> {
    let trimmed = raw.strip_suffix('\n').unwrap_or(raw);
    if trimmed.contains('\n') || trimmed.contains('\r') {
        return Err(String::from(
            "agent_id file has embedded newline — expected single-line hex",
        ));
    }
    if trimmed.len() != 32 {
        return Err(format!(
            "agent_id has {} hex chars (expected 32)",
            trimmed.len()
        ));
    }
    let bytes = hex::decode(trimmed).map_err(|e| format!("agent_id is not valid hex: {e}"))?;
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// The line the watchdog appends to its record of honoured shutdowns.
pub fn honoured_line(a: &Authorised) -> String {
    format!("{} {}\n", hex::encode(a.nonce), a.ts)
}

/// Whether `record` (lines of [`honoured_line`]) holds `nonce`.
pub fn was_honoured(record: &str, nonce: &[u8; 32]) -> bool {
    let hex_nonce = hex::encode(nonce);
    record
        .lines()
        .any(|l| l.split_whitespace().next() == Some(hex_nonce.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::admin_signed_payload::sign;
    use ed25519_dalek::SigningKey;

    const AGENT: [u8; 16] = [7; 16];
    const NOW: u64 = 1_800_000_000;

    struct Admins {
        sks: Vec<SigningKey>,
        keys: Vec<AdminKey>,
    }

    fn admins() -> Admins {
        let roles = [
            alloc::vec![Role::Shutdown],
            alloc::vec![Role::Unlock],
            alloc::vec![Role::Unlock],
        ];
        let sks: Vec<SigningKey> = (1..=3u8)
            .map(|s| SigningKey::from_bytes(&[s; 32]))
            .collect();
        let keys = sks
            .iter()
            .zip(roles)
            .map(|(sk, roles)| AdminKey {
                key: sk.verifying_key(),
                roles,
            })
            .collect();
        Admins { sks, keys }
    }

    fn signed(payload: &SignedPayload, by: &[&SigningKey], pid: u32) -> ShutdownMarker {
        let sigs: Vec<[u8; 64]> = by.iter().map(|sk| sign(payload, sk).unwrap()).collect();
        ShutdownMarker::new(payload, &sigs, pid).unwrap()
    }

    fn exp(keys: &[AdminKey]) -> Expectation<'_> {
        Expectation {
            keys,
            agent_id: AGENT,
            agent_pid: 4242,
            agent_started: Some(NOW - 3600),
            now: NOW,
        }
    }

    fn shutdown(ts: u64, grace: u32) -> SignedPayload {
        SignedPayload::new_shutdown([9; 32], ts, AGENT, grace)
    }

    #[test]
    fn agent_id_parses_as_the_agent_writes_it() {
        assert_eq!(parse_agent_id(&format!("{}\n", "07".repeat(16))), Ok(AGENT));
        assert!(parse_agent_id(&"07".repeat(16)).is_ok());
        assert!(parse_agent_id(&format!("{}\n\n", "07".repeat(16))).is_err());
        assert!(parse_agent_id("zz").is_err());
        assert_eq!(marker_sha256(b"").len(), 64);
    }

    #[test]
    fn a_quorum_signed_shutdown_by_the_agent_that_died_is_honoured() {
        let a = admins();
        let m = signed(&shutdown(NOW - 5, 30), &[&a.sks[0], &a.sks[1]], 4242);
        let m = ShutdownMarker::parse(&m.to_line()).unwrap();
        let ok = verify(&m, &exp(&a.keys), |_| false).unwrap();
        assert_eq!(ok.nonce, [9; 32]);
        assert_eq!(ok.signers, alloc::vec![0, 1]);
        let line = honoured_line(&ok);
        assert!(was_honoured(&line, &[9; 32]));
        assert!(!was_honoured(&line, &[8; 32]));
    }

    #[test]
    fn what_a_root_process_can_write_is_refused() {
        let a = admins();
        let e = exp(&a.keys);
        // the old marker shape
        assert!(matches!(
            ShutdownMarker::parse(r#"{"entry_hash":"00","grace_deadline_unix_ts":99999999999}"#),
            Err(Rejection::Malformed(_))
        ));
        // signed by keys that are not admins
        let strangers: Vec<SigningKey> = (8..=9u8)
            .map(|s| SigningKey::from_bytes(&[s; 32]))
            .collect();
        let m = signed(&shutdown(NOW, 30), &[&strangers[0], &strangers[1]], 4242);
        assert_eq!(
            verify(&m, &e, |_| false),
            Err(Rejection::Quorum(QuorumDecision::NoValidSignature))
        );
        // one admin twice, and two admins without the shutdown role
        let m = signed(&shutdown(NOW, 30), &[&a.sks[0], &a.sks[0]], 4242);
        assert!(matches!(
            verify(&m, &e, |_| false),
            Err(Rejection::Quorum(QuorumDecision::QuorumNotMet { .. }))
        ));
        let m = signed(&shutdown(NOW, 30), &[&a.sks[1], &a.sks[2]], 4242);
        assert!(matches!(
            verify(&m, &e, |_| false),
            Err(Rejection::Quorum(QuorumDecision::RoleDenied { .. }))
        ));
        // a genuine marker with its payload edited (longer grace)
        let mut m = signed(&shutdown(NOW, 30), &[&a.sks[0], &a.sks[1]], 4242);
        m.payload = hex::encode(encode_cbor(&shutdown(NOW, 300)).unwrap());
        assert!(matches!(
            verify(&m, &e, |_| false),
            Err(Rejection::Quorum(QuorumDecision::NoValidSignature))
        ));
    }

    #[test]
    fn a_genuine_authorisation_cannot_be_reused() {
        let a = admins();
        let e = exp(&a.keys);
        let by = [&a.sks[0], &a.sks[1]];
        // honoured once already
        let m = signed(&shutdown(NOW, 30), &by, 4242);
        assert_eq!(verify(&m, &e, |_| true), Err(Rejection::Replayed));
        // moved onto another agent's pid
        let m = signed(&shutdown(NOW, 30), &by, 777);
        assert!(matches!(
            verify(&m, &e, |_| false),
            Err(Rejection::WrongPid { .. })
        ));
        // signed before the agent that died started
        let m = signed(&shutdown(NOW - 7200, 300), &by, 4242);
        let late = Expectation {
            now: NOW - 7000,
            ..exp(&a.keys)
        };
        assert!(matches!(
            verify(&m, &late, |_| false),
            Err(Rejection::SignedBeforeAgentStarted { .. })
        ));
        // too old, and the grace is capped whatever was signed
        let m = signed(&shutdown(NOW - 3600, u32::MAX), &by, 4242);
        assert!(matches!(
            verify(&m, &e, |_| false),
            Err(Rejection::Expired { .. })
        ));
        let m = signed(&shutdown(NOW - (MAX_SKEW_SECS + 31), 30), &by, 4242);
        assert!(matches!(
            verify(&m, &e, |_| false),
            Err(Rejection::Expired { .. })
        ));
        let m = signed(&shutdown(NOW - (MAX_SKEW_SECS + 29), 30), &by, 4242);
        assert!(verify(&m, &e, |_| false).is_ok(), "inside skew + grace");
        // from the future, for another install, not a shutdown
        let m = signed(&shutdown(NOW + 600, 30), &by, 4242);
        assert!(matches!(
            verify(&m, &e, |_| false),
            Err(Rejection::FromTheFuture { .. })
        ));
        let other = SignedPayload::new_shutdown([9; 32], NOW, [1; 16], 30);
        let m = signed(&other, &by, 4242);
        assert_eq!(verify(&m, &e, |_| false), Err(Rejection::OtherAgent));
        let unlock = SignedPayload::new_unlock([9; 32], NOW, AGENT);
        let m = signed(&unlock, &by, 4242);
        assert_eq!(verify(&m, &e, |_| false), Err(Rejection::NotAShutdown));
    }

    /// External audit AUT-005 / AUT-001: a marker is judged as the agent
    /// judges the request — at most `MAX_SUBMITTED_SIGNATURES` signatures,
    /// refused before any is decoded, and a shutdown `op` carrying another
    /// operation's `extra` is not a shutdown.
    #[test]
    fn oversized_or_mismatched_markers_are_refused() {
        use crate::wire::admin_signed_payload::{OperationExtra, UnlockExtra};
        let a = admins();
        let e = exp(&a.keys);
        let payload = shutdown(NOW, 30);
        let two = [
            sign(&payload, &a.sks[0]).unwrap(),
            sign(&payload, &a.sks[1]).unwrap(),
        ];
        let at_cap: Vec<[u8; 64]> = two
            .iter()
            .cycle()
            .take(admin_quorum::MAX_SUBMITTED_SIGNATURES)
            .copied()
            .collect();
        let m = ShutdownMarker::new(&payload, &at_cap, 4242).unwrap();
        assert!(
            verify(&m, &e, |_| false).is_ok(),
            "the cap itself is accepted"
        );
        let mut over = at_cap.clone();
        over.push(two[0]);
        let m = ShutdownMarker::new(&payload, &over, 4242).unwrap();
        assert_eq!(
            verify(&m, &e, |_| false),
            Err(Rejection::TooManySignatures(
                admin_quorum::MAX_SUBMITTED_SIGNATURES + 1
            ))
        );
        let mut garbage = m.clone();
        garbage.signatures = alloc::vec![String::from("zz"); 1000];
        assert_eq!(
            verify(&garbage, &e, |_| false),
            Err(Rejection::TooManySignatures(1000))
        );
        assert!(Rejection::TooManySignatures(17)
            .to_string()
            .contains("at most 8"));
        let mismatched = SignedPayload {
            extra: OperationExtra::Unlock(UnlockExtra {}),
            ..payload
        };
        let m = signed(&mismatched, &[&a.sks[0], &a.sks[1]], 4242);
        assert_eq!(verify(&m, &e, |_| false), Err(Rejection::NotAShutdown));
    }
}
