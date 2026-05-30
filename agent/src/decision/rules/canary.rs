//! Tappa 9.5 (K5) — canary detection rules NN-L-CANARY-001..004.
//!
//! Four rules, one per canary type. All Critical-always, all
//! `KillProcessTree`, all transitioning posture to COMBAT
//! (handled by the posture state machine on Critical-severity
//! verdicts via the Tappa 7 task 7 autonomous-iptables-drop
//! pathway). NEVER throttled by any rate-limiter (the zero-FP
//! contract — a real canary trip is, by construction, infrequent;
//! storm-protection trumps would be a categorical mistake).
//!
//! ## Zero-FP contract (design §3 + §6)
//!
//! Every `Event::CanaryTripped` reaching the rule engine has
//! already been filtered by the K3 detector against the K2
//! registry. By construction:
//!
//! 1. The detector observed an access to a deployed canary's
//!    inode / exe path / port.
//! 2. The Registry::mark_tripped + access-log append already
//!    fired (the chain captures every access regardless of
//!    rule outcome, per K3's "chain always, rule sometimes"
//!    invariant — §12 Q2 single-trip lock-in).
//! 3. The rule layer's job is to drive the deterministic
//!    response (KillProcessTree + posture→COMBAT). NO
//!    additional filtering — that would weaken the zero-FP
//!    contract.
//!
//! Each rule is functionally near-identical (same severity,
//! same action, same posture transition); the distinct
//! `rule_id` exists so:
//!
//! 1. The audit chain row distinguishes canary types for
//!    operator triage (`grep canary_type=Credential`).
//! 2. Future per-type response-action diversification (V1.1:
//!    credential canary trip → also rotate cloud control-plane
//!    keys; file canary trip → also snapshot the host's
//!    process tree for forensics).
//! 3. ADE prompt variation per type (Credential trips get the
//!    richest enrichment; Network trips get the connecting
//!    peer's IP + Tappa 10 JA3 fingerprint when wired).
//!
//! ## Source-event filter
//!
//! The K3 detector emits `Event::CanaryTripped` and replaces
//! the source `Event::Fim` / `Event::ProcessSpawn` in
//! main::process_event BEFORE the rule engine sees it.
//! Consequence: the K5 rules NEVER see the source events —
//! they consume only `Event::CanaryTripped`. The K2/K9 FIM
//! rules see the ORIGINAL `Event::Fim` only when the detector
//! returned `None` (no matching canary).

use common::{CanaryAccessKind, CanaryTypeTag, Event, ResponseAction, Severity, Verdict};

use crate::decision::Rule;

// ── helpers ────────────────────────────────────────────────────────

/// Extract the [`Event::CanaryTripped`] fields from an `Event`
/// or return `None`. All K5 rules call this first + then check
/// `canary_type` for their per-type dispatch.
fn as_canary(e: &Event) -> Option<CanaryView<'_>> {
    match e {
        Event::CanaryTripped {
            canary_id,
            canary_name,
            canary_type,
            access_kind,
            accessor_pid,
            accessor_uid,
            accessor_comm,
            accessor_exe,
            timestamp_ns,
        } => Some(CanaryView {
            canary_id,
            canary_name,
            canary_type: *canary_type,
            access_kind: *access_kind,
            accessor_pid: *accessor_pid,
            accessor_uid: *accessor_uid,
            accessor_comm,
            accessor_exe: accessor_exe.as_deref(),
            timestamp_ns: *timestamp_ns,
        }),
        _ => None,
    }
}

/// Borrowed projection of `Event::CanaryTripped` — keeps the
/// rule evaluate() body free of repeated field destructuring.
///
/// `canary_id` + `accessor_uid` + `accessor_comm` + `accessor_exe`
/// aren't read by the K5 rules' verdict construction (the rules
/// drive the deterministic response; the audit-chain already
/// captures the full event via K3's `CanaryAccessEntry`), but
/// they're retained on the view so future rule extensions
/// (V1.1+: per-cred-family allowlist of comms that legitimately
/// read canaries during a planned IR exercise) don't need to
/// re-plumb the destructure.
#[allow(dead_code)]
struct CanaryView<'a> {
    canary_id: &'a str,
    canary_name: &'a str,
    canary_type: CanaryTypeTag,
    access_kind: CanaryAccessKind,
    accessor_pid: u32,
    accessor_uid: u32,
    accessor_comm: &'a str,
    accessor_exe: Option<&'a str>,
    timestamp_ns: u64,
}

/// Build a Verdict from a `CanaryView`. Same shape as
/// `crate::fim::rules::fim_verdict` — kept separate so the
/// canary rules don't reach into the FIM rule helpers.
///
/// `event_pid` carries the accessor PID (the attacker's
/// process — what `KillProcessTree` targets). `event_filename`
/// carries the human-readable `canary_name` so operator-
/// facing logs + the audit-chain row's filename slot point at
/// the canary, not at an empty string.
fn canary_verdict(rule: &dyn Rule, view: &CanaryView<'_>, reasoning: &str) -> Verdict {
    Verdict {
        rule_id: rule.id().to_string(),
        rule_name: rule.name().to_string(),
        category: rule.category().to_string(),
        action: ResponseAction::KillProcessTree,
        severity: Severity::Critical,
        reasoning: reasoning.to_string(),
        event_pid: view.accessor_pid,
        event_filename: view.canary_name.to_string(),
        timestamp_ns: view.timestamp_ns,
    }
}

// ── NN-L-CANARY-001 — File canary access ───────────────────────────

/// File canary access — the K3 detector observed a
/// `Event::Fim` whose inode matched a deployed `File`-type
/// canary in the K2 registry. By zero-FP construction this is
/// guaranteed-malicious activity (no operator workflow
/// legitimately reads a canary file). Always Critical,
/// KillProcessTree the accessor, posture → COMBAT.
pub struct NnLCanary001FileAccess;

impl Rule for NnLCanary001FileAccess {
    fn id(&self) -> &'static str {
        "NN-L-CANARY-001_FileAccess"
    }
    fn name(&self) -> &'static str {
        "Canary file access"
    }
    fn category(&self) -> &'static str {
        "canary_deception"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let view = as_canary(event)?;
        if view.canary_type != CanaryTypeTag::File {
            return None;
        }
        // The K3 detector should always pair File canary type
        // with FileOpen access_kind — defensive check anyway
        // (any other access_kind means K3-side wire drift,
        // which we'd rather surface as a missed rule than a
        // wrong-type fire).
        if view.access_kind != CanaryAccessKind::FileOpen {
            return None;
        }
        Some(canary_verdict(
            self,
            &view,
            "File canary access — zero-FP intrusion signal; \
             kill the accessor tree + posture → COMBAT",
        ))
    }
}

// ── NN-L-CANARY-002 — Process canary exec ──────────────────────────

/// Process canary executed — the K3 detector observed a
/// `Event::ProcessSpawn` whose `filename` matched a deployed
/// `Process`-type canary in the K2 registry. By zero-FP
/// construction this is guaranteed-malicious activity (no
/// operator workflow ever execs a canary binary; legitimate
/// operators use `nn-admin`). Always Critical, KillProcessTree
/// the accessor, posture → COMBAT.
pub struct NnLCanary002ProcessExec;

impl Rule for NnLCanary002ProcessExec {
    fn id(&self) -> &'static str {
        "NN-L-CANARY-002_ProcessExec"
    }
    fn name(&self) -> &'static str {
        "Canary process executed"
    }
    fn category(&self) -> &'static str {
        "canary_deception"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let view = as_canary(event)?;
        if view.canary_type != CanaryTypeTag::Process {
            return None;
        }
        if view.access_kind != CanaryAccessKind::ProcessExec {
            return None;
        }
        Some(canary_verdict(
            self,
            &view,
            "Process canary executed — zero-FP intrusion signal; \
             kill the accessor tree + posture → COMBAT",
        ))
    }
}

// ── NN-L-CANARY-003 — Network canary connected ─────────────────────

/// Network listener canary connected — the K3 detector
/// observed a `tokio::TcpListener::accept()` return on a
/// deployed `Network`-type canary's port. By zero-FP
/// construction this is guaranteed-malicious activity (no
/// operator process should be scanning ports the agent owns
/// for deception). Always Critical, KillProcessTree the
/// accessor, posture → COMBAT.
///
/// **Dormant until Tappa 10:** the K3 detector's
/// `is_canary_port` helper exists today but is consulted only
/// when `Event::NetFlow` events are wired into the inline
/// filter — that wiring is part of Tappa 10's NetFlow drain
/// loop. Until then this rule compiles + tests pass with
/// synthetic events, but production never sees a Network
/// canary trip.
pub struct NnLCanary003NetworkConnect;

impl Rule for NnLCanary003NetworkConnect {
    fn id(&self) -> &'static str {
        "NN-L-CANARY-003_NetworkConnect"
    }
    fn name(&self) -> &'static str {
        "Canary network connect"
    }
    fn category(&self) -> &'static str {
        "canary_deception"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let view = as_canary(event)?;
        if view.canary_type != CanaryTypeTag::Network {
            return None;
        }
        if view.access_kind != CanaryAccessKind::NetworkConnect {
            return None;
        }
        Some(canary_verdict(
            self,
            &view,
            "Network canary connected — zero-FP intrusion signal; \
             kill the accessor tree + posture → COMBAT",
        ))
    }
}

// ── NN-L-CANARY-004 — Credential canary read ───────────────────────

/// Credential canary read — the K3 detector observed a
/// `Event::Fim` whose inode matched a deployed `Credential`-
/// type canary in the K2 registry (rendered via the K4
/// templates module). By zero-FP construction this is
/// guaranteed-malicious activity (no operator workflow ever
/// reads a canary credential file; legitimate cloud-CLI tools
/// read REAL creds at REAL paths). Always Critical,
/// KillProcessTree the accessor, posture → COMBAT.
///
/// **Distinction from NN-L-FIM-011..014:** the FIM cloud-cred
/// rules fire on legitimate read paths too (the operator's
/// real `aws` CLI reads `~/.aws/credentials` for normal API
/// calls — High severity, not Critical, with a comm
/// allowlist). Canary creds NEVER have a legitimate read —
/// the K3 detector already filtered against the K2 registry,
/// so reaching this rule is unambiguous. Critical, no
/// allowlist, no exemptions.
pub struct NnLCanary004CredentialRead;

impl Rule for NnLCanary004CredentialRead {
    fn id(&self) -> &'static str {
        "NN-L-CANARY-004_CredentialRead"
    }
    fn name(&self) -> &'static str {
        "Canary credential read"
    }
    fn category(&self) -> &'static str {
        "canary_deception"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let view = as_canary(event)?;
        if view.canary_type != CanaryTypeTag::Credential {
            return None;
        }
        if view.access_kind != CanaryAccessKind::FileOpen {
            return None;
        }
        Some(canary_verdict(
            self,
            &view,
            "Credential canary read — zero-FP intrusion signal; \
             kill the accessor tree + posture → COMBAT",
        ))
    }
}

// ── builder ────────────────────────────────────────────────────────

/// Build the K5 canary rule set in evaluation order. Each rule
/// matches a distinct (canary_type, access_kind) pair so the
/// order is not load-bearing — they're independent in
/// practice. Listed in NN-L-CANARY-NNN sequence for operator
/// readability.
///
/// Wired into [`crate::decision::rules::default_rules`] via
/// `rules.extend(crate::canary::rules::canary_rules())`.
pub fn canary_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(NnLCanary001FileAccess),
        Box::new(NnLCanary002ProcessExec),
        Box::new(NnLCanary003NetworkConnect),
        Box::new(NnLCanary004CredentialRead),
    ]
}

// ── tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::rules::testutil::spawn;

    fn canary_event(canary_type: CanaryTypeTag, access_kind: CanaryAccessKind) -> Event {
        Event::CanaryTripped {
            canary_id: "9f3c8a01b2c3d4e5f6a7b8c9d0e1f2a3".to_string(),
            canary_name: "test_canary".to_string(),
            canary_type,
            access_kind,
            accessor_pid: 12345,
            accessor_uid: 0,
            accessor_comm: "attacker".to_string(),
            accessor_exe: Some("/tmp/payload".to_string()),
            timestamp_ns: 1_700_000_000_000_000_000,
        }
    }

    fn fim_event() -> Event {
        Event::Fim(common::wire::FimEvent {
            timestamp_ns: 1_700_000_000_000_000_000,
            path: "/etc/passwd".to_string(),
            op: common::wire::FimOp::Modified,
            new_sha256: None,
            baseline_sha256: None,
            modifier_exe: None,
            modifier_pid: 4242,
            modifier_uid: 0,
            modifier_comm: "tester".to_string(),
            dest_path: None,
            child_truncated: false,
        })
    }

    // ── NN-L-CANARY-001 (file canary) ─────────────────────────

    /// K5 test #1: NN-L-CANARY-001 fires on (File, FileOpen) +
    /// emits Critical KillProcessTree.
    #[test]
    fn canary001_fires_on_file_canary_file_open() {
        let r = NnLCanary001FileAccess;
        let v = r
            .evaluate(&canary_event(
                CanaryTypeTag::File,
                CanaryAccessKind::FileOpen,
            ))
            .expect("file canary access must fire");
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        assert_eq!(v.rule_id, "NN-L-CANARY-001_FileAccess");
        assert_eq!(v.event_pid, 12345, "verdict targets accessor PID");
        assert_eq!(v.event_filename, "test_canary");
    }

    /// K5 test #2: NN-L-CANARY-001 abstains on canary types
    /// other than File — each rule is tightly typed to its
    /// canary kind.
    #[test]
    fn canary001_does_not_fire_on_non_file_canary_types() {
        let r = NnLCanary001FileAccess;
        for canary_type in [
            CanaryTypeTag::Process,
            CanaryTypeTag::Network,
            CanaryTypeTag::Credential,
        ] {
            assert!(
                r.evaluate(&canary_event(canary_type, CanaryAccessKind::FileOpen))
                    .is_none(),
                "canary001 must not fire on {canary_type:?}"
            );
        }
    }

    // ── NN-L-CANARY-002 (process canary) ──────────────────────

    #[test]
    fn canary002_fires_on_process_canary_exec() {
        let r = NnLCanary002ProcessExec;
        let v = r
            .evaluate(&canary_event(
                CanaryTypeTag::Process,
                CanaryAccessKind::ProcessExec,
            ))
            .expect("process canary exec must fire");
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        assert_eq!(v.rule_id, "NN-L-CANARY-002_ProcessExec");
    }

    #[test]
    fn canary002_does_not_fire_on_non_process_canary_types() {
        let r = NnLCanary002ProcessExec;
        for canary_type in [
            CanaryTypeTag::File,
            CanaryTypeTag::Network,
            CanaryTypeTag::Credential,
        ] {
            assert!(
                r.evaluate(&canary_event(canary_type, CanaryAccessKind::ProcessExec))
                    .is_none(),
                "canary002 must not fire on {canary_type:?}"
            );
        }
    }

    // ── NN-L-CANARY-003 (network canary, dormant until T10) ───

    #[test]
    fn canary003_fires_on_network_canary_connect() {
        let r = NnLCanary003NetworkConnect;
        let v = r
            .evaluate(&canary_event(
                CanaryTypeTag::Network,
                CanaryAccessKind::NetworkConnect,
            ))
            .expect("network canary connect must fire");
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        assert_eq!(v.rule_id, "NN-L-CANARY-003_NetworkConnect");
    }

    #[test]
    fn canary003_does_not_fire_on_non_network_canary_types() {
        let r = NnLCanary003NetworkConnect;
        for canary_type in [
            CanaryTypeTag::File,
            CanaryTypeTag::Process,
            CanaryTypeTag::Credential,
        ] {
            assert!(
                r.evaluate(&canary_event(canary_type, CanaryAccessKind::NetworkConnect))
                    .is_none(),
                "canary003 must not fire on {canary_type:?}"
            );
        }
    }

    // ── NN-L-CANARY-004 (credential canary) ───────────────────

    #[test]
    fn canary004_fires_on_credential_canary_read() {
        let r = NnLCanary004CredentialRead;
        let v = r
            .evaluate(&canary_event(
                CanaryTypeTag::Credential,
                CanaryAccessKind::FileOpen,
            ))
            .expect("credential canary read must fire");
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        assert_eq!(v.rule_id, "NN-L-CANARY-004_CredentialRead");
    }

    #[test]
    fn canary004_does_not_fire_on_non_credential_canary_types() {
        let r = NnLCanary004CredentialRead;
        for canary_type in [
            CanaryTypeTag::File,
            CanaryTypeTag::Process,
            CanaryTypeTag::Network,
        ] {
            assert!(
                r.evaluate(&canary_event(canary_type, CanaryAccessKind::FileOpen))
                    .is_none(),
                "canary004 must not fire on {canary_type:?}"
            );
        }
    }

    // ── cross-cutting invariants ─────────────────────────────

    /// K5 test #9: NONE of the canary rules fire on non-
    /// CanaryTripped events (FIM events, ProcessSpawn, etc.
    /// — the K3 detector filters BEFORE the rule engine, but
    /// defensive rule-side check anyway).
    #[test]
    fn canary_rules_abstain_on_non_canary_events() {
        let rules = canary_rules();
        // Try every non-canary event variant. None should
        // fire any canary rule.
        let non_canary_events = [fim_event(), spawn("ls", "/bin/ls")];
        for event in &non_canary_events {
            for r in &rules {
                assert!(
                    r.evaluate(event).is_none(),
                    "{} must not fire on {:?}",
                    r.id(),
                    event
                );
            }
        }
    }

    /// K5 test #10: every canary rule is Critical-always +
    /// KillProcessTree-always. The zero-FP contract + Critical-
    /// uncapped lock-in (§13 Q4 from Tappa 9) — these
    /// invariants are load-bearing.
    #[test]
    fn all_canary_rules_emit_critical_kill_process_tree() {
        let pairs: &[(CanaryTypeTag, CanaryAccessKind)] = &[
            (CanaryTypeTag::File, CanaryAccessKind::FileOpen),
            (CanaryTypeTag::Process, CanaryAccessKind::ProcessExec),
            (CanaryTypeTag::Network, CanaryAccessKind::NetworkConnect),
            (CanaryTypeTag::Credential, CanaryAccessKind::FileOpen),
        ];
        let rules = canary_rules();
        for (ct, ak) in pairs {
            let ev = canary_event(*ct, *ak);
            let firing: Vec<&Box<dyn Rule>> =
                rules.iter().filter(|r| r.evaluate(&ev).is_some()).collect();
            assert_eq!(
                firing.len(),
                1,
                "exactly one rule should fire on ({ct:?}, {ak:?}); got {} rules",
                firing.len()
            );
            let v = firing[0].evaluate(&ev).unwrap();
            assert_eq!(
                v.severity,
                Severity::Critical,
                "{} must be Critical-always",
                v.rule_id
            );
            assert_eq!(
                v.action,
                ResponseAction::KillProcessTree,
                "{} must be KillProcessTree-always",
                v.rule_id
            );
        }
    }

    /// K5 test #11: `canary_rules()` builder returns exactly 4
    /// rules with stable IDs. Anchored so a rename surfaces
    /// here at compile-cycle.
    #[test]
    fn canary_rules_builder_returns_four_rules() {
        let rules = canary_rules();
        assert_eq!(rules.len(), 4);
        let ids: Vec<&str> = rules.iter().map(|r| r.id()).collect();
        assert_eq!(
            ids,
            vec![
                "NN-L-CANARY-001_FileAccess",
                "NN-L-CANARY-002_ProcessExec",
                "NN-L-CANARY-003_NetworkConnect",
                "NN-L-CANARY-004_CredentialRead",
            ]
        );
        // All rules share the canary_deception category.
        for r in &rules {
            assert_eq!(r.category(), "canary_deception");
        }
    }

    /// K5 test #12: zero-FP contract — when the access_kind
    /// matches the canary_type's expected kind, EVERY one of
    /// the 4 rules' positive-match cases produces Some(verdict)
    /// (never None). Asserts the "by construction" zero-FP
    /// guarantee at the rule layer.
    #[test]
    fn zero_fp_contract_every_matched_event_fires_exactly_one_rule() {
        let rules = canary_rules();
        let pairs: &[(CanaryTypeTag, CanaryAccessKind)] = &[
            (CanaryTypeTag::File, CanaryAccessKind::FileOpen),
            (CanaryTypeTag::Process, CanaryAccessKind::ProcessExec),
            (CanaryTypeTag::Network, CanaryAccessKind::NetworkConnect),
            (CanaryTypeTag::Credential, CanaryAccessKind::FileOpen),
        ];
        for (ct, ak) in pairs {
            let ev = canary_event(*ct, *ak);
            let any_fired = rules.iter().any(|r| r.evaluate(&ev).is_some());
            assert!(
                any_fired,
                "({ct:?}, {ak:?}) must fire at least one rule \
                 (zero-FP contract — detector filtered before us)"
            );
        }
    }
}
