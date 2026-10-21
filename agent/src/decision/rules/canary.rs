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
//!
//! (A third reason, the prompt variation per type of the on-host LLM
//! advisor, left with the advisor in Wave 4, lab PR 214.)
//!
//! ## Source-event filter
//!
//! The K3 detector emits `Event::CanaryTripped` and replaces
//! the source `Event::Fim` / `Event::ProcessSpawn` /
//! `Event::TcpConnect` in
//! main::process_event BEFORE the rule engine sees it.
//! Consequence: the K5 rules NEVER see the source events —
//! they consume only `Event::CanaryTripped`. The K2/K9 FIM
//! rules see the ORIGINAL `Event::Fim` only when the detector
//! returned `None` (no matching canary).

use common::{CanaryAccessKind, CanaryTypeTag, Event, ResponseAction, Severity, Verdict};

use crate::canary::readers::CanaryReaders;
use crate::decision::attack::{AttackRef, Tactic};
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
            first_trip,
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
            first_trip: *first_trip,
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
    first_trip: bool,
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

/// A recorded trip: the verdict without a response.
fn logged(
    rule: &dyn Rule,
    view: &CanaryView<'_>,
    severity: Severity,
    reasoning: String,
) -> Verdict {
    Verdict {
        action: ResponseAction::Log,
        severity,
        reasoning,
        ..canary_verdict(rule, view, "")
    }
}

/// External audit DEC-004 / DEC-005: what a trip gets. An access to a
/// canary already tripped is recorded — the first one was the trip (design
/// §7.5, §12 Q2), and every access is in the signed `canary_access.jsonl`
/// chain all the same; before, every later read killed again, a backup's
/// every scheduled run. A File or Credential canary read by `reader`, a
/// program that reads whole trees by design ([`CanaryReaders`]), is
/// recorded, not killed. Any other trip kills the accessor's tree.
fn respond(
    rule: &dyn Rule,
    view: &CanaryView<'_>,
    reasoning: &str,
    reader: Option<String>,
) -> Verdict {
    if !view.first_trip {
        return logged(
            rule,
            view,
            Severity::Low,
            "Access to a canary already tripped — recorded; the first access was the trip \
             (design §7.5)"
                .to_string(),
        );
    }
    if let Some(reader) = reader {
        return logged(
            rule,
            view,
            Severity::High,
            format!(
                "Canary read by {reader}, a program that reads whole trees by design \
                 (backup, anti-malware, indexer, sync) — recorded, not killed; if it should \
                 not reach this canary, move the canary or drop it from canary-readers"
            ),
        );
    }
    canary_verdict(rule, view, reasoning)
}

/// External audit NETR-006: the response to a trip, decided on the access,
/// not on the (type, access) pair. Each rule used to require one exact
/// pair, and nothing answered the others — yet running a File or
/// Credential decoy (its path is in the exec index) produces
/// (File|Credential, ProcessExec), and since DEC-004 that unanswered first
/// access burned the canary: every later access was a Low record.
///
/// - Read: [`respond`] with the readers of whole trees spared (DEC-005).
/// - Executed: [`respond`] — no backup or indexer executes what it reads.
/// - Connected to: kill, on every connect (NN-L-CANARY-003's response).
///
/// The rule id names the canary's type; the reasoning, when the access is
/// not the one this type expects, names it.
fn respond_to_access(
    rule: &dyn Rule,
    view: &CanaryView<'_>,
    readers: &CanaryReaders,
    expected: CanaryAccessKind,
    expected_reasoning: &str,
) -> Verdict {
    let unusual;
    let reasoning = if view.access_kind == expected {
        expected_reasoning
    } else {
        unusual = format!(
            "{:?} canary {} — not the access this decoy expects (it is meant to be {}); \
             intrusion signal; kill the accessor tree",
            view.canary_type,
            access_verb(view.access_kind),
            access_verb(expected),
        );
        &unusual
    };
    match view.access_kind {
        CanaryAccessKind::FileOpen => {
            let reader = view
                .first_trip
                .then(|| readers.reader(view.accessor_pid))
                .flatten();
            respond(rule, view, reasoning, reader)
        }
        CanaryAccessKind::ProcessExec => respond(rule, view, reasoning, None),
        CanaryAccessKind::NetworkConnect => canary_verdict(rule, view, reasoning),
    }
}

fn access_verb(kind: CanaryAccessKind) -> &'static str {
    match kind {
        CanaryAccessKind::FileOpen => "read",
        CanaryAccessKind::ProcessExec => "executed",
        CanaryAccessKind::NetworkConnect => "connected to",
    }
}

// ── NN-L-CANARY-001 — File canary access ───────────────────────────

/// File canary access — the K3 detector observed a
/// `Event::Fim` whose inode matched a deployed `File`-type
/// canary in the K2 registry. Critical, KillProcessTree the
/// accessor — on the first access, and unless the accessor is a
/// program that reads whole trees by design (external audit
/// DEC-005: a canary in a home directory is opened by every backup
/// run and scan; "no workflow reads a canary" held for Process and
/// Network canaries, not for these). See [`respond`].
#[derive(Default)]
pub struct NnLCanary001FileAccess {
    readers: CanaryReaders,
}

impl NnLCanary001FileAccess {
    pub fn new(readers: CanaryReaders) -> Self {
        Self { readers }
    }
}

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
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[AttackRef::new(Tactic::Collection, "T1005")];
        ATTACK
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let view = as_canary(event)?;
        if view.canary_type != CanaryTypeTag::File {
            return None;
        }
        // External audit NETR-006: any access answers; an exec of the
        // decoy's path is not a missed rule.
        Some(respond_to_access(
            self,
            &view,
            &self.readers,
            CanaryAccessKind::FileOpen,
            "File canary access — intrusion signal; kill the accessor tree + posture → COMBAT",
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
#[derive(Default)]
pub struct NnLCanary002ProcessExec {
    /// External audit NETR-006: spared when they read the canary.
    readers: CanaryReaders,
}

impl NnLCanary002ProcessExec {
    pub fn new(readers: CanaryReaders) -> Self {
        Self { readers }
    }
}

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
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[AttackRef::new(Tactic::Discovery, "T1083")];
        ATTACK
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let view = as_canary(event)?;
        if view.canary_type != CanaryTypeTag::Process {
            return None;
        }
        Some(respond_to_access(
            self,
            &view,
            &self.readers,
            CanaryAccessKind::ProcessExec,
            "Process canary executed — zero-FP intrusion signal; \
             kill the accessor tree + posture → COMBAT",
        ))
    }
}

// ── NN-L-CANARY-003 — Network canary connected ─────────────────────

/// Network canary connected — the K3 detector observed a local
/// process connecting (`Event::TcpConnect`, the connect kprobe) to a
/// deployed `Network`-type canary's address and port: a destination no
/// legitimate process uses ([`crate::canary::network`]). Always
/// Critical, KillProcessTree the connecting process's tree, on every
/// connect (external audit NETR-006).
///
/// Lab PR 163: the detector consults the canary destinations on every
/// connect. Before, nothing did (`is_canary_port` was called by tests
/// only) and this rule could not fire. The design's listener on the
/// canary port (§5.3) is not built: no sensor observes an accept, and
/// a remote peer has no process to kill.
#[derive(Default)]
pub struct NnLCanary003NetworkConnect {
    /// External audit NETR-006: spared when they read the canary.
    readers: CanaryReaders,
}

impl NnLCanary003NetworkConnect {
    pub fn new(readers: CanaryReaders) -> Self {
        Self { readers }
    }
}

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
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[
            AttackRef::new(Tactic::Discovery, "T1046"),
            AttackRef::new(Tactic::LateralMovement, "T1021"),
        ];
        ATTACK
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let view = as_canary(event)?;
        if view.canary_type != CanaryTypeTag::Network {
            return None;
        }
        Some(respond_to_access(
            self,
            &view,
            &self.readers,
            CanaryAccessKind::NetworkConnect,
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
/// allowlist, no exemptions — except the readers of whole trees
/// (external audit DEC-005, see [`respond`]): a canary credential under
/// `~/.aws` is in every backup of that home.
#[derive(Default)]
pub struct NnLCanary004CredentialRead {
    readers: CanaryReaders,
}

impl NnLCanary004CredentialRead {
    pub fn new(readers: CanaryReaders) -> Self {
        Self { readers }
    }
}

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
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[AttackRef::new(Tactic::CredentialAccess, "T1552.001")];
        ATTACK
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let view = as_canary(event)?;
        if view.canary_type != CanaryTypeTag::Credential {
            return None;
        }
        Some(respond_to_access(
            self,
            &view,
            &self.readers,
            CanaryAccessKind::FileOpen,
            "Credential canary read — intrusion signal; kill the accessor tree + posture → COMBAT",
        ))
    }
}

// ── builder ────────────────────────────────────────────────────────

/// Build the K5 canary rule set in evaluation order. Each rule
/// matches a distinct canary type, whatever the access (external audit
/// NETR-006), so the order is not load-bearing. Listed in
/// NN-L-CANARY-NNN sequence for operator readability.
///
/// Wired into [`crate::decision::rules::default_rules`] via
/// `rules.extend(crate::canary::rules::canary_rules())`.
pub fn canary_rules() -> Vec<Box<dyn Rule>> {
    canary_rules_with_readers(CanaryReaders::none())
}

/// [`canary_rules`] with the readers the File and Credential rules spare
/// (production: the built-in readers plus the signed
/// `canary-readers.local`, judged through the lineage cache).
pub fn canary_rules_with_readers(readers: CanaryReaders) -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(NnLCanary001FileAccess::new(readers.clone())),
        Box::new(NnLCanary002ProcessExec::new(readers.clone())),
        Box::new(NnLCanary003NetworkConnect::new(readers.clone())),
        Box::new(NnLCanary004CredentialRead::new(readers)),
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
            first_trip: true,
        }
    }

    fn trip(
        canary_type: CanaryTypeTag,
        access_kind: CanaryAccessKind,
        pid: u32,
        first_trip: bool,
    ) -> Event {
        match canary_event(canary_type, access_kind) {
            Event::CanaryTripped {
                canary_id,
                canary_name,
                canary_type,
                access_kind,
                accessor_uid,
                accessor_comm,
                accessor_exe,
                timestamp_ns,
                ..
            } => Event::CanaryTripped {
                canary_id,
                canary_name,
                canary_type,
                access_kind,
                accessor_pid: pid,
                accessor_uid,
                accessor_comm,
                accessor_exe,
                timestamp_ns,
                first_trip,
            },
            _ => unreachable!(),
        }
    }

    /// External audit DEC-004: only the first access is a trip the rules
    /// respond to; a later one is recorded (every access is in the chain).
    #[test]
    fn a_later_access_to_a_tripped_canary_is_recorded_not_killed() {
        for (ty, kind) in [
            (CanaryTypeTag::File, CanaryAccessKind::FileOpen),
            (CanaryTypeTag::Process, CanaryAccessKind::ProcessExec),
            (CanaryTypeTag::Credential, CanaryAccessKind::FileOpen),
        ] {
            let fired: Vec<Verdict> = canary_rules()
                .iter()
                .filter_map(|r| r.evaluate(&trip(ty, kind, 77, false)))
                .collect();
            assert_eq!(fired.len(), 1, "{ty:?}");
            assert_eq!(fired[0].action, ResponseAction::Log, "{ty:?}");
            assert_eq!(fired[0].severity, Severity::Low, "{ty:?}");
            let first: Vec<Verdict> = canary_rules()
                .iter()
                .filter_map(|r| r.evaluate(&trip(ty, kind, 77, true)))
                .collect();
            assert_eq!(first[0].action, ResponseAction::KillProcessTree, "{ty:?}");
        }
    }

    /// External audit DEC-005: a File or Credential canary read by a backup,
    /// anti-malware or indexing program — by what the kernel executed — is
    /// recorded; a copy outside the system trees, a generic tool, and the
    /// Process canary (nobody legitimately executes it) still kill.
    #[test]
    fn a_reader_of_whole_trees_is_recorded_not_killed() {
        let dir = tempfile::tempdir().unwrap();
        let t = crate::posture::lineage::AuthSessionTracker::new(dir.path());
        t.ingest_spawn_with_argv(500, 1, "/usr/bin/restic", &["restic".into()], 1);
        t.ingest_spawn_with_argv(501, 1, "/usr/sbin/clamd", &["clamd".into()], 1);
        t.ingest_spawn_with_argv(502, 1, "/tmp/restic", &["restic".into()], 1);
        t.ingest_spawn_with_argv(503, 1, "/usr/bin/tar", &["tar".into()], 1);
        let rules = canary_rules_with_readers(CanaryReaders::new(Default::default(), t));
        let verdict = |ty, kind, pid| -> Verdict {
            rules
                .iter()
                .find_map(|r| r.evaluate(&trip(ty, kind, pid, true)))
                .unwrap()
        };
        for ty in [CanaryTypeTag::File, CanaryTypeTag::Credential] {
            for pid in [500, 501] {
                let v = verdict(ty, CanaryAccessKind::FileOpen, pid);
                assert_eq!(v.action, ResponseAction::Log, "{ty:?} {pid}");
                assert_eq!(v.severity, Severity::High, "{ty:?} {pid}");
                assert!(v.reasoning.contains("reads whole trees"), "{}", v.reasoning);
            }
            for pid in [502, 503, 504] {
                let v = verdict(ty, CanaryAccessKind::FileOpen, pid);
                assert_eq!(v.action, ResponseAction::KillProcessTree, "{ty:?} {pid}");
            }
        }
        let v = verdict(CanaryTypeTag::Process, CanaryAccessKind::ProcessExec, 500);
        assert_eq!(v.action, ResponseAction::KillProcessTree);
    }

    /// Every canary type and access kind; the `match` stops compiling when
    /// a variant is added, so the exhaustive test below stays exhaustive.
    fn all_pairs() -> Vec<(CanaryTypeTag, CanaryAccessKind)> {
        let types = [
            CanaryTypeTag::File,
            CanaryTypeTag::Process,
            CanaryTypeTag::Network,
            CanaryTypeTag::Credential,
        ];
        let kinds = [
            CanaryAccessKind::FileOpen,
            CanaryAccessKind::ProcessExec,
            CanaryAccessKind::NetworkConnect,
        ];
        for t in types {
            match t {
                CanaryTypeTag::File
                | CanaryTypeTag::Process
                | CanaryTypeTag::Network
                | CanaryTypeTag::Credential => {}
            }
        }
        for k in kinds {
            match k {
                CanaryAccessKind::FileOpen
                | CanaryAccessKind::ProcessExec
                | CanaryAccessKind::NetworkConnect => {}
            }
        }
        types
            .iter()
            .flat_map(|t| kinds.iter().map(move |k| (*t, *k)))
            .collect()
    }

    /// External audit NETR-006: a first trip gets a verdict whatever the
    /// (type, access) pair — exactly one rule, named by the type, Critical,
    /// KillProcessTree; the reasoning names an access the type does not
    /// expect.
    #[test]
    fn every_type_and_access_pair_yields_a_verdict() {
        let rules = canary_rules();
        for (ty, kind) in all_pairs() {
            let fired: Vec<Verdict> = rules
                .iter()
                .filter_map(|r| r.evaluate(&canary_event(ty, kind)))
                .collect();
            assert_eq!(fired.len(), 1, "({ty:?}, {kind:?})");
            let v = &fired[0];
            assert_eq!(
                v.action,
                ResponseAction::KillProcessTree,
                "({ty:?}, {kind:?})"
            );
            assert_eq!(v.severity, Severity::Critical, "({ty:?}, {kind:?})");
            let expected = match ty {
                CanaryTypeTag::File => "NN-L-CANARY-001_FileAccess",
                CanaryTypeTag::Process => "NN-L-CANARY-002_ProcessExec",
                CanaryTypeTag::Network => "NN-L-CANARY-003_NetworkConnect",
                CanaryTypeTag::Credential => "NN-L-CANARY-004_CredentialRead",
            };
            assert_eq!(v.rule_id, expected);
            let usual = matches!(
                (ty, kind),
                (CanaryTypeTag::File, CanaryAccessKind::FileOpen)
                    | (CanaryTypeTag::Process, CanaryAccessKind::ProcessExec)
                    | (CanaryTypeTag::Network, CanaryAccessKind::NetworkConnect)
                    | (CanaryTypeTag::Credential, CanaryAccessKind::FileOpen)
            );
            assert_eq!(
                v.reasoning.contains("not the access this decoy expects"),
                !usual,
                "({ty:?}, {kind:?}): {}",
                v.reasoning
            );
        }
    }

    /// External audit NETR-006: running a File decoy's path (root made it
    /// executable, or a user who owns the directory put a file there) is
    /// answered on its first trip, not burned.
    #[test]
    fn an_exec_of_a_file_canary_kills() {
        let v = canary_rules()
            .iter()
            .find_map(|r| {
                r.evaluate(&canary_event(
                    CanaryTypeTag::File,
                    CanaryAccessKind::ProcessExec,
                ))
            })
            .expect("an exec of a File canary gets a verdict");
        assert_eq!(v.rule_id, "NN-L-CANARY-001_FileAccess");
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        assert!(
            v.reasoning.contains("File canary executed"),
            "{}",
            v.reasoning
        );
    }

    /// External audit NETR-006 with DEC-005: the readers of whole trees are
    /// spared when they read a canary, of any type, never when they
    /// execute one.
    #[test]
    fn a_reader_is_spared_only_when_it_reads() {
        let dir = tempfile::tempdir().unwrap();
        let t = crate::posture::lineage::AuthSessionTracker::new(dir.path());
        t.ingest_spawn_with_argv(500, 1, "/usr/bin/restic", &["restic".into()], 1);
        let rules = canary_rules_with_readers(CanaryReaders::new(Default::default(), t));
        let verdict = |ty, kind| -> Verdict {
            rules
                .iter()
                .find_map(|r| r.evaluate(&trip(ty, kind, 500, true)))
                .unwrap()
        };
        for ty in [
            CanaryTypeTag::File,
            CanaryTypeTag::Process,
            CanaryTypeTag::Credential,
        ] {
            let read = verdict(ty, CanaryAccessKind::FileOpen);
            assert_eq!(read.action, ResponseAction::Log, "{ty:?}");
            assert_eq!(read.severity, Severity::High, "{ty:?}");
            let run = verdict(ty, CanaryAccessKind::ProcessExec);
            assert_eq!(run.action, ResponseAction::KillProcessTree, "{ty:?}");
        }
    }

    fn fim_event() -> Event {
        Event::Fim(common::wire::FimEvent {
            timestamp_ns: 1_700_000_000_000_000_000,
            path: "/etc/passwd".to_string(),
            op: common::wire::FimOp::Modified,
            new_sha256: None,
            baseline_sha256: None,
            new_size: None,
            baseline_size: None,
            modifier_exe: None,
            modifier_pid: 4242,
            modifier_uid: 0,
            modifier_comm: "tester".to_string(),
            dest_path: None,
            child_truncated: false,
            wide_coverage: false,
            owner_uid: None,
            reader_dac_capable: false,
            capability: None,
            attrs: None,
            file_key: None,
            is_dir: false,
            moved_in: false,
        })
    }

    // ── NN-L-CANARY-001 (file canary) ─────────────────────────

    /// K5 test #1: NN-L-CANARY-001 fires on (File, FileOpen) +
    /// emits Critical KillProcessTree.
    #[test]
    fn canary001_fires_on_file_canary_file_open() {
        let r = NnLCanary001FileAccess::default();
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
        let r = NnLCanary001FileAccess::default();
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
        let r = NnLCanary002ProcessExec::default();
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
        let r = NnLCanary002ProcessExec::default();
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
        let r = NnLCanary003NetworkConnect::default();
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
        let r = NnLCanary003NetworkConnect::default();
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
        let r = NnLCanary004CredentialRead::default();
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
        let r = NnLCanary004CredentialRead::default();
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
