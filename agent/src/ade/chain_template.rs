//! Tappa 10.5 D8 — ADE prompt template for Critical chain/correlation
//! events (NN-L-CHAIN-001..003).
//!
//! Sibling of [`crate::ade::fim_template`]: wires the three Critical
//! chain rules into the existing Tappa 6 ADE pipeline as **enrichment,
//! NOT a gate**. By the time this template is built the deterministic
//! correlation rule has ALREADY fired `KillProcessTree` + posture →
//! COMBAT (`agent/src/decision/rules/chain.rs`); ADE only adds an
//! attribution / false-positive second opinion to the audit chain so
//! post-incident review has LLM context alongside the raw correlation.
//!
//! ## Which events qualify
//!
//! The three stateful single-trigger chain rules from D5, all
//! Critical, all firing on the trigger `Event::NetFlow`:
//!
//! - **NN-L-CHAIN-001** credential-store read → egress (T1555 → T1041)
//! - **NN-L-CHAIN-002** `/tmp` exec → non-DNS egress (T1059 → T1571)
//! - **NN-L-CHAIN-003** canary trip → egress (deception → T1041)
//!
//! [`is_critical_chain_rule`] is the gate the caller checks before
//! building a prompt — disjoint from
//! [`crate::ade::fim_template::is_critical_fim_rule`], so a Critical
//! FIM verdict routes to `fim_template` and a Critical CHAIN verdict
//! routes here.
//!
//! ## Rate-limit envelope (§8 + §13 Q9 lock-in)
//!
//! Chain rules fire on the trigger `Event::NetFlow`, so chain
//! enrichment routes through the existing **Net-domain** ADE budget
//! (11 calls/min — 10 individual + 1 batched, per §13 Q9). This module
//! deliberately introduces **no new rate limiter**: adding a fourth
//! per-domain bucket would break the Q9 FIM/Net/Process lock-in. The
//! `chain_*` rule category shares the Net domain's
//! [`crate::ade::fim_template::AdeFimRateLimiter`]-shaped bucket at the
//! production-wiring layer (the same Tappa 10+ follow-up that wires the
//! FIM template's limiter — see that module's "deliberately does NOT
//! do" note). The DETERMINISTIC kill is never throttled regardless.
//!
//! ## What this module deliberately does NOT do
//!
//! - **Spawn ADE calls / persist responses** — same boundary as
//!   `fim_template`: C9/D8 ship the template + gate as pure,
//!   unit-testable modules; the production `process_event` wiring is
//!   the natural follow-up alongside the existing ADE integration.

use common::wire::NetFlowEvent;
use common::{Severity, Verdict};

/// The 3 Critical chain rule IDs (match the strings produced by
/// `agent/src/decision/rules/chain.rs::NnLChain00{1,2,3}*::id()`).
/// Anchored as a `const` slice so a rule rename surfaces here at
/// compile time + the unit test pins the membership.
pub const CRITICAL_CHAIN_RULE_IDS: &[&str] = &[
    "NN-L-CHAIN-001_CredReadThenEgress",
    "NN-L-CHAIN-002_TmpExecThenEgress",
    "NN-L-CHAIN-003_CanaryThenEgress",
];

/// Returns `true` if `verdict.severity == Critical` AND its `rule_id`
/// is in [`CRITICAL_CHAIN_RULE_IDS`]. The caller checks this BEFORE
/// building a prompt. Disjoint from
/// [`crate::ade::fim_template::is_critical_fim_rule`].
pub fn is_critical_chain_rule(verdict: &Verdict) -> bool {
    verdict.severity == Severity::Critical
        && CRITICAL_CHAIN_RULE_IDS
            .iter()
            .any(|rid| *rid == verdict.rule_id)
}

/// Per-rule MITRE kill-chain context, spliced into
/// [`render_chain_prompt`] as a `### chain-context:` block so the LLM
/// second-opinion is anchored on the precursor→trigger TTP pair the
/// deterministic rule correlated on. Returns `None` for any rule_id
/// outside [`CRITICAL_CHAIN_RULE_IDS`] (the prompt omits the section).
pub fn critical_chain_rule_context(rule_id: &str) -> Option<&'static str> {
    match rule_id {
        "NN-L-CHAIN-001_CredReadThenEgress" => Some(
            "Kill chain T1555 (Credentials from Password Stores) → T1041 \
             (Exfiltration Over C2 Channel). The same PID read a credential \
             store (browser / password-manager / GPG keyring) and then opened \
             an outbound flow inside the correlation window — credential theft \
             staged for exfiltration.",
        ),
        "NN-L-CHAIN-002_TmpExecThenEgress" => Some(
            "Kill chain T1059 (Command and Scripting Interpreter) → T1571 \
             (Non-Standard Port). The same PID executed from /tmp/ and then \
             opened an outbound flow to a non-DNS port inside the window — a \
             dropper calling home to C2.",
        ),
        "NN-L-CHAIN-003_CanaryThenEgress" => Some(
            "Kill chain deception-trap → T1041 (Exfiltration Over C2 Channel). \
             The same PID tripped a deception canary (decoy credential / file) \
             and then opened an outbound flow inside the window — a hands-on \
             intruder staging stolen decoy material for exfiltration.",
        ),
        _ => None,
    }
}

/// Build the structured ADE prompt envelope for a single Critical
/// chain correlation. Same shape as
/// [`crate::ade::fim_template::render_individual_prompt`] — header
/// sections + key:value lines + a final `### question:`.
///
/// `flow` is the triggering outbound [`NetFlowEvent`]; the precursor
/// event (cred read / `/tmp` exec / canary trip) that completed the
/// chain lives in the rule's per-PID `ChainCorrelationBuffer` and is
/// summarised in `verdict.reasoning` (the `### correlation:` block) —
/// the wire `Verdict` carries no separate precursor record and §9
/// forbids a wire change to add one.
///
/// The `### question:` asks the LLM for the §12-D8 second opinion:
/// **confirm Critical / argue a downgrade to High / false-positive
/// analysis**. ADE confidence never gates the response — the
/// deterministic kill + posture → COMBAT already fired; this is audit
/// enrichment only.
pub fn render_chain_prompt(verdict: &Verdict, flow: &NetFlowEvent, posture: &str) -> String {
    let mut s = String::with_capacity(1024);
    s.push_str("### event: critical_chain_correlation\n");
    s.push_str(&format!("rule_id: {}\n", verdict.rule_id));
    s.push_str(&format!("rule_name: {}\n", verdict.rule_name));
    s.push_str(&format!("category: {}\n", verdict.category));
    s.push_str(&format!("severity: {:?}\n", verdict.severity));
    s.push_str(&format!("posture_at_fire: {posture}\n"));
    s.push('\n');

    // System context (MITRE kill chain) for the firing rule.
    if let Some(ctx) = critical_chain_rule_context(&verdict.rule_id) {
        s.push_str("### chain-context:\n");
        s.push_str(ctx);
        s.push('\n');
        s.push('\n');
    }

    s.push_str("### trigger-flow:\n");
    s.push_str(&format!("pid: {}\n", flow.pid));
    s.push_str(&format!("uid: {}\n", flow.uid));
    s.push_str(&format!("comm: {}\n", flow.comm));
    if let Some(exe) = flow.exe.as_deref() {
        s.push_str(&format!("exe: {exe}\n"));
    }
    s.push_str(&format!("dst_addr: {}\n", flow.dst_addr));
    s.push_str(&format!("dst_port: {}\n", flow.dst_port));
    s.push_str(&format!("proto: {}\n", flow.proto));
    if let Some(host) = flow.resolved_hostname.as_deref() {
        s.push_str(&format!("resolved_hostname: {host}\n"));
    }
    s.push_str(&format!("bytes_sent: {}\n", flow.bytes_sent));
    s.push_str(&format!("bytes_recv: {}\n", flow.bytes_recv));
    s.push('\n');

    s.push_str("### correlation:\n");
    s.push_str(&format!("precursor_then_trigger: {}\n", verdict.reasoning));
    s.push('\n');

    s.push_str("### already-taken-action:\n");
    s.push_str(&format!("response: {:?}\n", verdict.action));
    s.push('\n');

    s.push_str("### question:\n");
    s.push_str(
        "The deterministic correlation rule has ALREADY fired the response \
         above (KillProcessTree → posture COMBAT); the chain action is NOT \
         gated on your reply. Provide a second opinion for the audit chain:\n\
         1. confirm Critical, or argue a downgrade to High with reasoning,\n\
         2. false-positive analysis: could this precursor + egress be a \
            benign coincidence for this comm/exe?,\n\
         3. attribution hints + related IoCs to investigate next.\n",
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::wire::NetFlowEvent;
    use common::ResponseAction;
    use std::net::{IpAddr, Ipv4Addr};

    fn fake_critical_chain_verdict(rule_id: &str) -> Verdict {
        Verdict {
            rule_id: rule_id.to_string(),
            rule_name: "chain test".to_string(),
            category: "chain_exfiltration".to_string(),
            action: ResponseAction::KillProcessTree,
            severity: Severity::Critical,
            reasoning: "precursor then egress within window".to_string(),
            event_pid: 1234,
            event_filename: "evilbin".to_string(),
            timestamp_ns: 0,
        }
    }

    fn fake_flow(pid: u32, dst_port: u16) -> NetFlowEvent {
        NetFlowEvent {
            start_ns: 1_700_000_000_000_000_000,
            end_ns: 1_700_000_000_000_001_000,
            family: 2,
            src_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            src_port: 54321,
            dst_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            dst_port,
            proto: 6,
            pid,
            uid: 1000,
            comm: "evilbin".to_string(),
            exe: Some("/usr/bin/evilbin".to_string()),
            bytes_sent: 4096,
            bytes_recv: 128,
            resolved_hostname: Some("exfil.example.org".to_string()),
            tls_fingerprint: None,
            flow_id: "abc".to_string(),
            close_reason: 0,
        }
    }

    /// D8 test #1: `CRITICAL_CHAIN_RULE_IDS` pins the three D5 chain
    /// rule IDs; a rename in chain.rs surfaces here.
    #[test]
    fn critical_chain_rule_ids_lists_the_three_chain_rules() {
        assert_eq!(
            CRITICAL_CHAIN_RULE_IDS,
            &[
                "NN-L-CHAIN-001_CredReadThenEgress",
                "NN-L-CHAIN-002_TmpExecThenEgress",
                "NN-L-CHAIN-003_CanaryThenEgress",
            ]
        );
    }

    /// D8 test #2 (routing): `is_critical_chain_rule` accepts only the
    /// three Critical chain rules — false for a Critical FIM verdict
    /// (routes to fim_template) and for a High-severity chain verdict.
    #[test]
    fn is_critical_chain_rule_accepts_only_critical_chain_rules() {
        for rid in CRITICAL_CHAIN_RULE_IDS {
            assert!(
                is_critical_chain_rule(&fake_critical_chain_verdict(rid)),
                "{rid} should qualify"
            );
        }
        // Critical FIM verdict routes to fim_template, not here.
        let fim = fake_critical_chain_verdict("NN-L-FIM-021_PamModuleModified");
        assert!(!is_critical_chain_rule(&fim));
        // Hypothetical High-severity chain verdict — not in scope.
        let mut high = fake_critical_chain_verdict("NN-L-CHAIN-001_CredReadThenEgress");
        high.severity = Severity::High;
        assert!(!is_critical_chain_rule(&high));
    }

    /// D8 test #3: per-rule MITRE kill-chain context for all three
    /// rules; `None` for an unknown id.
    #[test]
    fn critical_chain_rule_context_maps_each_kill_chain() {
        let c1 = critical_chain_rule_context("NN-L-CHAIN-001_CredReadThenEgress")
            .expect("CHAIN-001 context");
        assert!(c1.contains("T1555"));
        assert!(c1.contains("T1041"));
        let c2 = critical_chain_rule_context("NN-L-CHAIN-002_TmpExecThenEgress")
            .expect("CHAIN-002 context");
        assert!(c2.contains("T1059"));
        assert!(c2.contains("T1571"));
        let c3 = critical_chain_rule_context("NN-L-CHAIN-003_CanaryThenEgress")
            .expect("CHAIN-003 context");
        assert!(c3.contains("deception"));
        assert!(c3.contains("T1041"));
        assert!(critical_chain_rule_context("NN-L-CHAIN-099_Bogus").is_none());
    }

    /// D8 test #4: `render_chain_prompt` includes all structured
    /// sections — event header, chain-context, trigger-flow (network
    /// metadata), correlation, already-taken-action, and the
    /// confirm/downgrade/FP question.
    #[test]
    fn render_chain_prompt_includes_all_structured_sections() {
        let v = fake_critical_chain_verdict("NN-L-CHAIN-001_CredReadThenEgress");
        let f = fake_flow(1234, 443);
        let p = render_chain_prompt(&v, &f, "Combat");
        assert!(p.contains("### event: critical_chain_correlation\n"));
        assert!(p.contains("rule_id: NN-L-CHAIN-001_CredReadThenEgress"));
        assert!(p.contains("posture_at_fire: Combat"));
        assert!(p.contains("### chain-context:"));
        assert!(p.contains("T1555"));
        assert!(p.contains("### trigger-flow:"));
        assert!(p.contains("comm: evilbin"));
        assert!(p.contains("dst_addr: 203.0.113.9"));
        assert!(p.contains("dst_port: 443"));
        assert!(p.contains("resolved_hostname: exfil.example.org"));
        assert!(p.contains("### correlation:"));
        assert!(p.contains("### already-taken-action:"));
        assert!(p.contains("response: KillProcessTree"));
        assert!(p.contains("### question:"));
        assert!(p.contains("ALREADY fired"));
        assert!(p.contains("confirm Critical"));
        assert!(p.contains("downgrade to High"));
        assert!(p.contains("false-positive"));
    }

    /// D8 test #5: the CHAIN-002 prompt carries the T1059→T1571 dropper
    /// kill chain (distinct from CHAIN-001's credential chain).
    #[test]
    fn render_chain_prompt_chain002_carries_dropper_kill_chain() {
        let v = fake_critical_chain_verdict("NN-L-CHAIN-002_TmpExecThenEgress");
        let p = render_chain_prompt(&v, &fake_flow(1234, 4444), "Combat");
        assert!(p.contains("T1059"));
        assert!(p.contains("T1571"));
        assert!(!p.contains("T1555"));
    }

    /// D8 test #6: an unknown rule_id renders no `### chain-context:`
    /// section (graceful omission, mirroring fim_template).
    #[test]
    fn render_chain_prompt_omits_context_for_unknown_rule() {
        let v = fake_critical_chain_verdict("NN-L-CHAIN-099_Bogus");
        let p = render_chain_prompt(&v, &fake_flow(1234, 443), "Combat");
        assert!(!p.contains("### chain-context:"));
        // Trigger-flow + question still render.
        assert!(p.contains("### trigger-flow:"));
        assert!(p.contains("### question:"));
    }
}
