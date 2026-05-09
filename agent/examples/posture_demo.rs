//! Posture state machine demo (Sub-tappa 6.5).
//!
//! Drives a [`PostureMachine`] through three transitions and one
//! verdict modulation to show the state machine end-to-end without
//! needing eBPF / a live host. Run with:
//!
//! ```text
//! cargo run -p northnarrow-agent --release --example posture_demo
//! ```
//!
//! The demo:
//!
//! 1. Starts in `OBSERVING`.
//! 2. Fires three TCP connect events to distinct ports → posture
//!    lifts to `ALERTED`.
//! 3. Modulates an `Allow + None` ADE verdict against the new
//!    posture and shows it become `Alert + Low`.
//! 4. Spawns a netcat process → posture lifts to `ENGAGED`.
//! 5. Spawns a `/tmp/payload` exec → posture lifts to `COMBAT`.
//! 6. Confirms automatic decay won't leave `COMBAT`, then shows the
//!    admin-override stub returning posture to `ENGAGED`.

use common::ade_types::{
    AdeAction, AdeMetadata, AdeSeverity, AdeVerdict, AlternativeExplanations, Evidence, FollowUp,
    FollowUpPolicy, MitreAttack, ReasoningSteps, RecommendedAction, ThreatClassification,
    ADE_SCHEMA_VERSION,
};
use common::Event;
use northnarrow_agent::posture::PostureMachine;

fn main() {
    println!("=== NorthNarrow posture state machine demo ===\n");

    let machine = PostureMachine::new();
    println!("[init] posture: {}\n", machine.current_kind());

    // ---- Phase 1: reconnaissance ----------------------------------
    println!("[phase 1] simulate 3 TCP connects to distinct ports (recon)");
    let recon_recent = vec![
        tcp_v4(42, [127, 0, 0, 1], 22, 100),
        tcp_v4(42, [127, 0, 0, 1], 80, 200),
    ];
    let recon_focal = tcp_v4(42, [127, 0, 0, 1], 443, 300);
    if let Some(state) = machine.observe(&recon_focal, &recon_recent) {
        println!(
            "  POSTURE TRANSITION → {} (trigger: reconnaissance pattern detected)",
            state.kind()
        );
    }
    println!("  posture: {}\n", machine.current_kind());

    // ---- Phase 2: modulate ambiguous verdict -----------------------
    println!("[phase 2] ADE verdict: Allow + None");
    let raw = baseline_verdict(AdeAction::Allow, AdeSeverity::None);
    let modulated = machine.modulate_verdict(raw.clone());
    println!("  raw: action={} severity={}", raw.verdict, raw.severity);
    println!(
        "  posture-modulated: action={} severity={}",
        modulated.verdict, modulated.severity
    );
    println!(
        "  → verdict modulated by posture: {} -> {}\n",
        raw.verdict, modulated.verdict
    );

    // ---- Phase 3: exploit attempt ----------------------------------
    println!("[phase 3] simulate netcat exec (exploit attempt)");
    let nc = spawn(99, 1, "ncat", "/usr/bin/ncat", 400);
    if let Some(state) = machine.observe(&nc, &[]) {
        println!(
            "  POSTURE TRANSITION → {} (trigger: confirmed exploit)",
            state.kind()
        );
    }
    println!("  posture: {}\n", machine.current_kind());

    // ---- Phase 4: confirmed intrusion ------------------------------
    println!("[phase 4] simulate exec from /tmp/payload (confirmed intrusion)");
    let intrusion = spawn(100, 1, "evil", "/tmp/payload", 500);
    if let Some(state) = machine.observe(&intrusion, &[]) {
        println!(
            "  POSTURE TRANSITION → {} (trigger: confirmed intrusion / persistence)",
            state.kind()
        );
    }
    println!("  posture: {}\n", machine.current_kind());

    // ---- Phase 5: COMBAT lock and admin override -------------------
    println!("[phase 5] confirm COMBAT does not auto-decay, then admin override");
    let auto = machine.tick_decay();
    println!(
        "  tick_decay returned: {:?}",
        auto.map(|s| s.kind().to_string())
    );
    println!("  posture (still): {}", machine.current_kind());
    let unauth = machine.admin_release_combat(false);
    println!("  admin_release(false): {:?}", unauth.err());
    let auth = machine.admin_release_combat(true).expect("authorized");
    println!(
        "  admin_release(true): posture {} (admin override required)",
        auth.kind()
    );
    println!("  posture: {}\n", machine.current_kind());

    println!("=== transition log ===");
    for (i, t) in machine.transition_log().iter().enumerate() {
        println!(
            "  {:>2}. {} -> {} ({}) — {}",
            i + 1,
            t.from,
            t.to,
            t.trigger
                .map(|x| x.as_str().to_string())
                .unwrap_or_else(|| "decay/override".to_string()),
            t.reason
        );
    }
}

fn spawn(pid: u32, ppid: u32, comm: &str, filename: &str, ts: u64) -> Event {
    Event::ProcessSpawn {
        pid,
        ppid,
        uid: 1000,
        gid: 1000,
        comm: comm.into(),
        filename: filename.into(),
        timestamp_ns: ts,
    }
}

fn tcp_v4(pid: u32, dst: [u8; 4], dst_port: u16, ts: u64) -> Event {
    let mut a = [0u8; 16];
    a[..4].copy_from_slice(&dst);
    Event::TcpConnect {
        pid,
        uid: 1000,
        comm: "demo".into(),
        family: 2,
        src_addr: [0u8; 16],
        src_port: 0,
        dst_addr: a,
        dst_port,
        timestamp_ns: ts,
    }
}

fn baseline_verdict(action: AdeAction, severity: AdeSeverity) -> AdeVerdict {
    AdeVerdict {
        schema_version: ADE_SCHEMA_VERSION.to_string(),
        trace_id: "00000000-0000-4000-8000-000000000000".to_string(),
        timestamp_utc: "2026-05-09T08:30:00Z".to_string(),
        language_used: "en-US".to_string(),
        verdict: action,
        severity,
        confidence: 0.65,
        threat_classification: ThreatClassification {
            family: "demo".into(),
            kind: "ambiguous".into(),
            novelty: 0.5,
        },
        reasoning: ReasoningSteps {
            step_1_extract: "x".into(),
            step_2_pattern_match: "x".into(),
            step_3_criticality: "x".into(),
            step_4_alternative_explanations: AlternativeExplanations {
                legitimate_uses: vec!["dev work".into()],
                assessment: "x".into(),
            },
            step_5_decision: "x".into(),
        },
        evidence: Evidence {
            primary_indicators: vec!["x".into()],
            secondary_indicators: vec![],
            correlation_window_s: None,
        },
        mitre_attack: MitreAttack {
            tactic: vec!["TA0002".into()],
            technique: vec![],
        },
        recommended_action: RecommendedAction {
            action,
            justification: "demo".into(),
            side_effects: vec![],
        },
        follow_up: FollowUp {
            policy: FollowUpPolicy::None,
            monitoring_duration_s: None,
        },
        escalation_tier: None,
        escalation_package: None,
        metadata: AdeMetadata {
            model_id: "demo".into(),
            model_quantization: "Q4_K_M".into(),
            backend: "demo".into(),
            host_id: "host-x".into(),
            agent_version: "0.0.1".into(),
            inference_latency_ms: 0,
        },
    }
}
