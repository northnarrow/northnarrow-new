//! Tappa 10.6 D7 — ADE prompt template for High-tier process-exec
//! rules (R011/R012/R013/R017), folded in from the T10.5 D8 deferral.
//!
//! Sibling of [`crate::ade::fim_template`] +
//! [`crate::ade::chain_template`]: wires the process rules that most
//! warrant an LLM second opinion into the Tappa 6 ADE pipeline as
//! **enrichment, NOT a gate**. The deterministic rule has ALREADY fired
//! its response (`agent/src/decision/rules/r0*.rs`); ADE only adds an
//! attribution / false-positive opinion to the audit chain.
//!
//! ## Why this was deferred to T10.6 (and why it lands now)
//!
//! T10.5 D8 shipped the FIM + chain templates but **deferred
//! `process_template`** because the process `Event` carried only
//! `comm + filename + uid` — too thin for a useful prompt. The T10.6
//! D2 refit added **`argv` + `parent_comm`**, and D5 surfaced them in
//! the rule reasoning. With invocation + provenance now available, an
//! argv- and lineage-aware second opinion is worthwhile (design §8,
//! §13 Q8 fold-in ruling).
//!
//! ## Which events qualify
//!
//! Process rules top out at **High** severity (none are Critical at the
//! rule level), so — unlike the `severity == Critical` gate the FIM /
//! chain templates use — the gate here keys on **High severity +
//! membership** in [`ADE_PROCESS_RULE_IDS`]. The set is the four High,
//! argv-enriched rules with the clearest escalation / attribution value:
//!
//! - **R011** kernel-module tooling (T1547.006) — rootkit / persistence
//! - **R012** setcap (T1548) — capability privilege escalation
//! - **R013** namespace-escape tooling (T1611) — container escape
//! - **R017** shell from a non-standard path (T1059.004) — reverse shell
//!
//! The Medium/Log rules (R014 at/batch, R015 encoding, R016 debugger)
//! are deliberately excluded — their D5 argv reasoning is sufficient and
//! they don't warrant an ADE call against the §13 Q9 Process-domain
//! budget.
//!
//! ## What this module deliberately does NOT do
//!
//! Same boundary as `fim_template` / `chain_template`: it ships the
//! template + gate as a pure, unit-testable module. Spawning ADE calls
//! and persisting responses is the **shared** production-`process_event`
//! wiring follow-up for all three templates (none are wired live yet —
//! see the `chain_template` "deliberately does NOT do" note). The
//! deterministic response is never gated on ADE regardless.

use common::{Event, Severity, Verdict};

/// High-tier process rule IDs that route to ADE for a second opinion
/// (match `r0*.rs::id()`). Anchored as a `const` so a rule rename
/// surfaces here at compile time + the unit test pins the membership.
pub const ADE_PROCESS_RULE_IDS: &[&str] = &[
    "R011_KernelModuleTooling",
    "R012_SetcapTooling",
    "R013_NamespaceEscapeTooling",
    "R017_ShellFromNonstandardPath",
];

/// Returns `true` if `verdict` is a High-severity process rule in
/// [`ADE_PROCESS_RULE_IDS`]. The caller checks this BEFORE building a
/// prompt. Disjoint from [`crate::ade::fim_template::is_critical_fim_rule`]
/// and [`crate::ade::chain_template::is_critical_chain_rule`] (those gate
/// on `Critical`; process rules top out at `High`).
pub fn is_ade_process_rule(verdict: &Verdict) -> bool {
    verdict.severity == Severity::High
        && ADE_PROCESS_RULE_IDS
            .iter()
            .any(|rid| *rid == verdict.rule_id)
}

/// Per-rule MITRE context, spliced into [`render_process_prompt`] as a
/// `### rule-context:` block so the LLM second opinion is anchored on
/// the technique the deterministic rule fired on. `None` for any rule_id
/// outside [`ADE_PROCESS_RULE_IDS`] (the prompt omits the section).
pub fn ade_process_rule_context(rule_id: &str) -> Option<&'static str> {
    match rule_id {
        "R011_KernelModuleTooling" => Some(
            "MITRE T1547.006 (Boot or Logon Autostart Execution: Kernel \
             Modules and Extensions). A kernel-module load/manage tool ran. \
             A concrete `/lib/modules/...` or `*.ko` path in argv confirms a \
             real module load (kernel rootkit / persistence) vs a benign \
             `--help` / dependency probe.",
        ),
        "R012_SetcapTooling" => Some(
            "MITRE T1548 (Abuse Elevation Control Mechanism). `setcap` grants \
             file capabilities; a `cap_*+ep` spec in argv names the exact \
             privilege being assigned (e.g. `cap_setuid` = a SUID-equivalent \
             escalation primitive).",
        ),
        "R013_NamespaceEscapeTooling" => Some(
            "MITRE T1611 (Escape to Host). nsenter/unshare/runc from a \
             non-standard path. Host-escape flags in argv (`nsenter -t 1 -m`, \
             `--privileged`, `--mount`, `--net=host`) distinguish a container \
             breakout attempt from benign namespace use.",
        ),
        "R017_ShellFromNonstandardPath" => Some(
            "MITRE T1059.004 (Unix Shell). An interactive shell from a \
             non-standard path (copied/renamed shell). An inline `-c <payload>` \
             in argv is the reverse-shell one-liner shape; the parent comm \
             (sshd / cron / a web server) gives provenance — a webserver-spawned \
             shell is a likely webshell.",
        ),
        _ => None,
    }
}

/// Build the structured ADE prompt envelope for a single High-tier
/// process-exec verdict. Same shape as
/// [`crate::ade::fim_template::render_individual_prompt`] — header
/// sections + key:value lines + a final `### question:`. Uses the
/// T10.6 `argv` + `parent_comm` (D2/D5); empty argv / missing
/// parent_comm degrade gracefully (the section line is simply omitted),
/// matching the "graceful-degrade on an un-refit host" contract.
///
/// `event` is the triggering [`Event::ProcessSpawn`]; a non-spawn event
/// yields the header + action only (defensive — the caller only routes
/// process verdicts here).
pub fn render_process_prompt(event: &Event, verdict: &Verdict, posture: &str) -> String {
    let mut s = String::with_capacity(1024);
    s.push_str("### event: high_process_exec\n");
    s.push_str(&format!("rule_id: {}\n", verdict.rule_id));
    s.push_str(&format!("rule_name: {}\n", verdict.rule_name));
    s.push_str(&format!("category: {}\n", verdict.category));
    s.push_str(&format!("severity: {:?}\n", verdict.severity));
    s.push_str(&format!("posture_at_fire: {posture}\n"));
    s.push('\n');

    if let Some(ctx) = ade_process_rule_context(&verdict.rule_id) {
        s.push_str("### rule-context:\n");
        s.push_str(ctx);
        s.push('\n');
        s.push('\n');
    }

    if let Event::ProcessSpawn {
        pid,
        ppid,
        uid,
        gid,
        comm,
        filename,
        argv,
        parent_comm,
        ..
    } = event
    {
        s.push_str("### process:\n");
        s.push_str(&format!("pid: {pid}\n"));
        s.push_str(&format!("ppid: {ppid}\n"));
        s.push_str(&format!("uid: {uid}\n"));
        s.push_str(&format!("gid: {gid}\n"));
        s.push_str(&format!("comm: {comm}\n"));
        s.push_str(&format!("filename: {filename}\n"));
        // T10.6 argv (D2/D5) — the invocation. Omitted when empty (an
        // un-refit host / older agent) so the prompt stays honest.
        if !argv.is_empty() {
            s.push_str(&format!("argv: {}\n", argv.join(" ")));
        }
        // Resolved parent comm (D2) — provenance. Omitted when unknown.
        if !parent_comm.is_empty() {
            s.push_str(&format!("parent_comm: {parent_comm}\n"));
        }
        s.push('\n');
    }

    s.push_str("### already-taken-action:\n");
    s.push_str(&format!("response: {:?}\n", verdict.action));
    s.push_str(&format!("reasoning: {}\n", verdict.reasoning));
    s.push('\n');

    s.push_str("### question:\n");
    s.push_str(
        "The deterministic rule has ALREADY fired the response above; do NOT \
         recommend a different posture or kill action unless you have a \
         specific reason to override. Using the invocation (argv) and parent \
         provenance, provide a second opinion for the audit chain:\n\
         1. is this a true positive given the argv + parent_comm, or a benign \
            pattern for this comm/exe (false-positive analysis)?,\n\
         2. attack-stage labeling (persistence / privilege-escalation / \
            execution / impact),\n\
         3. attribution hints + related IoCs to investigate next.\n",
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::ResponseAction;

    fn process_verdict(rule_id: &str, severity: Severity) -> Verdict {
        Verdict {
            rule_id: rule_id.to_string(),
            rule_name: "test process rule".to_string(),
            category: "persistence".to_string(),
            action: ResponseAction::KillProcess,
            severity,
            reasoning: "test reasoning".to_string(),
            event_pid: 4242,
            event_filename: "/usr/sbin/insmod".to_string(),
            timestamp_ns: 42,
        }
    }

    fn spawn(comm: &str, filename: &str, argv: &[&str], parent_comm: &str) -> Event {
        Event::ProcessSpawn {
            pid: 4242,
            ppid: 1000,
            uid: 0,
            gid: 0,
            comm: comm.to_string(),
            filename: filename.to_string(),
            timestamp_ns: 42,
            argv: argv.iter().map(|s| s.to_string()).collect(),
            parent_comm: parent_comm.to_string(),
            parent_start_ns: 0,
        }
    }

    #[test]
    fn ade_process_rule_ids_are_pinned() {
        assert_eq!(
            ADE_PROCESS_RULE_IDS,
            &[
                "R011_KernelModuleTooling",
                "R012_SetcapTooling",
                "R013_NamespaceEscapeTooling",
                "R017_ShellFromNonstandardPath",
            ]
        );
    }

    #[test]
    fn gate_accepts_only_high_process_rules() {
        for rid in ADE_PROCESS_RULE_IDS {
            assert!(is_ade_process_rule(&process_verdict(rid, Severity::High)));
            // A Medium verdict for the same rule must NOT route to ADE.
            assert!(!is_ade_process_rule(&process_verdict(
                rid,
                Severity::Medium
            )));
        }
        // Out-of-set process rules (Medium-tier) never route.
        assert!(!is_ade_process_rule(&process_verdict(
            "R014_AtBatchScheduling",
            Severity::Medium
        )));
        assert!(!is_ade_process_rule(&process_verdict(
            "R015_EncodingToolingServiceUid",
            Severity::Medium
        )));
        // A Critical FIM verdict is not a process rule.
        assert!(!is_ade_process_rule(&process_verdict(
            "NN-L-FIM-021_PamModuleModified",
            Severity::Critical
        )));
    }

    #[test]
    fn renders_r011_with_argv() {
        let v = process_verdict("R011_KernelModuleTooling", Severity::High);
        let ev = spawn(
            "insmod",
            "/usr/sbin/insmod",
            &["insmod", "/lib/modules/6.8.0/evil.ko"],
            "bash",
        );
        let p = render_process_prompt(&ev, &v, "ENGAGED");
        assert!(p.contains("### event: high_process_exec"));
        assert!(p.contains("T1547.006"));
        assert!(p.contains("argv: insmod /lib/modules/6.8.0/evil.ko"));
        assert!(p.contains("parent_comm: bash"));
        assert!(p.contains("### question:"));
    }

    #[test]
    fn renders_r013_with_argv_and_parent() {
        let v = process_verdict("R013_NamespaceEscapeTooling", Severity::High);
        let ev = spawn(
            "nsenter",
            "/tmp/nsenter",
            &["nsenter", "-t", "1", "-m"],
            "sshd",
        );
        let p = render_process_prompt(&ev, &v, "ENGAGED");
        assert!(p.contains("T1611"));
        assert!(p.contains("argv: nsenter -t 1 -m"));
        assert!(p.contains("parent_comm: sshd"));
    }

    #[test]
    fn empty_argv_is_omitted_gracefully() {
        let v = process_verdict("R011_KernelModuleTooling", Severity::High);
        let ev = spawn("insmod", "/usr/sbin/insmod", &[], "");
        let p = render_process_prompt(&ev, &v, "ENGAGED");
        // No argv / parent_comm lines, but the prompt still renders.
        assert!(!p.contains("argv:"));
        assert!(!p.contains("parent_comm:"));
        assert!(p.contains("comm: insmod"));
        assert!(p.contains("### question:"));
    }

    #[test]
    fn missing_parent_comm_is_omitted_but_argv_kept() {
        let v = process_verdict("R017_ShellFromNonstandardPath", Severity::High);
        let ev = spawn("sh", "/dev/shm/sh", &["sh", "-c", "id"], "");
        let p = render_process_prompt(&ev, &v, "ENGAGED");
        assert!(p.contains("argv: sh -c id"));
        assert!(!p.contains("parent_comm:"));
    }

    #[test]
    fn context_is_none_outside_the_set() {
        assert!(ade_process_rule_context("R014_AtBatchScheduling").is_none());
        assert!(ade_process_rule_context("R011_KernelModuleTooling").is_some());
    }

    #[test]
    fn prompt_stays_within_a_sane_token_budget() {
        // A worst-case long argv must not blow the prompt up. Cap-check:
        // the rendered prompt stays comfortably under ~4 KB (well inside
        // the §13 Q9 Process-domain budget envelope).
        let v = process_verdict("R017_ShellFromNonstandardPath", Severity::High);
        let long: Vec<&str> = vec!["arg"; 200];
        let ev = spawn("sh", "/dev/shm/sh", &long, "sshd");
        let p = render_process_prompt(&ev, &v, "ENGAGED");
        assert!(p.len() < 4096, "prompt was {} bytes", p.len());
    }
}
