//! Tappa 9 C9 — ADE prompt template for Critical FIM events.
//!
//! Wires the four Critical-tier FIM rules into the existing Tappa 6
//! ADE pipeline as enrichment (NOT a gate — the deterministic rule
//! has ALREADY fired its KillProcessTree + posture transition by
//! the time this template is built). ADE adds attribution hints,
//! attack-stage labeling, and related-IoC suggestions to the audit
//! chain so post-incident review has LLM context alongside the raw
//! event.
//!
//! ## Which events qualify
//!
//! Per design §6.5 + §13 Q4 lock-in, the Critical-tier FIM rules
//! are:
//!
//! - **NN-L-FIM-001** system binary modified
//! - **NN-L-FIM-002** new SUID-root in user-writable directory
//! - **NN-L-FIM-008** kernel module file modified
//! - **NN-L-FIM-010** ransomware extension rename
//!
//! [`is_critical_fim_rule`] is the gate the caller checks before
//! building a prompt. High / Medium / Low FIM events do NOT
//! escalate to ADE — they stay in the deterministic-rule path.
//!
//! ## Rate-limit envelope (§13 Q9 tiered cap)
//!
//! [`AdeFimRateLimiter`] is the standalone bucket limiter the
//! caller consults BEFORE submitting to the existing
//! [`crate::ade::AdeEngine`]. Two-tier:
//!
//! - **10 individual prompts / minute** — one per Critical FIM
//!   event until the cap. Each prompt carries the full event
//!   context for fine-grained LLM analysis.
//! - **1 batched overflow prompt / minute** — fired when the
//!   individual cap is exhausted. Carries the list of suppressed
//!   `FimEvent`s as a single batched context so the LLM still
//!   sees signal density without N separate API calls.
//!
//! Upper bound: **11 ADE calls / minute**. The DETERMINISTIC rule
//! path is NEVER throttled by this limiter — it fires on every
//! Critical event regardless of whether ADE saw the event
//! individually or in the batch. ADE is enrichment, not a gate.
//!
//! ## What this module deliberately does NOT do
//!
//! - **Spawn ADE calls.** That wiring sits in
//!   `crate::main::process_event` — when an `Event::Fim` with a
//!   matching rule reaches there, the caller checks
//!   [`is_critical_fim_rule`], consults the rate limiter, and
//!   submits to the existing [`crate::ade::AdeEngine::evaluate`]
//!   surface. C9 ships the template + limiter as pure modules so
//!   they're unit-testable in isolation; the production wiring is
//!   the natural Tappa 10+ follow-up alongside the existing ADE
//!   integration tests.
//! - **Persist ADE responses.** The audit chain captures the
//!   pre-rule-execution event row today; capturing the
//!   post-ADE-response enrichment requires a `FimDriftEntry`
//!   schema bump that's out of polish #4 scope (the field would
//!   need to handle async response arrival vs the synchronous
//!   `BaselineDb::append` contract).
//!
//! ## Tiered cap rationale (per design §8.1 + Q9)
//!
//! 10/min works in steady state. A multi-stage attack with 50
//! critical events in 30 seconds would lose 40 events of LLM
//! context under a simple-cap design; the batched overflow tier
//! preserves signal density at one extra API call/minute. Setting
//! `batched_overflow_per_min: 0` disables the batched tier for
//! cost-sensitive deployments.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use common::wire::FimEvent;
use common::{Severity, Verdict};

/// The 4 Critical FIM rule IDs (matches the strings produced by
/// `agent/src/fim/rules.rs::NnLFim00{1,2,8}*::id()` +
/// `NnLFim010RansomwareExtensionRename::id()`). Anchored as a
/// `const` slice so a future rule rename surfaces here at compile
/// time + the unit test pins the membership.
pub const CRITICAL_FIM_RULE_IDS: &[&str] = &[
    "NN-L-FIM-001_SystemBinaryModified",
    "NN-L-FIM-002_NewSuidBinary",
    "NN-L-FIM-008_KernelModuleModified",
    "NN-L-FIM-010_RansomwareExtensionRename",
    // Tappa 10.5 D3 Critical FIM rules — route to ADE enrichment
    // alongside the deterministic kill (§8). The deterministic
    // KillProcessTree + posture→COMBAT fires regardless; this list
    // gates only the ADE prompt.
    "NN-L-FIM-021_PamModuleModified",
    "NN-L-FIM-022_LdSoPreloadModified",
];

/// Returns `true` if `verdict.severity == Critical` AND its
/// `rule_id` is in [`CRITICAL_FIM_RULE_IDS`]. The caller checks
/// this BEFORE building a prompt; non-Critical-FIM verdicts stay
/// in the deterministic-rule path without ADE enrichment.
pub fn is_critical_fim_rule(verdict: &Verdict) -> bool {
    verdict.severity == Severity::Critical
        && CRITICAL_FIM_RULE_IDS
            .iter()
            .any(|rid| *rid == verdict.rule_id)
}

/// Per-rule MITRE / threat-actor context for a Critical FIM rule,
/// spliced into [`render_individual_prompt`] as a `### rule-context:`
/// block so the LLM second-opinion is anchored on the SAME TTP mapping
/// the deterministic rule fired on (rather than re-deriving it from the
/// raw path). Tappa 10.5 D8 adds the two D3 Critical rules; the four
/// Tappa 9 rules keep their pre-D8 generic prompt (the file path alone
/// is self-describing for those — system-binary / SUID / kmod /
/// ransomware-rename). Returns `None` for any rule without a curated
/// line, in which case the prompt omits the section entirely
/// (byte-identical to the pre-D8 output for those rules).
pub fn critical_fim_rule_context(rule_id: &str) -> Option<&'static str> {
    match rule_id {
        "NN-L-FIM-021_PamModuleModified" => Some(
            "MITRE T1543 (Create or Modify System Process) + T1556 (Modify \
             Authentication Process). A PAM `.so` written outside the package \
             manager is a credential-harvesting + auth-bypass persistence \
             primitive — a staple of Russian-APT and other state-actor Linux \
             toolkits (capture plaintext credentials at authentication time, \
             install a hidden backdoor auth path). High-confidence Critical: \
             legitimate PAM modules ship via dpkg/rpm, not ad-hoc writes.",
        ),
        "NN-L-FIM-022_LdSoPreloadModified" => Some(
            "MITRE T1574.006 (Dynamic Linker Hijacking). /etc/ld.so.preload is \
             the canonical userland-rootkit anchor and is legitimately ABSENT \
             on a stock host — any create/modify is a near-certain LD_PRELOAD \
             rootkit indicator (Diamorphine / HiddenWasp / Symbiote lineage). \
             High-confidence Critical: no benign comm exemption applies.",
        ),
        _ => None,
    }
}

// ── prompt builder ──────────────────────────────────────────────────

/// Build the structured ADE prompt envelope for a single
/// Critical FIM event. The output is operator-readable + LLM-
/// parseable — same shape as the existing Tappa 6 structured
/// prompts (header sections + key:value lines + a final
/// `### question:` section).
///
/// The deterministic rule has already fired by the time this
/// runs; the prompt's `### already-taken-action:` section makes
/// that explicit so the LLM doesn't double-recommend.
pub fn render_individual_prompt(event: &FimEvent, verdict: &Verdict, posture: &str) -> String {
    let mut s = String::with_capacity(1024);
    s.push_str("### event: critical_fim_drift\n");
    s.push_str(&format!("rule_id: {}\n", verdict.rule_id));
    s.push_str(&format!("rule_name: {}\n", verdict.rule_name));
    s.push_str(&format!("category: {}\n", verdict.category));
    s.push_str(&format!("severity: {:?}\n", verdict.severity));
    s.push_str(&format!("posture_at_fire: {posture}\n"));
    s.push('\n');

    // System context (MITRE TTP) for the D3 Critical rules — omitted
    // for rules whose path is already self-describing (see
    // [`critical_fim_rule_context`]).
    if let Some(ctx) = critical_fim_rule_context(&verdict.rule_id) {
        s.push_str("### rule-context:\n");
        s.push_str(ctx);
        s.push('\n');
        s.push('\n');
    }

    s.push_str("### file:\n");
    s.push_str(&format!("path: {}\n", event.path));
    if let Some(dest) = event.dest_path.as_deref() {
        s.push_str(&format!("dest_path: {dest}\n"));
    }
    s.push_str(&format!("op: {:?}\n", event.op));
    if let Some(b) = event.baseline_sha256 {
        s.push_str(&format!("baseline_sha256: {}\n", hex::encode(b)));
    }
    if let Some(n) = event.new_sha256 {
        s.push_str(&format!("new_sha256: {}\n", hex::encode(n)));
    }
    s.push('\n');

    s.push_str("### modifier:\n");
    s.push_str(&format!("pid: {}\n", event.modifier_pid));
    s.push_str(&format!("uid: {}\n", event.modifier_uid));
    s.push_str(&format!("comm: {}\n", event.modifier_comm));
    if let Some(exe) = event.modifier_exe.as_deref() {
        s.push_str(&format!("exe: {exe}\n"));
    }
    s.push('\n');

    s.push_str("### already-taken-action:\n");
    s.push_str(&format!("response: {:?}\n", verdict.action));
    s.push_str(&format!("reasoning: {}\n", verdict.reasoning));
    s.push('\n');

    s.push_str("### question:\n");
    s.push_str(
        "Cross-reference recent process spawns and network activity for the \
         modifier PID. Provide:\n\
         1. attribution hints (any signatures matching known threat actors),\n\
         2. attack-stage labeling (initial access / persistence / impact),\n\
         3. related IoCs to investigate next.\n\
         The deterministic rule has ALREADY fired the response above; do NOT \
         recommend a different posture or kill action unless you have a \
         specific reason to override.\n",
    );
    s
}

/// Build the BATCHED ADE prompt envelope from a sequence of
/// suppressed `FimEvent`s (each paired with its firing
/// [`Verdict`]). Fired by the rate limiter's overflow tier
/// when the individual cap is exhausted. The LLM sees signal
/// density at one prompt instead of N — useful for multi-stage
/// attacks generating bursts of Critical events.
pub fn render_batched_overflow_prompt(events: &[(FimEvent, Verdict)], posture: &str) -> String {
    let mut s = String::with_capacity(events.len() * 256);
    s.push_str("### event: critical_fim_drift_batched_overflow\n");
    s.push_str(&format!("posture_at_window_start: {posture}\n"));
    s.push_str(&format!("event_count: {}\n", events.len()));
    s.push('\n');

    for (idx, (event, verdict)) in events.iter().enumerate() {
        s.push_str(&format!("### event[{idx}]:\n"));
        s.push_str(&format!("rule_id: {}\n", verdict.rule_id));
        s.push_str(&format!("path: {}\n", event.path));
        if let Some(dest) = event.dest_path.as_deref() {
            s.push_str(&format!("dest_path: {dest}\n"));
        }
        s.push_str(&format!("op: {:?}\n", event.op));
        s.push_str(&format!(
            "modifier: pid={} uid={} comm={}\n",
            event.modifier_pid, event.modifier_uid, event.modifier_comm
        ));
        s.push('\n');
    }

    s.push_str("### question:\n");
    s.push_str(
        "These Critical FIM events fired within a single rate-limit window. \
         Correlate them: is this a single coordinated attack (e.g., a \
         ransomware loop sweeping a directory), or independent unrelated \
         events? Identify:\n\
         1. common modifier PID or process tree,\n\
         2. attack-stage progression across the events,\n\
         3. paths or extensions that suggest a campaign signature.\n\
         The deterministic rule has ALREADY fired the per-event response; \
         this prompt is for forensic enrichment only.\n",
    );
    s
}

// ── rate limiter (§13 Q9 tiered cap) ────────────────────────────────

/// Default individual-tier cap per §13 Q9 resolution.
pub const DEFAULT_INDIVIDUAL_CAP_PER_MIN: u32 = 10;

/// Default batched-overflow cap per §13 Q9 resolution. Setting
/// this to 0 disables the batched tier (operator preference for
/// cost-sensitive deployments).
pub const DEFAULT_BATCHED_OVERFLOW_PER_MIN: u32 = 1;

/// Outcome of [`AdeFimRateLimiter::try_consume`]. The caller
/// branches on this to decide whether to submit an individual
/// prompt, buffer for batched, or no-op.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdeAdmit {
    /// Submit one individual ADE prompt — bucket had capacity.
    Individual,
    /// Buffer the event for the next batched-overflow flush.
    /// The caller appends to its buffer; the next
    /// [`AdeFimRateLimiter::try_flush_overflow`] call drains
    /// the buffer and consumes the batched-overflow token (if
    /// available).
    BufferedForOverflow,
    /// Both buckets exhausted — drop the event for ADE
    /// purposes. The deterministic rule path is unaffected.
    Suppressed,
}

/// Hierarchical token-bucket per `AdeAdmit` tier, matching the
/// shape of [`crate::fim::drain::DriftRateLimiter`] but
/// independently configured per §13 Q9.
pub struct AdeFimRateLimiter {
    state: Mutex<AdeBucketState>,
    individual_cap_per_min: u32,
    batched_overflow_per_min: u32,
}

struct AdeBucketState {
    individual_remaining: u32,
    overflow_remaining: u32,
    window_started: Instant,
}

impl AdeFimRateLimiter {
    /// Build with the §13 Q9 defaults
    /// ([`DEFAULT_INDIVIDUAL_CAP_PER_MIN`] +
    /// [`DEFAULT_BATCHED_OVERFLOW_PER_MIN`]).
    pub fn new() -> Self {
        Self::with_caps(
            DEFAULT_INDIVIDUAL_CAP_PER_MIN,
            DEFAULT_BATCHED_OVERFLOW_PER_MIN,
        )
    }

    /// Build with explicit caps. Test-friendly + operator-
    /// override-friendly (the production config knobs in
    /// `/etc/northnarrow/config.toml` map to these args once
    /// the V1.0 ADE-FIM wiring lands).
    pub fn with_caps(individual_cap_per_min: u32, batched_overflow_per_min: u32) -> Self {
        Self {
            state: Mutex::new(AdeBucketState {
                individual_remaining: individual_cap_per_min,
                overflow_remaining: batched_overflow_per_min,
                window_started: Instant::now(),
            }),
            individual_cap_per_min,
            batched_overflow_per_min,
        }
    }

    /// Decide whether the next Critical FIM event admits to an
    /// individual prompt, buffers for overflow, or is dropped.
    /// `now` injected for deterministic testing.
    pub fn try_consume_with_now(&self, now: Instant) -> AdeAdmit {
        let mut s = self.state.lock().expect("AdeFimRateLimiter mutex poisoned");
        // Window roll-over.
        if now.duration_since(s.window_started) >= Duration::from_secs(60) {
            s.individual_remaining = self.individual_cap_per_min;
            s.overflow_remaining = self.batched_overflow_per_min;
            s.window_started = now;
        }
        if s.individual_remaining > 0 {
            s.individual_remaining -= 1;
            AdeAdmit::Individual
        } else if s.overflow_remaining > 0 {
            // The batched tier accepts EVENTS into its
            // buffer; the BUCKET ticks once per FLUSH (see
            // try_flush_overflow). The non-zero remaining
            // here just signals "buffering is open".
            AdeAdmit::BufferedForOverflow
        } else {
            AdeAdmit::Suppressed
        }
    }

    /// Production wrapper around `try_consume_with_now` that
    /// pins `now = Instant::now()`.
    pub fn try_consume(&self) -> AdeAdmit {
        self.try_consume_with_now(Instant::now())
    }

    /// Consume one batched-overflow token. Caller invokes this
    /// when its buffered-events queue is non-empty AND it's
    /// time to flush (typically a 1-second heartbeat
    /// post-buffering, or at window roll-over). Returns `true`
    /// if a token was consumed (flush may proceed) or `false`
    /// (overflow bucket empty — buffered events stay queued
    /// for the next window).
    pub fn try_flush_overflow_with_now(&self, now: Instant) -> bool {
        let mut s = self.state.lock().expect("AdeFimRateLimiter mutex poisoned");
        if now.duration_since(s.window_started) >= Duration::from_secs(60) {
            s.individual_remaining = self.individual_cap_per_min;
            s.overflow_remaining = self.batched_overflow_per_min;
            s.window_started = now;
        }
        if s.overflow_remaining > 0 {
            s.overflow_remaining -= 1;
            true
        } else {
            false
        }
    }

    /// Production wrapper around `try_flush_overflow_with_now`.
    pub fn try_flush_overflow(&self) -> bool {
        self.try_flush_overflow_with_now(Instant::now())
    }

    /// Current individual-tier cap (operator-visible via the
    /// future `nn-admin fim status` ADE-stats extension).
    pub fn individual_cap_per_min(&self) -> u32 {
        self.individual_cap_per_min
    }

    /// Current batched-overflow cap.
    pub fn batched_overflow_per_min(&self) -> u32 {
        self.batched_overflow_per_min
    }
}

impl Default for AdeFimRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

// ── caller-side buffer (helper, not a hard requirement) ─────────────

/// Simple FIFO buffer for the BufferedForOverflow events the
/// caller accumulates until the next flush. Bounded so a
/// pathological event storm can't OOM the agent. Exceeding the
/// cap drops the OLDEST events (newest wins — most recent
/// signal is freshest).
#[derive(Debug)]
pub struct OverflowBuffer {
    cap: usize,
    inner: Mutex<VecDeque<(FimEvent, Verdict)>>,
}

impl OverflowBuffer {
    /// Build with explicit capacity. Recommended: 100 (matches
    /// the design §6.5 highish-water-mark for burst events
    /// per window).
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            cap,
            inner: Mutex::new(VecDeque::with_capacity(cap.min(1024))),
        }
    }

    /// Append one event/verdict pair, dropping the oldest if at cap.
    pub fn push(&self, event: FimEvent, verdict: Verdict) {
        let mut q = self.inner.lock().expect("OverflowBuffer mutex poisoned");
        if q.len() >= self.cap {
            q.pop_front();
        }
        q.push_back((event, verdict));
    }

    /// Drain the buffer for a batched-overflow prompt. Returns
    /// an empty Vec if nothing buffered.
    pub fn drain(&self) -> Vec<(FimEvent, Verdict)> {
        let mut q = self.inner.lock().expect("OverflowBuffer mutex poisoned");
        q.drain(..).collect()
    }

    /// Current buffered-event count (operator-visible via
    /// future status surface).
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .expect("OverflowBuffer mutex poisoned")
            .len()
    }

    /// True when zero events are buffered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::wire::FimOp;
    use common::ResponseAction;

    fn fake_critical_verdict(rule_id: &str) -> Verdict {
        Verdict {
            rule_id: rule_id.to_string(),
            rule_name: "test".to_string(),
            category: "test".to_string(),
            action: ResponseAction::KillProcessTree,
            severity: Severity::Critical,
            reasoning: "test reasoning".to_string(),
            event_pid: 0,
            event_filename: String::new(),
            timestamp_ns: 0,
        }
    }

    fn fake_fim_event(path: &str, dest: Option<&str>) -> FimEvent {
        FimEvent {
            timestamp_ns: 1_700_000_000_000_000_000,
            path: path.to_string(),
            op: FimOp::Renamed,
            new_sha256: None,
            baseline_sha256: Some([0xAA; 32]),
            modifier_exe: Some("/usr/bin/attacker".to_string()),
            modifier_pid: 1234,
            modifier_uid: 0,
            modifier_comm: "ransomware".to_string(),
            dest_path: dest.map(String::from),
        }
    }

    /// C9 test #1 (+ Tappa 10.5 D3): `CRITICAL_FIM_RULE_IDS` matches
    /// the six Critical FIM rules from agent/src/fim/rules.rs —
    /// FIM-001/002/008/010 (Tappa 9) + FIM-021/022 (Tappa 10.5 D3).
    /// Anchored so a rename in rules.rs surfaces here at
    /// compile-time-cycle.
    #[test]
    fn critical_fim_rule_ids_lists_the_critical_rules() {
        assert_eq!(
            CRITICAL_FIM_RULE_IDS,
            &[
                "NN-L-FIM-001_SystemBinaryModified",
                "NN-L-FIM-002_NewSuidBinary",
                "NN-L-FIM-008_KernelModuleModified",
                "NN-L-FIM-010_RansomwareExtensionRename",
                "NN-L-FIM-021_PamModuleModified",
                "NN-L-FIM-022_LdSoPreloadModified",
            ]
        );
    }

    /// C9 test #2: `is_critical_fim_rule` returns true for the
    /// four Critical FIM rules, false for non-FIM Critical
    /// rules (Tappa 2 R001..R010 also produce Critical
    /// verdicts but are NOT in the ADE-FIM enrichment scope).
    #[test]
    fn is_critical_fim_rule_accepts_only_critical_fim_rules() {
        for rid in CRITICAL_FIM_RULE_IDS {
            let v = fake_critical_verdict(rid);
            assert!(is_critical_fim_rule(&v), "{rid} should qualify");
        }
        // Non-FIM Critical rule — skip.
        let non_fim = fake_critical_verdict("R001_ExecFromTmp");
        assert!(!is_critical_fim_rule(&non_fim));
        // Tappa 10.5 D8 routing: a Critical CHAIN verdict is NOT a FIM
        // verdict — it routes to chain_template, not here.
        let chain = fake_critical_verdict("NN-L-CHAIN-001_CredReadThenEgress");
        assert!(!is_critical_fim_rule(&chain));
        // High-severity FIM rule (e.g., NN-L-FIM-003 sensitive config) — skip.
        let mut high = fake_critical_verdict("NN-L-FIM-003_SensitiveConfigModified");
        high.severity = Severity::High;
        assert!(!is_critical_fim_rule(&high));
    }

    /// D8 test: `critical_fim_rule_context` carries the per-rule MITRE
    /// TTP for the two D3 Critical rules and `None` for rules whose
    /// path is self-describing (FIM-001/002/008/010).
    #[test]
    fn critical_fim_rule_context_covers_the_d3_critical_rules() {
        let pam = critical_fim_rule_context("NN-L-FIM-021_PamModuleModified")
            .expect("FIM-021 has context");
        assert!(pam.contains("T1543"));
        assert!(pam.contains("T1556"));
        assert!(pam.contains("PAM"));
        let ld = critical_fim_rule_context("NN-L-FIM-022_LdSoPreloadModified")
            .expect("FIM-022 has context");
        assert!(ld.contains("T1574.006"));
        assert!(ld.contains("ld.so.preload"));
        // Tappa 9 rules + unknown ids → no curated line.
        assert!(critical_fim_rule_context("NN-L-FIM-010_RansomwareExtensionRename").is_none());
        assert!(critical_fim_rule_context("NN-L-FIM-999_Bogus").is_none());
    }

    /// D8 test: rendering a FIM-021 prompt splices the `### rule-context:`
    /// MITRE block; rendering a rule without context omits the section
    /// (byte-compatible with the pre-D8 prompt for those rules).
    #[test]
    fn render_individual_prompt_splices_rule_context_only_when_present() {
        let v21 = fake_critical_verdict("NN-L-FIM-021_PamModuleModified");
        let e = fake_fim_event("/lib/x86_64-linux-gnu/security/pam_evil.so", None);
        let p21 = render_individual_prompt(&e, &v21, "Combat");
        assert!(p21.contains("### rule-context:\n"));
        assert!(p21.contains("T1543"));
        assert!(p21.contains("persistence"));

        // FIM-010 has no curated context → no rule-context section.
        let v10 = fake_critical_verdict("NN-L-FIM-010_RansomwareExtensionRename");
        let p10 = render_individual_prompt(&e, &v10, "Combat");
        assert!(!p10.contains("### rule-context:"));
    }

    /// C9 test #3: `render_individual_prompt` includes all of:
    /// rule_id, path, dest_path (when present), modifier
    /// triple, already-taken-action section, question section.
    /// Anchors the prompt structure against future refactors.
    #[test]
    fn render_individual_prompt_includes_all_structured_sections() {
        let v = fake_critical_verdict("NN-L-FIM-010_RansomwareExtensionRename");
        let e = fake_fim_event("/home/u/doc.docx", Some("/home/u/doc.docx.crypted"));
        let prompt = render_individual_prompt(&e, &v, "Combat");
        assert!(prompt.contains("### event: critical_fim_drift\n"));
        assert!(prompt.contains("rule_id: NN-L-FIM-010_RansomwareExtensionRename"));
        assert!(prompt.contains("posture_at_fire: Combat"));
        assert!(prompt.contains("### file:"));
        assert!(prompt.contains("path: /home/u/doc.docx"));
        assert!(prompt.contains("dest_path: /home/u/doc.docx.crypted"));
        assert!(prompt.contains("### modifier:"));
        assert!(prompt.contains("comm: ransomware"));
        assert!(prompt.contains("### already-taken-action:"));
        assert!(prompt.contains("response: KillProcessTree"));
        assert!(prompt.contains("### question:"));
        assert!(prompt.contains("ALREADY fired"));
    }

    /// C9 test #4: `render_batched_overflow_prompt` includes
    /// per-event sections + event_count + the overflow-specific
    /// correlation question.
    #[test]
    fn render_batched_overflow_prompt_includes_per_event_sections() {
        let pairs: Vec<(FimEvent, Verdict)> = (0..3)
            .map(|i| {
                (
                    fake_fim_event(
                        &format!("/home/u/doc{i}.docx"),
                        Some(&format!("/home/u/doc{i}.docx.crypted")),
                    ),
                    fake_critical_verdict("NN-L-FIM-010_RansomwareExtensionRename"),
                )
            })
            .collect();
        let prompt = render_batched_overflow_prompt(&pairs, "Combat");
        assert!(prompt.contains("### event: critical_fim_drift_batched_overflow"));
        assert!(prompt.contains("event_count: 3"));
        for i in 0..3 {
            assert!(
                prompt.contains(&format!("### event[{i}]:")),
                "missing event[{i}]"
            );
            assert!(prompt.contains(&format!("/home/u/doc{i}.docx")));
        }
        assert!(prompt.contains("ALREADY fired"));
        assert!(prompt.contains("Correlate them"));
    }

    /// C9 test #5: the §13 Q9 individual-cap fires after exactly
    /// DEFAULT_INDIVIDUAL_CAP_PER_MIN admits. The (cap+1)th
    /// call returns `BufferedForOverflow`, and subsequent
    /// calls AFTER the overflow bucket also drains return
    /// `Suppressed`.
    #[test]
    fn rate_limiter_individual_cap_then_overflow_then_suppressed() {
        let l = AdeFimRateLimiter::with_caps(3, 1);
        let start = Instant::now();
        // Three individual admits.
        for i in 0..3 {
            assert_eq!(
                l.try_consume_with_now(start),
                AdeAdmit::Individual,
                "admit {i} should pass"
            );
        }
        // Fourth admit — individual cap exhausted, overflow
        // bucket still has 1 → buffered.
        assert_eq!(l.try_consume_with_now(start), AdeAdmit::BufferedForOverflow);
        // Flush the overflow once — succeeds.
        assert!(l.try_flush_overflow_with_now(start));
        // Subsequent flush — overflow drained, returns false.
        assert!(!l.try_flush_overflow_with_now(start));
        // After overflow flush has consumed its token, further
        // consume() calls return Suppressed (both buckets empty).
        assert_eq!(l.try_consume_with_now(start), AdeAdmit::Suppressed);
    }

    /// C9 test #6: window roll-over refills both buckets.
    #[test]
    fn rate_limiter_window_roll_over_refills_both_buckets() {
        let l = AdeFimRateLimiter::with_caps(2, 1);
        let start = Instant::now();
        for _ in 0..2 {
            assert_eq!(l.try_consume_with_now(start), AdeAdmit::Individual);
        }
        assert_eq!(l.try_consume_with_now(start), AdeAdmit::BufferedForOverflow);
        // Advance past the 60-second window.
        let after = start + Duration::from_secs(61);
        // First admit in the new window should be Individual
        // again (cap refilled).
        assert_eq!(l.try_consume_with_now(after), AdeAdmit::Individual);
    }

    /// C9 test #7: `OverflowBuffer` drops the OLDEST when at
    /// cap (newest-wins policy per the module doc-comment).
    #[test]
    fn overflow_buffer_drops_oldest_when_at_cap() {
        let buf = OverflowBuffer::with_capacity(3);
        for i in 0..5 {
            buf.push(
                fake_fim_event(&format!("/file{i}"), None),
                fake_critical_verdict("NN-L-FIM-010_RansomwareExtensionRename"),
            );
        }
        let drained = buf.drain();
        // Cap is 3 → oldest 2 dropped → /file2, /file3, /file4
        // survived. Assert in arrival order.
        assert_eq!(drained.len(), 3);
        assert_eq!(drained[0].0.path, "/file2");
        assert_eq!(drained[1].0.path, "/file3");
        assert_eq!(drained[2].0.path, "/file4");
        // Buffer is now empty.
        assert!(buf.is_empty());
    }

    /// C9 test #8: disabling the batched tier
    /// (batched_overflow_per_min = 0) skips straight from the
    /// individual cap to Suppressed — useful for cost-sensitive
    /// deployments that prefer the simple cap.
    #[test]
    fn rate_limiter_zero_overflow_cap_skips_batched_tier() {
        let l = AdeFimRateLimiter::with_caps(2, 0);
        let start = Instant::now();
        for _ in 0..2 {
            assert_eq!(l.try_consume_with_now(start), AdeAdmit::Individual);
        }
        // Overflow bucket disabled → third consume goes
        // straight to Suppressed.
        assert_eq!(l.try_consume_with_now(start), AdeAdmit::Suppressed);
    }
}
