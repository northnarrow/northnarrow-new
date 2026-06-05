//! COMBAT graduated active-response ladder.
//!
//! ## Why this exists
//!
//! In V1, reaching `PostureKind::Combat` fired a single fire-and-forget
//! hook that ran `NetworkIsolator::engage()` — an immediate, host-wide
//! iptables/ip6tables DROP. A single (now multi-signal, post-BUG-032)
//! escalation cut the box off the network with no intermediate action.
//! That made COMBAT *dangerous*: a benign-but-anomalous burst could
//! isolate a healthy host, and the operator was blinded the moment it
//! happened.
//!
//! This module reframes COMBAT as **"enter active-response mode"**, not
//! "isolate". Reaching COMBAT engages a three-stage ladder; isolation is
//! the **last resort**, taken only when the threat cannot be contained at
//! the process level:
//!
//! 1. [`CombatStage::Investigate`] — network stays **up**. Identify the
//!    offending process(es), begin evidence capture, and apply a
//!    *surgical* per-PID egress block (so a real threat cannot exfiltrate
//!    while we analyse, without the full lockout — the host's management
//!    and evidence channels stay open). Time-bound: a deadline advances
//!    to NEUTRALIZE; an actively-exfiltrating/spreading threat *jumps
//!    ahead* immediately (the investigate window is never an exploitable
//!    free pass).
//! 2. [`CombatStage::Neutralize`] — kill + quarantine the offending
//!    process(es) and verify they are gone / not respawning. No network
//!    isolation. If neutralization is confirmed, the threat is contained
//!    without ever cutting the host off.
//! 3. [`CombatStage::Isolate`] — **only** if neutralization fails
//!    (unkillable, respawning, kernel-level, otherwise uncontainable):
//!    the existing full network isolation
//!    ([`crate::anti_tamper::network_isolate::NetworkIsolator::engage`]),
//!    released via the same Ed25519 admin-key path as today. By this
//!    point the dossier is already captured and emitted, so isolation
//!    does not blind the operator.
//!
//! ## Shape
//!
//! The ladder is a small state machine ([`LadderState`]) behind a
//! [`parking_lot::Mutex`], driven from three places in `main.rs`:
//!
//! - [`CombatLadder::engage`] — on the non-Combat → Combat edge (and via
//!   the posture combat-entry hook, so an admin-forced COMBAT engages it
//!   too). Idempotent: the first call opens the episode; later calls
//!   merge freshly-attributed offenders.
//! - [`CombatLadder::observe`] — every event while engaged, for the
//!   jump-ahead check (active exfil / lateral spread by an offender).
//! - [`CombatLadder::tick`] — a fast heartbeat that advances the
//!   time-bound INVESTIGATE deadline.
//!
//! The two side-effecting dependencies are injected as trait objects
//! ([`CombatActuator`], [`LadderEvidence`]) so the stage logic is unit
//! tested deterministically without touching the real kill / nftables /
//! iptables / audit machinery. The production wiring lives in
//! [`actuator`] / [`evidence`]; `main.rs` constructs the trio.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tracing::{info, warn};

use common::posture_types::TriggerType;
use common::Event;

pub mod actuator;
pub mod evidence;
pub mod protected;

#[cfg(test)]
mod tests;

pub use actuator::{CombatActuator, NeutralizeOutcome, SystemActuator};
pub use evidence::{AuditEvidence, LadderEvidence, StageTransition};
pub use protected::{NoProtectedProcs, ProtectedProcs, ProtectedReason, SystemProtectedProcs};

/// The active-response stage WITHIN COMBAT posture. Ordered by
/// invasiveness (`Investigate < Neutralize < Isolate`); the ladder only
/// ever advances upward within an episode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CombatStage {
    /// Network up. Capture evidence + surgical per-PID soft egress.
    Investigate,
    /// Kill + quarantine the offending process(es); verify contained.
    Neutralize,
    /// Last resort: full network isolation (admin-key release).
    Isolate,
}

impl CombatStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            CombatStage::Investigate => "INVESTIGATE",
            CombatStage::Neutralize => "NEUTRALIZE",
            CombatStage::Isolate => "ISOLATE",
        }
    }
}

impl core::fmt::Display for CombatStage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Tunables for the ladder. Production reads these from `main.rs`; tests
/// use a short window so the deadline path is cheap to exercise.
#[derive(Debug, Clone, Copy)]
pub struct LadderConfig {
    /// How long STAGE 1 INVESTIGATE runs before the deadline advances to
    /// NEUTRALIZE absent a jump-ahead. Bounded so the investigate window
    /// can never become an indefinite free pass for a slow threat.
    pub investigate_window: Duration,
}

impl Default for LadderConfig {
    fn default() -> Self {
        Self {
            // 30 s: long enough to capture a dossier and correlate, short
            // enough that a contained-but-confirmed threat is neutralized
            // promptly. The jump-ahead path pre-empts this for an
            // actively-exfiltrating threat.
            investigate_window: Duration::from_secs(30),
        }
    }
}

/// Live ladder state for one COMBAT episode. Only meaningful while
/// `engaged`; the timestamps are re-stamped on each `engage`/advance.
#[derive(Debug)]
struct LadderState {
    engaged: bool,
    stage: CombatStage,
    /// When the current `stage` was entered (drives the INVESTIGATE
    /// deadline). Monotonic — immune to wall-clock skew, like the posture
    /// FSM's own timers.
    stage_since: Instant,
    /// PIDs attributed to the threat this episode. Grows as `observe`
    /// sees the offender spawn children (lateral spread).
    offenders: BTreeSet<u32>,
    /// The posture trigger that drove COMBAT (telemetry / audit only).
    trigger: Option<TriggerType>,
    /// Set once STAGE 3 has run, so a repeat tick/observe is a no-op.
    isolated: bool,
    /// Set once a NEUTRALIZE attempt has run, so a repeat advance does
    /// not re-kill (the decision to escalate to ISOLATE is taken from
    /// that one attempt's outcome).
    neutralize_attempted: bool,
}

impl LadderState {
    fn idle(now: Instant) -> Self {
        Self {
            engaged: false,
            stage: CombatStage::Investigate,
            stage_since: now,
            offenders: BTreeSet::new(),
            trigger: None,
            isolated: false,
            neutralize_attempted: false,
        }
    }
}

/// The graduated active-response controller. Cheap to share (`Arc` it in
/// `main.rs`); all methods take `&self` and lock internally.
pub struct CombatLadder {
    state: Mutex<LadderState>,
    actuator: Box<dyn CombatActuator>,
    evidence: Box<dyn LadderEvidence>,
    /// Host-critical process guard. Consulted before every per-PID action
    /// so the ladder never kills / net-cuts PID 1, the agent, its
    /// watchdog, or the SSH service — it skips + logs them and escalates
    /// to ISOLATE instead. See [`protected`].
    protected: Box<dyn ProtectedProcs>,
    cfg: LadderConfig,
}

/// Internal: the side effects a stage transition must perform once the
/// state lock has been released. Computed under the lock (which mutates
/// the stage flags atomically), then executed WITHOUT the lock so a
/// blocking kill / iptables / audit shell-out never serialises against a
/// concurrent `current_stage()` reader or the other driver task.
enum LadderStep {
    /// Already at/past the target (or not engaged) — nothing to do.
    None,
    Neutralize {
        from: CombatStage,
        offenders: Vec<u32>,
        trigger: Option<TriggerType>,
    },
    Isolate {
        from: CombatStage,
        offenders: Vec<u32>,
        trigger: Option<TriggerType>,
    },
}

impl CombatLadder {
    pub fn new(
        actuator: Box<dyn CombatActuator>,
        evidence: Box<dyn LadderEvidence>,
        protected: Box<dyn ProtectedProcs>,
        cfg: LadderConfig,
    ) -> Self {
        Self {
            state: Mutex::new(LadderState::idle(Instant::now())),
            actuator,
            evidence,
            protected,
            cfg,
        }
    }

    /// Partition `pids` into `(actionable, spared)` — the host-critical
    /// processes (PID 1, the agent, its watchdog, sshd) are pulled out
    /// with their [`ProtectedReason`] and never handed to the actuator.
    fn split_protected(&self, pids: &[u32]) -> (Vec<u32>, Vec<(u32, ProtectedReason)>) {
        let mut actionable = Vec::new();
        let mut spared = Vec::new();
        for &pid in pids {
            match self.protected.protected_reason(pid) {
                Some(reason) => spared.push((pid, reason)),
                None => actionable.push(pid),
            }
        }
        (actionable, spared)
    }

    /// Current stage if a COMBAT episode is active, else `None`. Surfaced
    /// for `nn-admin status` and used by tests.
    pub fn current_stage(&self) -> Option<CombatStage> {
        let s = self.state.lock();
        if s.engaged {
            Some(s.stage)
        } else {
            None
        }
    }

    /// Snapshot of the offender PID set (test/telemetry helper).
    pub fn offenders(&self) -> Vec<u32> {
        self.state.lock().offenders.iter().copied().collect()
    }

    /// Enter (or re-confirm) active-response mode at STAGE 1 INVESTIGATE.
    ///
    /// Idempotent per episode: the first call opens the episode (records
    /// the offender + trigger, applies surgical soft egress, captures the
    /// initial dossier, and emits the INVESTIGATE audit entry). Later
    /// calls — e.g. the context-free combat-entry hook firing alongside
    /// the context-carrying `process_event` call — merely **merge** a
    /// freshly-attributed offender and soft-egress-block it. Reaching
    /// COMBAT does NOT isolate the network here; that is STAGE 3 only.
    pub fn engage(&self, offender: Option<u32>, trigger: Option<TriggerType>, now: Instant) {
        let mut s = self.state.lock();
        if !s.engaged {
            *s = LadderState::idle(now);
            s.engaged = true;
            s.stage = CombatStage::Investigate;
            s.stage_since = now;
            s.trigger = trigger;
            if let Some(pid) = offender {
                s.offenders.insert(pid);
            }
            let offenders: Vec<u32> = s.offenders.iter().copied().collect();
            let trig = s.trigger;
            // Drop the lock before side effects so the actuator/evidence
            // calls (which may shell out) don't serialise against a
            // concurrent `current_stage()` reader for longer than needed.
            drop(s);

            info!(
                target: "combat.ladder",
                stage = %CombatStage::Investigate,
                offenders = ?offenders,
                trigger = ?trig,
                "COMBAT: entered active-response mode — INVESTIGATE (network UP)"
            );
            // Surgical soft egress: block ONLY the offender(s) so a real
            // threat can't exfiltrate while we analyse, without the full
            // host lockout (management + evidence channels stay open).
            // A host-critical offender is SKIPPED (cutting sshd / the
            // agent / the watchdog / init mid-INVESTIGATE would lock the
            // operator out or blind the defender); INVESTIGATE keeps the
            // network up by design, so the proportionate escalation for a
            // confirmed protected offender is deferred to NEUTRALIZE.
            //
            // KNOWN GAP: because the surgical block is the one containment
            // that can never apply to a spared offender, a spared offender
            // has NO egress cut during the investigate window. Its
            // pre-deadline containment relies solely on the `observe`
            // jump-ahead, which today fires only on a fresh `TcpConnect`
            // (not `DnsQuery`, and not exfil over an already-established
            // socket). So a protected offender exfiltrating over DNS or a
            // pre-existing connection runs uncut until the deadline → ISOLATE
            // (default 30s). Tightening this (DNS in the jump-ahead, or a
            // shorter window for a spared offender) is a jump-ahead-semantics
            // change tracked as a follow-up.
            for pid in &offenders {
                if let Some(reason) = self.protected.protected_reason(*pid) {
                    warn!(
                        target: "combat.ladder",
                        pid,
                        protected = %reason,
                        "COMBAT: refusing surgical soft-egress on host-critical process — \
                         skipped (network left intact)"
                    );
                    continue;
                }
                self.actuator.soft_egress_block(*pid);
            }
            self.evidence.record_stage(&StageTransition {
                from: None,
                to: CombatStage::Investigate,
                trigger: trig,
                offenders: offenders.clone(),
                reason: "COMBAT entry — investigate first, network up".to_string(),
            });
            return;
        }

        // Already engaged: merge a newly-attributed offender. Still record
        // it (so the audit + any later NEUTRALIZE sees the full set), but
        // do NOT soft-cut a host-critical process.
        if let Some(pid) = offender {
            if s.offenders.insert(pid) {
                drop(s);
                info!(
                    target: "combat.ladder",
                    pid,
                    "COMBAT: additional offender attributed during active response"
                );
                if let Some(reason) = self.protected.protected_reason(pid) {
                    warn!(
                        target: "combat.ladder",
                        pid,
                        protected = %reason,
                        "COMBAT: refusing surgical soft-egress on host-critical offender — \
                         skipped (network left intact)"
                    );
                } else {
                    self.actuator.soft_egress_block(pid);
                }
            }
        }
    }

    /// Feed one event to the ladder for the jump-ahead check. Called for
    /// every event while engaged. If the offender is actively
    /// exfiltrating (outbound connect to a non-loopback destination) or
    /// spreading (spawning a child) DURING INVESTIGATE, the ladder
    /// advances immediately — the investigate window must never let a
    /// fast threat run free.
    pub fn observe(&self, event: &Event, now: Instant) {
        // Decide under the lock (attribute spread, evaluate jump-ahead),
        // then RELEASE the lock before any side effect — so a kill /
        // iptables / audit shell-out triggered by a jump-ahead never
        // serialises against `current_stage()` or the tick task.
        enum Next {
            Idle,
            JumpAhead(&'static str),
            SoftBlock(u32),
        }
        let next = {
            let mut s = self.state.lock();
            if !s.engaged {
                Next::Idle
            } else {
                // Lateral spread: an offender spawned a child → attribute it.
                let mut spread_child: Option<u32> = None;
                if let Event::ProcessSpawn { pid, ppid, .. } = event {
                    if s.offenders.contains(ppid) && s.offenders.insert(*pid) {
                        spread_child = Some(*pid);
                    }
                }
                // Active exfil: an offender opened an outbound connection
                // to a non-loopback destination.
                let exfil = match event {
                    Event::TcpConnect {
                        pid,
                        family,
                        dst_addr,
                        ..
                    } => s.offenders.contains(pid) && !is_loopback(*family, dst_addr),
                    _ => false,
                };
                if s.stage == CombatStage::Investigate && (spread_child.is_some() || exfil) {
                    Next::JumpAhead(if exfil {
                        "jump-ahead: offender active exfiltration during INVESTIGATE"
                    } else {
                        "jump-ahead: offender spawning children (lateral spread) during INVESTIGATE"
                    })
                } else if let Some(child) = spread_child {
                    // Spread after INVESTIGATE (already neutralizing /
                    // isolated): soft-egress the newly-attributed child.
                    Next::SoftBlock(child)
                } else {
                    Next::Idle
                }
            }
        };
        match next {
            Next::Idle => {}
            Next::JumpAhead(reason) => self.drive_to(CombatStage::Neutralize, now, reason),
            Next::SoftBlock(pid) => {
                if let Some(reason) = self.protected.protected_reason(pid) {
                    warn!(
                        target: "combat.ladder",
                        pid,
                        protected = %reason,
                        "COMBAT: refusing surgical soft-egress on host-critical spread child — \
                         skipped (network left intact)"
                    );
                } else {
                    self.actuator.soft_egress_block(pid);
                }
            }
        }
    }

    /// Heartbeat: advance the time-bound INVESTIGATE deadline. A no-op
    /// unless engaged and the investigate window has elapsed.
    pub fn tick(&self, now: Instant) {
        // Read the deadline under a short lock; act (if due) without it.
        // A racing observe()-jump-ahead may have already advanced past
        // INVESTIGATE between this check and `drive_to`'s own lock —
        // `drive_to` re-checks under the lock and no-ops, so the two
        // drivers never double-act.
        let due = {
            let s = self.state.lock();
            s.engaged
                && s.stage == CombatStage::Investigate
                && now.saturating_duration_since(s.stage_since) >= self.cfg.investigate_window
        };
        if due {
            self.drive_to(
                CombatStage::Neutralize,
                now,
                "INVESTIGATE deadline elapsed — proceed to NEUTRALIZE",
            );
        }
    }

    /// Stand down — admin released COMBAT. Clears the episode, lifts the
    /// surgical soft-egress blocks. (The full-isolation iptables teardown
    /// is performed by the posture release hook via
    /// `NetworkIsolator::release`, which holds the Ed25519 `UnlockToken`.)
    pub fn stand_down(&self, now: Instant) {
        let mut s = self.state.lock();
        if !s.engaged {
            return;
        }
        let offenders: Vec<u32> = s.offenders.iter().copied().collect();
        let from = s.stage;
        *s = LadderState::idle(now);
        drop(s);
        info!(
            target: "combat.ladder",
            from = %from,
            "COMBAT: admin stand-down — active response cleared"
        );
        for pid in offenders {
            self.actuator.soft_egress_clear(pid);
        }
    }

    /// Advance to `target`, performing each stage's evidence + actuator
    /// side effects WITHOUT holding the state lock across them. Each
    /// `(mutate-state, drop-lock, side-effect)` is a distinct critical
    /// section, so a blocking kill / iptables / audit shell-out never
    /// serialises against `current_stage()` or the other driver task.
    ///
    /// NEUTRALIZE chains into ISOLATE when the threat is uncontainable.
    /// The `neutralize_attempted` / `isolated` flags persist in the state
    /// across the re-lock gap, so a racing tick + observe-jump-ahead can
    /// never double-neutralize or double-isolate (the second caller's
    /// under-lock check yields [`LadderStep::None`]). Evidence for a stage
    /// is ALWAYS emitted before that stage's enforcement action — so the
    /// dossier precedes any isolation in every COMBAT case.
    fn drive_to(&self, target: CombatStage, now: Instant, reason: &str) {
        let mut target = target;
        let mut reason = reason.to_string();
        loop {
            // ── Critical section: decide + mutate state, extract work ──
            let step = {
                let mut s = self.state.lock();
                if !s.engaged {
                    LadderStep::None
                } else {
                    match target {
                        CombatStage::Neutralize => {
                            if s.neutralize_attempted || s.stage >= CombatStage::Neutralize {
                                LadderStep::None
                            } else {
                                let from = s.stage;
                                s.neutralize_attempted = true;
                                s.stage = CombatStage::Neutralize;
                                s.stage_since = now;
                                LadderStep::Neutralize {
                                    from,
                                    offenders: s.offenders.iter().copied().collect(),
                                    trigger: s.trigger,
                                }
                            }
                        }
                        CombatStage::Isolate => {
                            if s.isolated {
                                LadderStep::None
                            } else {
                                let from = s.stage;
                                s.isolated = true;
                                s.stage = CombatStage::Isolate;
                                s.stage_since = now;
                                LadderStep::Isolate {
                                    from,
                                    offenders: s.offenders.iter().copied().collect(),
                                    trigger: s.trigger,
                                }
                            }
                        }
                        CombatStage::Investigate => LadderStep::None,
                    }
                }
            }; // ── state lock RELEASED here, before any side effect ──

            match step {
                LadderStep::None => return,
                LadderStep::Neutralize {
                    from,
                    offenders,
                    trigger,
                } => {
                    // Pull host-critical processes out of the kill set: the
                    // ladder never SIGKILLs init / the agent / its watchdog
                    // / sshd. A spared offender is logged here and, because
                    // we refused to kill it, is by definition uncontainable
                    // at the process level — so it drives the escalation to
                    // ISOLATE below.
                    let (actionable, spared) = self.split_protected(&offenders);
                    for (pid, why) in &spared {
                        warn!(
                            target: "combat.ladder",
                            pid,
                            protected = %why,
                            "COMBAT: NEUTRALIZE refusing to kill host-critical offender — \
                             spared; threat to be contained at the network level (ISOLATE)"
                        );
                    }
                    warn!(
                        target: "combat.ladder",
                        offenders = ?actionable,
                        spared = ?spared.iter().map(|(p, _)| *p).collect::<Vec<_>>(),
                        reason = %reason,
                        "COMBAT: NEUTRALIZE — kill + quarantine offending process(es), no isolation"
                    );
                    // Evidence FIRST — captured/emitted before the
                    // neutralization (and before any later isolation). The
                    // record carries the FULL attributed set plus a note of
                    // who was spared, so the audit trail is complete.
                    let neutralize_reason = if spared.is_empty() {
                        reason.clone()
                    } else {
                        format!(
                            "{reason} | host-critical offenders spared (not killed): {}",
                            fmt_protected(&spared)
                        )
                    };
                    self.evidence.record_stage(&StageTransition {
                        from: Some(from),
                        to: CombatStage::Neutralize,
                        trigger,
                        offenders: offenders.clone(),
                        reason: neutralize_reason,
                    });

                    // Every offender host-critical → nothing to kill. Go
                    // straight to ISOLATE without troubling the actuator
                    // (calling neutralize(&[]) would mislabel the cause as
                    // "no offender attributed").
                    if actionable.is_empty() && !spared.is_empty() {
                        warn!(
                            target: "combat.ladder",
                            "COMBAT: all attributed offenders are host-critical and were spared — \
                             escalating to ISOLATE (last resort)"
                        );
                        reason = format!(
                            "all attributed offenders host-critical, spared: {}",
                            fmt_protected(&spared)
                        );
                        target = CombatStage::Isolate;
                        continue;
                    }

                    match self.actuator.neutralize(&actionable) {
                        NeutralizeOutcome::Contained if spared.is_empty() => {
                            info!(
                                target: "combat.ladder",
                                offenders = ?actionable,
                                "COMBAT: threat NEUTRALIZED and verified contained — \
                                 host stays on the network (no isolation)"
                            );
                            return;
                        }
                        NeutralizeOutcome::Contained => {
                            // Killable offenders contained, but a spared
                            // host-critical offender remains implicated and
                            // could not be neutralized → escalate.
                            warn!(
                                target: "combat.ladder",
                                spared = ?spared.iter().map(|(p, _)| *p).collect::<Vec<_>>(),
                                "COMBAT: actionable offenders contained but host-critical offender(s) \
                                 spared — escalating to ISOLATE (cannot contain them at process level)"
                            );
                            reason = format!(
                                "host-critical offender(s) spared, cannot contain at process level: {}",
                                fmt_protected(&spared)
                            );
                            target = CombatStage::Isolate;
                            // loop → ISOLATE (fresh critical section)
                        }
                        NeutralizeOutcome::Uncontainable { reason: why } => {
                            warn!(
                                target: "combat.ladder",
                                offenders = ?actionable,
                                why,
                                "COMBAT: neutralization INSUFFICIENT — escalating to ISOLATE (last resort)"
                            );
                            reason = format!("neutralization failed: {why}");
                            target = CombatStage::Isolate;
                            // loop → ISOLATE (fresh critical section)
                        }
                    }
                }
                LadderStep::Isolate {
                    from,
                    offenders,
                    trigger,
                } => {
                    warn!(
                        target: "combat.ladder",
                        offenders = ?offenders,
                        reason = %reason,
                        "COMBAT: ISOLATE (last resort) — engaging full network isolation"
                    );
                    // Evidence FIRST — emitted before the iptables DROP,
                    // so isolation never blinds the operator.
                    self.evidence.record_stage(&StageTransition {
                        from: Some(from),
                        to: CombatStage::Isolate,
                        trigger,
                        offenders,
                        reason: reason.clone(),
                    });
                    self.actuator.isolate();
                    return;
                }
            }
        }
    }
}

/// Render the spared host-critical offenders for an audit reason string,
/// e.g. `ssh-service(sshd) (pid 4242), northnarrow-watchdog (pid 4300)`.
fn fmt_protected(spared: &[(u32, ProtectedReason)]) -> String {
    spared
        .iter()
        .map(|(pid, reason)| format!("{reason} (pid {pid})"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// True if `addr` (interpreted per `family`: 2 = AF_INET, 10 = AF_INET6)
/// is a loopback address. Outbound connects to loopback are not exfil and
/// must not trigger the jump-ahead.
fn is_loopback(family: u8, addr: &[u8]) -> bool {
    const AF_INET: u8 = 2;
    const AF_INET6: u8 = 10;
    match family {
        AF_INET => addr.first().copied() == Some(127),
        AF_INET6 => {
            // ::1 — fifteen zero bytes then 0x01.
            addr.len() >= 16 && addr[..15].iter().all(|b| *b == 0) && addr[15] == 1
        }
        _ => false,
    }
}
