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

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tracing::{info, warn};

use common::posture_types::TriggerType;
use common::Event;

pub mod actuator;
pub mod evidence;
pub mod protected;
pub mod reconcile;

#[cfg(test)]
mod tests;

pub use crate::response::proc_ref::ProcRef;
pub use actuator::{CombatActuator, NeutralizeOutcome, SoftBlock, SystemActuator};
pub use evidence::{AuditEvidence, EvidenceCounts, LadderEvidence, StageTransition, Unrecorded};
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
    /// External audit CMB-014: the INVESTIGATE window of an episode in
    /// which a soft egress block did not take effect — the offender is
    /// not contained while we analyse, so the analysis is shorter.
    pub failed_block_window: Duration,
    /// External audit CMB-011: the most processes attributed to one
    /// episode. A tree that grows past it is not containable process by
    /// process: the ladder escalates instead of attributing more.
    pub max_offenders: usize,
}

impl Default for LadderConfig {
    fn default() -> Self {
        Self {
            // 30 s: long enough to capture a dossier and correlate, short
            // enough that a contained-but-confirmed threat is neutralized
            // promptly. The jump-ahead path pre-empts this for an
            // actively-exfiltrating threat.
            investigate_window: Duration::from_secs(30),
            failed_block_window: Duration::from_secs(10),
            max_offenders: 1024,
        }
    }
}

/// Live ladder state for one COMBAT episode. Only meaningful while
/// `engaged`; the timestamps are re-stamped on each `engage`/advance.
#[derive(Debug)]
struct LadderState {
    engaged: bool,
    /// External audit CMB-012: bumped when an episode opens and at
    /// stand-down; the worker drops a queued step of another episode.
    episode: u64,
    stage: CombatStage,
    /// When the current `stage` was entered (drives the INVESTIGATE
    /// deadline). Monotonic — immune to wall-clock skew, like the posture
    /// FSM's own timers.
    stage_since: Instant,
    /// PIDs attributed to the threat this episode. Grows as `observe`
    /// sees the offender spawn children (lateral spread), up to
    /// [`LadderConfig::max_offenders`]. External audit CMB-004: each one
    /// captured (pidfd + start time) when it was attributed — the actions
    /// reach that process, never a later holder of its PID.
    offenders: BTreeMap<u32, Arc<ProcRef>>,
    /// External audit CMB-010: the processes the actuator reported
    /// blocked this episode — the only ones the stand-down releases.
    blocked: BTreeMap<u32, Arc<ProcRef>>,
    /// External audit CMB-014: a soft egress block of this episode did
    /// not take effect (the shorter window applies).
    block_failed: bool,
    /// External audit CMB-011: the offender set reached its cap.
    attribution_capped: bool,
    /// A stage advance is queued and has not started: the tick and the
    /// jump-ahead do not queue another.
    drive_queued: bool,
    /// The posture trigger that drove COMBAT (telemetry / audit only).
    trigger: Option<TriggerType>,
    /// Set once STAGE 3 has run, so a repeat tick/observe is a no-op.
    isolated: bool,
    /// Set once a NEUTRALIZE attempt has run, so a repeat advance does
    /// not re-kill (the decision to escalate to ISOLATE is taken from
    /// that one attempt's outcome).
    neutralize_attempted: bool,
    /// External audit POS-001: why the ladder wanted to isolate when the
    /// isolation gate was closed. The tick retries once the gate opens
    /// (the posture locked COMBAT on later evidence).
    isolation_deferred: Option<String>,
}

impl LadderState {
    fn idle(now: Instant, episode: u64) -> Self {
        Self {
            engaged: false,
            episode,
            stage: CombatStage::Investigate,
            stage_since: now,
            offenders: BTreeMap::new(),
            blocked: BTreeMap::new(),
            block_failed: false,
            attribution_capped: false,
            drive_queued: false,
            trigger: None,
            isolated: false,
            neutralize_attempted: false,
            isolation_deferred: None,
        }
    }

    /// The INVESTIGATE window that applies to this episode.
    fn investigate_window(&self, cfg: &LadderConfig) -> Duration {
        if self.block_failed {
            cfg.investigate_window.min(cfg.failed_block_window)
        } else {
            cfg.investigate_window
        }
    }
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
        /// The attributed processes (external audit CMB-004).
        refs: Vec<Arc<ProcRef>>,
        trigger: Option<TriggerType>,
    },
    /// External audit POS-001: ISOLATE was due but the gate is closed.
    IsolationRefused {
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

/// The ladder's decisions and the side effects that carry them out.
struct Inner {
    state: Mutex<LadderState>,
    actuator: Box<dyn CombatActuator>,
    evidence: Box<dyn LadderEvidence>,
    /// Host-critical process guard. Consulted before every per-PID action
    /// so the ladder never kills / net-cuts PID 1, the agent, its
    /// watchdog, or the SSH service — it skips + logs them and escalates
    /// to ISOLATE instead. See [`protected`].
    protected: Box<dyn ProtectedProcs>,
    cfg: LadderConfig,
    /// External audit POS-001 (NN-AUD-002): whether ISOLATE may run.
    /// Production asks the posture whether COMBAT is locked — reached on
    /// evidence an unprivileged user cannot produce, or forced by an
    /// administrator. On heuristics alone the ladder stops at the process
    /// level. Default: always (tests, callers without a posture).
    isolation_gate: Box<dyn Fn() -> bool + Send + Sync>,
}

/// A side effect of the ladder, run in order by [`Runner`].
enum Job {
    /// An episode opened: soft-block its offenders, record INVESTIGATE.
    Investigate {
        episode: u64,
        offenders: Vec<Arc<ProcRef>>,
        trigger: Option<TriggerType>,
    },
    /// Soft-block an offender attributed later in the episode.
    SoftBlock { episode: u64, target: Arc<ProcRef> },
    /// Advance the episode to `target` (decided again when it runs).
    Drive {
        episode: u64,
        target: CombatStage,
        now: Instant,
        reason: String,
    },
    /// Release what the closed episode blocked; `done` is told once the
    /// release ran (every earlier job ran before it).
    StandDown {
        from: CombatStage,
        blocked: Vec<Arc<ProcRef>>,
        done: Option<std::sync::mpsc::SyncSender<()>>,
    },
}

/// How jobs run: in the caller (unit tests, and the fallback when the
/// worker thread cannot start) or on the ladder's worker thread.
enum Runner {
    Inline,
    Worker(std::sync::mpsc::SyncSender<Job>),
}

/// Jobs waiting for the worker. An episode queues at most one job per
/// attributed offender plus a few stage advances.
const QUEUE_DEPTH: usize = 4096;

/// The graduated active-response controller. Cheap to share (`Arc` it in
/// `main.rs`); all methods take `&self` and lock internally.
///
/// External audit CMB-007: the decisions are taken under the state lock
/// in the caller (the event loop, the tick, the posture hooks); their
/// side effects — `nft`, cgroup writes, kills with their verification,
/// quarantine, iptables, the signed audit entries — run in order on one
/// worker thread ([`CombatLadder::with_worker`]). A NEUTRALIZE of a large
/// tree no longer stops the event loop, and the two drivers and the
/// stand-down are serialised by the queue (CMB-012).
pub struct CombatLadder {
    inner: Arc<Inner>,
    runner: Runner,
}

impl CombatLadder {
    pub fn new(
        actuator: Box<dyn CombatActuator>,
        evidence: Box<dyn LadderEvidence>,
        protected: Box<dyn ProtectedProcs>,
        cfg: LadderConfig,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(LadderState::idle(Instant::now(), 0)),
                actuator,
                evidence,
                protected,
                cfg,
                isolation_gate: Box::new(|| true),
            }),
            runner: Runner::Inline,
        }
    }

    /// External audit POS-001: ISOLATE runs only while `gate` says so.
    /// Call before [`Self::with_worker`].
    pub fn with_isolation_gate(mut self, gate: impl Fn() -> bool + Send + Sync + 'static) -> Self {
        match Arc::get_mut(&mut self.inner) {
            Some(inner) => inner.isolation_gate = Box::new(gate),
            None => warn!(
                target: "combat.ladder",
                "isolation gate set after the worker started — ignored"
            ),
        }
        self
    }

    /// External audit CMB-007: run the side effects on a worker thread of
    /// their own. Without it (unit tests) they run in the caller.
    pub fn with_worker(mut self) -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel::<Job>(QUEUE_DEPTH);
        let inner = Arc::clone(&self.inner);
        match std::thread::Builder::new()
            .name("nn-combat-ladder".into())
            .spawn(move || {
                for job in rx {
                    inner.run(job);
                }
            }) {
            Ok(_) => self.runner = Runner::Worker(tx),
            Err(e) => tracing::error!(
                target: "combat.ladder",
                error = %e,
                "COMBAT ladder worker could not start — side effects run on the caller"
            ),
        }
        self
    }

    /// Current stage if a COMBAT episode is active, else `None`. Surfaced
    /// for `nn-admin status` and used by tests. With the worker, the
    /// stage is the decided one; its side effects may still be queued.
    pub fn current_stage(&self) -> Option<CombatStage> {
        let s = self.inner.state.lock();
        if s.engaged {
            Some(s.stage)
        } else {
            None
        }
    }

    /// External audit CMB-027: the stage transitions the signed audit log
    /// did not get when they happened, for `nn-admin status`.
    pub fn evidence_counts(&self) -> EvidenceCounts {
        self.inner.evidence.counts()
    }

    /// Snapshot of the offender PID set (test/telemetry helper).
    pub fn offenders(&self) -> Vec<u32> {
        self.inner.state.lock().offenders.keys().copied().collect()
    }

    /// Hand `job` to the runner. A full queue drops a soft block or a
    /// stage advance (the tick queues the advance again); an episode
    /// opening or a stand-down waits for room.
    fn dispatch(&self, job: Job) {
        let tx = match &self.runner {
            Runner::Inline => return self.inner.run(job),
            Runner::Worker(tx) => tx,
        };
        let must_run = matches!(job, Job::Investigate { .. } | Job::StandDown { .. });
        let res = if must_run {
            tx.send(job)
                .map_err(|e| std::sync::mpsc::TrySendError::Disconnected(e.0))
        } else {
            tx.try_send(job)
        };
        match res {
            Ok(()) => {}
            Err(std::sync::mpsc::TrySendError::Full(job)) => {
                if let Job::Drive { .. } = job {
                    self.inner.state.lock().drive_queued = false;
                }
                warn!(
                    target: "combat.ladder",
                    "COMBAT: the ladder's queue is full — a step was dropped (an advance is queued again by the tick)"
                );
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => tracing::error!(
                target: "combat.ladder",
                "COMBAT: the ladder worker is gone — step not run"
            ),
        }
    }

    /// Queue an advance to `target` unless one is queued already.
    fn queue_drive(
        &self,
        s: &mut LadderState,
        target: CombatStage,
        now: Instant,
        reason: &str,
    ) -> Option<Job> {
        if s.drive_queued {
            return None;
        }
        s.drive_queued = true;
        Some(Job::Drive {
            episode: s.episode,
            target,
            now,
            reason: reason.to_string(),
        })
    }

    /// Attribute `pid` to the episode, within the cap, capturing the
    /// process (external audit CMB-004; `start_ns` from its exec event,
    /// `seen_ns` the attributing event's time, 0 when unknown). `Ok(Some)`
    /// with the new offender; `Err` once the cap is reached (the first time
    /// only: `Err(true)`).
    fn attribute(
        &self,
        s: &mut LadderState,
        pid: u32,
        start_ns: u64,
        seen_ns: u64,
    ) -> Result<Option<Arc<ProcRef>>, bool> {
        // External audit CMB-004: the PID of an offender that has exited
        // may name a new process by now — attributed afresh, in its place.
        let reused = match s.offenders.get(&pid) {
            Some(known) if self.inner.actuator.same_process(known, start_ns) => return Ok(None),
            known => known.is_some(),
        };
        if !reused && s.offenders.len() >= self.inner.cfg.max_offenders {
            let first = !s.attribution_capped;
            s.attribution_capped = true;
            return Err(first);
        }
        let target = self.inner.actuator.identify(pid, start_ns, seen_ns);
        s.offenders.insert(pid, Arc::clone(&target));
        Ok(Some(target))
    }

    /// External audit CMB-011: the step for a tree past the cap — not
    /// containable process by process. During INVESTIGATE, neutralize
    /// now; past it, ask for ISOLATE (through the gate).
    fn capped_step(&self, s: &mut LadderState, now: Instant) -> Option<Job> {
        let cap = self.inner.cfg.max_offenders;
        warn!(
            target: "combat.ladder",
            cap,
            "COMBAT: the offender tree grew past the attribution cap — not containable process by process"
        );
        if s.stage == CombatStage::Investigate {
            self.queue_drive(
                s,
                CombatStage::Neutralize,
                now,
                &format!("jump-ahead: offender tree past {cap} processes during INVESTIGATE"),
            )
        } else {
            // Not through `drive_queued`: an ISOLATE asked while a
            // NEUTRALIZE is queued still has to run after it.
            Some(Job::Drive {
                episode: s.episode,
                target: CombatStage::Isolate,
                now,
                reason: format!(
                    "offender tree past {cap} processes: not containable at the process level"
                ),
            })
        }
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
        self.engage_with(offender, 0, 0, trigger, now);
    }

    /// [`Self::engage`] with what the event that names the offender says
    /// about it (external audit CMB-004): `start_ns`, its exec's start,
    /// and `seen_ns`, the event's time (it was running then) — 0 when
    /// unknown. They identify it after it has exited: the events of the
    /// children it left are matched to it, not to a later holder of its
    /// PID.
    pub fn engage_with(
        &self,
        offender: Option<u32>,
        start_ns: u64,
        seen_ns: u64,
        trigger: Option<TriggerType>,
        now: Instant,
    ) {
        let job = {
            let mut s = self.inner.state.lock();
            if !s.engaged {
                let episode = s.episode + 1;
                *s = LadderState::idle(now, episode);
                s.engaged = true;
                s.stage = CombatStage::Investigate;
                s.stage_since = now;
                s.trigger = trigger;
                if let Some(pid) = offender {
                    let target = self.inner.actuator.identify(pid, start_ns, seen_ns);
                    s.offenders.insert(pid, target);
                }
                let offenders: Vec<Arc<ProcRef>> = s.offenders.values().cloned().collect();
                info!(
                    target: "combat.ladder",
                    stage = %CombatStage::Investigate,
                    offenders = ?s.offenders.keys().collect::<Vec<_>>(),
                    trigger = ?trigger,
                    "COMBAT: entered active-response mode — INVESTIGATE (network UP)"
                );
                Some(Job::Investigate {
                    episode,
                    offenders,
                    trigger,
                })
            } else if let Some(pid) = offender {
                // Already engaged: merge a newly-attributed offender (so
                // the audit + any later NEUTRALIZE sees the full set).
                match self.attribute(&mut s, pid, start_ns, seen_ns) {
                    Ok(Some(target)) => {
                        info!(
                            target: "combat.ladder",
                            pid,
                            "COMBAT: additional offender attributed during active response"
                        );
                        Some(Job::SoftBlock {
                            episode: s.episode,
                            target,
                        })
                    }
                    Ok(None) | Err(false) => None,
                    Err(true) => self.capped_step(&mut s, now),
                }
            } else {
                None
            }
        };
        if let Some(job) = job {
            self.dispatch(job);
        }
    }

    /// Feed one event to the ladder for the jump-ahead check. Called for
    /// every event while engaged. If the offender is actively
    /// exfiltrating (outbound connect to a non-loopback destination) or
    /// spreading (spawning a child) DURING INVESTIGATE, the ladder
    /// advances immediately — the investigate window must never let a
    /// fast threat run free.
    pub fn observe(&self, event: &Event, now: Instant) {
        // Decide under the lock (attribute spread, evaluate jump-ahead);
        // the side effects are queued (external audit CMB-007).
        let job = {
            let mut s = self.inner.state.lock();
            if !s.engaged {
                None
            } else {
                // Lateral spread: an offender spawned a child → attribute it.
                let mut spread_child: Option<Arc<ProcRef>> = None;
                let mut capped = false;
                if let Event::ProcessSpawn {
                    pid,
                    ppid,
                    start_ns,
                    parent_start_ns,
                    timestamp_ns,
                    ..
                } = event
                {
                    // External audit CMB-004: the parent is the offender,
                    // not a process that took its PID after it exited.
                    let from_offender = s
                        .offenders
                        .get(ppid)
                        .is_some_and(|p| self.inner.actuator.same_process(p, *parent_start_ns));
                    if from_offender {
                        match self.attribute(&mut s, *pid, *start_ns, *timestamp_ns) {
                            Ok(Some(target)) => spread_child = Some(target),
                            Ok(None) | Err(false) => {}
                            Err(true) => capped = true,
                        }
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
                    } => {
                        s.offenders
                            .get(pid)
                            .is_some_and(|r| self.inner.actuator.same_process(r, 0))
                            && !is_loopback(*family, dst_addr)
                    }
                    _ => false,
                };
                if capped {
                    self.capped_step(&mut s, now)
                } else if s.stage == CombatStage::Investigate && (spread_child.is_some() || exfil) {
                    let reason = if exfil {
                        "jump-ahead: offender active exfiltration during INVESTIGATE"
                    } else {
                        "jump-ahead: offender spawning children (lateral spread) during INVESTIGATE"
                    };
                    // The child is attributed; the NEUTRALIZE kills the
                    // tree it belongs to.
                    self.queue_drive(&mut s, CombatStage::Neutralize, now, reason)
                } else {
                    // Spread after INVESTIGATE (already neutralizing /
                    // isolated): soft-egress the newly-attributed child.
                    spread_child.map(|target| Job::SoftBlock {
                        episode: s.episode,
                        target,
                    })
                }
            }
        };
        if let Some(job) = job {
            self.dispatch(job);
        }
    }

    /// Heartbeat: advance the time-bound INVESTIGATE deadline. A no-op
    /// unless engaged and the investigate window has elapsed.
    pub fn tick(&self, now: Instant) {
        let due = {
            let mut s = self.inner.state.lock();
            if s.engaged
                && s.stage == CombatStage::Investigate
                && now.saturating_duration_since(s.stage_since)
                    >= s.investigate_window(&self.inner.cfg)
            {
                let reason = if s.block_failed {
                    "INVESTIGATE deadline elapsed (shortened: a soft egress block did not take effect) — proceed to NEUTRALIZE"
                } else {
                    "INVESTIGATE deadline elapsed — proceed to NEUTRALIZE"
                };
                self.queue_drive(&mut s, CombatStage::Neutralize, now, reason)
            } else {
                None
            }
        };
        if let Some(job) = due {
            self.dispatch(job);
        }
        // External audit POS-001: an isolation refused while COMBAT rested
        // on heuristics runs once the posture locks COMBAT. The gate is
        // asked without the ladder's lock (the posture's lock is never
        // taken under it).
        let deferred = {
            let s = self.inner.state.lock();
            if s.engaged && !s.isolated && !s.drive_queued {
                s.isolation_deferred.clone()
            } else {
                None
            }
        };
        if let Some(why) = deferred {
            if (self.inner.isolation_gate)() {
                let job = {
                    let mut s = self.inner.state.lock();
                    if s.engaged && !s.isolated {
                        self.queue_drive(
                            &mut s,
                            CombatStage::Isolate,
                            now,
                            &format!("{why} — COMBAT since locked on non-heuristic evidence"),
                        )
                    } else {
                        None
                    }
                };
                if let Some(job) = job {
                    self.dispatch(job);
                }
            }
        }
    }

    /// Stand down — admin released COMBAT, or (external audit POS-001) an
    /// unlocked COMBAT decayed. Clears the episode, lifts the
    /// surgical soft-egress blocks. (The full-isolation iptables teardown
    /// is performed by the posture release hook via
    /// `NetworkIsolator::release`, which holds the Ed25519 `UnlockToken`.)
    pub fn stand_down(&self, now: Instant) {
        self.stand_down_inner(now, None);
    }

    /// [`Self::stand_down`], returning once every step queued before it
    /// — an ISOLATE among them — has run, or after `wait`. External audit
    /// CMB-012: the release hook lifts the iptables isolation only after
    /// this, so a step taken just before an admin unlock cannot isolate
    /// the host after the release.
    pub fn stand_down_and_wait(&self, now: Instant, wait: Duration) {
        self.stand_down_inner(now, Some(wait));
    }

    fn stand_down_inner(&self, now: Instant, wait: Option<Duration>) {
        let job = {
            let mut s = self.inner.state.lock();
            if !s.engaged {
                return;
            }
            let from = s.stage;
            // External audit CMB-010 (stop-gap): only what this episode
            // blocked is released — not every attributed PID.
            let blocked: Vec<Arc<ProcRef>> = s.blocked.values().cloned().collect();
            let episode = s.episode + 1;
            *s = LadderState::idle(now, episode);
            info!(
                target: "combat.ladder",
                from = %from,
                "COMBAT: stand-down (admin release, or an unlocked COMBAT decayed) — \
                 active response cleared"
            );
            (from, blocked)
        };
        let (from, blocked) = job;
        let (done_tx, done_rx) = match wait {
            Some(_) => {
                let (tx, rx) = std::sync::mpsc::sync_channel(1);
                (Some(tx), Some(rx))
            }
            None => (None, None),
        };
        self.dispatch(Job::StandDown {
            from,
            blocked,
            done: done_tx,
        });
        if let (Some(rx), Some(wait)) = (done_rx, wait) {
            if rx.recv_timeout(wait).is_err() {
                warn!(
                    target: "combat.ladder",
                    wait_secs = wait.as_secs(),
                    "COMBAT: stand-down still queued behind a running step — releasing anyway"
                );
            }
        }
    }
}

impl Inner {
    /// External audit CMB-027: evidence before enforcement, checked. A
    /// transition the audit log did not take is logged here whole, at
    /// ERROR — then the journal line is its record until the sink writes it
    /// late — and the ladder proceeds: holding the next stage on the audit
    /// log would let whoever breaks it (fills its filesystem) prevent the
    /// containment.
    fn record(&self, t: StageTransition) {
        if let Err(why) = self.evidence.record_stage(&t) {
            tracing::error!(
                target: "combat.audit",
                from = t.from.map(|s| s.as_str()).unwrap_or("-"),
                to = %t.to,
                trigger = ?t.trigger,
                offenders = ?t.offenders,
                reason = %common::log_escape::Escaped(&t.reason),
                why = %why,
                "COMBAT stage transition NOT in the signed audit log — enforcement proceeds"
            );
        }
    }

    /// Run one job (on the worker, or inline).
    fn run(&self, job: Job) {
        let current = |episode: u64| {
            let s = self.state.lock();
            s.engaged && s.episode == episode
        };
        match job {
            Job::Investigate {
                episode,
                offenders,
                trigger,
            } => {
                if !current(episode) {
                    return self.dropped("INVESTIGATE");
                }
                self.actuator.begin_episode();
                // Surgical soft egress: block ONLY the offender(s) so a
                // real threat can't exfiltrate while we analyse, without
                // the full host lockout. A host-critical offender is
                // SKIPPED (cutting sshd / the agent / the watchdog / init
                // mid-INVESTIGATE would lock the operator out or blind the
                // defender); its escalation is deferred to NEUTRALIZE.
                //
                // KNOWN GAP: a spared offender has NO egress cut during
                // the investigate window; its pre-deadline containment is
                // the `observe` jump-ahead (a fresh `TcpConnect`), not DNS
                // or an established socket.
                let mut notes = Vec::new();
                for target in &offenders {
                    if let Some(note) = self.soft_block(episode, target, false) {
                        notes.push(note);
                    }
                }
                let mut reason = "COMBAT entry — investigate first, network up".to_string();
                if !notes.is_empty() {
                    reason.push_str(&format!(" | soft egress: {}", notes.join("; ")));
                }
                self.record(StageTransition {
                    from: None,
                    to: CombatStage::Investigate,
                    trigger,
                    offenders: offenders.iter().map(|r| r.pid()).collect(),
                    reason,
                });
            }
            Job::SoftBlock { episode, target } => {
                if !current(episode) {
                    return self.dropped("soft egress");
                }
                self.soft_block(episode, &target, true);
            }
            Job::Drive {
                episode,
                target,
                now,
                reason,
            } => {
                {
                    let mut s = self.state.lock();
                    if s.episode == episode {
                        s.drive_queued = false;
                    }
                }
                if !current(episode) {
                    return self.dropped(target.as_str());
                }
                self.drive_to(target, now, &reason);
                self.close_exited();
            }
            Job::StandDown {
                from,
                blocked,
                done,
            } => {
                info!(
                    target: "combat.ladder",
                    from = %from,
                    blocked = blocked.len(),
                    "COMBAT: stand-down — releasing the soft egress blocks of the closed episode"
                );
                for target in blocked {
                    self.actuator.soft_egress_clear(&target);
                }
                // External audit CMB-027: the episode's transitions the
                // audit log refused do not wait for the next episode.
                self.evidence.retry_pending();
                if let Some(done) = done {
                    let _ = done.try_send(());
                }
            }
        }
    }

    /// Close the pidfds of attributed processes that have exited — a
    /// NEUTRALIZE kills them, and a large episode would otherwise keep a
    /// descriptor per dead process until the stand-down.
    fn close_exited(&self) {
        let mut s = self.state.lock();
        let s = &mut *s;
        for map in [&mut s.offenders, &mut s.blocked] {
            for r in map.values_mut() {
                if r.has_fd() && !r.is_live() {
                    *r = Arc::new(r.without_fd());
                }
            }
        }
    }

    fn dropped(&self, what: &str) {
        info!(
            target: "combat.ladder",
            step = what,
            "COMBAT: a step of a closed episode was dropped"
        );
    }

    /// Soft-block one offender of `episode`; record the outcome in the
    /// state. Returns a note for the evidence when the block did not take
    /// effect or the process was spared. With `record`, the episode's
    /// first failed block is a signed record of its own (an offender
    /// attributed after the INVESTIGATE record was written).
    fn soft_block(&self, episode: u64, target: &Arc<ProcRef>, record: bool) -> Option<String> {
        let pid = target.pid();
        if self.is_gone(target) {
            return Some(format!("{pid} not blocked (process already exited)"));
        }
        if let Some(reason) = self.protected.protected_reason(pid) {
            warn!(
                target: "combat.ladder",
                pid,
                protected = %reason,
                "COMBAT: refusing surgical soft-egress on host-critical process — \
                 skipped (network left intact)"
            );
            return Some(format!("{pid} spared ({reason})"));
        }
        let outcome = self.actuator.soft_egress_block(target);
        let mut s = self.state.lock();
        let ours = s.engaged && s.episode == episode;
        match outcome {
            SoftBlock::Blocked => {
                if ours {
                    s.blocked.insert(pid, Arc::clone(target));
                } else {
                    // The episode closed while the block ran: its
                    // stand-down did not know this process — release it
                    // here, or it would stay blocked with no release.
                    drop(s);
                    info!(
                        target: "combat.ladder",
                        pid,
                        "COMBAT: a soft block finished after its episode closed — released"
                    );
                    self.actuator.soft_egress_clear(target);
                }
                None
            }
            SoftBlock::NotNeeded(why) => Some(format!("{pid} not blocked ({why})")),
            SoftBlock::Failed(why) => {
                // External audit CMB-014: the offender is not contained
                // while we analyse — the episode's INVESTIGATE is shorter.
                let first = ours && !s.block_failed;
                if ours {
                    s.block_failed = true;
                }
                let (stage, trigger) = (s.stage, s.trigger);
                drop(s);
                let window = self
                    .cfg
                    .investigate_window
                    .min(self.cfg.failed_block_window);
                warn!(
                    target: "combat.ladder",
                    pid,
                    why = %why,
                    window_secs = window.as_secs(),
                    "COMBAT: soft egress block did NOT take effect — the INVESTIGATE window is shortened"
                );
                if record && first {
                    self.record(StageTransition {
                        from: Some(stage),
                        to: stage,
                        trigger,
                        offenders: vec![pid],
                        reason: format!(
                            "soft egress: {pid} FAILED ({why}) — the offender is not contained; \
                             INVESTIGATE shortened to {} s",
                            window.as_secs()
                        ),
                    });
                }
                Some(format!("{pid} FAILED ({why})"))
            }
        }
    }

    /// Partition the offenders into `(actionable, spared)` — the
    /// host-critical processes (PID 1, the agent, its watchdog, sshd) are
    /// pulled out with their [`ProtectedReason`] and never handed to the
    /// actuator.
    /// External audit CMB-004: an offender that has exited is gone — the
    /// guard's lookup by PID would judge the process that holds the PID
    /// now (an sshd child, a restarted watchdog: spared, then ISOLATE).
    fn is_gone(&self, r: &ProcRef) -> bool {
        !self.actuator.same_process(r, 0) && r.capture_errno().is_none()
    }

    fn split_protected(
        &self,
        refs: &[Arc<ProcRef>],
    ) -> (Vec<Arc<ProcRef>>, Vec<(u32, ProtectedReason)>) {
        let mut actionable = Vec::new();
        let mut spared = Vec::new();
        for r in refs {
            if self.is_gone(r) {
                // the kill reports it gone
                actionable.push(Arc::clone(r));
                continue;
            }
            match self.protected.protected_reason(r.pid()) {
                Some(reason) => spared.push((r.pid(), reason)),
                None => actionable.push(Arc::clone(r)),
            }
        }
        (actionable, spared)
    }

    /// Advance to `target`, performing each stage's evidence + actuator
    /// side effects WITHOUT holding the state lock across them. Each
    /// `(mutate-state, drop-lock, side-effect)` is a distinct critical
    /// section, so a blocking kill / iptables / audit shell-out never
    /// serialises against `current_stage()` or the drivers.
    ///
    /// NEUTRALIZE chains into ISOLATE when the threat is uncontainable.
    /// The `neutralize_attempted` / `isolated` flags persist in the state
    /// across the re-lock gap, so a repeated advance can never
    /// double-neutralize or double-isolate (its under-lock check yields
    /// [`LadderStep::None`]). Evidence for a stage is ALWAYS emitted
    /// before that stage's enforcement action — so the dossier precedes
    /// any isolation in every COMBAT case.
    fn drive_to(&self, target: CombatStage, now: Instant, reason: &str) {
        let mut target = target;
        let mut reason = reason.to_string();
        loop {
            // External audit POS-001: asked before taking the state lock,
            // so the posture's lock is never taken under the ladder's.
            let isolation_allowed = target != CombatStage::Isolate || (self.isolation_gate)();
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
                                    offenders: s.offenders.keys().copied().collect(),
                                    refs: s.offenders.values().cloned().collect(),
                                    trigger: s.trigger,
                                }
                            }
                        }
                        CombatStage::Isolate => {
                            if s.isolated {
                                LadderStep::None
                            } else if !isolation_allowed {
                                if s.isolation_deferred.replace(reason.clone()).is_some() {
                                    LadderStep::None
                                } else {
                                    LadderStep::IsolationRefused {
                                        from: s.stage,
                                        offenders: s.offenders.keys().copied().collect(),
                                        trigger: s.trigger,
                                    }
                                }
                            } else {
                                let from = s.stage;
                                s.isolation_deferred = None;
                                s.isolated = true;
                                s.stage = CombatStage::Isolate;
                                s.stage_since = now;
                                LadderStep::Isolate {
                                    from,
                                    offenders: s.offenders.keys().copied().collect(),
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
                    refs,
                    trigger,
                } => {
                    // Pull host-critical processes out of the kill set: the
                    // ladder never SIGKILLs init / the agent / its watchdog
                    // / sshd. A spared offender is logged here and, because
                    // we refused to kill it, is by definition uncontainable
                    // at the process level — so it drives the escalation to
                    // ISOLATE below.
                    let (actionable, spared) = self.split_protected(&refs);
                    let actionable_pids: Vec<u32> = actionable.iter().map(|r| r.pid()).collect();
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
                        offenders = ?actionable_pids,
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
                    self.record(StageTransition {
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
                                offenders = ?actionable_pids,
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
                                offenders = ?actionable_pids,
                                why,
                                "COMBAT: neutralization INSUFFICIENT — escalating to ISOLATE (last resort)"
                            );
                            reason = format!("neutralization failed: {why}");
                            target = CombatStage::Isolate;
                            // loop → ISOLATE (fresh critical section)
                        }
                    }
                }
                LadderStep::IsolationRefused {
                    from,
                    offenders,
                    trigger,
                } => {
                    warn!(
                        target: "combat.ladder",
                        offenders = ?offenders,
                        reason = %reason,
                        "COMBAT: ISOLATE refused — COMBAT rests on heuristic evidence only \
                         (unlocked); containment stays at the process level until the \
                         posture locks COMBAT"
                    );
                    self.record(StageTransition {
                        from: Some(from),
                        to: from,
                        trigger,
                        offenders,
                        reason: format!(
                            "ISOLATE refused ({reason}): COMBAT rests on heuristic evidence only, \
                             which any local user can produce; the host stays on the network"
                        ),
                    });
                    return;
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
                    self.record(StageTransition {
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
///
/// External audit NET-001: `::ffff:127.0.0.1` (a dual-stack socket) is
/// loopback too.
fn is_loopback(family: u8, addr: &[u8]) -> bool {
    use common::netaddr::{canonical_ip, AF_INET, AF_INET6};
    if family != AF_INET && family != AF_INET6 {
        return false;
    }
    let mut b = [0u8; 16];
    let n = addr.len().min(16);
    b[..n].copy_from_slice(&addr[..n]);
    canonical_ip(family, &b).is_loopback()
}
