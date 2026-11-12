//! Lot 314 (the third bug hunt, F3): the posture machine tested as a state
//! machine ([`crate::model_check`]). A seeded generator draws sequences of
//! what the agent does to it — events of one service's process (an
//! offensive tool, a scan, a burst of connects to a public address, a
//! kernel denial), the clock moving, the decay tick, an administrator's
//! force-posture and unlock — and every step is checked against an oracle:
//! - a force toward the current state changes nothing — its timers, the
//!   transition log, the admin action — except the explicit lock of an
//!   unlocked COMBAT, which is one row and an admin action (BUG-84);
//! - an unlocked COMBAT decays exactly when no escalation signal came for
//!   the quiet window, counted from the last one (BUG-94), and a locked
//!   COMBAT never does;
//! - a change of the kind or of COMBAT's lock is exactly one row of the
//!   transition log, and nothing else is one;
//! - the transition log and the corroboration ledger keep their caps.

use std::sync::Arc;
use std::time::{Duration, Instant, UNIX_EPOCH};

use nn_model::posture_types::PostureKind;
use nn_model::Event;

use super::clock::{Clock, TestClock};
use super::host::testing::TestHost;
use super::state::PostureState;
use super::transitions::COMBAT_QUIET_WINDOW;
use super::triggers::testutil::{fs_protect_denial, spawn, tcp_v4};
use super::{AuthSessionTracker, ExemptPids};
use crate::model_check::{check, Rng, SEQUENCES};

type PostureMachine = super::PostureMachine<TestHost>;

const MIN: Duration = Duration::from_secs(60);
const PID: u32 = 42;

/// What happens to the machine.
#[derive(Debug, Clone, Copy)]
enum Op {
    /// An event of pid 42 (`app.service`).
    Event(Ev),
    Advance(Duration),
    Tick,
    Force(PostureKind),
    Unlock,
}

/// The events of the model, and whether each is an escalation signal (the
/// ledger records it: ENGAGED tier or above,
/// `TriggerType::is_corroboration`) — checked against the trigger detector
/// by [`the_model_s_events_are_what_it_says`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ev {
    /// `nc` executed: an offensive tool (ENGAGED tier).
    Nc,
    /// `nmap` executed: reconnaissance (ALERTED tier, not a signal).
    Nmap,
    /// The twenty-first connect to a public address in a burst: a COMBAT-tier
    /// heuristic.
    Burst,
    /// A kernel denial of the anti-tamper hooks: decisive, locks COMBAT.
    Deny,
}

impl Ev {
    fn escalates(self) -> bool {
        !matches!(self, Ev::Nmap)
    }

    fn event(self, ts: u64) -> Event {
        match self {
            Ev::Nc => spawn(PID, 1, "nc", "/usr/bin/nc", ts),
            Ev::Nmap => spawn(PID, 1, "nmap", "/usr/bin/nmap", ts),
            Ev::Burst => tcp_v4(PID, [203, 0, 113, 9], 443, ts),
            Ev::Deny => fs_protect_denial(PID, ts),
        }
    }
}

fn burst_before(ts: u64) -> Vec<Event> {
    (0..20u64)
        .map(|i| tcp_v4(PID, [203, 0, 113, 9], 443, ts.saturating_sub(20 - i)))
        .collect()
}

/// The `/proc` of the model: pid 42 in `app.service`, no login.
fn proc_root() -> tempfile::TempDir {
    let tmp = tempfile::TempDir::new().unwrap();
    let d = tmp.path().join(PID.to_string());
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("cgroup"), "0::/system.slice/app.service\n").unwrap();
    std::fs::write(d.join("loginuid"), "4294967295").unwrap();
    tmp
}

fn machine(proc: &tempfile::TempDir) -> (PostureMachine, Arc<TestClock>) {
    let clock = Arc::new(TestClock::at(
        UNIX_EPOCH + Duration::from_secs(1_767_225_600),
    ));
    let m = PostureMachine::new_with_hooks_and_exempt_and_auth(
        Arc::new(|_| {}),
        Arc::new(|_, _| Ok(String::new())),
        ExemptPids::default(),
        AuthSessionTracker::new(proc.path()),
    )
    .with_clock(clock.clone());
    (m, clock)
}

/// The same state: kind, timers, lock.
fn same(a: &PostureState, b: &PostureState) -> bool {
    match (a, b) {
        (PostureState::Observing, PostureState::Observing) => true,
        (
            PostureState::Alerted {
                since: s1,
                last_trigger: l1,
            },
            PostureState::Alerted {
                since: s2,
                last_trigger: l2,
            },
        )
        | (
            PostureState::Engaged {
                since: s1,
                last_trigger: l1,
            },
            PostureState::Engaged {
                since: s2,
                last_trigger: l2,
            },
        ) => s1 == s2 && l1 == l2,
        (
            PostureState::Combat {
                since: s1,
                locked: k1,
            },
            PostureState::Combat {
                since: s2,
                locked: k2,
            },
        ) => s1 == s2 && k1 == k2,
        _ => false,
    }
}

fn draw(rng: &mut Rng) -> Op {
    match rng.below(20) {
        0..=2 => Op::Event(Ev::Nc),
        3..=4 => Op::Event(Ev::Nmap),
        5..=7 => Op::Event(Ev::Burst),
        8 if rng.one_in(3) => Op::Event(Ev::Deny),
        8..=11 => Op::Advance(rng.range(1, 40) as u32 * MIN),
        12..=15 => Op::Tick,
        16..=18 => Op::Force(*rng.pick(&[
            PostureKind::Observing,
            PostureKind::Alerted,
            PostureKind::Engaged,
            PostureKind::Combat,
        ])),
        _ => Op::Unlock,
    }
}

/// One sequence: `steps` operations, every invariant checked after each.
fn run(rng: &mut Rng, proc: &tempfile::TempDir, steps: usize) -> Result<(), String> {
    let (m, clock) = machine(proc);
    let t0 = clock.now();
    let ns = |at: Instant| 1_000_000_000 + at.saturating_duration_since(t0).as_nanos() as u64;
    // the oracle: the last escalation signal, the last admin action
    let mut last_signal: Option<Instant> = None;
    let mut admin_at: Option<Instant> = None;
    let mut trace: Vec<Op> = Vec::new();
    for _ in 0..steps {
        let op = draw(rng);
        trace.push(op);
        let now = clock.now();
        let before = m.current();
        let rows = m.transition_log().len();
        match op {
            Op::Event(e) => {
                let ts = ns(now);
                let recent = if e == Ev::Burst {
                    burst_before(ts)
                } else {
                    Vec::new()
                };
                m.observe(&e.event(ts), &recent);
                if e.escalates() {
                    last_signal = Some(now);
                }
            }
            Op::Advance(d) => clock.advance(d),
            Op::Tick => {
                m.tick_decay();
            }
            Op::Force(to) => {
                let out = m
                    .admin_force_state_with_token((), to, true)
                    .map_err(|e| format!("force {to:?} refused: {e:?}; {trace:?}"))?;
                if out.from != before.kind() {
                    return Err(format!("force named {:?} as left; {trace:?}", out.from));
                }
            }
            Op::Unlock => {
                m.admin_release_combat_with_token(())
                    .map_err(|e| format!("unlock failed: {e:?}; {trace:?}"))?;
            }
        }
        let after = m.current();
        let added = m.transition_log().len() - rows;
        let changed =
            before.kind() != after.kind() || before.is_combat_locked() != after.is_combat_locked();
        // one row per change of kind or lock, none otherwise
        if added != usize::from(changed) {
            return Err(format!(
                "{added} transition row(s) for {before:?} -> {after:?}; {trace:?}"
            ));
        }
        if changed && matches!(op, Op::Force(_) | Op::Unlock) {
            admin_at = Some(now);
        }
        match op {
            // a command toward the current state changes nothing but the
            // explicit lock of an unlocked COMBAT
            Op::Force(to) if to == before.kind() => {
                let want = match before {
                    PostureState::Combat { since, .. } => PostureState::Combat {
                        since,
                        locked: true,
                    },
                    ref other => other.clone(),
                };
                if !same(&after, &want) {
                    return Err(format!(
                        "a force to the current {to:?} left {after:?} (was {before:?}); {trace:?}"
                    ));
                }
            }
            Op::Force(to) => {
                let fresh = match after {
                    PostureState::Observing => true,
                    PostureState::Alerted {
                        since,
                        last_trigger,
                    }
                    | PostureState::Engaged {
                        since,
                        last_trigger,
                    } => since == now && last_trigger == now,
                    PostureState::Combat { since, locked } => since == now && locked,
                };
                if after.kind() != to || !fresh {
                    return Err(format!("a force to {to:?} left {after:?}; {trace:?}"));
                }
            }
            // the quiet window, from the last signal
            Op::Tick => {
                if let PostureState::Combat { since, locked } = before {
                    let quiet_since = last_signal.map_or(since, |s| s.max(since));
                    let due = !locked && now.duration_since(quiet_since) >= COMBAT_QUIET_WINDOW;
                    let decayed = after.kind() == PostureKind::Engaged;
                    if decayed != due {
                        return Err(format!(
                            "COMBAT (locked {locked}) {} at {:?} after the last signal (quiet \
                             since {:?} after the entry); {trace:?}",
                            if decayed { "decayed" } else { "held" },
                            now.duration_since(quiet_since),
                            quiet_since.duration_since(since),
                        ));
                    }
                }
            }
            _ => {}
        }
        // the admin action, only on what an administrator changed
        let shown = m.last_admin_action_secs_ago();
        let want = admin_at.map(|t| clock.now().duration_since(t).as_secs());
        if shown != want {
            return Err(format!(
                "last admin action {shown:?} s ago, the oracle says {want:?}; {trace:?}"
            ));
        }
        // the caps
        if m.transition_log().len() > 256 || m.corroboration_len() > 256 {
            return Err(format!(
                "a table past its cap: {} rows, {} signals",
                m.transition_log().len(),
                m.corroboration_len()
            ));
        }
    }
    Ok(())
}

/// The events the model draws raise what it says of them, on a fresh
/// machine: an escalation signal is ENGAGED tier or above
/// (`TriggerType::is_corroboration`, what the ledger records).
#[test]
fn the_model_s_events_are_what_it_says() {
    let proc = proc_root();
    for e in [Ev::Nc, Ev::Nmap, Ev::Burst, Ev::Deny] {
        let (m, _) = machine(&proc);
        let ts = 5_000_000_000;
        let recent = if e == Ev::Burst {
            burst_before(ts)
        } else {
            Vec::new()
        };
        let hits = m.trigger_detector().detect(&e.event(ts), &recent);
        assert!(!hits.is_empty(), "{e:?} raises a signal");
        assert_eq!(
            hits.iter().any(|t| t.is_corroboration()),
            e.escalates(),
            "{e:?}: {hits:?}"
        );
    }
}

/// [`crate::model_check::SEQUENCES`] sequences of 24 steps.
#[test]
fn the_posture_machine_keeps_its_invariants() {
    let proc = proc_root();
    check("posture machine", 0x3140_0000, SEQUENCES, |rng| {
        run(rng, &proc, 24)
    });
}

/// The two counterexamples the third bug hunt found, as sequences: they
/// break the oracle on main (BUG-84, BUG-94; also the golden cases
/// `force-same-state` and `combat-quiet-after-a-prune`).
#[test]
fn the_bug_hunt_s_counterexamples_hold() {
    let proc = proc_root();
    // BUG-84: ALERTED forced to ALERTED 59 minutes in decays at 60.
    let (m, clock) = machine(&proc);
    m.admin_force_state_with_token((), PostureKind::Alerted, true)
        .unwrap();
    clock.advance(59 * MIN);
    m.admin_force_state_with_token((), PostureKind::Alerted, true)
        .unwrap();
    clock.advance(MIN);
    assert_eq!(
        m.tick_decay().map(|s| s.kind()),
        Some(PostureKind::Observing)
    );
    // BUG-94: an unlocked COMBAT, a signal at +20, a scan at +36: held at
    // +37 and until +50.
    let (m, clock) = machine(&proc);
    let t0 = clock.now();
    let ns = |c: &TestClock| 1_000_000_000 + c.now().duration_since(t0).as_nanos() as u64;
    m.observe(&Ev::Nc.event(ns(&clock)), &[]);
    let ts = ns(&clock) + 1;
    m.observe(&Ev::Burst.event(ts), &burst_before(ts));
    assert!(matches!(
        m.current(),
        PostureState::Combat { locked: false, .. }
    ));
    clock.advance(20 * MIN);
    m.observe(&Ev::Nc.event(ns(&clock)), &[]);
    clock.advance(16 * MIN);
    m.observe(&Ev::Nmap.event(ns(&clock)), &[]);
    for _ in 0..13 {
        clock.advance(MIN);
        assert!(m.tick_decay().is_none(), "held until +50");
    }
    clock.advance(MIN);
    assert_eq!(m.tick_decay().map(|s| s.kind()), Some(PostureKind::Engaged));
}
