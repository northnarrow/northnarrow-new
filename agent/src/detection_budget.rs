//! Per-(rule, uid) budget for logging and storing detections (review 75).
//!
//! Every verdict is acted on: the response, the posture and the
//! correlation see all of them. What a flood must not do is fill the
//! journal and the detection store with copies of one detection. A loop of
//! reads of the user's own credential file made thousands of NN-L-FIM-011
//! verdicts per second: journald suppressed the agent's lines and the
//! store's drop-oldest queue evicted the records of real kills.
//!
//! A token bucket per (rule, uid) lets a burst of [`BURST`] through, then
//! records one detection per [`REFILL`]. The ones it holds back are counted
//! twice over, each count complete: the next record of that (rule, uid)
//! carries the number held since the previous record (`suppressed_before`),
//! and the reporter task logs a WARN and writes one signed audit entry per
//! [`REPORT_SECS`] with the number held in that window. The journal gets
//! one WARN when a pair runs out, not one per second. The key is the acting
//! uid, which an unprivileged user cannot vary: a flood by one user leaves
//! every other (rule, uid) its own budget.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tracing::warn;

/// Detections of one (rule, uid) recorded in a burst before the budget
/// applies.
pub const BURST: u32 = 100;
/// After a burst, one more detection of that (rule, uid) per interval.
pub const REFILL: Duration = Duration::from_secs(1);
/// (rule, uid) pairs tracked at most. When full, pairs with a full bucket
/// and nothing held are forgotten; a new pair that still finds no room is
/// recorded unbudgeted.
const MAX_KEYS: usize = 4096;
/// Period of the reporter task.
pub const REPORT_SECS: u64 = 60;
/// Audit op of a held-back report.
pub const AUDIT_OP: &str = "detections_held";

/// What to do with one detection beyond acting on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    /// Log and store it. `suppressed_before`: detections of the same
    /// (rule, uid) held back since its previous record.
    Record { suppressed_before: u64 },
    /// Count it, do not log or store it. `first`: the budget has just run
    /// out, after a full refill since it last did (worth one WARN line).
    Hold { first: bool },
}

impl Admit {
    pub fn record(self) -> bool {
        matches!(self, Admit::Record { .. })
    }
}

struct Bucket {
    tokens: u32,
    refilled: Instant,
    /// Held since the last record of this pair.
    held_since_record: u64,
    /// Held since the reporter last took the count.
    held_since_report: u64,
    /// Ran out, and not refilled to a full burst since.
    throttled: bool,
}

impl Bucket {
    fn new(now: Instant) -> Self {
        Bucket {
            tokens: BURST,
            refilled: now,
            held_since_record: 0,
            held_since_report: 0,
            throttled: false,
        }
    }

    fn refill(&mut self, now: Instant) {
        let steps = now.saturating_duration_since(self.refilled).as_nanos() / REFILL.as_nanos();
        if steps == 0 {
            return;
        }
        let tokens = u128::from(self.tokens) + steps;
        if tokens >= u128::from(BURST) {
            self.tokens = BURST;
            self.refilled = now;
            self.throttled = false;
        } else {
            // `steps` < BURST here, so the product cannot overflow.
            self.tokens = tokens as u32;
            self.refilled += REFILL * steps as u32;
        }
    }

    /// Nothing left to report, nothing spent: safe to forget.
    fn idle(&self) -> bool {
        self.tokens == BURST && self.held_since_report == 0
    }
}

#[derive(Default)]
struct Inner {
    rules: HashMap<String, HashMap<u32, Bucket>>,
    keys: usize,
}

impl Inner {
    /// Forget the pairs with nothing to report and a full bucket.
    fn prune(&mut self, now: Instant) {
        let mut keys = 0;
        self.rules.retain(|_, uids| {
            uids.retain(|_, b| {
                b.refill(now);
                !b.idle()
            });
            keys += uids.len();
            !uids.is_empty()
        });
        self.keys = keys;
    }
}

/// The budget. One per process ([`admit`]); tests build their own.
#[derive(Default)]
pub struct DetectionBudget {
    inner: Mutex<Inner>,
}

impl DetectionBudget {
    pub fn admit_at(&self, rule: &str, uid: u32, now: Instant) -> Admit {
        let mut g = self.inner.lock();
        let inner = &mut *g;
        let known = inner.rules.get(rule).is_some_and(|u| u.contains_key(&uid));
        if !known {
            if inner.keys >= MAX_KEYS {
                inner.prune(now);
            }
            if inner.keys >= MAX_KEYS {
                return Admit::Record {
                    suppressed_before: 0,
                };
            }
            inner.keys += 1;
        }
        let bucket = inner
            .rules
            .entry(rule.to_string())
            .or_default()
            .entry(uid)
            .or_insert_with(|| Bucket::new(now));
        bucket.refill(now);
        if bucket.tokens > 0 {
            bucket.tokens -= 1;
            Admit::Record {
                suppressed_before: std::mem::take(&mut bucket.held_since_record),
            }
        } else {
            bucket.held_since_record += 1;
            bucket.held_since_report += 1;
            let first = !bucket.throttled;
            bucket.throttled = true;
            Admit::Hold { first }
        }
    }

    /// Take the counts held since the last call: `(rule, uid, held)`.
    pub fn take_held(&self) -> Vec<(String, u32, u64)> {
        let mut g = self.inner.lock();
        let mut out = Vec::new();
        for (rule, uids) in g.rules.iter_mut() {
            for (uid, b) in uids.iter_mut() {
                if b.held_since_report > 0 {
                    out.push((rule.clone(), *uid, std::mem::take(&mut b.held_since_report)));
                }
            }
        }
        out.sort();
        out
    }
}

static BUDGET: LazyLock<DetectionBudget> = LazyLock::new(DetectionBudget::default);

/// The process-wide budget, now.
pub fn admit(rule: &str, uid: u32) -> Admit {
    BUDGET.admit_at(rule, uid, Instant::now())
}

/// Report held-back detections every [`REPORT_SECS`]: one WARN per
/// (rule, uid) and one signed audit entry for all of them.
pub fn spawn_reporter(audit_log: Option<Arc<parking_lot::Mutex<crate::audit::AuditLog>>>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(REPORT_SECS));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let held = BUDGET.take_held();
            if held.is_empty() {
                continue;
            }
            for (rule, uid, n) in &held {
                warn!(
                    rule = %rule,
                    uid,
                    held = n,
                    "detections acted on but not logged or stored (per-rule budget)"
                );
            }
            let Some(log) = audit_log.as_ref() else {
                continue;
            };
            let draft = crate::audit::AuditEntryDraft {
                op: AUDIT_OP.to_string(),
                extra: serde_json::json!({
                    "window_secs": REPORT_SECS,
                    "held": held
                        .iter()
                        .map(|(rule, uid, n)| serde_json::json!({ "rule": rule, "uid": uid, "count": n }))
                        .collect::<Vec<_>>(),
                }),
                key_fp: "agent-self".to_string(),
                cosigner_fps: Vec::new(),
                result: "detected".to_string(),
                client_pid: std::process::id(),
                client_uid: 0,
                client_comm: "northnarrow-agent".to_string(),
            };
            if let Err(e) = log.lock().append(draft) {
                warn!(
                    error = format!("{e:#}"),
                    "detections-held audit entry failed"
                );
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn records(b: &DetectionBudget, rule: &str, uid: u32, n: u32, now: Instant) -> u32 {
        (0..n)
            .filter(|_| b.admit_at(rule, uid, now).record())
            .count() as u32
    }

    #[test]
    fn burst_then_one_per_refill_and_each_count_complete() {
        let b = DetectionBudget::default();
        let t0 = Instant::now();
        assert_eq!(records(&b, "R", 1000, BURST, t0), BURST);
        assert_eq!(b.admit_at("R", 1000, t0), Admit::Hold { first: true });
        assert_eq!(b.admit_at("R", 1000, t0), Admit::Hold { first: false });
        // One refill later: one record, carrying the two held before it.
        assert_eq!(
            b.admit_at("R", 1000, t0 + REFILL),
            Admit::Record {
                suppressed_before: 2
            }
        );
        // Still the same episode: no second "ran out" line.
        assert_eq!(
            b.admit_at("R", 1000, t0 + REFILL),
            Admit::Hold { first: false }
        );
        // The reporter takes all three held in its window, once.
        assert_eq!(b.take_held(), vec![("R".to_string(), 1000, 3)]);
        assert!(b.take_held().is_empty());
        // The next record carries the one held since the previous record.
        assert_eq!(
            b.admit_at("R", 1000, t0 + REFILL * 2),
            Admit::Record {
                suppressed_before: 1
            }
        );
    }

    #[test]
    fn a_new_episode_starts_only_after_a_full_refill() {
        let b = DetectionBudget::default();
        let t0 = Instant::now();
        assert_eq!(records(&b, "R", 1, BURST, t0), BURST);
        assert_eq!(b.admit_at("R", 1, t0), Admit::Hold { first: true });
        let full = t0 + REFILL * BURST;
        assert_eq!(records(&b, "R", 1, BURST, full), BURST);
        assert_eq!(b.admit_at("R", 1, full), Admit::Hold { first: true });
    }

    #[test]
    fn a_flood_by_one_uid_leaves_other_pairs_their_budget() {
        let b = DetectionBudget::default();
        let t0 = Instant::now();
        assert_eq!(records(&b, "NN-L-FIM-011", 1000, 50_000, t0), BURST);
        assert_eq!(records(&b, "NN-L-FIM-007", 0, 3, t0), 3);
        assert_eq!(records(&b, "NN-L-FIM-011", 0, 3, t0), 3);
        assert_eq!(records(&b, "R001", 1000, 3, t0), 3);
    }

    #[test]
    fn idle_bucket_refills_to_burst_not_beyond() {
        let b = DetectionBudget::default();
        let t0 = Instant::now();
        assert_eq!(records(&b, "R", 7, BURST, t0), BURST);
        let later = t0 + REFILL * (BURST * 10);
        assert_eq!(records(&b, "R", 7, BURST + 5, later), BURST);
    }

    #[test]
    fn full_table_forgets_idle_pairs_and_never_drops_a_new_one() {
        let b = DetectionBudget::default();
        let t0 = Instant::now();
        for uid in 0..MAX_KEYS as u32 {
            assert!(b.admit_at("R", uid, t0).record());
        }
        // Table full, nothing idle yet (each bucket spent a token): a new
        // pair is still recorded.
        assert!(b.admit_at("R", 999_999, t0).record());
        // Once the buckets refilled, the idle pairs are forgotten and the
        // new pair is tracked (and budgeted) again.
        let later = t0 + REFILL * 2;
        assert_eq!(records(&b, "S", 1, BURST, later), BURST);
        assert_eq!(b.admit_at("S", 1, later), Admit::Hold { first: true });
    }
}
