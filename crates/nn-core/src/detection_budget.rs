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
//!
//! A rule that coalesces the repeats of one action into its first record
//! (NN-L-EVA-002: one switch-off command by one process tree, lab PR 225)
//! counts them here too ([`count_coalesced`]), without spending the pair's
//! budget: the next record carries them in `suppressed_before`, the
//! reporter's signed entry in its count.
//!
//! A flood must not hide what it is made of either: while a pair is held
//! back, the budget keeps up to [`MAX_SAMPLES`] distinct subjects (the file
//! or the executable the detection is about; the `comm` only when there is
//! neither) and the reporter writes them with the count. A credential read
//! hidden in a flood of reads of the user's own credentials still names
//! its file in the signed audit entry.

use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

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
/// Distinct subjects kept per pair between two reports.
pub const MAX_SAMPLES: usize = 8;

/// What the reporter takes for one (rule, uid): the count held since its
/// previous report and the distinct subjects among them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    pub rule: String,
    pub uid: u32,
    pub count: u64,
    pub samples: Vec<String>,
}

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
    /// Distinct subjects held since the last report: (key, text).
    samples: Vec<(String, String)>,
}

impl Bucket {
    fn new(now: Instant) -> Self {
        Bucket {
            tokens: BURST,
            refilled: now,
            held_since_record: 0,
            held_since_report: 0,
            throttled: false,
            samples: Vec::new(),
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

    /// One more held back, its subject kept while there is room.
    fn hold(&mut self, sample: impl FnOnce() -> (String, String)) {
        self.held_since_record += 1;
        self.held_since_report += 1;
        if self.samples.len() < MAX_SAMPLES {
            let (key, text) = sample();
            if !self.samples.iter().any(|(k, _)| *k == key) {
                self.samples.push((key, text));
            }
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
    /// The pair's bucket, refilled to `now`; `None` when it is new and no
    /// pair has room.
    fn bucket(&mut self, rule: &str, uid: u32, now: Instant) -> Option<&mut Bucket> {
        let known = self.rules.get(rule).is_some_and(|u| u.contains_key(&uid));
        if !known {
            if self.keys >= MAX_KEYS {
                self.prune(now);
            }
            if self.keys >= MAX_KEYS {
                return None;
            }
            self.keys += 1;
        }
        let bucket = self
            .rules
            .entry(rule.to_string())
            .or_default()
            .entry(uid)
            .or_insert_with(|| Bucket::new(now));
        bucket.refill(now);
        Some(bucket)
    }

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
    /// `sample` names the detection's subject, `(key, text)`: called only
    /// for a detection held back while fewer than [`MAX_SAMPLES`] distinct
    /// keys are kept.
    pub fn admit_at(
        &self,
        rule: &str,
        uid: u32,
        now: Instant,
        sample: impl FnOnce() -> (String, String),
    ) -> Admit {
        let mut g = self.inner.lock();
        let Some(bucket) = g.bucket(rule, uid, now) else {
            return Admit::Record {
                suppressed_before: 0,
            };
        };
        if bucket.tokens > 0 {
            bucket.tokens -= 1;
            Admit::Record {
                suppressed_before: std::mem::take(&mut bucket.held_since_record),
            }
        } else {
            bucket.hold(sample);
            let first = !bucket.throttled;
            bucket.throttled = true;
            Admit::Hold { first }
        }
    }

    /// A detection its rule coalesced into an earlier record of the same
    /// action: counted as one held back (the next record of the pair, the
    /// reporter's entry), the pair's budget not spent. Not counted when
    /// no pair has room ([`MAX_KEYS`]).
    pub fn count_coalesced_at(
        &self,
        rule: &str,
        uid: u32,
        now: Instant,
        sample: impl FnOnce() -> (String, String),
    ) {
        if let Some(bucket) = self.inner.lock().bucket(rule, uid, now) {
            bucket.hold(sample);
        }
    }

    /// `n` detections coalesced at once ([`Self::count_coalesced_at`] `n`
    /// times, one subject): R12b (lab PR 269), the denials the event bus
    /// coalesced or capped, counted as NN-L-AT-001's held records.
    pub fn count_coalesced_many_at(
        &self,
        rule: &str,
        uid: u32,
        n: u64,
        now: Instant,
        sample: impl FnOnce() -> (String, String),
    ) {
        if n == 0 {
            return;
        }
        if let Some(bucket) = self.inner.lock().bucket(rule, uid, now) {
            bucket.hold(sample);
            bucket.held_since_record += n - 1;
            bucket.held_since_report += n - 1;
        }
    }

    /// Take the counts and samples held since the last call.
    pub fn take_held(&self) -> Vec<Held> {
        let mut g = self.inner.lock();
        let mut out = Vec::new();
        for (rule, uids) in g.rules.iter_mut() {
            for (uid, b) in uids.iter_mut() {
                if b.held_since_report > 0 {
                    out.push(Held {
                        rule: rule.clone(),
                        uid: *uid,
                        count: std::mem::take(&mut b.held_since_report),
                        samples: std::mem::take(&mut b.samples)
                            .into_iter()
                            .map(|(_, text)| text)
                            .collect(),
                    });
                }
            }
        }
        out.sort_by(|a, b| (&a.rule, a.uid).cmp(&(&b.rule, b.uid)));
        out
    }
}

static BUDGET: LazyLock<DetectionBudget> = LazyLock::new(DetectionBudget::default);

/// The process-wide budget, now. `sample`: see [`DetectionBudget::admit_at`].
pub fn admit(rule: &str, uid: u32, sample: impl FnOnce() -> (String, String)) -> Admit {
    BUDGET.admit_at(rule, uid, Instant::now(), sample)
}

/// [`DetectionBudget::count_coalesced_at`] on the process-wide budget, now.
pub fn count_coalesced(rule: &str, uid: u32, sample: impl FnOnce() -> (String, String)) {
    BUDGET.count_coalesced_at(rule, uid, Instant::now(), sample)
}

/// [`DetectionBudget::count_coalesced_many_at`] on the process-wide budget,
/// now.
pub fn count_coalesced_many(
    rule: &str,
    uid: u32,
    n: u64,
    sample: impl FnOnce() -> (String, String),
) {
    BUDGET.count_coalesced_many_at(rule, uid, n, Instant::now(), sample)
}

/// [`DetectionBudget::take_held`] on the process-wide budget: what the
/// agent's reporter task takes every [`REPORT_SECS`] (R08a, lab PR 250).
pub fn take_held() -> Vec<Held> {
    BUDGET.take_held()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nos() -> (String, String) {
        (String::new(), String::new())
    }

    fn records(b: &DetectionBudget, rule: &str, uid: u32, n: u32, now: Instant) -> u32 {
        (0..n)
            .filter(|_| {
                b.admit_at(rule, uid, now, || (String::new(), String::new()))
                    .record()
            })
            .count() as u32
    }

    #[test]
    fn burst_then_one_per_refill_and_each_count_complete() {
        let b = DetectionBudget::default();
        let t0 = Instant::now();
        assert_eq!(records(&b, "R", 1000, BURST, t0), BURST);
        assert_eq!(b.admit_at("R", 1000, t0, nos), Admit::Hold { first: true });
        assert_eq!(b.admit_at("R", 1000, t0, nos), Admit::Hold { first: false });
        // One refill later: one record, carrying the two held before it.
        assert_eq!(
            b.admit_at("R", 1000, t0 + REFILL, nos),
            Admit::Record {
                suppressed_before: 2
            }
        );
        // Still the same episode: no second "ran out" line.
        assert_eq!(
            b.admit_at("R", 1000, t0 + REFILL, nos),
            Admit::Hold { first: false }
        );
        // The reporter takes all three held in its window, once.
        let held = b.take_held();
        assert_eq!(held.len(), 1);
        assert_eq!(
            (held[0].rule.as_str(), held[0].uid, held[0].count),
            ("R", 1000, 3)
        );
        assert!(b.take_held().is_empty());
        // The next record carries the one held since the previous record.
        assert_eq!(
            b.admit_at("R", 1000, t0 + REFILL * 2, nos),
            Admit::Record {
                suppressed_before: 1
            }
        );
    }

    /// Review 75 residual: a flood does not hide what it is made of. The
    /// held report keeps distinct subjects (by key), at most MAX_SAMPLES.
    #[test]
    fn held_report_names_distinct_subjects() {
        let b = DetectionBudget::default();
        let t0 = Instant::now();
        let own = || {
            (
                "/home/u/.aws/credentials".to_string(),
                "cat (pid 1) /home/u/.aws/credentials".to_string(),
            )
        };
        assert_eq!(records(&b, "FIM-011", 0, BURST, t0), BURST);
        for _ in 0..1000 {
            assert!(!b.admit_at("FIM-011", 0, t0, own).record());
        }
        let other = || {
            (
                "/home/alice/.aws/credentials".to_string(),
                "cat (pid 2) /home/alice/.aws/credentials".to_string(),
            )
        };
        assert!(!b.admit_at("FIM-011", 0, t0, other).record());
        let held = b.take_held();
        assert_eq!(held[0].count, 1001);
        assert_eq!(
            held[0].samples,
            vec![
                "cat (pid 1) /home/u/.aws/credentials".to_string(),
                "cat (pid 2) /home/alice/.aws/credentials".to_string()
            ]
        );
        // At most MAX_SAMPLES distinct subjects between two reports.
        for i in 0..20 {
            let _ = b.admit_at("FIM-011", 0, t0, || (format!("k{i}"), format!("t{i}")));
        }
        assert_eq!(b.take_held()[0].samples.len(), MAX_SAMPLES);
    }

    /// Lab PR 225 (NN-L-EVA-002): repeats a rule coalesced into its record
    /// are counted for the next record and the reporter, and spend nothing
    /// of the pair's budget.
    #[test]
    fn coalesced_repeats_are_counted_without_spending_the_budget() {
        let b = DetectionBudget::default();
        let t0 = Instant::now();
        assert!(b.admit_at("EVA-002", 0, t0, nos).record());
        let sample = || {
            (
                "iptables iptables -F 601".to_string(),
                "iptables -F again by the children of pid 601".to_string(),
            )
        };
        for _ in 0..30 {
            b.count_coalesced_at("EVA-002", 0, t0, sample);
        }
        let held = b.take_held();
        assert_eq!(held.len(), 1);
        assert_eq!((held[0].rule.as_str(), held[0].count), ("EVA-002", 30));
        assert_eq!(
            held[0].samples,
            vec!["iptables -F again by the children of pid 601".to_string()]
        );
        // The next record carries the thirty; the budget lost only the two
        // records' tokens.
        assert_eq!(
            b.admit_at("EVA-002", 0, t0, nos),
            Admit::Record {
                suppressed_before: 30
            }
        );
        assert_eq!(records(&b, "EVA-002", 0, BURST, t0), BURST - 2);
    }

    /// R12b (C5): `n` coalesced at once count as `n` held — in the next
    /// record's `suppressed_before` and the report — without the budget.
    #[test]
    fn many_coalesced_at_once_count_as_many_held() {
        let b = DetectionBudget::default();
        let t0 = Instant::now();
        b.count_coalesced_many_at("AT-001", 0, 1_499, t0, || {
            ("chmod".into(), "chmod (pid 9)".into())
        });
        b.count_coalesced_many_at("AT-001", 0, 0, t0, nos);
        assert_eq!(
            b.admit_at("AT-001", 0, t0, nos),
            Admit::Record {
                suppressed_before: 1_499
            },
            "the budget not spent: the next one is recorded, carrying them"
        );
        let held = b.take_held();
        assert_eq!(held.len(), 1);
        assert_eq!(
            (held[0].count, &held[0].samples[..]),
            (1_499, &["chmod (pid 9)".to_string()][..])
        );
    }

    #[test]
    fn a_new_episode_starts_only_after_a_full_refill() {
        let b = DetectionBudget::default();
        let t0 = Instant::now();
        assert_eq!(records(&b, "R", 1, BURST, t0), BURST);
        assert_eq!(b.admit_at("R", 1, t0, nos), Admit::Hold { first: true });
        let full = t0 + REFILL * BURST;
        assert_eq!(records(&b, "R", 1, BURST, full), BURST);
        assert_eq!(b.admit_at("R", 1, full, nos), Admit::Hold { first: true });
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
            assert!(b.admit_at("R", uid, t0, nos).record());
        }
        // Table full, nothing idle yet (each bucket spent a token): a new
        // pair is still recorded.
        assert!(b.admit_at("R", 999_999, t0, nos).record());
        // Once the buckets refilled, the idle pairs are forgotten and the
        // new pair is tracked (and budgeted) again.
        let later = t0 + REFILL * 2;
        assert_eq!(records(&b, "S", 1, BURST, later), BURST);
        assert_eq!(b.admit_at("S", 1, later, nos), Admit::Hold { first: true });
    }
}
