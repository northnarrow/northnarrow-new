//! External audit NET-019 (design §6.5, lock-in Q4): the netflow rows
//! handed to the rules, paced per uid.
//!
//! A loop of short connections, which any user can run, made one row per
//! close, each written, fsynced and sent to the rules before the drain read
//! the next record: the drain fell behind and the kernel ring dropped
//! closes, other users' among them. Every row is still written to
//! `netflow.jsonl` (with a group commit since, see `net::drain`). What is
//! paced is the hand-off to the rules: a token bucket per uid lets a burst
//! of [`BURST`] rows through, then [`REFILL_PER_SEC`] a second. A row held
//! back is written with `decision_engine_skipped: true` and not evaluated.
//!
//! Some rows are never held back. Their checks run before the bucket and
//! take no token:
//! - a row a killing rule could match: a destination on the operator
//!   blocklist (NN-L-NET-001), or the predicate of NN-L-NET-002, -003,
//!   -008, -010 or -018, allowlists aside
//!   ([`crate::decision::rules::net::may_meet_a_kill_rule`]);
//! - a row of a process that holds, or whose ancestors hold, a chain
//!   precursor in the correlation window (the NN-L-CHAIN rules).
//!
//! A row held back is still noted as an egress in the correlation store,
//! as NN-L-CHAIN-007 notes every flow it sees, so a precursor processed
//! after it still completes its chain (review 70).
//!
//! What a held-back row misses, for the uid that floods and while it
//! floods: the rules that only record (beacon timing, byte volume, internal
//! destinations, plaintext services) and the posture signals of its flows.
//! The key is the acting uid, which an unprivileged user cannot vary: every
//! other user keeps its own budget. The first row a bucket holds back after
//! a full refill is a WARN naming the uid; the rows held back since boot
//! are counted for `nn-admin net status`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::wire::NetFlowEvent;
use parking_lot::Mutex;
use tracing::warn;

use crate::decision::correlation::{CorrelationStore, EgressNote};
use crate::net::blocklist::NetBlocklist;

/// Rows of one uid handed to the rules in a burst before the pacing
/// applies.
pub const BURST: u32 = 1_000;
/// After a burst, rows of one uid handed to the rules per second.
pub const REFILL_PER_SEC: u32 = 200;
/// Uids tracked at most. When full, uids whose bucket is full again are
/// forgotten; a new uid that still finds no room is not paced.
const MAX_UIDS: usize = 4096;

/// Rows held back from the rules since boot.
static ROWS_SKIPPED: AtomicU64 = AtomicU64::new(0);

/// Rows written with `decision_engine_skipped` since boot (status surface).
pub fn rows_skipped_total() -> u64 {
    ROWS_SKIPPED.load(Ordering::Relaxed)
}

/// What the bucket says about one row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pace {
    /// Hand it to the rules.
    Rules,
    /// Hold it back. `first`: the bucket has just run out, after a full
    /// refill since it last did (worth one WARN line).
    Skip { first: bool },
}

struct Bucket {
    tokens: u32,
    refilled: Instant,
    /// A WARN was logged since the bucket was last full.
    warned: bool,
}

/// Token bucket per uid.
pub struct UidPacer {
    buckets: HashMap<u32, Bucket>,
    burst: u32,
    refill_every: Duration,
}

impl Default for UidPacer {
    fn default() -> Self {
        Self::with_rate(BURST, REFILL_PER_SEC)
    }
}

impl UidPacer {
    /// `burst` rows, then `per_sec` a second, per uid.
    pub fn with_rate(burst: u32, per_sec: u32) -> Self {
        Self {
            buckets: HashMap::new(),
            burst,
            refill_every: Duration::from_secs(1) / per_sec.max(1),
        }
    }

    fn refill(&self, b: &mut Bucket, now: Instant) {
        let elapsed = now.saturating_duration_since(b.refilled);
        let earned = elapsed.as_nanos() / self.refill_every.as_nanos().max(1);
        if earned == 0 {
            return;
        }
        let room = u128::from(self.burst - b.tokens);
        if earned >= room {
            b.tokens = self.burst;
            b.refilled = now;
            b.warned = false;
        } else {
            b.tokens += earned as u32;
            b.refilled += self.refill_every * earned as u32;
        }
    }

    /// Take a token of `uid` at `now`.
    pub fn admit(&mut self, uid: u32, now: Instant) -> Pace {
        if !self.buckets.contains_key(&uid) && self.buckets.len() >= MAX_UIDS {
            let (burst, every) = (self.burst, self.refill_every);
            self.buckets.retain(|_, b| {
                let elapsed = now.saturating_duration_since(b.refilled);
                let earned = elapsed.as_nanos() / every.as_nanos().max(1);
                u128::from(b.tokens) + earned < u128::from(burst)
            });
            if self.buckets.len() >= MAX_UIDS {
                return Pace::Rules;
            }
        }
        let mut b = self.buckets.remove(&uid).unwrap_or(Bucket {
            tokens: self.burst,
            refilled: now,
            warned: false,
        });
        self.refill(&mut b, now);
        let pace = if b.tokens > 0 {
            b.tokens -= 1;
            Pace::Rules
        } else {
            let first = !b.warned;
            b.warned = true;
            Pace::Skip { first }
        };
        self.buckets.insert(uid, b);
        pace
    }
}

/// External audit NET-019: decides, row by row, whether a netflow row
/// reaches the rules (module docs). Owned by the net drain task.
pub struct RuleGate {
    blocklist: Arc<NetBlocklist>,
    correlation: Arc<Mutex<CorrelationStore>>,
    pacer: UidPacer,
}

impl RuleGate {
    /// `correlation` is the store the chain rules of the engine use.
    pub fn new(blocklist: Arc<NetBlocklist>, correlation: Arc<Mutex<CorrelationStore>>) -> Self {
        Self::with_pacer(blocklist, correlation, UidPacer::default())
    }

    pub fn with_pacer(
        blocklist: Arc<NetBlocklist>,
        correlation: Arc<Mutex<CorrelationStore>>,
        pacer: UidPacer,
    ) -> Self {
        Self {
            blocklist,
            correlation,
            pacer,
        }
    }

    /// `true` when `ev` is held back from the rules: it is then written
    /// with `decision_engine_skipped` and not sent on the bus.
    pub fn hold_back(&mut self, ev: &NetFlowEvent, now: Instant) -> bool {
        if crate::decision::rules::net::may_meet_a_kill_rule(ev, &self.blocklist) {
            return false;
        }
        if self
            .correlation
            .lock()
            .has_precursor_in_lineage(ev.pid, ev.start_ns)
        {
            return false;
        }
        let Pace::Skip { first } = self.pacer.admit(ev.uid, now) else {
            return false;
        };
        ROWS_SKIPPED.fetch_add(1, Ordering::Relaxed);
        if first {
            warn!(
                uid = ev.uid,
                pid = ev.pid,
                comm = %common::log_escape::Escaped(&ev.comm),
                burst = self.pacer.burst,
                per_sec = (Duration::from_secs(1).as_nanos()
                    / self.pacer.refill_every.as_nanos().max(1)) as u64,
                skipped_total = rows_skipped_total(),
                "netflow: this uid's flows arrive faster than the rules are given them; \
                 the rows beyond are written to netflow.jsonl with decision_engine_skipped \
                 and not evaluated (rows a killing rule could match, and rows of processes \
                 with chain precursors, always are)"
            );
        }
        let mut store = self.correlation.lock();
        let key = store.current_key(ev.pid);
        store.note_egress(
            key,
            EgressNote {
                pid: ev.pid,
                comm: ev.comm.clone(),
                start_ns: ev.start_ns,
            },
        );
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::correlation::PrecursorKind;
    use std::net::IpAddr;

    fn row(uid: u32, pid: u32, dst: &str, port: u16) -> NetFlowEvent {
        NetFlowEvent {
            start_ns: 5_000_000_000,
            end_ns: 5_000_000_100,
            family: 2,
            src_addr: "100.64.0.2".parse().unwrap(),
            src_port: 40000,
            dst_addr: dst.parse::<IpAddr>().unwrap(),
            dst_port: port,
            proto: 6,
            pid,
            uid,
            comm: "nnflood".to_string(),
            exe: Some("/opt/nnx/nnflood".to_string()),
            bytes_sent: 0,
            bytes_recv: 0,
            resolved_hostname: None,
            tls_fingerprint: None,
            flow_id: "f".to_string(),
            close_reason: 0,
            proc_start_ns: 0,
        }
    }

    #[test]
    fn the_bucket_lets_a_burst_through_then_paces_per_uid() {
        let mut p = UidPacer::with_rate(3, 10);
        let t0 = Instant::now();
        for _ in 0..3 {
            assert_eq!(p.admit(1000, t0), Pace::Rules);
        }
        assert_eq!(p.admit(1000, t0), Pace::Skip { first: true });
        assert_eq!(p.admit(1000, t0), Pace::Skip { first: false });
        // Another user keeps its own budget.
        assert_eq!(p.admit(1001, t0), Pace::Rules);
        // 100 ms earns one token; the WARN is not repeated until the
        // bucket has been full again.
        let t1 = t0 + Duration::from_millis(100);
        assert_eq!(p.admit(1000, t1), Pace::Rules);
        assert_eq!(p.admit(1000, t1), Pace::Skip { first: false });
        let t2 = t1 + Duration::from_secs(1);
        for _ in 0..3 {
            assert_eq!(p.admit(1000, t2), Pace::Rules);
        }
        assert_eq!(p.admit(1000, t2), Pace::Skip { first: true });
    }

    #[test]
    fn the_uid_table_is_bounded() {
        let mut p = UidPacer::with_rate(1, 1);
        let t0 = Instant::now();
        for uid in 0..MAX_UIDS as u32 {
            assert_eq!(p.admit(uid, t0), Pace::Rules);
        }
        // Every bucket is empty: a new uid is not paced, nothing grows.
        assert_eq!(p.admit(999_999, t0), Pace::Rules);
        assert_eq!(p.buckets.len(), MAX_UIDS);
        // Once they are full again they make room.
        let t1 = t0 + Duration::from_secs(2);
        assert_eq!(p.admit(999_999, t1), Pace::Rules);
        assert!(p.buckets.len() <= 1);
    }

    fn gate(burst: u32) -> (RuleGate, Arc<Mutex<CorrelationStore>>) {
        let bl = NetBlocklist::from_entries([crate::net::blocklist::NetBlocklistEntry::Cidr {
            net: "192.0.2.0".parse().unwrap(),
            prefix: 24,
        }]);
        let store = Arc::new(Mutex::new(CorrelationStore::new()));
        (
            RuleGate::with_pacer(
                Arc::new(bl),
                Arc::clone(&store),
                UidPacer::with_rate(burst, 1),
            ),
            store,
        )
    }

    /// The flood of one uid is held back past its burst; a blocklisted
    /// destination, a killing predicate and a process with a chain
    /// precursor are never held back, even with that uid's bucket empty.
    #[test]
    fn a_flood_is_held_back_but_never_a_row_a_kill_or_chain_needs() {
        let (mut g, store) = gate(5);
        let now = Instant::now();
        let before = rows_skipped_total();
        let held = (0..100)
            .filter(|_| g.hold_back(&row(1000, 4242, "100.64.0.1", 8080), now))
            .count();
        assert_eq!(held, 95);
        assert!(rows_skipped_total() >= before + 95);
        assert!(!g.hold_back(&row(1000, 4242, "192.0.2.10", 8080), now));
        assert!(!g.hold_back(&row(1000, 4242, "100.64.0.1", 4444), now));
        let mut staged = row(1000, 4243, "100.64.0.1", 8080);
        staged.exe = Some("/tmp/stage2".to_string());
        assert!(!g.hold_back(&staged, now));
        store
            .lock()
            .record_for_pid(4244, PrecursorKind::CredRead, 4_000_000_000);
        assert!(!g.hold_back(&row(1000, 4244, "100.64.0.1", 8080), now));
        // A child of a process with a precursor is covered too.
        store.lock().observe_spawn(4245, 4244, 4_500_000_000);
        assert!(!g.hold_back(&row(1000, 4245, "100.64.0.1", 8080), now));
        // Another user is not held back.
        assert!(!g.hold_back(&row(1001, 5000, "100.64.0.1", 8080), now));
    }

    /// A held-back row is noted as an egress, so a credential read
    /// processed after it still completes NN-L-CHAIN-007 (review 70).
    #[test]
    fn a_held_back_row_is_noted_for_a_late_precursor() {
        let (mut g, store) = gate(0);
        let r = row(1000, 4300, "100.64.0.1", 8080);
        assert!(g.hold_back(&r, Instant::now()));
        let mut s = store.lock();
        let key = s.current_key(4300);
        let note = s
            .take_egress_after(
                key,
                4_000_000_000,
                crate::decision::correlation::CORRELATION_WINDOW_NS,
            )
            .expect("the held-back egress is in the store");
        assert_eq!(note.start_ns, r.start_ns);
    }
}
