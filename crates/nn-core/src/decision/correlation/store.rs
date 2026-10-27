//! Tappa 10.6 (D3) — `CorrelationStore`.
//!
//! Generalises the T10.5 D5 `ChainCorrelationBuffer` (same-PID,
//! single-precursor, timestamp-only) into the engine's shared
//! correlation state, per design §4.2 / §13 Q3 (single-pass, deferred
//! store — the `Rule::evaluate` contract is unchanged; chain rules hold
//! an `Arc<Mutex<CorrelationStore>>` and record/query through it).
//!
//! What D3 adds over the old buffer:
//!
//! - **Typed precursors.** One shared store records *kinds*
//!   ([`PrecursorKind`]) instead of one buffer per rule, so different
//!   chain rules stay isolated by kind while sharing memory + eviction.
//! - **N-event sequences.** [`CorrelationStore::has_sequence`] matches
//!   an ordered list of precursor kinds within a window — the
//!   foundation for the D6 multi-step kill chains (CHAIN-004..008).
//! - **(pid, start_ns) keying.** Entries key on [`ProcKey`] so a
//!   recycled PID (same number, new `start_time`) is a *distinct*
//!   process (§13 Q2). External audit NETR-009: an exec precursor is
//!   recorded with the start its `ProcessSpawn` carries (POS-003); any
//!   other precursor, and every query, takes the PID's current
//!   incarnation from the ancestry tree. An unknown incarnation is
//!   `start_ns = 0` and matches only 0, so processes started before the
//!   agent keep the PID-only behaviour.
//! - **Per-rule window.** Each query passes its own `window_ns`
//!   (§13 Q4 — 300 s default, configurable per rule).
//!
//! External audit NETR-014 (lab PR 213): retention per precursor kind
//! ([`retention_ns`]). A credential read and a canary trip are kept
//! [`LONG_RETENTION_NS`] (30 min), a staging-directory exec and a
//! `sudo`/`su` [`CORRELATION_WINDOW_NS`] (300 s), as before. An egress
//! within 300 s of its precursor is the chain's Critical verdict, as
//! before; past it and within the retention it is one High record with no
//! response, once per precursor ([`CorrelationStore::chain_age`]): waiting
//! out five minutes no longer hides a slow exfiltration, and a long-lived
//! process that reads its own credentials and talks to the network much
//! later (a backup client, an agent-style helper) is not killed for it.
//!
//! External audit NETR-004: memory is bounded by a per-process ring
//! capped at [`MAX_EVENTS_PER_PROC`] and a hard cap of
//! [`MAX_TRACKED_PROCS`] keys, enforced in O(1) per insert with
//! [`LazyLru`] queues. Keys that hold only `PrivEsc` (whose chain only
//! logs) go first; evicting a key that still holds a `CredRead`,
//! `TmpExec` or `CanaryTrip` is counted, with a rate-limited WARN. Stale
//! keys are swept every [`SWEEP_EVERY`] new keys and dropped on query.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use nn_model::telemetry::NetFlowEvent;

use super::ancestry::AncestryTree;
use crate::decision::bounded::{LazyLru, LossCounter};
use crate::posture::host::PostureHost;

/// Default correlation lookback (§13 Q4). Rules may pass a different
/// `window_ns`; this is the value the migrated CHAIN-001..003 use,
/// matching the T10.5 5-minute precedent.
pub const CORRELATION_WINDOW_NS: u64 = 300 * 1_000_000_000;

/// External audit NETR-014 (lab PR 213): how long a credential read and a
/// canary trip are kept — 30 minutes. Past [`CORRELATION_WINDOW_NS`] they
/// give a record, never a response ([`ChainAge::Aged`]).
pub const LONG_RETENTION_NS: u64 = 30 * 60 * 1_000_000_000;

/// External audit NETR-014: how long a precursor of `kind` is kept, the
/// longest window any query of that kind may use. The high-confidence
/// precursors whose chain an attacker could outwait — a credential-store
/// read, a canary trip — are kept 30 minutes; a staging-directory exec
/// (package scriptlets, builds) and a `sudo`/`su` (routine admin work), as
/// common as they are short-lived, stay at 300 s.
pub fn retention_ns(kind: PrecursorKind) -> u64 {
    match kind {
        PrecursorKind::CredRead | PrecursorKind::CanaryTrip => LONG_RETENTION_NS,
        PrecursorKind::TmpExec | PrecursorKind::PrivEsc => CORRELATION_WINDOW_NS,
    }
}

/// External audit NETR-014: what a precursor of the queried kind is to an
/// egress ([`CorrelationStore::chain_age`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainAge {
    /// Within [`CORRELATION_WINDOW_NS`]: the chain's Critical verdict and
    /// its response, as before.
    Fresh,
    /// Older, within the kind's retention, and not reported yet: one High
    /// record without a response. `age_ns` is the age of the most recent
    /// such precursor; every aged one of the kind is then marked reported.
    Aged { age_ns: u64 },
}

/// Per-process precursor ring cap. A process that re-triggers the same
/// precursor many times only needs the most recent few to answer
/// "any/which precursor in window?".
const MAX_EVENTS_PER_PROC: usize = 16;

/// Distinct-process cap (hard, external audit NETR-004).
const MAX_TRACKED_PROCS: usize = 4096;

/// New keys between two sweeps of fully stale keys.
const SWEEP_EVERY: u64 = 256;

/// Review 70: egresses kept per process for a late precursor.
const MAX_EGRESS_PER_PROC: usize = 4;

/// Keys evicted while holding an in-window `CredRead`, `TmpExec` or
/// `CanaryTrip`, by any store since the agent started.
static LOST_PRECURSOR_KEYS: AtomicU64 = AtomicU64::new(0);

/// External audit NETR-004: processes whose blocking-chain precursors were
/// evicted for room, process-wide.
pub fn lost_precursor_keys_total() -> u64 {
    LOST_PRECURSOR_KEYS.load(Ordering::Relaxed)
}

/// Review 70 — an egress a chain rule evaluated before a precursor that
/// happened earlier in kernel time. The precursor travels through another
/// ring and pump (a credential read through the open sensor or FIM, the
/// egress through the network drain), so it can be processed after the
/// egress it precedes; the chain then completes on the precursor. Only
/// what the verdict needs is kept.
///
/// Lab PR 244: and the destination, which NN-L-CHAIN-002 judges — its
/// exemption of a lookup at a configured resolver and its port-53 hold —
/// when the staging exec is processed after the egress. Two fixed-size
/// fields: a note stays bounded, as the notes do
/// ([`MAX_EGRESS_PER_PROC`] per process, [`MAX_TRACKED_PROCS`] processes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EgressNote {
    pub pid: u32,
    pub comm: String,
    pub start_ns: u64,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
}

impl EgressNote {
    /// The note of a flow.
    pub fn of(nf: &NetFlowEvent) -> Self {
        Self {
            pid: nf.pid,
            comm: nf.comm.clone(),
            start_ns: nf.start_ns,
            dst_addr: nf.dst_addr,
            dst_port: nf.dst_port,
        }
    }
}

/// Lab PR 235: a noted egress, and whether a two-step chain already fired
/// on it. A claimed egress completes no further two-step chain, but a late
/// precursor can still complete the three-step CHAIN-007 with it.
///
/// Lab PR 244: the claim names the precursor of the two-step chain —
/// `CredRead` for NN-L-CHAIN-001, `TmpExec` for NN-L-CHAIN-002 — because
/// the step CHAIN-007 still lacks differs: after CHAIN-001 the staging exec
/// ([`CorrelationStore::exec_sequence_egress`]), after CHAIN-002 the
/// credential read ([`CorrelationStore::take_egress_after`]).
#[derive(Clone, Debug)]
struct NotedEgress {
    note: EgressNote,
    claimed_by: Option<PrecursorKind>,
}

/// PID-reuse-safe process identity (§13 Q2). `start_ns` is the task's
/// `start_time` (CLOCK_MONOTONIC ns, `Event::ProcessSpawn::start_ns`);
/// `start_ns == 0` means "incarnation unknown".
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ProcKey {
    pub pid: u32,
    pub start_ns: u64,
}

impl ProcKey {
    /// Key for a bare PID whose incarnation is not known.
    pub fn unresolved(pid: u32) -> Self {
        Self { pid, start_ns: 0 }
    }
}

/// The kind of precursor a chain rule records. Isolated by kind so a
/// credential read never satisfies a `/tmp`-exec query. Extensible:
/// D6 multi-step chains add their own kinds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PrecursorKind {
    /// NN-L-CHAIN-001 — credential-store FIM access (T1555).
    CredRead,
    /// NN-L-CHAIN-002 — process image executed from `/tmp/` (T1059).
    TmpExec,
    /// NN-L-CHAIN-003 — deception canary trip.
    CanaryTrip,
    /// NN-L-CHAIN-008 (D6) — `sudo`/`su` privilege-escalation exec
    /// (T1548). Recorded on the privesc process so a descendant's
    /// egress can be back-correlated to it.
    PrivEsc,
}

#[derive(Clone, Copy)]
struct Precursor {
    kind: PrecursorKind,
    ts_ns: u64,
    /// External audit NETR-014: an aged correlation was already recorded
    /// for it — no second record, and it no longer keeps its process's
    /// flows from the netflow pacing.
    aged_reported: bool,
}

impl Precursor {
    /// Kept at `now_ns`: within its kind's retention, or within `window_ns`
    /// when a query asks for more.
    fn kept(&self, now_ns: u64, window_ns: u64) -> bool {
        self.ts_ns >= now_ns.saturating_sub(retention_ns(self.kind).max(window_ns))
    }

    /// Could still complete a chain with an egress at `now_ns`: fresh, or
    /// aged within its retention and not reported yet.
    fn can_complete(&self, now_ns: u64) -> bool {
        self.ts_ns >= now_ns.saturating_sub(CORRELATION_WINDOW_NS)
            || (!self.aged_reported && self.kept(now_ns, 0))
    }
}

/// Shared correlation state. `Arc<Mutex<_>>`-wrapped by the engine and
/// queried from `Rule::evaluate`.
///
/// R08b (lab PR 251): `H` is the host of its ancestry tree
/// ([`AncestryTree`]'s).
pub struct CorrelationStore<H: PostureHost> {
    per_proc: HashMap<ProcKey, VecDeque<Precursor>>,
    /// External audit NETR-004: keys holding only `PrivEsc`, evicted
    /// first, least recently recorded first.
    privesc_only: LazyLru<ProcKey>,
    /// Keys holding a `CredRead`, `TmpExec` or `CanaryTrip`.
    protected: LazyLru<ProcKey>,
    /// New keys recorded, for the periodic sweep.
    new_keys: u64,
    lost: LossCounter,
    /// D4 — parent→child lineage for cross-PID correlation, and the
    /// `pid → start_ns` map (NETR-009).
    tree: AncestryTree<H>,
    /// Review 70 — egresses noted for a precursor processed after them,
    /// per process.
    egress: HashMap<ProcKey, VecDeque<NotedEgress>>,
    egress_order: LazyLru<ProcKey>,
}

impl<H: PostureHost> Default for CorrelationStore<H> {
    fn default() -> Self {
        Self::with_tree(AncestryTree::new())
    }
}

impl<H: PostureHost> CorrelationStore<H> {
    pub fn new() -> Self {
        Self::default()
    }

    /// A store over `tree` (a fixture proc root in tests).
    pub fn with_tree(tree: AncestryTree<H>) -> Self {
        Self {
            per_proc: HashMap::new(),
            privesc_only: LazyLru::new(),
            protected: LazyLru::new(),
            new_keys: 0,
            lost: LossCounter::new(&LOST_PRECURSOR_KEYS),
            tree,
            egress: HashMap::new(),
            egress_order: LazyLru::new(),
        }
    }

    // ── recording ───────────────────────────────────────────────────

    /// Record a `kind` precursor for an explicit [`ProcKey`] (an exec
    /// precursor, keyed with the start its event carries).
    pub fn record(&mut self, key: ProcKey, kind: PrecursorKind, ts_ns: u64) {
        self.push(
            key,
            Precursor {
                kind,
                ts_ns,
                aged_reported: false,
            },
        );
    }

    /// [`Self::record`] of a whole precursor (its reported mark kept when
    /// an exec hands it to a new incarnation).
    fn push(&mut self, key: ProcKey, precursor: Precursor) {
        let Precursor { kind, ts_ns, .. } = precursor;
        if !self.per_proc.contains_key(&key) {
            self.new_keys = self.new_keys.wrapping_add(1);
            if self.new_keys.is_multiple_of(SWEEP_EVERY) {
                self.prune_stale(ts_ns);
            }
            while self.per_proc.len() >= MAX_TRACKED_PROCS {
                if !self.evict_one(ts_ns) {
                    break;
                }
            }
        }
        let q = self.per_proc.entry(key).or_default();
        q.push_back(precursor);
        while q.len() > MAX_EVENTS_PER_PROC {
            q.pop_front();
        }
        if kind == PrecursorKind::PrivEsc && !self.protected.contains(&key) {
            self.privesc_only.touch(key);
        } else {
            self.privesc_only.remove(&key);
            self.protected.touch(key);
        }
    }

    /// Record for `pid`'s current incarnation (a precursor from a non-exec
    /// event: a FIM read, a canary trip).
    pub fn record_for_pid(&mut self, pid: u32, kind: PrecursorKind, ts_ns: u64) {
        self.record(self.current_key(pid), kind, ts_ns);
    }

    /// `pid`'s current incarnation as the ancestry tree knows it
    /// (`start_ns = 0` when its exec was never seen).
    pub fn current_key(&self, pid: u32) -> ProcKey {
        self.tree.current(pid)
    }

    /// Review 70: keep an egress that completed no same-process chain, for
    /// a precursor that arrives after it but happened before it.
    /// External audit NETR-004: the least recently noted key makes room,
    /// in O(1).
    pub fn note_egress(&mut self, key: ProcKey, note: EgressNote) {
        if !self.egress.contains_key(&key) {
            while self.egress.len() >= MAX_TRACKED_PROCS {
                match self.egress_order.pop_oldest() {
                    Some(old) => {
                        self.egress.remove(&old);
                    }
                    None => break,
                }
            }
        }
        let q = self.egress.entry(key).or_default();
        // Lab PR 224: a flow is judged at its connect, in snapshots and at
        // its close, all under its connect's timestamp: one note.
        if q.iter().any(|n| n.note.start_ns == note.start_ns) {
            self.egress_order.touch(key);
            return;
        }
        q.push_back(NotedEgress {
            note,
            claimed_by: None,
        });
        while q.len() > MAX_EGRESS_PER_PROC {
            q.pop_front();
        }
        self.egress_order.touch(key);
    }

    /// Review 70: take the earliest noted egress of `key` that happened
    /// after `after_ns`, within `window_ns` of it — the one a credential
    /// read stamped `after_ns` completes CHAIN-007 with. It is taken: an
    /// egress completes one late chain only. Lab PR 244: unclaimed, or
    /// claimed by NN-L-CHAIN-002 (`TmpExec`), whose verdict lacked the read;
    /// not one NN-L-CHAIN-001 claimed (the read was its own step).
    pub fn take_egress_after(
        &mut self,
        key: ProcKey,
        after_ns: u64,
        window_ns: u64,
    ) -> Option<EgressNote> {
        let q = self.egress.get_mut(&key)?;
        let idx = earliest_after(q, after_ns, window_ns, |c| {
            matches!(c, None | Some(PrecursorKind::TmpExec))
        });
        let note = idx.and_then(|i| q.remove(i)).map(|n| n.note);
        if q.is_empty() {
            self.remove_egress(&key);
        }
        note
    }

    /// Lab PR 235: [`Self::take_egress_after`] for a two-step chain
    /// (CHAIN-001): the earliest unclaimed egress is claimed, not removed —
    /// no later precursor completes a two-step chain with it again, and a
    /// `/tmp` exec processed after both can still complete CHAIN-007 with
    /// it.
    pub fn claim_egress_after(
        &mut self,
        key: ProcKey,
        after_ns: u64,
        window_ns: u64,
    ) -> Option<EgressNote> {
        let q = self.egress.get_mut(&key)?;
        let i = earliest_after(q, after_ns, window_ns, |c| c.is_none())?;
        let n = &mut q[i];
        n.claimed_by = Some(PrecursorKind::CredRead);
        Some(n.note.clone())
    }

    /// Lab PR 246: the connection a network canary trip owns — `pid`'s
    /// flow connected at `connect_ns`, the trip's own time — is no egress:
    /// its note is dropped. The note was taken when a row of the
    /// connection reached the rules before the trip (the close comes on
    /// another ring than the connect); left there, a precursor processed
    /// later would complete a chain with the trip's own connection
    /// (CHAIN-001 or CHAIN-007 on a late read, CHAIN-002 or CHAIN-007 on a
    /// late exec), which in the other order is never judged. Every key of
    /// the pid is looked at: until its exec is seen a note sits under the
    /// unresolved or the previous incarnation.
    pub fn drop_trip_egress(&mut self, pid: u32, connect_ns: u64) {
        let keys: Vec<ProcKey> = self
            .egress
            .keys()
            .filter(|k| k.pid == pid)
            .copied()
            .collect();
        for key in keys {
            if let Some(q) = self.egress.get_mut(&key) {
                q.retain(|n| n.note.start_ns != connect_ns);
                if q.is_empty() {
                    self.remove_egress(&key);
                }
            }
        }
    }

    /// Review 70: a two-step chain fired on this egress — `by` its
    /// precursor — so no late precursor may complete a two-step chain with
    /// it again. Lab PR 235: claimed, not removed (see
    /// [`Self::claim_egress_after`]). Lab PR 244: the first claim is kept
    /// (CHAIN-001 and CHAIN-002 may both answer a flow in order).
    pub fn claim_egress(&mut self, key: ProcKey, start_ns: u64, by: PrecursorKind) {
        if let Some(q) = self.egress.get_mut(&key) {
            for n in q.iter_mut().filter(|n| n.note.start_ns == start_ns) {
                n.claimed_by.get_or_insert(by);
            }
        }
    }

    /// Lab PR 244: the two-step NN-L-CHAIN-002 whose staging exec (`exec_ts`,
    /// of the process started at `start_ns`) is processed after the egress
    /// it preceded — the exec ring's pump behind the connect's, as in lab
    /// PR 235. The unclaimed noted egresses of the process at or after the
    /// exec (and its start) and within `window_ns` of it, earliest first;
    /// the rule picks the first its predicate admits and claims it
    /// ([`Self::claim_exec_egress`]). Bounded: at most
    /// [`MAX_EGRESS_PER_PROC`] per key, three keys. Read-only; none for an
    /// unknown start.
    pub fn exec_egresses(
        &self,
        pid: u32,
        start_ns: u64,
        exec_ts: u64,
        window_ns: u64,
    ) -> Vec<EgressNote> {
        if start_ns == 0 {
            return Vec::new();
        }
        let keys = self.exec_keys(pid, start_ns);
        let within = |ts: u64| ts >= exec_ts && ts >= start_ns && ts - exec_ts <= window_ns;
        let mut out: Vec<EgressNote> = keys
            .iter()
            .enumerate()
            .filter(|&(i, k)| !keys[..i].contains(k))
            .filter_map(|(_, k)| self.egress.get(k))
            .flatten()
            .filter(|n| n.claimed_by.is_none() && within(n.note.start_ns))
            .map(|n| n.note.clone())
            .collect();
        out.sort_by_key(|n| n.start_ns);
        out
    }

    /// Lab PR 244: NN-L-CHAIN-002 completed by a late exec on the egress
    /// connected at `egress_start_ns` ([`Self::exec_egresses`]): claimed
    /// (`TmpExec`) under whichever of the exec's keys holds it.
    pub fn claim_exec_egress(&mut self, pid: u32, start_ns: u64, egress_start_ns: u64) {
        for key in self.exec_keys(pid, start_ns) {
            self.claim_egress(key, egress_start_ns, PrecursorKind::TmpExec);
        }
    }

    /// Where the notes of an exec's process may be, before or after the
    /// exec is observed ([`Self::observe_spawn`] hands them to its own key):
    /// its own key, the PID's unresolved one, the incarnation the tree last
    /// saw (the keys of [`Self::exec_sequence_egress`]).
    fn exec_keys(&self, pid: u32, start_ns: u64) -> [ProcKey; 3] {
        [
            ProcKey { pid, start_ns },
            ProcKey::unresolved(pid),
            self.current_key(pid),
        ]
    }

    /// Lab PR 235: the three-step CHAIN-007 whose `/tmp` exec (`exec_ts`,
    /// of the process started at `start_ns`) is processed after the
    /// credential read and the egress that followed it — another ring, in
    /// kernel order before both (the CI flake of 22/10/2026). Returns the
    /// earliest noted egress, claimed or not, that follows a credential
    /// read of the same process made at or after the exec, all within
    /// `window_ns` of the exec. Read-only: [`Self::complete_exec_sequence`]
    /// commits it.
    ///
    /// Before the exec is observed, the read and the egress sit under the
    /// PID's unresolved key, the incarnation the tree last saw, or this
    /// one; all three are looked at, as [`Self::observe_spawn`] hands them
    /// over (only what happened since `start_ns`).
    pub fn exec_sequence_egress(
        &self,
        pid: u32,
        start_ns: u64,
        exec_ts: u64,
        window_ns: u64,
    ) -> Option<EgressNote> {
        if start_ns == 0 {
            return None;
        }
        let keys = [
            ProcKey { pid, start_ns },
            ProcKey::unresolved(pid),
            self.current_key(pid),
        ];
        let within = |ts: u64| ts >= exec_ts && ts >= start_ns && ts - exec_ts <= window_ns;
        let read_ts = keys
            .iter()
            .filter_map(|k| self.per_proc.get(k))
            .flatten()
            .filter(|p| p.kind == PrecursorKind::CredRead && within(p.ts_ns))
            .map(|p| p.ts_ns)
            .min()?;
        keys.iter()
            .filter_map(|k| self.egress.get(k))
            .flatten()
            .map(|n| &n.note)
            .filter(|n| n.start_ns > read_ts && within(n.start_ns))
            .min_by_key(|n| n.start_ns)
            .cloned()
    }

    /// Lab PR 235: commit a late exec's CHAIN-007 found by
    /// [`Self::exec_sequence_egress`]: the exec is observed (the read and
    /// the egress handed to its incarnation), its `TmpExec` recorded, and
    /// the egress removed — it completes no other chain.
    pub fn complete_exec_sequence(
        &mut self,
        pid: u32,
        ppid: u32,
        start_ns: u64,
        exec_ts: u64,
        egress_start_ns: u64,
    ) {
        self.observe_spawn(pid, ppid, start_ns);
        let key = ProcKey { pid, start_ns };
        self.record(key, PrecursorKind::TmpExec, exec_ts);
        if let Some(q) = self.egress.get_mut(&key) {
            q.retain(|n| n.note.start_ns != egress_start_ns);
            if q.is_empty() {
                self.remove_egress(&key);
            }
        }
    }

    // ── querying ─────────────────────────────────────────────────────

    /// `true` if `key` has a `kind` precursor within `window_ns` at or
    /// before `now_ns`. Prunes out-of-window entries; drops the key
    /// when its ring empties.
    pub fn has_recent(
        &mut self,
        key: ProcKey,
        kind: PrecursorKind,
        now_ns: u64,
        window_ns: u64,
    ) -> bool {
        let hit = self.with_in_window(key, now_ns, window_ns, |events, match_cutoff| {
            events
                .iter()
                .any(|e| e.kind == kind && e.ts_ns >= match_cutoff)
        });
        self.drop_if_empty(&key);
        hit
    }

    /// [`Self::has_recent`] for `pid`'s current incarnation.
    pub fn has_recent_for_pid(
        &mut self,
        pid: u32,
        kind: PrecursorKind,
        now_ns: u64,
        window_ns: u64,
    ) -> bool {
        self.has_recent(self.current_key(pid), kind, now_ns, window_ns)
    }

    /// `true` if every kind in `kinds` appears, **in order**, among
    /// `key`'s in-window precursors (an ordered subsequence by
    /// timestamp). The N-event foundation for the D6 kill chains. An
    /// empty `kinds` is vacuously `true`.
    pub fn has_sequence(
        &mut self,
        key: ProcKey,
        kinds: &[PrecursorKind],
        now_ns: u64,
        window_ns: u64,
    ) -> bool {
        let matched = self.with_in_window(key, now_ns, window_ns, |events, match_cutoff| {
            // Consider only in-(query)-window precursors, in ts order
            // (insertion order ≈ ts order; sort defensively).
            let mut ordered: Vec<&Precursor> =
                events.iter().filter(|e| e.ts_ns >= match_cutoff).collect();
            ordered.sort_by_key(|e| e.ts_ns);
            let mut idx = 0usize;
            for e in ordered {
                if idx < kinds.len() && e.kind == kinds[idx] {
                    idx += 1;
                }
            }
            idx == kinds.len()
        });
        self.drop_if_empty(&key);
        matched
    }

    /// [`Self::has_sequence`] for `pid`'s current incarnation.
    pub fn has_sequence_for_pid(
        &mut self,
        pid: u32,
        kinds: &[PrecursorKind],
        now_ns: u64,
        window_ns: u64,
    ) -> bool {
        self.has_sequence(self.current_key(pid), kinds, now_ns, window_ns)
    }

    /// External audit NETR-014 (lab PR 213): what `key`'s precursors of
    /// `kind` are to an egress at `now_ns` — [`ChainAge::Fresh`] when one is
    /// within [`CORRELATION_WINDOW_NS`], else [`ChainAge::Aged`] for the
    /// first query that finds one within the kind's [`retention_ns`] (they
    /// are then marked reported), else `None`. Prunes like
    /// [`Self::has_recent`].
    pub fn chain_age(
        &mut self,
        key: ProcKey,
        kind: PrecursorKind,
        now_ns: u64,
    ) -> Option<ChainAge> {
        let retention = retention_ns(kind);
        let q = self.per_proc.get_mut(&key)?;
        q.retain(|e| e.kept(now_ns, retention));
        let fresh_cutoff = now_ns.saturating_sub(CORRELATION_WINDOW_NS);
        let retention_cutoff = now_ns.saturating_sub(retention);
        let age = if q.iter().any(|e| e.kind == kind && e.ts_ns >= fresh_cutoff) {
            Some(ChainAge::Fresh)
        } else {
            let mut newest: Option<u64> = None;
            for e in q
                .iter_mut()
                .filter(|e| e.kind == kind && !e.aged_reported && e.ts_ns >= retention_cutoff)
            {
                e.aged_reported = true;
                newest = Some(newest.map_or(e.ts_ns, |n| n.max(e.ts_ns)));
            }
            newest.map(|ts| ChainAge::Aged {
                age_ns: now_ns.saturating_sub(ts),
            })
        };
        self.drop_if_empty(&key);
        age
    }

    /// [`Self::chain_age`] for `pid`'s current incarnation.
    pub fn chain_age_for_pid(
        &mut self,
        pid: u32,
        kind: PrecursorKind,
        now_ns: u64,
    ) -> Option<ChainAge> {
        self.chain_age(self.current_key(pid), kind, now_ns)
    }

    /// [`Self::chain_age`] over `pid`'s strict ancestors (CHAIN-004/006): a
    /// fresh precursor in any of them first (the Critical verdict), else
    /// the nearest ancestor with an aged, unreported one.
    pub fn chain_age_in_ancestors(
        &mut self,
        pid: u32,
        kind: PrecursorKind,
        now_ns: u64,
    ) -> Option<ChainAge> {
        if self.has_recent_in_ancestors(pid, kind, now_ns, CORRELATION_WINDOW_NS) {
            return Some(ChainAge::Fresh);
        }
        for ancestor in self.tree.get_ancestors(pid) {
            if let Some(age) = self.chain_age(ancestor, kind, now_ns) {
                return Some(age);
            }
        }
        None
    }

    // ── D4: cross-PID lineage ────────────────────────────────────────

    /// Observe the exec of `child_pid` (own start `start_ns`, 0 when the
    /// record predates POS-003) under parent `ppid`.
    ///
    /// External audit NETR-009: a start other than the one recorded for
    /// the PID is a new incarnation. It takes over the precursors and
    /// egresses recorded under the PID's previous or unknown incarnation
    /// that happened at or after its own start — an event processed
    /// before the exec that started it (another ring) — and the rest is
    /// dropped. A re-exec of the same process (same start) keeps its
    /// state. Without a start, a second sighting of the PID is a reuse
    /// and its state is dropped, as before.
    pub fn observe_spawn(&mut self, child_pid: u32, ppid: u32, start_ns: u64) {
        let previous = self.tree.observe(child_pid, ppid, start_ns);
        if previous == Some(start_ns) && start_ns != 0 {
            return;
        }
        let new_key = ProcKey {
            pid: child_pid,
            start_ns,
        };
        let mut old_keys = vec![ProcKey::unresolved(child_pid)];
        if let Some(prev) = previous.filter(|&p| p != 0 && p != start_ns) {
            old_keys.push(ProcKey {
                pid: child_pid,
                start_ns: prev,
            });
        }
        if start_ns == 0 {
            // No incarnation to hand anything to.
            if previous.is_some() {
                for k in old_keys {
                    self.remove_key(&k);
                    self.remove_egress(&k);
                }
            }
            return;
        }
        for old in old_keys {
            if let Some(q) = self.per_proc.get(&old).cloned() {
                self.remove_key(&old);
                for p in q.iter().filter(|p| p.ts_ns >= start_ns) {
                    self.push(new_key, *p);
                }
            }
            if let Some(q) = self.egress.get(&old).cloned() {
                self.remove_egress(&old);
                for n in q.into_iter().filter(|n| n.note.start_ns >= start_ns) {
                    let (claimed_by, at) = (n.claimed_by, n.note.start_ns);
                    self.note_egress(new_key, n.note);
                    if let Some(by) = claimed_by {
                        self.claim_egress(new_key, at, by);
                    }
                }
            }
        }
    }

    /// Same-PID **or** any-ancestor: `true` if `pid` itself, or any
    /// process in its lineage, has a `kind` precursor in window. The
    /// cross-PID kill-chain query (design §4 G4) the D6 chains build on.
    pub fn has_recent_in_lineage(
        &mut self,
        pid: u32,
        kind: PrecursorKind,
        now_ns: u64,
        window_ns: u64,
    ) -> bool {
        self.has_recent_for_pid(pid, kind, now_ns, window_ns)
            || self.has_recent_in_ancestors(pid, kind, now_ns, window_ns)
    }

    /// Strictly an **ancestor** (not self) has a `kind` precursor in
    /// window — the pure cross-PID query the D6 CHAIN-004..008 rules use,
    /// so they never shadow the same-PID CHAIN-001..003. External audit
    /// NETR-009: each ancestor is queried with its own incarnation.
    pub fn has_recent_in_ancestors(
        &mut self,
        pid: u32,
        kind: PrecursorKind,
        now_ns: u64,
        window_ns: u64,
    ) -> bool {
        for ancestor in self.tree.get_ancestors(pid) {
            if self.has_recent(ancestor, kind, now_ns, window_ns) {
                return true;
            }
        }
        false
    }

    /// External audit NET-019: whether `pid` or one of its ancestors
    /// holds a precursor that could still complete a chain with a flow at
    /// `now_ns` — so the netflow limiter never holds it back. External
    /// audit NETR-014: within [`CORRELATION_WINDOW_NS`], or within its
    /// kind's retention while its aged correlation is not recorded yet.
    /// Read-only: nothing is pruned.
    pub fn has_precursor_in_lineage(&self, pid: u32, now_ns: u64) -> bool {
        let live = |key: &ProcKey| {
            self.per_proc
                .get(key)
                .is_some_and(|q| q.iter().any(|p| p.can_complete(now_ns)))
        };
        live(&self.current_key(pid)) || self.tree.get_ancestors(pid).iter().any(live)
    }

    /// Lab PR 224 (CM-02 d): the first of `kinds` that `pid` or one of its
    /// ancestors holds and that could still complete a chain at `now_ns`
    /// (as [`Self::has_precursor_in_lineage`] reads it). Read-only.
    pub fn precursor_in_lineage(
        &self,
        pid: u32,
        kinds: &[PrecursorKind],
        now_ns: u64,
    ) -> Option<PrecursorKind> {
        let held = |key: &ProcKey| {
            self.per_proc.get(key).and_then(|q| {
                q.iter()
                    .find(|p| kinds.contains(&p.kind) && p.can_complete(now_ns))
                    .map(|p| p.kind)
            })
        };
        held(&self.current_key(pid)).or_else(|| self.tree.get_ancestors(pid).iter().find_map(held))
    }

    /// Read-only view of the ancestry tree (lineage queries / tests).
    pub fn ancestry(&self) -> &AncestryTree<H> {
        &self.tree
    }

    /// Keys evicted from this store while holding an in-window
    /// `CredRead`, `TmpExec` or `CanaryTrip`.
    pub fn lost_precursor_keys(&self) -> u64 {
        self.lost.count()
    }

    // ── internals ────────────────────────────────────────────────────

    /// TTL-prune `key`'s entries, then run `f` over the survivors with
    /// the query's match-cutoff. Each entry is pruned past the **larger**
    /// of its kind's [`retention_ns`] and the query window (external audit
    /// NETR-014: per kind, so a short-window query of one kind never evicts
    /// a precursor of another kind kept longer); `f` then filters to the
    /// query's own window via the `match_cutoff` it receives. Returns `f`'s
    /// result (or its default when `key` is absent).
    fn with_in_window<R: Default>(
        &mut self,
        key: ProcKey,
        now_ns: u64,
        window_ns: u64,
        f: impl FnOnce(&VecDeque<Precursor>, u64) -> R,
    ) -> R {
        let match_cutoff = now_ns.saturating_sub(window_ns);
        if let Some(q) = self.per_proc.get_mut(&key) {
            q.retain(|e| e.kept(now_ns, window_ns));
            f(q, match_cutoff)
        } else {
            R::default()
        }
    }

    fn drop_if_empty(&mut self, key: &ProcKey) {
        if self.per_proc.get(key).is_some_and(|q| q.is_empty()) {
            self.remove_key(key);
        }
    }

    /// O(1): the queues drop their entries lazily.
    fn remove_key(&mut self, key: &ProcKey) {
        if self.per_proc.remove(key).is_some() {
            self.privesc_only.remove(key);
            self.protected.remove(key);
        }
    }

    fn remove_egress(&mut self, key: &ProcKey) {
        if self.egress.remove(key).is_some() {
            self.egress_order.remove(key);
        }
    }

    /// External audit NETR-004: evict one key, `PrivEsc`-only keys first.
    /// `false` when there is nothing to evict.
    fn evict_one(&mut self, now_ns: u64) -> bool {
        let (victim, protected) = match self.privesc_only.pop_oldest() {
            Some(k) => (k, false),
            None => match self.protected.pop_oldest() {
                Some(k) => (k, true),
                None => return false,
            },
        };
        let lost = self.per_proc.remove(&victim).is_some_and(|q| {
            protected
                && q.iter()
                    .any(|p| p.kind != PrecursorKind::PrivEsc && p.can_complete(now_ns))
        });
        if lost && self.lost.bump() {
            tracing::warn!(
                pid = victim.pid,
                evicted = self.lost.count(),
                cap = MAX_TRACKED_PROCS,
                "correlation store full: evicted a process holding a chain \
                 precursor, its chain can no longer complete"
            );
        }
        true
    }

    /// Drop the precursors past their kind's retention relative to
    /// `now_ns` (external audit NETR-014), and the processes left with
    /// none. Run every [`SWEEP_EVERY`] new keys.
    fn prune_stale(&mut self, now_ns: u64) {
        let (low, high) = (&mut self.privesc_only, &mut self.protected);
        self.per_proc.retain(|k, q| {
            q.retain(|e| e.kept(now_ns, 0));
            if q.is_empty() {
                low.remove(k);
                high.remove(k);
                false
            } else {
                true
            }
        });
    }

    #[cfg(test)]
    fn tracked_procs(&self) -> usize {
        self.per_proc.len()
    }
}

/// The index of the earliest egress of `q` after `after_ns` and within
/// `window_ns` of it, of those whose claim `takes` accepts.
fn earliest_after(
    q: &VecDeque<NotedEgress>,
    after_ns: u64,
    window_ns: u64,
    takes: impl Fn(Option<PrecursorKind>) -> bool,
) -> Option<usize> {
    q.iter()
        .enumerate()
        .filter(|(_, n)| takes(n.claimed_by))
        .filter(|(_, n)| n.note.start_ns > after_ns && n.note.start_ns - after_ns <= window_ns)
        .min_by_key(|(_, n)| n.note.start_ns)
        .map(|(i, _)| i)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::posture::host::testing::TestHost as H;

    /// R08b (lab PR 251): the store on the portable test host.
    type CorrelationStore = super::CorrelationStore<H>;

    const SEC: u64 = 1_000_000_000;
    const W: u64 = CORRELATION_WINDOW_NS;

    fn key(pid: u32, start: u64) -> ProcKey {
        ProcKey {
            pid,
            start_ns: start,
        }
    }

    /// The note of an egress of `pid` connected at `at` to `port` of
    /// 203.0.113.9.
    fn note(pid: u32, at: u64, port: u16) -> EgressNote {
        EgressNote {
            pid,
            comm: "p".to_string(),
            start_ns: at,
            dst_addr: IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 9)),
            dst_port: port,
        }
    }

    #[test]
    fn records_and_finds_within_window() {
        let mut s = CorrelationStore::new();
        s.record_for_pid(42, PrecursorKind::CredRead, 10 * SEC);
        assert!(s.has_recent_for_pid(42, PrecursorKind::CredRead, 10 * SEC + 30 * SEC, W));
    }

    #[test]
    fn evicts_after_ttl() {
        let mut s = CorrelationStore::new();
        s.record_for_pid(42, PrecursorKind::TmpExec, 10 * SEC);
        // 6 minutes later — past the 5-minute window.
        assert!(!s.has_recent_for_pid(42, PrecursorKind::TmpExec, 10 * SEC + 360 * SEC, W));
        // And the now-empty key was dropped.
        assert_eq!(s.tracked_procs(), 0);
        // External audit NETR-014: a credential read is past the 300 s
        // window then too, but kept for its 30 minutes.
        s.record_for_pid(43, PrecursorKind::CredRead, 10 * SEC);
        assert!(!s.has_recent_for_pid(43, PrecursorKind::CredRead, 10 * SEC + 360 * SEC, W));
        assert_eq!(s.tracked_procs(), 1);
        assert!(!s.has_recent_for_pid(
            43,
            PrecursorKind::CredRead,
            10 * SEC + LONG_RETENTION_NS + SEC,
            LONG_RETENTION_NS
        ));
        assert_eq!(s.tracked_procs(), 0);
    }

    /// External audit NETR-014 (lab PR 213): the triage's pins, at the
    /// store. A credential read correlates for 30 minutes (fresh within
    /// 300 s, aged after, nothing past 30 min); so does a canary trip.
    #[test]
    fn a_cred_read_correlates_for_thirty_minutes() {
        for kind in [PrecursorKind::CredRead, PrecursorKind::CanaryTrip] {
            let t0 = 100 * SEC;
            let mut s = CorrelationStore::new();
            s.record_for_pid(42, kind, t0);
            assert_eq!(
                s.chain_age_for_pid(42, kind, t0 + 60 * SEC),
                Some(ChainAge::Fresh)
            );
            assert_eq!(
                s.chain_age_for_pid(42, kind, t0 + 20 * 60 * SEC),
                Some(ChainAge::Aged {
                    age_ns: 20 * 60 * SEC
                })
            );
            let mut s = CorrelationStore::new();
            s.record_for_pid(42, kind, t0);
            assert_eq!(s.chain_age_for_pid(42, kind, t0 + 31 * 60 * SEC), None);
            assert_eq!(s.tracked_procs(), 0, "pruned past its retention");
        }
    }

    /// A staging exec (and a sudo/su) still expires after five minutes.
    #[test]
    fn a_tmp_exec_still_expires_after_five_minutes() {
        for kind in [PrecursorKind::TmpExec, PrecursorKind::PrivEsc] {
            let mut s = CorrelationStore::new();
            s.record_for_pid(42, kind, 10 * SEC);
            assert_eq!(
                s.chain_age_for_pid(42, kind, 10 * SEC + 299 * SEC),
                Some(ChainAge::Fresh)
            );
            assert_eq!(s.chain_age_for_pid(42, kind, 10 * SEC + 301 * SEC), None);
            assert_eq!(s.tracked_procs(), 0);
        }
        assert_eq!(retention_ns(PrecursorKind::TmpExec), CORRELATION_WINDOW_NS);
        assert_eq!(retention_ns(PrecursorKind::PrivEsc), CORRELATION_WINDOW_NS);
        assert_eq!(retention_ns(PrecursorKind::CredRead), 30 * 60 * SEC);
        assert_eq!(retention_ns(PrecursorKind::CanaryTrip), 30 * 60 * SEC);
    }

    /// An aged correlation is given once per precursor: every aged one of
    /// the kind is marked; a fresh one still answers Fresh; a newer read is
    /// a new record. The mark follows an exec to the new incarnation.
    #[test]
    fn an_aged_precursor_is_reported_once() {
        let mut s = CorrelationStore::new();
        let k = key(42, 5 * SEC);
        s.record(k, PrecursorKind::CredRead, 10 * SEC);
        s.record(k, PrecursorKind::CredRead, 20 * SEC);
        assert_eq!(
            s.chain_age(k, PrecursorKind::CredRead, 20 * SEC + 400 * SEC),
            Some(ChainAge::Aged { age_ns: 400 * SEC }),
            "the most recent aged read's age"
        );
        assert_eq!(
            s.chain_age(k, PrecursorKind::CredRead, 20 * SEC + 401 * SEC),
            None
        );
        s.record(k, PrecursorKind::CredRead, 500 * SEC);
        assert_eq!(
            s.chain_age(k, PrecursorKind::CredRead, 600 * SEC),
            Some(ChainAge::Fresh)
        );
        assert_eq!(
            s.chain_age(k, PrecursorKind::CredRead, 600 * SEC),
            Some(ChainAge::Fresh)
        );
        assert_eq!(
            s.chain_age(k, PrecursorKind::CredRead, 900 * SEC),
            Some(ChainAge::Aged { age_ns: 400 * SEC })
        );
        assert_eq!(s.chain_age(k, PrecursorKind::CredRead, 901 * SEC), None);
        // another kind of the same process is its own
        s.record(k, PrecursorKind::CanaryTrip, 30 * SEC);
        assert!(matches!(
            s.chain_age(k, PrecursorKind::CanaryTrip, 902 * SEC),
            Some(ChainAge::Aged { .. })
        ));
        // A re-exec under the same PID (a new start) inherits the marked
        // reads processed before it: no second record.
        let mut s = CorrelationStore::new();
        s.record_for_pid(77, PrecursorKind::CredRead, 10 * SEC);
        assert!(s
            .chain_age_for_pid(77, PrecursorKind::CredRead, 400 * SEC)
            .is_some());
        s.observe_spawn(77, 1, 9 * SEC);
        assert_eq!(
            s.chain_age_for_pid(77, PrecursorKind::CredRead, 410 * SEC),
            None
        );
    }

    /// The pruning is per kind: a short query of one kind never removes a
    /// precursor of a kind kept longer, nor does the periodic sweep.
    #[test]
    fn a_short_query_or_the_sweep_keeps_a_long_kind() {
        let mut s = CorrelationStore::new();
        let k = key(42, 1);
        s.record(k, PrecursorKind::CredRead, 10 * SEC);
        s.record(k, PrecursorKind::TmpExec, 11 * SEC);
        assert!(!s.has_recent(k, PrecursorKind::TmpExec, 611 * SEC, W));
        assert_eq!(
            s.per_proc.get(&k).map(|q| q.len()),
            Some(1),
            "the exec went"
        );
        assert!(matches!(
            s.chain_age(k, PrecursorKind::CredRead, 611 * SEC),
            Some(ChainAge::Aged { .. })
        ));
        let mut s = CorrelationStore::new();
        s.record(key(1, 1), PrecursorKind::CredRead, 10 * SEC);
        s.record(key(2, 1), PrecursorKind::TmpExec, 10 * SEC);
        s.prune_stale(10 * SEC + 600 * SEC);
        assert_eq!(s.tracked_procs(), 1);
        assert!(s.per_proc.contains_key(&key(1, 1)));
        s.prune_stale(10 * SEC + LONG_RETENTION_NS + SEC);
        assert_eq!(s.tracked_procs(), 0);
    }

    /// External audit NET-019 / NETR-014: the netflow limiter keeps
    /// evaluating the flows of a process whose credential read could still
    /// give its aged record — not once it was given, nor past 30 minutes.
    #[test]
    fn the_limiter_guard_follows_the_retention() {
        let mut s = CorrelationStore::new();
        s.record_for_pid(42, PrecursorKind::CredRead, 10 * SEC);
        s.observe_spawn(43, 42, 11 * SEC);
        assert!(s.has_precursor_in_lineage(42, 20 * 60 * SEC));
        assert!(s.has_precursor_in_lineage(43, 20 * 60 * SEC), "a child too");
        assert!(!s.has_precursor_in_lineage(42, 10 * SEC + LONG_RETENTION_NS + SEC));
        assert!(s
            .chain_age_for_pid(42, PrecursorKind::CredRead, 20 * 60 * SEC)
            .is_some());
        assert!(
            !s.has_precursor_in_lineage(42, 20 * 60 * SEC + SEC),
            "reported"
        );
        // a staging exec: 300 s, as before
        let mut s = CorrelationStore::new();
        s.record_for_pid(50, PrecursorKind::TmpExec, 10 * SEC);
        assert!(s.has_precursor_in_lineage(50, 300 * SEC));
        assert!(!s.has_precursor_in_lineage(50, 311 * SEC));
    }

    #[test]
    fn per_pid_isolated() {
        let mut s = CorrelationStore::new();
        s.record_for_pid(42, PrecursorKind::CredRead, 10 * SEC);
        assert!(!s.has_recent_for_pid(99, PrecursorKind::CredRead, 11 * SEC, W));
        assert!(s.has_recent_for_pid(42, PrecursorKind::CredRead, 11 * SEC, W));
    }

    #[test]
    fn kinds_are_isolated() {
        // Cross-rule isolation: a CredRead precursor must not satisfy a
        // TmpExec query for the same pid.
        let mut s = CorrelationStore::new();
        s.record_for_pid(42, PrecursorKind::CredRead, 10 * SEC);
        assert!(!s.has_recent_for_pid(42, PrecursorKind::TmpExec, 11 * SEC, W));
        assert!(s.has_recent_for_pid(42, PrecursorKind::CredRead, 11 * SEC, W));
    }

    #[test]
    fn pid_reuse_keys_are_distinct() {
        // (pid=42, start=A) and (pid=42, start=B) are different processes.
        let mut s = CorrelationStore::new();
        s.record(key(42, 1_000), PrecursorKind::CredRead, 10 * SEC);
        assert!(
            !s.has_recent(key(42, 2_000), PrecursorKind::CredRead, 11 * SEC, W),
            "recycled PID with a new start_ns must not inherit the old precursor"
        );
        assert!(s.has_recent(key(42, 1_000), PrecursorKind::CredRead, 11 * SEC, W));
    }

    #[test]
    fn bounded_events_per_proc() {
        let mut s = CorrelationStore::new();
        for i in 0..(MAX_EVENTS_PER_PROC as u64 + 10) {
            s.record_for_pid(7, PrecursorKind::CanaryTrip, (i + 1) * SEC);
        }
        let k = ProcKey::unresolved(7);
        assert_eq!(
            s.per_proc.get(&k).map(|q| q.len()),
            Some(MAX_EVENTS_PER_PROC)
        );
    }

    #[test]
    fn bounded_tracked_procs_prunes_stale_on_overflow() {
        let mut s = CorrelationStore::new();
        // Fill with stale (t=1) entries, then insert a fresh one far in
        // the future at capacity → stale ones get pruned.
        for pid in 0..MAX_TRACKED_PROCS as u32 {
            s.record_for_pid(pid, PrecursorKind::TmpExec, SEC);
        }
        assert_eq!(s.tracked_procs(), MAX_TRACKED_PROCS);
        // A new pid at t = 10 min forces prune_stale (all old are stale).
        s.record_for_pid(u32::MAX, PrecursorKind::TmpExec, 600 * SEC);
        assert!(s.tracked_procs() <= MAX_TRACKED_PROCS);
    }

    #[test]
    fn sequence_three_events_in_order() {
        let mut s = CorrelationStore::new();
        let k = key(42, 1_000);
        s.record(k, PrecursorKind::TmpExec, SEC);
        s.record(k, PrecursorKind::CredRead, 2 * SEC);
        s.record(k, PrecursorKind::CanaryTrip, 3 * SEC);
        assert!(s.has_sequence(
            k,
            &[
                PrecursorKind::TmpExec,
                PrecursorKind::CredRead,
                PrecursorKind::CanaryTrip
            ],
            4 * SEC,
            W
        ));
    }

    #[test]
    fn sequence_breaks_if_event_missing() {
        let mut s = CorrelationStore::new();
        let k = key(42, 1_000);
        s.record(k, PrecursorKind::TmpExec, SEC);
        s.record(k, PrecursorKind::CanaryTrip, 3 * SEC);
        // CredRead never recorded → the 3-step sequence does not match.
        assert!(!s.has_sequence(
            k,
            &[
                PrecursorKind::TmpExec,
                PrecursorKind::CredRead,
                PrecursorKind::CanaryTrip
            ],
            4 * SEC,
            W
        ));
        // But the 2-step subsequence still present does.
        assert!(s.has_sequence(
            k,
            &[PrecursorKind::TmpExec, PrecursorKind::CanaryTrip],
            4 * SEC,
            W
        ));
    }

    #[test]
    fn sequence_respects_window() {
        let mut s = CorrelationStore::new();
        let k = key(42, 1_000);
        s.record(k, PrecursorKind::TmpExec, SEC);
        s.record(k, PrecursorKind::CredRead, 2 * SEC);
        // Query 6 minutes after the first event — TmpExec is now out of
        // window, so the [TmpExec, CredRead] sequence can't complete.
        assert!(!s.has_sequence(
            k,
            &[PrecursorKind::TmpExec, PrecursorKind::CredRead],
            SEC + 360 * SEC,
            W
        ));
    }

    #[test]
    fn sequence_out_of_order_does_not_match() {
        let mut s = CorrelationStore::new();
        let k = key(42, 1_000);
        // Recorded CredRead before TmpExec.
        s.record(k, PrecursorKind::CredRead, SEC);
        s.record(k, PrecursorKind::TmpExec, 2 * SEC);
        // Asking for [TmpExec, CredRead] order → no match (CredRead is
        // earlier than TmpExec).
        assert!(!s.has_sequence(
            k,
            &[PrecursorKind::TmpExec, PrecursorKind::CredRead],
            3 * SEC,
            W
        ));
    }

    #[test]
    fn empty_sequence_is_vacuously_true_when_proc_known() {
        let mut s = CorrelationStore::new();
        let k = key(1, 1);
        s.record(k, PrecursorKind::CredRead, SEC);
        assert!(s.has_sequence(k, &[], 2 * SEC, W));
    }

    #[test]
    fn per_rule_window_is_honoured() {
        let mut s = CorrelationStore::new();
        s.record_for_pid(42, PrecursorKind::CredRead, 100 * SEC);
        // A short 10s window misses a 30s-old precursor...
        assert!(!s.has_recent_for_pid(42, PrecursorKind::CredRead, 130 * SEC, 10 * SEC));
        // ...but the default window still finds it.
        assert!(s.has_recent_for_pid(42, PrecursorKind::CredRead, 130 * SEC, W));
    }

    // ── D4 cross-PID lineage ────────────────────────────────────────

    #[test]
    fn cross_pid_chain_detection_via_ancestry() {
        // Parent (pid 100) reads creds; it spawns child 200; the child
        // does the egress. has_recent_in_lineage(child) finds the
        // parent's precursor via the ancestry walk.
        let mut s = CorrelationStore::new();
        s.record_for_pid(100, PrecursorKind::CredRead, 10 * SEC);
        s.observe_spawn(200, 100, 0);
        assert!(s.has_recent_in_lineage(200, PrecursorKind::CredRead, 12 * SEC, W));
        // Same-PID still matches via lineage (self is checked first).
        s.record_for_pid(300, PrecursorKind::CanaryTrip, 10 * SEC);
        assert!(s.has_recent_in_lineage(300, PrecursorKind::CanaryTrip, 11 * SEC, W));
    }

    #[test]
    fn multi_level_lineage_lookup() {
        // 100 → 200 → 300; precursor on the grandparent reaches the
        // grandchild.
        let mut s = CorrelationStore::new();
        s.record_for_pid(100, PrecursorKind::TmpExec, 10 * SEC);
        s.observe_spawn(200, 100, 0);
        s.observe_spawn(300, 200, 0);
        assert!(s.has_recent_in_lineage(300, PrecursorKind::TmpExec, 12 * SEC, W));
    }

    #[test]
    fn ancestor_chain_breaks_on_unrelated_process() {
        let mut s = CorrelationStore::new();
        s.record_for_pid(100, PrecursorKind::CredRead, 10 * SEC);
        s.observe_spawn(200, 100, 0);
        // 999 is not in 200's lineage and has no precursor of its own.
        assert!(!s.has_recent_in_lineage(999, PrecursorKind::CredRead, 12 * SEC, W));
        // And a different kind along the real lineage still misses.
        assert!(!s.has_recent_in_lineage(200, PrecursorKind::TmpExec, 12 * SEC, W));
    }

    #[test]
    fn pid_reuse_via_observe_spawn_wipes_stale_precursor() {
        // pid 200 reads creds, then the PID is recycled (a fresh spawn
        // of 200) — the new incarnation must not inherit the precursor.
        let mut s = CorrelationStore::new();
        s.record_for_pid(200, PrecursorKind::CredRead, 10 * SEC);
        s.observe_spawn(200, 100, 0); // first sighting (not reuse)
        assert!(
            s.has_recent_for_pid(200, PrecursorKind::CredRead, 11 * SEC, W),
            "first spawn does not wipe"
        );
        s.observe_spawn(200, 150, 0); // second sighting = reuse
        assert!(
            !s.has_recent_for_pid(200, PrecursorKind::CredRead, 12 * SEC, W),
            "recycled PID's stale precursor must be wiped"
        );
    }

    #[test]
    fn lineage_exposes_ancestry_tree() {
        let mut s = CorrelationStore::new();
        s.observe_spawn(200, 100, 0);
        assert!(s.ancestry().is_ancestor(200, ProcKey::unresolved(100)));
    }

    /// Lab PR 246: a network canary trip's own connection, noted when a
    /// row of it reached the rules before the trip, is dropped under every
    /// key of the pid (unresolved, previous incarnation): no late read or
    /// exec completes a chain with it. Another flow of the pid, and the
    /// same connect time of another pid, stay.
    #[test]
    fn a_trips_own_connection_is_no_egress_for_a_late_precursor() {
        let note = |pid, start_ns| EgressNote {
            pid,
            comm: "bash".into(),
            start_ns,
            dst_addr: "127.0.0.1".parse().unwrap(),
            dst_port: 41147,
        };
        let mut s = CorrelationStore::new();
        s.note_egress(ProcKey::unresolved(9825), note(9825, 100 * SEC));
        s.note_egress(key(9825, 7), note(9825, 100 * SEC));
        s.note_egress(key(9825, 7), note(9825, 101 * SEC));
        s.note_egress(ProcKey::unresolved(9826), note(9826, 100 * SEC));
        s.drop_trip_egress(9825, 100 * SEC);
        assert!(
            !s.egress.contains_key(&ProcKey::unresolved(9825)),
            "emptied, removed"
        );
        assert!(s
            .claim_egress_after(key(9825, 7), 99 * SEC, W)
            .is_some_and(|n| n.start_ns == 101 * SEC));
        assert!(s
            .take_egress_after(ProcKey::unresolved(9826), 99 * SEC, W)
            .is_some());
    }

    // ── External audit NETR-004: a hard cap, O(1) per insert ─────────

    #[test]
    fn record_keeps_the_cap_with_live_keys() {
        let mut s = CorrelationStore::new();
        // The oldest key holds only PrivEsc; the others a TmpExec.
        s.record(key(1, 1), PrecursorKind::PrivEsc, SEC);
        for pid in 2..=5000u32 {
            s.record(key(pid, 1), PrecursorKind::TmpExec, SEC + u64::from(pid));
        }
        assert_eq!(s.tracked_procs(), MAX_TRACKED_PROCS);
        assert!(!s.has_recent(key(1, 1), PrecursorKind::PrivEsc, 2 * SEC, W));
        assert!(s.has_recent(key(5000, 1), PrecursorKind::TmpExec, 2 * SEC, W));
        // 5000 keys for a cap of 4096: the PrivEsc-only key went first,
        // then 903 protected ones, each counted.
        assert_eq!(s.lost_precursor_keys(), 5000 - 1 - MAX_TRACKED_PROCS as u64);
        assert!(lost_precursor_keys_total() >= s.lost_precursor_keys());
    }

    #[test]
    fn a_hundred_thousand_live_keys_stay_cheap() {
        let mut s = CorrelationStore::new();
        let t0 = std::time::Instant::now();
        for pid in 0..100_000u32 {
            s.record(key(pid, 7), PrecursorKind::PrivEsc, SEC + u64::from(pid));
            s.note_egress(key(pid, 7), note(pid, SEC + u64::from(pid), 443));
        }
        assert_eq!(s.tracked_procs(), MAX_TRACKED_PROCS);
        assert_eq!(s.egress.len(), MAX_TRACKED_PROCS);
        assert!(s.privesc_only.queue_len() <= 2 * MAX_TRACKED_PROCS + 1);
        assert!(s.egress_order.queue_len() <= 2 * MAX_TRACKED_PROCS + 1);
        // O(n) per insert above the cap took minutes in a debug build.
        let took = t0.elapsed();
        assert!(took < std::time::Duration::from_secs(10), "{took:?}");
    }

    #[test]
    fn eviction_queue_stays_bounded_under_query_churn() {
        let mut s = CorrelationStore::new();
        for pid in 0..10_000u32 {
            s.record(key(pid, 1), PrecursorKind::CredRead, SEC);
            // Past its retention by now (external audit NETR-014: 30 min
            // for a credential read): the query drops the key.
            let later = 2 * SEC + LONG_RETENTION_NS;
            assert!(!s.has_recent(key(pid, 1), PrecursorKind::CredRead, later, W));
        }
        assert_eq!(s.tracked_procs(), 0);
        assert!(
            s.protected.queue_len() <= 2 * 64 + 1,
            "{}",
            s.protected.queue_len()
        );
    }

    #[test]
    fn a_privesc_flood_does_not_evict_a_cred_read() {
        let mut s = CorrelationStore::new();
        s.record(key(42, 1), PrecursorKind::CredRead, SEC);
        for pid in 1_000..21_000u32 {
            s.record(key(pid, 1), PrecursorKind::PrivEsc, 2 * SEC);
        }
        assert!(s.has_recent(key(42, 1), PrecursorKind::CredRead, 3 * SEC, W));
        assert_eq!(s.lost_precursor_keys(), 0);
        assert!(s.tracked_procs() <= MAX_TRACKED_PROCS);
    }

    #[test]
    fn a_privesc_key_that_gains_a_cred_read_is_protected() {
        let mut s = CorrelationStore::new();
        s.record(key(42, 1), PrecursorKind::PrivEsc, SEC);
        s.record(key(42, 1), PrecursorKind::CredRead, SEC);
        s.record(key(42, 1), PrecursorKind::PrivEsc, SEC);
        for pid in 1_000..9_000u32 {
            s.record(key(pid, 1), PrecursorKind::PrivEsc, 2 * SEC);
        }
        assert!(s.has_recent(key(42, 1), PrecursorKind::CredRead, 3 * SEC, W));
    }

    // ── External audit NETR-009: the incarnation is kept ─────────────

    #[test]
    fn precursors_follow_the_incarnation() {
        let mut s = CorrelationStore::new();
        // (200, start 10 s) runs from /tmp.
        s.observe_spawn(200, 1, 10 * SEC);
        s.record(key(200, 10 * SEC), PrecursorKind::TmpExec, 10 * SEC);
        assert!(s.has_recent_for_pid(200, PrecursorKind::TmpExec, 11 * SEC, W));
        // A FIM read is recorded for the current incarnation.
        s.record_for_pid(200, PrecursorKind::CredRead, 11 * SEC);
        assert!(s.has_recent(key(200, 10 * SEC), PrecursorKind::CredRead, 12 * SEC, W));
        // A re-exec of the same process keeps them.
        s.observe_spawn(200, 1, 10 * SEC);
        assert!(s.has_recent_for_pid(200, PrecursorKind::TmpExec, 12 * SEC, W));
        // The PID goes to a new process: nothing carries over.
        s.observe_spawn(200, 1, 20 * SEC);
        assert!(!s.has_recent_for_pid(200, PrecursorKind::TmpExec, 21 * SEC, W));
        assert!(!s.has_recent_for_pid(200, PrecursorKind::CredRead, 21 * SEC, W));
    }

    /// The tree lost the PID's edge (evicted): the new incarnation still
    /// does not inherit what the old one recorded.
    #[test]
    fn a_reused_pid_inherits_nothing_once_its_edge_is_gone() {
        let mut s = CorrelationStore::new();
        s.observe_spawn(200, 1, 10 * SEC);
        s.record(key(200, 10 * SEC), PrecursorKind::TmpExec, 10 * SEC);
        s.tree.forget(200);
        s.observe_spawn(200, 1, 20 * SEC);
        assert!(!s.has_recent_for_pid(200, PrecursorKind::TmpExec, 21 * SEC, W));
    }

    /// A precursor processed before the exec that started its process
    /// (another ring) is handed to that process; an older one is not.
    #[test]
    fn a_precursor_processed_before_the_exec_goes_to_the_new_incarnation() {
        let mut s = CorrelationStore::new();
        s.record_for_pid(300, PrecursorKind::CredRead, 5 * SEC); // older holder
        s.record_for_pid(300, PrecursorKind::CanaryTrip, 12 * SEC);
        s.observe_spawn(300, 1, 10 * SEC);
        assert!(s.has_recent_for_pid(300, PrecursorKind::CanaryTrip, 13 * SEC, W));
        assert!(!s.has_recent_for_pid(300, PrecursorKind::CredRead, 13 * SEC, W));
    }

    #[test]
    fn a_recycled_ancestor_pid_carries_nothing() {
        let mut s = CorrelationStore::new();
        // (100, 1 s) read credentials, then exited; its PID went to a new
        // process (100, 9 s), whose child 300 egresses.
        s.observe_spawn(100, 1, SEC);
        s.record_for_pid(100, PrecursorKind::CredRead, 2 * SEC);
        s.observe_spawn(100, 1, 9 * SEC);
        s.observe_spawn(300, 100, 10 * SEC);
        assert!(!s.has_recent_in_ancestors(300, PrecursorKind::CredRead, 11 * SEC, W));
        // The real parent's precursor still reaches its child.
        s.record_for_pid(100, PrecursorKind::CredRead, 10 * SEC);
        assert!(s.has_recent_in_ancestors(300, PrecursorKind::CredRead, 11 * SEC, W));
    }

    #[test]
    fn an_ancestor_started_after_the_child_ends_the_walk() {
        let mut s = CorrelationStore::new();
        // 300 was forked by the first holder of 100; 100 now names a
        // process that started later and reads credentials.
        s.observe_spawn(300, 100, 3 * SEC);
        s.observe_spawn(100, 1, 5 * SEC);
        s.record_for_pid(100, PrecursorKind::CredRead, 6 * SEC);
        assert!(!s.has_recent_in_ancestors(300, PrecursorKind::CredRead, 7 * SEC, W));
    }

    /// A parent started before the agent (no exec seen) keeps the PID-only
    /// behaviour.
    #[test]
    fn a_parent_older_than_the_agent_keeps_pid_only_matching() {
        let mut s = CorrelationStore::new();
        s.record_for_pid(100, PrecursorKind::CredRead, 10 * SEC);
        s.observe_spawn(300, 100, 11 * SEC);
        assert!(s.has_recent_in_ancestors(300, PrecursorKind::CredRead, 12 * SEC, W));
    }

    // ── Lab PR 244: NN-L-CHAIN-002 completed by a late exec ──────────

    /// A note keeps the flow's destination (CHAIN-002's resolver
    /// exemption and port-53 hold need it), not the rest of the flow (its
    /// resolved name, its TLS fingerprint).
    #[test]
    fn a_note_keeps_the_destination() {
        let nf = NetFlowEvent {
            start_ns: 12 * SEC,
            end_ns: 0,
            family: 2,
            src_addr: "10.0.2.15".parse().unwrap(),
            src_port: 40_000,
            dst_addr: "100.64.20.9".parse().unwrap(),
            dst_port: 53,
            proto: 6,
            pid: 42,
            uid: 1000,
            comm: "dropper".to_string(),
            exe: Some("/tmp/dropper".to_string()),
            proc_start_ns: 0,
            bytes_sent: 0,
            bytes_recv: 0,
            resolved_hostname: Some("c2.example".to_string()),
            tls_fingerprint: None,
            flow_id: "f".to_string(),
            close_reason: 0,
            phase: Default::default(),
            observed_ns: 0,
        };
        assert_eq!(
            EgressNote::of(&nf),
            EgressNote {
                pid: 42,
                comm: "dropper".to_string(),
                start_ns: 12 * SEC,
                dst_addr: "100.64.20.9".parse().unwrap(),
                dst_port: 53,
            }
        );
    }

    /// The egresses a late staging exec may complete CHAIN-002 with: the
    /// unclaimed ones of the process at or after the exec, within the
    /// window of it, earliest first — not one before the exec or the
    /// process's start, not one past the window, none for an unknown start.
    #[test]
    fn a_late_exec_finds_the_unclaimed_egresses_after_it() {
        let mut s = CorrelationStore::new();
        // Process 42 started at 9 s, its exec at 10 s is processed last.
        let k = s.current_key(42);
        s.note_egress(k, note(42, 8 * SEC, 443)); // a previous holder's
        s.note_egress(k, note(42, 9 * SEC + 5, 443)); // before the exec
        s.note_egress(k, note(42, 12 * SEC, 53));
        s.note_egress(k, note(42, 11 * SEC, 443));
        let at = |s: &CorrelationStore, start| -> Vec<(u64, u16)> {
            s.exec_egresses(42, start, 10 * SEC, W)
                .iter()
                .map(|n| (n.start_ns, n.dst_port))
                .collect()
        };
        assert_eq!(at(&s, 9 * SEC), [(11 * SEC, 443), (12 * SEC, 53)]);
        assert!(at(&s, 0).is_empty(), "start unknown");
        s.claim_egress(k, 11 * SEC, PrecursorKind::CredRead);
        assert_eq!(at(&s, 9 * SEC), [(12 * SEC, 53)], "a claimed one is not");
        // Observed, the exec's incarnation holds them, the claim kept.
        s.observe_spawn(42, 1, 9 * SEC);
        assert_eq!(at(&s, 9 * SEC), [(12 * SEC, 53)]);
        assert!(s
            .claim_egress_after(key(42, 9 * SEC), 10 * SEC, W)
            .is_some());
        assert!(at(&s, 9 * SEC).is_empty());
        // The window is the exec's: at its end, not past it.
        let mut s = CorrelationStore::new();
        s.note_egress(key(43, SEC), note(43, 10 * SEC + W, 443));
        s.note_egress(key(43, SEC), note(43, 10 * SEC + W + 1, 443));
        let got = s.exec_egresses(43, SEC, 10 * SEC, W);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].start_ns, 10 * SEC + W);
    }

    /// The claim names the two-step chain, which decides what may still
    /// complete the egress: after CHAIN-002 (`TmpExec`) no second two-step
    /// chain, and CHAIN-007 with a late read; after CHAIN-001 (`CredRead`)
    /// no second two-step chain, and CHAIN-007 with a late exec only. The
    /// first claim is kept.
    #[test]
    fn the_claim_names_the_two_step_chain() {
        let k = key(42, SEC);
        let mut s = CorrelationStore::new();
        s.note_egress(k, note(42, 12 * SEC, 443));
        s.claim_egress(k, 12 * SEC, PrecursorKind::TmpExec);
        assert!(s.claim_egress_after(k, 11 * SEC, W).is_none(), "CHAIN-001");
        assert!(
            s.exec_egresses(42, SEC, 10 * SEC, W).is_empty(),
            "CHAIN-002"
        );
        assert_eq!(
            s.take_egress_after(k, 11 * SEC, W).map(|n| n.start_ns),
            Some(12 * SEC),
            "CHAIN-007 on a late read"
        );
        assert!(s.take_egress_after(k, 11 * SEC, W).is_none(), "taken");

        let mut s = CorrelationStore::new();
        s.note_egress(k, note(42, 12 * SEC, 443));
        s.record(k, PrecursorKind::CredRead, 11 * SEC);
        assert!(s.claim_egress_after(k, 11 * SEC, W).is_some(), "CHAIN-001");
        s.claim_egress(k, 12 * SEC, PrecursorKind::TmpExec);
        assert!(s.claim_egress_after(k, 11 * SEC, W).is_none());
        assert!(s.exec_egresses(42, SEC, 10 * SEC, W).is_empty());
        assert!(
            s.take_egress_after(k, 11 * SEC + 5, W).is_none(),
            "a late read does not upgrade CHAIN-001: the read was its step"
        );
        assert_eq!(
            s.exec_sequence_egress(42, SEC, 10 * SEC, W)
                .map(|n| n.start_ns),
            Some(12 * SEC),
            "a late exec does"
        );
    }
}
