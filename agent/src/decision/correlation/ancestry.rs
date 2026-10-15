//! Tappa 10.6 (D4) — process-lineage ancestry tree.
//!
//! Tracks per-host parent→child edges so the [`CorrelationStore`] can
//! correlate a precursor on an *ancestor* with a trigger on a
//! *descendant* (the cross-PID kill chains of design §4.2 / §4 G4 —
//! `sshd → bash → curl`).
//!
//! ## Keying
//!
//! An edge is keyed by the child's `pid` and records its parent's pid.
//! The parent start the D2 wire carries (`parent_start_ns`) is the start
//! of the thread that forked, not of the process, so it is not used.
//!
//! External audit NETR-009: each edge also records the child's own
//! `start_time` (`Event::ProcessSpawn::start_ns`, POS-003), so the tree
//! is the store's `pid → start_ns` map. A lineage walk keys each ancestor
//! with the start recorded for *it*, not with the parent start carried by
//! the child's exec (that is the start of the forking thread), and stops
//! at a hop that started after its child: such a hop is a later process
//! holding a reused PID (the POS-003 rule of `lineage_match`).
//!
//! External audit NETR-010: bounded at [`MAX_TRACKED_EDGES`] edges with
//! second-chance eviction. When the tree is full, up to
//! [`SECOND_CHANCE_SCAN`] edges are taken from the front of the recency
//! queue: those of processes that are gone (or whose PID now names a
//! process with another start) are dropped, live ones are re-queued, and
//! only when all of them are live is the oldest evicted — counted, with a
//! rate-limited WARN. There is still no `sched_process_exit` feed; the
//! liveness check reads `<proc_root>/<pid>/stat`. Walks are capped at
//! [`MAX_ANCESTRY_DEPTH`] with a cycle guard.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::store::ProcKey;
use crate::decision::bounded::{LazyLru, LossCounter};

/// Max parent→child edges retained (about 2 MiB with the recency queue).
pub const MAX_TRACKED_EDGES: usize = 65_536;

/// Edges examined per insert while the tree is full.
const SECOND_CHANCE_SCAN: usize = 8;

/// Max ancestry-walk depth — deep enough for real process trees, capped
/// so a pathological/looping chain can't run unbounded.
const MAX_ANCESTRY_DEPTH: usize = 16;

/// Live edges evicted by any tree since the agent started.
static LIVE_EDGE_EVICTIONS: AtomicU64 = AtomicU64::new(0);

/// External audit NETR-010: edges of live processes evicted because the
/// tree was full (lineage lost), process-wide.
pub fn live_edge_evictions_total() -> u64 {
    LIVE_EDGE_EVICTIONS.load(Ordering::Relaxed)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Edge {
    ppid: u32,
    /// The child's own start (0: unknown, an older record).
    start_ns: u64,
}

/// Per-host parent→child lineage, keyed by child pid.
pub struct AncestryTree {
    edges: HashMap<u32, Edge>,
    order: LazyLru<u32>,
    proc_root: PathBuf,
    cap: usize,
    live_evictions: LossCounter,
}

impl Default for AncestryTree {
    fn default() -> Self {
        Self::with_proc_root("/proc", MAX_TRACKED_EDGES)
    }
}

impl AncestryTree {
    pub fn new() -> Self {
        Self::default()
    }

    /// A tree checking liveness under `proc_root` (a fixture in tests).
    pub fn with_proc_root(proc_root: impl Into<PathBuf>, cap: usize) -> Self {
        Self {
            edges: HashMap::new(),
            order: LazyLru::new(),
            proc_root: proc_root.into(),
            cap: cap.max(1),
            live_evictions: LossCounter::new(&LIVE_EDGE_EVICTIONS),
        }
    }

    /// Record the exec of `child_pid` (own start `start_ns`, 0 if unknown)
    /// under parent `ppid`. Returns the start previously recorded for
    /// `child_pid`, if any: the store compares it to tell a re-exec of the
    /// same process from a reused PID. External audit NETR-010: either
    /// way the PID moves to the back of the recency queue.
    pub fn observe(&mut self, child_pid: u32, ppid: u32, start_ns: u64) -> Option<u64> {
        let previous = self.edges.get(&child_pid).map(|e| e.start_ns);
        if previous.is_none() && self.edges.len() >= self.cap {
            self.make_room();
        }
        self.edges.insert(child_pid, Edge { ppid, start_ns });
        self.order.touch(child_pid);
        previous
    }

    /// The immediate parent pid of `pid`, if known.
    pub fn parent_of(&self, pid: u32) -> Option<u32> {
        self.edges.get(&pid).map(|e| e.ppid)
    }

    /// The start recorded for `pid`'s exec; 0 when unknown.
    pub fn start_of(&self, pid: u32) -> u64 {
        self.edges.get(&pid).map_or(0, |e| e.start_ns)
    }

    /// `pid`'s current incarnation as far as the tree knows: its recorded
    /// start, or 0 (unknown — matches only precursors recorded as unknown).
    pub fn current(&self, pid: u32) -> ProcKey {
        ProcKey {
            pid,
            start_ns: self.start_of(pid),
        }
    }

    /// Ancestor [`ProcKey`]s of `pid`, nearest first, each keyed with its
    /// own recorded start, up to [`MAX_ANCESTRY_DEPTH`]. Cycle-guarded.
    /// External audit NETR-009: the walk ends at a hop that started after
    /// the process below it (a later holder of a reused PID). Unknown
    /// starts are not held against a hop; the latest known start below
    /// still bounds the hops above.
    pub fn get_ancestors(&self, pid: u32) -> Vec<ProcKey> {
        let mut out = Vec::new();
        let mut visited = HashSet::new();
        visited.insert(pid);
        let mut cur = pid;
        let mut below_start = self.start_of(pid);
        for _ in 0..MAX_ANCESTRY_DEPTH {
            let Some(edge) = self.edges.get(&cur) else {
                break;
            };
            if !visited.insert(edge.ppid) {
                break; // cycle / reused-pid loop guard
            }
            let up = self.current(edge.ppid);
            if up.start_ns != 0 && below_start != 0 && up.start_ns > below_start {
                break;
            }
            out.push(up);
            if up.start_ns != 0 {
                below_start = up.start_ns;
            }
            cur = edge.ppid;
        }
        out
    }

    /// `true` if `ancestor` (pid and incarnation) appears in
    /// `descendant_pid`'s lineage.
    pub fn is_ancestor(&self, descendant_pid: u32, ancestor: ProcKey) -> bool {
        self.get_ancestors(descendant_pid).contains(&ancestor)
    }

    /// Drop a process's edge. O(1): the queue entry goes lazily.
    pub fn forget(&mut self, pid: u32) {
        if self.edges.remove(&pid).is_some() {
            self.order.remove(&pid);
        }
    }

    /// Live edges this tree evicted for room.
    pub fn live_evictions(&self) -> u64 {
        self.live_evictions.count()
    }

    pub fn len(&self) -> usize {
        self.edges.len()
    }

    pub fn is_empty(&self) -> bool {
        self.edges.is_empty()
    }

    /// External audit NETR-010: second-chance eviction (module docs).
    fn make_room(&mut self) {
        let mut live: Vec<u32> = Vec::with_capacity(SECOND_CHANCE_SCAN);
        let mut freed = false;
        for _ in 0..SECOND_CHANCE_SCAN {
            let Some(pid) = self.order.pop_oldest() else {
                break;
            };
            let Some(edge) = self.edges.get(&pid).copied() else {
                continue;
            };
            if is_alive(&self.proc_root, pid, edge.start_ns) {
                live.push(pid);
            } else {
                self.edges.remove(&pid);
                freed = true;
            }
        }
        if !freed && !live.is_empty() {
            let oldest = live.remove(0);
            self.edges.remove(&oldest);
            if self.live_evictions.bump() {
                tracing::warn!(
                    pid = oldest,
                    evicted = self.live_evictions.count(),
                    cap = self.cap,
                    "ancestry tree full of live processes: evicted the oldest \
                     edge, cross-PID chain correlation for its descendants is lost"
                );
            }
        }
        for pid in live {
            self.order.touch(pid);
        }
    }
}

/// `pid` still names the process recorded with `start_ns`: its
/// `<proc_root>/<pid>/stat` exists and, when the start is known, shows it.
/// `/proc` shows the start in CLOCK_BOOTTIME ticks, ahead of the
/// monotonic `start_ns` by the time suspended before the start (as in
/// `posture::lineage`).
fn is_alive(proc_root: &Path, pid: u32, start_ns: u64) -> bool {
    let Some(ticks) = proc_start_ticks(proc_root, pid) else {
        return false;
    };
    if start_ns == 0 {
        return true;
    }
    let tick = tick_ns();
    let shown = ticks.saturating_mul(tick);
    let slack = 2 * tick;
    shown + slack >= start_ns && shown <= start_ns + suspended_ns() + slack
}

/// `starttime`, field 22 of `/proc/<pid>/stat`, counted after `(comm)`.
fn proc_start_ticks(proc_root: &Path, pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(proc_root.join(pid.to_string()).join("stat")).ok()?;
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

fn tick_ns() -> u64 {
    static TICK: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *TICK.get_or_init(|| {
        // SAFETY: sysconf has no preconditions.
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if hz > 0 {
            1_000_000_000 / hz as u64
        } else {
            10_000_000
        }
    })
}

/// `CLOCK_BOOTTIME` − `CLOCK_MONOTONIC`: the time spent suspended.
fn suspended_ns() -> u64 {
    let now = |clock| {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: a valid clock id and a timespec to fill.
        unsafe { libc::clock_gettime(clock, &mut ts) };
        ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
    };
    now(libc::CLOCK_BOOTTIME).saturating_sub(now(libc::CLOCK_MONOTONIC))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(pid: u32, start: u64) -> ProcKey {
        ProcKey {
            pid,
            start_ns: start,
        }
    }

    /// A fixture proc root where each `(pid, ticks)` has a `stat` file.
    fn proc_fixture(procs: &[(u32, u64)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (pid, ticks) in procs {
            write_stat(dir.path(), *pid, *ticks);
        }
        dir
    }

    fn write_stat(root: &Path, pid: u32, ticks: u64) {
        let d = root.join(pid.to_string());
        std::fs::create_dir_all(&d).unwrap();
        // pid (comm) state + 18 fields, then starttime (field 22)
        let mut stat = format!("{pid} (p) S");
        for _ in 0..18 {
            stat.push_str(" 0");
        }
        stat.push_str(&format!(" {ticks} 0 0\n"));
        std::fs::write(d.join("stat"), stat).unwrap();
    }

    #[test]
    fn direct_parent_child_detected() {
        let mut t = AncestryTree::new();
        t.observe(100, 1, 1_000);
        t.observe(200, 100, 2_000);
        assert!(t.is_ancestor(200, k(100, 1_000)));
        assert_eq!(t.parent_of(200), Some(100));
        assert_eq!(t.current(200), k(200, 2_000));
    }

    #[test]
    fn multi_level_ancestry() {
        let mut t = AncestryTree::new();
        // 100 → 200 → 300 (grandparent → parent → child).
        t.observe(100, 1, 1_000);
        t.observe(200, 100, 2_000);
        t.observe(300, 200, 3_000);
        let anc = t.get_ancestors(300);
        assert_eq!(anc, vec![k(200, 2_000), k(100, 1_000), k(1, 0)]);
        assert!(t.is_ancestor(300, k(100, 1_000)));
        assert!(t.is_ancestor(300, k(200, 2_000)));
        assert!(!t.is_ancestor(300, k(999, 0)));
    }

    /// External audit NETR-009: an incarnation that is not the recorded
    /// one is not an ancestor.
    #[test]
    fn is_ancestor_compares_the_incarnation() {
        let mut t = AncestryTree::new();
        t.observe(100, 1, 1_000);
        t.observe(200, 100, 2_000);
        assert!(!t.is_ancestor(200, k(100, 50)));
        assert!(!t.is_ancestor(200, k(100, 0)));
    }

    #[test]
    fn previous_start_is_reported() {
        let mut t = AncestryTree::new();
        assert_eq!(t.observe(200, 100, 1_000), None, "first sighting");
        assert_eq!(t.observe(200, 150, 5_000), Some(1_000), "second sighting");
        // The edge now points at the new parent.
        assert_eq!(t.parent_of(200), Some(150));
        assert_eq!(t.start_of(200), 5_000);
    }

    /// External audit NETR-009: a hop that started after its child is a
    /// later process holding the parent's PID; the walk stops there.
    #[test]
    fn a_hop_started_after_the_child_ends_the_walk() {
        let mut t = AncestryTree::new();
        t.observe(50, 1, 500);
        t.observe(300, 100, 3_000); // forked by the first holder of 100
        t.observe(100, 50, 5_000); // 100 reused after 300 started
        assert!(t.get_ancestors(300).is_empty());
        // An unknown start does not end it, and the known start below
        // still bounds the hops above.
        t.observe(400, 200, 4_000);
        t.observe(200, 60, 0);
        t.observe(60, 1, 9_000);
        assert_eq!(t.get_ancestors(400), vec![k(200, 0)]);
    }

    #[test]
    fn cycle_guard_terminates_walk() {
        let mut t = AncestryTree::new();
        // Construct a degenerate loop 1→2→1 (only possible via PID
        // reuse); the walk must terminate, not spin.
        t.observe(1, 2, 0);
        t.observe(2, 1, 0);
        let anc = t.get_ancestors(1);
        assert!(anc.len() <= 2);
    }

    #[test]
    fn forget_drops_edge() {
        let mut t = AncestryTree::new();
        t.observe(200, 100, 1);
        t.forget(200);
        assert!(t.parent_of(200).is_none());
        assert!(t.get_ancestors(200).is_empty());
        assert_eq!(t.order.len(), 0);
    }

    #[test]
    fn bounded_edges_stay_under_the_cap() {
        let root = proc_fixture(&[]);
        let mut t = AncestryTree::with_proc_root(root.path(), 1_000);
        for child in 0..5_000u32 {
            t.observe(child, child.wrapping_add(1), 1);
        }
        assert!(t.len() <= 1_000);
        assert_eq!(t.live_evictions(), 0, "all of them were dead");
    }

    /// External audit NETR-010: a long-lived `sshd → bash → curl` lineage
    /// survives a flood of short-lived (exited) processes.
    #[test]
    fn live_edges_survive_a_flood_of_dead_ones() {
        let root = proc_fixture(&[(1000, 0), (1001, 0), (1002, 0)]);
        let mut t = AncestryTree::with_proc_root(root.path(), 64);
        t.observe(1001, 1000, 0);
        t.observe(1002, 1001, 0);
        for pid in 10_000..30_000u32 {
            t.observe(pid, 1, 0);
        }
        assert!(t.len() <= 64);
        assert!(t.is_ancestor(1002, k(1000, 0)));
        assert_eq!(t.live_evictions(), 0);
    }

    /// External audit NETR-010: a PID that now names a process with
    /// another start is dead for the tree.
    #[test]
    fn a_reused_pid_counts_as_dead() {
        // pid 7 exists, but its start (1 tick) is not the recorded one.
        let root = proc_fixture(&[(7, 1), (8, 0)]);
        let mut t = AncestryTree::with_proc_root(root.path(), 2);
        t.observe(7, 1, 1_000_000 * tick_ns());
        t.observe(8, 1, 0);
        t.observe(9, 1, 0);
        assert!(t.parent_of(7).is_none());
        assert!(t.parent_of(8).is_some());
        assert_eq!(t.live_evictions(), 0);
    }

    /// External audit NETR-010: when every scanned edge is live the
    /// oldest goes, and that is counted.
    #[test]
    fn live_evictions_are_counted() {
        let procs: Vec<(u32, u64)> = (1..=40).map(|p| (p, 5)).collect();
        let root = proc_fixture(&procs);
        let mut t = AncestryTree::with_proc_root(root.path(), 16);
        for pid in 1..=40u32 {
            t.observe(pid, 1, 5 * tick_ns());
        }
        assert_eq!(t.len(), 16);
        assert_eq!(t.live_evictions(), 24);
        assert!(live_edge_evictions_total() >= 24);
    }

    /// External audit NETR-010: a re-observed PID moves to the back of the
    /// queue instead of keeping its old position.
    #[test]
    fn a_reobserved_pid_moves_to_the_back() {
        let procs: Vec<(u32, u64)> = (1..=5).map(|p| (p, 0)).collect();
        let root = proc_fixture(&procs);
        let mut t = AncestryTree::with_proc_root(root.path(), 4);
        for pid in 1..=4u32 {
            t.observe(pid, 1, 0);
        }
        t.observe(1, 1, 0);
        t.observe(5, 1, 0);
        assert!(t.parent_of(1).is_some());
        assert!(t.parent_of(2).is_none(), "the oldest untouched edge goes");
    }

    /// The liveness check against the real `/proc`: a child process is
    /// live with its own start, and dead once reaped.
    #[test]
    fn real_proc_liveness_follows_the_process() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = child.id();
        let root = Path::new("/proc");
        let start = proc_start_ticks(root, pid).unwrap() * tick_ns();
        assert!(is_alive(root, pid, start));
        assert!(!is_alive(root, pid, start + 3_600 * 1_000_000_000));
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(!is_alive(root, pid, start));
    }

    /// External audit NETR-009/010 (privileged: writes `ns_last_pid`): a
    /// PID handed to a new process after the recorded one exited is dead
    /// for the tree, against the real `/proc`.
    #[test]
    #[ignore = "privileged: root (ns_last_pid)"]
    fn a_really_reused_pid_is_dead_for_the_tree() {
        use std::process::{Command, Stdio};
        for _attempt in 0..20 {
            let mut first = Command::new("sleep")
                .arg("30")
                .stdout(Stdio::null())
                .spawn()
                .unwrap();
            let pid = first.id();
            let root = Path::new("/proc");
            let start = proc_start_ticks(root, pid).unwrap() * tick_ns();
            first.kill().unwrap();
            first.wait().unwrap();
            // more than the 2-tick slack between the two starts
            std::thread::sleep(std::time::Duration::from_millis(200));
            if std::fs::write("/proc/sys/kernel/ns_last_pid", format!("{}", pid - 1)).is_err() {
                panic!("cannot write ns_last_pid: run as root");
            }
            let mut harmless = Command::new("sleep")
                .arg("30")
                .stdout(Stdio::null())
                .spawn()
                .unwrap();
            if harmless.id() != pid {
                let _ = harmless.kill();
                let _ = harmless.wait();
                continue;
            }
            let alive = is_alive(root, pid, start);
            let _ = harmless.kill();
            let _ = harmless.wait();
            assert!(
                !alive,
                "the PID's new holder passed for the recorded process"
            );
            return;
        }
        panic!("the PID was never reused in 20 attempts");
    }
}
