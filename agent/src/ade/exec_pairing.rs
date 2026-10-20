//! Lab PR 162: which of an exec's two events the ADE evaluates.
//!
//! An exec reaches the agent twice. The `ExecCheck` of LSM
//! `bprm_check_security` (one per binfmt pass; one per `execve` in
//! tracepoint mode) is read in the calling task before the new image runs,
//! so it carries the parent's comm. Once the exec has succeeded, the
//! `ProcessSpawn` of `sched_process_exec` carries the child's comm, argv
//! and file. The ADE has one evaluation slot ([`super::slot::AdeSlot`]):
//! the `ExecCheck` took it, and the `ProcessSpawn` read microseconds later
//! was counted as skipped. The model judged every exec under its parent's
//! name, and in the lab a `lockbit-*` binary was never evaluated.
//!
//! The ADE now evaluates the `ProcessSpawn`; the rules still see both
//! events. An `ExecCheck` no rule matched is held back. A `ProcessSpawn` of
//! the same exec settles it; one that nothing settles within
//! [`EXEC_CHECK_GRACE`] goes to the ADE on its own. That is an exec that
//! did not complete (no binary format accepted the file, a later security
//! hook refused it, the task was killed before the point of no return) or
//! whose `ProcessSpawn` was lost (a full ring). Its `ExecCheck` is then the
//! only record of the attempt, so the model is still asked. Such execs are
//! rare and cost the slot little.
//!
//! The two events come from two ring buffers drained by two tasks, so the
//! `ProcessSpawn` may be read first: spawns are remembered for the same
//! grace. A spawn settles an `ExecCheck` only when it can be the same exec:
//! same pid, the process already started at the check (`start_ns`: a
//! reused pid starts later), and the check not after the spawn (a later
//! failed exec of the process is not settled by an earlier spawn). A spawn
//! settles every check of its process up to it: a script's two passes,
//! and an earlier attempt that failed (the process is judged through the
//! exec that succeeded). Both tables are bounded; when the held-back table
//! is full, its oldest entry goes to the ADE at once.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use common::Event;
use parking_lot::Mutex;

/// How long an `ExecCheck` waits for its `ProcessSpawn`. The two are
/// microseconds apart in the kernel; the wait covers the drain of two rings
/// and an event loop behind on its queue.
pub const EXEC_CHECK_GRACE: Duration = Duration::from_secs(2);

/// Held-back `ExecCheck`s at most.
pub const HELD_CAP: usize = 1024;

/// Remembered spawns at most.
const SPAWN_CAP: usize = 4096;

struct Held {
    pid: u32,
    timestamp_ns: u64,
    since: Instant,
    event: Event,
}

#[derive(Clone, Copy)]
struct Spawned {
    start_ns: u64,
    timestamp_ns: u64,
    at: Instant,
}

#[derive(Default)]
struct Tables {
    /// In arrival order, so the oldest is at the front.
    held: VecDeque<Held>,
    /// The last spawn read per pid.
    spawns: HashMap<u32, Spawned>,
}

/// See the module docs.
#[derive(Default)]
pub struct ExecPairing {
    tables: Mutex<Tables>,
    settled: AtomicU64,
    unsettled: AtomicU64,
}

/// Whether a spawn (its process start and its time) can complete the exec
/// checked at `check_ns`. 0 is an unknown time (older records) and is not
/// held against the match.
fn completes(start_ns: u64, spawn_ns: u64, check_ns: u64) -> bool {
    let known = |t: u64| t != 0 && check_ns != 0;
    let started = !known(start_ns) || start_ns <= check_ns;
    let not_later = !known(spawn_ns) || check_ns <= spawn_ns;
    started && not_later
}

impl ExecPairing {
    pub fn new() -> Self {
        Self::default()
    }

    /// Every `ProcessSpawn`, whatever the rules make of it: it settles the
    /// held-back `ExecCheck`s of its exec, and one read after it. Other
    /// events are ignored.
    pub fn note_spawn(&self, event: &Event, now: Instant) {
        let Event::ProcessSpawn {
            pid,
            start_ns,
            timestamp_ns,
            ..
        } = event
        else {
            return;
        };
        let mut t = self.tables.lock();
        let before = t.held.len();
        t.held
            .retain(|h| !(h.pid == *pid && completes(*start_ns, *timestamp_ns, h.timestamp_ns)));
        let settled = before - t.held.len();
        if settled > 0 {
            self.settled.fetch_add(settled as u64, Ordering::Relaxed);
        }
        if t.spawns.len() >= SPAWN_CAP {
            t.spawns
                .retain(|_, s| now.saturating_duration_since(s.at) < EXEC_CHECK_GRACE);
        }
        if t.spawns.len() < SPAWN_CAP || t.spawns.contains_key(pid) {
            t.spawns.insert(
                *pid,
                Spawned {
                    start_ns: *start_ns,
                    timestamp_ns: *timestamp_ns,
                    at: now,
                },
            );
        }
    }

    /// What the ADE evaluates now for `event`, which no rule matched: a
    /// `ProcessSpawn` itself. An `ExecCheck` is held back (`None`), or
    /// settled at once by a spawn already read; when the held-back table is
    /// full, its oldest entry is returned in its place. Any other event:
    /// `None`.
    pub fn admit(&self, event: Event, now: Instant) -> Option<Event> {
        let (pid, timestamp_ns) = match &event {
            Event::ProcessSpawn { .. } => return Some(event),
            Event::ExecCheck {
                pid, timestamp_ns, ..
            } => (*pid, *timestamp_ns),
            _ => return None,
        };
        let mut t = self.tables.lock();
        let spawned = t.spawns.get(&pid).is_some_and(|s| {
            now.saturating_duration_since(s.at) < EXEC_CHECK_GRACE
                && completes(s.start_ns, s.timestamp_ns, timestamp_ns)
        });
        if spawned {
            self.settled.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        // One held entry per process: a script's second pass, or a retry
        // along PATH, waits with the first.
        if t.held.iter().any(|h| h.pid == pid) {
            return None;
        }
        let evicted = if t.held.len() >= HELD_CAP {
            t.held.pop_front().map(|h| h.event)
        } else {
            None
        };
        t.held.push_back(Held {
            pid,
            timestamp_ns,
            since: now,
            event,
        });
        if evicted.is_some() {
            self.unsettled.fetch_add(1, Ordering::Relaxed);
        }
        evicted
    }

    /// The held-back `ExecCheck`s that no `ProcessSpawn` settled within
    /// [`EXEC_CHECK_GRACE`], oldest first, for the ADE. Cheap when there
    /// are none.
    pub fn take_unsettled(&self, now: Instant) -> Vec<Event> {
        let mut t = self.tables.lock();
        let mut out = Vec::new();
        while t
            .held
            .front()
            .is_some_and(|h| now.saturating_duration_since(h.since) >= EXEC_CHECK_GRACE)
        {
            if let Some(h) = t.held.pop_front() {
                out.push(h.event);
            }
        }
        if !out.is_empty() {
            self.unsettled
                .fetch_add(out.len() as u64, Ordering::Relaxed);
        }
        out
    }

    /// `ExecCheck`s settled by their `ProcessSpawn` since boot (not offered
    /// to the ADE).
    pub fn settled(&self) -> u64 {
        self.settled.load(Ordering::Relaxed)
    }

    /// `ExecCheck`s offered to the ADE on their own since boot.
    pub fn unsettled(&self) -> u64 {
        self.unsettled.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ade::slot::AdeSlot;

    const LATER: Duration = EXEC_CHECK_GRACE;

    fn exec_check(pid: u32, comm: &str, filename: &str, ts: u64) -> Event {
        Event::ExecCheck {
            pid,
            ppid: 1,
            uid: 0,
            comm: comm.into(),
            filename: filename.into(),
            timestamp_ns: ts,
            exe: Default::default(),
        }
    }

    fn spawn(pid: u32, comm: &str, filename: &str, start_ns: u64, ts: u64) -> Event {
        Event::ProcessSpawn {
            pid,
            ppid: 1,
            uid: 0,
            gid: 0,
            comm: comm.into(),
            filename: filename.into(),
            timestamp_ns: ts,
            argv: vec![filename.into()],
            parent_comm: "bash".into(),
            parent_start_ns: 0,
            start_ns,
            parent_is_kthread: false,
            exe: Default::default(),
            argv_truncated: false,
            filename_truncated: false,
        }
    }

    fn comm(event: &Event) -> String {
        match event {
            Event::ProcessSpawn { comm, .. } | Event::ExecCheck { comm, .. } => comm.clone(),
            _ => String::new(),
        }
    }

    /// What `main.rs` does with an exec event no rule matched: the spawn is
    /// noted before the rules, then the pairing decides what the slot is
    /// offered. The evaluation never ends, like a model still thinking.
    fn offer(
        pairing: &ExecPairing,
        slot: &AdeSlot,
        evaluated: &mut Vec<String>,
        event: Event,
        now: Instant,
    ) {
        pairing.note_spawn(&event, now);
        if let Some(event) = pairing.admit(event, now) {
            let name = comm(&event);
            if slot.try_spawn(std::future::pending::<()>()) {
                evaluated.push(name);
            }
        }
    }

    /// The finding: for an exec no rule covers, the slot used to take the
    /// `ExecCheck` (the parent's comm) and skip the `ProcessSpawn`. It now
    /// gets the spawn, with the child's comm, and skips nothing.
    #[tokio::test]
    async fn the_slot_gets_the_spawn_with_the_childs_comm() {
        let (pairing, slot) = (ExecPairing::new(), AdeSlot::new());
        let mut evaluated = Vec::new();
        let now = Instant::now();
        let path = "/opt/nn162/lockbit-nn162";
        offer(
            &pairing,
            &slot,
            &mut evaluated,
            exec_check(4242, "bash", path, 100),
            now,
        );
        offer(
            &pairing,
            &slot,
            &mut evaluated,
            spawn(4242, "lockbit-nn162", path, 50, 120),
            now,
        );
        assert_eq!(evaluated, ["lockbit-nn162"]);
        assert_eq!(slot.skipped(), 0);
        assert!(pairing.take_unsettled(now + LATER).is_empty());
        assert_eq!((pairing.settled(), pairing.unsettled()), (1, 0));
    }

    /// An exec that did not complete, or whose spawn was lost: its
    /// `ExecCheck` waits the grace, then goes to the ADE once.
    #[test]
    fn an_exec_check_nothing_settles_goes_to_the_ade_after_the_grace() {
        let pairing = ExecPairing::new();
        let now = Instant::now();
        assert!(pairing
            .admit(exec_check(7, "sh", "/tmp/x", 100), now)
            .is_none());
        assert!(pairing
            .take_unsettled(now + LATER - Duration::from_millis(1))
            .is_empty());
        let out = pairing.take_unsettled(now + LATER);
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], Event::ExecCheck { pid: 7, .. }));
        assert!(pairing.take_unsettled(now + LATER * 2).is_empty());
        assert_eq!(pairing.unsettled(), 1);
    }

    /// The spawn's ring was drained first: the check read after it is
    /// settled at once.
    #[test]
    fn a_spawn_read_before_its_check_settles_it() {
        let pairing = ExecPairing::new();
        let now = Instant::now();
        pairing.note_spawn(&spawn(9, "tool", "/usr/bin/tool", 50, 200), now);
        assert!(pairing
            .admit(exec_check(9, "bash", "/usr/bin/tool", 150), now)
            .is_none());
        assert!(pairing.take_unsettled(now + LATER).is_empty());
        assert_eq!(pairing.settled(), 1);
    }

    /// A later exec of the same process that fails is not settled by the
    /// spawn of an earlier one, and a reused pid (a process started after
    /// the check) settles nothing.
    #[test]
    fn only_the_same_exec_settles_a_check() {
        let pairing = ExecPairing::new();
        let now = Instant::now();
        pairing.note_spawn(&spawn(11, "a", "/usr/bin/a", 50, 200), now);
        assert!(pairing
            .admit(exec_check(11, "a", "/usr/bin/b", 300), now)
            .is_none());
        assert!(pairing
            .admit(exec_check(12, "sh", "/usr/bin/c", 300), now)
            .is_none());
        pairing.note_spawn(&spawn(12, "c", "/usr/bin/c", 400, 450), now);
        let pids: Vec<u32> = pairing
            .take_unsettled(now + LATER)
            .iter()
            .filter_map(|e| match e {
                Event::ExecCheck { pid, .. } => Some(*pid),
                _ => None,
            })
            .collect();
        assert_eq!(pids, [11, 12]);
    }

    /// A script's two passes wait as one: settled together by the spawn,
    /// or offered once.
    #[test]
    fn a_scripts_two_passes_wait_as_one() {
        let pairing = ExecPairing::new();
        let now = Instant::now();
        for (pid, settle) in [(21, true), (22, false)] {
            assert!(pairing
                .admit(exec_check(pid, "bash", "/opt/run.sh", 100), now)
                .is_none());
            assert!(pairing
                .admit(exec_check(pid, "bash", "/bin/sh", 101), now)
                .is_none());
            if settle {
                pairing.note_spawn(&spawn(pid, "run.sh", "/opt/run.sh", 10, 110), now);
            }
        }
        let out = pairing.take_unsettled(now + LATER);
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], Event::ExecCheck { pid: 22, .. }));
    }

    /// A full table never grows: its oldest entry goes to the ADE in the
    /// place of the newcomer.
    #[test]
    fn a_full_table_hands_over_its_oldest() {
        let pairing = ExecPairing::new();
        let now = Instant::now();
        for pid in 0..HELD_CAP as u32 {
            assert!(pairing
                .admit(exec_check(1000 + pid, "sh", "/x", 1), now)
                .is_none());
        }
        let out = pairing.admit(exec_check(9999, "sh", "/x", 1), now);
        assert!(matches!(out, Some(Event::ExecCheck { pid: 1000, .. })));
        assert_eq!(pairing.take_unsettled(now + LATER).len(), HELD_CAP);
    }

    /// Only exec events are routed; nothing else reaches the ADE.
    #[test]
    fn other_events_are_not_routed() {
        let pairing = ExecPairing::new();
        let open = Event::FileOpen {
            pid: 5,
            uid: 0,
            gid: 0,
            comm: "cat".into(),
            filename: "/etc/shadow".into(),
            flags: 0,
            timestamp_ns: 1,
            path_from_user: false,
            kernel_class: 0,
        };
        assert!(pairing.admit(open, Instant::now()).is_none());
        assert!(pairing.take_unsettled(Instant::now() + LATER).is_empty());
    }
}
