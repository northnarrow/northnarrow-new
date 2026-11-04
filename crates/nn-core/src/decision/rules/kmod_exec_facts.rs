//! Lot 279: what the exec pump read of an exec of a kernel-module tool, AT
//! the exec — what its event does not carry and R011 judges beside the
//! command line's syntax ([`super::kmod_invocation`]):
//!
//! - **the program**: the file the kernel executed (`exe`'s device and
//!   inode, from the LSM hook) is the system's module tool — the inode of
//!   `/usr/bin/kmod`, `/usr/sbin/modprobe`, … as the pump stats them then.
//!   A copy, a file of another filesystem, an exec the hook did not
//!   describe (tracepoint mode) is not;
//! - **the environment**: the process's `/proc/<pid>/environ`, tied to the
//!   exec by its start time, holds no `MODPROBE_OPTIONS` — options kmod
//!   puts in front of the command line (`-d`, `-C`, `--`…), which the
//!   sensor does not see. Present: killed; unreadable or empty (the
//!   process gone before the pump read it, its pid another's): killed,
//!   nothing told it apart.
//!
//! The core reads none of it (nn-linux's `sensors::kmod_exec` does, on the
//! exec pump's thread, for the execs of a module tool only); the answer is
//! kept here per exec — (pid, the exec's time) — for the decision. An exec
//! the pump did not read (the replay, a test, an answer evicted) has no
//! facts: R011 kills it, as it killed every exec before lot 279.

use std::collections::{HashMap, VecDeque};
use std::sync::LazyLock;

use nn_model::Event;
use parking_lot::Mutex;

/// Kernel-module load/manage tool comms (design §7.1).
pub const KMOD_TOOLS: &[&str] = &["insmod", "modprobe", "kmod"];

/// What the exec pump read of one exec of a module tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecFacts {
    /// `Ok` when the executed file is the system's module tool; else why
    /// not.
    pub program: Result<(), String>,
    /// `Ok` when the environment was read and holds no `MODPROBE_OPTIONS`;
    /// else why not.
    pub environment: Result<(), String>,
}

impl ExecFacts {
    /// Why the exec is not vouched for by what the pump read, if it is not.
    pub fn refusal(&self) -> Option<&str> {
        self.program
            .as_ref()
            .err()
            .or(self.environment.as_ref().err())
            .map(String::as_str)
    }
}

/// (pid, the exec's time): one exec.
type ExecKey = (u32, u64);

/// The facts the exec pump read, per exec, oldest first out.
#[derive(Default)]
struct Kept {
    facts: HashMap<ExecKey, ExecFacts>,
    order: VecDeque<ExecKey>,
}

impl Kept {
    /// `facts` of the exec `k`, at most `cap` execs kept: past it, the
    /// oldest go.
    fn keep(&mut self, k: ExecKey, facts: ExecFacts, cap: usize) {
        if self.facts.insert(k, facts).is_none() {
            self.order.push_back(k);
        }
        while self.order.len() > cap {
            if let Some(old) = self.order.pop_front() {
                self.facts.remove(&old);
            }
        }
    }
}

static KEPT: LazyLock<Mutex<Kept>> = LazyLock::new(Default::default);

/// The execs [`KEPT`] keeps facts for at most: past it, the oldest go
/// (the decision reads an exec's facts right after its pump sent it).
pub const KEPT_EXECS: usize = 1024;

/// The key of `event`, an exec.
fn key(event: &Event) -> Option<ExecKey> {
    match event {
        Event::ProcessSpawn {
            pid, timestamp_ns, ..
        } => Some((*pid, *timestamp_ns)),
        _ => None,
    }
}

/// The exec pump's call: what it read of `event` (an exec of a module
/// tool), kept for the decision.
pub fn keep(event: &Event, facts: ExecFacts) {
    let Some(k) = key(event) else {
        return;
    };
    KEPT.lock().keep(k, facts, KEPT_EXECS);
}

/// What the exec pump read of `event`, if it read it.
pub fn of(event: &Event) -> Option<ExecFacts> {
    let k = key(event)?;
    KEPT.lock().facts.get(&k).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::rules::testutil::spawn;

    fn exec_at(pid: u32, ts: u64) -> Event {
        let mut e = spawn("modprobe", "/sbin/modprobe");
        if let Event::ProcessSpawn {
            pid: p,
            timestamp_ns,
            ..
        } = &mut e
        {
            (*p, *timestamp_ns) = (pid, ts);
        }
        e
    }

    fn ok() -> ExecFacts {
        ExecFacts {
            program: Ok(()),
            environment: Ok(()),
        }
    }

    /// Each exec its own facts — (pid, the exec's time): the same pid's
    /// next exec has none until its pump read it.
    #[test]
    fn the_facts_are_kept_per_exec() {
        let e = exec_at(u32::MAX - 1, 279_001);
        assert_eq!(of(&e), None);
        keep(&e, ok());
        assert_eq!(of(&e), Some(ok()));
        assert_eq!(of(&exec_at(u32::MAX - 1, 279_002)), None);
        let env = ExecFacts {
            environment: Err("MODPROBE_OPTIONS".into()),
            ..ok()
        };
        keep(&e, env.clone());
        assert_eq!(of(&e), Some(env.clone()));
        assert_eq!(env.refusal(), Some("MODPROBE_OPTIONS"));
        let prog = ExecFacts {
            program: Err("a copy".into()),
            ..env
        };
        assert_eq!(prog.refusal(), Some("a copy"), "the program first");
        assert_eq!(ok().refusal(), None);
        // not an exec: nothing kept, nothing read
        let other = Event::DefenderSignal {
            pid: u32::MAX - 1,
            uid: 0,
            comm: "modprobe".into(),
            target_pid: 1,
            signal: 9,
            timestamp_ns: 279_001,
        };
        keep(&other, ok());
        assert_eq!(of(&other), None);
    }

    /// Bounded: past its cap the oldest exec's facts go first, the newest
    /// stay; a key kept again is not counted twice (a local store: the
    /// shared one serves the other tests meanwhile).
    #[test]
    fn the_oldest_facts_go_first() {
        let mut kept = Kept::default();
        for ts in 1..=3 {
            kept.keep((7, ts), ok(), 3);
        }
        kept.keep((7, 3), ok(), 3);
        assert_eq!(kept.order.len(), 3);
        kept.keep((7, 4), ok(), 3);
        assert!(!kept.facts.contains_key(&(7, 1)), "the oldest went");
        for ts in 2..=4 {
            assert_eq!(kept.facts.get(&(7, ts)), Some(&ok()), "{ts}");
        }
        assert_eq!(kept.order, VecDeque::from([(7, 2), (7, 3), (7, 4)]));
    }
}
