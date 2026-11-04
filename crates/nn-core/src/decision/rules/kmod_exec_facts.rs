//! Lot 279: what the exec pump read of an exec of a kernel-module tool, AT
//! the exec — what its event does not carry and R011 judges beside the
//! command line's syntax ([`super::kmod_invocation`]):
//!
//! - **the program**: the file the kernel executed (`exe`'s device and
//!   inode, from the LSM hook) is the system's module tool — the one file
//!   `/usr/bin/kmod` resolves to, as the pump stats it then (the links the
//!   distribution installs execute that file). A copy, a file of its own
//!   under a tool's name, a file of another filesystem, an exec the hook
//!   did not describe (tracepoint mode) is not; nothing is when
//!   `/usr/bin/kmod` and `/bin/kmod` are two different files (one file
//!   under both names, a merged `/usr`, is the tool: the re-check of #498,
//!   N-3);
//! - **the environment**: the process's `/proc/<pid>/environ`, tied to the
//!   exec by a pidfd and its start time, holds neither `MODPROBE_OPTIONS`
//!   (options kmod puts in front of the command line: `-d`, `-C`, `--`…,
//!   which the sensor does not see) nor the dynamic linker's `LD_PRELOAD`,
//!   `LD_AUDIT`, `LD_LIBRARY_PATH` (code of the caller's choosing in the
//!   tool). One read: killed, whatever became of the process — evidence,
//!   not a false positive (the coordinator, 04/11). A RUNNING
//!   process whose environment could not be read, an environment over
//!   1 MiB, an unknown start: killed, nothing told it apart. A process that
//!   had EXITED before its environment could be read — no process with its
//!   pid, its pid another process's (its start not the exec's), a zombie,
//!   past its exit with its memory gone whatever was read then — is not
//!   killed: a kill would reach no one and leave only a false High kill
//!   (the coordinator's decision of 04/11, the re-review's conditions); an
//!   invocation R011 would record otherwise is recorded, its environment
//!   not verified ([`Environment::Exited`]). A leader that exited while
//!   another thread of its process runs on (`pthread_exit`) has not: the
//!   environment is read through that thread, refused when it cannot be
//!   read whole (the re-check of #498, DC-A) — or when no thread is seen
//!   while the kernel counts more than one (DC-B). An empty environment read
//!   from the running process is one (libxtables runs `modprobe` with
//!   none). Best effort: a short-lived `modprobe` may exit before the pump
//!   reads it, the likelier as a burst of execs slows the pump; code
//!   injected into the tool may outlive it in a child it forked, which
//!   R011's kill of the tool would not reach (N-1).
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

/// What the exec pump read of a module tool's environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Environment {
    /// Read from the running process: no `MODPROBE_OPTIONS`.
    Clean,
    /// The process had exited before its environment could be read (what
    /// was read, if anything, held no `MODPROBE_OPTIONS`): how.
    Exited(String),
    /// Not vouched for (why): R011's kill.
    Refused(String),
}

/// What the exec pump read of one exec of a module tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecFacts {
    /// `Ok` when the executed file is the system's module tool; else why
    /// not.
    pub program: Result<(), String>,
    pub environment: Environment,
}

impl ExecFacts {
    /// Why the exec is not vouched for by what the pump read, if it is not.
    pub fn refusal(&self) -> Option<&str> {
        match (&self.program, &self.environment) {
            (Err(why), _) | (Ok(()), Environment::Refused(why)) => Some(why),
            _ => None,
        }
    }

    /// The process had exited before its environment could be read.
    pub fn exited(&self) -> bool {
        matches!(self.environment, Environment::Exited(_))
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
            environment: Environment::Clean,
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
            environment: Environment::Refused("MODPROBE_OPTIONS".into()),
            ..ok()
        };
        keep(&e, env.clone());
        assert_eq!(of(&e), Some(env.clone()));
        assert_eq!(env.refusal(), Some("MODPROBE_OPTIONS"));
        assert!(!env.exited());
        let prog = ExecFacts {
            program: Err("a copy".into()),
            ..env
        };
        assert_eq!(prog.refusal(), Some("a copy"), "the program first");
        assert_eq!(ok().refusal(), None);
        assert!(!ok().exited());
        // exited before its environment could be read: no refusal, noted
        let gone = ExecFacts {
            environment: Environment::Exited("reaped".into()),
            ..ok()
        };
        assert_eq!(gone.refusal(), None);
        assert!(gone.exited());
        let gone_copy = ExecFacts {
            program: Err("a copy".into()),
            ..gone
        };
        assert_eq!(gone_copy.refusal(), Some("a copy"));
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
