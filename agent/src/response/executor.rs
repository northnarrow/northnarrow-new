//! Dispatcher: turns a `(ResponseAction, target_pid)` into an
//! [`ExecutionReport`].

use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, Instant},
};

use common::ResponseAction;
use tracing::warn;

use super::{
    block_outbound, kill, quarantine, throttle, ExecutionOutcome, ExecutionReport, ExecutorConfig,
};

/// Hard floor on PIDs we're willing to touch. Anything below this is
/// almost certainly a kernel thread or core service (PID 1, kthreadd,
/// systemd helpers). Conservative on purpose — we'd rather miss a
/// quirky early-PID malware than ever kill init.
const PID_PROTECTION_FLOOR: u32 = 100;

/// Per-pid guard consulted by KillProcessTree for every pid in the walk
/// (audit `combat-avail-2`). Returns the reason a pid must be spared.
pub type TreeGuard = Arc<dyn Fn(u32) -> Option<&'static str> + Send + Sync>;

/// Reusable executor. Cheap to clone (Arc-wraps the read-only state),
/// so tasks can grab their own copy and run kill syscalls on a
/// blocking pool without contention.
#[derive(Clone)]
pub struct Executor {
    own_pid: u32,
    protected: Arc<HashSet<u32>>,
    config: Arc<ExecutorConfig>,
    /// Set once the COMBAT ladder's `ProtectedProcs` exists (it is built
    /// after the executor, so this is a late-bound slot shared by clones).
    tree_guard: Arc<parking_lot::RwLock<Option<TreeGuard>>>,
}

impl std::fmt::Debug for Executor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Executor")
            .field("own_pid", &self.own_pid)
            .field("protected", &self.protected)
            .field("config", &self.config)
            .field("tree_guard", &self.tree_guard.read().is_some())
            .finish()
    }
}

impl Executor {
    /// Build a default executor with `init`, `kthreadd`, and the
    /// agent's own PID in the protected set, and a default
    /// [`ExecutorConfig`].
    pub fn new() -> Self {
        Self::with_config(ExecutorConfig::from_env())
    }

    /// Build an executor with an explicit [`ExecutorConfig`]. Useful
    /// for tests and for binaries that want to tweak paths or
    /// dry-run mode without touching env vars.
    pub fn with_config(config: ExecutorConfig) -> Self {
        let own_pid = std::process::id();
        let mut protected = HashSet::new();
        protected.insert(0);
        protected.insert(1);
        protected.insert(2);
        protected.insert(own_pid);
        Self {
            own_pid,
            protected: Arc::new(protected),
            config: Arc::new(config),
            tree_guard: Arc::new(parking_lot::RwLock::new(None)),
        }
    }

    /// Install the host-critical guard consulted on every pid of a
    /// KillProcessTree walk (root AND /proc descendants). Idempotent;
    /// visible to every clone of this executor.
    pub fn set_tree_guard(&self, guard: TreeGuard) {
        *self.tree_guard.write() = Some(guard);
    }

    /// PID of the running agent. Exposed for telemetry; never killable.
    pub fn own_pid(&self) -> u32 {
        self.own_pid
    }

    /// Protected PID set (read-only). Mostly useful for tests.
    pub fn protected(&self) -> &HashSet<u32> {
        &self.protected
    }

    /// Active configuration (read-only).
    pub fn config(&self) -> &ExecutorConfig {
        &self.config
    }

    /// Run a verdict's `action`: [`Self::execute`], except the actions
    /// that act on the verdict's file rather than on its process
    /// (review 86: [`ResponseAction::StripFileCapability`]).
    pub fn execute_for(
        &self,
        action: ResponseAction,
        target_pid: u32,
        filename: &str,
    ) -> ExecutionReport {
        if !matches!(action, ResponseAction::StripFileCapability) || self.config.dry_run {
            return self.execute(action, target_pid);
        }
        let start = Instant::now();
        ExecutionReport {
            action,
            primary: super::file_caps::strip(filename, target_pid),
            additional: Vec::new(),
            elapsed: clamp_elapsed(start.elapsed()),
        }
    }

    /// Review 87: quarantine the binary `handle` holds, which backed `pid`
    /// (already killed; external audit CMB-001: opened before the kill, the
    /// inode itself, not a path). Detect-only reports `WouldExecute`.
    pub fn quarantine_handle(&self, handle: &quarantine::ExeHandle, pid: u32) -> ExecutionReport {
        let start = Instant::now();
        let primary = if self.config.dry_run {
            ExecutionOutcome::WouldExecute { pid }
        } else {
            quarantine::quarantine_handle(handle, pid, &self.config)
        };
        ExecutionReport {
            action: ResponseAction::Quarantine,
            primary,
            additional: Vec::new(),
            elapsed: clamp_elapsed(start.elapsed()),
        }
    }

    /// Run `action` against `target_pid`. Always returns; never panics.
    pub fn execute(&self, action: ResponseAction, target_pid: u32) -> ExecutionReport {
        let start = Instant::now();
        let mut additional: Vec<ExecutionOutcome> = Vec::new();

        // External audit CMB-006: host-wide isolation is the COMBAT ladder's
        // alone — engaged from locked COMBAT (kernel evidence), through the
        // management carve-out (`combat-allow.cidrs`), released with the
        // signed unlock, reported by `nn-admin status`. This action
        // installed a second, separate nftables blackout reachable from an
        // ADE verdict: no carve-out (an open SSH session died too: no
        // established rule on output), no release verb, no status.
        if action == ResponseAction::FullNetworkIsolation {
            warn!(
                target_pid,
                "host-wide isolation requested outside the COMBAT ladder — refused"
            );
            return ExecutionReport {
                action,
                primary: ExecutionOutcome::Refused {
                    pid: target_pid,
                    reason: ISOLATION_IS_THE_LADDERS,
                },
                additional,
                elapsed: clamp_elapsed(start.elapsed()),
            };
        }

        // Detect-only / monitor mode (BUG-033): the single agent-wide
        // no-enforcement gate, checked here at the dispatcher so it
        // covers EVERY action — including KillProcess[Tree], which has
        // no per-module suppression branch and would otherwise SIGKILL
        // for real. Log what we would have done and return
        // `WouldExecute`, touching nothing. main.rs gates COMBAT-posture
        // isolation on the same flag, so both enforcement entry points
        // honour one switch.
        if self.config.dry_run {
            // A Log verdict has nothing to suppress: no line per verdict
            // (a flood of them filled the journal, review 75).
            if !matches!(action, ResponseAction::Log) {
                warn!(
                    target: "response.detect_only",
                    action = ?action,
                    target_pid,
                    "DETECT-ONLY: would execute response action — suppressed, no system change"
                );
            }
            return ExecutionReport {
                action,
                primary: ExecutionOutcome::WouldExecute { pid: target_pid },
                additional,
                elapsed: clamp_elapsed(start.elapsed()),
            };
        }

        // The PID protection floor only applies to actions that
        // operate on a specific PID. `FullNetworkIsolation` is
        // host-wide and ignores `target_pid` entirely.
        let pid_scoped = !matches!(action, ResponseAction::FullNetworkIsolation);
        // External audit CMB-005: the host-critical guard — the floor, and
        // the ladder's guard (the agent's stack, the SSH service) — applies
        // to every action that acts on a process. It was consulted only by
        // the tree walk, so a rule's KillProcess, or a Quarantine,
        // BlockOutbound or Throttle verdict, could take down sshd or the
        // watchdog.
        let guard = self.tree_guard.read().clone();
        let spared = move |pid: u32| -> Option<&'static str> {
            if pid < PID_PROTECTION_FLOOR {
                return Some("PID below protection floor (kernel thread / core service)");
            }
            guard.as_ref().and_then(|g| g(pid))
        };
        let acts_on_process = matches!(
            action,
            ResponseAction::KillProcess
                | ResponseAction::KillProcessTree
                | ResponseAction::BlockOutbound
                | ResponseAction::Quarantine
                | ResponseAction::ThrottleProcess
        );
        let primary = if pid_scoped && target_pid != 0 && target_pid < PID_PROTECTION_FLOOR {
            ExecutionOutcome::Refused {
                pid: target_pid,
                reason: "PID below protection floor (kernel thread / core service)",
            }
        } else if let Some(reason) =
            spared(target_pid).filter(|_| acts_on_process && target_pid != 0)
        {
            ExecutionOutcome::Refused {
                pid: target_pid,
                reason,
            }
        } else {
            match action {
                ResponseAction::Log => ExecutionOutcome::Refused {
                    pid: target_pid,
                    reason: "Log action — no execution required",
                },
                ResponseAction::KillProcess => kill::kill_process(target_pid, &self.protected),
                ResponseAction::KillProcessTree => {
                    // The same guard for every pid the walk reaps, not
                    // only for the attributed root (combat-avail-2).
                    let (p, kids) =
                        kill::kill_process_tree_guarded(target_pid, &self.protected, &spared);
                    additional = kids;
                    p
                }
                ResponseAction::BlockOutbound => block_outbound::block_outbound_for_pid(
                    target_pid,
                    &self.protected,
                    &self.config,
                ),
                ResponseAction::FullNetworkIsolation => ExecutionOutcome::Refused {
                    pid: target_pid,
                    reason: ISOLATION_IS_THE_LADDERS,
                },
                ResponseAction::Quarantine => {
                    quarantine::quarantine_process_binary(target_pid, &self.protected, &self.config)
                }
                ResponseAction::ThrottleProcess => {
                    throttle::throttle_pid(target_pid, &self.protected, &self.config)
                }
                // Acts on a file: only through `execute_for`.
                ResponseAction::StripFileCapability => ExecutionOutcome::Refused {
                    pid: target_pid,
                    reason: "StripFileCapability needs the verdict's file (execute_for)",
                },
            }
        };

        ExecutionReport {
            action,
            primary,
            additional,
            elapsed: clamp_elapsed(start.elapsed()),
        }
    }
}

/// Why [`ResponseAction::FullNetworkIsolation`] is refused (external audit
/// CMB-006).
pub const ISOLATION_IS_THE_LADDERS: &str =
    "host-wide isolation is the COMBAT ladder's (locked COMBAT, management carve-out, signed release)";

impl Default for Executor {
    fn default() -> Self {
        Self::new()
    }
}

/// Normalise zero/sub-microsecond elapsed durations to 1µs for cleaner
/// logging. Has no behavioural impact otherwise.
fn clamp_elapsed(d: Duration) -> Duration {
    if d.as_nanos() == 0 {
        Duration::from_micros(1)
    } else {
        d
    }
}
