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
    block_outbound, kill, network_isolation, quarantine, throttle, ExecutionOutcome,
    ExecutionReport, ExecutorConfig,
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

    /// Run `action` against `target_pid`. Always returns; never panics.
    pub fn execute(&self, action: ResponseAction, target_pid: u32) -> ExecutionReport {
        let start = Instant::now();
        let mut additional: Vec<ExecutionOutcome> = Vec::new();

        // Detect-only / monitor mode (BUG-033): the single agent-wide
        // no-enforcement gate, checked here at the dispatcher so it
        // covers EVERY action — including KillProcess[Tree], which has
        // no per-module suppression branch and would otherwise SIGKILL
        // for real. Log what we would have done and return
        // `WouldExecute`, touching nothing. main.rs gates COMBAT-posture
        // isolation on the same flag, so both enforcement entry points
        // honour one switch.
        if self.config.dry_run {
            warn!(
                target: "response.detect_only",
                action = ?action,
                target_pid,
                "DETECT-ONLY: would execute response action — suppressed, no system change"
            );
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
        let primary = if pid_scoped && target_pid != 0 && target_pid < PID_PROTECTION_FLOOR {
            ExecutionOutcome::Refused {
                pid: target_pid,
                reason: "PID below protection floor (kernel thread / core service)",
            }
        } else {
            match action {
                ResponseAction::Log => ExecutionOutcome::Refused {
                    pid: target_pid,
                    reason: "Log action — no execution required",
                },
                ResponseAction::KillProcess => kill::kill_process(target_pid, &self.protected),
                ResponseAction::KillProcessTree => {
                    // The protection floor + the ladder's host-critical
                    // guard apply to every pid the walk reaps, not only to
                    // the attributed root (combat-avail-2).
                    let guard = self.tree_guard.read().clone();
                    let combined = move |pid: u32| -> Option<&'static str> {
                        if pid < PID_PROTECTION_FLOOR {
                            return Some(
                                "PID below protection floor (kernel thread / core service)",
                            );
                        }
                        guard.as_ref().and_then(|g| g(pid))
                    };
                    let (p, kids) =
                        kill::kill_process_tree_guarded(target_pid, &self.protected, &combined);
                    additional = kids;
                    p
                }
                ResponseAction::BlockOutbound => block_outbound::block_outbound_for_pid(
                    target_pid,
                    &self.protected,
                    &self.config,
                ),
                ResponseAction::FullNetworkIsolation => network_isolation::engage(&self.config),
                ResponseAction::Quarantine => {
                    quarantine::quarantine_process_binary(target_pid, &self.protected, &self.config)
                }
                ResponseAction::ThrottleProcess => {
                    throttle::throttle_pid(target_pid, &self.protected, &self.config)
                }
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
