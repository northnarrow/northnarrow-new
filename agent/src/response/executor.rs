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
    block_outbound, kill, proc_ref::ProcRef, quarantine, throttle, ExecutionOutcome,
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
    /// External audit CMB-017: the signed audit log, once open (late-bound
    /// like the guard) — every quarantine is recorded in it.
    audit: Arc<parking_lot::RwLock<Option<SharedAuditLog>>>,
}

/// The agent's signed audit log, shared.
pub type SharedAuditLog = Arc<parking_lot::Mutex<crate::audit::AuditLog>>;

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
            audit: Arc::new(parking_lot::RwLock::new(None)),
        }
    }

    /// External audit CMB-017: record quarantines in the signed audit log
    /// from now on. Visible to every clone of this executor.
    pub fn set_audit_log(&self, log: SharedAuditLog) {
        *self.audit.write() = Some(log);
    }

    /// A response entry in the signed audit log, when it is open.
    fn audit_entry(&self, op: &str, extra: serde_json::Value, result: &str) {
        let Some(log) = self.audit.read().clone() else {
            return;
        };
        let draft = crate::audit::AuditEntryDraft {
            op: op.to_string(),
            extra,
            key_fp: "agent-self".to_string(),
            cosigner_fps: Vec::new(),
            result: result.to_string(),
            client_pid: std::process::id(),
            client_uid: 0,
            client_comm: "northnarrow-agent".to_string(),
            client_exe: None,
        };
        let appended = log.lock().append(draft);
        if let Err(e) = appended {
            warn!(error = %e, op, "recording a response in the audit log failed");
        }
    }

    /// External audit CMB-010: a process moved into a containment scope,
    /// with the cgroup it came from, in the signed audit log.
    fn record_contain(&self, pid: u32, scope: &str) {
        let origin = super::containment::find(&self.config, pid, scope).map(|c| c.origin);
        self.audit_entry(
            "response_contain",
            serde_json::json!({ "pid": pid, "scope": scope, "origin": origin }),
            "success",
        );
    }

    /// External audit CMB-010: a release (or a release left undone, with
    /// why) in the signed audit log.
    pub fn record_release(&self, pid: u32, scope: &str, outcome: &super::containment::Release) {
        let (result, why) = match outcome {
            super::containment::Release::Released => ("success", None),
            super::containment::Release::Skipped(why) => ("skipped", Some(*why)),
        };
        self.audit_entry(
            "response_release",
            serde_json::json!({ "pid": pid, "scope": scope, "why": why }),
            result,
        );
    }

    /// External audit CMB-017: a quarantine (and any index repair) in the
    /// signed audit log — the vault id, the path, the content's SHA-256
    /// and size, the process.
    fn record_quarantine(&self, pid: u32, outcome: &ExecutionOutcome) {
        let notes = quarantine::take_index_notes();
        let ExecutionOutcome::Quarantined {
            original_path,
            vault_id,
        } = outcome
        else {
            if notes.is_empty() {
                return;
            }
            return self.record_index_notes(notes);
        };
        let Some(log) = self.audit.read().clone() else {
            warn!(vault_id = %vault_id, "quarantine not recorded: the audit log is not open");
            return;
        };
        let meta = quarantine::vault_meta(vault_id, &self.config).unwrap_or_default();
        let draft = crate::audit::AuditEntryDraft {
            op: "response_quarantine".to_string(),
            extra: serde_json::json!({
                "vault_id": vault_id,
                "original_path": original_path,
                "sha256": meta["sha256"],
                "size_bytes": meta["size_bytes"],
                "pid": pid,
            }),
            key_fp: "agent-self".to_string(),
            cosigner_fps: Vec::new(),
            result: "success".to_string(),
            client_pid: std::process::id(),
            client_uid: 0,
            client_comm: "northnarrow-agent".to_string(),
            client_exe: None,
        };
        if let Err(e) = log.lock().append(draft) {
            warn!(error = %e, "recording a quarantine in the audit log failed");
        }
        self.record_index_notes(notes);
    }

    fn record_index_notes(&self, notes: Vec<String>) {
        let Some(log) = self.audit.read().clone() else {
            return;
        };
        for note in notes {
            let draft = crate::audit::AuditEntryDraft {
                op: crate::self_integrity::AUDIT_OP.to_string(),
                extra: serde_json::json!({"kind": "quarantine_index_rebuilt", "detail": note}),
                key_fp: "agent-self".to_string(),
                cosigner_fps: Vec::new(),
                result: "detected".to_string(),
                client_pid: std::process::id(),
                client_uid: 0,
                client_comm: "northnarrow-agent".to_string(),
                client_exe: None,
            };
            if let Err(e) = log.lock().append(draft) {
                warn!(error = %e, "recording a quarantine index repair failed");
            }
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
        self.execute_for_started(action, target_pid, 0, 0, filename)
    }

    /// [`Self::execute_for`] for the process the verdict's event reported:
    /// started at `start_ns` (an exec), or, that unknown, by `seen_ns` (the
    /// event's time) — `CLOCK_MONOTONIC`, 0 = unknown. External audit
    /// CMB-004: a kill does not reach a process that took the PID after the
    /// event.
    pub fn execute_for_started(
        &self,
        action: ResponseAction,
        target_pid: u32,
        start_ns: u64,
        seen_ns: u64,
        filename: &str,
    ) -> ExecutionReport {
        if !matches!(action, ResponseAction::StripFileCapability) || self.config.dry_run {
            return self.execute_started(action, target_pid, start_ns, seen_ns);
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
            let o = quarantine::quarantine_handle(handle, pid, &self.config);
            self.record_quarantine(pid, &o);
            o
        };
        ExecutionReport {
            action: ResponseAction::Quarantine,
            primary,
            additional: Vec::new(),
            elapsed: clamp_elapsed(start.elapsed()),
        }
    }

    /// Run `action` against `target_pid` — the process it names now.
    /// Always returns; never panics.
    pub fn execute(&self, action: ResponseAction, target_pid: u32) -> ExecutionReport {
        self.execute_started(action, target_pid, 0, 0)
    }

    /// [`Self::execute`] for the process its event reported: started at
    /// `start_ns` (an exec), or, that unknown, by `seen_ns` (the event's
    /// time) — `CLOCK_MONOTONIC`, 0 = unknown. External audit CMB-004: a
    /// kill does not reach a process that took the PID after the event.
    pub fn execute_started(
        &self,
        action: ResponseAction,
        target_pid: u32,
        start_ns: u64,
        seen_ns: u64,
    ) -> ExecutionReport {
        let target = Self::capture(&action, target_pid, start_ns, seen_ns);
        self.execute_on(action, &target)
    }

    /// A kill acts on a process captured by its pidfd (external audit
    /// CMB-004); the other actions on the PID. `start_ns` / `seen_ns` (the
    /// event's, `CLOCK_MONOTONIC`; 0 = unknown): a PID that names a process
    /// with another start, or one started after the event, by now is not
    /// the target.
    fn capture(action: &ResponseAction, pid: u32, start_ns: u64, seen_ns: u64) -> ProcRef {
        if matches!(
            action,
            ResponseAction::KillProcess | ResponseAction::KillProcessTree
        ) && pid > 1
        {
            ProcRef::open_for_event(pid, start_ns, seen_ns)
        } else {
            ProcRef::unopened(pid)
        }
    }

    /// Run `action` against the process `target` holds (external audit
    /// CMB-004: the COMBAT ladder captures its offenders when it
    /// attributes them). Always returns; never panics.
    pub fn execute_on(&self, action: ResponseAction, target: &ProcRef) -> ExecutionReport {
        let target_pid = target.pid();
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
        } else if matches!(
            action,
            ResponseAction::KillProcess | ResponseAction::KillProcessTree
        ) && target_pid != 0
            && !target.is_live()
            && target.capture_errno().is_none()
        {
            // External audit CMB-004: a kill target that has exited is gone
            // — decided before the guard, which looks at the PID: by now it
            // may name a protected process (an sshd child, a restarted
            // watchdog), and a refusal would read as an offender that
            // could not be contained.
            ExecutionOutcome::AlreadyGone { pid: target_pid }
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
                ResponseAction::KillProcess => kill::kill_ref(target, &self.protected),
                ResponseAction::KillProcessTree => {
                    // The same guard for every pid the walk reaps, not
                    // only for the attributed root (combat-avail-2).
                    // External audit CMB-019: through a cgroup of its own.
                    static KILL_CGROUPS: std::sync::atomic::AtomicU64 =
                        std::sync::atomic::AtomicU64::new(0);
                    let n = KILL_CGROUPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let scope = self.config.kill_cgroup_dir(n);
                    let (p, kids) = kill::kill_tree(target, &self.protected, &spared, Some(&scope));
                    additional = kids;
                    p
                }
                ResponseAction::BlockOutbound => {
                    let o = block_outbound::block_outbound_for_pid(
                        target_pid,
                        &self.protected,
                        &self.config,
                    );
                    if matches!(o, ExecutionOutcome::Blocked { .. }) && !self.config.dry_run {
                        self.record_contain(target_pid, "blocked");
                    }
                    o
                }
                ResponseAction::FullNetworkIsolation => ExecutionOutcome::Refused {
                    pid: target_pid,
                    reason: ISOLATION_IS_THE_LADDERS,
                },
                ResponseAction::Quarantine => {
                    let o = quarantine::quarantine_process_binary(
                        target_pid,
                        &self.protected,
                        &self.config,
                    );
                    self.record_quarantine(target_pid, &o);
                    o
                }
                ResponseAction::ThrottleProcess => {
                    let o = throttle::throttle_pid(target_pid, &self.protected, &self.config);
                    if matches!(o, ExecutionOutcome::Throttled { .. }) && !self.config.dry_run {
                        self.record_contain(target_pid, "throttled");
                    }
                    o
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
