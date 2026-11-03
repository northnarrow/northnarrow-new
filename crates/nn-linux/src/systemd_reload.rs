//! Lot 273c (the review of #490): the agent asks systemd for a
//! `daemon-reload` when its copy of a unit may hold what the kernel
//! refused.
//!
//! A `systemctl set-property` outside a window is refused at the cgroup
//! file and at its drop-in, but systemd sets the unit's property in memory
//! first, and the unit's next start applies it to the fresh cgroup (the
//! lab measured it on all five systemd versions). A reload takes systemd's
//! copy back to the unit's files. It is asked:
//!
//! * when PID 1's write of a protected resource file, or its new entry in
//!   a protected drop-in directory, is refused (`request`, from the
//!   pipeline's denial arm) — at most one reload per [`MIN_INTERVAL`],
//!   and not again for the same target within [`TARGET_QUIET`] (a unit
//!   whose own file sets a value below a floor would otherwise loop);
//! * when a trusted-installer window opens, before the maintenance it is
//!   for restarts a unit.
//!
//! Each reload is a signed audit entry (`systemd_reload`) once the audit
//! log is attached. The reload is systemd's on a SIGHUP, sent once its
//! private socket is found served by PID 1
//! ([`crate::systemd_state::reload`]: not `Manager.Reload()`, which waits
//! for polkit without `CAP_SYS_ADMIN`), from a thread of its own.

use std::collections::HashMap;
use std::path::Path;
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tracing::{info, warn};

use crate::audit::{AuditEntryDraft, AuditLog};

/// At most one reload this often.
pub const MIN_INTERVAL: Duration = Duration::from_secs(30);
/// The same target triggers a reload at most once this often.
pub const TARGET_QUIET: Duration = Duration::from_secs(600);

/// Why a reload is asked: a refused write of PID 1 (its target, as the
/// denial names it) or a window that opened.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Reason {
    Refused {
        op: &'static str,
        dev: u64,
        ino: u64,
    },
    WindowOpened,
    /// A host drop-in reaching the units was quarantined
    /// ([`crate::dropin_quarantine`]): systemd's copy still has it.
    Quarantined,
}

impl Reason {
    fn text(&self) -> String {
        match self {
            Self::Refused { op, dev, ino } => {
                format!("PID 1's {op} refused on {dev}:{ino} (a set-property outside a window)")
            }
            Self::WindowOpened => "a trusted-installer window opened".to_string(),
            Self::Quarantined => "a host drop-in reaching the units was quarantined".to_string(),
        }
    }
}

/// What the rate limit decides of a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Reload now.
    Now,
    /// Reload once this has passed (the interval since the last one): the
    /// request is kept, not lost — systemd's copy must not stay.
    After(Duration),
    /// Not again: the same target within its quiet (a loop).
    Skip,
}

/// The decision of the rate limit (pure, for the tests).
#[derive(Debug, Default)]
pub struct Limiter {
    last: Option<Instant>,
    targets: HashMap<(u64, u64), Instant>,
}

impl Limiter {
    /// What a request for `reason` at `now` gets. A window or a quarantine
    /// always reloads now (rare, and their reload must not be lost); a
    /// refusal at most once per [`MIN_INTERVAL`] (later, not dropped), and
    /// once per target per [`TARGET_QUIET`].
    pub fn decide(&mut self, reason: &Reason, now: Instant) -> Decision {
        if let Reason::Refused { dev, ino, .. } = reason {
            if let Some(seen) = self.targets.get(&(*dev, *ino)) {
                if now.saturating_duration_since(*seen) < TARGET_QUIET {
                    return Decision::Skip;
                }
            }
            self.targets
                .retain(|_, t| now.saturating_duration_since(*t) < TARGET_QUIET);
            self.targets.insert((*dev, *ino), now);
            if let Some(last) = self.last {
                let since = now.saturating_duration_since(last);
                if since < MIN_INTERVAL {
                    return Decision::After(MIN_INTERVAL - since);
                }
            }
        }
        Decision::Now
    }

    /// A reload was made at `now`.
    pub fn reloaded(&mut self, now: Instant) {
        self.last = Some(now);
    }
}

/// The agent's handle on its reload worker (R11c: an explicit handle the
/// start hands on, no process-wide slot). Cheap to clone.
#[derive(Clone)]
pub struct Reloader {
    tx: Option<SyncSender<Reason>>,
    audit: Arc<Mutex<Option<Arc<Mutex<AuditLog>>>>>,
}

impl Reloader {
    /// A reloader that asks nothing (no systemd here, a test).
    pub fn inert() -> Self {
        Self {
            tx: None,
            audit: Arc::new(Mutex::new(None)),
        }
    }

    /// Start the worker on systemd's private socket `socket`; inert when
    /// the socket is not there (no systemd) or the thread cannot start.
    pub fn start(socket: &'static str) -> Self {
        if !Path::new(socket).exists() {
            return Self::inert();
        }
        let (tx, rx) = sync_channel::<Reason>(16);
        let audit: Arc<Mutex<Option<Arc<Mutex<AuditLog>>>>> = Arc::new(Mutex::new(None));
        let worker_audit = Arc::clone(&audit);
        let spawned = std::thread::Builder::new()
            .name("nn-sd-reload".into())
            .spawn(move || worker(rx, Path::new(socket), worker_audit));
        match spawned {
            Ok(_) => Self {
                tx: Some(tx),
                audit,
            },
            Err(e) => {
                warn!(error = %e, "systemd reload worker not started — a refused set-property's copy stays until the next reload");
                Self::inert()
            }
        }
    }

    /// The signed log the reloads are recorded in, once it is open.
    pub fn set_audit_log(&self, audit: Arc<Mutex<AuditLog>>) {
        *self.audit.lock() = Some(audit);
    }

    /// Ask for a reload; never blocks (a full queue drops the request: a
    /// reload is coming anyway).
    pub fn request(&self, reason: Reason) {
        let Some(tx) = &self.tx else { return };
        match tx.try_send(reason) {
            Ok(()) | Err(TrySendError::Full(_)) => {}
            Err(TrySendError::Disconnected(_)) => {
                warn!("systemd reload worker gone — reload not asked");
            }
        }
    }
}

fn worker(rx: Receiver<Reason>, socket: &Path, audit: Arc<Mutex<Option<Arc<Mutex<AuditLog>>>>>) {
    // A chain writer on a thread of its own: no capability but the
    // writer's (the socket's peer, PID 1's SIGHUP — root to root — and the
    // audit log need none).
    let _ = crate::caps::enter_or_report(crate::caps::Role::Writer);
    let mut limiter = Limiter::default();
    // A refusal kept for after the interval, and when.
    let mut pending: Option<(Reason, Instant)> = None;
    loop {
        let next = match &pending {
            Some((_, at)) => rx.recv_timeout(at.saturating_duration_since(Instant::now())),
            None => rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
        };
        let reason = match next {
            Ok(r) => match limiter.decide(&r, Instant::now()) {
                Decision::Now => r,
                Decision::After(wait) => {
                    if pending.is_none() {
                        pending = Some((r, Instant::now() + wait));
                    }
                    continue;
                }
                Decision::Skip => continue,
            },
            Err(RecvTimeoutError::Timeout) => match pending.take() {
                Some((r, _)) => r,
                None => continue,
            },
            Err(RecvTimeoutError::Disconnected) => return,
        };
        // a reload now covers what was pending too
        pending = None;
        limiter.reloaded(Instant::now());
        let result = crate::systemd_state::reload(socket);
        let why = reason.text();
        match &result {
            Ok(()) => {
                info!(reason = %why, "systemd asked to reload (SIGHUP, its daemon-reload): its copy of the units becomes their files again")
            }
            Err(e) => {
                warn!(reason = %why, error = %e, "systemd reload NOT asked — a refused set-property's copy may stay until the next reload")
            }
        }
        record(&audit, &why, result.as_ref().err().map(|e| e.to_string()));
    }
}

fn record(slot: &Mutex<Option<Arc<Mutex<AuditLog>>>>, why: &str, error: Option<String>) {
    let audit = slot.lock().clone();
    let Some(audit) = audit else { return };
    let mut log = audit.lock();
    let draft = AuditEntryDraft {
        op: "systemd_reload".to_string(),
        extra: serde_json::json!({ "reason": why, "error": error }),
        key_fp: "agent-self".to_string(),
        cosigner_fps: Vec::new(),
        result: if error.is_none() {
            "requested".into()
        } else {
            "failed".into()
        },
        client_pid: log.self_pid(),
        client_uid: 0,
        client_comm: "northnarrow-agent".to_string(),
        client_exe: None,
    };
    if let Err(e) = log.append(draft) {
        warn!(error = %e, "systemd reload: audit entry failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_reload_per_interval_kept_not_lost_and_one_per_target_quiet() {
        let mut l = Limiter::default();
        let t0 = Instant::now();
        let a = Reason::Refused {
            op: "cgroup_limit",
            dev: 1,
            ino: 2,
        };
        let b = Reason::Refused {
            op: "create",
            dev: 1,
            ino: 3,
        };
        assert_eq!(l.decide(&a, t0), Decision::Now);
        l.reloaded(t0);
        // within the interval: later, not dropped
        assert_eq!(
            l.decide(&b, t0 + Duration::from_secs(5)),
            Decision::After(MIN_INTERVAL - Duration::from_secs(5))
        );
        // the same target within its quiet: not again
        assert_eq!(l.decide(&a, t0 + MIN_INTERVAL * 3), Decision::Skip);
        // a window or a quarantine: now, whatever the interval
        assert_eq!(
            l.decide(&Reason::WindowOpened, t0 + Duration::from_secs(1)),
            Decision::Now
        );
        assert_eq!(
            l.decide(&Reason::Quarantined, t0 + Duration::from_secs(1)),
            Decision::Now
        );
        // the target after its quiet
        assert_eq!(
            l.decide(&a, t0 + TARGET_QUIET + MIN_INTERVAL),
            Decision::Now
        );
    }

    #[test]
    fn the_reason_says_what_was_refused() {
        let r = Reason::Refused {
            op: "cgroup_limit",
            dev: 28,
            ino: 3843,
        };
        assert!(r.text().contains("cgroup_limit refused on 28:3843"));
        assert!(Reason::WindowOpened.text().contains("window opened"));
    }
}
