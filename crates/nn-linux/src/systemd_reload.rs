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

use std::path::Path;
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tracing::{info, warn};

use crate::audit::{AuditEntryDraft, AuditLog};
use nn_core::decision::bounded::RepeatWindow;

/// At most one reload this often.
pub const MIN_INTERVAL: Duration = Duration::from_secs(30);
/// The same target triggers a reload at most once this often.
pub const TARGET_QUIET: Duration = Duration::from_secs(600);
/// Lot 314 (the third bug hunt, BUG-125's family): the targets the quiet is
/// kept for; past it the one admitted least recently is forgotten (one more
/// reload, still within [`MIN_INTERVAL`]). The table had no cap, and was
/// swept whole at every refusal.
pub const TARGETS_CAP: usize = 1024;

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
    /// Lot 273d: a drop-in of our own units' directories, made inside a
    /// window and harmful to them, quarantined at the window's close
    /// ([`crate::own_dropins`]): systemd's copy may hold it. At most one
    /// reload per [`MIN_INTERVAL`], like a refusal.
    OwnDropinQuarantined,
}

impl Reason {
    fn text(&self) -> String {
        match self {
            Self::Refused { op, dev, ino } => {
                format!("PID 1's {op} refused on {dev}:{ino} (a set-property outside a window)")
            }
            Self::WindowOpened => "a trusted-installer window opened".to_string(),
            Self::OwnDropinQuarantined => {
                "a drop-in of our units made inside a window, harmful to them, was quarantined"
                    .to_string()
            }
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
pub struct Limiter {
    last: Option<Instant>,
    /// Lot 314: the targets' quiet, capped ([`TARGETS_CAP`]).
    targets: RepeatWindow<(u64, u64)>,
}

impl Default for Limiter {
    fn default() -> Self {
        Self {
            last: None,
            targets: RepeatWindow::new(TARGET_QUIET, TARGETS_CAP),
        }
    }
}

impl std::fmt::Debug for Limiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Limiter")
            .field("last", &self.last)
            .field("targets", &self.targets.len())
            .finish()
    }
}

impl Limiter {
    /// What a request for `reason` at `now` gets. A window always reloads
    /// now (signed, rare, and its reload must not be lost); a
    /// refusal at most once per [`MIN_INTERVAL`] (later, not dropped), and
    /// once per target per [`TARGET_QUIET`].
    pub fn decide(&mut self, reason: &Reason, now: Instant) -> Decision {
        if let Reason::Refused { dev, ino, .. } = reason {
            if !self.targets.admit((*dev, *ino), now) {
                return Decision::Skip;
            }
        }
        if matches!(reason, Reason::WindowOpened) {
            return Decision::Now;
        }
        self.interval(now)
    }

    /// Now, or once [`MIN_INTERVAL`] since the last reload has passed.
    pub fn interval(&self, now: Instant) -> Decision {
        if let Some(last) = self.last {
            let since = now.saturating_duration_since(last);
            if since < MIN_INTERVAL {
                return Decision::After(MIN_INTERVAL - since);
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
    pub fn start(socket: &'static str, after: AfterReload) -> Self {
        if !Path::new(socket).exists() {
            return Self::inert();
        }
        let (tx, rx) = sync_channel::<Reason>(16);
        let audit: Arc<Mutex<Option<Arc<Mutex<AuditLog>>>>> = Arc::new(Mutex::new(None));
        let worker_audit = Arc::clone(&audit);
        let spawned = std::thread::Builder::new()
            .name("nn-sd-reload".into())
            .spawn(move || worker(rx, Path::new(socket), worker_audit, after));
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

fn worker(
    rx: Receiver<Reason>,
    socket: &Path,
    audit: Arc<Mutex<Option<Arc<Mutex<AuditLog>>>>>,
    after: AfterReload,
) {
    // A chain writer on a thread of its own: no capability but the
    // writer's (the socket's peer, PID 1's SIGHUP — root to root — and the
    // audit log need none).
    let _ = crate::caps::enter_or_report(crate::caps::Role::Writer);
    let mut limiter = Limiter::default();
    // A refusal kept for after the interval, and when.
    let mut pending: Option<(Reason, Instant)> = None;
    // Lot 273d: what systemd's copy still held below the floors after a
    // confirmed reload — the units' own files set it: no reload again for
    // the same values (a loop), a signed degradation while it holds.
    let mut on_disk: Vec<antitamper_bpf::unit_props::Below> = Vec::new();
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
                // Lot 273d (the review of #492): the same target within its
                // quiet is verified, not skipped — systemd's copy read back;
                // a copy below the floors that a reload did not already
                // find on disk is reloaded (after the interval).
                Decision::Skip => match hostile_copy(socket, &on_disk) {
                    Some(_) => match limiter.interval(Instant::now()) {
                        Decision::Now => r,
                        Decision::After(wait) => {
                            if pending.is_none() {
                                pending = Some((r, Instant::now() + wait));
                            }
                            continue;
                        }
                        Decision::Skip => continue,
                    },
                    None => continue,
                },
            },
            Err(RecvTimeoutError::Timeout) => match pending.take() {
                Some((r, _)) => r,
                None => continue,
            },
            Err(RecvTimeoutError::Disconnected) => return,
        };
        // a reload now covers what was pending too
        pending = None;
        let why = reason.text();
        let roots = crate::self_integrity::unit_roots(Path::new("/"));
        let search: Vec<&Path> = roots.iter().map(|p| p.as_path()).collect();
        let harms = crate::host_dropins::harmful(&search, &crate::host_dropins::HostLimits::read());
        match outcome(&harms, || {
            crate::systemd_state::reload_verified(socket, RELOAD_TIMEOUT)
        }) {
            Outcome::Withheld(what) => {
                warn!(reason = %why, withheld = %what, "systemd reload WITHHELD: a host drop-in harmful to our units is on disk, and a reload would apply it (inside a window, through)");
                crate::boot::degradation::report(
                    DEGRADATION,
                    &format!("the agent's reloads of systemd are withheld while {what}"),
                );
                record(&audit, &why, "withheld", Some(what), None);
            }
            Outcome::Confirmed(note) => {
                limiter.reloaded(Instant::now());
                // Lot 273d: the copy after the reload is the units' files.
                let still = antitamper_bpf::unit_props::below_floors(socket, PROPS_TIMEOUT)
                    .unwrap_or_default();
                crate::boot::degradation::withdraw(DEGRADATION, &[]);
                let after_note = if still.is_empty() {
                    on_disk.clear();
                    info!(reason = %why, note, "systemd reloaded (confirmed): its copy of the units is their files again");
                    None
                } else {
                    let what = still
                        .iter()
                        .map(antitamper_bpf::unit_props::Below::detail)
                        .collect::<Vec<_>>()
                        .join("; ");
                    warn!(reason = %why, still = %what, "systemd reloaded, and its copy is STILL below the floors: the units' files set it");
                    crate::boot::degradation::report(
                        DEGRADATION,
                        &format!("after a confirmed reload, the units' files set: {what}"),
                    );
                    on_disk = still;
                    Some(what)
                };
                record(
                    &audit,
                    &why,
                    "reloaded",
                    None,
                    after_note.or(Some(note.to_string())),
                );
                after();
            }
            Outcome::Failed(e) => {
                limiter.reloaded(Instant::now());
                warn!(reason = %why, error = %e, "systemd reload NOT confirmed — a refused set-property's copy may stay until the next reload");
                crate::boot::degradation::report(
                    DEGRADATION,
                    &format!("a reload of systemd was not confirmed: {e}"),
                );
                record(&audit, &why, "failed", Some(e), None);
            }
        }
    }
}

/// How long a reload may take to be confirmed.
const RELOAD_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a property read may take.
const PROPS_TIMEOUT: Duration = Duration::from_secs(5);
/// The degradation's source (`nn-admin status --key`, the manifest, the
/// heartbeat).
pub const DEGRADATION: &str = "systemd_reload";

/// What runs after a confirmed reload (lot 273d: the floors' values back
/// to the configured ones, `crate::anti_tamper::cgroup_guard`).
pub type AfterReload = Arc<dyn Fn() + Send + Sync>;

/// A value of systemd's copy below its floor that a confirmed reload did
/// not find set by the units' files (`on_disk`): a hostile copy.
fn hostile_copy(
    socket: &Path,
    on_disk: &[antitamper_bpf::unit_props::Below],
) -> Option<antitamper_bpf::unit_props::Below> {
    antitamper_bpf::unit_props::below_floors(socket, PROPS_TIMEOUT)
        .ok()?
        .into_iter()
        .find(|b| !on_disk.contains(b))
}

/// What a reload came to.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Asked and confirmed (systemd's `Reloading(false)`).
    Confirmed(&'static str),
    /// Not asked: a host drop-in harmful to our units is on disk
    /// (`crate::host_dropins`), and a reload would load it into systemd's
    /// copy — inside a trusted-installer window, where PID 1's writes are
    /// let through, onto our units' cgroups (the review of #492, C1; the
    /// lab's round 7 saw a `MemoryMax=4K` on `system.slice.d` applied by
    /// the window's own reload and the slice's services killed).
    Withheld(String),
    /// Asked and failed.
    Failed(String),
}

/// The reload of `reload`, unless `harms` holds a harmful drop-in.
pub fn outcome(
    harms: &[crate::host_dropins::Harm],
    reload: impl FnOnce() -> std::io::Result<&'static str>,
) -> Outcome {
    if let Some(h) = crate::host_dropins::withholding(harms) {
        let more = harms
            .iter()
            .filter(|x| x.kind == crate::host_dropins::Kind::Harmful)
            .count()
            - 1;
        return Outcome::Withheld(if more == 0 {
            h.detail()
        } else {
            format!("{} (and {more} more)", h.detail())
        });
    }
    match reload() {
        Ok(note) => Outcome::Confirmed(note),
        Err(e) => Outcome::Failed(e.to_string()),
    }
}

fn record(
    slot: &Mutex<Option<Arc<Mutex<AuditLog>>>>,
    why: &str,
    result: &str,
    error: Option<String>,
    note: Option<String>,
) {
    let audit = slot.lock().clone();
    let Some(audit) = audit else { return };
    let mut log = audit.lock();
    let draft = AuditEntryDraft {
        op: "systemd_reload".to_string(),
        extra: serde_json::json!({ "reason": why, "error": error, "note": note }),
        key_fp: "agent-self".to_string(),
        cosigner_fps: Vec::new(),
        result: result.to_string(),
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
        // a window: now, whatever the interval
        assert_eq!(
            l.decide(&Reason::WindowOpened, t0 + Duration::from_secs(1)),
            Decision::Now
        );
        // the target after its quiet
        assert_eq!(
            l.decide(&a, t0 + TARGET_QUIET + MIN_INTERVAL),
            Decision::Now
        );
    }

    /// Lot 314: the targets' table keeps its cap under a flood of distinct
    /// refused targets, each still a reload of its own once the interval
    /// allows it.
    #[test]
    fn the_targets_table_is_capped() {
        let mut l = Limiter::default();
        let t0 = Instant::now();
        for ino in 0..(TARGETS_CAP as u64 * 3) {
            let r = Reason::Refused {
                op: "cgroup_limit",
                dev: 1,
                ino,
            };
            assert_ne!(l.decide(&r, t0), Decision::Skip, "a new target");
        }
        assert_eq!(l.targets.len(), TARGETS_CAP);
        let newest = Reason::Refused {
            op: "cgroup_limit",
            dev: 1,
            ino: TARGETS_CAP as u64 * 3 - 1,
        };
        assert_eq!(l.decide(&newest, t0), Decision::Skip, "still quiet");
    }

    /// The review of #492 (C1), round 7: no reload while a host drop-in
    /// harmful to our units is on disk — a reload would apply it, inside
    /// a window onto our units' cgroups; the reload itself is not tried.
    #[test]
    fn a_harmful_host_drop_in_withholds_the_reload() {
        let harm = crate::host_dropins::Harm {
            path: "/etc/systemd/system/system.slice.d/99-x.conf".into(),
            directive: "MemoryMax".into(),
            value: "4K".into(),
            why: "below the slice's floor".into(),
            reach: crate::host_dropins::Reach::OurSlice,
            kind: crate::host_dropins::Kind::Harmful,
        };
        let mut tried = false;
        let o = outcome(std::slice::from_ref(&harm), || {
            tried = true;
            Ok("x")
        });
        assert!(!tried, "no reload tried");
        assert!(
            matches!(&o, Outcome::Withheld(w) if w.contains("99-x.conf sets MemoryMax=4K")),
            "{o:?}"
        );
        assert_eq!(
            outcome(&[], || Ok("confirmed")),
            Outcome::Confirmed("confirmed")
        );
        assert_eq!(
            outcome(&[], || Err(std::io::Error::other("no"))),
            Outcome::Failed("no".into())
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
