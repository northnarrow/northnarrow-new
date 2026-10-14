//! FIM-009 self-upgrade (§15.1) — userland half of the trusted-installer
//! FS-pin override.
//!
//! The kernel half: `agent-ebpf/src/inode_protect.rs` short-circuits its
//! deny hooks to ALLOW when
//! [`override_active`](../../../agent-ebpf/src/inode_protect.rs) reads a
//! `FS_GRANT[0]` whose nonce matches this boot's `AGENT_SESSION[0]` and
//! whose deadline has not passed. This module is the userland arming path.
//!
//! ## What an armed override does
//!
//! While a grant window is open:
//! - **Prevention half (kernel):** `FS_GRANT[0]` carries the session
//!   nonce and the deadline, so every `inode_protect` deny hook passes
//!   through until then —
//!   a trusted local installer can rewrite the agent's protected binary
//!   / protected `/etc/northnarrow` files without the EPERM (BUG-020).
//! - **Detection half (userland):** [`Self::is_window_open`] is `true`,
//!   so the `NN-L-FIM-009` rule downgrades a write of the agent's OWN
//!   systemd units from `KillProcess`/High to an audit-level `Log`
//!   (see `crate::fim::rules`). It is a *pure read* of this state.
//!
//! - **PID-1 stop grant (external audit EBPF-001):** `KILL_GRANT` lets
//!   systemd deliver the stop signals to the agent and the watchdog until
//!   the window ends, so `systemctl stop`/`restart` works for the
//!   installer; outside a window it is refused.
//!
//! ## Invariants
//!
//! - **boot-zero.** The agent boot-zeroes `FS_GRANT` and rolls a fresh
//!   `AGENT_SESSION` nonce on every start (`super::boot_zero_fs_grant` +
//!   `super::arm_session`), and
//!   this struct constructs disarmed. A grant NEVER survives a restart;
//!   it must be re-presented. Even if the boot-zero map write is lost,
//!   the kernel's session-nonce compare rejects a stale pinned value.
//! - **TTL.** A grant carries an operator-chosen `window_secs`, clamped
//!   to [`MAX_TRUSTED_INSTALLER_WINDOW_SECS`]. The window expires at a
//!   real-time deadline (monotonic [`Instant`], NOT the event stream —
//!   a security grant must expire even on a silent host). The detection
//!   half flips back to `KillProcess` the instant
//!   [`Self::is_window_open`] is consulted past the deadline; the kernel
//!   half ends at the same deadline by itself (external audit ATP-003:
//!   the grant carries it, as `KILL_GRANT` does — before, the slot was
//!   zeroed only by an event-path sweep, and a host whose events had
//!   stopped kept the files, the pin root and the kexec refusal open).
//!   A one-second ticker closes the window on time and records it
//!   ([`Self::close_if_expired`]).
//! - **anti-replay.** The signed grant is verified through the standard
//!   `verify_signed_payload_quorum` path (single-use challenge nonce +
//!   `agent_id` binding + skew), so a captured grant cannot be replayed
//!   to re-arm; the per-boot session nonce makes a captured *map value*
//!   un-reusable across boots.
//!
//! ## Scope note (resolved in recon)
//!
//! The kernel `FS_GRANT` short-circuit is GLOBAL — while
//! armed, EVERY protected inode is writable, not just the agent's own
//! paths. That is the accepted beta posture (bounded by auth + a short
//! TTL + audit + the operator-driven window); per-path scoping of the
//! FS suspension is a V2 follow-up. The DETECTION downgrade, by
//! contrast, IS tightly path-scoped to the agent's own units in the
//! rule layer.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use aya::maps::{Array as AyaArray, Map as AyaMap, MapData};
use parking_lot::Mutex;
use tracing::{info, warn};

use super::{
    AyaFsGrant, AyaKillGrant, AGENT_SESSION_MAP_NAME, FS_GRANT_MAP_NAME, KILL_GRANT_MAP_NAME,
};
use crate::audit::{AuditEntryDraft, AuditLog};
use common::wire::{FsGrant, KillGrant};

/// Hard ceiling on a grant window. A grant whose `window_secs` exceeds
/// this is clamped down — a captured or fat-fingered grant can never
/// hold the FS pin open longer than this, and the operator lifecycle
/// (arm → install → `systemctl restart`) closes it far sooner in
/// practice. 10 minutes is generous for an in-place upgrade.
pub const MAX_TRUSTED_INSTALLER_WINDOW_SECS: u32 = 600;

/// The agent's OWN systemd unit paths — the ONLY units whose
/// `NN-L-FIM-009` verdict the override downgrades. A write to any other
/// unit path still trips `KillProcess` even inside an open window. These
/// are the canonical install locations (`deploy/install.sh` copies the
/// units to `/etc/systemd/system/`).
pub const OWN_SYSTEMD_UNITS: &[&str] = &[
    "/etc/systemd/system/northnarrow-agent.service",
    "/etc/systemd/system/northnarrow-watchdog.service",
    // Review 26: a distro package ships the units in the vendor
    // directory. On a merged-/usr host the FIM sensor may report that
    // directory through either spelling.
    "/usr/lib/systemd/system/northnarrow-agent.service",
    "/usr/lib/systemd/system/northnarrow-watchdog.service",
    "/lib/systemd/system/northnarrow-agent.service",
    "/lib/systemd/system/northnarrow-watchdog.service",
];

/// Userland state of the trusted-installer override. Shared via `Arc`
/// across the admin-socket dispatcher (arms it), the `NN-L-FIM-009` rule
/// (reads it), and the event-path sweep (lazily closes it on expiry).
///
/// The `armed` flag is a lock-free fast path: the per-event sweep and
/// the rule both gate on it with a single relaxed atomic load, taking
/// the `Mutex` only while a window is actually open (rare + short).
pub struct TrustedInstallerOverride {
    /// Fast-path gate. `true` between [`arm`](Self::arm) and the close
    /// that follows expiry. Lets the hot event path skip the mutex.
    armed: AtomicBool,
    inner: Mutex<Inner>,
    /// bpffs root for opening the pinned `FS_GRANT` map.
    /// `None` ⇒ no bpffs this boot ⇒ the kernel FS suspension is
    /// unavailable (the in-memory detection downgrade still works).
    bpffs_root: Option<PathBuf>,
    /// This boot's `AGENT_SESSION[0]` nonce. Written into `FS_GRANT[0]` on
    /// arm so the kernel compare matches.
    /// `0` ⇒ session unavailable ⇒ FS suspension stays dormant.
    session_nonce: u32,
    /// Chain-log writer for the close/expiry record. The ARM record is
    /// written by the admin-socket dispatch path (`emit_audit_for`); the
    /// close is agent-initiated (not an admin op), so it is logged here.
    /// Late-bound via [`Self::set_audit_log`] — the override is built
    /// early at boot (before the engine) but the audit log opens a little
    /// later. `None` ⇒ close is logged to tracing only.
    audit: Mutex<Option<Arc<Mutex<AuditLog>>>>,
    max_window: Duration,
}

#[derive(Default)]
struct Inner {
    /// Real-time deadline of the current window, or `None` when closed.
    deadline: Option<Instant>,
}

impl TrustedInstallerOverride {
    /// Construct with explicit dependencies. Production callers use
    /// [`Self::boot`]; tests use this directly with `bpffs_root: None`
    /// (the map writes become no-ops) and a small `max_window`.
    pub fn new(
        bpffs_root: Option<PathBuf>,
        session_nonce: u32,
        audit: Option<Arc<Mutex<AuditLog>>>,
        max_window: Duration,
    ) -> Self {
        Self {
            armed: AtomicBool::new(false),
            inner: Mutex::new(Inner::default()),
            bpffs_root,
            session_nonce,
            audit: Mutex::new(audit),
            max_window,
        }
    }

    /// Late-bind the audit-chain writer. main.rs constructs the override
    /// early (before the engine, so the NN-L-FIM-009 rule can hold it)
    /// then calls this once the audit log is opened, so close/expiry
    /// records are chained. A second call replaces the writer.
    pub fn set_audit_log(&self, audit: Arc<Mutex<AuditLog>>) {
        *self.audit.lock() = Some(audit);
    }

    /// An override that can never engage the FS pin (no bpffs, no session
    /// nonce) and starts disarmed. Used by the non-production rule paths
    /// (`default_rules`, unit tests) where no dispatcher exists to arm
    /// it — `NN-L-FIM-009` then behaves exactly as before.
    pub fn inert() -> Self {
        Self::new(
            None,
            0,
            None,
            Duration::from_secs(MAX_TRUSTED_INSTALLER_WINDOW_SECS as u64),
        )
    }

    /// `Arc`-wrapped [`Self::inert`].
    pub fn inert_arc() -> Arc<Self> {
        Arc::new(Self::inert())
    }

    /// Production constructor. Reads this boot's session nonce from the
    /// pinned `AGENT_SESSION` map and belt-and-suspenders boot-zeroes
    /// `FS_GRANT` (the kernel attach path also zeroes it; this
    /// guarantees the in-memory state and the map agree at construction).
    /// Constructs disarmed.
    pub fn boot(bpffs_root: Option<PathBuf>, audit: Option<Arc<Mutex<AuditLog>>>) -> Arc<Self> {
        let session_nonce = bpffs_root
            .as_deref()
            .and_then(read_session_nonce)
            .unwrap_or(0);
        if session_nonce == 0 {
            warn!(
                target: "anti_tamper.trusted_installer",
                "no AGENT_SESSION nonce readable — trusted-installer FS suspension will be \
                 DORMANT this boot (detection downgrade still available); session arming \
                 may have failed or bpffs is absent"
            );
        }
        // Belt-and-suspenders boot-zero of the in-mem-visible map.
        if let Err(e) = write_fs_grant(bpffs_root.as_deref(), FsGrant::default()) {
            warn!(
                target: "anti_tamper.trusted_installer",
                error = %e,
                "boot-zero of FS_GRANT from userland failed (kernel attach path also zeroes \
                 it; continuing)"
            );
        }
        Arc::new(Self::new(
            bpffs_root,
            session_nonce,
            audit,
            Duration::from_secs(MAX_TRUSTED_INSTALLER_WINDOW_SECS as u64),
        ))
    }

    /// Arm the override for `window_secs` (clamped to `[1, max]`) as of
    /// `now`. Writes the session nonce and the deadline into `FS_GRANT[0]`
    /// so the kernel FS pin is suspended until then, then opens the
    /// in-memory window.
    /// Returns the effective (clamped) window so the caller can log it.
    ///
    /// The ARM is recorded in the audit chain by the dispatch path
    /// (`emit_audit_for`), not here.
    pub fn arm(&self, window_secs: u32, now: Instant) -> Duration {
        let max = self.max_window.as_secs().min(u32::MAX as u64) as u32;
        let secs = window_secs.clamp(1, max.max(1));
        let window = Duration::from_secs(secs as u64);

        // Suspend the kernel FS pin (best-effort). A failure here does
        // NOT abort the grant: the in-memory window still opens so the
        // NN-L-FIM-009 detection downgrade engages (the part that stops
        // the agent killing the installer). A failed FS suspension is
        // self-evident at install time (install.sh EPERMs on a protected
        // path) and is logged loudly here.
        // One deadline for both kernel grants and the in-memory window.
        let expires_ns = monotonic_ns().saturating_add(window.as_nanos() as u64);
        let fs_pin_suspended = if self.session_nonce != 0 {
            let grant = FsGrant {
                nonce: self.session_nonce,
                _pad: 0,
                expires_ns,
            };
            match write_fs_grant(self.bpffs_root.as_deref(), grant) {
                Ok(()) => self.bpffs_root.is_some(),
                Err(e) => {
                    warn!(
                        target: "anti_tamper.trusted_installer",
                        error = %e,
                        "arming FS pin suspension failed — detection downgrade still active, \
                         but install.sh writes to PROTECTED inodes will still EPERM"
                    );
                    false
                }
            }
        } else {
            warn!(
                target: "anti_tamper.trusted_installer",
                "arming with no session nonce — FS pin NOT suspended; \
                 NN-L-FIM-009 detection downgrade only"
            );
            false
        };

        // External audit EBPF-001: for the same window, PID 1 may deliver
        // the stop signals to the agent and the watchdog — `systemctl
        // stop`/`restart` by install.sh, uninstall.sh or the operator.
        // Outside a window systemd's signals are refused like any root
        // shell's.
        let systemctl_stop_granted = if self.session_nonce != 0 {
            let grant = KillGrant {
                nonce: self.session_nonce,
                sig_mask: KillGrant::STOP_SIGNALS,
                expires_ns,
            };
            match write_kill_grant(self.bpffs_root.as_deref(), grant) {
                Ok(()) => self.bpffs_root.is_some(),
                Err(e) => {
                    warn!(
                        target: "anti_tamper.trusted_installer",
                        error = %e,
                        "arming the PID-1 stop grant failed — `systemctl stop` of the units \
                         stays refused in this window"
                    );
                    false
                }
            }
        } else {
            false
        };

        self.inner.lock().deadline = Some(now + window);
        self.armed.store(true, Ordering::SeqCst);
        info!(
            target: "anti_tamper.trusted_installer",
            window_secs = secs,
            requested_secs = window_secs,
            fs_pin_suspended,
            systemctl_stop_granted,
            "trusted-installer override ARMED (FIM-009 §15.1)"
        );
        window
    }

    /// Is the window open as of `now`? Pure read (an atomic load plus,
    /// when armed, a short mutex). The `NN-L-FIM-009` rule calls this
    /// via [`Self::is_window_open`].
    pub fn is_active_at(&self, now: Instant) -> bool {
        if !self.armed.load(Ordering::SeqCst) {
            return false;
        }
        match self.inner.lock().deadline {
            Some(deadline) => now < deadline,
            None => false,
        }
    }

    /// [`Self::is_active_at`] clocked at the real-time now. This is the
    /// rule-facing accessor: detection expires exactly at the deadline,
    /// independent of event flow.
    pub fn is_window_open(&self) -> bool {
        self.is_active_at(Instant::now())
    }

    /// Lazy expiry on the event path. If a window is open but `now` is
    /// at/after its deadline, close it (zero the kernel map + audit) and
    /// return `true`. Cheap no-op (single atomic load) when disarmed —
    /// safe to call on every event.
    pub fn close_if_expired(&self, now: Instant) -> bool {
        if !self.armed.load(Ordering::SeqCst) {
            return false;
        }
        let expired = match self.inner.lock().deadline {
            Some(deadline) => now >= deadline,
            None => true,
        };
        if expired {
            self.close("ttl_expired");
            true
        } else {
            false
        }
    }

    /// Close the window: clear the in-memory deadline, zero the kernel
    /// map (re-engage the FS pin), and append a close record to the
    /// audit chain. Idempotent — a second call is a cheap no-op.
    ///
    /// External audit ATP-012: a zeroing that failed, or that a read-back
    /// does not show, is recorded as such (`close_failed`), not as
    /// "closed"; the kernel's own deadline still ends the window.
    pub fn close(&self, reason: &str) {
        let was_armed = self.armed.swap(false, Ordering::SeqCst);
        self.inner.lock().deadline = None;
        let zeroed =
            write_fs_grant(self.bpffs_root.as_deref(), FsGrant::default()).and_then(|()| {
                match read_fs_grant(self.bpffs_root.as_deref()) {
                    Some(g) if g != FsGrant::default() => {
                        anyhow::bail!("FS_GRANT still holds a grant after zeroing")
                    }
                    _ => Ok(()),
                }
            });
        let close_failed = match &zeroed {
            Ok(()) => None,
            Err(e) => {
                tracing::error!(
                    target: "anti_tamper.trusted_installer",
                    error = %format!("{e:#}"),
                    "disarm of FS_GRANT failed — the FS pin stays suspended until the grant's \
                     own deadline"
                );
                Some(format!("{e:#}"))
            }
        };
        if let Err(e) = write_kill_grant(self.bpffs_root.as_deref(), KillGrant::default()) {
            warn!(
                target: "anti_tamper.trusted_installer",
                error = %e,
                "withdrawing the PID-1 stop grant failed — it still expires with the window"
            );
        }
        if was_armed {
            info!(
                target: "anti_tamper.trusted_installer",
                reason,
                close_failed = close_failed.is_some(),
                "trusted-installer override CLOSED (FIM-009 §15.1)"
            );
            self.audit_close(reason, close_failed.as_deref());
        }
    }

    fn audit_close(&self, reason: &str, close_failed: Option<&str>) {
        let audit = self.audit.lock().clone();
        let Some(audit) = audit else {
            return;
        };
        let (extra, result) = match close_failed {
            None => (
                serde_json::json!({ "reason": reason }),
                format!("closed: {reason}"),
            ),
            Some(error) => (
                serde_json::json!({ "reason": reason, "error": error }),
                format!("close_failed: {reason} (the kernel grant ends at its own deadline)"),
            ),
        };
        let draft = AuditEntryDraft {
            op: "trusted_installer_window_close".to_string(),
            extra,
            // Agent-initiated (TTL/forced), not an operator signature.
            key_fp: "(agent)".to_string(),
            cosigner_fps: Vec::new(),
            result,
            client_pid: std::process::id(),
            client_uid: 0,
            client_comm: "northnarrow-agent".to_string(),
        };
        let appended = audit.lock().append(draft);
        if let Err(e) = appended {
            warn!(
                target: "anti_tamper.trusted_installer",
                error = %e,
                "appending trusted-installer close record to audit chain failed"
            );
        }
    }
}

/// Write `grant` to slot 0 of the pinned `FS_GRANT` map (a zeroed grant
/// closes the window). `bpffs_root: None` ⇒ no-op success (no pinned map
/// this boot; the in-memory detection state still governs the
/// downgrade). Mirrors the `ProtectedObserversHandle::open` pinned-map
/// idiom.
fn write_fs_grant(bpffs_root: Option<&Path>, grant: FsGrant) -> Result<()> {
    let Some(root) = bpffs_root else {
        return Ok(());
    };
    let pin_path = root.join(FS_GRANT_MAP_NAME);
    let map_data = MapData::from_pin(&pin_path).with_context(|| {
        format!(
            "opening pinned {FS_GRANT_MAP_NAME} at {}",
            pin_path.display()
        )
    })?;
    let mut arr: AyaArray<_, AyaFsGrant> = AyaArray::try_from(AyaMap::Array(map_data))
        .with_context(|| format!("{FS_GRANT_MAP_NAME} is not an Array<FsGrant>"))?;
    arr.set(0, AyaFsGrant(grant), 0)
        .with_context(|| format!("setting {FS_GRANT_MAP_NAME}[0]"))?;
    Ok(())
}

/// External audit ATP-012: what `FS_GRANT[0]` holds now — the read-back
/// after a close. `None` without a bpffs or when the pin cannot be read.
fn read_fs_grant(bpffs_root: Option<&Path>) -> Option<FsGrant> {
    let pin_path = bpffs_root?.join(FS_GRANT_MAP_NAME);
    let map_data = MapData::from_pin(&pin_path).ok()?;
    let arr: AyaArray<_, AyaFsGrant> = AyaArray::try_from(AyaMap::Array(map_data)).ok()?;
    arr.get(&0, 0).ok().map(|g| g.0)
}

/// External audit EBPF-001: write the pinned `KILL_GRANT` slot (a zeroed
/// grant withdraws it). `bpffs_root: None` ⇒ no-op success.
fn write_kill_grant(bpffs_root: Option<&Path>, grant: KillGrant) -> Result<()> {
    let Some(root) = bpffs_root else {
        return Ok(());
    };
    let pin_path = root.join(KILL_GRANT_MAP_NAME);
    let map_data = MapData::from_pin(&pin_path).with_context(|| {
        format!(
            "opening pinned {KILL_GRANT_MAP_NAME} at {}",
            pin_path.display()
        )
    })?;
    let mut arr: AyaArray<_, AyaKillGrant> = AyaArray::try_from(AyaMap::Array(map_data))
        .with_context(|| format!("{KILL_GRANT_MAP_NAME} is not an Array<KillGrant>"))?;
    arr.set(0, AyaKillGrant(grant), 0)
        .with_context(|| format!("setting {KILL_GRANT_MAP_NAME}[0]"))?;
    Ok(())
}

/// CLOCK_MONOTONIC in nanoseconds — the clock of `bpf_ktime_get_ns`.
fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid out-pointer; CLOCK_MONOTONIC always exists.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}

/// Best-effort read of this boot's `AGENT_SESSION[0]` session nonce from
/// the pinned map. `None` on any failure (no pin, wrong shape) — the
/// caller treats `None`/`0` as "FS suspension dormant".
fn read_session_nonce(bpffs_root: &Path) -> Option<u32> {
    let pin_path = bpffs_root.join(AGENT_SESSION_MAP_NAME);
    let map_data = MapData::from_pin(&pin_path).ok()?;
    let arr: AyaArray<_, u32> = AyaArray::try_from(AyaMap::Array(map_data)).ok()?;
    arr.get(&0, 0).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test override with no bpffs (map writes are no-ops) and a tiny
    /// max window so clamp behaviour is observable.
    fn test_override(max_secs: u32) -> TrustedInstallerOverride {
        TrustedInstallerOverride::new(None, 0, None, Duration::from_secs(max_secs as u64))
    }

    #[test]
    fn starts_disarmed_boot_zero() {
        let ov = test_override(600);
        assert!(
            !ov.is_active_at(Instant::now()),
            "fresh override is disarmed"
        );
        // close on a disarmed override is a harmless no-op.
        ov.close("noop");
        assert!(!ov.is_active_at(Instant::now()));
    }

    #[test]
    fn arm_opens_window_until_deadline() {
        let ov = test_override(600);
        let t0 = Instant::now();
        let window = ov.arm(30, t0);
        assert_eq!(window, Duration::from_secs(30));
        // Active at t0 and just before the deadline.
        assert!(ov.is_active_at(t0));
        assert!(ov.is_active_at(t0 + Duration::from_secs(29)));
        // Inactive at/after the deadline — TTL expiry is real-time.
        assert!(!ov.is_active_at(t0 + Duration::from_secs(30)));
        assert!(!ov.is_active_at(t0 + Duration::from_secs(31)));
    }

    #[test]
    fn window_clamped_to_max() {
        let ov = test_override(60);
        // Request 99999s, max is 60s → clamped to 60.
        let window = ov.arm(99_999, Instant::now());
        assert_eq!(window, Duration::from_secs(60));
    }

    #[test]
    fn window_clamped_to_min_one_second() {
        let ov = test_override(600);
        // A zero-second request is clamped up to 1s (never an
        // instantly-stale, but technically-armed, window).
        let window = ov.arm(0, Instant::now());
        assert_eq!(window, Duration::from_secs(1));
    }

    /// External audit ATP-012: a close whose zeroing of the kernel grant
    /// failed is recorded as `close_failed`, not as "closed".
    #[test]
    fn close_with_unwritable_map_is_recorded_as_failed() {
        let dir = tempfile::TempDir::new().unwrap();
        let key = crate::audit::AgentSigningKey::load_or_bootstrap(&dir.path().join("k")).unwrap();
        let log = AuditLog::open(&dir.path().join("audit.log"), key, [1u8; 16]).unwrap();
        // a bpffs root without the FS_GRANT pin, and a session: every map
        // write fails
        let empty_root = dir.path().join("bpffs");
        std::fs::create_dir(&empty_root).unwrap();
        let ov = TrustedInstallerOverride::new(
            Some(empty_root),
            0xABCD,
            Some(Arc::new(Mutex::new(log))),
            Duration::from_secs(600),
        );
        ov.arm(30, Instant::now());
        ov.close("ttl_expired");
        let text = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
        let last: serde_json::Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
        assert_eq!(last["op"], "trusted_installer_window_close");
        assert!(
            last["result"].as_str().unwrap().starts_with("close_failed"),
            "{last}"
        );
        // and once: a second close finds nothing armed
        ov.close("ttl_expired");
        let n = std::fs::read_to_string(dir.path().join("audit.log"))
            .unwrap()
            .lines()
            .filter(|l| l.contains("trusted_installer_window_close"))
            .count();
        assert_eq!(n, 1);
    }

    #[test]
    fn close_if_expired_disarms_only_after_deadline() {
        let ov = test_override(600);
        let t0 = Instant::now();
        ov.arm(30, t0);

        // Before the deadline: not closed, still active.
        assert!(!ov.close_if_expired(t0 + Duration::from_secs(10)));
        assert!(ov.is_active_at(t0 + Duration::from_secs(11)));

        // At/after the deadline: closed exactly once, then disarmed.
        assert!(ov.close_if_expired(t0 + Duration::from_secs(30)));
        assert!(!ov.is_active_at(t0 + Duration::from_secs(30)));
        // Idempotent: a second sweep finds nothing to close.
        assert!(!ov.close_if_expired(t0 + Duration::from_secs(31)));
    }

    #[test]
    fn close_if_expired_noop_when_disarmed() {
        let ov = test_override(600);
        assert!(!ov.close_if_expired(Instant::now()));
    }

    #[test]
    fn re_arm_after_close_reopens_window() {
        let ov = test_override(600);
        let t0 = Instant::now();
        ov.arm(10, t0);
        ov.close("manual");
        assert!(!ov.is_active_at(t0 + Duration::from_secs(1)));
        // A fresh grant re-opens the window from a new origin.
        let t1 = t0 + Duration::from_secs(100);
        ov.arm(10, t1);
        assert!(ov.is_active_at(t1 + Duration::from_secs(5)));
        assert!(!ov.is_active_at(t1 + Duration::from_secs(10)));
    }

    #[test]
    fn inert_override_never_opens() {
        let ov = TrustedInstallerOverride::inert();
        // Even after an arm, an inert override has session_nonce 0 (FS
        // suspension dormant) but the in-memory window still opens —
        // inert is about the FS map, not the detection clock. The
        // detection downgrade is acceptable here because nothing wires a
        // dispatcher to inert overrides (default_rules / tests).
        assert!(!ov.is_active_at(Instant::now()), "inert starts disarmed");
    }
}
