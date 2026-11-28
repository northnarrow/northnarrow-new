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
//!   ([`Self::close_if_expired`]). Lab PR 243: the window reads the time
//!   through [`Clock`] (the host's by default; the golden replay of the
//!   posture gives it its own, [`TrustedInstallerOverride::with_clock`]).
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
//!
//! ## The window per process tree (lot 2.3a's minimal path)
//!
//! Lot 2.3a's minimal path, for the tests and the lab only; lot 2.3b
//! replaces it (the real admin handler, `nn-admin window-run`, the
//! admission policy, the leases, the controlled stop). The design:
//! `docs/design/ANTITAMPER_TRUST_MODEL.md`, "Trusted-installer window per
//! process tree", sections 1 and 5.
//!
//! - [`TrustedInstallerOverride::arm_tree`] writes the kernel half in the
//!   design's order: the members of the line (`TREE_MEMBERS`, the root
//!   flagged), a second read of every line process's tracer, seccomp mode
//!   and start, then the grant (`FS_GRANT_V2`: this boot's session, the
//!   next generation, a `CLOCK_BOOTTIME` deadline, the heartbeat). It is
//!   refused while any window is open (one window at a time: the
//!   host-wide one's handler asks [`TrustedInstallerOverride::legacy_arming`]
//!   first, under the same lock), while the kernel manifest names anything
//!   missing (`window_tree::manifest_missing`), and with no pin root.
//! - [`TrustedInstallerOverride::tree_tick`] (the one-second ticker)
//!   writes the heartbeat, and closes the window at its deadline, when the
//!   kernel closed it (`TREE_CLOSED` names its generation: the root's
//!   death or eviction) or when the root's pid no longer has its start.
//! - [`TrustedInstallerOverride::close_tree`] zeroes the grant first, then
//!   empties the members, then `TREE_CLOSED` (only once the grant is gone:
//!   a window the kernel closed never opens again for the span between).
//! - A tree window softens nothing in the agent:
//!   [`TrustedInstallerOverride::is_window_open`] stays false (lot 2.3b
//!   judges by who acted).
//! - Each grant, refusal and close appends to the audit log.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use aya::maps::{Array as AyaArray, Map as AyaMap, MapData};
use parking_lot::Mutex;
use tracing::{info, warn};

use super::{
    AGENT_SESSION_MAP_NAME, AyaFsGrant, AyaKillGrant, FS_GRANT_MAP_NAME, KILL_GRANT_MAP_NAME,
};
use crate::audit::{AuditEntryDraft, AuditLog};
use crate::posture::clock::{Clock, SystemClock};
use common::wire::{
    FS_GRANT_V2_MAP_NAME, FsGrant, FsGrantV2, InodeKey, KillGrant, TREE_CGROUP_FILES_MAP_NAME,
    TREE_MEMBER_ROOT, TREE_MEMBERS_MAP_NAME, TreeMember, WINDOW_MAX_NS,
};

// R08b (lab PR 251): the agent's own units and a window's grant are the
// window's vocabulary, which the rules moving to nn-core read (NN-L-FIM-009,
// NN-L-EVA-001's sanction): nn-core's `anti_tamper::trusted_installer`, cut
// verbatim, here under their names. R10 (lab PR 259): the window's hard
// ceiling too, which nn-admin clamps `--window-secs` to (it names no module
// of nn-linux).
pub use nn_core::anti_tamper::trusted_installer::{
    MAX_TRUSTED_INSTALLER_WINDOW_SECS, OWN_SYSTEMD_UNITS, WindowGrant, WindowGrantee,
};

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
    /// Lab PR 243: where the window reads the time — the host's clocks,
    /// or a replay's ([`Self::with_clock`]). The kernel grant's deadline
    /// is the kernel's monotonic clock, always.
    clock: Arc<dyn Clock>,
    /// Lot 273c (the review of #490): the reload asked when a window opens
    /// (systemd's copy of the units back to their files before the
    /// maintenance restarts one). Late-bound by the start.
    reloader: Mutex<Option<crate::systemd_reload::Reloader>>,
    /// Lot 273d: when the open window was armed (its close judges our
    /// units' drop-ins made since, `crate::own_dropins`).
    armed_at: Mutex<Option<std::time::SystemTime>>,
    /// The re-review of #497 (RR1): the protected-inode keys the passes
    /// over our drop-ins registered — this window's close and the
    /// integrity round (through [`Self::own_dropin_keys`]) share them, so
    /// one pass takes out a key another registered once its path no
    /// longer names it.
    own_dropin_keys: crate::own_dropins::Registered,
    /// Lot 2.3a's minimal path (lot 2.3b replaces it): one window at a
    /// time. Held by [`Self::arm_tree`] for its whole arming, and by the
    /// host-wide grant's handler across its arming
    /// ([`Self::legacy_arming`]), so two grants racing on two connections
    /// cannot both open a window.
    arming: Mutex<()>,
    /// Lot 2.3a: fast path of [`Self::tree_window_open`] and the ticker.
    tree_armed: AtomicBool,
    /// Lot 2.3a: the tree window's state (its grant, the generations).
    tree: Mutex<TreeState>,
}

#[derive(Default)]
struct Inner {
    /// Real-time deadline of the current window, or `None` when closed.
    deadline: Option<Instant>,
    /// Who opened the current window and until when (lab PR 225).
    grant: Option<WindowGrant>,
}

/// Lot 2.3a's minimal path (lot 2.3b replaces it): the tree window as the
/// agent armed it.
#[derive(Default)]
struct TreeState {
    /// The last generation handed out this boot (0: none yet). Raised when
    /// a grant writes its first member, so a generation whose members were
    /// written is never handed out again, even when that arming was
    /// refused after.
    last_generation: u64,
    /// The window open, `None` when closed.
    open: Option<TreeWindow>,
}

struct TreeWindow {
    /// The grant as written in `FS_GRANT_V2[0]` (the heartbeat moves).
    grant: FsGrantV2,
    /// A heartbeat that could not be written was reported (once per
    /// window: the kernel's grace ends the window 60 s after the last one).
    beat_failed: bool,
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
            clock: Arc::new(SystemClock),
            reloader: Mutex::new(None),
            armed_at: Mutex::new(None),
            own_dropin_keys: crate::own_dropins::Registered::default(),
            arming: Mutex::new(()),
            tree_armed: AtomicBool::new(false),
            tree: Mutex::new(TreeState::default()),
        }
    }

    /// Lot 273c: the reloader a window's opening asks (the start's).
    pub fn set_reloader(&self, reloader: crate::systemd_reload::Reloader) {
        *self.reloader.lock() = Some(reloader);
    }

    /// Lab PR 243: read the time from `clock` — the window's deadline and
    /// its wall-clock end (the golden replay of the posture). Production
    /// keeps the host's clocks.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
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
        self.arm_by(window_secs, now, "(no key id)")
    }

    /// [`Self::arm`] for the signed grant of the admin key `key_id` (its
    /// fingerprint): the window remembers who opened it, and until when
    /// ([`Self::grant_at`]).
    pub fn arm_by(&self, window_secs: u32, now: Instant, key_id: &str) -> Duration {
        self.arm_for(window_secs, now, key_id, None)
    }

    /// Lot 278: [`Self::arm_by`] for the installer `grantee` names (its pid
    /// and start, [`installer_of_requester`]): the window remembers it,
    /// with the time of the grant, and R009 records the root execs of that
    /// process's own tree from a home or `/tmp`, after the grant and while
    /// the window is open, at Low ([`WindowGrant::grantee`]). A grant
    /// replaces the previous one's grantee: one installer at a time.
    pub fn arm_for(
        &self,
        window_secs: u32,
        now: Instant,
        key_id: &str,
        grantee: Option<(u32, u64)>,
    ) -> Duration {
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

        // The deadline on the wall clock, from the monotonic one (`now` may
        // lie in the past: a test of an expired window).
        let deadline = now + window;
        let mono_now = self.clock.now();
        let wall_now = nn_evidence::time::from_system_time(self.clock.wall());
        let span = |d: Duration| nn_evidence::time::SignedDuration::try_from(d).unwrap_or_default();
        let wall = if deadline >= mono_now {
            wall_now + span(deadline - mono_now)
        } else {
            wall_now - span(mono_now - deadline)
        };
        {
            let mut inner = self.inner.lock();
            inner.deadline = Some(deadline);
            inner.grant = Some(WindowGrant {
                key_id: key_id.to_string(),
                expires_at: nn_evidence::time::format_secs(wall),
                grantee: grantee.map(|(pid, start_ticks)| WindowGrantee {
                    pid,
                    start_ticks,
                    granted_ns: monotonic_ns(),
                }),
            });
        }
        self.armed.store(true, Ordering::SeqCst);
        {
            let mut at = self.armed_at.lock();
            if at.is_none() {
                *at = Some(std::time::SystemTime::now());
            }
        }
        // Lot 273d (the review of #492): the host's harmful drop-ins, read
        // now — the status the grant's `nn-admin` reads next warns the
        // operator before a `daemon-reload` inside this window applies one.
        let harms = crate::host_dropins::harmful_here();
        if let Some(h) = crate::host_dropins::withholding(&harms) {
            warn!(drop_in = %h.detail(), "trusted-installer window opened with a harmful host drop-in on disk: {}", crate::host_dropins::WINDOW_WARNING);
        }
        crate::host_dropins::note_degradation(&harms);
        // Lot 273c (the review of #490): systemd's copy of the units back to
        // their files before the maintenance this window is for restarts
        // one — a refused `set-property` left its value there.
        if let Some(r) = self.reloader.lock().as_ref() {
            r.request(crate::systemd_reload::Reason::WindowOpened);
        }
        info!(
            target: "anti_tamper.trusted_installer",
            window_secs = secs,
            requested_secs = window_secs,
            fs_pin_suspended,
            systemctl_stop_granted,
            granted_to_pid = grantee.map(|(pid, _)| pid),
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
        self.is_active_at(self.clock.now())
    }

    /// The bpffs root its kernel maps are pinned under (`None`: no deny
    /// hook this boot) — the integrity round's write protection of our
    /// kept drop-ins opens the protected-inode map there (the re-review of
    /// #497, RR1).
    pub fn bpffs_root(&self) -> Option<&Path> {
        self.bpffs_root.as_deref()
    }

    /// The keys the passes over our drop-ins registered (the re-review of
    /// #497, RR1; the round's [`crate::own_dropins::Protector`] shares
    /// them with this window's close).
    pub fn own_dropin_keys(&self) -> &crate::own_dropins::Registered {
        &self.own_dropin_keys
    }

    /// Lab PR 225: the grant of the window open as of `now` — its key id
    /// and its deadline — or `None` when no window is open (never armed,
    /// closed, or past its deadline).
    pub fn grant_at(&self, now: Instant) -> Option<WindowGrant> {
        if !self.is_active_at(now) {
            return None;
        }
        self.inner.lock().grant.clone()
    }

    /// [`Self::grant_at`] clocked at the window's now (lab PR 243: its
    /// [`Clock`], the host's in production).
    pub fn current_grant(&self) -> Option<WindowGrant> {
        self.grant_at(self.clock.now())
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
    ///
    /// Lot 273b: a window that was open ends with the units' resource
    /// values registered again (`cgroup_guard::refresh_values`): a limit
    /// changed inside it is what PID 1 may write back afterwards.
    pub fn close(&self, reason: &str) {
        let was_armed = self.armed.swap(false, Ordering::SeqCst);
        {
            let mut inner = self.inner.lock();
            inner.deadline = None;
            inner.grant = None;
        }
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
            // Lot 273b: a resource limit changed inside the window stays —
            // its value is the one PID 1 may write back from now on.
            super::cgroup_guard::refresh_values(self.bpffs_root.as_deref());
            // Lot 273d (the review of #492): our units' drop-ins made
            // inside the window, judged; a harmful one quarantined, systemd
            // reloaded (rate-limited).
            let since = self
                .armed_at
                .lock()
                .take()
                .map(|t| t - std::time::Duration::from_secs(2))
                .unwrap_or(std::time::UNIX_EPOCH);
            let moved =
                own_dropins_at_close(since, self.bpffs_root.as_deref(), &self.own_dropin_keys);
            if moved.iter().any(|m| m.to.is_some()) {
                if let Some(r) = self.reloader.lock().as_ref() {
                    r.request(crate::systemd_reload::Reason::OwnDropinQuarantined);
                }
            }
            for m in &moved {
                warn!(target: "anti_tamper.trusted_installer", detail = %m.detail(), "a drop-in of our units made inside the window, harmful to them");
            }
            // Lot 273d (R1 of the external review of 04/11): a guarded
            // sysctl set harmful inside the window — `ftrace_enabled=0`
            // above all, whose NOPs outlive the window — is put back at
            // its close, not at the round's next pass.
            let sysctls = sysctls_at_close();
            for l in &sysctls {
                warn!(target: "anti_tamper.trusted_installer", detail = %l, "a guarded sysctl set inside the window");
            }
            info!(
                target: "anti_tamper.trusted_installer",
                reason,
                close_failed = close_failed.is_some(),
                "trusted-installer override CLOSED (FIM-009 §15.1)"
            );
            let lines: Vec<String> = moved
                .iter()
                .map(crate::own_dropins::Moved::detail)
                .collect();
            self.audit_close(reason, close_failed.as_deref(), &lines, &sysctls);
        }
    }

    fn audit_close(
        &self,
        reason: &str,
        close_failed: Option<&str>,
        quarantined: &[String],
        sysctls: &[String],
    ) {
        let audit = self.audit.lock().clone();
        let Some(audit) = audit else {
            return;
        };
        let (mut extra, result) = match close_failed {
            None => (
                serde_json::json!({ "reason": reason }),
                format!("closed: {reason}"),
            ),
            Some(error) => (
                serde_json::json!({ "reason": reason, "error": error }),
                format!("close_failed: {reason} (the kernel grant ends at its own deadline)"),
            ),
        };
        if !quarantined.is_empty() {
            extra["dropins_quarantined"] = serde_json::json!(quarantined);
        }
        if !sysctls.is_empty() {
            extra["sysctls"] = serde_json::json!(sysctls);
        }
        let mut log = audit.lock();
        let draft = AuditEntryDraft {
            op: "trusted_installer_window_close".to_string(),
            extra,
            // Agent-initiated (TTL/forced), not an operator signature.
            key_fp: "(agent)".to_string(),
            cosigner_fps: Vec::new(),
            result,
            // Lab PR 249: the log's own pid (the agent's; a replay's log
            // names the replayed agent).
            client_pid: log.self_pid(),
            client_uid: 0,
            client_comm: "northnarrow-agent".to_string(),
            client_exe: None,
        };
        let appended = log.append(draft);
        drop(log);
        if let Err(e) = appended {
            warn!(
                target: "anti_tamper.trusted_installer",
                error = %e,
                "appending trusted-installer close record to audit chain failed"
            );
        }
    }

    // ── Lot 2.3a's minimal path (lot 2.3b replaces it): the tree window ──

    /// Lot 2.3a's minimal path (lot 2.3b replaces it): one window at a
    /// time for the host-wide grant. Its handler takes this before it
    /// verifies and arms ([`Self::arm_for`]) and holds it until the arming
    /// is done: `Err` (the reason) while a tree window is open — the grant
    /// is then refused, not armed. [`Self::arm_tree`] takes the same lock,
    /// so the two cannot race.
    pub fn legacy_arming(&self) -> std::result::Result<parking_lot::MutexGuard<'_, ()>, String> {
        let permit = self.arming.lock();
        match self.tree.lock().open.as_ref() {
            Some(w) => Err(format!(
                "a trusted-installer window per process tree is open (generation {}, root \
                 {}): one window at a time",
                w.grant.generation, w.grant.root_tgid
            )),
            None => Ok(permit),
        }
    }

    /// Lot 2.3a: whether a tree window is open (armed by [`Self::arm_tree`],
    /// not yet closed by [`Self::close_tree`] or [`Self::tree_tick`]). It
    /// softens nothing: [`Self::is_window_open`] stays false meanwhile.
    pub fn tree_window_open(&self) -> bool {
        self.tree_armed.load(Ordering::SeqCst)
    }

    /// Lot 2.3a: the open tree window's generation (`None`: none open).
    pub fn tree_generation(&self) -> Option<u64> {
        self.tree.lock().open.as_ref().map(|w| w.grant.generation)
    }

    /// The agent's own processes, never on a tree's line: this process and
    /// the roles the kernel's `ROLE_TGIDS` names (the agent, the watchdog).
    /// `Err` when the pin root is there and the roles cannot be read: the
    /// grant is then refused, never judged without them (with no pin root
    /// no tree window opens anyway).
    pub fn own_tgids(&self) -> std::result::Result<Vec<u32>, String> {
        let mut own = vec![std::process::id()];
        if let Some(root) = self.bpffs_root.as_deref() {
            own.extend(read_role_tgids(root)?.into_iter().filter(|p| *p != 0));
        }
        Ok(own)
    }

    /// Lot 2.3a's minimal path (lot 2.3b replaces it): arm the window for
    /// the tree of `root` (`(pid, start_ticks)`), whose `line` (root first,
    /// down to the requester: [`line_to_root`]) becomes its first members,
    /// for `window_secs` (clamped to `[1, max]`, the max never above 600 s).
    /// `Ok` the window's generation; `Err` why it was refused (logged and
    /// recorded; nothing of it is left in the kernel's maps).
    pub fn arm_tree(
        &self,
        window_secs: u32,
        root: (u32, u64),
        line: &[(u32, u64)],
    ) -> std::result::Result<u64, String> {
        let mut pinned = self.bpffs_root.as_deref().map(PinnedTreeMaps);
        self.arm_tree_with(
            pinned.as_mut().map(|m| m as &mut dyn TreeMaps),
            &ProcFs(Path::new("/proc")),
            &super::window_tree::manifest_missing(self.bpffs_root.as_deref()),
            boottime_ns(),
            window_secs,
            root,
            line,
        )
    }

    /// Lot 2.3a: a tree grant refused before [`Self::arm_tree`] (the walk
    /// of its line, [`line_to_root`]): logged and recorded, as the arming's
    /// own refusals.
    pub fn note_tree_refusal(&self, why: &str) {
        warn!(
            target: "anti_tamper.trusted_installer",
            reason = why,
            "trusted-installer window per process tree REFUSED"
        );
        self.audit_tree(
            "trusted_installer_tree_grant_refused",
            serde_json::json!({ "reason": why }),
            format!("refused: {why}"),
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn arm_tree_with(
        &self,
        maps: Option<&mut dyn TreeMaps>,
        reader: &dyn LineReader,
        missing: &[String],
        now_boot_ns: u64,
        window_secs: u32,
        root: (u32, u64),
        line: &[(u32, u64)],
    ) -> std::result::Result<u64, String> {
        let one_window = self.arming.lock();
        let armed =
            self.arm_tree_locked(maps, reader, missing, now_boot_ns, window_secs, root, line);
        drop(one_window);
        match &armed {
            Ok(g) => {
                info!(
                    target: "anti_tamper.trusted_installer",
                    generation = g.generation,
                    root_pid = g.root_tgid,
                    members = line.len(),
                    "trusted-installer window per process tree ARMED"
                );
                self.audit_tree(
                    "trusted_installer_tree_window_open",
                    serde_json::json!({
                        "generation": g.generation,
                        "root_pid": g.root_tgid,
                        "root_start_ticks": g.root_start_ticks,
                        "members": line.iter().map(|(pid, _)| *pid).collect::<Vec<u32>>(),
                        "expires_boot_ns": g.expires_boot_ns,
                    }),
                    format!("opened: generation {}", g.generation),
                );
            }
            Err(why) => self.note_tree_refusal(why),
        }
        armed.map(|g| g.generation)
    }

    /// [`Self::arm_tree_with`] under the one-window lock: the refusals, then
    /// the design's order (members, the second read, the grant).
    #[allow(clippy::too_many_arguments)]
    fn arm_tree_locked(
        &self,
        maps: Option<&mut dyn TreeMaps>,
        reader: &dyn LineReader,
        missing: &[String],
        now_boot_ns: u64,
        window_secs: u32,
        root: (u32, u64),
        line: &[(u32, u64)],
    ) -> std::result::Result<FsGrantV2, String> {
        if self.is_window_open() {
            return Err(
                "the host-wide trusted-installer window is open: one window at a time".to_string(),
            );
        }
        let mut tree = self.tree.lock();
        if let Some(w) = tree.open.as_ref() {
            return Err(format!(
                "a trusted-installer window per process tree is open (generation {}): one \
                 window at a time",
                w.grant.generation
            ));
        }
        if !missing.is_empty() {
            return Err(format!(
                "window_tree_unavailable: {} (never a host-wide window instead)",
                missing.join("; ")
            ));
        }
        let Some(maps) = maps else {
            return Err("no bpffs pin root this boot: no tree window".to_string());
        };
        if self.session_nonce == 0 {
            return Err("no session nonce this boot: no tree window".to_string());
        }
        if line.first() != Some(&root) {
            return Err("the line does not begin at the signed root".to_string());
        }
        if line.len() > MAX_TREE_LINE
            || (1..line.len()).any(|i| line[..i].iter().any(|(p, _)| *p == line[i].0))
        {
            return Err(
                "the line is longer than the walk allows, or names a pid twice".to_string(),
            );
        }
        let generation = tree
            .last_generation
            .checked_add(1)
            .ok_or_else(|| "no generation left this boot".to_string())?;
        // spent from here on: never handed out again this boot
        tree.last_generation = generation;
        // 1. the members of the line, the root flagged
        for &(pid, start_ticks) in line {
            let member = TreeMember {
                start_ticks,
                generation,
                flags: if (pid, start_ticks) == root {
                    TREE_MEMBER_ROOT
                } else {
                    0
                },
                _pad: 0,
            };
            if let Err(e) = maps.put_member(pid, member) {
                return Err(withdrawn(
                    maps,
                    format!("member {pid} not written to {TREE_MEMBERS_MAP_NAME}: {e}"),
                ));
            }
        }
        // 1b. (lot 2.3a, D7) the root's cgroup files: an outsider's
        // `cgroup.kill` / `cgroup.freeze` of the members' cgroup refused
        let files = match reader.cgroup_files(root.0) {
            Ok(f) => f,
            Err(e) => return Err(withdrawn(maps, format!("the root's cgroup files: {e}"))),
        };
        for (key, op) in files {
            if let Err(e) = maps.put_cgroup_file(key, [generation, u64::from(op)]) {
                return Err(withdrawn(
                    maps,
                    format!(
                        "cgroup file {}:{} not written to {TREE_CGROUP_FILES_MAP_NAME}: {e}",
                        key.dev, key.ino
                    ),
                ));
            }
        }
        // 2. the second read: a tracer, a filter or another process found
        // now clears the members, and the grant is refused
        for &(pid, start_ticks) in line {
            let why = match (reader.hop(pid), reader.guards(pid)) {
                (Ok(hop), _) if hop.start_ticks != start_ticks => Some(format!(
                    "process {pid}'s start is {} now, {start_ticks} at the walk (another \
                     process)",
                    hop.start_ticks
                )),
                (Ok(_), Ok((0, 0))) => None,
                (Ok(_), Ok((tracer, seccomp))) => Some(format!(
                    "process {pid} is traced (TracerPid {tracer}) or filtered (Seccomp \
                     {seccomp}) at the second read"
                )),
                (Err(e), _) | (_, Err(e)) => Some(format!("process {pid} at the second read: {e}")),
            };
            if let Some(why) = why {
                return Err(withdrawn(maps, why));
            }
        }
        // 3. the grant
        let max_secs = self
            .max_window
            .as_secs()
            .clamp(1, WINDOW_MAX_NS / 1_000_000_000);
        let secs = u64::from(window_secs).clamp(1, max_secs);
        let grant = FsGrantV2 {
            nonce: self.session_nonce,
            root_tgid: root.0,
            generation,
            expires_boot_ns: now_boot_ns.saturating_add(secs.saturating_mul(1_000_000_000)),
            root_start_ticks: root.1,
            heartbeat_boot_ns: now_boot_ns,
            first_grant_boot_ns: now_boot_ns,
        };
        if let Err(e) = maps.write_grant(grant) {
            let _ = maps.write_grant(FsGrantV2::default());
            return Err(withdrawn(
                maps,
                format!("{FS_GRANT_V2_MAP_NAME} not written: {e}"),
            ));
        }
        tree.open = Some(TreeWindow {
            grant,
            beat_failed: false,
        });
        self.tree_armed.store(true, Ordering::SeqCst);
        Ok(grant)
    }

    /// Lot 2.3a's minimal path (lot 2.3b replaces it), the one-second
    /// ticker's (`now_boot_ns`: `CLOCK_BOOTTIME`, [`boottime_ns`]): the open
    /// tree window's heartbeat, or its close — at its deadline, when the
    /// kernel closed it (`TREE_CLOSED`: its root died or left the tree), or
    /// when the root's pid no longer has the root's start. A cheap no-op
    /// (one atomic load) while no tree window is open.
    pub fn tree_tick(&self, now_boot_ns: u64) {
        if !self.tree_armed.load(Ordering::SeqCst) {
            return;
        }
        let Some(root) = self.bpffs_root.as_deref() else {
            return;
        };
        self.tree_tick_with(
            &mut PinnedTreeMaps(root),
            &ProcFs(Path::new("/proc")),
            now_boot_ns,
        );
    }

    /// [`Self::tree_tick`] on `maps` and `reader`: the close's reason, when
    /// it closed the window.
    fn tree_tick_with(
        &self,
        maps: &mut dyn TreeMaps,
        reader: &dyn LineReader,
        now_boot_ns: u64,
    ) -> Option<&'static str> {
        if !self.tree_armed.load(Ordering::SeqCst) {
            return None;
        }
        let mut tree = self.tree.lock();
        let g = tree.open.as_ref()?.grant;
        let reason = if now_boot_ns >= g.expires_boot_ns {
            Some("ttl_expired")
        } else if maps
            .read_closed()
            .is_ok_and(|c| common::window_tree::window_closed(&c, g.nonce, g.generation))
        {
            Some("closed_by_kernel")
        } else if reader.hop(g.root_tgid).map(|h| h.start_ticks) != Ok(g.root_start_ticks) {
            Some("root_exited")
        } else {
            None
        };
        if let Some(reason) = reason {
            let closed = close_tree_locked(&mut tree, &self.tree_armed, maps);
            drop(tree);
            if let Some(c) = closed {
                self.audit_tree_close(reason, &c);
            }
            return Some(reason);
        }
        let beat = FsGrantV2 {
            heartbeat_boot_ns: now_boot_ns.max(g.heartbeat_boot_ns),
            ..g
        };
        let written = maps.write_grant(beat);
        if let Some(w) = tree.open.as_mut() {
            match written {
                Ok(()) => {
                    w.grant = beat;
                    w.beat_failed = false;
                }
                Err(e) if !w.beat_failed => {
                    w.beat_failed = true;
                    warn!(
                        target: "anti_tamper.trusted_installer",
                        error = %e,
                        generation = g.generation,
                        "tree window: heartbeat not written — the kernel ends the window 60 s \
                         after the last one"
                    );
                }
                Err(_) => {}
            }
        }
        None
    }

    /// Lot 2.3a's minimal path (lot 2.3b replaces it): close the open tree
    /// window (`reason` in its record): the grant zeroed first, then the
    /// members emptied, then `TREE_CLOSED` (only once the grant is gone).
    /// `false` when none was open.
    pub fn close_tree(&self, reason: &str) -> bool {
        let Some(root) = self.bpffs_root.as_deref() else {
            return false;
        };
        self.close_tree_with(&mut PinnedTreeMaps(root), reason)
    }

    fn close_tree_with(&self, maps: &mut dyn TreeMaps, reason: &str) -> bool {
        let mut tree = self.tree.lock();
        let closed = close_tree_locked(&mut tree, &self.tree_armed, maps);
        drop(tree);
        match closed {
            Some(c) => {
                self.audit_tree_close(reason, &c);
                true
            }
            None => false,
        }
    }

    fn audit_tree_close(&self, reason: &str, c: &TreeClosed) {
        let result = if c.failed.is_empty() {
            info!(
                target: "anti_tamper.trusted_installer",
                reason,
                generation = c.grant.generation,
                "trusted-installer window per process tree CLOSED"
            );
            format!("closed: {reason}")
        } else {
            tracing::error!(
                target: "anti_tamper.trusted_installer",
                reason,
                generation = c.grant.generation,
                failed = %c.failed.join("; "),
                "tree window close FAILED in part — the kernel's grace or deadline ends it"
            );
            format!("close_failed: {reason} (the kernel grant ends at its grace or deadline)")
        };
        self.audit_tree(
            "trusted_installer_tree_window_close",
            serde_json::json!({
                "reason": reason,
                "generation": c.grant.generation,
                "root_pid": c.grant.root_tgid,
                "root_start_ticks": c.grant.root_start_ticks,
                "members_cleared": c.members_cleared,
                "errors": c.failed,
            }),
            result,
        );
    }

    /// One record of the tree window (the agent's, as the host-wide
    /// window's close).
    fn audit_tree(&self, op: &str, extra: serde_json::Value, result: String) {
        let audit = self.audit.lock().clone();
        let Some(audit) = audit else {
            return;
        };
        let mut log = audit.lock();
        let draft = AuditEntryDraft {
            op: op.to_string(),
            extra,
            key_fp: "(agent)".to_string(),
            cosigner_fps: Vec::new(),
            result,
            client_pid: log.self_pid(),
            client_uid: 0,
            client_comm: "northnarrow-agent".to_string(),
            client_exe: None,
        };
        let appended = log.append(draft);
        drop(log);
        if let Err(e) = appended {
            warn!(
                target: "anti_tamper.trusted_installer",
                error = %e,
                op,
                "appending a tree window record to the audit chain failed"
            );
        }
    }
}

// ── Lot 2.3a's minimal path (lot 2.3b replaces it): the tree's kernel half ─

/// How many processes the walk from the requester up to the signed root
/// reads at most (the root included).
pub const MAX_TREE_LINE: usize = 32;

/// `PF_KTHREAD`, in `/proc/<pid>/stat`'s `flags` (field 9).
const PF_KTHREAD: u64 = 0x0020_0000;

/// What the walk reads of one process (`/proc/<pid>/stat`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcHop {
    /// Its parent (field 4).
    pub ppid: u32,
    /// Its start (field 22, `wire::start_ticks`).
    pub start_ticks: u64,
    /// A kernel thread (`PF_KTHREAD` in field 9).
    pub kthread: bool,
}

/// Lot 2.3a: where the walk and the arming read a process — `/proc`
/// ([`ProcFs`]), or a test's fake.
pub trait LineReader {
    /// Its parent, start and kind (`stat`).
    fn hop(&self, pid: u32) -> std::result::Result<ProcHop, String>;
    /// Its tracer and seccomp mode (`status`: `TracerPid`, `Seccomp`).
    fn guards(&self, pid: u32) -> std::result::Result<(u32, u32), String>;
    /// Lot 2.3a (D7, the review of #647): the `cgroup.kill` and
    /// `cgroup.freeze` of its cgroup of the unified hierarchy and of every
    /// cgroup above it but the root ([`cgroup_file_plan`]), by inode, each
    /// with its operation (`FS_OP_CGROUP_KILL`, `FS_OP_CGROUP_FREEZE`); a
    /// file this kernel does not have is skipped; its `cgroup` file not
    /// read is an error (the grant refused: fail closed).
    fn cgroup_files(&self, _pid: u32) -> std::result::Result<Vec<(InodeKey, u8)>, String> {
        Ok(Vec::new())
    }
}

/// Lot 2.3a (D7, the review of #647): the files of `cgroup` (a path of the
/// unified hierarchy, `/proc/<pid>/cgroup`'s `0::` line) and of every
/// cgroup above it under `root` (`/sys/fs/cgroup`, its own root excluded:
/// it has neither file) through which a member is killed or frozen with
/// its cgroup, each with the operation its refusal is signed as.
pub fn cgroup_file_plan(root: &Path, cgroup: &str) -> Vec<(PathBuf, u8)> {
    let mut out = Vec::new();
    let mut cur = Path::new(cgroup.trim().trim_start_matches('/'));
    loop {
        if cur.as_os_str().is_empty() {
            break;
        }
        let dir = root.join(cur);
        out.push((dir.join("cgroup.kill"), common::wire::FS_OP_CGROUP_KILL));
        out.push((dir.join("cgroup.freeze"), common::wire::FS_OP_CGROUP_FREEZE));
        match cur.parent() {
            Some(p) => cur = p,
            None => break,
        }
    }
    out
}

/// `/proc/<pid>/cgroup`'s path in the unified hierarchy (its `0::` line).
fn unified_cgroup(text: &str) -> Option<&str> {
    text.lines().find_map(|l| l.strip_prefix("0::"))
}

/// The [`LineReader`] of a `/proc` (the kernel's: `Path::new("/proc")`).
pub struct ProcFs<'a>(pub &'a Path);

impl LineReader for ProcFs<'_> {
    fn hop(&self, pid: u32) -> std::result::Result<ProcHop, String> {
        let stat = crate::state_read::read_state(self.0.join(pid.to_string()).join("stat"))
            .map_err(|e| format!("/proc/{pid}/stat: {e}"))?;
        parse_hop(&stat).ok_or_else(|| format!("/proc/{pid}/stat: not understood"))
    }

    fn guards(&self, pid: u32) -> std::result::Result<(u32, u32), String> {
        let status = crate::state_read::read_state(self.0.join(pid.to_string()).join("status"))
            .map_err(|e| format!("/proc/{pid}/status: {e}"))?;
        parse_guards(&status).ok_or_else(|| format!("/proc/{pid}/status: no TracerPid or Seccomp"))
    }

    fn cgroup_files(&self, pid: u32) -> std::result::Result<Vec<(InodeKey, u8)>, String> {
        let text = crate::state_read::read_state(self.0.join(pid.to_string()).join("cgroup"))
            .map_err(|e| format!("/proc/{pid}/cgroup: {e}"))?;
        // no unified hierarchy: no cgroup.kill nor cgroup.freeze to guard
        let Some(cg) = unified_cgroup(&text) else {
            return Ok(Vec::new());
        };
        Ok(cgroup_file_plan(Path::new("/sys/fs/cgroup"), cg)
            .into_iter()
            .filter_map(|(p, op)| {
                let m = antitamper_bpf::kernel_roots::metadata(&p).ok()?;
                Some((
                    InodeKey {
                        dev: super::filesystem::stat_dev_to_kernel_dev(
                            std::os::unix::fs::MetadataExt::dev(&m),
                        ),
                        ino: std::os::unix::fs::MetadataExt::ino(&m),
                    },
                    op,
                ))
            })
            .collect())
    }
}

/// `/proc/<pid>/stat`'s parent, start and kernel-thread flag, counted after
/// the `(comm)` field (which may hold spaces or parentheses).
fn parse_hop(stat: &str) -> Option<ProcHop> {
    let rest: Vec<&str> = stat.rsplit_once(')')?.1.split_whitespace().collect();
    Some(ProcHop {
        ppid: rest.get(1)?.parse().ok()?,
        start_ticks: rest.get(19)?.parse().ok()?,
        kthread: rest.get(6)?.parse::<u64>().ok()? & PF_KTHREAD != 0,
    })
}

/// `/proc/<pid>/status`'s `TracerPid` and `Seccomp` (a kernel without
/// seccomp has no such line: not understood, the stricter side).
fn parse_guards(status: &str) -> Option<(u32, u32)> {
    let field = |name: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .and_then(|v| v.trim().parse::<u32>().ok())
    };
    Some((field("TracerPid:")?, field("Seccomp:")?))
}

/// Lot 2.3a's minimal path (lot 2.3b replaces it with pidfds and the
/// admission policy): the line from the requester (`SO_PEERCRED` pid) up
/// through its parents to the signed `root` (`(pid, start_ticks)`), root
/// first, each with its start. Refused (`Err`, why): a root that is PID 1
/// or 0, not on the line within [`MAX_TREE_LINE`] processes, or whose
/// start differs from the signed one (another process took its pid); a
/// line that holds a kernel thread, a traced or seccomp-filtered process,
/// or one of the agent's own (`own`: [`TrustedInstallerOverride::own_tgids`]);
/// a root whose parent is one of the agent's own (its worker); any
/// process on it that cannot be read.
pub fn line_to_root(
    reader: &dyn LineReader,
    requester: u32,
    root: (u32, u64),
    own: &[u32],
) -> std::result::Result<Vec<(u32, u64)>, String> {
    let (root_pid, root_start) = root;
    if root_pid <= 1 {
        return Err(format!(
            "root {root_pid}: PID 1 (or 0) is never a window's root"
        ));
    }
    if requester <= 1 {
        return Err(format!(
            "requester {requester}: PID 1 (or 0) asks for no window"
        ));
    }
    let mut line = Vec::new();
    let mut pid = requester;
    for _ in 0..MAX_TREE_LINE {
        let hop = reader.hop(pid)?;
        if hop.kthread {
            return Err(format!("process {pid} on the line is a kernel thread"));
        }
        if own.contains(&pid) {
            return Err(format!(
                "process {pid} on the line is the agent's or the watchdog's"
            ));
        }
        match reader.guards(pid)? {
            (0, 0) => {}
            (tracer, seccomp) => {
                return Err(format!(
                    "process {pid} on the line is traced (TracerPid {tracer}) or filtered \
                     (Seccomp {seccomp})"
                ));
            }
        }
        line.push((pid, hop.start_ticks));
        if pid == root_pid {
            if hop.start_ticks != root_start {
                return Err(format!(
                    "root {root_pid}: its start is {}, the signed one {root_start} (another \
                     process)",
                    hop.start_ticks
                ));
            }
            if own.contains(&hop.ppid) {
                return Err(format!(
                    "root {root_pid} is a child of the agent's own process {}",
                    hop.ppid
                ));
            }
            line.reverse();
            return Ok(line);
        }
        if hop.ppid <= 1 || hop.ppid == pid {
            return Err(format!(
                "root {root_pid} is not on the requester {requester}'s line (it reaches {pid}, \
                 whose parent is {})",
                hop.ppid
            ));
        }
        pid = hop.ppid;
    }
    Err(format!(
        "root {root_pid} is not within {MAX_TREE_LINE} processes above the requester {requester}"
    ))
}

/// What a close did: the grant it ended, the members it took out, the
/// writes that failed.
struct TreeClosed {
    grant: FsGrantV2,
    members_cleared: usize,
    failed: Vec<String>,
}

/// Close the open window of `tree` on `maps`, under the caller's lock: the
/// grant zeroed first (no more lift, no new member), the members emptied,
/// then `TREE_CLOSED` — only once the grant is gone, so a window the kernel
/// closed is never open again in between. `None`: no window was open.
fn close_tree_locked(
    tree: &mut TreeState,
    armed: &AtomicBool,
    maps: &mut dyn TreeMaps,
) -> Option<TreeClosed> {
    let w = tree.open.take()?;
    armed.store(false, Ordering::SeqCst);
    let mut failed = Vec::new();
    let grant_gone = match maps.write_grant(FsGrantV2::default()) {
        Ok(()) => true,
        Err(e) => {
            failed.push(format!("{FS_GRANT_V2_MAP_NAME} not zeroed: {e}"));
            false
        }
    };
    let members_cleared = match maps.clear_members() {
        Ok(n) => n,
        Err(e) => {
            failed.push(format!("{TREE_MEMBERS_MAP_NAME} not emptied: {e}"));
            0
        }
    };
    if grant_gone {
        if let Err(e) = maps.zero_closed() {
            failed.push(format!(
                "{} not emptied: {e}",
                super::window_tree::TREE_CLOSED_MAP_NAME
            ));
        }
    }
    Some(TreeClosed {
        grant: w.grant,
        members_cleared,
        failed,
    })
}

/// A refused arming's members taken out again; `why`, with what could not
/// be taken out.
fn withdrawn(maps: &mut dyn TreeMaps, why: String) -> String {
    match maps.clear_members() {
        Ok(_) => why,
        Err(e) => format!("{why} (and {TREE_MEMBERS_MAP_NAME} not emptied: {e})"),
    }
}

/// Lot 2.3a: the tree window's kernel maps as the agent writes them — the
/// pins ([`PinnedTreeMaps`]), or a test's fake.
trait TreeMaps {
    /// `TREE_MEMBERS[tgid] = member`.
    fn put_member(&mut self, tgid: u32, member: TreeMember) -> std::result::Result<(), String>;
    /// Every entry of `TREE_MEMBERS` removed; how many.
    fn clear_members(&mut self) -> std::result::Result<usize, String>;
    /// `FS_GRANT_V2[0] = grant`.
    fn write_grant(&mut self, grant: FsGrantV2) -> std::result::Result<(), String>;
    /// `TREE_CLOSED[0]`.
    fn read_closed(&mut self) -> std::result::Result<[u64; 2], String>;
    /// `TREE_CLOSED[0] = [0, 0]`.
    fn zero_closed(&mut self) -> std::result::Result<(), String>;
    /// Lot 2.3a (D7): `TREE_CGROUP_FILES[key] = value` (`[generation,
    /// operation]`). Emptied with the members ([`Self::clear_members`]).
    fn put_cgroup_file(
        &mut self,
        _key: InodeKey,
        _value: [u64; 2],
    ) -> std::result::Result<(), String> {
        Ok(())
    }
}

/// The pinned maps under the pin root.
struct PinnedTreeMaps<'a>(&'a Path);

impl PinnedTreeMaps<'_> {
    fn open(&self, name: &str) -> std::result::Result<MapData, String> {
        MapData::from_pin(self.0.join(name)).map_err(|e| format!("opening pinned {name}: {e}"))
    }

    fn members(&self) -> std::result::Result<aya::maps::HashMap<MapData, u32, PodMember>, String> {
        aya::maps::HashMap::try_from(AyaMap::HashMap(self.open(TREE_MEMBERS_MAP_NAME)?))
            .map_err(|e| e.to_string())
    }

    fn closed(&self) -> std::result::Result<AyaArray<MapData, [u64; 2]>, String> {
        let name = super::window_tree::TREE_CLOSED_MAP_NAME;
        AyaArray::try_from(AyaMap::Array(self.open(name)?)).map_err(|e| e.to_string())
    }
}

impl TreeMaps for PinnedTreeMaps<'_> {
    fn put_member(&mut self, tgid: u32, member: TreeMember) -> std::result::Result<(), String> {
        self.members()?
            .insert(&tgid, &PodMember(member), 0)
            .map_err(|e| e.to_string())
    }

    fn clear_members(&mut self) -> std::result::Result<usize, String> {
        let mut h = self.members()?;
        let keys: Vec<u32> = h.keys().filter_map(std::result::Result::ok).collect();
        for k in &keys {
            h.remove(k).map_err(|e| e.to_string())?;
        }
        // lot 2.3a (D7): and the root's cgroup files
        let mut c: aya::maps::HashMap<MapData, super::filesystem::AyaInodeKey, [u64; 2]> =
            aya::maps::HashMap::try_from(AyaMap::HashMap(self.open(TREE_CGROUP_FILES_MAP_NAME)?))
                .map_err(|e| e.to_string())?;
        let files: Vec<super::filesystem::AyaInodeKey> =
            c.keys().filter_map(std::result::Result::ok).collect();
        for k in &files {
            c.remove(k).map_err(|e| e.to_string())?;
        }
        Ok(keys.len())
    }

    fn put_cgroup_file(
        &mut self,
        key: InodeKey,
        value: [u64; 2],
    ) -> std::result::Result<(), String> {
        let mut c: aya::maps::HashMap<MapData, super::filesystem::AyaInodeKey, [u64; 2]> =
            aya::maps::HashMap::try_from(AyaMap::HashMap(self.open(TREE_CGROUP_FILES_MAP_NAME)?))
                .map_err(|e| e.to_string())?;
        c.insert(&super::filesystem::AyaInodeKey(key), &value, 0)
            .map_err(|e| e.to_string())
    }

    fn write_grant(&mut self, grant: FsGrantV2) -> std::result::Result<(), String> {
        let mut a: AyaArray<MapData, PodGrantV2> =
            AyaArray::try_from(AyaMap::Array(self.open(FS_GRANT_V2_MAP_NAME)?))
                .map_err(|e| e.to_string())?;
        a.set(0, &PodGrantV2(grant), 0).map_err(|e| e.to_string())
    }

    fn read_closed(&mut self) -> std::result::Result<[u64; 2], String> {
        self.closed()?.get(&0, 0).map_err(|e| e.to_string())
    }

    fn zero_closed(&mut self) -> std::result::Result<(), String> {
        self.closed()?
            .set(0, &[0u64; 2], 0)
            .map_err(|e| e.to_string())
    }
}

#[derive(Clone, Copy)]
#[repr(transparent)]
struct PodGrantV2(FsGrantV2);
// SAFETY: `FsGrantV2` is `repr(C)`, `bytemuck::Pod` (no padding, every bit
// pattern valid); the wrapper is `repr(transparent)`.
unsafe impl aya::Pod for PodGrantV2 {}

#[derive(Clone, Copy)]
#[repr(transparent)]
struct PodMember(TreeMember);
// SAFETY: as above (`TreeMember` is `bytemuck::Pod`).
unsafe impl aya::Pod for PodMember {}

/// The roles `ROLE_TGIDS` names (the watchdog's slot, the agent's), read
/// from its pin.
fn read_role_tgids(bpffs_root: &Path) -> std::result::Result<Vec<u32>, String> {
    let name = antitamper_bpf::ROLE_TGIDS_MAP_NAME;
    let md = MapData::from_pin(bpffs_root.join(name))
        .map_err(|e| format!("opening pinned {name}: {e}"))?;
    let a = AyaArray::<MapData, u32>::try_from(AyaMap::Array(md)).map_err(|e| e.to_string())?;
    [
        antitamper_bpf::ROLE_SLOT_WATCHDOG,
        antitamper_bpf::ROLE_SLOT_AGENT,
    ]
    .iter()
    .map(|s| a.get(s, 0).map_err(|e| format!("{name}[{s}]: {e}")))
    .collect()
}

/// `CLOCK_BOOTTIME` in nanoseconds — the clock of `bpf_ktime_get_boot_ns`,
/// the tree grant's deadline and heartbeat.
pub fn boottime_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid out-pointer; CLOCK_BOOTTIME exists on every
    // kernel the agent runs on (2.6.39+).
    unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}

/// Lot 273d (R1): the guarded sysctls judged at a window's close, the
/// harmful ones put back (`sysctl_guard::check`); each one put back, or
/// not, a line `<kind>: <detail>` of the signed close record (strict
/// overcommit and, lot 280a, a value the signed opt-out allows — the
/// operator's — are the round's findings only).
fn sysctls_at_close() -> Vec<String> {
    crate::sysctl_guard::check(
        std::path::Path::new("/"),
        antitamper_bpf::cgroup_floors::Host::read().mem_total,
        true,
    )
    .into_iter()
    .filter(|s| s.kind != "sysctl_strict" && s.kind != "sysctl_opted_out")
    .map(|s| format!("{}: {}", s.kind, s.detail))
    .collect()
}

/// Lot 273d: our units' drop-ins made since `since`, judged on this host;
/// the re-review of #497 (RR1): the ones kept, and the environment files
/// they name, write-protected (the pinned map under `bpffs_root`).
fn own_dropins_at_close(
    since: std::time::SystemTime,
    bpffs_root: Option<&Path>,
    keys: &crate::own_dropins::Registered,
) -> Vec<crate::own_dropins::Moved> {
    let roots = crate::self_integrity::unit_roots(std::path::Path::new("/"));
    let search: Vec<&std::path::Path> = roots.iter().map(|p| p.as_path()).collect();
    let mut protector = crate::own_dropins::Protector::open(bpffs_root, keys);
    let moved = crate::own_dropins::quarantine(
        &search,
        &crate::host_dropins::HostLimits::read(),
        crate::own_dropins::Pass {
            since,
            when: crate::own_dropins::AT_CLOSE,
        },
        std::path::Path::new(crate::own_dropins::QUARANTINE_DIR),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        crate::self_integrity::is_known_dropin,
        &mut |p| protector.protect(p),
    );
    protector.finish();
    moved
}

/// Lot 278: the installer a grant asked for an installer acts for (review
/// of #493, note a: `nn-admin trusted-installer-grant --for-installer`) —
/// the parent of `requester` (the `nn-admin` at the other end of the admin
/// socket, its `SO_PEERCRED` pid): `install.sh` or `uninstall.sh` runs
/// `nn-admin trusted-installer-grant` itself. Its pid and start (`starttime` of
/// `/proc/<ppid>/stat`), read under `proc_root`. `None` when it cannot be
/// told: the requester is gone, or no longer the child of that process
/// (read twice), or its parent is PID 1 or 0 (a requester started by init
/// acts for no installer, and the whole host must never be one).
pub fn installer_of_requester(proc_root: &Path, requester: u32) -> Option<(u32, u64)> {
    if requester <= 1 {
        return None;
    }
    let (ppid, _) = stat_parent_and_start(proc_root, requester)?;
    if ppid <= 1 || ppid == requester {
        return None;
    }
    let (_, start_ticks) = stat_parent_and_start(proc_root, ppid)?;
    // the requester still the child of that process: it waits for this
    // reply, so a change means another process took its pid
    if stat_parent_and_start(proc_root, requester)?.0 != ppid {
        return None;
    }
    Some((ppid, start_ticks))
}

/// `/proc/<pid>/stat`'s parent (field 4) and start (field 22), counted
/// after the `(comm)` field, which may hold spaces or parentheses.
fn stat_parent_and_start(proc_root: &Path, pid: u32) -> Option<(u32, u64)> {
    let stat = crate::state_read::read_state(proc_root.join(pid.to_string()).join("stat")).ok()?;
    let rest: Vec<&str> = stat.rsplit_once(')')?.1.split_whitespace().collect();
    Some((rest.get(1)?.parse().ok()?, rest.get(19)?.parse().ok()?))
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
    arr.set(0, &AyaFsGrant(grant), 0)
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
    arr.set(0, &AyaKillGrant(grant), 0)
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
        // lot 345: the close reports its unprotected drop-ins into the
        // process's one registry — the tests that write it run one at a
        // time (its report was signed into another test's log: the gate's
        // flake of `a_degradation_withdrawn_before_its_flush_is_still_signed`)
        let _g = crate::boot::degradation::TEST_LOCK.lock();
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

    /// Lab PR 225: the open window names its key and its deadline; once
    /// past it (or closed) there is no grant.
    #[test]
    fn the_open_window_names_its_key_and_deadline() {
        let ov = test_override(600);
        assert!(ov.grant_at(Instant::now()).is_none());
        let t0 = Instant::now();
        ov.arm_by(120, t0, "c2e8f3da");
        let g = ov
            .grant_at(t0 + Duration::from_secs(1))
            .expect("open window");
        assert_eq!(g.key_id, "c2e8f3da");
        assert!(
            g.expires_at.ends_with('Z') && g.expires_at.len() == 20,
            "{}",
            g.expires_at
        );
        assert!(ov.grant_at(t0 + Duration::from_secs(121)).is_none());
        ov.close("test");
        assert!(ov.grant_at(t0 + Duration::from_secs(1)).is_none());
    }

    /// Lab PR 243: the window reads the time through its clock — whether
    /// it is open, and its end on the wall clock — never the host's.
    #[test]
    fn the_window_reads_its_clock() {
        use crate::posture::clock::{Clock, TestClock};
        let clock = Arc::new(TestClock::at(
            std::time::UNIX_EPOCH + Duration::from_secs(1_767_225_600),
        ));
        let ov = test_override(600).with_clock(clock.clone());
        ov.arm_by(90, clock.now(), "c2e8f3da");
        assert!(ov.is_window_open());
        let g = ov.current_grant().expect("open window");
        assert_eq!(g.expires_at, "2026-01-01T00:01:30Z");
        clock.advance(Duration::from_secs(89));
        assert!(ov.is_window_open());
        clock.advance(Duration::from_secs(1));
        assert!(!ov.is_window_open());
        assert!(ov.current_grant().is_none());
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

    /// Lot 278: a grant made for an installer names it — its pid and start
    /// — with the time of the grant, until the window ends; a grant without
    /// one (`arm_by`) names none.
    #[test]
    fn a_grant_names_the_installer_it_was_made_for() {
        let ov = test_override(600);
        let before = monotonic_ns();
        ov.arm_for(60, Instant::now(), "c2e8f3da", Some((4242, 777)));
        let g = ov.current_grant().expect("open window");
        let who = g.grantee.expect("an installer");
        assert_eq!((who.pid, who.start_ticks), (4242, 777));
        assert!(who.granted_ns >= before && who.granted_ns <= monotonic_ns());
        ov.arm_by(60, Instant::now(), "c2e8f3da");
        assert_eq!(ov.current_grant().expect("open").grantee, None);
        ov.close("test");
        assert!(ov.current_grant().is_none());
    }

    /// Lot 278: the installer of a grant is its requester's parent, read
    /// from `/proc`; never PID 1 or 0, and not known when the requester is
    /// gone or its parent cannot be read.
    #[test]
    fn the_installer_is_the_requester_s_parent() {
        let proc = tempfile::TempDir::new().unwrap();
        let stat = |pid: u32, ppid: u32, ticks: u64| {
            let d = proc.path().join(pid.to_string());
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(
                d.join("stat"),
                format!(
                    "{pid} (n (a) b) S {ppid} 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 {ticks} 0 0\n"
                ),
            )
            .unwrap();
        };
        // install.sh (500, started at tick 9000) ran nn-admin (501)
        stat(500, 400, 9_000);
        stat(501, 500, 9_100);
        assert_eq!(installer_of_requester(proc.path(), 501), Some((500, 9_000)));
        // a requester started by init acts for no installer (init's own
        // stat readable: the refusal is the rule's, not a missing file)
        stat(1, 0, 1);
        stat(601, 1, 9_200);
        assert_eq!(installer_of_requester(proc.path(), 601), None);
        stat(602, 0, 9_200);
        assert_eq!(installer_of_requester(proc.path(), 602), None);
        // a requester that is gone, or whose parent is gone
        assert_eq!(installer_of_requester(proc.path(), 700), None);
        stat(801, 800, 9_300);
        assert_eq!(installer_of_requester(proc.path(), 801), None);
        // PID 1 itself is no requester
        assert_eq!(installer_of_requester(proc.path(), 1), None);
    }

    /// Lot 311 (N6): an installer's lineage hop whose `comm` is not UTF-8
    /// is read (parent and start) — on main the read failed.
    #[test]
    fn a_hop_whose_comm_is_not_utf8_has_its_parent_and_start() {
        let t = tempfile::tempdir().unwrap();
        crate::state_read::testing::write_non_utf8_proc(t.path(), 4301, 77, 0, 555);
        assert_eq!(stat_parent_and_start(t.path(), 4301), Some((77, 555)));
    }

    // ── Lot 2.3a's minimal path (lot 2.3b replaces it): the tree window ──

    use std::collections::BTreeMap;

    /// A session nonce no literal names (CodeQL
    /// `rust/hard-coded-cryptographic-value`, as lot 2.2's `test_nonce`).
    fn test_nonce() -> u32 {
        let pid = std::process::id();
        pid.rotate_left(7) ^ pid
    }
    const NOW: u64 = 5_000_000_000_000;
    const SEC: u64 = 1_000_000_000;

    /// The kernel's maps, each write in `ops` in its order.
    #[derive(Default)]
    struct FakeMaps {
        ops: Vec<String>,
        members: BTreeMap<u32, TreeMember>,
        grant: FsGrantV2,
        closed: [u64; 2],
        refuse_grant: bool,
    }

    impl TreeMaps for FakeMaps {
        fn put_member(&mut self, tgid: u32, m: TreeMember) -> std::result::Result<(), String> {
            self.ops.push(format!(
                "member {tgid} gen {} flags {}",
                m.generation, m.flags
            ));
            self.members.insert(tgid, m);
            Ok(())
        }
        fn clear_members(&mut self) -> std::result::Result<usize, String> {
            self.ops.push("clear members".to_string());
            let n = self.members.len();
            self.members.clear();
            Ok(n)
        }
        fn write_grant(&mut self, g: FsGrantV2) -> std::result::Result<(), String> {
            if self.refuse_grant {
                return Err("EPERM".to_string());
            }
            self.ops.push(format!("grant gen {}", g.generation));
            self.grant = g;
            Ok(())
        }
        fn read_closed(&mut self) -> std::result::Result<[u64; 2], String> {
            Ok(self.closed)
        }
        fn zero_closed(&mut self) -> std::result::Result<(), String> {
            self.ops.push("zero closed".to_string());
            self.closed = [0; 2];
            Ok(())
        }
    }

    /// A `/proc`: per pid its parent, start, kind, tracer and seccomp mode.
    #[derive(Default, Clone)]
    struct FakeProc(BTreeMap<u32, (ProcHop, (u32, u32))>);

    impl FakeProc {
        fn with(mut self, pid: u32, ppid: u32, start_ticks: u64) -> Self {
            let hop = ProcHop {
                ppid,
                start_ticks,
                kthread: false,
            };
            self.0.insert(pid, (hop, (0, 0)));
            self
        }
        fn guarded(mut self, pid: u32, tracer: u32, seccomp: u32) -> Self {
            self.0.get_mut(&pid).unwrap().1 = (tracer, seccomp);
            self
        }
    }

    impl LineReader for FakeProc {
        fn hop(&self, pid: u32) -> std::result::Result<ProcHop, String> {
            self.0
                .get(&pid)
                .map(|e| e.0)
                .ok_or_else(|| format!("{pid}: gone"))
        }
        fn guards(&self, pid: u32) -> std::result::Result<(u32, u32), String> {
            self.0
                .get(&pid)
                .map(|e| e.1)
                .ok_or_else(|| format!("{pid}: gone"))
        }
    }

    /// install.sh (501, started at 9000) ran a shell (502) that ran
    /// nn-admin (503); its parent is a login shell (400).
    fn host() -> FakeProc {
        FakeProc::default()
            .with(400, 1, 100)
            .with(501, 400, 9_000)
            .with(502, 501, 9_100)
            .with(503, 502, 9_200)
            .with(1, 0, 1)
    }

    fn line() -> Vec<(u32, u64)> {
        vec![(501, 9_000), (502, 9_100), (503, 9_200)]
    }

    fn tree_override() -> TrustedInstallerOverride {
        TrustedInstallerOverride::new(None, test_nonce(), None, Duration::from_secs(600))
    }

    fn arm(
        ov: &TrustedInstallerOverride,
        maps: &mut FakeMaps,
        reader: &FakeProc,
        missing: &[String],
    ) -> std::result::Result<u64, String> {
        ov.arm_tree_with(Some(maps), reader, missing, NOW, 120, (501, 9_000), &line())
    }

    #[test]
    fn the_walk_finds_the_root_on_the_requester_s_line() {
        let line = line_to_root(&host(), 503, (501, 9_000), &[]).expect("on the line");
        assert_eq!(line, vec![(501, 9_000), (502, 9_100), (503, 9_200)]);
        // the requester's own parent, the hidden flag's root
        assert_eq!(
            line_to_root(&host(), 503, (502, 9_100), &[]).unwrap(),
            vec![(502, 9_100), (503, 9_200)]
        );
        // the requester itself (lot 2.3b's `window-run`)
        assert_eq!(
            line_to_root(&host(), 503, (503, 9_200), &[]).unwrap(),
            vec![(503, 9_200)]
        );
    }

    #[test]
    fn the_walk_refuses_a_root_not_on_the_line() {
        let reader = host().with(777, 400, 9_050);
        let e = line_to_root(&reader, 503, (777, 9_050), &[]).unwrap_err();
        assert!(e.contains("not on the requester 503's line"), "{e}");
        // a hop that cannot be read refuses too (never judged unknown-as-fine)
        let gone = FakeProc::default().with(503, 502, 9_200);
        assert!(line_to_root(&gone, 503, (501, 9_000), &[]).is_err());
        // nor beyond the bound
        let mut deep = FakeProc::default().with(2_000, 1, 1);
        for pid in 2_001..2_000 + MAX_TREE_LINE as u32 + 2 {
            deep = deep.with(pid, pid - 1, u64::from(pid));
        }
        let top = 2_000 + MAX_TREE_LINE as u32 + 1;
        let e = line_to_root(&deep, top, (2_000, 1), &[]).unwrap_err();
        assert!(e.contains("not within"), "{e}");
    }

    #[test]
    fn the_walk_refuses_a_root_whose_start_differs() {
        let e = line_to_root(&host(), 503, (501, 8_999), &[]).unwrap_err();
        assert!(e.contains("another process"), "{e}");
    }

    #[test]
    fn the_walk_refuses_pid_1_as_root() {
        for root in [(1, 1), (0, 0)] {
            let e = line_to_root(&host(), 503, root, &[]).unwrap_err();
            assert!(e.contains("PID 1"), "{e}");
        }
        assert!(line_to_root(&host(), 1, (501, 9_000), &[]).is_err());
    }

    #[test]
    fn the_walk_refuses_a_kernel_thread_a_traced_or_filtered_hop_and_the_agent_s_own() {
        let mut kthread = host();
        kthread.0.get_mut(&502).unwrap().0.kthread = true;
        assert!(
            line_to_root(&kthread, 503, (501, 9_000), &[])
                .unwrap_err()
                .contains("kernel thread")
        );
        let traced = host().guarded(502, 4242, 0);
        assert!(
            line_to_root(&traced, 503, (501, 9_000), &[])
                .unwrap_err()
                .contains("TracerPid 4242")
        );
        let filtered = host().guarded(501, 0, 2);
        assert!(
            line_to_root(&filtered, 503, (501, 9_000), &[])
                .unwrap_err()
                .contains("Seccomp 2")
        );
        // the agent (or the watchdog) on the line, or the root's parent
        assert!(
            line_to_root(&host(), 503, (501, 9_000), &[502])
                .unwrap_err()
                .contains("the agent's")
        );
        assert!(
            line_to_root(&host(), 503, (501, 9_000), &[400])
                .unwrap_err()
                .contains("child of the agent's own")
        );
    }

    #[test]
    fn the_stat_and_status_lines_are_read_as_the_kernel_writes_them() {
        let stat = "501 (a) b (c)) S 400 501 501 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 9000 0 0\n";
        assert_eq!(
            parse_hop(stat),
            Some(ProcHop {
                ppid: 400,
                start_ticks: 9_000,
                kthread: false
            })
        );
        let kthread = "2 (kthreadd) S 0 0 0 0 -1 2129984 0 0 0 0 0 0 0 0 20 0 1 0 1 0 0\n";
        assert!(parse_hop(kthread).unwrap().kthread);
        let status = "Name:\tTracerPid: 9\nUmask:\t0022\nTracerPid:\t0\nSeccomp:\t2\n";
        assert_eq!(parse_guards(status), Some((0, 2)));
        assert_eq!(parse_guards("Name:\tx\nTracerPid:\t0\n"), None);
    }

    #[test]
    fn a_tree_grant_is_refused_while_the_host_wide_window_is_open() {
        let ov = tree_override();
        ov.arm(30, Instant::now());
        let mut maps = FakeMaps::default();
        let e = arm(&ov, &mut maps, &host(), &[]).unwrap_err();
        assert!(e.contains("host-wide"), "{e}");
        assert!(maps.ops.is_empty(), "{:?}", maps.ops);
        assert!(!ov.tree_window_open());
        ov.close("test");
        assert!(arm(&ov, &mut maps, &host(), &[]).is_ok());
    }

    #[test]
    fn a_tree_grant_is_refused_while_a_tree_window_is_open() {
        let ov = tree_override();
        let mut maps = FakeMaps::default();
        assert_eq!(arm(&ov, &mut maps, &host(), &[]), Ok(1));
        let before = maps.ops.len();
        let e = arm(&ov, &mut maps, &host(), &[]).unwrap_err();
        assert!(e.contains("one window at a time"), "{e}");
        assert_eq!(maps.ops.len(), before, "nothing written: {:?}", maps.ops);
        assert_eq!(ov.tree_generation(), Some(1));
    }

    #[test]
    fn a_tree_grant_is_refused_when_the_kernel_manifest_misses_anything() {
        let ov = tree_override();
        let mut maps = FakeMaps::default();
        let missing = vec!["programs: tree_fork (sched_process_fork): EINVAL".to_string()];
        let e = arm(&ov, &mut maps, &host(), &missing).unwrap_err();
        assert!(
            e.contains("window_tree_unavailable") && e.contains("tree_fork"),
            "{e}"
        );
        assert!(maps.ops.is_empty());
        // no pin root: refused as well
        let e = ov
            .arm_tree_with(None, &host(), &[], NOW, 120, (501, 9_000), &line())
            .unwrap_err();
        assert!(e.contains("no bpffs"), "{e}");
        // no session this boot
        let dormant = TrustedInstallerOverride::new(None, 0, None, Duration::from_secs(600));
        assert!(arm(&dormant, &mut maps, &host(), &[]).is_err());
        assert!(maps.ops.is_empty());
    }

    #[test]
    fn the_members_are_written_before_the_grant() {
        let ov = tree_override();
        let mut maps = FakeMaps::default();
        assert_eq!(arm(&ov, &mut maps, &host(), &[]), Ok(1));
        assert_eq!(
            maps.ops,
            vec![
                format!("member 501 gen 1 flags {TREE_MEMBER_ROOT}"),
                "member 502 gen 1 flags 0".to_string(),
                "member 503 gen 1 flags 0".to_string(),
                "grant gen 1".to_string(),
            ]
        );
        assert_eq!(
            maps.grant,
            FsGrantV2 {
                nonce: test_nonce(),
                root_tgid: 501,
                generation: 1,
                expires_boot_ns: NOW + 120 * SEC,
                root_start_ticks: 9_000,
                heartbeat_boot_ns: NOW,
                first_grant_boot_ns: NOW,
            }
        );
        assert_eq!(maps.members[&502].start_ticks, 9_100);
        // the kernel's own test lifts for the members of this grant
        assert!(maps.grant.lifts_for(
            maps.members.get(&503),
            9_200,
            false,
            NOW + SEC,
            test_nonce()
        ));
        // clamped to the 600 s ceiling
        let ov = tree_override();
        let mut maps = FakeMaps::default();
        ov.arm_tree_with(
            Some(&mut maps),
            &host(),
            &[],
            NOW,
            99_999,
            (501, 9_000),
            &line(),
        )
        .unwrap();
        assert_eq!(maps.grant.expires_boot_ns, NOW + 600 * SEC);
    }

    #[test]
    fn a_tracer_found_at_the_second_read_clears_the_members_and_no_grant_is_written() {
        let ov = tree_override();
        for reader in [
            host().guarded(502, 77, 0),
            host().guarded(503, 0, 1),
            host().with(502, 501, 9_999),
            FakeProc::default().with(501, 400, 9_000),
        ] {
            let mut maps = FakeMaps::default();
            assert!(arm(&ov, &mut maps, &reader, &[]).is_err());
            assert_eq!(maps.ops.last().map(String::as_str), Some("clear members"));
            assert!(
                !maps.ops.iter().any(|o| o.starts_with("grant")),
                "{:?}",
                maps.ops
            );
            assert!(maps.members.is_empty());
            assert!(!ov.tree_window_open());
        }
        // a grant that cannot be written: the members out again too
        let mut maps = FakeMaps {
            refuse_grant: true,
            ..FakeMaps::default()
        };
        assert!(arm(&ov, &mut maps, &host(), &[]).is_err());
        assert!(maps.members.is_empty());
        assert!(!ov.tree_window_open());
    }

    #[test]
    fn the_generation_rises_by_one_and_is_never_reused() {
        let ov = tree_override();
        let mut maps = FakeMaps::default();
        assert_eq!(arm(&ov, &mut maps, &host(), &[]), Ok(1));
        assert!(ov.close_tree_with(&mut maps, "test"));
        assert_eq!(arm(&ov, &mut maps, &host(), &[]), Ok(2));
        assert!(ov.close_tree_with(&mut maps, "test"));
        // a refusal before any member is written spends nothing
        assert!(arm(&ov, &mut maps, &host(), &["x".to_string()]).is_err());
        // one refused after its members were written spends its number
        assert!(arm(&ov, &mut maps, &host().guarded(503, 9, 0), &[]).is_err());
        assert_eq!(arm(&ov, &mut maps, &host(), &[]), Ok(4));
    }

    #[test]
    fn the_tick_beats_and_closes_at_the_deadline_the_kernel_s_close_or_the_root_s_end() {
        let ov = tree_override();
        let mut maps = FakeMaps::default();
        arm(&ov, &mut maps, &host(), &[]).unwrap();
        // a beat: the slot as it is, the heartbeat moved
        assert_eq!(ov.tree_tick_with(&mut maps, &host(), NOW + 5 * SEC), None);
        assert_eq!(maps.grant.heartbeat_boot_ns, NOW + 5 * SEC);
        assert_eq!(maps.grant.expires_boot_ns, NOW + 120 * SEC);
        assert!(ov.tree_window_open());
        // the deadline
        assert_eq!(
            ov.tree_tick_with(&mut maps, &host(), NOW + 120 * SEC),
            Some("ttl_expired")
        );
        assert!(!ov.tree_window_open());
        assert_eq!(maps.grant, FsGrantV2::default());
        assert!(maps.members.is_empty());
        let tail: Vec<&str> = maps
            .ops
            .iter()
            .rev()
            .take(3)
            .rev()
            .map(String::as_str)
            .collect();
        assert_eq!(tail, ["grant gen 0", "clear members", "zero closed"]);
        // closed by the kernel (the root died, or was evicted)
        arm(&ov, &mut maps, &host(), &[]).unwrap();
        maps.closed = [u64::from(test_nonce()), 2];
        assert_eq!(
            ov.tree_tick_with(&mut maps, &host(), NOW + SEC),
            Some("closed_by_kernel")
        );
        assert_eq!(maps.closed, [0; 2]);
        // another window's close names no other generation
        arm(&ov, &mut maps, &host(), &[]).unwrap();
        maps.closed = [u64::from(test_nonce()), 2];
        assert_eq!(ov.tree_tick_with(&mut maps, &host(), NOW + SEC), None);
        // the root's pid gone, or another process's now
        assert_eq!(
            ov.tree_tick_with(&mut maps, &host().with(501, 400, 9_500), NOW + 2 * SEC),
            Some("root_exited")
        );
        assert_eq!(ov.tree_tick_with(&mut maps, &host(), NOW + 3 * SEC), None);
        arm(&ov, &mut maps, &host(), &[]).unwrap();
        let mut gone = host();
        gone.0.remove(&501);
        assert_eq!(
            ov.tree_tick_with(&mut maps, &gone, NOW + 2 * SEC),
            Some("root_exited")
        );
    }

    #[test]
    fn a_close_whose_grant_was_not_zeroed_leaves_the_kernel_s_close_in_place() {
        let ov = tree_override();
        let mut maps = FakeMaps::default();
        arm(&ov, &mut maps, &host(), &[]).unwrap();
        maps.closed = [u64::from(test_nonce()), 1];
        maps.refuse_grant = true;
        assert!(ov.close_tree_with(&mut maps, "test"));
        assert_eq!(maps.closed, [u64::from(test_nonce()), 1], "{:?}", maps.ops);
        assert!(maps.members.is_empty());
        assert!(!ov.tree_window_open());
        // and once
        assert!(!ov.close_tree_with(&mut maps, "test"));
    }

    #[test]
    fn a_tree_window_softens_nothing_in_the_agent() {
        let ov = tree_override();
        let mut maps = FakeMaps::default();
        arm(&ov, &mut maps, &host(), &[]).unwrap();
        assert!(ov.tree_window_open());
        assert!(!ov.is_window_open());
        assert!(!ov.is_active_at(Instant::now()));
        assert!(ov.current_grant().is_none());
    }

    #[test]
    fn the_host_wide_grant_is_refused_while_a_tree_window_is_open() {
        let ov = tree_override();
        assert!(ov.legacy_arming().is_ok());
        let mut maps = FakeMaps::default();
        arm(&ov, &mut maps, &host(), &[]).unwrap();
        let e = ov.legacy_arming().unwrap_err();
        assert!(e.contains("one window at a time"), "{e}");
        ov.close_tree_with(&mut maps, "test");
        assert!(ov.legacy_arming().is_ok());
    }

    #[test]
    fn each_tree_grant_refusal_and_close_is_recorded() {
        let dir = tempfile::TempDir::new().unwrap();
        let key = crate::audit::AgentSigningKey::load_or_bootstrap(&dir.path().join("k")).unwrap();
        let log = AuditLog::open(&dir.path().join("audit.log"), key, [1u8; 16]).unwrap();
        let ov = TrustedInstallerOverride::new(
            None,
            test_nonce(),
            Some(Arc::new(Mutex::new(log))),
            Duration::from_secs(600),
        );
        let mut maps = FakeMaps::default();
        arm(&ov, &mut maps, &host(), &[]).unwrap();
        assert!(arm(&ov, &mut maps, &host(), &[]).is_err());
        ov.note_tree_refusal("root 7 is not on the line");
        ov.tree_tick_with(&mut maps, &host(), NOW + 120 * SEC);
        let rows: Vec<serde_json::Value> = std::fs::read_to_string(dir.path().join("audit.log"))
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
            .filter(|r| {
                r["op"]
                    .as_str()
                    .is_some_and(|o| o.starts_with("trusted_installer_tree"))
            })
            .collect();
        let ops: Vec<&str> = rows.iter().map(|r| r["op"].as_str().unwrap()).collect();
        assert_eq!(
            ops,
            [
                "trusted_installer_tree_window_open",
                "trusted_installer_tree_grant_refused",
                "trusted_installer_tree_grant_refused",
                "trusted_installer_tree_window_close",
            ]
        );
        assert_eq!(rows[3]["result"], "closed: ttl_expired");
        assert_eq!(rows[3]["extra"]["members_cleared"], 3);
    }

    /// Lot 2.3a (D7, the review of #647): the root's cgroup and every cgroup
    /// above it but the hierarchy's root, `cgroup.kill` and `cgroup.freeze`.
    #[test]
    fn the_root_s_cgroup_files_are_its_cgroup_s_and_its_ancestors() {
        let root = Path::new("/sys/fs/cgroup");
        let plan = cgroup_file_plan(root, "/user.slice/user-0.slice/session-3.scope\n");
        let kill = common::wire::FS_OP_CGROUP_KILL;
        let freeze = common::wire::FS_OP_CGROUP_FREEZE;
        let p = |s: &str| PathBuf::from(format!("/sys/fs/cgroup/{s}"));
        assert_eq!(
            plan,
            vec![
                (
                    p("user.slice/user-0.slice/session-3.scope/cgroup.kill"),
                    kill
                ),
                (
                    p("user.slice/user-0.slice/session-3.scope/cgroup.freeze"),
                    freeze
                ),
                (p("user.slice/user-0.slice/cgroup.kill"), kill),
                (p("user.slice/user-0.slice/cgroup.freeze"), freeze),
                (p("user.slice/cgroup.kill"), kill),
                (p("user.slice/cgroup.freeze"), freeze),
            ]
        );
        assert!(
            cgroup_file_plan(root, "/").is_empty(),
            "the root has neither file"
        );
        assert_eq!(
            unified_cgroup("12:pids:/x\n0::/system.slice/apt.service\n"),
            Some("/system.slice/apt.service")
        );
        assert_eq!(unified_cgroup("1:name=systemd:/x\n"), None);
    }
}
