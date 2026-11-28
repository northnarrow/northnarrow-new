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
pub use nn_proto::admin_signed_payload::TreeRootKind;
use common::wire::{
    FROZEN_INODES_MAP_NAME, FROZEN_NAMES_MAP_NAME, FS_GRANT_V2_MAP_NAME, FsGrant, FsGrantV2,
    INODE_EXT_MAP_NAME, InodeKey, KillGrant, TREE_CGROUP_FILES_MAP_NAME, TREE_MEMBER_ROOT,
    TREE_MEMBERS_MAP_NAME, TreeMember, WINDOW_LEASES_MAP_NAME, WINDOW_LEASES_MAX, WINDOW_MAX_NS,
    WindowLease,
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
    /// Lot 2.3b (D1): the controlled stop or restart a member asked for —
    /// the run loop's stop reason, taken once.
    controlled: Mutex<Option<&'static str>>,
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
    /// Lot 2.3b (D5): PID 1's manager environment at the grant, compared at
    /// each controlled stop and lease and at the close.
    pid1_env: Vec<String>,
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
            controlled: Mutex::new(None),
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
        notes: serde_json::Value,
    ) -> std::result::Result<u64, String> {
        let mut pinned = self.bpffs_root.as_deref().map(PinnedTreeMaps);
        self.arm_tree_noted(
            pinned.as_mut().map(|m| m as &mut dyn TreeMaps),
            &ProcFs(Path::new("/proc")),
            &super::window_tree::manifest_missing(self.bpffs_root.as_deref()),
            boottime_ns(),
            (window_secs, root, line),
            notes,
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
        self.arm_tree_noted(
            maps,
            reader,
            missing,
            now_boot_ns,
            (window_secs, root, line),
            serde_json::Value::Null,
        )
    }

    /// [`Self::arm_tree_with`] whose open record also carries `notes` (lot
    /// 2.3b: the root's kind, the interactive mark, the pre-grant check).
    fn arm_tree_noted(
        &self,
        maps: Option<&mut dyn TreeMaps>,
        reader: &dyn LineReader,
        missing: &[String],
        now_boot_ns: u64,
        (window_secs, root, line): (u32, (u32, u64), &[(u32, u64)]),
        notes: serde_json::Value,
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
                let mut extra = serde_json::json!({
                    "generation": g.generation,
                    "root_pid": g.root_tgid,
                    "root_start_ticks": g.root_start_ticks,
                    "members": line.iter().map(|(pid, _)| *pid).collect::<Vec<u32>>(),
                    "expires_boot_ns": g.expires_boot_ns,
                });
                if let (Some(e), serde_json::Value::Object(n)) = (extra.as_object_mut(), notes) {
                    e.extend(n);
                }
                self.audit_tree(
                    "trusted_installer_tree_window_open",
                    extra,
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
        // 1c. (lot 2.3b, D5) the system code frozen against outsiders
        let plan = match reader.freeze_plan() {
            Ok(p) => p,
            Err(e) => return Err(withdrawn(maps, format!("the frozen objects: {e}"))),
        };
        for mark in plan {
            let written = match mark {
                FreezeMark::Inode(key, reach) => maps.put_frozen_inode(key, [generation, reach]),
                FreezeMark::Name(name, reach) => maps.put_frozen_name(name, [generation, reach]),
            };
            if let Err(e) = written {
                return Err(withdrawn(maps, format!("a frozen object not written: {e}")));
            }
        }
        // 1d. (lot 2.3b, D5) PID 1's environment, watched: detected, not
        // refused (no file holds it)
        let pid1_env = match reader.pid1_env() {
            Ok(env) => env,
            Err(e) => {
                return Err(withdrawn(
                    maps,
                    format!("PID 1's environment could not be read, so the window could not watch it: {e}"),
                ));
            }
        };
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
            pid1_env,
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
            // lot 2.3b: PID 1's environment, at the close too
            let at_grant = tree.open.as_ref().map(|w| w.pid1_env.clone()).unwrap_or_default();
            let closed = close_tree_locked(&mut tree, &self.tree_armed, maps);
            drop(tree);
            self.pid1_env_at_close(reader, &at_grant);
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
        let at_grant = tree.open.as_ref().map(|w| w.pid1_env.clone());
        let closed = close_tree_locked(&mut tree, &self.tree_armed, maps);
        drop(tree);
        // lot 2.3b: PID 1's environment, at the close too (a close it caused
        // has already signed its change)
        if let Some(env) = at_grant.filter(|_| reason != "pid1_environment_changed") {
            self.pid1_env_at_close(&ProcFs(Path::new("/proc")), &env);
        }
        match closed {
            Some(c) => {
                self.audit_tree_close(reason, &c);
                true
            }
            None => false,
        }
    }

    /// Lot 2.3b: PID 1's environment at a window's close compared with
    /// `at_grant`; a change is signed High (the window is closing anyway).
    fn pid1_env_at_close(&self, reader: &dyn LineReader, at_grant: &[String]) {
        match reader.pid1_env() {
            Ok(now) if nn_core::anti_tamper::trusted_installer::pid1_env_changed(at_grant, &now) => {
                self.report_high(
                    PID1_ENV_CHANGED,
                    &format!(
                        "PID 1's manager environment changed during the window (seen at its \
                         close): {} variable(s) at the grant, {} now",
                        at_grant.len(),
                        now.len()
                    ),
                );
            }
            Ok(_) => {}
            Err(e) => warn!(
                target: "anti_tamper.trusted_installer",
                error = %e,
                "PID 1's environment could not be read at the window's close"
            ),
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

    /// Lot 2.3b (D1, the leases): the member of the open window that asks
    /// over the admin socket — `requester`, the socket's peer, pinned
    /// before it is read — authenticated by three facts: its member entry
    /// (`TREE_MEMBERS`, its own start), the window's generation (the one
    /// the request names), and its own state now (not traced, no seccomp
    /// mode, the initial namespaces). `Ok((tgid, start))`; `Err` why, for
    /// an outsider (signed by the caller).
    pub fn window_member(
        &self,
        requester: u32,
        generation: u64,
    ) -> std::result::Result<(u32, u64), String> {
        let Some(root) = self.bpffs_root.as_deref() else {
            return Err("no bpffs pin root this boot: no tree window".to_string());
        };
        self.window_member_with(
            &mut PinnedTreeMaps(root),
            &ProcFs(Path::new("/proc")),
            requester,
            generation,
        )
    }

    fn window_member_with(
        &self,
        maps: &mut dyn TreeMaps,
        reader: &dyn LineReader,
        requester: u32,
        generation: u64,
    ) -> std::result::Result<(u32, u64), String> {
        let open = self.tree.lock().open.as_ref().map(|w| w.grant.generation);
        let Some(current) = open else {
            return Err("no trusted-installer window per process tree is open".to_string());
        };
        if generation != current {
            return Err(format!(
                "the request names generation {generation}, the open window is {current}"
            ));
        }
        if requester <= 1 {
            return Err(format!("requester {requester}: PID 1 (or 0) is no member"));
        }
        let pin = reader.pin(requester)?;
        let start = reader.hop(requester)?.start_ticks;
        match maps.member(requester)? {
            Some(m) if m.generation == current && m.start_ticks == start => {}
            Some(_) => {
                return Err(format!(
                    "process {requester} holds no entry of this window for itself (another \
                     generation or another process's start)"
                ));
            }
            None => return Err(format!("process {requester} is outside the window's tree")),
        }
        match reader.guards(requester)? {
            (0, 0) => {}
            (tracer, seccomp) => {
                return Err(format!(
                    "member {requester} is traced (TracerPid {tracer}) or filtered (Seccomp \
                     {seccomp})"
                ));
            }
        }
        if !reader.ns_initial(requester)? {
            return Err(format!(
                "member {requester} is outside the initial pid, user or mount namespace"
            ));
        }
        if !pin.alive() {
            return Err(format!("process {requester} exited while it was read"));
        }
        Ok((requester, start))
    }

    /// Lot 2.3b (refinement 2 of D5): PID 1's manager environment compared
    /// with the grant's, through `reader`; a change (or an environment that
    /// can no longer be read) closes the window, signed High (`when`: the
    /// controlled stop, a lease, the close). `true` when it closed it.
    fn pid1_env_closes(
        &self,
        maps: &mut dyn TreeMaps,
        reader: &dyn LineReader,
        when: &str,
    ) -> bool {
        let at_grant = match self.tree.lock().open.as_ref() {
            Some(w) => w.pid1_env.clone(),
            None => return false,
        };
        let why = match reader.pid1_env() {
            Ok(now) if !nn_core::anti_tamper::trusted_installer::pid1_env_changed(&at_grant, &now) => {
                return false;
            }
            Ok(now) => format!(
                "PID 1's manager environment changed since the window's grant (at {when}): {} \
                 variable(s) at the grant, {} now",
                at_grant.len(),
                now.len()
            ),
            Err(e) => format!("PID 1's manager environment could not be read at {when}: {e}"),
        };
        self.report_high(PID1_ENV_CHANGED, &why);
        self.close_tree_with(maps, "pid1_environment_changed")
    }

    /// A High finding of the window (`kind`), signed in the audit chain.
    fn report_high(&self, kind: &'static str, detail: &str) {
        let audit = self.audit.lock().clone();
        crate::self_integrity::report_event(
            audit.as_ref(),
            &crate::self_integrity::Finding {
                kind,
                detail: detail.to_string(),
            },
        );
    }

    /// Lot 2.3b (the single-use leases, the design's section 2): a lease
    /// for PID 1's removal of our units' enablement link `link`, armed for
    /// `member` ([`Self::window_member`]) in the window `generation`: bound
    /// to the link's directory (its inode, a directory of our links the
    /// start registered) and its name, consumed by its first use, void
    /// after `WINDOW_LEASE_TTL_NS`; PID 1's environment is compared first.
    /// `Ok` the slot; `Err` why (signed by the caller).
    pub fn arm_lease(
        &self,
        member: (u32, u64),
        generation: u64,
        link: &str,
    ) -> std::result::Result<u32, String> {
        let Some(root) = self.bpffs_root.as_deref() else {
            return Err("no bpffs pin root this boot: no lease".to_string());
        };
        self.arm_lease_with(
            &mut PinnedTreeMaps(root),
            &ProcFs(Path::new("/proc")),
            &stat_key,
            boottime_ns(),
            member,
            generation,
            link,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn arm_lease_with(
        &self,
        maps: &mut dyn TreeMaps,
        reader: &dyn LineReader,
        stat: &dyn Fn(&Path) -> Option<InodeKey>,
        now_boot_ns: u64,
        member: (u32, u64),
        generation: u64,
        link: &str,
    ) -> std::result::Result<u32, String> {
        let Some((dir, name)) = nn_core::anti_tamper::trusted_installer::lease_link(link) else {
            return Err(format!(
                "{link} is not one of our units' enablement links (a `*.wants` or `*.requires` \
                 entry named after the agent's or the watchdog's unit)"
            ));
        };
        if self.pid1_env_closes(maps, reader, "a lease") {
            return Err("PID 1's environment changed: the window is closed".to_string());
        }
        if self.tree_generation() != Some(generation) {
            return Err(format!("the window {generation} is not open"));
        }
        let Some(key) = stat(Path::new(dir)) else {
            return Err(format!("{dir}: no such directory"));
        };
        match maps.inode_ext(key)? {
            Some(ext) if ext & common::wire::INODE_EXT_UNIT_LINKS != 0 => {}
            _ => {
                return Err(format!(
                    "{dir} is not a directory of our units' links this start registered"
                ));
            }
        }
        let leases = maps.leases()?;
        let live = |l: &WindowLease| {
            l.used == 0 && l.generation == generation && now_boot_ns < l.expires_boot_ns
        };
        let armed_this_window = leases.iter().filter(|l| l.generation == generation).count();
        if armed_this_window >= WINDOW_LEASES_MAX as usize {
            return Err(format!(
                "this window armed {armed_this_window} leases already (at most {WINDOW_LEASES_MAX})"
            ));
        }
        let Some(slot) = leases.iter().position(|l| !live(l) && l.generation != generation)
        else {
            return Err("no lease slot is free".to_string());
        };
        let lease = WindowLease {
            generation,
            dir: key,
            name_hash: common::wire::pin_name_hash(name.as_bytes()),
            expires_boot_ns: now_boot_ns.saturating_add(common::wire::WINDOW_LEASE_TTL_NS),
            member_tgid: member.0,
            action: common::wire::LEASE_REMOVE,
            used: 0,
            _pad: 0,
        };
        let slot = slot as u32;
        maps.put_lease(slot, lease)?;
        self.audit_tree(
            "trusted_installer_tree_lease_armed",
            serde_json::json!({
                "generation": generation,
                "slot": slot,
                "link": link,
                "action": "remove",
                "member_pid": member.0,
                "member_start_ticks": member.1,
                "expires_boot_ns": lease.expires_boot_ns,
            }),
            format!("armed: slot {slot}"),
        );
        Ok(slot)
    }

    /// Lot 2.3b (D1, the controlled stop): `member` ([`Self::window_member`])
    /// asked the window `generation` for a stop (`restart`: false) or a
    /// restart: PID 1's environment is compared, the record naming the
    /// member is signed, and the run loop's stop reason is set
    /// (`controlled_stop`, `controlled_restart`: [`Self::take_controlled_stop`]).
    /// The caller writes the watchdog's stand-down for a stop and wakes the
    /// run loop. `Err` why, nothing recorded as asked.
    pub fn controlled_stop(
        &self,
        member: (u32, u64),
        generation: u64,
        restart: bool,
    ) -> std::result::Result<&'static str, String> {
        let Some(root) = self.bpffs_root.as_deref() else {
            return Err("no bpffs pin root this boot: no tree window".to_string());
        };
        self.controlled_stop_with(
            &mut PinnedTreeMaps(root),
            &ProcFs(Path::new("/proc")),
            member,
            generation,
            restart,
        )
    }

    fn controlled_stop_with(
        &self,
        maps: &mut dyn TreeMaps,
        reader: &dyn LineReader,
        member: (u32, u64),
        generation: u64,
        restart: bool,
    ) -> std::result::Result<&'static str, String> {
        if self.pid1_env_closes(maps, reader, "a controlled stop") {
            return Err("PID 1's environment changed: the window is closed".to_string());
        }
        if self.tree_generation() != Some(generation) {
            return Err(format!("the window {generation} is not open"));
        }
        let reason = if restart {
            CONTROLLED_RESTART_REASON
        } else {
            CONTROLLED_STOP_REASON
        };
        self.audit_tree(
            "trusted_installer_tree_controlled_stop",
            serde_json::json!({
                "generation": generation,
                "action": if restart { "restart" } else { "stop" },
                "member_pid": member.0,
                "member_start_ticks": member.1,
                "agent_pid": std::process::id(),
            }),
            format!("{reason}: asked by member {}", member.0),
        );
        *self.controlled.lock() = Some(reason);
        Ok(reason)
    }

    /// Lot 2.3b: the controlled stop's reason a member asked for, taken
    /// once (the run loop's, when the admin shutdown signal wakes it).
    pub fn take_controlled_stop(&self) -> Option<&'static str> {
        self.controlled.lock().take()
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

/// Lot 2.3b: the stop reasons of a member's controlled stop and restart
/// (clean stops: `nn_evidence::heartbeat::CLEAN_STOP_REASONS`).
pub const CONTROLLED_STOP_REASON: &str = "controlled_stop";
pub const CONTROLLED_RESTART_REASON: &str = "controlled_restart";

/// Lot 2.3b (D5, refinement 2): the finding of PID 1's environment changed
/// during a window, High (`crate::self_integrity`).
pub const PID1_ENV_CHANGED: &str = "window_pid1_environment_changed";

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
    /// Lot 2.3b (the admission policy): a handle that tells, after the
    /// reads, whether `pid` still names the process it named when the
    /// handle was taken (a pidfd: [`Pidfd`]). Taken before any read of
    /// the process.
    fn pin(&self, _pid: u32) -> std::result::Result<Box<dyn ProcPin>, String> {
        Ok(Box::new(AlwaysAlive))
    }
    /// Lot 2.3b: whether `pid` is in the initial pid, user and mount
    /// namespaces (its `ns/pid`, `ns/user`, `ns/mnt` those of PID 1).
    fn ns_initial(&self, _pid: u32) -> std::result::Result<bool, String> {
        Ok(true)
    }
    /// Lot 2.3b: its executable — `(st_dev, st_ino)` and its resolved path.
    fn exe(&self, pid: u32) -> std::result::Result<((u64, u64), String), String> {
        Err(format!("/proc/{pid}/exe: not read"))
    }
    /// Lot 2.3b: its arguments.
    fn cmdline(&self, _pid: u32) -> std::result::Result<Vec<String>, String> {
        Ok(Vec::new())
    }
    /// Lot 2.3b: its initial environment (`NAME=value` entries).
    fn environ(&self, _pid: u32) -> std::result::Result<Vec<String>, String> {
        Ok(Vec::new())
    }
    /// Lot 2.3b: the SHA-256 of each regular file it holds open (at most
    /// [`MAX_DIGESTED_FDS`] descriptors, each file at most
    /// [`MAX_SCRIPT_BYTES`]).
    fn open_file_digests(&self, _pid: u32) -> std::result::Result<Vec<[u8; 32]>, String> {
        Ok(Vec::new())
    }
    /// Lot 2.3b: the SHA-256 of the file `arg` names for `pid` (relative
    /// to its working directory), when it is a regular file of at most
    /// [`MAX_SCRIPT_BYTES`].
    fn arg_file_digest(&self, _pid: u32, _arg: &str) -> Option<[u8; 32]> {
        None
    }
    /// Lot 2.3b (D5): the objects the window freezes against outsiders,
    /// as this host has them ([`freeze_plan`]).
    fn freeze_plan(&self) -> std::result::Result<Vec<FreezeMark>, String> {
        Ok(Vec::new())
    }
    /// Lot 2.3b (D5): PID 1's manager environment (systemd's
    /// `Environment`, what `systemctl set-environment` changes).
    fn pid1_env(&self) -> std::result::Result<Vec<String>, String> {
        Ok(Vec::new())
    }
}

/// Lot 2.3b: the most descriptors of a script root whose files are hashed.
pub const MAX_DIGESTED_FDS: usize = 64;
/// Lot 2.3b: the largest script the admission hashes.
pub const MAX_SCRIPT_BYTES: u64 = 4 << 20;

/// Lot 2.3b: a handle on a process taken before it is read ([`LineReader::pin`]).
pub trait ProcPin {
    /// Whether the pid still names the process the handle was taken on.
    fn alive(&self) -> bool;
}

struct AlwaysAlive;

impl ProcPin for AlwaysAlive {
    fn alive(&self) -> bool {
        true
    }
}

/// Lot 2.3b: a pidfd (`pidfd_open`, 5.3+), closed on drop. The kernel
/// keeps it on the process it was opened for: a pid reused since names
/// another process, and this one answers "gone".
pub struct Pidfd(std::os::fd::OwnedFd);

impl Pidfd {
    /// `pidfd_open(pid, 0)`.
    pub fn open(pid: u32) -> std::result::Result<Self, String> {
        let pid = libc::pid_t::try_from(pid).map_err(|_| format!("pid {pid} out of range"))?;
        // SAFETY: a syscall with two integer arguments; the descriptor it
        // returns, if any, is owned here.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if fd < 0 {
            return Err(format!(
                "pidfd_open({pid}): {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: a fresh descriptor the kernel just returned to us.
        Ok(Self(unsafe {
            <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd as i32)
        }))
    }
}

impl ProcPin for Pidfd {
    fn alive(&self) -> bool {
        use std::os::fd::AsRawFd;
        // SAFETY: signal 0 (a liveness test, no signal is sent) through our
        // own descriptor, no siginfo.
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.0.as_raw_fd(),
                0,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            ) == 0
        }
    }
}

/// Lot 2.3b (D5): one object the window freezes against outsiders, as the
/// kernel keys it: by its inode (`FROZEN_INODES`), or by its name in its
/// directory (`FROZEN_NAMES`), with its reach (`FROZEN_SUBTREE`,
/// `FROZEN_SELF`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreezeMark {
    Inode(InodeKey, u64),
    Name(common::wire::FrozenName, u64),
}

/// Lot 2.3b (D5): the window's frozen objects
/// (`nn_core::anti_tamper::trusted_installer::FROZEN`) as `stat` (an
/// object's key, `None` when it does not exist) finds them: each existing
/// object by its inode — one mark per inode, the reaches joined (`/bin` is
/// `/usr/bin` on a merged-`/usr` host) — and each name of
/// `frozen_names()` in its existing parent.
pub fn freeze_plan(stat: &dyn Fn(&Path) -> Option<InodeKey>) -> Vec<FreezeMark> {
    use nn_core::anti_tamper::trusted_installer::{FROZEN, Freeze, frozen_names};
    let reach = |h: Freeze| match h {
        Freeze::Subtree => common::wire::FROZEN_SUBTREE,
        Freeze::SelfOnly => common::wire::FROZEN_SELF,
    };
    let mut inodes: Vec<(InodeKey, u64)> = Vec::new();
    for (path, how) in FROZEN {
        if let Some(key) = stat(Path::new(path)) {
            match inodes.iter_mut().find(|(k, _)| *k == key) {
                Some((_, f)) => *f |= reach(*how),
                None => inodes.push((key, reach(*how))),
            }
        }
    }
    let mut out: Vec<FreezeMark> = inodes
        .into_iter()
        .map(|(k, f)| FreezeMark::Inode(k, f))
        .collect();
    for (parent, name, how) in frozen_names() {
        if let Some(dir) = stat(Path::new(parent)) {
            out.push(FreezeMark::Name(
                common::wire::FrozenName {
                    dir,
                    name: common::window_tree::name_words4(name.as_bytes()),
                },
                reach(how),
            ));
        }
    }
    out
}

/// A path's key as the kernel builds it (`stat`, following links).
fn stat_key(path: &Path) -> Option<InodeKey> {
    let m = antitamper_bpf::kernel_roots::metadata(path).ok()?;
    Some(InodeKey {
        dev: super::filesystem::stat_dev_to_kernel_dev(std::os::unix::fs::MetadataExt::dev(&m)),
        ino: std::os::unix::fs::MetadataExt::ino(&m),
    })
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

    fn pin(&self, pid: u32) -> std::result::Result<Box<dyn ProcPin>, String> {
        Ok(Box::new(Pidfd::open(pid)?))
    }

    fn ns_initial(&self, pid: u32) -> std::result::Result<bool, String> {
        use std::os::unix::fs::MetadataExt;
        for ns in ["pid", "user", "mnt"] {
            let id = |p: &str| {
                std::fs::metadata(self.0.join(p).join("ns").join(ns))
                    .map(|m| (m.dev(), m.ino()))
                    .map_err(|e| format!("/proc/{p}/ns/{ns}: {e}"))
            };
            if id(&pid.to_string())? != id("1")? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn exe(&self, pid: u32) -> std::result::Result<((u64, u64), String), String> {
        use std::os::unix::fs::MetadataExt;
        let link = self.0.join(pid.to_string()).join("exe");
        let m = std::fs::metadata(&link).map_err(|e| format!("/proc/{pid}/exe: {e}"))?;
        let path = std::fs::read_link(&link).map_err(|e| format!("/proc/{pid}/exe: {e}"))?;
        Ok(((m.dev(), m.ino()), path.to_string_lossy().into_owned()))
    }

    fn cmdline(&self, pid: u32) -> std::result::Result<Vec<String>, String> {
        let raw = std::fs::read(self.0.join(pid.to_string()).join("cmdline"))
            .map_err(|e| format!("/proc/{pid}/cmdline: {e}"))?;
        Ok(nul_split(&raw))
    }

    fn environ(&self, pid: u32) -> std::result::Result<Vec<String>, String> {
        use std::io::Read;
        let mut raw = Vec::new();
        std::fs::File::open(self.0.join(pid.to_string()).join("environ"))
            .and_then(|f| f.take(64 * 1024).read_to_end(&mut raw))
            .map_err(|e| format!("/proc/{pid}/environ: {e}"))?;
        Ok(nul_split(&raw))
    }

    fn open_file_digests(&self, pid: u32) -> std::result::Result<Vec<[u8; 32]>, String> {
        let dir = self.0.join(pid.to_string()).join("fd");
        let entries = std::fs::read_dir(&dir).map_err(|e| format!("/proc/{pid}/fd: {e}"))?;
        Ok(entries
            .flatten()
            .take(MAX_DIGESTED_FDS)
            .filter_map(|e| file_digest(&e.path()))
            .collect())
    }

    fn arg_file_digest(&self, pid: u32, arg: &str) -> Option<[u8; 32]> {
        let p = Path::new(arg);
        let path = if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.0.join(pid.to_string()).join("cwd").join(p)
        };
        file_digest(&path)
    }

    fn freeze_plan(&self) -> std::result::Result<Vec<FreezeMark>, String> {
        Ok(freeze_plan(&stat_key))
    }

    fn pid1_env(&self) -> std::result::Result<Vec<String>, String> {
        let v = crate::systemd_state::manager_property(
            Path::new(crate::systemd_state::PRIVATE_SOCKET),
            Duration::from_secs(2),
            "Environment",
        )
        .map_err(|e| format!("PID 1's Environment: {e}"))?;
        v.strings()
            .ok_or_else(|| "PID 1's Environment: not a list of strings".to_string())
    }
}

/// The NUL-separated strings of a `/proc` file (`cmdline`, `environ`).
fn nul_split(raw: &[u8]) -> Vec<String> {
    raw.split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

/// The SHA-256 of the regular file at `path` (followed), when it is at
/// most [`MAX_SCRIPT_BYTES`].
fn file_digest(path: &Path) -> Option<[u8; 32]> {
    use sha2::Digest;
    use std::io::Read;
    let f = std::fs::File::open(path).ok()?;
    let m = f.metadata().ok()?;
    if !m.is_file() || m.len() > MAX_SCRIPT_BYTES {
        return None;
    }
    let mut buf = Vec::new();
    f.take(MAX_SCRIPT_BYTES + 1).read_to_end(&mut buf).ok()?;
    if buf.len() as u64 > MAX_SCRIPT_BYTES {
        return None;
    }
    Some(sha2::Sha256::digest(&buf).into())
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

/// The line from the requester (`SO_PEERCRED` pid) up through its parents
/// to the signed `root` (`(pid, start_ticks)`), root first, each with its
/// start, every process pinned ([`LineReader::pin`]) before it is read and
/// checked still alive after the walk. Refused (`Err`, why): a root that
/// is PID 1 or 0, not on the line within [`MAX_TREE_LINE`] processes, or
/// whose start differs from the signed one (another process took its pid);
/// a line that holds a kernel thread, a traced or seccomp-filtered process,
/// a process outside the initial pid, user or mount namespace (lot 2.3b),
/// or one of the agent's own (`own`: [`TrustedInstallerOverride::own_tgids`]);
/// a root whose parent is one of the agent's own (its worker); any process
/// on it that cannot be read, or that exited during the walk. Lot 2.3b's
/// admission policy ([`admit_line`]) then judges the root's kind.
pub fn line_to_root(
    reader: &dyn LineReader,
    requester: u32,
    root: (u32, u64),
    own: &[u32],
) -> std::result::Result<Vec<(u32, u64)>, String> {
    let mut pins = Vec::new();
    let line = walk_line(reader, requester, root, own, &mut pins)?;
    check_pins(&line, &pins)?;
    Ok(line)
}

/// Every pinned process of the line still alive (lot 2.3b: the pidfds
/// taken before the reads; a pid reused meanwhile is another process).
fn check_pins(line: &[(u32, u64)], pins: &[(u32, Box<dyn ProcPin>)]) -> std::result::Result<(), String> {
    for (pid, pin) in pins {
        if !pin.alive() {
            return Err(format!(
                "process {pid} on the line exited during the admission (its pidfd names no live \
                 process: {} on the line)",
                line.len()
            ));
        }
    }
    Ok(())
}

/// [`line_to_root`]'s walk, each process pinned into `pins` first.
fn walk_line(
    reader: &dyn LineReader,
    requester: u32,
    root: (u32, u64),
    own: &[u32],
    pins: &mut Vec<(u32, Box<dyn ProcPin>)>,
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
        pins.push((pid, reader.pin(pid)?));
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
        if !reader.ns_initial(pid)? {
            return Err(format!(
                "process {pid} on the line is outside the initial pid, user or mount namespace"
            ));
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

/// Lot 2.3b: the signed request's root as the admission policy judges it
/// (`TrustedInstallerTreeGrantExtra`'s root, its kind and its script's
/// digest).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeRoot {
    pub pid: u32,
    pub start_ticks: u64,
    pub kind: TreeRootKind,
    pub script_sha256: [u8; 32],
}

/// Lot 2.3b (D3, the admission policy; the design's section 1): the line
/// from `requester` to `root` ([`line_to_root`]'s refusals), then the
/// root's kind — the agent admits only these roots, every other refused
/// with its reason:
///
/// - **`window-run`:** the root is the requester itself, and runs the
///   installed `nn-admin` (`installed_admin`: its `(st_dev, st_ino)`; the
///   one beside the agent's binary).
/// - **our `install.sh`:** the root is the requester's parent, a system
///   shell started with a script (an argument of its command line) whose
///   SHA-256 is the signed one, a file it also holds open.
/// - **a package manager:** the root runs a package manager's packaged
///   program (`dpkg`, `rpm`, `dnf`, …), every process between it and the
///   requester is a system shell, and one of them is our package's
///   scriptlet (dpkg's or rpm's variables naming our package).
///
/// So a session daemon, a subreaper, a terminal multiplexer, `systemd
/// --user` or an interactive shell is never a root: the allowlist refuses
/// them, not a denylist. Every process is pinned before it is read and
/// checked alive after every read.
pub fn admit_line(
    reader: &dyn LineReader,
    requester: u32,
    root: &TreeRoot,
    own: &[u32],
    installed_admin: Option<(u64, u64)>,
) -> std::result::Result<Vec<(u32, u64)>, String> {
    use nn_core::anti_tamper::trusted_installer::{
        is_our_scriptlet_env, is_system_shell, package_manager,
    };
    let mut pins = Vec::new();
    let line = walk_line(reader, requester, (root.pid, root.start_ticks), own, &mut pins)?;
    let kind = root.kind.as_str();
    match root.kind {
        TreeRootKind::WindowRun => {
            if line.len() != 1 {
                return Err(format!(
                    "a {kind} root is the requesting nn-admin itself (the line holds {} processes)",
                    line.len()
                ));
            }
            let (exe_id, exe) = reader.exe(root.pid)?;
            match installed_admin {
                Some(id) if id == exe_id => {}
                Some(_) => {
                    return Err(format!(
                        "the {kind} root {} runs {exe}, not the installed nn-admin",
                        root.pid
                    ));
                }
                None => {
                    return Err("the installed nn-admin could not be read: no window-run".to_string());
                }
            }
        }
        TreeRootKind::InstallScript => {
            if line.len() != 2 {
                return Err(format!(
                    "an {kind} root is the requester's parent (the line holds {} processes)",
                    line.len()
                ));
            }
            let (_, exe) = reader.exe(root.pid)?;
            if !is_system_shell(&exe) {
                return Err(format!("the {kind} root {} runs {exe}, not a system shell", root.pid));
            }
            if root.script_sha256 == [0; 32] {
                return Err(format!("an {kind} grant names no script digest"));
            }
            let args = reader.cmdline(root.pid)?;
            let started_with = args
                .iter()
                .skip(1)
                .any(|a| reader.arg_file_digest(root.pid, a) == Some(root.script_sha256));
            if !started_with {
                return Err(format!(
                    "the {kind} root {} was not started with the signed script (no argument of \
                     its command line has that digest)",
                    root.pid
                ));
            }
            if !reader.open_file_digests(root.pid)?.contains(&root.script_sha256) {
                return Err(format!(
                    "the {kind} root {} does not hold the signed script open",
                    root.pid
                ));
            }
        }
        TreeRootKind::PackageManager => {
            if line.len() < 2 {
                return Err(format!(
                    "a {kind} root is above its scriptlet (the line holds {} process)",
                    line.len()
                ));
            }
            let (_, exe) = reader.exe(root.pid)?;
            let args = reader.cmdline(root.pid)?;
            if package_manager(&exe, &args).is_none() {
                return Err(format!(
                    "the {kind} root {} runs {exe}, not a package manager's packaged program",
                    root.pid
                ));
            }
            let mut scriptlet = false;
            for &(pid, _) in &line[1..line.len() - 1] {
                let (_, e) = reader.exe(pid)?;
                if !is_system_shell(&e) {
                    return Err(format!(
                        "process {pid} between the {kind} root and the requester runs {e}, not a \
                         system shell"
                    ));
                }
                scriptlet |= is_our_scriptlet_env(reader.environ(pid)?.iter().map(String::as_str));
            }
            if !scriptlet {
                return Err(format!(
                    "no process between the {kind} root and the requester is our package's \
                     scriptlet"
                ));
            }
        }
    }
    check_pins(&line, &pins)?;
    Ok(line)
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
    // lot 2.3b: the frozen marks and the leases of the window go with it
    // (a mark or a lease of another generation is void in the kernel anyway)
    if let Err(e) = maps.clear_frozen() {
        failed.push(format!("the frozen marks not emptied: {e}"));
    }
    if let Err(e) = maps.clear_leases() {
        failed.push(format!("{WINDOW_LEASES_MAP_NAME} not emptied: {e}"));
    }
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
    let frozen = maps.clear_frozen();
    match (maps.clear_members(), frozen) {
        (Ok(_), Ok(())) => why,
        (Err(e), _) => format!("{why} (and {TREE_MEMBERS_MAP_NAME} not emptied: {e})"),
        (_, Err(e)) => format!("{why} (and the frozen marks not emptied: {e})"),
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
    /// Lot 2.3b (D5): `FROZEN_INODES[key] = value` (`[generation, reach]`).
    fn put_frozen_inode(
        &mut self,
        _key: InodeKey,
        _value: [u64; 2],
    ) -> std::result::Result<(), String> {
        Ok(())
    }
    /// Lot 2.3b (D5): `FROZEN_NAMES[name] = value`.
    fn put_frozen_name(
        &mut self,
        _name: common::wire::FrozenName,
        _value: [u64; 2],
    ) -> std::result::Result<(), String> {
        Ok(())
    }
    /// Lot 2.3b (D5): both frozen maps emptied.
    fn clear_frozen(&mut self) -> std::result::Result<(), String> {
        Ok(())
    }
    /// Lot 2.3b: `TREE_MEMBERS[tgid]`.
    fn member(&mut self, _tgid: u32) -> std::result::Result<Option<TreeMember>, String> {
        Ok(None)
    }
    /// Lot 2.3b: the lease slots, in order.
    fn leases(&mut self) -> std::result::Result<Vec<WindowLease>, String> {
        Ok(Vec::new())
    }
    /// Lot 2.3b: `WINDOW_LEASES[slot] = lease`.
    fn put_lease(&mut self, _slot: u32, _lease: WindowLease) -> std::result::Result<(), String> {
        Ok(())
    }
    /// Lot 2.3b: every lease slot zeroed.
    fn clear_leases(&mut self) -> std::result::Result<(), String> {
        Ok(())
    }
    /// Lot 2.3b: `INODE_EXT[key]` (a directory of our units' links).
    fn inode_ext(&mut self, _key: InodeKey) -> std::result::Result<Option<u8>, String> {
        Ok(None)
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

    fn put_frozen_inode(
        &mut self,
        key: InodeKey,
        value: [u64; 2],
    ) -> std::result::Result<(), String> {
        let mut m: aya::maps::HashMap<MapData, super::filesystem::AyaInodeKey, [u64; 2]> =
            aya::maps::HashMap::try_from(AyaMap::HashMap(self.open(FROZEN_INODES_MAP_NAME)?))
                .map_err(|e| e.to_string())?;
        m.insert(&super::filesystem::AyaInodeKey(key), &value, 0)
            .map_err(|e| e.to_string())
    }

    fn put_frozen_name(
        &mut self,
        name: common::wire::FrozenName,
        value: [u64; 2],
    ) -> std::result::Result<(), String> {
        let mut m: aya::maps::HashMap<MapData, PodFrozenName, [u64; 2]> =
            aya::maps::HashMap::try_from(AyaMap::HashMap(self.open(FROZEN_NAMES_MAP_NAME)?))
                .map_err(|e| e.to_string())?;
        m.insert(&PodFrozenName(name), &value, 0)
            .map_err(|e| e.to_string())
    }

    fn clear_frozen(&mut self) -> std::result::Result<(), String> {
        let mut i: aya::maps::HashMap<MapData, super::filesystem::AyaInodeKey, [u64; 2]> =
            aya::maps::HashMap::try_from(AyaMap::HashMap(self.open(FROZEN_INODES_MAP_NAME)?))
                .map_err(|e| e.to_string())?;
        let keys: Vec<super::filesystem::AyaInodeKey> =
            i.keys().filter_map(std::result::Result::ok).collect();
        for k in &keys {
            i.remove(k).map_err(|e| e.to_string())?;
        }
        let mut n: aya::maps::HashMap<MapData, PodFrozenName, [u64; 2]> =
            aya::maps::HashMap::try_from(AyaMap::HashMap(self.open(FROZEN_NAMES_MAP_NAME)?))
                .map_err(|e| e.to_string())?;
        let names: Vec<PodFrozenName> = n.keys().filter_map(std::result::Result::ok).collect();
        for k in &names {
            n.remove(k).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn member(&mut self, tgid: u32) -> std::result::Result<Option<TreeMember>, String> {
        match self.members()?.get(&tgid, 0) {
            Ok(m) => Ok(Some(m.0)),
            Err(aya::maps::MapError::KeyNotFound) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    fn leases(&mut self) -> std::result::Result<Vec<WindowLease>, String> {
        let a = self.lease_slots()?;
        (0..WINDOW_LEASES_MAX)
            .map(|i| a.get(&i, 0).map(|l| l.0).map_err(|e| e.to_string()))
            .collect()
    }

    fn put_lease(&mut self, slot: u32, lease: WindowLease) -> std::result::Result<(), String> {
        self.lease_slots()?
            .set(slot, &PodLease(lease), 0)
            .map_err(|e| e.to_string())
    }

    fn clear_leases(&mut self) -> std::result::Result<(), String> {
        let mut a = self.lease_slots()?;
        for i in 0..WINDOW_LEASES_MAX {
            a.set(i, &PodLease(bytemuck::Zeroable::zeroed()), 0)
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn inode_ext(&mut self, key: InodeKey) -> std::result::Result<Option<u8>, String> {
        let m: aya::maps::HashMap<MapData, super::filesystem::AyaInodeKey, u8> =
            aya::maps::HashMap::try_from(AyaMap::HashMap(self.open(INODE_EXT_MAP_NAME)?))
                .map_err(|e| e.to_string())?;
        match m.get(&super::filesystem::AyaInodeKey(key), 0) {
            Ok(v) => Ok(Some(v)),
            Err(aya::maps::MapError::KeyNotFound) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
}

impl PinnedTreeMaps<'_> {
    fn lease_slots(&self) -> std::result::Result<AyaArray<MapData, PodLease>, String> {
        AyaArray::try_from(AyaMap::Array(self.open(WINDOW_LEASES_MAP_NAME)?))
            .map_err(|e| e.to_string())
    }
}

#[derive(Clone, Copy)]
#[repr(transparent)]
struct PodFrozenName(common::wire::FrozenName);
// SAFETY: `FrozenName` is `repr(C)`, `bytemuck::Pod`; the wrapper is
// `repr(transparent)`.
unsafe impl aya::Pod for PodFrozenName {}

#[derive(Clone, Copy)]
#[repr(transparent)]
struct PodLease(WindowLease);
// SAFETY: `WindowLease` is `repr(C)`, `bytemuck::Pod`; as above.
unsafe impl aya::Pod for PodLease {}

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
        cgroup_files: Vec<(InodeKey, [u64; 2])>,
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
        fn put_cgroup_file(
            &mut self,
            key: InodeKey,
            value: [u64; 2],
        ) -> std::result::Result<(), String> {
            self.ops
                .push(format!("cgroup file {} op {}", key.ino, value[1]));
            self.cgroup_files.push((key, value));
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

    /// A [`LineReader`] whose root's cgroup files are `files`.
    struct CgroupReader(FakeProc, std::result::Result<Vec<(InodeKey, u8)>, String>);

    impl LineReader for CgroupReader {
        fn hop(&self, pid: u32) -> std::result::Result<ProcHop, String> {
            self.0.hop(pid)
        }
        fn guards(&self, pid: u32) -> std::result::Result<(u32, u32), String> {
            self.0.guards(pid)
        }
        fn cgroup_files(&self, pid: u32) -> std::result::Result<Vec<(InodeKey, u8)>, String> {
            assert_eq!(pid, 501, "the root's");
            self.1.clone()
        }
    }

    /// Lot 2.3a (D7, the review of #647): the root's cgroup files are
    /// written with the generation and their operation after the members,
    /// before the grant; a root whose cgroup cannot be read is refused its
    /// grant (fail closed), the members withdrawn.
    #[test]
    fn the_root_s_cgroup_files_are_armed_with_the_window_and_an_unread_cgroup_refuses_it() {
        let kill = common::wire::FS_OP_CGROUP_KILL;
        let freeze = common::wire::FS_OP_CGROUP_FREEZE;
        let k = |ino| InodeKey { dev: 7, ino };
        let ov = tree_override();
        let mut maps = FakeMaps::default();
        let reader = CgroupReader(host(), Ok(vec![(k(30), kill), (k(31), freeze)]));
        let g = ov
            .arm_tree_with(
                Some(&mut maps),
                &reader,
                &[],
                NOW,
                120,
                (501, 9_000),
                &line(),
            )
            .expect("armed");
        assert_eq!(
            maps.cgroup_files,
            vec![
                (k(30), [g, u64::from(kill)]),
                (k(31), [g, u64::from(freeze)])
            ]
        );
        let files = maps
            .ops
            .iter()
            .position(|o| o.starts_with("cgroup file"))
            .unwrap();
        let grant = maps
            .ops
            .iter()
            .position(|o| o.starts_with("grant"))
            .unwrap();
        let last_member = maps
            .ops
            .iter()
            .rposition(|o| o.starts_with("member"))
            .unwrap();
        assert!(last_member < files && files < grant, "{:?}", maps.ops);

        let ov = tree_override();
        let mut maps = FakeMaps::default();
        let reader = CgroupReader(host(), Err("/proc/501/cgroup: EACCES".to_string()));
        let e = ov
            .arm_tree_with(
                Some(&mut maps),
                &reader,
                &[],
                NOW,
                120,
                (501, 9_000),
                &line(),
            )
            .unwrap_err();
        assert!(e.contains("the root's cgroup files"), "{e}");
        assert!(maps.members.is_empty(), "the members withdrawn");
        assert!(
            !maps.ops.iter().any(|o| o.starts_with("grant")),
            "{:?}",
            maps.ops
        );
    }

    // ── Lot 2.3b: the admission policy, the freeze, the leases, the stop ──

    use std::cell::{Cell, RefCell};

    /// A `/proc` with what the admission reads besides the walk: each
    /// pid's executable, command line, environment, open files' digests,
    /// namespaces, and whether its pidfd still names it after the walk.
    struct FlowProc {
        base: FakeProc,
        exe: BTreeMap<u32, ((u64, u64), String)>,
        cmdline: BTreeMap<u32, Vec<String>>,
        environ: BTreeMap<u32, Vec<String>>,
        digests: BTreeMap<u32, Vec<[u8; 32]>>,
        args: BTreeMap<(u32, String), [u8; 32]>,
        foreign_ns: Vec<u32>,
        dies: Vec<u32>,
        freeze: Vec<FreezeMark>,
        pid1_env: RefCell<std::result::Result<Vec<String>, String>>,
        pins: Cell<usize>,
    }

    impl Default for FlowProc {
        fn default() -> Self {
            Self {
                base: FakeProc::default(),
                exe: BTreeMap::new(),
                cmdline: BTreeMap::new(),
                environ: BTreeMap::new(),
                digests: BTreeMap::new(),
                args: BTreeMap::new(),
                foreign_ns: Vec::new(),
                dies: Vec::new(),
                freeze: Vec::new(),
                pid1_env: RefCell::new(Ok(Vec::new())),
                pins: Cell::new(0),
            }
        }
    }

    struct FakePin(bool);
    impl ProcPin for FakePin {
        fn alive(&self) -> bool {
            self.0
        }
    }

    impl LineReader for FlowProc {
        fn hop(&self, pid: u32) -> std::result::Result<ProcHop, String> {
            self.base.hop(pid)
        }
        fn guards(&self, pid: u32) -> std::result::Result<(u32, u32), String> {
            self.base.guards(pid)
        }
        fn pin(&self, pid: u32) -> std::result::Result<Box<dyn ProcPin>, String> {
            self.pins.set(self.pins.get() + 1);
            Ok(Box::new(FakePin(!self.dies.contains(&pid))))
        }
        fn ns_initial(&self, pid: u32) -> std::result::Result<bool, String> {
            Ok(!self.foreign_ns.contains(&pid))
        }
        fn exe(&self, pid: u32) -> std::result::Result<((u64, u64), String), String> {
            self.exe.get(&pid).cloned().ok_or_else(|| format!("{pid}: no exe"))
        }
        fn cmdline(&self, pid: u32) -> std::result::Result<Vec<String>, String> {
            Ok(self.cmdline.get(&pid).cloned().unwrap_or_default())
        }
        fn environ(&self, pid: u32) -> std::result::Result<Vec<String>, String> {
            Ok(self.environ.get(&pid).cloned().unwrap_or_default())
        }
        fn open_file_digests(&self, pid: u32) -> std::result::Result<Vec<[u8; 32]>, String> {
            Ok(self.digests.get(&pid).cloned().unwrap_or_default())
        }
        fn arg_file_digest(&self, pid: u32, arg: &str) -> Option<[u8; 32]> {
            self.args.get(&(pid, arg.to_string())).copied()
        }
        fn freeze_plan(&self) -> std::result::Result<Vec<FreezeMark>, String> {
            Ok(self.freeze.clone())
        }
        fn pid1_env(&self) -> std::result::Result<Vec<String>, String> {
            self.pid1_env.borrow().clone()
        }
    }

    const ADMIN: (u64, u64) = (0x803, 4242);
    const SCRIPT: [u8; 32] = [0x5c; 32];

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// window-run: nn-admin (700, started 7000) under a login shell (600).
    fn window_run_host() -> FlowProc {
        let mut f = FlowProc {
            base: FakeProc::default().with(600, 1, 6_000).with(700, 600, 7_000),
            pid1_env: RefCell::new(Ok(strs(&["LANG=C.UTF-8"]))),
            ..FlowProc::default()
        };
        f.exe.insert(700, (ADMIN, "/usr/local/bin/nn-admin".to_string()));
        f.exe.insert(600, ((0x803, 1), "/usr/bin/bash".to_string()));
        f
    }

    fn root(pid: u32, start_ticks: u64, kind: TreeRootKind) -> TreeRoot {
        TreeRoot {
            pid,
            start_ticks,
            kind,
            script_sha256: SCRIPT,
        }
    }

    /// Lot 2.3b (D2, D3): a window-run's root is the requesting nn-admin
    /// itself, the installed one by its image; every process is pinned
    /// before it is read and must still be alive after.
    #[test]
    fn a_window_run_root_is_the_installed_nn_admin_requesting_itself() {
        let host = window_run_host();
        let r = root(700, 7_000, TreeRootKind::WindowRun);
        assert_eq!(admit_line(&host, 700, &r, &[], Some(ADMIN)), Ok(vec![(700, 7_000)]));
        assert_eq!(host.pins.get(), 1, "pinned before it is read");
        // another nn-admin (a copy elsewhere), no installed one, a root that
        // is not the requester (the login shell)
        let e = admit_line(&host, 700, &r, &[], Some((0x803, 1))).unwrap_err();
        assert!(e.contains("not the installed nn-admin"), "{e}");
        let e = admit_line(&host, 700, &r, &[], None).unwrap_err();
        assert!(e.contains("could not be read"), "{e}");
        let e = admit_line(&host, 700, &root(600, 6_000, TreeRootKind::WindowRun), &[], Some(ADMIN))
            .unwrap_err();
        assert!(e.contains("requesting nn-admin itself"), "{e}");
        // its pidfd names no live process after the reads
        let mut dying = window_run_host();
        dying.dies.push(700);
        let e = admit_line(&dying, 700, &r, &[], Some(ADMIN)).unwrap_err();
        assert!(e.contains("exited during the admission"), "{e}");
        // outside the initial namespaces
        let mut ns = window_run_host();
        ns.foreign_ns.push(700);
        let e = admit_line(&ns, 700, &r, &[], Some(ADMIN)).unwrap_err();
        assert!(e.contains("initial pid, user or mount namespace"), "{e}");
        // traced, filtered
        for (t, sc) in [(9, 0), (0, 2)] {
            let mut g = window_run_host();
            g.base = g.base.guarded(700, t, sc);
            assert!(admit_line(&g, 700, &r, &[], Some(ADMIN)).is_err());
        }
    }

    /// install.sh: bash (501) runs the script, nn-admin (502) asks.
    fn script_host() -> FlowProc {
        let mut f = FlowProc {
            base: FakeProc::default()
                .with(400, 1, 100)
                .with(501, 400, 9_000)
                .with(502, 501, 9_100),
            ..FlowProc::default()
        };
        f.exe.insert(501, ((0x803, 2), "/usr/bin/bash".to_string()));
        f.exe.insert(502, ((0x803, 3), "/opt/release/nn-admin".to_string()));
        f.cmdline.insert(501, strs(&["bash", "./install.sh", "--upgrade"]));
        f.args.insert((501, "./install.sh".to_string()), SCRIPT);
        f.digests.insert(501, vec![[1; 32], SCRIPT]);
        f
    }

    /// Lot 2.3b (D3): our install.sh is a system shell started with the
    /// signed script, holding it open, the requester's parent.
    #[test]
    fn an_install_script_root_is_a_shell_started_with_the_signed_script() {
        let r = root(501, 9_000, TreeRootKind::InstallScript);
        assert_eq!(
            admit_line(&script_host(), 502, &r, &[], None),
            Ok(vec![(501, 9_000), (502, 9_100)])
        );
        // an interactive shell that merely holds the script open
        let mut i = script_host();
        i.cmdline.insert(501, strs(&["-bash"]));
        let e = admit_line(&i, 502, &r, &[], None).unwrap_err();
        assert!(e.contains("not started with the signed script"), "{e}");
        // started with it but no longer holding it (another file in its place)
        let mut c = script_host();
        c.digests.insert(501, vec![[1; 32]]);
        let e = admit_line(&c, 502, &r, &[], None).unwrap_err();
        assert!(e.contains("does not hold the signed script open"), "{e}");
        // another digest signed, none signed
        let e = admit_line(&script_host(), 502, &TreeRoot { script_sha256: [2; 32], ..r }, &[], None)
            .unwrap_err();
        assert!(e.contains("not started with the signed script"), "{e}");
        let e = admit_line(&script_host(), 502, &TreeRoot { script_sha256: [0; 32], ..r }, &[], None)
            .unwrap_err();
        assert!(e.contains("no script digest"), "{e}");
        // not a system shell (sshd, tmux, a shell copied to /tmp)
        for exe in ["/usr/sbin/sshd", "/usr/bin/tmux", "/tmp/bash"] {
            let mut n = script_host();
            n.exe.insert(501, ((0x803, 2), exe.to_string()));
            let e = admit_line(&n, 502, &r, &[], None).unwrap_err();
            assert!(e.contains("not a system shell"), "{exe}: {e}");
        }
        // the grandparent instead of the parent
        let e = admit_line(&script_host(), 502, &root(400, 100, TreeRootKind::InstallScript), &[], None)
            .unwrap_err();
        assert!(e.contains("requester's parent"), "{e}");
    }

    /// dpkg (300) runs our preinst (310, dash), which runs install.sh
    /// (320, bash), which runs nn-admin (330).
    fn package_host() -> FlowProc {
        let mut f = FlowProc {
            base: FakeProc::default()
                .with(290, 1, 50)
                .with(300, 290, 3_000)
                .with(310, 300, 3_100)
                .with(320, 310, 3_200)
                .with(330, 320, 3_300),
            ..FlowProc::default()
        };
        f.exe.insert(300, ((0x803, 10), "/usr/bin/dpkg".to_string()));
        f.cmdline.insert(300, strs(&["dpkg", "-i", "northnarrow.deb"]));
        f.exe.insert(310, ((0x803, 11), "/usr/bin/dash".to_string()));
        f.exe.insert(320, ((0x803, 12), "/usr/bin/bash".to_string()));
        f.environ.insert(
            310,
            strs(&["DPKG_MAINTSCRIPT_PACKAGE=northnarrow", "DPKG_MAINTSCRIPT_NAME=preinst"]),
        );
        f
    }

    /// Lot 2.3b (D3): a package manager's process roots a window only for
    /// our package's scriptlet, through system shells.
    #[test]
    fn a_package_manager_root_runs_its_packaged_program_for_our_scriptlet() {
        let r = root(300, 3_000, TreeRootKind::PackageManager);
        assert_eq!(admit_line(&package_host(), 330, &r, &[], None).map(|l| l.len()), Ok(4));
        // another package's scriptlet
        let mut o = package_host();
        o.environ.insert(310, strs(&["DPKG_MAINTSCRIPT_PACKAGE=other"]));
        let e = admit_line(&o, 330, &r, &[], None).unwrap_err();
        assert!(e.contains("our package's scriptlet"), "{e}");
        // a process between them that is not a shell (a terminal multiplexer)
        let mut m = package_host();
        m.exe.insert(320, ((0x803, 13), "/usr/bin/tmux".to_string()));
        let e = admit_line(&m, 330, &r, &[], None).unwrap_err();
        assert!(e.contains("not a system shell"), "{e}");
        // not a package manager (cron, a user's copy of dpkg)
        for exe in ["/usr/sbin/cron", "/tmp/dpkg"] {
            let mut n = package_host();
            n.exe.insert(300, ((0x803, 10), exe.to_string()));
            let e = admit_line(&n, 330, &r, &[], None).unwrap_err();
            assert!(e.contains("not a package manager"), "{exe}: {e}");
        }
        // the scriptlet's parent's parent (the session above dpkg)
        let mut s = package_host();
        s.exe.insert(290, ((0x803, 14), "/usr/sbin/sshd".to_string()));
        assert!(admit_line(&s, 330, &root(290, 50, TreeRootKind::PackageManager), &[], None).is_err());
        // the line's processes are pinned, each before its read
        let p = package_host();
        admit_line(&p, 330, &r, &[], None).unwrap();
        assert_eq!(p.pins.get(), 4);
    }

    /// Lot 2.3b (D5): the plan freezes each existing object by its inode,
    /// one mark per inode with the reaches joined, and each name in its
    /// existing parent.
    #[test]
    fn the_freeze_plan_marks_inodes_once_and_names_in_their_parents() {
        use common::wire::{FROZEN_SELF, FROZEN_SUBTREE};
        let key = |ino| InodeKey { dev: 8, ino };
        // a merged-/usr host: /bin is /usr/bin; no /etc/ld.so.preload
        let stat = |p: &Path| -> Option<InodeKey> {
            match p.to_str()? {
                "/usr/bin" | "/bin" => Some(key(10)),
                "/usr" => Some(key(2)),
                "/etc" => Some(key(3)),
                "/etc/ld.so.preload" => None,
                "/etc/ld.so.cache" => Some(key(30)),
                "/" => Some(key(1)),
                _ => None,
            }
        };
        let plan = freeze_plan(&stat);
        let inodes: Vec<(InodeKey, u64)> = plan
            .iter()
            .filter_map(|m| match m {
                FreezeMark::Inode(k, f) => Some((*k, *f)),
                FreezeMark::Name(..) => None,
            })
            .collect();
        assert_eq!(inodes.iter().filter(|(k, _)| *k == key(10)).count(), 1);
        assert!(inodes.contains(&(key(10), FROZEN_SUBTREE)));
        assert!(inodes.contains(&(key(2), FROZEN_SELF)));
        assert!(inodes.contains(&(key(30), FROZEN_SUBTREE)));
        let name = |dir, n: &str| common::wire::FrozenName {
            dir,
            name: common::window_tree::name_words4(n.as_bytes()),
        };
        assert!(plan.contains(&FreezeMark::Name(name(key(3), "ld.so.preload"), FROZEN_SUBTREE)));
        assert!(plan.contains(&FreezeMark::Name(name(key(1), "bin"), FROZEN_SUBTREE)));
        assert!(plan.contains(&FreezeMark::Name(name(key(1), "usr"), FROZEN_SELF)));
        assert!(plan.contains(&FreezeMark::Name(name(key(2), "bin"), FROZEN_SUBTREE)));
    }

    /// The kernel's maps of lot 2.3b, recorded.
    #[derive(Default)]
    struct FlowMaps {
        base: FakeMaps,
        frozen: Vec<FreezeMark>,
        frozen_cleared: usize,
        leases: Vec<WindowLease>,
        leases_cleared: usize,
        ext: BTreeMap<(u64, u64), u8>,
    }

    impl TreeMaps for FlowMaps {
        fn put_member(&mut self, tgid: u32, m: TreeMember) -> std::result::Result<(), String> {
            self.base.put_member(tgid, m)
        }
        fn clear_members(&mut self) -> std::result::Result<usize, String> {
            self.base.clear_members()
        }
        fn write_grant(&mut self, g: FsGrantV2) -> std::result::Result<(), String> {
            self.base.write_grant(g)
        }
        fn read_closed(&mut self) -> std::result::Result<[u64; 2], String> {
            self.base.read_closed()
        }
        fn zero_closed(&mut self) -> std::result::Result<(), String> {
            self.base.zero_closed()
        }
        fn put_frozen_inode(&mut self, k: InodeKey, v: [u64; 2]) -> std::result::Result<(), String> {
            self.base.ops.push(format!("frozen inode {} gen {} reach {}", k.ino, v[0], v[1]));
            self.frozen.push(FreezeMark::Inode(k, v[1]));
            Ok(())
        }
        fn put_frozen_name(
            &mut self,
            n: common::wire::FrozenName,
            v: [u64; 2],
        ) -> std::result::Result<(), String> {
            self.base.ops.push(format!("frozen name in {} gen {}", n.dir.ino, v[0]));
            self.frozen.push(FreezeMark::Name(n, v[1]));
            Ok(())
        }
        fn clear_frozen(&mut self) -> std::result::Result<(), String> {
            self.frozen_cleared += 1;
            self.frozen.clear();
            Ok(())
        }
        fn member(&mut self, tgid: u32) -> std::result::Result<Option<TreeMember>, String> {
            Ok(self.base.members.get(&tgid).copied())
        }
        fn leases(&mut self) -> std::result::Result<Vec<WindowLease>, String> {
            if self.leases.is_empty() {
                self.leases = vec![bytemuck::Zeroable::zeroed(); WINDOW_LEASES_MAX as usize];
            }
            Ok(self.leases.clone())
        }
        fn put_lease(&mut self, slot: u32, l: WindowLease) -> std::result::Result<(), String> {
            self.leases[slot as usize] = l;
            Ok(())
        }
        fn clear_leases(&mut self) -> std::result::Result<(), String> {
            self.leases_cleared += 1;
            self.leases.clear();
            Ok(())
        }
        fn inode_ext(&mut self, k: InodeKey) -> std::result::Result<Option<u8>, String> {
            Ok(self.ext.get(&(k.dev, k.ino)).copied())
        }
    }

    fn flow_override() -> TrustedInstallerOverride {
        let ov = tree_override();
        // the walk's own reader holds no window; arm one on the fakes
        ov
    }

    /// Arm a window-run window on `maps` for nn-admin 700.
    fn arm_window_run(ov: &TrustedInstallerOverride, maps: &mut FlowMaps, host: &FlowProc) -> u64 {
        ov.arm_tree_noted(
            Some(maps),
            host,
            &[],
            NOW,
            (120, (700, 7_000), &[(700, 7_000)]),
            serde_json::json!({ "root_kind": "window-run" }),
        )
        .expect("armed")
    }

    /// Lot 2.3b (D5): the frozen marks are written with the members, before
    /// the second read and the grant, and go with the window — at its
    /// close, or when the arming is refused after them.
    #[test]
    fn the_frozen_marks_are_written_before_the_grant_and_go_with_the_window() {
        let key = InodeKey { dev: 8, ino: 10 };
        let mut host = window_run_host();
        host.freeze = vec![FreezeMark::Inode(key, common::wire::FROZEN_SUBTREE)];
        let ov = flow_override();
        let mut maps = FlowMaps::default();
        let g = arm_window_run(&ov, &mut maps, &host);
        let ops = &maps.base.ops;
        let frozen = ops.iter().position(|o| o.starts_with("frozen inode 10 gen 1")).unwrap();
        let grant = ops.iter().position(|o| o == "grant gen 1").unwrap();
        assert!(frozen < grant, "{ops:?}");
        assert!(ov.close_tree_with(&mut maps, "test"));
        assert!(maps.frozen.is_empty() && maps.frozen_cleared == 1 && maps.leases_cleared == 1);
        assert_eq!(g, 1);
        // refused after the marks (a tracer at the second read): withdrawn
        let ov = flow_override();
        let mut maps = FlowMaps::default();
        let mut traced = window_run_host();
        traced.freeze = host.freeze.clone();
        traced.base = traced.base.guarded(700, 9, 0);
        let r = ov.arm_tree_noted(
            Some(&mut maps),
            &traced,
            &[],
            NOW,
            (120, (700, 7_000), &[(700, 7_000)]),
            serde_json::Value::Null,
        );
        assert!(r.is_err());
        assert!(maps.frozen.is_empty() && maps.frozen_cleared >= 1);
        // PID 1's environment unread: refused, nothing left
        let ov = flow_override();
        let mut maps = FlowMaps::default();
        let unread = window_run_host();
        *unread.pid1_env.borrow_mut() = Err("no bus".to_string());
        let e = ov
            .arm_tree_noted(Some(&mut maps), &unread, &[], NOW, (120, (700, 7_000), &[(700, 7_000)]), serde_json::Value::Null)
            .unwrap_err();
        assert!(e.contains("PID 1's environment could not be read"), "{e}");
        assert!(maps.base.members.is_empty() && !ov.tree_window_open());
    }

    /// Lot 2.3b (D1): a member asks by its entry, its own start, the
    /// window's generation and its own state now; anyone else is refused.
    #[test]
    fn only_a_member_of_the_open_generation_is_authenticated() {
        let host = window_run_host();
        let ov = flow_override();
        let mut maps = FlowMaps::default();
        let g = arm_window_run(&ov, &mut maps, &host);
        assert_eq!(ov.window_member_with(&mut maps, &host, 700, g), Ok((700, 7_000)));
        // another generation, an outsider, PID 1, a reused pid
        assert!(ov.window_member_with(&mut maps, &host, 700, g + 1).is_err());
        let e = ov.window_member_with(&mut maps, &host, 600, g).unwrap_err();
        assert!(e.contains("outside the window's tree"), "{e}");
        assert!(ov.window_member_with(&mut maps, &host, 1, g).is_err());
        let reused = FlowProc {
            base: FakeProc::default().with(700, 600, 7_777),
            ..FlowProc::default()
        };
        let e = ov.window_member_with(&mut maps, &reused, 700, g).unwrap_err();
        assert!(e.contains("another process's start"), "{e}");
        // traced or filtered now, outside the namespaces, gone meanwhile
        let mut t = window_run_host();
        t.base = t.base.guarded(700, 9, 0);
        assert!(ov.window_member_with(&mut maps, &t, 700, g).is_err());
        let mut n = window_run_host();
        n.foreign_ns.push(700);
        assert!(ov.window_member_with(&mut maps, &n, 700, g).is_err());
        let mut d = window_run_host();
        d.dies.push(700);
        assert!(ov.window_member_with(&mut maps, &d, 700, g).is_err());
        // no window open
        ov.close_tree_with(&mut maps, "test");
        assert!(ov.window_member_with(&mut maps, &host, 700, g).is_err());
    }

    const LINK: &str = "/etc/systemd/system/multi-user.target.wants/northnarrow-agent.service";

    fn links_stat(p: &Path) -> Option<InodeKey> {
        (p == Path::new("/etc/systemd/system/multi-user.target.wants")).then_some(InodeKey { dev: 8, ino: 77 })
    }

    /// Lot 2.3b (the leases): one lease per link, bound to the registered
    /// directory, the link's name, the generation and the removal, short-
    /// lived; anything else is refused.
    #[test]
    fn a_lease_is_bound_to_one_registered_link_and_the_window() {
        let host = window_run_host();
        let ov = flow_override();
        let mut maps = FlowMaps::default();
        maps.ext.insert((8, 77), common::wire::INODE_EXT_UNIT_LINKS);
        let g = arm_window_run(&ov, &mut maps, &host);
        let slot = ov
            .arm_lease_with(&mut maps, &host, &links_stat, NOW, (700, 7_000), g, LINK)
            .expect("armed");
        let l = maps.leases[slot as usize];
        assert_eq!(l.generation, g);
        assert_eq!(l.dir, InodeKey { dev: 8, ino: 77 });
        assert_eq!(l.name_hash, common::window_tree::UNIT_LINK_HASHES[0]);
        assert_eq!(l.action, common::wire::LEASE_REMOVE);
        assert_eq!(l.member_tgid, 700);
        assert_eq!(l.expires_boot_ns, NOW + common::wire::WINDOW_LEASE_TTL_NS);
        // the kernel's test lets that very removal through, once
        let grant = maps.base.grant;
        assert!(l.usable_for(&grant, l.dir, l.name_hash, common::wire::LEASE_REMOVE, NOW + 1, test_nonce()));
        // a second lease takes another slot
        let other = ov.arm_lease_with(&mut maps, &host, &links_stat, NOW, (700, 7_000), g, LINK).unwrap();
        assert_ne!(other, slot);
        // not one of our links, a directory not registered, another window
        for bad in [
            "/etc/systemd/system/multi-user.target.wants/sshd.service",
            "/etc/systemd/system/northnarrow-agent.service",
        ] {
            assert!(ov.arm_lease_with(&mut maps, &host, &links_stat, NOW, (700, 7_000), g, bad).is_err(), "{bad}");
        }
        maps.ext.clear();
        let e = ov.arm_lease_with(&mut maps, &host, &links_stat, NOW, (700, 7_000), g, LINK).unwrap_err();
        assert!(e.contains("not a directory of our units' links"), "{e}");
        maps.ext.insert((8, 77), common::wire::INODE_EXT_UNIT_LINKS);
        assert!(ov.arm_lease_with(&mut maps, &host, &links_stat, NOW, (700, 7_000), g + 1, LINK).is_err());
        // at most WINDOW_LEASES_MAX a window
        let mut armed = 2;
        while ov.arm_lease_with(&mut maps, &host, &links_stat, NOW, (700, 7_000), g, LINK).is_ok() {
            armed += 1;
        }
        assert_eq!(armed, WINDOW_LEASES_MAX as usize);
    }

    /// Lot 2.3b (D5, refinement 2): PID 1's environment changed since the
    /// grant closes the window at the next lease or controlled stop, and
    /// nothing is armed or stopped.
    #[test]
    fn pid1_s_environment_changed_closes_the_window_at_the_next_lease_or_stop() {
        for lease in [true, false] {
            let host = window_run_host();
            let ov = flow_override();
            let mut maps = FlowMaps::default();
            maps.ext.insert((8, 77), common::wire::INODE_EXT_UNIT_LINKS);
            let g = arm_window_run(&ov, &mut maps, &host);
            *host.pid1_env.borrow_mut() = Ok(strs(&["LANG=C.UTF-8", "LD_PRELOAD=/tmp/x.so"]));
            let r = if lease {
                ov.arm_lease_with(&mut maps, &host, &links_stat, NOW, (700, 7_000), g, LINK).map(|_| "")
            } else {
                ov.controlled_stop_with(&mut maps, &host, (700, 7_000), g, false)
            };
            let e = r.unwrap_err();
            assert!(e.contains("PID 1's environment changed"), "{e}");
            assert!(!ov.tree_window_open(), "closed");
            assert_eq!(ov.take_controlled_stop(), None);
            assert!(maps.leases.iter().all(|l| l.generation == 0));
        }
    }

    /// Lot 2.3b (D1): a member's controlled stop or restart sets the run
    /// loop's reason once; refused for another generation.
    #[test]
    fn a_controlled_stop_sets_the_run_loop_s_reason_once() {
        let host = window_run_host();
        let ov = flow_override();
        let mut maps = FlowMaps::default();
        let g = arm_window_run(&ov, &mut maps, &host);
        assert!(ov.controlled_stop_with(&mut maps, &host, (700, 7_000), g + 1, true).is_err());
        assert_eq!(ov.take_controlled_stop(), None);
        assert_eq!(
            ov.controlled_stop_with(&mut maps, &host, (700, 7_000), g, true),
            Ok(CONTROLLED_RESTART_REASON)
        );
        assert_eq!(ov.take_controlled_stop(), Some(CONTROLLED_RESTART_REASON));
        assert_eq!(ov.take_controlled_stop(), None);
        assert_eq!(
            ov.controlled_stop_with(&mut maps, &host, (700, 7_000), g, false),
            Ok(CONTROLLED_STOP_REASON)
        );
        assert_eq!(ov.take_controlled_stop(), Some(CONTROLLED_STOP_REASON));
        // a stop softens nothing: no host-wide window, no kill grant
        assert!(!ov.is_window_open());
    }
}

