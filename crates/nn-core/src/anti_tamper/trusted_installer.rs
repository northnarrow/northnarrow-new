//! The trusted-installer window's vocabulary (FIM-009 self-upgrade, §15.1;
//! lab PR 225): the agent's own systemd units, the only ones whose
//! NN-L-FIM-009 verdict an open window downgrades, and who opened a window
//! and until when.
//!
//! R08b (lab PR 251): cut verbatim from the agent's
//! `anti_tamper::trusted_installer`, which re-exports both and keeps the
//! window itself — its kernel half (`FS_GRANT`, `KILL_GRANT`), its signed
//! close, its clock — until R04b splits the window from its kernel sync.
//! The rules that read them move to nn-core; they reach the window through
//! their host ([`crate::posture::host::PostureAgent::InstallerWindow`]).
//! R10 (lab PR 259): the window's ceiling too, which the agent clamps a
//! signed grant to and nn-admin clamps `--window-secs` to before it signs
//! (`MAX_TRUSTED_INSTALLER_WINDOW_SECS`, cut verbatim; the agent's module
//! re-exports it).

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
    // Lab PR 216: the watchdog's `OnFailure=` handler.
    "/etc/systemd/system/northnarrow-watchdog-failed.service",
    "/usr/lib/systemd/system/northnarrow-watchdog-failed.service",
    "/lib/systemd/system/northnarrow-watchdog-failed.service",
    // Lot 273d: the units' slice.
    "/etc/systemd/system/northnarrow.slice",
    "/usr/lib/systemd/system/northnarrow.slice",
    "/lib/systemd/system/northnarrow.slice",
];

/// Lab PR 225: who opened the current window and when it ends — named in
/// the records the window sanctions (a stop or restart of the agent's own
/// units, NN-L-EVA-001 at Low: [`crate::impair`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowGrant {
    /// Fingerprint of the admin key whose signed grant opened the window.
    pub key_id: String,
    /// The window's deadline, wall clock (UTC, RFC 3339 to the second).
    pub expires_at: String,
    /// Lot 278: the installer the window was granted to — the process that
    /// ran `nn-admin trusted-installer-grant` (the requester's parent) —
    /// when the agent could tell it. R009 records, at Low, what that
    /// process's own tree executes from a home or `/tmp` while the window
    /// is open, after the grant: the tree by lineage from that process
    /// (its pid and its start), never by a name or a path.
    pub grantee: Option<WindowGrantee>,
}

/// Lot 278: the process a trusted-installer window was granted to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowGrantee {
    pub pid: u32,
    /// Its start, `starttime` (field 22) of `/proc/<pid>/stat`, in clock
    /// ticks since boot: with the pid, the process itself (a pid reused
    /// since names another start).
    pub start_ticks: u64,
    /// When the window was granted to it (`CLOCK_MONOTONIC` ns, the clock
    /// of the exec events): what its tree executed before is not covered.
    pub granted_ns: u64,
}

/// Hard ceiling on a grant window. A grant whose `window_secs` exceeds
/// this is clamped down — a captured or fat-fingered grant can never
/// hold the FS pin open longer than this, and the operator lifecycle
/// (arm → install → `systemctl restart`) closes it far sooner in
/// practice. 10 minutes is generous for an in-place upgrade.
pub const MAX_TRUSTED_INSTALLER_WINDOW_SECS: u32 = 600;
