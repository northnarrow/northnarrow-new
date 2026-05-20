//! Userland half of the Tappa 7 anti-tamper kernel hooks.
//!
//! The kernel-side `task_kill` and `ptrace_access_check` LSM programs
//! (in `agent-ebpf/src/`) consult the [`PROTECTED_PIDS`] hash map and
//! return `-EPERM` to any caller — including `root` — whose target
//! `tgid` is present. This module is the userland half: at agent
//! startup it registers the agent's PID (and in Tappa 7 task 6 also
//! the watchdog's PID) into that map and attaches both LSM programs.
//!
//! ## Design notes
//!
//! - All LSM programs and anti-tamper maps (`PROTECTED_PIDS`,
//!   `KILL_OVERRIDE`, `PTRACE_OVERRIDE`, `PROTECTED_INODES`,
//!   `FS_PROTECT_OVERRIDE`, `FS_PROTECT_EVENTS`) live in the same
//!   eBPF object as the sensors. Loading that object twice would
//!   create two independent kernel copies of `PROTECTED_PIDS`, only
//!   one of which the in-kernel hooks would read, so attaching
//!   happens on the same [`Ebpf`] instance owned by
//!   [`SensorMultiplexer`].
//! - Per-hook failures are logged at WARN and tolerated. The hooks
//!   require `CONFIG_BPF_LSM=y` plus `bpf` in the kernel's runtime
//!   `lsm=` chain (see `docs/TAPPA7_PREREQ.md`); on a machine that
//!   doesn't have those, the agent still has to run with sensors
//!   active so we don't hard-fail.
//! - The map write happens *before* the attach calls so any time
//!   window in which the hook fires sees the protected set already
//!   populated.
//! - Stale-entry eviction: before registering new PIDs we walk the
//!   existing map and remove entries whose PID either no longer
//!   exists or whose `/proc/<pid>/comm` doesn't match the expected
//!   process name. This matters once eBPF programs and maps get
//!   pinned to bpffs (Tappa 7 task 6 commit #2) — a pinned map
//!   carries the dead agent's PID across the death/respawn gap,
//!   and an attacker who lands a process at the recycled PID
//!   would inherit LSM protection. Eviction closes that window
//!   on agent startup; the watchdog's `bpf_map_delete_elem` on
//!   SIGCHLD closes it during the death itself.

pub mod admin_auth;
pub mod filesystem;
pub mod network_isolate;

/// Test-only mint of an [`network_isolate::UnlockToken`] for unit
/// tests that exercise code paths consuming the capability (e.g.
/// `posture::admin_release_combat_with_token`). The production
/// capability invariant is unaffected — this helper is only
/// compiled under `cfg(test)`.
#[cfg(test)]
pub(crate) fn _test_mint_unlock_token() -> network_isolate::UnlockToken {
    network_isolate::mint_unlock_token()
}

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result};
use aya::{Btf, Ebpf};
use tracing::{info, warn};

// ISSUE_002: bpffs root / pin / LSM-attach primitives were
// extracted from this module into the `antitamper-bpf` workspace
// crate so the forthcoming watchdog binary can consume them
// without pulling the rest of `agent`. Re-exported here so
// every pre-extraction caller (sensors/multiplexer.rs,
// filesystem.rs, main.rs, tests) keeps compiling byte-identically.
pub use antitamper_bpf::{
    attach_lsm, attach_transient, fresh_attach_and_pin, lsm_pin_paths, prepare_pin_root,
    purge_stale_pin, read_proc_comm, read_self_comm, DEFAULT_BPFFS_ROOT, PROTECTED_PIDS_MAP_NAME,
};

// Watchdog W1: PROTECTED_PIDS userspace manipulation now goes
// through the typed handle in `antitamper-bpf` so both the agent
// (in-process, has the `Ebpf`) and the future watchdog binary
// (cross-process, opens by bpffs path) use the same code path.
use antitamper_bpf::ProtectedPidsHandle;

/// Watchdog W6: TASK_COMM_LEN-truncated comm of the watchdog
/// binary. The watchdog's W2 boot sequence calls
/// `prctl(PR_SET_NAME, "northnarrow-wat")` (15 chars + NUL fits
/// the kernel's 16-byte field exactly), so this is the literal
/// string `/proc/<watchdog_pid>/comm` produces.
///
/// Adding this to `attach()`'s `allowed_comms` set means
/// `evict_stale_pids` will NOT evict the watchdog's
/// `PROTECTED_PIDS` entry on the agent's next restart —
/// preserves the LSM kill/ptrace protection for the watchdog
/// across the agent death→respawn gap (per design §7.1).
pub const WATCHDOG_COMM: &str = "northnarrow-wat";

/// Watchdog W6: best-effort read of the watchdog's PID file.
/// Returns `Some(pid)` when the file exists AND parses as a
/// `u32`; returns `None` for every failure mode (file absent,
/// permission denied, garbage content, empty) AFTER logging.
/// Failure is NEVER propagated — a deployment that hasn't yet
/// rolled out the watchdog binary must boot the agent
/// unchanged (per design §7.1 "the agent runs without a
/// watchdog before W6 lands").
///
/// Trims a single trailing newline (the watchdog's atomic
/// pidfile writer emits `<pid>\n`); rejects multi-line content
/// because the canonical writer never produces such bytes.
pub fn read_watchdog_pid_optional(path: &Path) -> Option<u32> {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            info!(
                target: "anti_tamper.watchdog_pid",
                path = %path.display(),
                "no watchdog pidfile present — agent boots without watchdog co-protection"
            );
            return None;
        }
        Err(e) => {
            warn!(
                target: "anti_tamper.watchdog_pid",
                error = %e,
                path = %path.display(),
                "watchdog pidfile read failed — falling back to agent-only protection"
            );
            return None;
        }
    };
    let trimmed = raw.trim();
    match trimmed.parse::<u32>() {
        Ok(pid) => {
            info!(
                target: "anti_tamper.watchdog_pid",
                path = %path.display(),
                watchdog_pid = pid,
                "watchdog pidfile present — co-registering watchdog PID in PROTECTED_PIDS"
            );
            Some(pid)
        }
        Err(e) => {
            warn!(
                target: "anti_tamper.watchdog_pid",
                error = %e,
                path = %path.display(),
                content = %trimmed,
                "watchdog pidfile content is not a valid u32 — falling back to agent-only"
            );
            None
        }
    }
}

// TODO(Tappa 8): the three override arrays — KILL_OVERRIDE,
// PTRACE_OVERRIDE, FS_PROTECT_OVERRIDE — are now `pinned` by-name
// (commit #2), so slot 0 now SURVIVES an agent restart. They are
// shipped empty and never written in Tappa 7, so this is inert
// today. When Tappa 8 wires the Ed25519 verifier that writes a
// capability token into slot 0, it MUST zero that slot on agent
// boot (`MapData::insert(0, &0, 0)`) before trusting it, or a
// pre-restart grant would silently outlive its window. No zeroing
// is added here in commit #2: it would be dead code with no
// Tappa-7 caller and is out of this commit's scope.

/// Names mirroring `#[lsm(hook = "…")]` declarations in
/// `agent-ebpf/src/{task_kill,ptrace_check}.rs`. Kept here as
/// constants because aya looks them up by string at runtime. The
/// map-name constant lives in `antitamper-bpf::PROTECTED_PIDS_MAP_NAME`
/// (Watchdog W1) since both agent and watchdog reference it; these
/// hook/program names stay agent-side because only the agent
/// loads the LSM hooks.
const TASK_KILL_PROGRAM: &str = "task_kill";
const TASK_KILL_HOOK: &str = "task_kill";
const PTRACE_PROGRAM: &str = "ptrace_access_check";
const PTRACE_HOOK: &str = "ptrace_access_check";

/// Populate `PROTECTED_PIDS` and attach the two Tappa 7 LSM hooks.
///
/// A failure populating the map is fatal: the hooks would otherwise
/// fail open and we'd silently lose anti-tamper. Failure attaching
/// either LSM hook is logged and tolerated so the agent can still
/// run on kernels without BPF-LSM in the boot `lsm=` chain.
///
/// `pids` is a slice so callers can register multiple PIDs in one
/// call (Tappa 7 task 6: agent + watchdog). Stale entries from a
/// prior pinned-map load are evicted first — every entry whose PID
/// is dead or whose `/proc/<pid>/comm` is not in `allowed_comms`
/// is removed before `pids` is inserted.
pub fn attach(ebpf: &mut Ebpf, pids: &[u32], allowed_comms: &HashSet<String>) -> Result<()> {
    match evict_stale_pids(ebpf, allowed_comms) {
        Ok(0) => {}
        Ok(n) => info!(
            evicted = n,
            "anti-tamper: stale PIDs evicted from PROTECTED_PIDS"
        ),
        Err(e) => warn!(
            error = %e,
            "anti-tamper: stale-PID eviction failed, continuing (any leftover entries \
             will be overwritten by the registration step)"
        ),
    }
    register_protected_pids(ebpf, pids).context("populating PROTECTED_PIDS before LSM attach")?;
    info!(
        pids = ?pids,
        map = PROTECTED_PIDS_MAP_NAME,
        "anti-tamper: PIDs registered with kernel"
    );

    // PHASE_D_001: pin PROTECTED_PIDS by name to bpffs. The eBPF
    // source declares `HashMap::pinned(16, 0)` and the loader
    // calls `map_pin_path(root)`, which is documented to handle
    // by-name pinning automatically — empirically on aya 0.13.1 +
    // kernel 6.8 it does not, leaving the watchdog's
    // `ProtectedPidsHandle::open(bpffs_root)` unable to find the
    // map. Explicit pin here closes the gap. purge_stale_pin +
    // pin mirrors the W1 attach_lsm idiom: a leftover pin from a
    // prior wedged boot may point at a dead kernel map, so we
    // always re-pin against the live map this boot loaded.
    if let Some(root) = prepare_pin_root() {
        let map_pin_path = root.join(PROTECTED_PIDS_MAP_NAME);
        purge_stale_pin(&map_pin_path);
        ebpf.map_mut(PROTECTED_PIDS_MAP_NAME)
            .ok_or_else(|| {
                anyhow::anyhow!("map {PROTECTED_PIDS_MAP_NAME} missing from eBPF object")
            })?
            .pin(&map_pin_path)
            .with_context(|| {
                format!(
                    "pinning {PROTECTED_PIDS_MAP_NAME} to {}",
                    map_pin_path.display()
                )
            })?;
        info!(
            map = PROTECTED_PIDS_MAP_NAME,
            map_pin = %map_pin_path.display(),
            "anti-tamper: PROTECTED_PIDS pinned by-name to bpffs (PHASE_D_001)"
        );
    }

    // `Btf::from_sys_fs()` reads `/sys/kernel/btf/vmlinux`. The Lsm
    // loader resolves `bpf_lsm_<hook>` against it to set the
    // `attach_btf_id` the kernel expects. If we can't read vmlinux
    // BTF, neither hook can attach — log once and skip both rather
    // than warning twice for the same root cause.
    let btf = match Btf::from_sys_fs() {
        Ok(b) => b,
        Err(e) => {
            warn!(
                error = %e,
                "anti-tamper: vmlinux BTF unavailable, skipping LSM attach \
                 (kernel BPF-LSM disabled or CONFIG_DEBUG_INFO_BTF=n)"
            );
            return Ok(());
        }
    };

    // Commit #2b: the bpffs root that holds the prog/link pins. Same
    // root the multiplexer handed to `map_pin_path`; `prepare_pin_root`
    // is idempotent (dir already created) and silent on the happy
    // path, so re-deriving it here keeps the change inside
    // `anti_tamper/` without threading a new param through the
    // multiplexer. `None` (no bpffs) ⇒ transient attach, no
    // persistence — `attach_lsm` handles the degrade + log.
    let pin_root = prepare_pin_root();

    // On success `attach_lsm` logs the disposition (reused / freshly
    // attached / purged-then-attached) itself — the call sites only
    // escalate the *failure* case with its operator-facing severity.
    if let Err(e) = attach_lsm(ebpf, TASK_KILL_PROGRAM, TASK_KILL_HOOK, &btf, pin_root) {
        warn!(
            program = TASK_KILL_PROGRAM,
            hook = TASK_KILL_HOOK,
            error = %e,
            "anti-tamper: LSM hook attach FAILED — agent killable by root"
        );
    }

    if let Err(e) = attach_lsm(ebpf, PTRACE_PROGRAM, PTRACE_HOOK, &btf, pin_root) {
        warn!(
            program = PTRACE_PROGRAM,
            hook = PTRACE_HOOK,
            error = %e,
            "anti-tamper: LSM hook attach FAILED — agent inspectable by root"
        );
    }

    // Tappa 7 task 5: directory + inode protection. Failure to
    // bootstrap (no /var/lib, read-only rootfs, permission denied
    // even as root) is warn-and-continue: process-level anti-tamper
    // already attached above, so the agent isn't worthless without
    // FS protection.
    if let Err(e) = filesystem::attach(ebpf, &btf, pin_root) {
        warn!(error = %e, "anti-tamper FS: bootstrap failed, continuing without FS protection");
    }

    Ok(())
}

/// Insert each PID into `PROTECTED_PIDS`. Watchdog W1: this is now
/// a thin wrapper over [`ProtectedPidsHandle::insert`] so the agent
/// and the watchdog share one canonical map-mutation code path.
/// `BPF_ANY` upsert semantics are preserved by the handle — an
/// entry that already exists is overwritten.
fn register_protected_pids(ebpf: &mut Ebpf, pids: &[u32]) -> Result<()> {
    let mut handle = ProtectedPidsHandle::from_ebpf(ebpf)?;
    for &pid in pids {
        handle.insert(pid)?;
    }
    Ok(())
}

/// Walk every PID currently in `PROTECTED_PIDS`. Evict any entry
/// whose PID is dead OR whose `/proc/<pid>/comm` is not in
/// `allowed_comms`. Returns the number of entries removed.
///
/// This is a no-op on a freshly-loaded eBPF object (the map is
/// empty); it becomes load-bearing once the BPF pinning sprint
/// pins the map to bpffs, at which point a restarted agent inherits
/// the prior generation's entries and must clean up stale ones
/// before the new PIDs take effect.
///
/// Watchdog W1: walk + evict now go through the
/// [`ProtectedPidsHandle`] surface. Snapshot the PID set up front
/// via [`ProtectedPidsHandle::pids`] (which materialises a `Vec`
/// internally) so the eviction loop can call
/// [`ProtectedPidsHandle::evict`] without fighting an iterator
/// borrow on the underlying map.
fn evict_stale_pids(ebpf: &mut Ebpf, allowed_comms: &HashSet<String>) -> Result<usize> {
    let mut handle = ProtectedPidsHandle::from_ebpf(ebpf)?;
    let existing = handle.pids()?;
    let mut evicted = 0usize;
    for pid in existing {
        let alive_and_matching = match read_proc_comm(pid) {
            Some(comm) => allowed_comms.contains(&comm),
            None => false,
        };
        if alive_and_matching {
            continue;
        }
        match handle.evict(pid) {
            Ok(()) => evicted += 1,
            Err(e) => warn!(
                pid, error = %e,
                "anti-tamper: failed to evict stale PID (continuing)"
            ),
        }
    }
    Ok(evicted)
}

// ISSUE_002 extraction note: read_self_comm, read_proc_comm,
// lsm_pin_paths, purge_stale_pin, fresh_attach_and_pin,
// attach_transient, attach_lsm — plus their unit tests — all moved
// to `northnarrow-antitamper-bpf` and are re-exported via the
// `pub use` block at the top of this module. Functional behaviour
// is byte-identical; the only delta is the home crate.

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // ── Watchdog W6: pidfile reader + comm constant ────────────────

    /// Required W6 test 1: read_watchdog_pid_optional returns
    /// the PID when the watchdog pidfile is present and contains
    /// a valid u32 (with the canonical `<pid>\n` shape the
    /// watchdog's W2 atomic writer emits).
    #[test]
    fn read_watchdog_pid_optional_returns_pid_when_file_present() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("watchdog.pid");
        std::fs::write(&p, "4242\n").unwrap();
        assert_eq!(read_watchdog_pid_optional(&p), Some(4242));

        // No-newline shape also works (forward-compat with
        // alternate writers).
        let p2 = dir.path().join("watchdog2.pid");
        std::fs::write(&p2, "9999").unwrap();
        assert_eq!(read_watchdog_pid_optional(&p2), Some(9999));
    }

    /// Required W6 test 2: read_watchdog_pid_optional returns
    /// None — NOT an error — when the file is absent. Anchors
    /// the "agent boots without watchdog" no-op contract: a
    /// deployment that hasn't rolled out the watchdog binary
    /// MUST still boot the agent unchanged.
    #[test]
    fn read_watchdog_pid_optional_returns_none_when_file_missing() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("does-not-exist.pid");
        assert!(!p.exists());
        assert_eq!(read_watchdog_pid_optional(&p), None);
    }

    // ── Supplementary W6 tests ─────────────────────────────────────

    /// Garbage content surfaces as None (logged WARN), not an
    /// error. Documents that a corrupted pidfile degrades the
    /// agent to "no watchdog co-protection" rather than
    /// failing boot — a missing or wrong watchdog should never
    /// take the agent down.
    #[test]
    fn read_watchdog_pid_optional_returns_none_on_garbage() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("garbage.pid");
        std::fs::write(&p, "this is definitely not a pid\n").unwrap();
        assert_eq!(read_watchdog_pid_optional(&p), None);

        // Empty file also surfaces as None.
        let p2 = dir.path().join("empty.pid");
        std::fs::write(&p2, "").unwrap();
        assert_eq!(read_watchdog_pid_optional(&p2), None);

        // Whitespace-only also None.
        let p3 = dir.path().join("ws.pid");
        std::fs::write(&p3, "   \n\t\n").unwrap();
        assert_eq!(read_watchdog_pid_optional(&p3), None);
    }

    /// Cross-crate consistency anchor: WATCHDOG_COMM must match
    /// the literal string the watchdog's W2 `harden_self` sets
    /// via prctl(PR_SET_NAME). TASK_COMM_LEN is 16 bytes
    /// (including NUL terminator), so the value fits exactly
    /// with 15 chars + NUL. A future rename of the watchdog
    /// binary that changes its prctl name MUST update this
    /// constant in lock-step, or evict_stale_pids would silently
    /// evict the watchdog's PROTECTED_PIDS entry.
    #[test]
    fn watchdog_comm_constant_is_task_comm_len_safe() {
        assert_eq!(WATCHDOG_COMM, "northnarrow-wat");
        // 15 chars + implicit NUL = 16 bytes (TASK_COMM_LEN).
        assert_eq!(WATCHDOG_COMM.len(), 15);
        assert!(
            WATCHDOG_COMM.len() < 16,
            "TASK_COMM_LEN is 16 (incl. NUL); name must be ≤15"
        );
    }
}
