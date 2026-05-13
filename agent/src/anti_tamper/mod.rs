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

use anyhow::{Context, Result};
use aya::{Btf, Ebpf};
use tracing::{info, warn};

// Re-export the helpers the binary crate (main.rs) reaches for.
// The actual logic lives in northnarrow-antitamper-bpf so the
// watchdog can share it without pulling in agent's full library.
pub use antitamper_bpf::{read_proc_comm, read_self_comm, AntiTamper, HookAttachOutcome};

/// Run the full anti-tamper bootstrap against an already-loaded
/// [`Ebpf`] instance (the multiplexer is responsible for invoking
/// `AntiTamper::configure_loader(&mut loader)` BEFORE
/// `loader.load()` so map_pin_path takes effect; this function does
/// the post-load PID + LSM-link work).
///
/// Order: evict stale PIDs → register fresh PIDs → pin-or-attach
/// all 7 LSM hooks → filesystem bootstrap (Tappa 7 task 5). Per-hook
/// failures are logged WARN and tolerated so the agent still runs
/// on kernels without BPF-LSM.
pub fn attach(
    ebpf: &mut Ebpf,
    antitamper: &AntiTamper,
    pids: &[u32],
    allowed_comms: &HashSet<String>,
) -> Result<()> {
    match antitamper.evict_stale_pids(ebpf, allowed_comms) {
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
    antitamper
        .register_pids(ebpf, pids)
        .context("populating PROTECTED_PIDS before LSM attach")?;

    // `Btf::from_sys_fs()` reads `/sys/kernel/btf/vmlinux`. The Lsm
    // loader resolves `bpf_lsm_<hook>` against it. If we can't read
    // vmlinux BTF, no hook can attach — log once and skip the whole
    // batch rather than warning N times for the same root cause.
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

    let mut reused = 0usize;
    let mut fresh = 0usize;
    let mut failed = 0usize;
    for (hook, res) in antitamper.pin_or_attach_lsm_hooks(ebpf, &btf) {
        match res {
            Ok(HookAttachOutcome::ReusedPin) => {
                reused += 1;
                info!(hook, "anti-tamper: reused pinned LSM link");
            }
            Ok(HookAttachOutcome::FreshlyAttached) => {
                fresh += 1;
                info!(hook, "anti-tamper: LSM hook freshly attached + pinned");
            }
            Err(e) => {
                failed += 1;
                warn!(
                    hook, error = %e,
                    "anti-tamper: LSM hook attach FAILED — coverage degraded"
                );
            }
        }
    }
    info!(
        reused,
        fresh, failed, "anti-tamper: LSM hook attach summary"
    );

    // Tappa 7 task 5: directory + inode bootstrap. Filesystem
    // protection's LSM hooks (5 of the 7) are already attached by
    // pin_or_attach_lsm_hooks above; this call still runs the
    // mkdir + chattr +i + PROTECTED_INODES registration for
    // `/var/lib/northnarrow/`.
    if let Err(e) = filesystem::attach(ebpf, &btf) {
        warn!(
            error = %e,
            "anti-tamper FS: bootstrap failed (LSM hooks remain attached and pinned)"
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_self_comm_returns_non_empty_string() {
        let c = read_self_comm().expect("read_self_comm should succeed for our own /proc");
        assert!(!c.is_empty(), "self comm should be non-empty");
        // Trailing newline must be stripped — every assertion below
        // depends on the trim contract.
        assert!(
            !c.ends_with('\n'),
            "trailing newline must be stripped: {c:?}"
        );
    }

    #[test]
    fn read_proc_comm_for_self_matches_read_self_comm() {
        let mine = std::process::id();
        let via_self = read_self_comm().unwrap();
        let via_pid = read_proc_comm(mine).expect("read_proc_comm should find our own PID");
        assert_eq!(via_self, via_pid);
    }

    #[test]
    fn read_proc_comm_returns_none_for_impossibly_large_pid() {
        // Linux's pid_max ceiling is 2^22 on 64-bit systems; u32::MAX
        // is firmly above that, so /proc/<u32::MAX>/comm cannot exist
        // for any live process.
        let res = read_proc_comm(u32::MAX);
        assert!(res.is_none(), "expected None for u32::MAX, got {res:?}");
    }

    #[test]
    fn read_proc_comm_returns_none_for_pid_zero() {
        // PID 0 is the kernel's swapper, not exposed via /proc.
        let res = read_proc_comm(0);
        assert!(res.is_none(), "expected None for PID 0, got {res:?}");
    }
}
