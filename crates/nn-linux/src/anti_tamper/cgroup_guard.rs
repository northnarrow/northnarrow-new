//! Lot 273: the protected units' cgroups — the agent's half.
//!
//! On systemd 257 and later `systemctl kill -s SIGKILL` of the agent ends
//! in a write to its unit's `cgroup.kill` once the `task_kill` hook refused
//! the signal to the main process: the kernel kills the cgroup, and no hook
//! saw a signal. Any root shell can do the same, or freeze the unit through
//! `cgroup.freeze`, or move the agent to a cgroup of its own and kill that
//! one. This module closes the three:
//!
//! * the unit cgroups of the agent and of the watchdog (and their ancestor
//!   slices' kill and freeze) go into `PROTECTED_INODES`
//!   ([`antitamper_bpf::cgroup_guard`] says which inode with which flags):
//!   a write-open of `cgroup.kill` / `cgroup.freeze` is refused and signed
//!   `cgroup_kill` / `cgroup_freeze`, a child cgroup, a `chown` and an
//!   `rmdir` (but PID 1's) of the unit's directory are refused;
//! * the move guard — `cgroup_move_stash` (fexit
//!   `cgroup_procs_write_start`) and `cgroup_move_deny` (LSM
//!   `inode_permission`) — refuses moving a protected process to another
//!   cgroup, signed `cgroup_move`.
//!
//! Outside a signed trusted-installer window only; inside one, the hooks
//! refuse nothing (an upgrade's or an uninstall's `systemctl kill -s
//! SIGKILL` writes `cgroup.kill` on systemd 257). Host shutdown is not
//! touched: systemd stops the units through signals, which `systemd-shutdown`
//! delivers at the end, and its removal of the empty unit cgroups is let
//! through (`FS_PROTECT_INIT_RMDIR`).
//!
//! The move guard is an optional deny pair: attached where the kernel's
//! BTF has `cgroup_procs_write_start` in the shape the fexit reads (every
//! kernel from 5.14 checked), and signed degraded where it has not.

use std::path::Path;

use anyhow::Result;
use aya::{Btf, Ebpf};
use common::btf_offsets::CGROUP_MOVE_TARGET;
use common::wire::InodeKey;
use tracing::{info, warn};

pub use antitamper_bpf::cgroup_guard::UnitCgroup;

/// The move guard's lookup half and the kernel function it is attached to
/// (its pins carry the function's name: `prog_cgroup_procs_write_start`,
/// `link_cgroup_procs_write_start`).
pub(crate) const MOVE_STASH_PROGRAM: &str = "cgroup_move_stash";
pub const MOVE_STASH_HOOK: &str = CGROUP_MOVE_TARGET.func;
/// The move guard's refusal half and its LSM hook.
pub(crate) const MOVE_DENY_PROGRAM: &str = "cgroup_move_deny";
pub const MOVE_DENY_HOOK: &str = "inode_permission";

/// The two "hooks" of the move guard, as `OPTIONAL_DENY_HOOKS` names them.
pub const GUARD_HOOKS: [&str; 2] = [MOVE_DENY_HOOK, MOVE_STASH_HOOK];

/// What is lost when the move guard is not attached.
pub const MOVE_GUARD_ABSENT_EFFECT: &str =
    "the cgroup move guard is not attached: a protected process can be moved out of its \
     unit's cgroup (and killed or frozen through the new one)";

/// How the move guard counted this boot.
#[derive(Debug, Default)]
pub(crate) struct MoveGuardHealth {
    /// The guard's hooks this kernel has (0 or 2): expected deny hooks.
    pub present: usize,
    /// `(program, why)` of a program that the kernel has a hook for and
    /// that did not load or attach: deny-hook shortfalls.
    pub failures: Vec<(&'static str, String)>,
    /// Why the guard is not attached at all on this kernel (its attach
    /// point is absent or of another shape): a signed degradation.
    pub absent: Option<String>,
}

/// Attach the move guard: the refusal half first (it refuses nothing until
/// the lookup half records a move), then the lookup half, each attached
/// fresh before the prior boot's pins go ([`super::reattach_fresh`]).
pub(crate) fn attach_move_guard(
    ebpf: &mut Ebpf,
    btf: &Btf,
    pin_root: Option<&Path>,
) -> MoveGuardHealth {
    let mut health = MoveGuardHealth::default();
    let in_btf = super::btf_revalidate::optional_hook_in_kernel(MOVE_STASH_HOOK);
    if in_btf == Some(false) {
        let why = super::btf_revalidate::resolved()
            .and_then(|r| r.cgroup_move_target_mismatch())
            .map(str::to_string)
            .unwrap_or_else(|| format!("the kernel's BTF has no {}", CGROUP_MOVE_TARGET.func));
        warn!(reason = %why, effect = MOVE_GUARD_ABSENT_EFFECT, "anti-tamper cgroup: move guard not attached");
        // A prior boot's pins of the pair go too: a program of an older
        // agent must not stay attached where this one would not attach.
        if let Some(root) = pin_root {
            for hook in GUARD_HOOKS {
                let (prog, link) = antitamper_bpf::lsm_pin_paths(root, hook);
                antitamper_bpf::purge_stale_pin(&link);
                antitamper_bpf::purge_stale_pin(&prog);
            }
        }
        health.absent = Some(why);
        return health;
    }
    health.present = GUARD_HOOKS.len();
    if let Err(e) = super::reattach_fresh(ebpf, MOVE_DENY_PROGRAM, MOVE_DENY_HOOK, btf, pin_root) {
        warn!(program = MOVE_DENY_PROGRAM, hook = MOVE_DENY_HOOK, error = %format!("{e:#}"), "anti-tamper cgroup: LSM hook attach FAILED");
        health.failures.push((MOVE_DENY_PROGRAM, format!("{e:#}")));
        // Without the refusal half the lookup half refuses nothing: not
        // attached either, and counted missing.
        health.failures.push((
            MOVE_STASH_PROGRAM,
            "not attached: its refusal half did not attach".into(),
        ));
        return health;
    }
    if let Err(e) = antitamper_bpf::reattach_fresh_fexit(
        ebpf,
        MOVE_STASH_PROGRAM,
        MOVE_STASH_HOOK,
        btf,
        pin_root,
    ) {
        warn!(program = MOVE_STASH_PROGRAM, function = MOVE_STASH_HOOK, error = %format!("{e:#}"), "anti-tamper cgroup: fexit attach FAILED");
        health.failures.push((MOVE_STASH_PROGRAM, format!("{e:#}")));
    }
    health
}

/// What the registration of the unit cgroups found, for the journal and
/// the signed chain.
#[derive(Debug, Default)]
pub(crate) struct CgroupRegistration {
    /// `(pid, cgroup, entries)` of each process whose unit cgroup is
    /// protected now.
    pub protected: Vec<(u32, String, usize)>,
    /// Why a process's cgroup could not be protected (no cgroup v2, an
    /// unreadable cgroup): a signed degradation.
    pub unavailable: Vec<(u32, String)>,
}

/// Register the unit cgroups of `pids` (the agent and the watchdog) in
/// `PROTECTED_INODES` through the boot's registration (its keys survive
/// the stale-key prune). A process outside a systemd service's cgroup (a
/// privileged test, an agent started by hand) is left alone.
pub(crate) fn register_unit_cgroups(ebpf: &mut Ebpf, pids: &[u32]) -> Result<CgroupRegistration> {
    let mut out = CgroupRegistration::default();
    for &pid in pids {
        match antitamper_bpf::cgroup_guard::unit_cgroup_of(pid) {
            UnitCgroup::Service { cgroup, entries } => {
                for e in &entries {
                    super::filesystem::register_cgroup_inode(ebpf, &e.key, e.flags)?;
                }
                info!(
                    pid,
                    cgroup = %nn_model::log_escape::Escaped(&cgroup),
                    entries = entries.len(),
                    "anti-tamper cgroup: unit cgroup registered in PROTECTED_INODES (kill, freeze, \
                     child cgroups and rmdir refused outside a trusted-installer window)"
                );
                out.protected.push((pid, cgroup, entries.len()));
            }
            UnitCgroup::NotAService { cgroup } => info!(
                pid,
                cgroup = %nn_model::log_escape::Escaped(&cgroup),
                "anti-tamper cgroup: not a systemd service's cgroup — not protected"
            ),
            UnitCgroup::Unavailable { why } => {
                warn!(pid, reason = %why, "anti-tamper cgroup: unit cgroup NOT protected");
                out.unavailable.push((pid, why));
            }
        }
    }
    Ok(out)
}

/// The watchdog's unit cgroup, registered by the agent once it has
/// verified the watchdog's pid (the watchdog registers it itself at its
/// start; this covers one that could not). `previous`: the keys registered
/// for the former watchdog, released when they are not the new one's.
/// Returns the keys registered now.
pub fn protect_watchdog_cgroup(
    bpffs_root: Option<&Path>,
    pid: u32,
    previous: &[InodeKey],
) -> Vec<InodeKey> {
    let Some(root) = bpffs_root else {
        return Vec::new();
    };
    let keys = match antitamper_bpf::cgroup_guard::protect_unit_cgroup(root, pid) {
        Ok(UnitCgroup::Service { cgroup, entries }) => {
            info!(
                watchdog_pid = pid,
                cgroup = %nn_model::log_escape::Escaped(&cgroup),
                entries = entries.len(),
                "anti-tamper cgroup: watchdog unit cgroup registered in PROTECTED_INODES"
            );
            entries.iter().map(|e| e.key).collect::<Vec<_>>()
        }
        Ok(UnitCgroup::NotAService { cgroup }) => {
            info!(watchdog_pid = pid, cgroup = %nn_model::log_escape::Escaped(&cgroup), "anti-tamper cgroup: watchdog not in a systemd service's cgroup — not protected");
            Vec::new()
        }
        Ok(UnitCgroup::Unavailable { why }) => {
            warn!(watchdog_pid = pid, reason = %why, "anti-tamper cgroup: watchdog unit cgroup NOT protected");
            Vec::new()
        }
        Err(e) => {
            warn!(watchdog_pid = pid, error = %format!("{e:#}"), "anti-tamper cgroup: watchdog unit cgroup registration FAILED");
            Vec::new()
        }
    };
    let gone: Vec<InodeKey> = previous
        .iter()
        .copied()
        .filter(|k| !keys.contains(k))
        .collect();
    if !gone.is_empty() {
        if let Err(e) = antitamper_bpf::cgroup_guard::release_keys(root, &gone) {
            warn!(error = %format!("{e:#}"), "anti-tamper cgroup: the former watchdog's cgroup keys not released");
        }
    }
    keys
}

/// The agent's own unit cgroup, in the pinned `PROTECTED_INODES` before
/// the boot loads anything (as `preregister_self` does for its pid): the
/// prior boot's pinned deny hooks protect the new unit cgroup from the
/// first instant. `Ok(None)` when there is no pinned map (a first boot).
pub fn preregister_own_cgroup(bpffs_root: &Path) -> Result<Option<UnitCgroup>> {
    if !bpffs_root
        .join(antitamper_bpf::cgroup_guard::PROTECTED_INODES_MAP_NAME)
        .exists()
    {
        return Ok(None);
    }
    antitamper_bpf::cgroup_guard::protect_unit_cgroup(bpffs_root, std::process::id()).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The guard's pin names are the hooks' (the privileged pin test reads
    /// `prog_<hook>` / `link_<hook>`), and both are optional deny hooks with
    /// a fail-open slot.
    #[test]
    fn the_move_guard_is_an_optional_deny_pair() {
        assert_eq!(MOVE_STASH_HOOK, "cgroup_procs_write_start");
        assert_eq!(MOVE_DENY_HOOK, "inode_permission");
        for h in GUARD_HOOKS {
            assert!(super::super::OPTIONAL_DENY_HOOKS.contains(&h), "{h}");
            assert!(common::fail_open::FAIL_OPEN_HOOKS.contains(&h), "{h}");
            assert!(!super::super::DENY_HOOKS.contains(&h), "{h}");
        }
    }
}
