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

use anyhow::{anyhow, Context, Result};
use aya::{
    maps::{HashMap as AyaHashMap, MapData},
    programs::Lsm,
    Btf, Ebpf,
};
use tracing::{info, warn};

/// Names mirroring `#[map]` / `#[lsm(hook = "…")]` declarations in
/// `agent-ebpf/src/{task_kill,ptrace_check}.rs`. Kept here as
/// constants because aya looks them up by string at runtime.
const PROTECTED_PIDS_MAP: &str = "PROTECTED_PIDS";
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
        map = PROTECTED_PIDS_MAP,
        "anti-tamper: PIDs registered with kernel"
    );

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

    match attach_lsm(ebpf, TASK_KILL_PROGRAM, TASK_KILL_HOOK, &btf) {
        Ok(()) => info!(
            program = TASK_KILL_PROGRAM,
            hook = TASK_KILL_HOOK,
            "anti-tamper: LSM hook attached (denies SIGKILL/SIGTERM to agent)"
        ),
        Err(e) => warn!(
            program = TASK_KILL_PROGRAM,
            hook = TASK_KILL_HOOK,
            error = %e,
            "anti-tamper: LSM hook attach FAILED — agent killable by root"
        ),
    }

    match attach_lsm(ebpf, PTRACE_PROGRAM, PTRACE_HOOK, &btf) {
        Ok(()) => info!(
            program = PTRACE_PROGRAM,
            hook = PTRACE_HOOK,
            "anti-tamper: LSM hook attached (denies ptrace to agent)"
        ),
        Err(e) => warn!(
            program = PTRACE_PROGRAM,
            hook = PTRACE_HOOK,
            error = %e,
            "anti-tamper: LSM hook attach FAILED — agent inspectable by root"
        ),
    }

    // Tappa 7 task 5: directory + inode protection. Failure to
    // bootstrap (no /var/lib, read-only rootfs, permission denied
    // even as root) is warn-and-continue: process-level anti-tamper
    // already attached above, so the agent isn't worthless without
    // FS protection.
    if let Err(e) = filesystem::attach(ebpf, &btf) {
        warn!(error = %e, "anti-tamper FS: bootstrap failed, continuing without FS protection");
    }

    Ok(())
}

/// Insert each PID into `PROTECTED_PIDS`. `BPF_ANY` upsert
/// semantics: an entry that already exists is overwritten, so
/// re-registering the same PID after an eviction race is fine.
fn register_protected_pids(ebpf: &mut Ebpf, pids: &[u32]) -> Result<()> {
    let map = ebpf
        .map_mut(PROTECTED_PIDS_MAP)
        .ok_or_else(|| anyhow!("map {PROTECTED_PIDS_MAP} missing from eBPF object"))?;
    let mut hm: AyaHashMap<&mut MapData, u32, u8> = AyaHashMap::try_from(map)
        .with_context(|| format!("{PROTECTED_PIDS_MAP} is not a HashMap<u32, u8>"))?;
    for &pid in pids {
        hm.insert(pid, 1u8, 0)
            .with_context(|| format!("inserting PID {pid} into {PROTECTED_PIDS_MAP}"))?;
    }
    Ok(())
}

/// Walk every PID currently in `PROTECTED_PIDS`. Evict any entry
/// whose PID is dead OR whose `/proc/<pid>/comm` is not in
/// `allowed_comms`. Returns the number of entries removed.
///
/// This is a no-op on a freshly-loaded eBPF object (the map is
/// empty); it becomes load-bearing once Tappa 7 task 6 commit #2
/// pins the map to bpffs, at which point a restarted agent inherits
/// the prior generation's entries and must clean up stale ones
/// before the new PIDs take effect.
fn evict_stale_pids(ebpf: &mut Ebpf, allowed_comms: &HashSet<String>) -> Result<usize> {
    let map = ebpf
        .map_mut(PROTECTED_PIDS_MAP)
        .ok_or_else(|| anyhow!("map {PROTECTED_PIDS_MAP} missing from eBPF object"))?;
    let mut hm: AyaHashMap<&mut MapData, u32, u8> = AyaHashMap::try_from(map)
        .with_context(|| format!("{PROTECTED_PIDS_MAP} is not a HashMap<u32, u8>"))?;

    // Materialise the key set up-front; aya's `keys()` iterator
    // holds a borrow of the map, and we need `&mut hm` to call
    // `remove()`.
    let existing: Vec<u32> = hm.keys().filter_map(Result::ok).collect();
    let mut evicted = 0usize;
    for pid in existing {
        let alive_and_matching = match read_proc_comm(pid) {
            Some(comm) => allowed_comms.contains(&comm),
            None => false,
        };
        if alive_and_matching {
            continue;
        }
        match hm.remove(&pid) {
            Ok(()) => evicted += 1,
            Err(e) => warn!(
                pid, error = %e,
                "anti-tamper: failed to evict stale PID (continuing)"
            ),
        }
    }
    Ok(evicted)
}

/// Read `/proc/self/comm` and return it as an owned `String` with
/// the trailing newline stripped. Returns an error if the file is
/// missing or unreadable — both shouldn't happen for our own PID.
pub fn read_self_comm() -> Result<String> {
    let raw = std::fs::read_to_string("/proc/self/comm").context("reading /proc/self/comm")?;
    Ok(raw.trim_end_matches('\n').to_string())
}

/// Read `/proc/<pid>/comm` and return it as an owned `String`.
/// Returns `None` if the file does not exist (process gone) or
/// cannot be read for any other reason — callers treat both
/// outcomes as "this PID is no longer ours."
///
/// `comm` is the kernel-stamped 15-char-plus-NUL `TASK_COMM_LEN`
/// field, set on exec and updatable via `prctl(PR_SET_NAME)`. We
/// use it rather than `cmdline` because comm is the value the
/// kernel itself uses internally; cmdline can be rewritten via
/// `/proc/self/cmdline` write from userland. Neither defeats a
/// motivated attacker — comm is a sanity check for PID recycling
/// race, not a security primitive.
pub fn read_proc_comm(pid: u32) -> Option<String> {
    let path = format!("/proc/{pid}/comm");
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim_end_matches('\n').to_string())
}

pub(crate) fn attach_lsm(
    ebpf: &mut Ebpf,
    program_name: &str,
    hook_name: &str,
    btf: &Btf,
) -> Result<()> {
    let prog: &mut Lsm = ebpf
        .program_mut(program_name)
        .ok_or_else(|| anyhow!("program {program_name} missing from eBPF object"))?
        .try_into()
        .with_context(|| format!("program {program_name} is not an LSM program"))?;
    prog.load(hook_name, btf)
        .with_context(|| format!("verifier rejected LSM program `{program_name}`"))?;
    prog.attach()
        .with_context(|| format!("attaching LSM program `{program_name}` to hook `{hook_name}`"))?;
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
