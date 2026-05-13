//! Userland half of the Tappa 7 anti-tamper kernel hooks.
//!
//! The kernel-side `task_kill` and `ptrace_access_check` LSM programs
//! (in `agent-ebpf/src/`) read the agent's own thread-group id from a
//! BPF array map and return `-EPERM` to any caller — including
//! `root` — that targets it. This module is the userland half: at
//! agent startup, write `std::process::id()` to that map and attach
//! both LSM programs to their kernel hooks.
//!
//! ## Design notes
//!
//! - Both LSM programs and both anti-tamper maps (`PROTECTED_PID`,
//!   `KILL_OVERRIDE`, `PTRACE_OVERRIDE`) live in the same eBPF object
//!   as the sensors. Loading that object twice would create two
//!   independent kernel copies of `PROTECTED_PID`, only one of which
//!   the in-kernel hooks would read, so attaching happens on the
//!   same [`Ebpf`] instance owned by [`SensorMultiplexer`].
//! - Per-hook failures are logged at WARN and tolerated. The hooks
//!   require `CONFIG_BPF_LSM=y` plus `bpf` in the kernel's runtime
//!   `lsm=` chain (see `docs/TAPPA7_PREREQ.md`); on a machine that
//!   doesn't have those, the agent still has to run with sensors
//!   active so we don't hard-fail.
//! - The map write happens *before* the attach calls so any time
//!   window in which the hook fires sees a valid `tgid`, never `0`.

pub mod filesystem;
pub mod network_isolate;

use anyhow::{anyhow, Context, Result};
use aya::{
    maps::{Array, MapData},
    programs::Lsm,
    Btf, Ebpf,
};
use tracing::{info, warn};

/// Names mirroring `#[map]` / `#[lsm(hook = "…")]` declarations in
/// `agent-ebpf/src/{task_kill,ptrace_check}.rs`. Kept here as
/// constants because aya looks them up by string at runtime.
const PROTECTED_PID_MAP: &str = "PROTECTED_PID";
const TASK_KILL_PROGRAM: &str = "task_kill";
const TASK_KILL_HOOK: &str = "task_kill";
const PTRACE_PROGRAM: &str = "ptrace_access_check";
const PTRACE_HOOK: &str = "ptrace_access_check";

/// Populate `PROTECTED_PID` and attach the two Tappa 7 LSM hooks.
///
/// A failure populating the map is fatal: the hooks would otherwise
/// fail open and we'd silently lose anti-tamper. Failure attaching
/// either LSM hook is logged and tolerated so the agent can still
/// run on kernels without BPF-LSM in the boot `lsm=` chain.
pub fn attach(ebpf: &mut Ebpf, agent_pid: u32) -> Result<()> {
    write_protected_pid(ebpf, agent_pid).context("populating PROTECTED_PID before LSM attach")?;
    info!(
        agent_pid,
        map = PROTECTED_PID_MAP,
        "anti-tamper: agent PID registered with kernel"
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

fn write_protected_pid(ebpf: &mut Ebpf, agent_pid: u32) -> Result<()> {
    let map = ebpf
        .map_mut(PROTECTED_PID_MAP)
        .ok_or_else(|| anyhow!("map {PROTECTED_PID_MAP} missing from eBPF object"))?;
    let mut array: Array<&mut MapData, u32> = Array::try_from(map)
        .with_context(|| format!("{PROTECTED_PID_MAP} is not a BPF_MAP_TYPE_ARRAY<u32>"))?;
    array
        .set(0, agent_pid, 0)
        .with_context(|| format!("writing PID into {PROTECTED_PID_MAP}[0]"))?;
    Ok(())
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
