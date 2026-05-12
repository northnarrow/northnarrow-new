//! `ptrace_access_check` LSM hook — anti-tamper debugger denial.
//!
//! Tappa 7 (ROADMAP.md): the agent must be opaque to `ptrace(2)`
//! and to the `/proc/<pid>/{mem,maps,…}` family, including from
//! `root`. Both paths funnel through the kernel's
//! `security_ptrace_access_check` LSM call, so a single hook here
//! covers attach-style attacks (`PTRACE_ATTACH`, `PTRACE_SEIZE`)
//! and pure memory reads alike.
//!
//! Kernel hook signature (`linux/lsm_hook_defs.h`):
//! ```c
//! LSM_HOOK(int, 0, ptrace_access_check,
//!     struct task_struct *child,
//!     unsigned int mode)
//! ```
//! Aya appends the LSM chain `retval` as the last argument
//! (`arg(2)`), 0 if this is the first hook on the path. We honour
//! any prior denial by passing it through.
//!
//! Why deny `PTRACE_MODE_READ` and not just `PTRACE_MODE_ATTACH`:
//! a memory read of the agent process is sufficient to lift
//! in-memory secrets (Tappa 8 Ed25519 admin pubkey state, posture
//! machine, decision-engine internals). The Tappa 7 contract is
//! "the agent is not inspectable", so every mode is denied.
//!
//! Tappa 8 dependency: the signed-channel exception is stubbed via
//! the [`PTRACE_OVERRIDE`] map. It is always empty in the Tappa 7
//! build, so root truly cannot attach. Tappa 8 will wire the
//! Ed25519 verifier in userland that flips slot 0 to a non-zero
//! capability token after admin-signed approval (e.g. so an
//! incident-response engineer can run `gdb -p` after explicit
//! sign-off, without unloading the BPF program).

use aya_ebpf::{
    cty::{c_int, c_void},
    helpers::bpf_probe_read_kernel,
    macros::{lsm, map},
    maps::Array,
    programs::LsmContext,
};

use crate::task_kill::{PROTECTED_PID, TASK_STRUCT_TGID_OFFSET};

/// Linux `EPERM` value; LSM hooks return `-errno` to deny.
const EPERM: c_int = 1;

/// Tappa 8 stub: Ed25519-signed override capability for ptrace.
/// Slot 0 holds a monotonic token; a non-zero value means "current
/// admin-signed inspection request is in flight and may bypass the
/// deny". In the Tappa 7 ELF the map is shipped empty and never
/// written by the agent — root cannot attach a debugger, period.
///
/// Distinct from `task_kill::KILL_OVERRIDE` on purpose: signing off
/// "kill the agent" and signing off "let me read agent memory" are
/// independent capabilities and Tappa 8 should be able to grant
/// one without the other.
#[map]
pub static PTRACE_OVERRIDE: Array<u32> = Array::with_max_entries(1, 0);

#[lsm(hook = "ptrace_access_check")]
pub fn ptrace_access_check(ctx: LsmContext) -> i32 {
    unsafe { try_ptrace_access_check(&ctx) }
}

#[inline(always)]
unsafe fn try_ptrace_access_check(ctx: &LsmContext) -> i32 {
    // LSM-chain hygiene: if a prior hook on the chain already
    // produced a non-zero verdict, propagate it unchanged.
    let prev_retval: c_int = ctx.arg(2);
    if prev_retval != 0 {
        return prev_retval;
    }

    let protected = match PROTECTED_PID.get(0) {
        Some(p) => *p,
        None => return 0,
    };
    if protected == 0 {
        return 0;
    }

    let target: *const c_void = ctx.arg(0);
    if target.is_null() {
        return 0;
    }

    // Read `child->tgid` via the probe helper. With LSM + BTF the
    // pointer is a kernel-trusted `PTR_TO_BTF_ID`, but we use the
    // explicit helper so the verifier accepts the read without a
    // CO-RE relocation we don't yet emit from Rust. Offset is
    // shared with `task_kill` and validated by userland at boot
    // against `/sys/kernel/btf/vmlinux`.
    let tgid_ptr = (target as *const u8).add(TASK_STRUCT_TGID_OFFSET) as *const u32;
    let target_tgid = match bpf_probe_read_kernel::<u32>(tgid_ptr) {
        Ok(v) => v,
        Err(_) => return 0,
    };

    if target_tgid != protected {
        return 0;
    }

    // Tappa 8 escape hatch. The map is empty in the shipped Tappa 7
    // build; the lookup exists so the wiring is in place when the
    // Ed25519 verifier lands.
    let override_active = match PTRACE_OVERRIDE.get(0) {
        Some(v) => *v,
        None => 0,
    };
    if override_active != 0 {
        return 0;
    }

    -EPERM
}
