//! `task_kill` LSM hook — anti-tamper signal denial.
//!
//! Tappa 7 (ROADMAP.md): the agent must survive `SIGKILL`/`SIGTERM`
//! from any sender, including `root`. The kernel-mode policy is
//! enforced here by returning `-EPERM` when the target `tgid` is
//! present in the [`PROTECTED_PIDS`] map. Task 6 (Tappa 7) widened
//! the map from a single-slot `Array<u32>` to a `HashMap<u32, u8>`
//! so the agent AND the watchdog can both be protected from one
//! lookup.
//!
//! Kernel hook signature (`linux/lsm_hook_defs.h`):
//! ```c
//! LSM_HOOK(int, 0, task_kill,
//!     struct task_struct *p,
//!     struct kernel_siginfo *info,
//!     int sig,
//!     const struct cred *cred)
//! ```
//! Aya appends the LSM chain `retval` as the last argument (`arg(4)`),
//! 0 if this is the first hook on the path. We honour any prior
//! denial by passing it through.
//!
//! Tappa 8 dependency: the signed-channel exception is stubbed via
//! the [`KILL_OVERRIDE`] map. It is always empty in the Tappa 7
//! build, so root truly cannot kill the agent. Tappa 8 will wire an
//! Ed25519 verifier in userland that flips slot 0 to a non-zero
//! capability token after admin-signed approval.

use aya_ebpf::{
    cty::{c_int, c_void},
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel},
    macros::{lsm, map},
    maps::{Array, HashMap},
    programs::LsmContext,
};

use crate::btf_offsets::TASK_STRUCT_TGID_OFFSET;

const SIGKILL: c_int = 9;
const SIGTERM: c_int = 15;

/// Linux `EPERM` value; LSM hooks return `-errno` to deny.
const EPERM: c_int = 1;

/// PIDs the userland loader has registered for protection. Multi-PID
/// support (Tappa 7 task 6) replaces the prior `PROTECTED_PID:
/// Array<u32>` (single slot) so the agent AND the watchdog can both
/// be protected from the same hook with one bpf_map_lookup_elem.
///
/// Value is unused — presence is the signal — kept as `u8` to keep
/// each map node tiny. `max_entries = 16` is generous headroom for
/// V1 (agent + watchdog + room for future nn-config-daemon, Tappa 9);
/// real-world occupancy is 2 entries.
///
/// `0` is NOT a valid PID, so an empty map fails open (no protection)
/// rather than denying every kill on the host.
///
/// `HashMap::pinned` (Tappa 7 task 6 commit #2) emits
/// `LIBBPF_PIN_BY_NAME`. Aya only consults `EbpfLoader::map_pin_path`
/// for maps carrying that flag (`aya-0.13.1` `bpf.rs:494`); a plain
/// `with_max_entries` declaration is created fresh on every load,
/// which split-brained the pinned LSM hook off a stale map. Pinned,
/// a restarted agent reuses the SAME kernel map object via
/// `bpf_get_object`, keeping the hook's map binding intact.
#[map]
pub static PROTECTED_PIDS: HashMap<u32, u8> = HashMap::pinned(16, 0);

/// BUG-010 (PHASE 15.1): PID-1 carve-out token. Slot 0 holds the
/// agent's per-boot session nonce when the carve-out is armed;
/// zero (the default) means the carve-out is dormant and even PID 1
/// is denied.
///
/// The hook compares `KILL_OVERRIDE[0]` against [`AGENT_SESSION`]`[0]`.
/// Both are written by the agent at boot (see
/// `agent/src/anti_tamper/mod.rs::arm_kill_override`); a non-zero
/// match plus `caller_tgid == 1` bypasses the deny. The double-map
/// design lets a leftover pinned `KILL_OVERRIDE` from a prior install
/// be effectively dead after restart (new session nonce won't match
/// stale slot value).
///
/// Pinned by-name alongside `PROTECTED_PIDS` so the pinned hook and
/// userland share one kernel object across agent restarts.
#[map]
pub static KILL_OVERRIDE: Array<u32> = Array::pinned(1, 0);

/// BUG-010 (PHASE 15.1): per-boot session nonce. The agent picks a
/// fresh random u32 at boot and writes the SAME value to both this
/// map and [`KILL_OVERRIDE`] before LSM attach. The hook accepts the
/// PID-1 carve-out only when both slots are equal and non-zero;
/// otherwise (stale pinned slot from prior install, attacker who only
/// wrote `KILL_OVERRIDE`, etc.) it falls through to the deny.
#[map]
pub static AGENT_SESSION: Array<u32> = Array::pinned(1, 0);

#[lsm(hook = "task_kill")]
pub fn task_kill(ctx: LsmContext) -> i32 {
    unsafe { try_task_kill(&ctx) }
}

#[inline(always)]
unsafe fn try_task_kill(ctx: &LsmContext) -> i32 {
    // No prev-retval read on this kernel. Aya 0.13 documents a
    // "phony retval at arg(N)" convention, but on Ubuntu 6.8's
    // BPF-LSM trampoline that slot is not reliably zero-initialised
    // — file_ioctl was silently early-returning because of garbage
    // at arg(3) (see 2026-05-12 diagnosis). The kernel's
    // call_int_hook macro short-circuits the LSM chain on the first
    // non-zero verdict anyway, so we are only ever invoked when all
    // prior LSMs returned 0; the prev-retval read is dead code.

    // We only police the two signals that can terminate a daemon
    // without coordination. Everything else (SIGCHLD, SIGWINCH,
    // SIGUSR1, …) goes through untouched so the agent's own
    // signal handlers (graceful reload, etc.) keep working.
    let sig: c_int = ctx.arg(2);
    if sig != SIGKILL && sig != SIGTERM {
        return 0;
    }

    let target: *const c_void = ctx.arg(0);
    if target.is_null() {
        return 0;
    }

    // Read `target->tgid` via the probe helper. With LSM + BTF the
    // pointer is a kernel-trusted `PTR_TO_BTF_ID`, but we use the
    // explicit helper so the verifier accepts the read without a
    // CO-RE relocation we don't yet emit from Rust.
    let tgid_ptr = (target as *const u8).add(TASK_STRUCT_TGID_OFFSET) as *const u32;
    let target_tgid = match bpf_probe_read_kernel::<u32>(tgid_ptr) {
        Ok(v) => v,
        Err(_) => return 0,
    };

    // Multi-PID lookup. `HashMap::get` in aya-ebpf returns a raw
    // pointer to the value; we only care about presence, so the
    // is_some() check collapses to a single bpf_map_lookup_elem
    // call. Marked unsafe because the returned reference can be
    // invalidated if the map mutates concurrently — we don't deref
    // it, so the invalidation window is irrelevant here.
    let is_protected = PROTECTED_PIDS.get(&target_tgid).is_some();
    if !is_protected {
        return 0;
    }

    // BUG-010 (PHASE 15.1): PID-1 carve-out. systemd is the host's
    // legitimate process supervisor; without this `systemctl restart`
    // hangs forever (catalog §4). The carve-out fires ONLY when:
    //   1. The caller is PID 1 (kernel-assigned; not spoofable from
    //      userspace).
    //   2. The agent has armed the override by writing matching
    //      session-nonce values to KILL_OVERRIDE and AGENT_SESSION.
    //      Both default to zero; a leftover pinned slot from a prior
    //      install will not match the new agent's freshly-chosen
    //      nonce, so stale pins are effectively dead.
    // An attacker running `kill -TERM <agent>` from their own PID has
    // `caller_tgid != 1` and is still denied. A root attacker capable
    // of writing both BPF maps already has the kernel-side power to
    // unpin the LSM hook outright — out of scope for the V1 model.
    let caller_tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if caller_tgid == 1 {
        let override_val = match KILL_OVERRIDE.get(0) {
            Some(v) => *v,
            None => 0,
        };
        let session_val = match AGENT_SESSION.get(0) {
            Some(v) => *v,
            None => 0,
        };
        if override_val != 0 && override_val == session_val {
            return 0;
        }
    }

    -EPERM
}
