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
//! PID 1 (systemd) is no exception by itself: it signals a protected
//! process only under a [`KILL_GRANT`] the agent writes for a signed
//! trusted-installer window, or as `systemd-shutdown` at the very end of
//! a shutdown (external audit EBPF-001).
use northnarrow_common::wire::{InodeKey, KillGrant, FS_OP_SIGNAL};
use aya_ebpf::{
    cty::{c_int, c_void},
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{lsm, map},
    maps::{Array, HashMap},
    programs::LsmContext,
};

use crate::btf_offsets::TASK_STRUCT_TGID_OFFSET;

/// Kept for the doc/trace vocabulary; the policy below is now
/// deny-by-default for every signal, not a KILL/TERM allowlist.
#[allow(dead_code)]
const SIGKILL: c_int = 9;
#[allow(dead_code)]
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

/// External audit EBPF-001: when PID 1 may signal a protected process.
/// One slot, written by the agent only while a signed trusted-installer
/// window is open (the units are stopped or restarted with `systemctl`
/// during an upgrade or maintenance) and zeroed when it closes and at
/// every boot. It replaces BUG-010's `KILL_OVERRIDE`, which the agent
/// armed at boot for its whole life: any root shell could then stop or
/// kill the agent with `systemctl stop`/`kill`. See
/// [`KillGrant`](northnarrow_common::wire::KillGrant).
///
/// Pinned by name alongside `PROTECTED_PIDS` so the pinned hook and the
/// agent share one kernel object across restarts.
#[map]
pub static KILL_GRANT: Array<KillGrant> = Array::pinned(1, 0);

/// External audit EBPF-001: `(dev, ino)` of `systemd-shutdown`, the
/// program PID 1 becomes for the final stage of a shutdown (it signals
/// every remaining process, then halts or reboots). Written by the agent
/// at boot and kept current; zero means no carve-out.
#[map]
pub static SHUTDOWN_EXE: Array<InodeKey> = Array::pinned(1, 0);

/// BUG-010 (PHASE 15.1): per-boot session nonce. The agent picks a
/// fresh random u32 at boot and writes it here before LSM attach. Every
/// override and grant the hooks honour ([`KILL_GRANT`],
/// `FS_PROTECT_OVERRIDE`, `PTRACE_OVERRIDE`) must carry it, so a value
/// pinned by an earlier run is dead after a restart.
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

    // Policy (audit `task-kill-signals-1`, 2026-10-08): towards a
    // PROTECTED target, DENY EVERY signal except an explicit allowlist.
    // The previous "only SIGKILL + SIGTERM" rule left the agent's own
    // shutdown handlers reachable by any root shell: SIGINT / SIGHUP
    // are graceful-stop signals in main.rs, SIGQUIT's default action
    // terminates, SIGSTOP freezes the process (ptrace is denied, stop
    // was not), SIGSEGV/SIGABRT/SIGBUS abort it. `kill -INT <agent>`
    // from root stopped the agent cleanly — the exact "even root can't
    // stop it" guarantee Tappa 7 promises. Note this hook only sees
    // USERSPACE-originated signals (kill/tkill/rt_sigqueueinfo):
    // kernel-generated SIGCHLD/SIGPIPE/faults never reach
    // security_task_kill, so no allowlist entry is needed for them.
    //
    // Allowed regardless of target:
    //   - sig 0: existence probe (the watchdog's `kill -0`, nn-admin).
    // Allowed by CALLER (checked after the protected-target lookup):
    //   - caller == target: the process signalling itself (raise,
    //     tgkill between its own threads).
    //   - caller is itself in PROTECTED_PIDS: the watchdog's
    //     stuck-recovery SIGINT→SIGKILL and the agent↔watchdog pair.
    //   - caller is PID 1 under a live grant, or PID 1 as
    //     systemd-shutdown (below).
    let sig: c_int = ctx.arg(2);
    if sig == 0 {
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
    let tgid_ptr = (target as *const u8).add(off!(TASK_STRUCT_TGID_OFFSET)) as *const u32;
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

    let caller_tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    // Self-signal, or one protected process signalling another (the
    // watchdog's stuck recovery, the agent's own supervision of the
    // watchdog). An attacker's shell is in neither set.
    if caller_tgid == target_tgid || PROTECTED_PIDS.get(&caller_tgid).is_some() {
        return 0;
    }

    // External audit EBPF-001: PID 1 (systemd) signals a protected
    // process only (a) under a live grant — written for a signed
    // trusted-installer window, for the stop signals, until the window
    // ends, under this boot's session nonce — or (b) as
    // `systemd-shutdown`, the final stage of a shutdown, past which the
    // machine halts: the units are not stopped by the shutdown
    // transaction (no `Conflicts=shutdown.target`) and end here.
    // `systemctl stop`/`kill`/`restart` outside a window is refused like
    // a root shell's `kill`: systemd only relays root's request.
    if caller_tgid == 1 && (pid1_granted(sig) || pid1_is_final_shutdown()) {
        return 0;
    }

    // Evidence: a refused signal is an attempt on the agent (rate-limited).
    crate::inode_protect::emit_task_denial(FS_OP_SIGNAL, sig as u64, target_tgid);
    -EPERM
}

#[inline(always)]
fn pid1_granted(sig: c_int) -> bool {
    let session = match AGENT_SESSION.get(0) {
        Some(v) => *v,
        None => return false,
    };
    match KILL_GRANT.get(0) {
        Some(g) => g.allows(sig, unsafe { bpf_ktime_get_ns() }, session),
        None => false,
    }
}

/// `comm` of `systemd-shutdown` (15 bytes and the NUL), as two words: an
/// array compare would lower to a `memcmp` call.
const SHUTDOWN_COMM_LO: u64 = u64::from_ne_bytes(*b"systemd-");
const SHUTDOWN_COMM_HI: u64 = u64::from_ne_bytes(*b"shutdow\0");

/// PID 1 is running `systemd-shutdown`: the comm (only PID 1 itself can
/// set it) AND the executable the agent recorded — a comm set through
/// `ptrace` of PID 1 is not enough.
#[inline(always)]
fn pid1_is_final_shutdown() -> bool {
    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => return false,
    };
    let words: [u64; 2] = unsafe { core::mem::transmute(comm) };
    if words[0] != SHUTDOWN_COMM_LO || words[1] != SHUTDOWN_COMM_HI {
        return false;
    }
    let want = match SHUTDOWN_EXE.get(0) {
        Some(k) if k.ino != 0 => *k,
        _ => return false,
    };
    match unsafe { crate::bpf_defense::caller_exe_key() } {
        Some(k) => k.dev == want.dev && k.ino == want.ino,
        None => false,
    }
}
