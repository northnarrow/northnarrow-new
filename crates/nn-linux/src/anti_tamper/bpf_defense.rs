//! Userland half of the BPF self-defence (`agent-ebpf/src/bpf_defense.rs`).
//!
//! * attaches `bpf_map_guard` (deny set — counted in the fail-closed LSM
//!   health like every other deny hook) and `bpf_syscall_observe`
//!   (observe set: its attach failure does not refuse the start), and lot
//!   290's `bpf_prog_guard`; lot 302: the three pinned under the pin root
//!   like the deny hooks (`prog_<hook>`, `link_<hook>`), so the previous
//!   start's keep refusing through a restart or an upgrade's gap;
//! * registers the ids of every map and program of the loaded object in
//!   `OWN_BPF_IDS`, so the hooks recognise the agent's own objects;
//! * sets the mode: **enforce** in production, **observe** in
//!   `debug-trigger` builds (the e2e fixtures unprotect pids through
//!   `bpftool map delete`, which enforce denies by design) and when the
//!   operator sets [`OBSERVE_ENV`]`=1` for diagnosis.

use anyhow::{Context, Result};
use aya::maps::{Array, HashMap, Map, MapData};
use aya::{Btf, Ebpf};
use std::collections::HashSet;
use std::ffi::CString;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tracing::{debug, error, info, warn};

use crate::audit::{AuditEntryDraft, AuditLog};

/// Set to `1` to run the map guard in observe mode (log, never deny).
pub const OBSERVE_ENV: &str = "NN_BPF_DEFENSE_OBSERVE";
/// Set to `1` to ENFORCE even in a `debug-trigger` build (lab tests of the deny path).
pub const ENFORCE_ENV: &str = "NN_BPF_DEFENSE_ENFORCE";

pub const GUARD_PROGRAM: &str = "bpf_map_guard";
pub const GUARD_HOOK: &str = "bpf_map";
pub const OBSERVE_PROGRAM: &str = "bpf_syscall_observe";
pub const OBSERVE_HOOK: &str = "bpf";
/// Lot 290: the program-handle guard and the seen-load recorder.
pub const PROG_GUARD_PROGRAM: &str = "bpf_prog_guard";
pub const PROG_GUARD_HOOK: &str = "bpf_prog";
/// Lot 290: the signed per-loader opt-out's map (pinned by name).
pub const LOADER_OPTOUT_MAP: &str = "BPF_LOADER_OPTOUT";
/// Lot 345: the content judge at a load's kernel copy (6.9 and later).
pub const PROG_LOAD_GUARD_PROGRAM: &str = "bpf_prog_load_guard";
pub const PROG_LOAD_GUARD_HOOK: &str = "bpf_prog_load";
/// Lot 345: the content judge's configuration (written and frozen before
/// the guard is attached).
pub const CONTENT_CONF_MAP: &str = "PROG_CONTENT_CONF";

/// External audit EBPF-002: roles in `OWN_EXE_INODES` (mirrors
/// `agent-ebpf/src/bpf_defense.rs`).
const ROLE_WATCHDOG: u8 = 1;
const ROLE_AGENT: u8 = 2;
pub const ROLE_EXIT_PROGRAM: &str = "role_exit";
/// Pin of the liveness watch's link (a `link_*` pin: protected like the
/// LSM links, and found by the link self-check).
const ROLE_EXIT_LINK_PIN: &str = "link_role_exit";

const OWN_IDS_MAP: &str = "OWN_BPF_IDS";
const OWN_EXE_MAP: &str = "OWN_EXE_INODES";
const MODE_MAP: &str = "BPF_DEFENSE_MODE";
const KIND_MAP: u8 = 1;
const KIND_PROG: u8 = 2;
const KIND_LINK: u8 = 3;

/// Key of `OWN_BPF_IDS`: `(kind << 32) | id` — map, program and link ids
/// are independent kernel id spaces (mirrors `own_key` in the eBPF crate).
pub(crate) fn own_key(kind: u8, id: u32) -> u64 {
    ((kind as u64) << 32) | id as u64
}
const PIN_NAMES_MAP: &str = "OWN_PIN_NAMES";
/// The window the kernel reads a pin's final component from (mirrors
/// `PIN_NAME_LEN` in the eBPF crate): a longer name is never matched.
const PIN_NAME_LEN: usize = 32;
/// Prefix of the LSM link pins written by `antitamper_bpf::lsm_pin_paths`
/// (lot 300: and the self-test's consistency test reads it; lot 301: the
/// walk of the pin directories reads every entry, whatever its name).
pub const LINK_PIN_PREFIX: &str = "link_";
/// Period of the link self-check.
pub const LINK_CHECK_SECS: u64 = 10;
/// Audit op of a missing link (one entry per link, at the first miss).
pub const LINK_MISSING_AUDIT_OP: &str = "bpf_link_missing";

/// What the self-check needs, recorded at boot and read by the task spawned
/// later by the start (the audit log does not exist yet when the hooks
/// attach).
#[derive(Debug, Clone)]
struct OwnLinks {
    ids: Vec<u32>,
    pin_root: Option<PathBuf>,
}

/// The guard's record of this boot's own objects (R11c, lab PR 264): made
/// with the eBPF object (the maps' ids at the load,
/// [`Self::remember_loaded_maps`]), filled by the registration (the links
/// the self-check expects, the `link_*` pins that are not the agent's, the
/// liveness watch), read by the self-check and the foreign pins' attestation
/// the start runs once the audit log exists ([`Self::spawn_link_self_check`],
/// [`Self::attest_foreign_pins`]), told of the links the agent retires and
/// of its stop. The multiplexer that owns the object holds it. They were
/// process-wide statics (`LOADED_MAP_IDS`, `OWN_LINKS`, `FOREIGN_PINS`,
/// `RETIRED_LINKS`, `ROLE_WATCH`, `STOPPING`).
#[derive(Clone, Default)]
pub struct BpfGuard(Arc<GuardState>);

#[derive(Default)]
struct GuardState {
    /// External audit ATP-013: the ids of every map of the object as
    /// loaded, taken before the sensors move maps out of it. `take_map`
    /// removes a map from `ebpf.maps()`, and the twelve ring buffers
    /// (`FS_PROTECT_EVENTS`, with the anti-tamper denials, among them) and
    /// `RING_DROPS` were taken before [`register_own_objects`] ran: none
    /// was in `OWN_BPF_IDS`, so the guard handed a foreign root a writable
    /// handle on each — enough to move a ring's consumer position,
    /// silencing that sensor, or to zero the drop counters. `Err` names the
    /// maps whose id could not be read.
    loaded_map_ids: parking_lot::Mutex<Option<std::result::Result<Vec<u32>, String>>>,
    own_links: OnceLock<OwnLinks>,
    /// Links the agent detached on purpose (Tappa 10.9 step 1: the
    /// `sys_enter_openat` tracepoint once the LSM file-open sensor takes
    /// over). The self-check stops expecting them; any other missing link
    /// is still tampering.
    retired_links: parking_lot::Mutex<HashSet<u32>>,
    /// The `link_*` entries found at boot that are not the agent's links,
    /// for one signed `integrity_drift` each once the audit log is open
    /// ([`BpfGuard::attest_foreign_pins`]).
    foreign_pins: parking_lot::Mutex<Vec<String>>,
    /// The liveness watch is attached: `ROLE_TGIDS` slots are claimed.
    role_watch: std::sync::atomic::AtomicBool,
    /// The agent is stopping: its links go with it, and the self-check must
    /// not report them ([`BpfGuard::mark_stopping`]).
    stopping: std::sync::atomic::AtomicBool,
    /// Lot 290: the ids of the agent's programs, both registrations (the
    /// cross-view's "own").
    own_progs: parking_lot::Mutex<std::collections::BTreeSet<u32>>,
    /// Lot 290: the cross-view's kernel parts, set up at the attach and
    /// handed to the kernel-state round ([`BpfGuard::crossview`]).
    census: parking_lot::Mutex<Option<crate::bpf_crossview::Parts>>,
}

impl BpfGuard {
    /// An empty record, for one eBPF object.
    pub fn new() -> Self {
        Self::default()
    }

    /// Lot 290: the agent's program ids registered so far.
    pub fn own_prog_ids(&self) -> std::collections::BTreeSet<u32> {
        self.0.own_progs.lock().clone()
    }

    /// Lot 304: program `id` as one enumeration of the cross-view's
    /// iterators has it now (before the kernel-state round takes them), or
    /// why not.
    pub fn census_program(&self, id: u32) -> Result<crate::known_system_prog::Program, String> {
        let census = self.0.census.lock();
        let parts = census.as_ref().ok_or("no BPF cross-view iterators")?;
        let en = parts.enumerate()?;
        en.progs
            .iter()
            .find(|p| p.id == id)
            .map(crate::bpf_crossview::program_of)
            .ok_or_else(|| format!("program {id} not in the enumeration"))
    }

    /// Lot 290: the cross-view for the kernel-state round (its kernel parts
    /// taken once; `None` when the attach could not set them up — a signed
    /// degradation then), its status file at `status`.
    pub fn crossview(&self, status: Option<PathBuf>) -> Option<crate::bpf_crossview::CrossView> {
        let parts = self.0.census.lock().take()?;
        let guard = self.clone();
        Some(crate::bpf_crossview::CrossView {
            parts,
            own: Box::new(move || guard.own_prog_ids()),
            status,
            watch: crate::bpf_crossview::Watch::new(
                crate::bpf_crossview::host_user_space_start_ns(),
            ),
        })
    }

    /// Retire every live link of program `prog_id` before the agent itself
    /// detaches it; the number of links retired.
    pub fn retire_program_links(&self, prog_id: u32) -> usize {
        let pin_root = self.0.own_links.get().and_then(|o| o.pin_root.clone());
        let ids: Vec<u32> = live_links(pin_root.as_deref())
            .into_iter()
            .filter(|(_, prog)| *prog == prog_id)
            .map(|(id, _)| id)
            .collect();
        self.0.retired_links.lock().extend(ids.iter().copied());
        ids.len()
    }
}

/// `BPF_OBJ_GET` (lab PR 215: the number from `common::bpf_cmd`, the one
/// copy the eBPF hooks use too).
const OBJ_GET: libc::c_long = common::bpf_cmd::BPF_OBJ_GET as libc::c_long;

/// The `OBJ_GET` variant of `union bpf_attr`; a shorter `size` than the
/// union is accepted by the kernel (the rest is treated as zero).
#[repr(C)]
struct ObjGetAttr {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
}

/// What `register_own_objects` wrote to the kernel.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct OwnObjects {
    pub maps: usize,
    pub programs: usize,
    pub links: usize,
    pub pin_names: usize,
    pub enforce: bool,
}

#[derive(Debug, Default)]
pub(crate) struct BpfDefenseHealth {
    pub deny_failures: Vec<(&'static str, String)>,
    pub observe_failures: Vec<(&'static str, String)>,
}

/// Whether the guard should deny (true) or only observe (false).
pub fn enforce_mode() -> bool {
    if std::env::var(ENFORCE_ENV)
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        return true;
    }
    if cfg!(feature = "debug-trigger") {
        return false;
    }
    !std::env::var(OBSERVE_ENV)
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// External audit ATP-009: a guard that only observes refuses nothing. In a
/// production build that is a missing deny hook (it then starts only with
/// the degraded-mode override); a debug-trigger build observes by design
/// and says so on its signed boot entry.
pub(crate) fn observe_shortfall(enforce: bool, debug_build: bool) -> Option<String> {
    (!enforce && !debug_build).then(|| {
        format!(
            "observe mode ({OBSERVE_ENV}=1): foreign write handles on the agent's maps and \
             handles to its links are not refused"
        )
    })
}

/// Attach both hooks (deny + observe). Errors are reported to the caller's
/// health accounting, not returned: the anti-tamper health decides the
/// fail-closed outcome. Lot 302: the three LSM hooks of the guard
/// (`bpf_map`, `bpf`, `bpf_prog`) are pinned under `pin_root` and
/// re-attached fresh, the previous start's kept until this start's runs —
/// `bpf` and `bpf_prog` where the guard enforces ([`attach_guard_hook`]).
pub(crate) fn attach(
    guard: &BpfGuard,
    ebpf: &mut Ebpf,
    btf: &Btf,
    pin_root: Option<&Path>,
) -> BpfDefenseHealth {
    let mut health = BpfDefenseHealth::default();
    let enforce = enforce_mode();
    match antitamper_bpf::reattach_fresh(ebpf, GUARD_PROGRAM, GUARD_HOOK, btf, pin_root) {
        Ok(()) => info!(
            program = GUARD_PROGRAM,
            hook = GUARD_HOOK,
            "BPF self-defence: map guard attached"
        ),
        Err(e) => {
            dump_verifier_log(GUARD_PROGRAM, &e);
            warn!(
                program = GUARD_PROGRAM,
                hook = GUARD_HOOK,
                error = format!("{e:#}"),
                "BPF self-defence: map guard attach FAILED — the agent's maps are writable by root"
            );
            health.deny_failures.push((GUARD_PROGRAM, format!("{e:#}")));
        }
    }
    // External audit EBPF-002: the liveness watch behind the fresh-instance
    // window. Without it the window is bounded by age only (an ERROR):
    // restarts keep working.
    match attach_role_exit(ebpf, pin_root) {
        Ok(()) => {
            guard
                .0
                .role_watch
                .store(true, std::sync::atomic::Ordering::SeqCst);
            info!(
                program = ROLE_EXIT_PROGRAM,
                "BPF self-defence: role liveness watch attached (sched_process_exit)"
            );
        }
        Err(e) => {
            dump_verifier_log(ROLE_EXIT_PROGRAM, &e);
            error!(
                program = ROLE_EXIT_PROGRAM,
                error = format!("{e:#}"),
                "BPF self-defence: role liveness watch attach FAILED — a fresh agent or \
                 watchdog binary may take the agent's maps in its first minute even beside \
                 the live one"
            );
            health
                .observe_failures
                .push((ROLE_EXIT_PROGRAM, format!("{e:#}")));
        }
    }
    // Lot 345 (the re-check of #550, point 1 (ii)): the content judge — a
    // foreign program of a type refused by default (one only a signed
    // per-loader opt-out lets through) that calls a helper or kfunc that
    // signals, writes a process's memory or overrides a return is refused,
    // opt-out or not. 6.9 and later: at `bpf_prog_load`, on the kernel's
    // copy of the instructions (the helpers' ids). Before: at `bpf_prog`, on
    // the verified ones, against targets the hook calibrates from the
    // agent's own programs (below, once that hook is attached), and
    // `bpf_probe_write_user` at the verifier's lockdown question.
    let resolved = crate::anti_tamper::btf_revalidate::resolved();
    let at_load = resolved.is_some_and(|r| r.prog_load_hook)
        && match attach_guard_hook(
            ebpf,
            PROG_LOAD_GUARD_PROGRAM,
            PROG_LOAD_GUARD_HOOK,
            btf,
            pin_root,
            enforce,
        ) {
            Ok(()) => {
                info!(
                    program = PROG_LOAD_GUARD_PROGRAM,
                    hook = PROG_LOAD_GUARD_HOOK,
                    "BPF self-defence: content judge attached at the load (the kernel's copy)"
                );
                true
            }
            Err(e) => {
                dump_verifier_log(PROG_LOAD_GUARD_PROGRAM, &e);
                warn!(program = PROG_LOAD_GUARD_PROGRAM, error = format!("{e:#}"), "BPF self-defence: content judge at the load NOT attached — judged at the handle instead");
                health
                    .observe_failures
                    .push((PROG_LOAD_GUARD_PROGRAM, format!("{e:#}")));
                false
            }
        };
    if at_load {
        let judge = ContentJudge::at_load(
            resolved.map_or([None; common::bpf_prog_class::FORBIDDEN_KFUNCS.len()], |r| {
                *r.forbidden_kfunc_ids
            }),
        );
        match write_content_judge(ebpf, &judge, true) {
            Ok(()) => info!(
                kfuncs_every_type = judge.every_type,
                "BPF self-defence: content judge armed at the load (a foreign load of every type \
                 read for the signalling kfuncs this kernel has)"
            ),
            Err(e) => {
                warn!(error = %e, "BPF self-defence: content judge NOT armed");
                health
                    .observe_failures
                    .push((CONTENT_JUDGE, format!("{e} — {OPT_OUTS_SUSPENDED}")));
            }
        }
    }
    // Lot 302: the bpf() guard pinned like the deny hooks (`prog_bpf`,
    // `link_bpf` under the pin root, attach-before-purge): it went with the
    // agent, so through a restart or an upgrade's gap a handle on one of the
    // agent's links (the start-in-cgroup tracker's, pinned beside the root
    // and running all along) was given by id, and a kprobe or LSM program
    // was loaded unrefused (lot 301's residual). Pinned, the previous
    // start's program keeps refusing until this one is attached; its maps
    // (the own ids, the mode) live as long as its pin. A failure is still
    // an observe failure (the start goes on, signed).
    match attach_guard_hook(ebpf, OBSERVE_PROGRAM, OBSERVE_HOOK, btf, pin_root, enforce) {
        Ok(()) => info!(
            program = OBSERVE_PROGRAM,
            hook = OBSERVE_HOOK,
            pinned = pin_root.is_some() && enforce,
            "BPF self-defence: bpf() syscall guard attached"
        ),
        Err(e) => {
            dump_verifier_log(OBSERVE_PROGRAM, &e);
            warn!(program = OBSERVE_PROGRAM, hook = OBSERVE_HOOK, error = format!("{e:#}"), "BPF self-defence: bpf() observer attach FAILED — foreign BPF activity not reported");
            health
                .observe_failures
                .push((OBSERVE_PROGRAM, format!("{e:#}")));
        }
    }
    // Lot 290: the program-handle guard (and the seen loads' recorder), and
    // the cross-view's iterators.
    // Lot 302: pinned too (`prog_bpf_prog`, `link_bpf_prog`): a handle on
    // one of the agent's programs through a path the bpf() guard does not
    // read (a relative one, a bind mount) stays refused through the gap.
    match attach_guard_hook(
        ebpf,
        PROG_GUARD_PROGRAM,
        PROG_GUARD_HOOK,
        btf,
        pin_root,
        enforce,
    ) {
        Ok(()) => info!(
            program = PROG_GUARD_PROGRAM,
            hook = PROG_GUARD_HOOK,
            pinned = pin_root.is_some() && enforce,
            "BPF self-defence: program-handle guard attached"
        ),
        Err(e) => {
            dump_verifier_log(PROG_GUARD_PROGRAM, &e);
            warn!(program = PROG_GUARD_PROGRAM, hook = PROG_GUARD_HOOK, error = format!("{e:#}"), "BPF self-defence: program-handle guard attach FAILED — handles on the agent's programs not refused, loads not seen");
            health
                .observe_failures
                .push((PROG_GUARD_PROGRAM, format!("{e:#}")));
        }
    }
    // Lot 345: before 6.9, the content judge at the handle — calibrated by
    // the `bpf_prog` hook just attached, then armed and frozen.
    if !at_load {
        let lockdown = resolved.and_then(|r| r.lockdown_bpf_write_user);
        match arm_content_at_handle(ebpf, btf, pin_root, enforce, lockdown) {
            Ok(judge) => info!(
                targets = ?judge.targets,
                "BPF self-defence: content judge armed at the handle (calibrated)"
            ),
            Err(e) => {
                warn!(error = %e, "BPF self-defence: content judge at the handle NOT fully armed — the error says what an opted-out loader still loads, or that the opt-outs are suspended");
                health.observe_failures.push((CONTENT_JUDGE, e));
            }
        }
    }
    match crate::bpf_crossview::Parts::setup(ebpf, btf) {
        Ok(parts) => {
            *guard.0.census.lock() = Some(parts);
            info!("BPF self-defence: cross-view iterators ready");
        }
        Err(e) => {
            warn!(error = %e, "BPF self-defence: cross-view NOT set up — a program the bpf hook never saw is not found");
            health
                .observe_failures
                .push((crate::bpf_crossview::ITER_PROGS, e));
        }
    }
    health
}

/// Lot 302: the `bpf` or `bpf_prog` hook, pinned and re-attached fresh
/// where the guard enforces (production builds) — the previous start's
/// keeps refusing through a restart's or an upgrade's gap. An observing
/// guard (a `debug-trigger` build, `NN_BPF_DEFENSE_OBSERVE=1`) lives with
/// the agent, as before: its type refusals, which hold in every mode, would
/// otherwise outlive a stopped lab or test agent and refuse every later
/// kprobe or tracepoint load on the host (the KVM CI's in-process sensor
/// tests). A guard an earlier, enforcing start pinned is retired once this
/// start's runs (attach before purge).
fn attach_guard_hook(
    ebpf: &mut Ebpf,
    program: &str,
    hook: &str,
    btf: &Btf,
    pin_root: Option<&Path>,
    enforce: bool,
) -> Result<()> {
    match pin_root {
        Some(root) if enforce => {
            antitamper_bpf::reattach_fresh(ebpf, program, hook, btf, Some(root))
        }
        _ => {
            antitamper_bpf::attach_transient(ebpf, program, hook, btf)?;
            if let Some(root) = pin_root {
                let (prog_pin, link_pin) = antitamper_bpf::lsm_pin_paths(root, hook);
                antitamper_bpf::purge_stale_pin(&link_pin);
                antitamper_bpf::purge_stale_pin(&prog_pin);
            }
            Ok(())
        }
    }
}

/// Lot 345: the content judge, as its failures name it.
pub const CONTENT_JUDGE: &str = "bpf content judge";

/// Lot 345: the content judge's configuration for the running kernel —
/// `PROG_CONTENT_CONF` (`bpf_prog_class::CONTENT_CONF_SLOTS`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentJudge {
    /// `bpf_prog_class::CONTENT_STAGE_*`.
    pub stage: u32,
    /// `bpf_prog_class::CALL_TARGETS`, as the judged copy names them.
    pub targets: [u32; common::bpf_prog_class::CALL_TARGETS],
    /// The review of #553 (F1): how many kfunc targets this kernel has —
    /// not 0, a foreign load of EVERY type is read for them at
    /// `bpf_prog_load` (`bpf_prog_class::CONTENT_EVERY_TYPE_SLOT`).
    pub every_type: u32,
    /// Why there is no judge on this kernel (then `stage` is off).
    pub off: Option<String>,
}

impl ContentJudge {
    /// The call keys of the targets, each with its slot plus one
    /// (`PROG_CONTENT_KEYS`): none when the judge is off (its targets are
    /// all 0).
    pub fn keys(&self) -> Vec<(u64, u32)> {
        self.targets
            .iter()
            .enumerate()
            .filter_map(|(slot, t)| {
                common::bpf_prog_class::target_key(slot, *t).map(|k| (k, slot as u32 + 1))
            })
            .collect()
    }

    /// 6.9 and later, at `bpf_prog_load`: the helpers' uapi ids, and each
    /// kfunc's BTF id where vmlinux has it (`kfunc_btf_ids`, in the order of
    /// `bpf_prog_class::FORBIDDEN_KFUNCS`) — read in a foreign load of every
    /// type (the review of #553, F1).
    pub fn at_load(
        kfunc_btf_ids: [Option<u32>; common::bpf_prog_class::FORBIDDEN_KFUNCS.len()],
    ) -> Self {
        use common::bpf_prog_class::{
            CALL_TARGETS, CONTENT_STAGE_LOAD, FORBIDDEN_HELPERS, HELPER_SLOTS,
        };
        let mut targets = [0u32; CALL_TARGETS];
        for (slot, (id, _)) in FORBIDDEN_HELPERS.iter().enumerate() {
            targets[slot] = *id;
        }
        for (k, id) in kfunc_btf_ids.iter().enumerate() {
            targets[HELPER_SLOTS + k] = id.unwrap_or(0);
        }
        Self {
            stage: CONTENT_STAGE_LOAD,
            targets,
            every_type: kfunc_btf_ids.iter().flatten().count() as u32,
            off: None,
        }
    }

    /// No judge on this kernel, and why (the opt-outs are then suspended:
    /// the `bpf` hook honours none while the stage is off).
    pub fn off(why: String) -> Self {
        Self {
            stage: common::bpf_prog_class::CONTENT_STAGE_OFF,
            targets: [0; common::bpf_prog_class::CALL_TARGETS],
            every_type: 0,
            off: Some(why),
        }
    }

    /// Before 6.9, at `bpf_prog` once verified: a helper call's `imm` is
    /// then the helper's address less `__bpf_call_base` (the verifier's
    /// fix-up). `calibrated`: the targets the hook read from the agent's
    /// calibration programs (`PROG_CONTENT_CONF` after their loads) — the
    /// signals are required (without them nothing is judged); the return
    /// override is absent from a kernel built without
    /// `CONFIG_BPF_KPROBE_OVERRIDE`; `bpf_probe_write_user`'s slot stays 0
    /// (refused at the `locked_down` hook instead).
    pub fn at_handle(calibrated: [u32; common::bpf_prog_class::CALL_TARGETS]) -> Self {
        use common::bpf_prog_class::{CALL_TARGETS, CONTENT_STAGE_HANDLE, FORBIDDEN_HELPERS};
        let mut targets = [0u32; CALL_TARGETS];
        // the slots the calibrations fill: override, send_signal, _thread
        targets[1..4].copy_from_slice(&calibrated[1..4]);
        let missing: Vec<&str> = [2, 3]
            .iter()
            .filter(|s| targets[**s] == 0)
            .map(|s| FORBIDDEN_HELPERS[*s].1)
            .collect();
        if !missing.is_empty() {
            return Self::off(format!(
                "the calibration found no verified call of {}",
                missing.join(", ")
            ));
        }
        Self {
            stage: CONTENT_STAGE_HANDLE,
            targets,
            every_type: 0,
            off: None,
        }
    }
}

/// The review of #553 (F4): what a content judge that is not armed costs —
/// said in its observe failure (a signed degradation).
pub const OPT_OUTS_SUSPENDED: &str = "the bpf-loader-allow opt-outs are suspended: their types are \
     refused to every loader outside a window again, until a start arms the judge";

/// Lot 345 (before 6.9): calibrate the content judge — load each of the
/// agent's calibration programs while `PROG_CONTENT_CALIB` asks for it (the
/// `bpf_prog` hook writes the verified calls' targets), unload them, read
/// the targets back — then arm the stage and freeze the configuration.
///
/// The review of #553 (F4): the `locked_down` guard for
/// `bpf_probe_write_user` (this kernel's `LOCKDOWN_BPF_WRITE_USER`,
/// `lockdown`) is attached FIRST — it reads no calibration, and a failed one
/// dropped it with the rest. A failed calibration leaves the stage off,
/// which suspends the opt-outs (the `bpf` hook honours none then:
/// [`OPT_OUTS_SUSPENDED`]) — fail closed, where the opted-out loaders got
/// back the signals and the return override.
fn arm_content_at_handle(
    ebpf: &mut Ebpf,
    btf: &Btf,
    pin_root: Option<&Path>,
    enforce: bool,
    lockdown: Option<u32>,
) -> std::result::Result<ContentJudge, String> {
    use common::bpf_prog_class::{
        CALIB_NONE, CALIB_OVERRIDE, CALIB_SIGNALS, CALL_TARGETS, CONTENT_LOCKDOWN_SLOT,
    };
    let write_user = match lockdown {
        Some(v) if v != 0 => match attach_guard_hook(
            ebpf,
            WRITE_USER_GUARD_PROGRAM,
            WRITE_USER_GUARD_HOOK,
            btf,
            pin_root,
            enforce,
        ) {
            Ok(()) => Ok(v),
            Err(e) => {
                dump_verifier_log(WRITE_USER_GUARD_PROGRAM, &e);
                Err(format!("{WRITE_USER_GUARD_PROGRAM} not attached: {e:#}"))
            }
        },
        _ => Err("this kernel's BTF names no LOCKDOWN_BPF_WRITE_USER".to_string()),
    };
    if let Ok(v) = &write_user {
        let m = ebpf
            .map_mut(CONTENT_CONF_MAP)
            .ok_or_else(|| format!("{CONTENT_CONF_MAP} missing from the eBPF object"))?;
        let mut conf: Array<&mut MapData, u32> =
            Array::try_from(m).map_err(|e| format!("{CONTENT_CONF_MAP}: {e}"))?;
        conf.set(CONTENT_LOCKDOWN_SLOT, *v, 0)
            .map_err(|e| format!("{CONTENT_CONF_MAP} slot {CONTENT_LOCKDOWN_SLOT}: {e}"))?;
    }
    let write_user_note = match &write_user {
        Ok(_) => String::new(),
        Err(e) => format!("; bpf_probe_write_user is not refused at the lockdown question ({e})"),
    };
    let mut calibrated = [0u32; CALL_TARGETS];
    let mut wrong: Vec<String> = Vec::new();
    for (kind, program) in [
        (CALIB_SIGNALS, CALIB_SIGNALS_PROGRAM),
        (CALIB_OVERRIDE, CALIB_OVERRIDE_PROGRAM),
    ] {
        clear_seen(ebpf)?;
        set_calibration(ebpf, kind)?;
        let loaded = load_calibration(ebpf, program);
        set_calibration(ebpf, CALIB_NONE)?;
        if let Err(e) = loaded {
            // the override's helper is absent from some kernels' builds
            debug!(program, error = %e, "BPF self-defence: calibration program not loaded");
            continue;
        }
        if let Err(e) = place_calibration(kind, &read_seen(ebpf)?, &mut calibrated) {
            wrong.push(format!("{program}: {e}"));
        }
    }
    freeze_named(ebpf, CALIB_MAP)?;
    freeze_named(ebpf, SEEN_MAP)?;
    let judge = if wrong.is_empty() {
        ContentJudge::at_handle(calibrated)
    } else {
        ContentJudge::off(format!(
            "the calibration read what its programs do not make ({})",
            wrong.join("; ")
        ))
    };
    if let Some(why) = &judge.off {
        freeze_named(ebpf, CONTENT_CONF_MAP)?;
        return Err(format!("{why} — {OPT_OUTS_SUSPENDED}{write_user_note}"));
    }
    write_content_judge(ebpf, &judge, true)?;
    write_user.map(|_| judge).map_err(|e| {
        format!("bpf_probe_write_user is not refused to an opted-out loader ({e}); the signals and the return override are")
    })
}

/// Lot 345: the calibration programs and their request map.
pub const CALIB_SIGNALS_PROGRAM: &str = "nn_calib_signals";
pub const CALIB_OVERRIDE_PROGRAM: &str = "nn_calib_override";
const CALIB_MAP: &str = "PROG_CONTENT_CALIB";
/// Lot 345: the `bpf_probe_write_user` refusal at the verifier's lockdown
/// question (before 6.9).
pub const WRITE_USER_GUARD_PROGRAM: &str = "bpf_write_user_guard";
pub const WRITE_USER_GUARD_HOOK: &str = "locked_down";

const SEEN_MAP: &str = "PROG_CONTENT_SEEN";
/// Lot 345: the judge's call keys (`bpf_prog_class::target_key` → slot + 1).
pub const CONTENT_KEYS_MAP: &str = "PROG_CONTENT_KEYS";

/// Lot 345: the helper calls the hook recorded of calibration `kind`'s
/// program (`seen`, by instruction, 0 for any other), in order, put in
/// their targets' slots (`bpf_prog_class::calibration_slot`).
///
/// The review of #553 (F5): only when they are exactly the calls the
/// program makes — as many as its slots, each a different helper: another
/// load of the family in the window (its calls recorded over the
/// program's) put wrong targets in silently, refusing every bpftrace or BCC
/// load or judging nothing. Otherwise nothing is placed, and why is said.
pub fn place_calibration(
    kind: u32,
    seen: &[u32],
    calibrated: &mut [u32; common::bpf_prog_class::CALL_TARGETS],
) -> std::result::Result<(), String> {
    use common::bpf_prog_class::calibration_slot;
    let calls: Vec<u32> = seen.iter().copied().filter(|v| *v != 0).collect();
    let want = (0u32..)
        .take_while(|n| calibration_slot(kind, *n).is_some())
        .count();
    let mut distinct = calls.clone();
    distinct.sort_unstable();
    distinct.dedup();
    if want == 0 || calls.len() != want || distinct.len() != want {
        return Err(format!(
            "{} helper call(s) read, {} distinct, where the program makes {want}",
            calls.len(),
            distinct.len()
        ));
    }
    for (n, imm) in calls.iter().enumerate() {
        if let Some(slot) = calibration_slot(kind, n as u32) {
            calibrated[slot as usize - 1] = *imm;
        }
    }
    Ok(())
}

fn clear_seen(ebpf: &mut Ebpf) -> std::result::Result<(), String> {
    let m = ebpf
        .map_mut(SEEN_MAP)
        .ok_or_else(|| format!("{SEEN_MAP} missing from the eBPF object"))?;
    let mut a: Array<&mut MapData, u32> =
        Array::try_from(m).map_err(|e| format!("{SEEN_MAP}: {e}"))?;
    for i in 0..common::bpf_prog_class::CALIB_MAX_INSNS {
        a.set(i, 0, 0).map_err(|e| format!("{SEEN_MAP}: {e}"))?;
    }
    Ok(())
}

fn read_seen(ebpf: &Ebpf) -> std::result::Result<Vec<u32>, String> {
    let m = ebpf
        .map(SEEN_MAP)
        .ok_or_else(|| format!("{SEEN_MAP} missing from the eBPF object"))?;
    let a: Array<&MapData, u32> = Array::try_from(m).map_err(|e| format!("{SEEN_MAP}: {e}"))?;
    (0..common::bpf_prog_class::CALIB_MAX_INSNS)
        .map(|i| a.get(&i, 0).map_err(|e| format!("{SEEN_MAP}: {e}")))
        .collect()
}

fn set_calibration(ebpf: &mut Ebpf, kind: u32) -> std::result::Result<(), String> {
    let m = ebpf
        .map_mut(CALIB_MAP)
        .ok_or_else(|| format!("{CALIB_MAP} missing from the eBPF object"))?;
    let mut a: Array<&mut MapData, u32> =
        Array::try_from(m).map_err(|e| format!("{CALIB_MAP}: {e}"))?;
    a.set(0, kind, 0).map_err(|e| format!("{CALIB_MAP}: {e}"))
}

/// Load calibration program `name` (the hook reads it at the load) and
/// unload it: it is never attached.
fn load_calibration(ebpf: &mut Ebpf, name: &str) -> std::result::Result<(), String> {
    let prog: &mut aya::programs::KProbe = ebpf
        .program_mut(name)
        .ok_or_else(|| format!("{name} missing from the eBPF object"))?
        .try_into()
        .map_err(|e| format!("{name}: {e}"))?;
    prog.load().map_err(|e| format!("{name}: {e}"))?;
    prog.unload().map_err(|e| format!("{name} unload: {e}"))
}

/// Lot 345: write `judge` to the object's `PROG_CONTENT_CONF`, and freeze it
/// when `freeze` (no descriptor writes it again; the guard only reads it).
fn write_content_judge(
    ebpf: &mut Ebpf,
    judge: &ContentJudge,
    freeze: bool,
) -> std::result::Result<(), String> {
    let m = ebpf
        .map_mut(CONTENT_CONF_MAP)
        .ok_or_else(|| format!("{CONTENT_CONF_MAP} missing from the eBPF object"))?;
    let mut conf: Array<&mut MapData, u32> =
        Array::try_from(m).map_err(|e| format!("{CONTENT_CONF_MAP}: {e}"))?;
    conf.set(0, judge.stage, 0)
        .map_err(|e| format!("{CONTENT_CONF_MAP} slot 0: {e}"))?;
    for (i, t) in judge.targets.iter().enumerate() {
        conf.set(i as u32 + 1, *t, 0)
            .map_err(|e| format!("{CONTENT_CONF_MAP} slot {}: {e}", i + 1))?;
    }
    // the review of #553 (F1): the kfuncs read in a load of every type
    let every = common::bpf_prog_class::CONTENT_EVERY_TYPE_SLOT;
    conf.set(every, judge.every_type, 0)
        .map_err(|e| format!("{CONTENT_CONF_MAP} slot {every}: {e}"))?;
    // the keys the hook looks each instruction up in (the CI of #553)
    {
        let m = ebpf
            .map_mut(CONTENT_KEYS_MAP)
            .ok_or_else(|| format!("{CONTENT_KEYS_MAP} missing from the eBPF object"))?;
        let mut keys: HashMap<&mut MapData, u64, u32> =
            HashMap::try_from(m).map_err(|e| format!("{CONTENT_KEYS_MAP}: {e}"))?;
        for (key, slot) in judge.keys() {
            keys.insert(key, slot, 0)
                .map_err(|e| format!("{CONTENT_KEYS_MAP}: {e}"))?;
        }
    }
    if freeze {
        freeze_named(ebpf, CONTENT_KEYS_MAP)?;
        freeze_named(ebpf, CONTENT_CONF_MAP)?;
    }
    Ok(())
}

/// Attach the liveness watch and pin its link (`link_role_exit`): it must
/// outlive the agent's own objects — a clean exit releases them before the
/// process ends, and a dead agent must still see the watchdog exit. The
/// prior run's pin is replaced only once the fresh link fires.
fn attach_role_exit(ebpf: &mut Ebpf, pin_root: Option<&Path>) -> Result<()> {
    let prog: &mut aya::programs::RawTracePoint = ebpf
        .program_mut(ROLE_EXIT_PROGRAM)
        .with_context(|| format!("{ROLE_EXIT_PROGRAM} missing from the eBPF object"))?
        .try_into()
        .context("role_exit is not a raw tracepoint program")?;
    prog.load().context("loading role_exit")?;
    let link_id = prog
        .attach("sched_process_exit")
        .context("attaching role_exit to sched_process_exit")?;
    if let Some(root) = pin_root {
        let link_path = root.join(ROLE_EXIT_LINK_PIN);
        antitamper_bpf::purge_stale_pin(&link_path);
        let link = prog
            .take_link(link_id)
            .context("taking ownership of the role_exit link")?;
        let fd_link: aya::programs::links::FdLink = link.into();
        fd_link
            .pin(&link_path)
            .with_context(|| format!("pinning the role_exit link to {}", link_path.display()))?;
    }
    Ok(())
}

/// External audit EBPF-002: pin `ROLE_TGIDS` and record this agent as the
/// live one, once it is a protected pid and the liveness watch runs (else
/// the slot stays vacant: the window is bounded by age only).
fn claim_agent_role(guard: &BpfGuard, ebpf: &mut Ebpf, pin_root: Option<&Path>) -> Result<()> {
    if let Some(root) = pin_root {
        let pin = root.join(antitamper_bpf::ROLE_TGIDS_MAP_NAME);
        if !pin.exists() {
            ebpf.map_mut(antitamper_bpf::ROLE_TGIDS_MAP_NAME)
                .with_context(|| {
                    format!(
                        "{} missing from the eBPF object",
                        antitamper_bpf::ROLE_TGIDS_MAP_NAME
                    )
                })?
                .pin(&pin)
                .with_context(|| format!("pinning {}", pin.display()))?;
        }
    }
    if !guard.0.role_watch.load(std::sync::atomic::Ordering::SeqCst) {
        return Ok(());
    }
    let map = ebpf
        .map_mut(antitamper_bpf::ROLE_TGIDS_MAP_NAME)
        .with_context(|| {
            format!(
                "{} missing from the eBPF object",
                antitamper_bpf::ROLE_TGIDS_MAP_NAME
            )
        })?;
    let mut roles: Array<&mut MapData, u32> =
        Array::try_from(map).context("ROLE_TGIDS is not an Array<u32>")?;
    roles
        .set(antitamper_bpf::ROLE_SLOT_AGENT, std::process::id(), 0)
        .context("recording the agent in ROLE_TGIDS")?;
    Ok(())
}

impl BpfGuard {
    /// External audit ATP-013: record the ids of every map of `ebpf` — call
    /// right after the load, before any `take_map`.
    pub fn remember_loaded_maps(&self, ebpf: &Ebpf) {
        let mut ids = Vec::new();
        let mut unreadable = Vec::new();
        for (name, map) in ebpf.maps() {
            match map_data(map).info() {
                Ok(info) => ids.push(info.id()),
                Err(e) => unreadable.push(format!("{name}: {e}")),
            }
        }
        *self.0.loaded_map_ids.lock() = Some(if unreadable.is_empty() {
            Ok(ids)
        } else {
            Err(unreadable.join("; "))
        });
    }
}

/// The maps a loaded program of ours uses that are not in `own`: what the
/// guard would hand out. Empty when the set is complete.
fn unregistered_maps(ebpf: &Ebpf, own: &HashSet<u32>) -> Vec<String> {
    let mut missing = Vec::new();
    for (name, prog) in ebpf.programs() {
        let Ok(info) = prog.info() else {
            continue;
        };
        if let Ok(Some(used)) = info.map_ids() {
            for id in used.into_iter().filter(|id| !own.contains(id)) {
                missing.push(format!("map {id} (used by {name})"));
            }
        }
    }
    missing
}

/// Fill `OWN_BPF_IDS` with the ids of every map and program of this object
/// and arm the mode. Call once every program is loaded (after the
/// anti-tamper hooks), so the set is complete.
pub(crate) fn register_own_objects(
    guard: &BpfGuard,
    ebpf: &mut Ebpf,
    pin_root: Option<&Path>,
) -> Result<OwnObjects> {
    // External audit ATP-013: the maps taken out of the object before this
    // point, as recorded at load; then those still in it. An id that cannot
    // be read is a hole in the guard, not a map to skip.
    let loaded = guard.0.loaded_map_ids.lock().clone();
    let mut map_ids: Vec<u32> = match loaded {
        Some(Ok(ids)) => ids,
        Some(Err(unreadable)) => {
            anyhow::bail!("own map ids unreadable at load: {unreadable}")
        }
        None => Vec::new(),
    };
    for (name, map) in ebpf.maps() {
        let info = map_data(map)
            .info()
            .with_context(|| format!("reading own map {name}"))?;
        map_ids.push(info.id());
    }
    map_ids.sort_unstable();
    map_ids.dedup();
    let mut prog_ids: Vec<u32> = Vec::new();
    for (name, prog) in ebpf.programs() {
        match prog.info() {
            Ok(info) => prog_ids.push(info.id()),
            // The programs of a sensor not chosen this boot are never loaded.
            Err(aya::programs::ProgramError::NotLoaded) => {}
            Err(e) => {
                return Err(anyhow::Error::new(e))
                    .with_context(|| format!("reading own program {name}"))
            }
        }
    }
    // Lot 301: and every map and program the agent holds open — its own,
    // wherever it was taken from.
    for o in held_objects() {
        match o {
            BpfObj::Map(id) => map_ids.push(id),
            BpfObj::Prog(id) => prog_ids.push(id),
            BpfObj::Link(..) => {}
        }
    }
    map_ids.sort_unstable();
    map_ids.dedup();
    prog_ids.sort_unstable();
    prog_ids.dedup();
    // Every map our programs use must be in the set: a map moved out of the
    // object before its id was recorded would be guarded by nothing.
    let own: HashSet<u32> = map_ids.iter().copied().collect();
    let missing = unregistered_maps(ebpf, &own);
    if !missing.is_empty() {
        anyhow::bail!(
            "maps used by the agent's programs are not registered as its own: {}",
            missing.join(", ")
        );
    }
    guard.0.own_progs.lock().extend(prog_ids.iter().copied());
    let own = ebpf
        .map_mut(OWN_IDS_MAP)
        .with_context(|| format!("{OWN_IDS_MAP} missing from the eBPF object"))?;
    let mut own: HashMap<&mut MapData, u64, u8> =
        HashMap::try_from(own).context("OWN_BPF_IDS is not a HashMap<u64, u8>")?;
    for id in &map_ids {
        own.insert(own_key(KIND_MAP, *id), KIND_MAP, 0)
            .with_context(|| format!("registering own map id {id}"))?;
    }
    for id in &prog_ids {
        own.insert(own_key(KIND_PROG, *id), KIND_PROG, 0)
            .with_context(|| format!("registering own program id {id}"))?;
    }
    // Links: every link the agent holds whose program is ours (the sensors,
    // the transient hooks) and — lot 301 — every object pinned under its
    // pin directories, the pin root and those beside it (the start-in-cgroup
    // tracker's, the sysctl judge's, the module files' write history's, any
    // later one): each link there that runs one of our programs. Only the
    // root's `link_*` pins were read, so a link pinned beside it and closed
    // (the tracker's seven, lot 277) was not registered — a foreign root
    // took a handle on it by id. The kernel keeps map, program and link ids
    // in three separate spaces, hence the kind in the value.
    let own_maps: HashSet<u32> = map_ids.iter().copied().collect();
    let own_progs: HashSet<u32> = prog_ids.iter().copied().collect();
    let walk = pin_root.map(pinned_objects).unwrap_or_default();
    let pins = split_pins(&walk, &own_maps, &own_progs);
    let link_ids = own_links_of(held_objects(), &pins, &own_progs);
    for id in &link_ids {
        own.insert(own_key(KIND_LINK, *id), KIND_LINK, 0)
            .with_context(|| format!("registering own link id {id}"))?;
    }
    for (dir, ids) in pins.links_by_dir() {
        info!(
            dir = %dir.display(),
            links = ?ids,
            "BPF self-defence: the links pinned in this directory registered as the agent's own"
        );
    }
    let _ = guard.0.own_links.set(OwnLinks {
        ids: link_ids.clone(),
        pin_root: pin_root.map(Path::to_path_buf),
    });
    // Pin names: the final component of every link pin of ours under the
    // pin directories, so `OBJ_GET` on a pinned link is recognised without a
    // path walk in the kernel. External audit ATP-017 (NN-AUD-265): only
    // those — every `link_*` entry used to go in, so 64 planted ones (the
    // map's size) refused the start, and a planted name equal to another
    // product's pin denied that product's `OBJ_GET`. Lot 301: any other
    // entry under the pin directories (a map or a program that is not one
    // of ours, a link that runs none of our programs) is reported
    // (`foreign_pin`), never registered or removed.
    let PinSplit {
        names: pin_names,
        foreign,
        ..
    } = pins;
    for f in &foreign {
        warn!(
            pin = %f,
            "BPF self-defence: an entry under the agent's pin directories is not one of its \
             objects — not registered, not removed"
        );
    }
    *guard.0.foreign_pins.lock() = foreign;
    {
        let names = ebpf
            .map_mut(PIN_NAMES_MAP)
            .with_context(|| format!("{PIN_NAMES_MAP} missing from the eBPF object"))?;
        let mut names: HashMap<&mut MapData, u64, u8> =
            HashMap::try_from(names).context("OWN_PIN_NAMES is not a HashMap<u64, u8>")?;
        for key in &pin_names {
            names
                .insert(key, KIND_LINK, 0)
                .context("registering own link pin name")?;
        }
    }
    // The agent's own binaries, by role: this executable (the agent) and
    // its sibling watchdog. External audit EBPF-002: a process running one
    // of them may take write handles before it is a protected pid only
    // while that role has no live process, in its first minute
    // (`fresh_instance_may_load`); `nn-admin` is not one of them — it talks
    // to the agent through its socket. A copy elsewhere has another inode.
    let mut exe_keys: Vec<(common::wire::InodeKey, u8)> = Vec::new();
    if let Ok(own) = std::env::current_exe().and_then(|p| p.canonicalize()) {
        let dir = own.parent().map(Path::to_path_buf);
        let mut paths = vec![(own, ROLE_AGENT)];
        if let Some(d) = dir {
            paths.push((d.join("northnarrow-watchdog"), ROLE_WATCHDOG));
        }
        for (path, role) in paths {
            if let Ok(meta) = std::fs::metadata(&path) {
                use std::os::unix::fs::MetadataExt;
                exe_keys.push((
                    common::wire::InodeKey {
                        dev: crate::anti_tamper::filesystem::stat_dev_to_kernel_dev(meta.dev()),
                        ino: meta.ino(),
                    },
                    role,
                ));
            }
        }
    }
    {
        let exe_map = ebpf
            .map_mut(OWN_EXE_MAP)
            .with_context(|| format!("{OWN_EXE_MAP} missing from the eBPF object"))?;
        let mut exe_map: HashMap<&mut MapData, crate::anti_tamper::filesystem::AyaInodeKey, u8> =
            HashMap::try_from(exe_map).context("OWN_EXE_INODES is not a HashMap<InodeKey, u8>")?;
        for (k, role) in &exe_keys {
            exe_map
                .insert(crate::anti_tamper::filesystem::AyaInodeKey(*k), *role, 0)
                .with_context(|| format!("registering own exe inode {}:{}", k.dev, k.ino))?;
        }
    }
    // Not fatal: without the claim the fresh-instance window is bounded by
    // age only, while a failure here must not leave the guard unarmed.
    if let Err(e) = claim_agent_role(guard, ebpf, pin_root) {
        error!(
            error = format!("{e:#}"),
            "BPF self-defence: the agent's role NOT recorded in ROLE_TGIDS — a fresh agent \
             binary may take the agent's maps in its first minute even beside this one"
        );
    }
    let enforce = enforce_mode();
    let mode = ebpf
        .map_mut(MODE_MAP)
        .with_context(|| format!("{MODE_MAP} missing from the eBPF object"))?;
    let mut mode: Array<&mut MapData, u32> =
        Array::try_from(mode).context("BPF_DEFENSE_MODE is not an Array<u32>")?;
    mode.set(0, if enforce { 1 } else { 0 }, 0)
        .context("arming BPF_DEFENSE_MODE")?;
    // Lot 290: the signed per-loader opt-outs in force (a policy applied
    // before the load wrote nothing to the kernel yet).
    if let Err(e) = write_loader_opt_outs_object(ebpf) {
        error!(error = %e, "BPF self-defence: the per-loader opt-outs NOT written — their loads stay refused");
    }
    // Lot 290 (item 3): the read-only configuration maps written once,
    // frozen — no handle of any process writes them any more.
    for (name, outcome) in freeze_config_maps(ebpf) {
        match outcome {
            Ok(()) => debug!(map = name, "BPF self-defence: configuration map frozen"),
            Err(e) => {
                warn!(map = name, error = %e, "BPF self-defence: configuration map NOT frozen")
            }
        }
    }
    info!(
        maps = map_ids.len(),
        programs = prog_ids.len(),
        links = link_ids.len(),
        pin_names = pin_names.len(),
        exe_inodes = exe_keys.len(),
        mode = if enforce { "enforce" } else { "observe" },
        "BPF self-defence: own objects registered — foreign write handles on the agent's maps and \
         handles to its links are {}",
        if enforce {
            "DENIED"
        } else {
            "observed only (debug-trigger build or NN_BPF_DEFENSE_OBSERVE=1)"
        }
    );
    Ok(OwnObjects {
        maps: map_ids.len(),
        programs: prog_ids.len(),
        links: link_ids.len(),
        pin_names: pin_names.len(),
        enforce,
    })
}

/// Lot 290 (item 3): the configuration maps this module writes once, at
/// the registration, and nothing writes again — frozen right after
/// (`BPF_MAP_FREEZE`: no descriptor writes them any more, the agent's
/// included; the programs read them). `BTF_OFFSETS`, `EXECPOL_CONF`,
/// `EXECQ_CONF` and the start-in-cgroup tracker's pinned maps were frozen
/// before this lot; `SYSCTL_KERNEL_JUDGE`, `DNS_EXEMPT_UIDS` and
/// `NET_CONNECT_DENY_MODE` are frozen where they are written.
pub const FROZEN_AT_REGISTRATION: [&str; 3] = [MODE_MAP, OWN_EXE_MAP, PIN_NAMES_MAP];

/// [`FROZEN_AT_REGISTRATION`] frozen, each with its outcome.
fn freeze_config_maps(ebpf: &Ebpf) -> Vec<(&'static str, std::result::Result<(), String>)> {
    FROZEN_AT_REGISTRATION
        .iter()
        .map(|name| {
            let r = match ebpf.map(name) {
                Some(m) => freeze_map(map_data(m)).map(|_| ()),
                None => Err(format!("{name} missing from the eBPF object")),
            };
            (*name, r)
        })
        .collect()
}

/// Lot 290: map `name` of `ebpf` frozen ([`freeze_map`]).
pub fn freeze_named(ebpf: &Ebpf, name: &str) -> std::result::Result<bool, String> {
    let m = ebpf
        .map(name)
        .ok_or_else(|| format!("{name} missing from the eBPF object"))?;
    freeze_map(map_data(m)).map_err(|e| format!("{name}: {e}"))
}

/// Lot 290: `BPF_MAP_FREEZE` on `map` — unless its descriptor's fdinfo
/// says it is frozen already (a frozen map answers `EPERM`, not `EBUSY`:
/// lot 281's lab). `Ok(true)` frozen now, `Ok(false)` it was.
pub fn freeze_map(map: &MapData) -> std::result::Result<bool, String> {
    use crate::cgroup_join::{fdinfo_frozen, freeze_outcome, Freeze};
    const MAP_FREEZE: libc::c_long = common::bpf_cmd::BPF_MAP_FREEZE as libc::c_long;
    #[repr(C)]
    struct FreezeAttr {
        map_fd: u32,
    }
    let fd = map.fd().as_fd().as_raw_fd();
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}"))
        .map_err(|e| format!("its fdinfo: {e}"))?;
    match fdinfo_frozen(&info) {
        Some(true) => return Ok(false),
        Some(false) => {}
        None => return Err("no frozen state in its fdinfo".to_string()),
    }
    let attr = FreezeAttr { map_fd: fd as u32 };
    // SAFETY: bpf(BPF_MAP_FREEZE) with a valid, fully initialised attribute
    // block of its exact size; the fd is borrowed from the live map.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            MAP_FREEZE,
            &attr as *const FreezeAttr as *const libc::c_void,
            std::mem::size_of::<FreezeAttr>() as u32,
        )
    };
    let errno = if rc < 0 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
    } else {
        0
    };
    Ok(freeze_outcome(errno)? == Freeze::Now)
}

/// Lot 290: one signed per-loader opt-out in force — the line's executable,
/// the device and inode its path named when the policy was applied, the
/// types' mask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoaderOptOut {
    pub path: String,
    pub key: common::wire::InodeKey,
    pub mask: u32,
}

/// The per-loader opt-outs in force (from a signed policy only).
static LOADER_OPT_OUTS: parking_lot::RwLock<Vec<LoaderOptOut>> =
    parking_lot::RwLock::new(Vec::new());

/// The per-loader opt-outs in force now.
pub fn loader_opt_outs_now() -> Vec<LoaderOptOut> {
    LOADER_OPT_OUTS.read().clone()
}

/// Lot 290: the `bpf-loader-allow` lines of `policy` resolved — each path's
/// device and inode now (`stat` follows a symlink to the executable the
/// kernel runs) — and why a line is not, if one is not.
pub fn resolve_loader_opt_outs(
    lines: &[(&str, u32)],
    stat: impl Fn(&str) -> std::io::Result<(u64, u64)>,
) -> (Vec<LoaderOptOut>, Vec<String>) {
    let mut out = Vec::new();
    let mut unresolved = Vec::new();
    for (path, mask) in lines {
        match stat(path) {
            Ok((dev, ino)) => {
                let key = common::wire::InodeKey {
                    dev: crate::anti_tamper::filesystem::stat_dev_to_kernel_dev(dev),
                    ino,
                };
                // Lot 345 (the mini-hunt of N4): two lines that name one
                // executable (`/usr/bin/python3` and the `python3.12` it
                // links to) are one kernel entry with both lines' types —
                // the last one written replaced the other's
                match out.iter_mut().find(|o: &&mut LoaderOptOut| o.key == key) {
                    Some(o) => o.mask |= *mask,
                    None => out.push(LoaderOptOut {
                        path: path.to_string(),
                        key,
                        mask: *mask,
                    }),
                }
            }
            Err(e) => unresolved.push(format!("{path}: {e}")),
        }
    }
    (out, unresolved)
}

/// A regular file's `(st_dev, st_ino)` through `path` (a symlink followed).
fn stat_executable(path: &str) -> std::io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path)?;
    if !m.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    Ok((m.dev(), m.ino()))
}

/// Lot 290: put `policy`'s `bpf-loader-allow` lines in force — only when
/// `signed` (the policy's signature verified for the very text applied: an
/// unsigned policy loaded through `NN_OVERLAY_ALLOW_UNSIGNED` honours none)
/// — and write them to the kernel's pinned map under the pin root (when
/// the agent's object is not loaded yet, its registration writes them).
/// The detail of a signed degradation when a line is withheld or does not
/// resolve.
pub fn apply_loader_policy(
    policy: &nn_core::decision::rule_policy::RulePolicy,
    signed: bool,
) -> Option<String> {
    let lines: Vec<(&str, u32)> = policy.bpf_loader_opt_outs().collect();
    let (resolved, unresolved) = if signed {
        resolve_loader_opt_outs(&lines, stat_executable)
    } else {
        (Vec::new(), Vec::new())
    };
    *LOADER_OPT_OUTS.write() = resolved;
    if let Some(root) = antitamper_bpf::prepare_pin_root() {
        let pin = root.join(LOADER_OPTOUT_MAP);
        if pin.exists() {
            if let Err(e) = write_loader_opt_outs_pin(&pin) {
                warn!(error = %e, "BPF loader opt-out: NOT written to the kernel — its loads stay refused");
            }
        }
    }
    if !signed && !lines.is_empty() {
        return Some(format!(
            "{}: {} bpf-loader-allow line(s) NOT honoured — the policy was loaded without a valid \
             signature (NN_OVERLAY_ALLOW_UNSIGNED=1): those loaders' refused types stay refused",
            policy.source,
            lines.len()
        ));
    }
    if !unresolved.is_empty() {
        return Some(format!(
            "{}: bpf-loader-allow line(s) whose executable is not there: {} — its loads stay \
             refused",
            policy.source,
            unresolved.join("; ")
        ));
    }
    if !lines.is_empty() {
        info!(
            count = lines.len(),
            "BPF loader opt-out: the signed policy's bpf-loader-allow lines in force"
        );
    }
    None
}

/// The opt-outs in force written over `map`'s entries (every other entry
/// removed).
fn write_loader_opt_outs_to<M: std::borrow::BorrowMut<MapData> + std::borrow::Borrow<MapData>>(
    map: &mut HashMap<M, crate::anti_tamper::filesystem::AyaInodeKey, u32>,
) -> std::result::Result<usize, String> {
    use crate::anti_tamper::filesystem::AyaInodeKey;
    let want = loader_opt_outs_now();
    let stale: Vec<AyaInodeKey> = map
        .keys()
        .filter_map(std::result::Result::ok)
        .filter(|k| !want.iter().any(|o| o.key == k.0))
        .collect();
    for k in &stale {
        map.remove(k)
            .map_err(|e| format!("removing a stale opt-out: {e}"))?;
    }
    for o in &want {
        map.insert(AyaInodeKey(o.key), o.mask, 0)
            .map_err(|e| format!("{}: {e}", o.path))?;
    }
    Ok(want.len())
}

fn write_loader_opt_outs_pin(pin: &Path) -> std::result::Result<usize, String> {
    let md = MapData::from_pin(pin).map_err(|e| e.to_string())?;
    let mut map: HashMap<MapData, crate::anti_tamper::filesystem::AyaInodeKey, u32> =
        HashMap::try_from(Map::HashMap(md)).map_err(|e| e.to_string())?;
    write_loader_opt_outs_to(&mut map)
}

fn write_loader_opt_outs_object(ebpf: &mut Ebpf) -> std::result::Result<usize, String> {
    let m = ebpf
        .map_mut(LOADER_OPTOUT_MAP)
        .ok_or_else(|| format!("{LOADER_OPTOUT_MAP} missing from the eBPF object"))?;
    let mut map: HashMap<&mut MapData, crate::anti_tamper::filesystem::AyaInodeKey, u32> =
        HashMap::try_from(m).map_err(|e| e.to_string())?;
    write_loader_opt_outs_to(&mut map)
}

/// External audit ATP-013: the programs and links attached after the
/// anti-tamper step — the FIM observers, the file-open sensor — added to
/// `OWN_BPF_IDS` in a second pass, so the set stays complete. Returns how
/// many ids were written (inserting one already there changes nothing).
pub fn register_late_objects(guard: &BpfGuard, ebpf: &mut Ebpf) -> Result<usize> {
    let mut prog_ids: Vec<u32> = Vec::new();
    for (name, prog) in ebpf.programs() {
        match prog.info() {
            Ok(info) => prog_ids.push(info.id()),
            Err(aya::programs::ProgramError::NotLoaded) => {}
            Err(e) => {
                return Err(anyhow::Error::new(e))
                    .with_context(|| format!("reading own program {name}"))
            }
        }
    }
    // Lot 290: the cross-view's "own"
    guard.0.own_progs.lock().extend(prog_ids.iter().copied());
    // Their links are held by this process (not pinned): found through its
    // descriptors — lot 301: with every link pinned under the pin
    // directories that runs one of the agent's programs, so that nothing
    // pinned since the start's registration escapes it.
    let own_progs = guard.own_prog_ids();
    let pin_root = guard.0.own_links.get().and_then(|o| o.pin_root.clone());
    let link_ids: Vec<u32> = {
        let mut ids: Vec<u32> = live_links(pin_root.as_deref())
            .into_iter()
            .filter(|(_, prog)| own_progs.contains(prog))
            .map(|(id, _)| id)
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    };
    let own = ebpf
        .map_mut(OWN_IDS_MAP)
        .with_context(|| format!("{OWN_IDS_MAP} missing from the eBPF object"))?;
    let mut own: HashMap<&mut MapData, u64, u8> =
        HashMap::try_from(own).context("OWN_BPF_IDS is not a HashMap<u64, u8>")?;
    for id in &prog_ids {
        own.insert(own_key(KIND_PROG, *id), KIND_PROG, 0)
            .with_context(|| format!("registering own program id {id}"))?;
    }
    for id in &link_ids {
        own.insert(own_key(KIND_LINK, *id), KIND_LINK, 0)
            .with_context(|| format!("registering own link id {id}"))?;
    }
    Ok(prog_ids.len() + link_ids.len())
}

/// External audit DEP-006: name of the file, next to the agent's pid file
/// (the unit: `/run/northnarrow/bpf-own-ids`), that lists the ids of the
/// agent's loaded BPF programs. `install.sh --upgrade` and `uninstall.sh`
/// wait for exactly these to unload: their old gate waited for no LSM
/// program at all on the host, which another product's BPF-LSM programs
/// never reach, and gave up with the agent already stopped. Ids are read
/// from the agent, not through the pins: in enforce mode a foreign handle
/// on a pinned link is refused.
pub const OWN_IDS_FILE_NAME: &str = "bpf-own-ids";

/// Write the ids of every loaded program of `ebpf` to `path` (mode 0600,
/// replaced atomically): one `<id> <name>` line each after a comment line.
/// Called once the anti-tamper hooks are attached and again after the late
/// programs (FIM observers, file-open sensor). The file outlives the agent
/// on purpose: the pinned LSM programs do too, until the pin root goes.
/// Returns how many ids were written.
pub fn write_own_prog_ids(ebpf: &Ebpf, path: &Path) -> Result<usize> {
    let mut progs: Vec<(u32, &str)> = Vec::new();
    for (name, prog) in ebpf.programs() {
        match prog.info() {
            Ok(info) => progs.push((info.id(), name)),
            Err(aya::programs::ProgramError::NotLoaded) => {}
            Err(e) => {
                return Err(anyhow::Error::new(e))
                    .with_context(|| format!("reading own program {name}"))
            }
        }
    }
    progs.sort_unstable();
    let body = render_own_prog_ids(std::process::id(), &progs, kept_program);
    crate::atomic_file::replace(path, body.as_bytes(), 0o600)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(progs.len())
}

/// The programs pinned outside the pin root, which outlive an upgrade's
/// purge of it: the start-in-cgroup tracker's (lot 277) and, lot 280a, the
/// `cgroup/sysctl` judge's.
fn kept_program(name: &str) -> bool {
    crate::cgroup_join::is_kept_program(name)
        || crate::sysctl_cgroup::is_kept_program(name)
        || crate::module_writes::is_kept_program(name)
}

/// The body of the [`OWN_IDS_FILE_NAME`] file. The scripts read the first
/// field of every line that starts with a digit. The re-review of #494,
/// R2: a program pinned outside the pin root (the start-in-cgroup
/// tracker's, `kept(name)`) is marked `kept` in a third field —
/// `install.sh --upgrade` does not wait for it to unload (it outlives the
/// purge of the pin root on purpose), `uninstall.sh` does.
fn render_own_prog_ids(pid: u32, progs: &[(u32, &str)], kept: fn(&str) -> bool) -> String {
    let mut body = format!("# northnarrow-agent pid {pid}: loaded BPF programs (id name [kept])\n");
    for (id, name) in progs {
        if kept(name) {
            body.push_str(&format!("{id} {name} kept\n"));
        } else {
            body.push_str(&format!("{id} {name}\n"));
        }
    }
    body
}

/// Test builds only: keep the whole error chain (the verifier log can be
/// tens of KB, which journald truncates) in `/run/northnarrow/verifier-<program>.log`
/// so a kernel that rejects a program can be read from the lab.
fn dump_verifier_log(program: &str, e: &anyhow::Error) {
    if !cfg!(feature = "debug-trigger") {
        return;
    }
    let path = format!("/run/northnarrow/verifier-{program}.log");
    if let Err(w) = std::fs::write(&path, format!("{e:#}")) {
        warn!(error = %w, path, "BPF self-defence: could not write the verifier log");
    }
}

/// Ids of the agent's own links: the links whose fd this process holds
/// (`held`: sensors, transient hooks) and those pinned under its pin
/// directories (`pins`), kept when their program is one of ours. No
/// `CAP_SYS_ADMIN` is needed — `*_GET_NEXT_ID` would, and the unit does not
/// grant it: every link is reached through an fd and read from
/// `/proc/self/fdinfo`.
fn own_links_of(held: Vec<BpfObj>, pins: &PinSplit, own_progs: &HashSet<u32>) -> Vec<u32> {
    let mut ids: Vec<u32> = held
        .into_iter()
        .filter_map(BpfObj::link)
        .filter(|(_, prog)| own_progs.contains(prog))
        .map(|(id, _)| id)
        .chain(pins.links.iter().map(|(id, _)| *id))
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// `(link_id, prog_id)` of every link reachable from this process right
/// now: held fds and (lot 301) every link pinned under the agent's pin
/// directories ([`own_pin_dirs`]: the pin root and those beside it) — the
/// root's `link_*` pins were the only ones read, so a link pinned beside it
/// and closed (the start-in-cgroup tracker's, lot 277) was neither
/// registered nor checked. A link detached from outside keeps its id but
/// reports `prog_id` 0; a pin that is gone is simply absent.
pub(crate) fn live_links(pin_root: Option<&Path>) -> Vec<(u32, u32)> {
    let mut out: Vec<(u32, u32)> = held_objects()
        .into_iter()
        .filter_map(BpfObj::link)
        .collect();
    if let Some(root) = pin_root {
        out.extend(
            pinned_objects(root)
                .entries
                .iter()
                .filter_map(|p| p.obj.clone().ok().and_then(BpfObj::link)),
        );
    }
    out
}

/// Lot 301: the BPF object a descriptor holds, as its fdinfo names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BpfObj {
    Map(u32),
    Prog(u32),
    /// `(link_id, prog_id)`: `prog_id` 0 when the link holds no program
    /// (detached).
    Link(u32, u32),
}

impl BpfObj {
    fn link(self) -> Option<(u32, u32)> {
        match self {
            BpfObj::Link(id, prog) => Some((id, prog)),
            _ => None,
        }
    }
}

/// Every BPF map, program and link whose descriptor this process holds
/// (`/proc/self/fd`, each read from `/proc/self/fdinfo`).
fn held_objects() -> Vec<BpfObj> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
        for entry in entries.flatten() {
            let Some(fd) = entry
                .file_name()
                .to_str()
                .and_then(|n| n.parse::<i32>().ok())
            else {
                continue;
            };
            if let Some(o) = obj_from_fdinfo(fd) {
                out.push(o);
            }
        }
    }
    out
}

/// The BPF object `/proc/self/fdinfo/<fd>` describes, if any.
fn obj_from_fdinfo(fd: i32) -> Option<BpfObj> {
    let text = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")).ok()?;
    parse_obj_fdinfo(&text)
}

/// The kernel prints `link_id` and `prog_id` for a link (an iterator link
/// over a map's elements adds a `map_id`: a link is told first), `map_id`
/// for a map, `prog_id` for a program; nothing of these for any other file.
fn parse_obj_fdinfo(text: &str) -> Option<BpfObj> {
    let (mut link, mut map, mut prog) = (None, None, None);
    for line in text.lines() {
        let field = |name: &str| {
            line.strip_prefix(name)
                .and_then(|v| v.trim().parse::<u32>().ok())
        };
        if let Some(v) = field("link_id:") {
            link = Some(v);
        } else if let Some(v) = field("map_id:") {
            map = Some(v);
        } else if let Some(v) = field("prog_id:") {
            prog = Some(v);
        }
    }
    match (link, map, prog) {
        (Some(id), _, p) => Some(BpfObj::Link(id, p.unwrap_or(0))),
        (None, Some(id), _) => Some(BpfObj::Map(id)),
        (None, None, Some(id)) => Some(BpfObj::Prog(id)),
        (None, None, None) => None,
    }
}

/// Lot 301: the most entries one walk of the pin directories reads (the
/// agent pins under 200; past this a planted flood is not judged further,
/// and that is said).
const PIN_WALK_MAX: usize = 4096;
/// Lot 301: how deep a walk goes below a pin directory (the agent makes no
/// directory in one; a planted tree is not followed further).
const PIN_WALK_DEPTH: u32 = 4;

/// Lot 301: the agent's pin directories — the pin root and every directory
/// beside it whose name begins with the root's: the start-in-cgroup
/// tracker's (`<root>-cgroup-join-v<schema>_<generation>`), the sysctl
/// judge's (`<root>-sysctl`), the module files' write history's
/// (`<root>-module-writes`) and any later one. The `bpf` hook refuses a
/// foreign `OBJ_GET` under the same prefix (`PIN_DIRS_PREFIX` in the eBPF
/// crate); the registration walks the same directories. A symbolic link is
/// never one.
pub fn own_pin_dirs(pin_root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let (Some(parent), Some(name)) = (pin_root.parent(), pin_root.file_name()) else {
        return out;
    };
    let Ok(entries) = std::fs::read_dir(parent) else {
        return out;
    };
    for entry in entries.flatten() {
        if !entry.file_name().as_bytes().starts_with(name.as_bytes()) {
            continue;
        }
        if std::fs::symlink_metadata(entry.path()).is_ok_and(|m| m.is_dir()) {
            out.push(entry.path());
        }
    }
    out.sort();
    out
}

/// Lot 301: one entry under the agent's pin directories and the object it
/// holds — `Err` says why it holds none the agent could read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Pinned {
    pub path: PathBuf,
    pub obj: std::result::Result<BpfObj, String>,
}

/// Lot 301: one walk of the pin directories.
#[derive(Debug, Default)]
pub(crate) struct PinWalk {
    pub entries: Vec<Pinned>,
    /// The walk stopped at [`PIN_WALK_MAX`] entries.
    pub truncated: bool,
}

/// Lot 301: every entry under the pin directories of `pin_root`
/// ([`own_pin_dirs`]), each opened (`OBJ_GET`) and read from
/// `/proc/self/fdinfo`.
pub(crate) fn pinned_objects(pin_root: &Path) -> PinWalk {
    walk_pins(&own_pin_dirs(pin_root), &|path| {
        let fd = obj_get_fd(path).ok_or_else(|| "not openable as a BPF object".to_string())?;
        obj_from_fdinfo(fd.as_raw_fd()).ok_or_else(|| "not a BPF map, program or link".to_string())
    })
}

/// [`pinned_objects`] with the opener given: every entry of `dirs` and of
/// the directories below them ([`PIN_WALK_DEPTH`] deep), a symbolic link
/// never followed (it could name an object anywhere), at most
/// [`PIN_WALK_MAX`] entries.
fn walk_pins(
    dirs: &[PathBuf],
    open: &dyn Fn(&Path) -> std::result::Result<BpfObj, String>,
) -> PinWalk {
    let mut walk = PinWalk::default();
    let mut todo: Vec<(PathBuf, u32)> = dirs.iter().rev().map(|d| (d.clone(), 0)).collect();
    while let Some((dir, depth)) = todo.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
        paths.sort();
        for path in paths {
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.is_dir() && depth < PIN_WALK_DEPTH {
                todo.push((path, depth + 1));
                continue;
            }
            if walk.entries.len() >= PIN_WALK_MAX {
                walk.truncated = true;
                return walk;
            }
            let obj = if meta.is_dir() {
                Err(format!(
                    "a directory {PIN_WALK_DEPTH} levels down a pin directory: not walked"
                ))
            } else if meta.file_type().is_symlink() {
                Err("a symbolic link: not followed".to_string())
            } else {
                open(&path)
            };
            walk.entries.push(Pinned { path, obj });
        }
    }
    walk
}

/// Open a bpffs pin (`BPF_OBJ_GET`) and own the fd. aya keeps the fd of a
/// `PinnedLink` private, hence the raw call; our own `bpf` LSM hook lets
/// a protected pid through.
fn obj_get_fd(path: &Path) -> Option<OwnedFd> {
    let c = CString::new(path.as_os_str().as_bytes()).ok()?;
    let attr = ObjGetAttr {
        pathname: c.as_ptr() as u64,
        bpf_fd: 0,
        file_flags: 0,
    };
    // SAFETY: plain syscall with a valid, fully initialised attr struct and
    // its exact size; the returned fd is owned by `OwnedFd`.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            OBJ_GET,
            &attr as *const ObjGetAttr as *const libc::c_void,
            std::mem::size_of::<ObjGetAttr>() as u32,
        )
    };
    if fd < 0 {
        return None;
    }
    // SAFETY: a fresh fd returned by the kernel, owned here only.
    Some(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

/// Lot 301 (from external audit ATP-017, NN-AUD-265, the root's `link_*`
/// entries): the entries of the pin directories split by owner.
#[derive(Debug, Default)]
struct PinSplit {
    /// Each link of the agent's pinned there, with its pin.
    links: Vec<(u32, PathBuf)>,
    /// The [`pin_name_key`] of each of those pins.
    names: Vec<u64>,
    /// A description of every other entry (not registered, not removed).
    foreign: Vec<String>,
}

impl PinSplit {
    /// The agent's pinned links, by directory.
    fn links_by_dir(&self) -> std::collections::BTreeMap<PathBuf, Vec<u32>> {
        let mut by_dir: std::collections::BTreeMap<PathBuf, Vec<u32>> = Default::default();
        for (id, pin) in &self.links {
            let dir = pin.parent().map(Path::to_path_buf).unwrap_or_default();
            by_dir.entry(dir).or_default().push(*id);
        }
        by_dir
    }
}

/// Kind of the signed `integrity_drift` for an entry under the agent's pin
/// directories that is not one of its objects (lot 301: any entry; a
/// `link_*` entry of the pin root before).
pub const FOREIGN_PIN_KIND: &str = "foreign_pin";

/// Whose object a pinned entry holds (`Err`: none the agent could read). A
/// map or a program is the agent's when its id is one the agent registers
/// (`maps`, `progs`: its object's and those it holds); a link when it runs
/// one of the agent's programs. `Err` says why the entry is not the
/// agent's.
fn pinned_owner(
    obj: &std::result::Result<BpfObj, String>,
    maps: &HashSet<u32>,
    progs: &HashSet<u32>,
) -> std::result::Result<(), String> {
    match obj {
        Err(why) => Err(why.clone()),
        Ok(BpfObj::Map(id)) if maps.contains(id) => Ok(()),
        Ok(BpfObj::Map(id)) => Err(format!("map {id}, not one of the agent's")),
        Ok(BpfObj::Prog(id)) if progs.contains(id) => Ok(()),
        Ok(BpfObj::Prog(id)) => Err(format!("program {id}, not one of the agent's")),
        Ok(BpfObj::Link(id, 0)) => Err(format!("link {id} holds no program (detached)")),
        Ok(BpfObj::Link(_, prog)) if progs.contains(prog) => Ok(()),
        Ok(BpfObj::Link(id, prog)) => Err(format!(
            "link {id} runs program {prog}, not one of the agent's"
        )),
    }
}

/// The walk's entries split by owner ([`pinned_owner`]): the agent's
/// links, with their pins' names (a name that does not fit the key is
/// skipped with a WARN — none of ours is that long), and every entry that
/// is not the agent's. A walk cut short says so among the foreign.
fn split_pins(walk: &PinWalk, maps: &HashSet<u32>, progs: &HashSet<u32>) -> PinSplit {
    let mut out = PinSplit::default();
    for p in &walk.entries {
        if let Err(why) = pinned_owner(&p.obj, maps, progs) {
            out.foreign.push(format!("{}: {why}", p.path.display()));
            continue;
        }
        let Ok(BpfObj::Link(id, _)) = p.obj else {
            continue;
        };
        out.links.push((id, p.path.clone()));
        let name = p.path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        match pin_name_key(name) {
            Some(k) => out.names.push(k),
            None => warn!(
                pin = %p.path.display(),
                "BPF self-defence: link pin name too long for OWN_PIN_NAMES — not registered"
            ),
        }
    }
    if walk.truncated {
        out.foreign.push(format!(
            "more than {PIN_WALK_MAX} entries under the agent's pin directories: the rest not \
             judged"
        ));
    }
    out
}

impl BpfGuard {
    /// One signed `integrity_drift` ([`FOREIGN_PIN_KIND`]) per entry under
    /// the agent's pin directories found at boot that is not one of its
    /// objects (a stale pin of an earlier build, or one a root planted; lot
    /// 301: any entry of any of them — a `link_*` entry of the root before).
    /// Called by the start once the audit log is open.
    pub fn attest_foreign_pins(&self, audit_log: Option<&Arc<parking_lot::Mutex<AuditLog>>>) {
        let foreign = std::mem::take(&mut *self.0.foreign_pins.lock());
        if foreign.is_empty() {
            return;
        }
        error!(
            count = foreign.len(),
            "INTEGRITY DRIFT — entries under the agent's pin directories that are not its \
             objects (not registered as its own, not removed)"
        );
        let Some(log) = audit_log else {
            return;
        };
        for detail in foreign {
            let draft = AuditEntryDraft {
                op: crate::self_integrity::AUDIT_OP.to_string(),
                extra: serde_json::json!({
                    "kind": FOREIGN_PIN_KIND,
                    "detail": format!(
                        "{detail} — an entry under the agent's pin directories that is not one \
                         of its objects: not registered as its own, not removed"
                    ),
                    "at_boot": true,
                }),
                key_fp: "agent-self".to_string(),
                cosigner_fps: Vec::new(),
                result: "detected".to_string(),
                client_pid: std::process::id(),
                client_uid: 0,
                client_comm: "northnarrow-agent".to_string(),
                client_exe: None,
            };
            if let Err(e) = log.lock().append(draft) {
                warn!(
                    error = format!("{e:#}"),
                    "BPF self-defence: audit entry for a foreign pin failed"
                );
            }
        }
    }
}

/// The key the kernel computes for the final path component (external
/// audit EBPF-010: its hash, `common::wire::pin_name_hash`), or `None` for
/// a name the kernel's window cannot hold.
fn pin_name_key(name: &str) -> Option<u64> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() >= PIN_NAME_LEN {
        return None;
    }
    Some(common::wire::pin_name_hash(bytes))
}

impl BpfGuard {
    /// Mark the agent as stopping (see [`Self::spawn_link_self_check`]): its
    /// links go with it, and the self-check must not report them. Set by the
    /// start's stop as soon as the event loop ends, before anything is
    /// released. The lab caught the self-check of an agent stopped in a
    /// trusted-installer window reporting a link it had just released, 44 ms
    /// after `agent_stop`: a signed `bpf_link_missing` for an authorised
    /// restart.
    pub fn mark_stopping(&self) {
        self.0
            .stopping
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn stopping(&self) -> bool {
        self.0.stopping.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Periodic proof that the agent's own links are still attached: every
    /// link registered at boot must still be reachable (held fd or pin) with a
    /// non-zero program. A link that is gone while the agent is alive was
    /// unpinned or detached from outside (observe mode, a bypass of the pin
    /// protection): ERROR in the journal and one signed audit entry per link.
    /// Spawned by the start once the audit log exists.
    pub fn spawn_link_self_check(&self, audit_log: Option<Arc<parking_lot::Mutex<AuditLog>>>) {
        let Some(own) = self.0.own_links.get().cloned() else {
            return;
        };
        let guard = self.clone();
        let ids = own.ids.clone();
        if ids.is_empty() {
            return;
        }
        info!(
            links = ids.len(),
            every_secs = LINK_CHECK_SECS,
            "BPF self-defence: link self-check armed"
        );
        tokio::spawn(async move {
            let mut reported: HashSet<u32> = HashSet::new();
            loop {
                tokio::time::sleep(crate::self_integrity::jittered(Duration::from_secs(
                    LINK_CHECK_SECS,
                )))
                .await;
                if guard.stopping() {
                    return;
                }
                let live: HashSet<u32> = live_links(own.pin_root.as_deref())
                    .into_iter()
                    .filter(|(_, prog)| *prog != 0)
                    .map(|(id, _)| id)
                    .collect();
                for id in &ids {
                    // re-read per link: the stop can begin during the walk
                    if guard.stopping() {
                        return;
                    }
                    if live.contains(id)
                        || guard.0.retired_links.lock().contains(id)
                        || !reported.insert(*id)
                    {
                        continue;
                    }
                    error!(
                    link_id = id,
                    "ANTI-TAMPER: one of the agent's own BPF links is GONE — an LSM hook or sensor was \
                     detached from outside the agent"
                );
                    if let Some(log) = &audit_log {
                        let draft = AuditEntryDraft {
                            op: LINK_MISSING_AUDIT_OP.to_string(),
                            extra: serde_json::json!({ "link_id": id, "links_registered": ids.len() }),
                            key_fp: "agent-self".to_string(),
                            cosigner_fps: Vec::new(),
                            result: "detected".to_string(),
                            client_pid: std::process::id(),
                            client_uid: 0,
                            client_comm: "northnarrow-agent".to_string(),
                            client_exe: None,
                        };
                        if let Err(e) = log.lock().append(draft) {
                            warn!(
                                error = format!("{e:#}"),
                                "BPF self-defence: audit entry for the missing link failed"
                            );
                        }
                    }
                }
            }
        });
    }
}

/// The `MapData` behind any `Map` variant (aya 0.14 exposes `info()` on
/// `MapData` only, and `Map` is neither `#[non_exhaustive]` nor has an
/// accessor: an aya upgrade that adds a variant fails to compile here).
pub(crate) fn map_data(m: &Map) -> &MapData {
    match m {
        Map::Array(d)
        | Map::ArrayOfMaps(d)
        | Map::BloomFilter(d)
        | Map::CgroupArray(d)
        | Map::CgroupStorage(d)
        | Map::CgrpStorage(d)
        | Map::CpuMap(d)
        | Map::DevMap(d)
        | Map::DevMapHash(d)
        | Map::HashMap(d)
        | Map::HashOfMaps(d)
        | Map::InodeStorage(d)
        | Map::LpmTrie(d)
        | Map::LruHashMap(d)
        | Map::PerCpuArray(d)
        | Map::PerCpuCgroupStorage(d)
        | Map::PerCpuHashMap(d)
        | Map::PerCpuLruHashMap(d)
        | Map::PerfEventArray(d)
        | Map::ProgramArray(d)
        | Map::Queue(d)
        | Map::ReusePortSockArray(d)
        | Map::RingBuf(d)
        | Map::SkStorage(d)
        | Map::SockHash(d)
        | Map::SockMap(d)
        | Map::Stack(d)
        | Map::StackTraceMap(d)
        | Map::Unsupported(d)
        | Map::XskMap(d) => d,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// External audit ATP-017 (NN-AUD-265): only a pin whose link runs one
    /// of the agent's programs is its own; anything else named `link_*` is
    /// reported, not registered — 70 of them no longer overflow the
    /// 64-entry `OWN_PIN_NAMES` and refuse the start. Lot 301: every entry
    /// of the pin directories is judged, whatever its name (the root's
    /// `prog_task_kill` that is no BPF object is reported too), a directory
    /// is walked, not reported.
    #[test]
    fn foreign_link_pin_is_not_registered() {
        let own: HashSet<u32> = [7u32, 9].into_iter().collect();
        let maps: HashSet<u32> = [4u32].into_iter().collect();
        assert_eq!(pinned_owner(&Ok(BpfObj::Link(3, 7)), &maps, &own), Ok(()));
        assert!(pinned_owner(&Err("not a BPF link".into()), &maps, &own)
            .unwrap_err()
            .contains("not a BPF link"));
        assert!(pinned_owner(&Ok(BpfObj::Link(3, 0)), &maps, &own)
            .unwrap_err()
            .contains("detached"));
        assert!(pinned_owner(&Ok(BpfObj::Link(3, 8)), &maps, &own)
            .unwrap_err()
            .contains("program 8, not one of the agent's"));

        let bpffs = tempfile::tempdir().unwrap();
        let root = bpffs.path().join("northnarrow");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("link_x"), "").unwrap();
        std::fs::create_dir(root.join("link_dir")).unwrap();
        std::fs::write(root.join("prog_task_kill"), "").unwrap();
        for i in 0..70 {
            std::fs::write(root.join(format!("link_planted_{i}")), "").unwrap();
        }
        let pins = split_pins(&pinned_objects(&root), &maps, &own);
        assert!(pins.links.is_empty(), "no planted entry is registered");
        assert!(pins.names.is_empty(), "no planted name is registered");
        assert_eq!(pins.foreign.len(), 72, "{:?}", pins.foreign);
        assert!(pins
            .foreign
            .iter()
            .any(|f| f.contains("link_x: not openable as a BPF object")));
        assert!(pins.foreign.iter().any(|f| f.contains("prog_task_kill")));
        assert!(!pins.foreign.iter().any(|f| f.contains("link_dir")));
        assert!(split_pins(&PinWalk::default(), &maps, &own)
            .foreign
            .is_empty());
    }

    #[test]
    fn fdinfo_parser_reads_link_and_prog_ids() {
        let text = "pos:\t0\nflags:\t02000002\nmnt_id:\t15\nino:\t1058\nlink_type:\ttracing\nlink_id:\t557\nprog_tag:\tdeadbeef\nprog_id:\t781\n";
        assert_eq!(parse_obj_fdinfo(text), Some(BpfObj::Link(557, 781)));
        // detached link: prog_id 0
        assert_eq!(
            parse_obj_fdinfo("link_id:\t5\nprog_id:\t0\n"),
            Some(BpfObj::Link(5, 0))
        );
        // not a BPF object
        assert_eq!(parse_obj_fdinfo("pos:\t0\nflags:\t02\n"), None);
        // Lot 301: a map (5.15's and 6.8's fields), a program, an iterator
        // link over a map's elements (it prints the map's id too)
        let map = "pos:\t0\nflags:\t02000002\nmap_type:\t1\nkey_size:\t8\nvalue_size:\t1\nmax_entries:\t1024\nmap_flags:\t0x0\nmemlock:\t81920\nmap_id:\t312\nfrozen:\t0\n";
        assert_eq!(parse_obj_fdinfo(map), Some(BpfObj::Map(312)));
        let prog = "pos:\t0\nflags:\t02000002\nprog_type:\t29\nprog_jited:\t1\nprog_tag:\t0123456789abcdef\nmemlock:\t4096\nprog_id:\t1243\nrun_time_ns:\t0\nrun_cnt:\t0\nrecursion_misses:\t0\nverified_insns:\t466\n";
        assert_eq!(parse_obj_fdinfo(prog), Some(BpfObj::Prog(1243)));
        let iter = "link_type:\titer\nlink_id:\t9\nprog_tag:\tab\nprog_id:\t44\ntarget_name:\tbpf_map_elem\nmap_id:\t312\n";
        assert_eq!(parse_obj_fdinfo(iter), Some(BpfObj::Link(9, 44)));
    }

    /// Lot 301: the pin directories are the pin root and every directory
    /// beside it that the start-in-cgroup tracker, the sysctl judge and the
    /// module files' write history pin in — each named after the root, so
    /// the `bpf` hook's prefix refuses a foreign `OBJ_GET` in each — and
    /// nothing else: not a file, not a symbolic link, not another product's
    /// directory.
    #[test]
    fn the_pin_directories_are_the_root_and_those_beside_it() {
        let bpffs = tempfile::tempdir().unwrap();
        let root = bpffs.path().join("northnarrow");
        let tracker = PathBuf::from(common::cgroup_join::pin_dir(root.to_str().unwrap(), 3));
        let sysctl = crate::sysctl_cgroup::pin_dir(&root);
        let writes = crate::module_writes::pin_dir(&root);
        for d in [&root, &tracker, &sysctl, &writes] {
            std::fs::create_dir(d).unwrap();
        }
        std::fs::create_dir(bpffs.path().join("tc")).unwrap();
        std::fs::create_dir(bpffs.path().join("nn-feasibility")).unwrap();
        std::fs::write(bpffs.path().join("northnarrow-file"), "").unwrap();
        std::os::unix::fs::symlink(
            bpffs.path().join("tc"),
            bpffs.path().join("northnarrow-elsewhere"),
        )
        .unwrap();
        let mut want = vec![root.clone(), tracker, sysctl, writes];
        want.sort();
        assert_eq!(own_pin_dirs(&root), want);
        // the hook's prefix is the production root's: every directory the
        // agent pins in on a host starts with it
        let ebpf = include_str!(concat!(
            env!("NN_REPO_ROOT"),
            "/agent-ebpf/src/bpf_defense.rs"
        ));
        let prefix = ebpf
            .split("const PIN_DIRS_PREFIX: &[u8; 23] = b\"")
            .nth(1)
            .and_then(|r| r.split('"').next())
            .expect("PIN_DIRS_PREFIX");
        assert_eq!(prefix, antitamper_bpf::DEFAULT_BPFFS_ROOT);
        let real = Path::new(antitamper_bpf::DEFAULT_BPFFS_ROOT);
        for d in [
            common::cgroup_join::pin_dir(antitamper_bpf::DEFAULT_BPFFS_ROOT, 0),
            crate::sysctl_cgroup::pin_dir(real).display().to_string(),
            crate::module_writes::pin_dir(real).display().to_string(),
        ] {
            assert!(
                d.starts_with(prefix) && Path::new(&d).parent() == real.parent(),
                "{d}"
            );
        }
        assert!(own_pin_dirs(Path::new("/")).is_empty());
    }

    /// Lot 301 (named; the host half of the consistency check, the
    /// privileged e2e `every_object_pinned_under_the_pin_directories_is_
    /// registered_as_the_agent_s` is the kernel's): every object pinned
    /// under any of the pin directories is either registered as the
    /// agent's — a link that runs one of its programs, whatever the pin's
    /// name or depth, with its pin's name; a map or a program it registers
    /// — or reported, never left out in silence. Lot 300 found the tracker's
    /// links (pinned beside the root and closed) in neither: the root's
    /// `link_*` pins were the only ones read.
    #[test]
    fn every_object_pinned_under_the_pin_directories_is_registered_or_reported() {
        let bpffs = tempfile::tempdir().unwrap();
        let root = bpffs.path().join("northnarrow");
        let tracker = PathBuf::from(common::cgroup_join::pin_dir(root.to_str().unwrap(), 0));
        let sysctl = crate::sysctl_cgroup::pin_dir(&root);
        let writes = crate::module_writes::pin_dir(&root);
        let other = bpffs.path().join("other");
        for d in [&root, &tracker, &sysctl, &writes, &other] {
            std::fs::create_dir(d).unwrap();
        }
        std::fs::create_dir_all(root.join("sub/deeper")).unwrap();
        // what each pin holds, for the fake opener (an empty file: not a
        // BPF object)
        let mut objs: Vec<(PathBuf, BpfObj)> = vec![
            (root.join("link_task_kill"), BpfObj::Link(10, 100)),
            (root.join("prog_task_kill"), BpfObj::Prog(100)),
            (root.join("PROTECTED_PIDS"), BpfObj::Map(5)),
            (root.join("sub/deeper/odd_name"), BpfObj::Link(50, 100)),
            (root.join("link_foreign"), BpfObj::Link(60, 999)),
            (root.join("link_detached"), BpfObj::Link(61, 0)),
            (root.join("STALE_MAP"), BpfObj::Map(77)),
            (root.join("prog_planted"), BpfObj::Prog(888)),
            (tracker.join("CGROUP_JOINED"), BpfObj::Map(6)),
            (sysctl.join("link_nn_sysctl_guard"), BpfObj::Link(30, 300)),
            (sysctl.join("prog_nn_sysctl_guard"), BpfObj::Prog(300)),
            (
                crate::module_writes::link_pin(&writes),
                BpfObj::Link(40, 400),
            ),
            (other.join("link_x"), BpfObj::Link(70, 100)),
        ];
        for (i, (name, _, _)) in crate::cgroup_join::PROGRAMS.iter().enumerate() {
            let (prog, link) = crate::cgroup_join::pin_paths(&tracker, name);
            objs.push((link, BpfObj::Link(20 + i as u32, 200 + i as u32)));
            objs.push((prog, BpfObj::Prog(200 + i as u32)));
        }
        for (p, _) in &objs {
            std::fs::write(p, "").unwrap();
        }
        std::fs::write(root.join("not_bpf"), "").unwrap();
        std::os::unix::fs::symlink(tracker.join("link_cgroup_join_mark"), root.join("link_sym"))
            .unwrap();
        // as `OBJ_GET` would: a symbolic link resolved to what it names
        let open = |p: &Path| {
            let real = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
            objs.iter()
                .find(|(q, _)| std::fs::canonicalize(q).is_ok_and(|q| q == real))
                .map(|(_, o)| *o)
                .ok_or_else(|| "not openable as a BPF object".to_string())
        };
        let walk = walk_pins(&own_pin_dirs(&root), &open);
        assert!(!walk.truncated);
        assert!(
            !walk.entries.iter().any(|e| e.path.starts_with(&other)),
            "another directory walked"
        );
        let progs: HashSet<u32> = [100, 300, 400].into_iter().chain(200..207).collect();
        let maps: HashSet<u32> = [5, 6].into_iter().collect();
        let pins = split_pins(&walk, &maps, &progs);
        let mut links: Vec<u32> = pins.links.iter().map(|(id, _)| *id).collect();
        links.sort_unstable();
        let mut want: Vec<u32> = vec![10, 30, 40, 50];
        want.extend(20..27);
        want.sort_unstable();
        assert_eq!(links, want, "the agent's pinned links");
        // the tracker's seven, by directory
        let by_dir = pins.links_by_dir();
        assert_eq!(by_dir.get(&tracker).map(Vec::len), Some(7), "{by_dir:?}");
        // their pins' names (the kernel's OBJ_GET match), each of them
        for (_, pin) in &pins.links {
            let name = pin.file_name().unwrap().to_str().unwrap();
            assert!(pins.names.contains(&pin_name_key(name).unwrap()), "{name}");
        }
        assert_eq!(pins.names.len(), pins.links.len());
        // everything else reported, nothing in silence
        let mut foreign: Vec<String> = pins
            .foreign
            .iter()
            .map(|f| f.split_once(": ").map(|(p, _)| p.to_string()).unwrap())
            .collect();
        foreign.sort();
        let mut want_foreign: Vec<String> = [
            "link_detached",
            "link_foreign",
            "link_sym",
            "not_bpf",
            "prog_planted",
            "STALE_MAP",
        ]
        .iter()
        .map(|n| root.join(n).display().to_string())
        .collect();
        want_foreign.sort();
        assert_eq!(foreign, want_foreign);
        assert_eq!(
            walk.entries.len(),
            links.len() + pins.foreign.len() + 11,
            "every entry judged (the 11 maps and programs of the agent's: registered by id)"
        );
        // with what the agent holds: a held link of one of its programs in,
        // another's out
        let held = vec![BpfObj::Link(90, 100), BpfObj::Link(91, 999), BpfObj::Map(5)];
        let all = own_links_of(held, &pins, &progs);
        assert!(all.contains(&90) && !all.contains(&91) && all.contains(&26));
        assert_eq!(all.len(), want.len() + 1);
    }

    /// Lot 301: the walk is bounded — a planted tree is not followed below
    /// four levels (the directory there is reported), a flood stops at
    /// [`PIN_WALK_MAX`] entries and says so.
    #[test]
    fn the_walk_of_the_pin_directories_is_bounded() {
        let bpffs = tempfile::tempdir().unwrap();
        let root = bpffs.path().join("northnarrow");
        let deep = root.join("a/b/c/d/e");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(root.join("a/b/c/d/at_four"), "").unwrap();
        std::fs::write(deep.join("at_five"), "").unwrap();
        let open = |_: &Path| Ok(BpfObj::Map(1));
        let walk = walk_pins(&own_pin_dirs(&root), &open);
        let paths: Vec<&PathBuf> = walk.entries.iter().map(|e| &e.path).collect();
        assert_eq!(paths, [&root.join("a/b/c/d/at_four"), &deep], "{paths:?}");
        assert!(walk.entries[1]
            .obj
            .as_ref()
            .unwrap_err()
            .contains("not walked"));
        let flood = bpffs.path().join("northnarrow-flood");
        std::fs::create_dir(&flood).unwrap();
        for i in 0..=PIN_WALK_MAX {
            std::fs::write(flood.join(format!("p{i}")), "").unwrap();
        }
        let walk = walk_pins(&own_pin_dirs(&root), &open);
        assert!(walk.truncated);
        assert_eq!(walk.entries.len(), PIN_WALK_MAX);
        let pins = split_pins(&walk, &HashSet::new(), &HashSet::new());
        assert!(pins.foreign.last().unwrap().contains("the rest not judged"));
    }

    #[test]
    fn observe_is_a_deny_shortfall_in_production_builds() {
        assert!(observe_shortfall(false, false)
            .unwrap()
            .contains("observe mode"));
        assert_eq!(
            observe_shortfall(false, true),
            None,
            "debug-trigger: by design"
        );
        assert_eq!(observe_shortfall(true, false), None);
    }

    #[test]
    fn own_key_separates_the_three_id_spaces() {
        // the lab collision: map 357, program 357, link 357 are three objects
        let keys = [
            own_key(KIND_MAP, 357),
            own_key(KIND_PROG, 357),
            own_key(KIND_LINK, 357),
        ];
        assert_eq!(keys.iter().collect::<HashSet<_>>().len(), 3);
        assert_eq!(own_key(KIND_MAP, 357) & 0xFFFF_FFFF, 357);
        assert_eq!(own_key(KIND_LINK, u32::MAX) >> 32, KIND_LINK as u64);
    }

    #[test]
    fn a_role_reads_the_slot_its_process_claims() {
        // External audit EBPF-002: the guard reads ROLE_TGIDS[role - 1] for
        // the role OWN_EXE_INODES gives a binary; the watchdog and the agent
        // claim their slots by the shared crate's constants.
        assert_eq!(
            antitamper_bpf::ROLE_SLOT_WATCHDOG,
            u32::from(ROLE_WATCHDOG) - 1
        );
        assert_eq!(antitamper_bpf::ROLE_SLOT_AGENT, u32::from(ROLE_AGENT) - 1);
        assert_ne!(ROLE_WATCHDOG, ROLE_AGENT);
        assert_ne!(ROLE_WATCHDOG, 0, "0 is \"not one of ours\" in the guard");
        assert_ne!(ROLE_AGENT, 0, "0 is \"not one of ours\" in the guard");
    }

    #[test]
    fn pin_name_key_hashes_and_rejects_long_names() {
        let k = pin_name_key("link_task_kill").unwrap();
        assert_eq!(k, common::wire::pin_name_hash(b"link_task_kill"));
        assert_ne!(k, pin_name_key("link_task_kil").unwrap());
        assert!(pin_name_key("").is_none());
        assert!(pin_name_key(&"x".repeat(PIN_NAME_LEN)).is_none());
        assert!(pin_name_key(&"x".repeat(PIN_NAME_LEN - 1)).is_some());
    }

    /// External audit EBPF-010: the hook restarts the hash after every '/'
    /// of the window; the name it ends with must hash as userland
    /// registered it (FNV-1a, 64-bit — the published vector for "a").
    #[test]
    fn the_kernels_one_pass_hash_matches_the_registered_name() {
        assert_eq!(common::wire::pin_name_hash(b"a"), 0xaf63_dc4c_8601_ec8c);
        let window = b"fs/bpf/northnarrow/link_task_kill";
        let mut h = common::wire::PIN_NAME_HASH_SEED;
        for &c in window.iter() {
            if c == b'/' {
                h = common::wire::PIN_NAME_HASH_SEED;
            } else {
                h = (h ^ u64::from(c)).wrapping_mul(common::wire::PIN_NAME_HASH_PRIME);
            }
        }
        assert_eq!(Some(h), pin_name_key("link_task_kill"));
    }

    /// External audit DEP-006: install.sh and uninstall.sh take the first
    /// field of every line that is a number; the comment line is skipped.
    #[test]
    fn own_prog_ids_file_lists_one_id_per_line() {
        let body = render_own_prog_ids(
            4242,
            &[(17, "task_kill"), (305, "protected_open_deny")],
            crate::cgroup_join::is_kept_program,
        );
        let mut lines = body.lines();
        assert!(lines
            .next()
            .unwrap()
            .starts_with("# northnarrow-agent pid 4242"));
        let ids: Vec<u32> = body
            .lines()
            .filter_map(|l| l.split_whitespace().next())
            .filter(|f| f.bytes().all(|b| b.is_ascii_digit()))
            .map(|f| f.parse().unwrap())
            .collect();
        assert_eq!(ids, vec![17, 305]);
        assert!(body.ends_with("305 protected_open_deny\n"));
        assert_eq!(OWN_IDS_FILE_NAME, "bpf-own-ids");
    }

    /// The re-review of #494, R2: the tracker's programs are listed, marked
    /// `kept` (an upgrade does not wait for them; an uninstall does), and
    /// no other program is.
    #[test]
    fn the_tracker_s_programs_are_listed_as_kept() {
        let body = render_own_prog_ids(
            7,
            &[
                (3, "cgroup_join_mark"),
                (4, "cgroup_guard_src"),
                (5, "cgroup_join_exit"),
                (6, "task_kill"),
            ],
            crate::cgroup_join::is_kept_program,
        );
        let kept: Vec<&str> = body
            .lines()
            .filter(|l| l.split_whitespace().nth(2) == Some("kept"))
            .collect();
        assert_eq!(kept, ["3 cgroup_join_mark kept", "5 cgroup_join_exit kept"]);
        assert!(body.contains("\n4 cgroup_guard_src\n") && body.contains("\n6 task_kill\n"));
        for (name, _, _) in crate::cgroup_join::PROGRAMS {
            assert!(crate::cgroup_join::is_kept_program(name));
        }
        assert!(!crate::cgroup_join::is_kept_program("cgroup_join"));
    }

    /// Lot 280a: the own-programs file marks the cgroup/sysctl judge kept
    /// too (pinned beside the pin root, it outlives an upgrade's purge),
    /// with the tracker's; nothing else.
    #[test]
    fn the_sysctl_judge_is_listed_as_kept() {
        let body = render_own_prog_ids(
            7,
            &[
                (3, "cgroup_join_mark"),
                (8, crate::sysctl_cgroup::PROGRAM),
                (6, "task_kill"),
                (9, "protected_write_deny"),
            ],
            kept_program,
        );
        let kept: Vec<&str> = body
            .lines()
            .filter(|l| l.split_whitespace().nth(2) == Some("kept"))
            .collect();
        assert_eq!(kept, ["3 cgroup_join_mark kept", "8 nn_sysctl_guard kept"]);
        assert!(body.contains("\n6 task_kill\n") && body.contains("\n9 protected_write_deny\n"));
        assert!(pin_name_key(&format!("link_{}", crate::sysctl_cgroup::PROGRAM)).is_some());
    }

    /// Lot 290 (named): a `bpf-loader-allow` line is resolved to the
    /// device and inode its path names now (the kernel's device number), a
    /// path that is not there is named and not in force; the frozen maps
    /// are the three this module writes once.
    /// Named (lot 345; the re-check of #550, point 1 (ii)): the content
    /// judge's configuration — at the load (6.9+) the helpers' uapi ids and
    /// the kfunc's BTF id; at the handle (before) the calibrated targets,
    /// `bpf_probe_write_user`'s slot left to the lockdown guard, the judge
    /// off without the signals' calibration (said), the override optional.
    #[test]
    fn the_content_judge_is_configured_for_the_kernel() {
        use common::bpf_prog_class::{CONTENT_STAGE_HANDLE, CONTENT_STAGE_LOAD, CONTENT_STAGE_OFF};
        let kf = [Some(61_234), None, None, None, None];
        let j = ContentJudge::at_load(kf);
        assert_eq!(j.stage, CONTENT_STAGE_LOAD);
        assert_eq!(j.targets, [36, 58, 109, 117, 61_234, 0, 0, 0, 0]);
        assert_eq!(j.off, None);
        assert_eq!(j.every_type, 1);
        assert_eq!(ContentJudge::at_load([None; 5]).targets[4], 0);
        assert_eq!(ContentJudge::at_load([None; 5]).every_type, 0);
        // the calibration's slots: override, send_signal, send_signal_thread;
        // whatever slot 0 and the kfuncs' held is not taken
        let j = ContentJudge::at_handle([7, 0x10, 0x20, 0x30, 9, 9, 9, 9, 9]);
        assert_eq!(j.stage, CONTENT_STAGE_HANDLE);
        assert_eq!(j.targets, [0, 0x10, 0x20, 0x30, 0, 0, 0, 0, 0]);
        assert_eq!(j.every_type, 0);
        // a kernel without the override helper
        let j = ContentJudge::at_handle([0, 0, 0x20, 0x30, 0, 0, 0, 0, 0]);
        assert_eq!(j.stage, CONTENT_STAGE_HANDLE);
        assert_eq!(j.targets, [0, 0, 0x20, 0x30, 0, 0, 0, 0, 0]);
        // the keys: one a target, its slot plus one; the kfunc's src_reg 2
        let j = ContentJudge::at_load(kf);
        let keys = j.keys();
        assert_eq!(keys.len(), 5);
        assert!(keys.contains(&(0x85 | (109u64 << 32), 3)));
        assert!(keys.contains(&(0x85 | (2 << 12) | (61_234u64 << 32), 5)));
        assert_eq!(ContentJudge::at_load([None; 5]).keys().len(), 4);
        // the calibration's records, in order: the signals' two calls into
        // their slots, the override's one; other instructions are 0
        let mut cal = [0u32; 9];
        place_calibration(
            common::bpf_prog_class::CALIB_SIGNALS,
            &[0, 0x20, 0, 0x30, 0, 0],
            &mut cal,
        )
        .unwrap();
        place_calibration(
            common::bpf_prog_class::CALIB_OVERRIDE,
            &[0, 0x10, 0, 0],
            &mut cal,
        )
        .unwrap();
        assert_eq!(cal, [0, 0x10, 0x20, 0x30, 0, 0, 0, 0, 0]);
        assert_eq!(
            ContentJudge::at_handle(cal).targets,
            [0, 0x10, 0x20, 0x30, 0, 0, 0, 0, 0]
        );
        // no signal calibrated: off, said
        let j = ContentJudge::at_handle([0, 0x10, 0x20, 0, 0, 0, 0, 0, 0]);
        assert!(j.keys().is_empty());
        assert_eq!(j.stage, CONTENT_STAGE_OFF);
        assert_eq!(j.targets, [0; 9]);
        assert!(
            j.off
                .as_deref()
                .is_some_and(|w| w.contains("bpf_send_signal_thread")),
            "{j:?}"
        );
    }

    /// Named (the review of #553, F5): the calibration takes the calls it
    /// read only when they are exactly its program's — as many as its
    /// slots, each a different helper. Another load of the family in the
    /// window (more calls, fewer, the same one twice) placed wrong targets
    /// silently: every bpftrace or BCC load refused, or nothing judged.
    /// Then nothing is placed, and the start's judge is off (said, and the
    /// opt-outs suspended).
    #[test]
    fn a_calibration_that_read_other_calls_is_refused() {
        use common::bpf_prog_class::{CALIB_NONE, CALIB_OVERRIDE, CALIB_SIGNALS};
        for (kind, seen) in [
            (CALIB_SIGNALS, vec![0x20, 0, 0x30, 0x40]),
            (CALIB_SIGNALS, vec![0, 0x20, 0]),
            (CALIB_SIGNALS, vec![0x20, 0x20]),
            (CALIB_SIGNALS, vec![0; 16]),
            (CALIB_OVERRIDE, vec![0x10, 0x11]),
            (CALIB_OVERRIDE, vec![]),
            (CALIB_NONE, vec![0x10]),
        ] {
            let mut cal = [0u32; 9];
            let e = place_calibration(kind, &seen, &mut cal).expect_err("refused");
            assert!(e.contains("where the program makes"), "{e}");
            assert_eq!(cal, [0; 9], "{kind} {seen:?}: nothing placed");
        }
        let j = ContentJudge::off("the calibration read what its programs do not make".into());
        assert_eq!(j.stage, common::bpf_prog_class::CONTENT_STAGE_OFF);
        assert!(j.keys().is_empty());
        assert!(OPT_OUTS_SUSPENDED.contains("opt-outs are suspended"));
    }

    #[test]
    fn a_loader_opt_out_is_its_executable_s_device_and_inode() {
        let lines = [("/usr/bin/bpftrace", 0b100), ("/opt/gone", 0b1)];
        let stat = |p: &str| match p {
            "/usr/bin/bpftrace" => Ok(((8u64 << 8) | 2, 4242u64)),
            _ => Err(std::io::Error::from(std::io::ErrorKind::NotFound)),
        };
        let (ok, missing) = resolve_loader_opt_outs(&lines, stat);
        assert_eq!(
            ok,
            vec![LoaderOptOut {
                path: "/usr/bin/bpftrace".into(),
                key: common::wire::InodeKey {
                    dev: crate::anti_tamper::filesystem::stat_dev_to_kernel_dev((8 << 8) | 2),
                    ino: 4242
                },
                mask: 0b100
            }]
        );
        assert_eq!(missing.len(), 1);
        assert!(missing[0].starts_with("/opt/gone: "), "{missing:?}");
        assert_eq!(
            FROZEN_AT_REGISTRATION,
            ["BPF_DEFENSE_MODE", "OWN_EXE_INODES", "OWN_PIN_NAMES"]
        );
        // lot 345 (the mini-hunt of N4): two lines of one executable (a
        // symlink and its target) are one entry with both lines' types
        let lines = [
            ("/usr/bin/python3", 0b100),
            ("/usr/bin/python3.12", 0b10010),
        ];
        let (ok, _) = resolve_loader_opt_outs(&lines, |_| Ok((2049, 77)));
        assert_eq!(ok.len(), 1, "{ok:?}");
        assert_eq!(ok[0].mask, 0b10110);
        assert_eq!(ok[0].path, "/usr/bin/python3");
        // an unsigned policy honours none
        let p = nn_core::decision::rule_policy::parse("bpf-loader-allow /usr/bin/true kprobe\n")
            .unwrap();
        let detail = apply_loader_policy(&p, false).expect("withheld");
        assert!(detail.contains("NOT honoured"), "{detail}");
        assert!(loader_opt_outs_now().is_empty());
    }
}
