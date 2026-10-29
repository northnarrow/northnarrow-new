//! Userland side of the exploit post-condition guard (lab PR 219,
//! experimental; `agent-ebpf/src/epg.rs` and `epg_lite.rs`, decision model
//! `common::epg`).
//!
//! Two variants, one at a time:
//!
//! - **lite** (default): no system-call hooks. The mechanism hooks judge the
//!   call in progress; the use points (LSM `capable`, `bprm_check_security`,
//!   a filtered `file_open`) compare the task's objective credential and
//!   `nsproxy` with the ones its mechanisms last gave it, kept in an LRU
//!   task map keyed by `task_struct` address (aya cannot load task
//!   storage, 0.13 nor 0.14). The map is preallocated and sized here at load
//!   ([`lite_task_map_entries`]); a record it evicts is re-taken, counted
//!   (`baselines_lost`) and attested, and one that holds privilege is
//!   recorded as degraded evidence.
//! - **strict** (opt-in): the `sys_enter` / `sys_exit` comparison around
//!   every call; its task map is sized from `pid_max` (or
//!   `--exploit-guard-tasks`) and not preallocated, which needs 6.1+
//!   ([`strict_unsupported`]: checked here, not left to the verifier).
//!
//! [`attach`] checks that the running kernel has every field the chosen
//! programs read, in the layout they read it (`common::epg::guard_config`),
//! writes the configuration unarmed, attaches the programs that keep
//! baselines and mechanisms first and the ones that judge last, then arms.
//! Any failure detaches what was attached and leaves the guard off: a
//! partial guard would flag every `sudo`.
//!
//! The response starts as detect. [`set_response`] switches to enforce once
//! `main` has resolved `--detect-only` (the global no-enforcement switch
//! wins). A sampler sums the per-CPU counters for `nn-admin status`, warns
//! when strict's task map is full or lite's lost records, and attests each
//! once per window.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aya::maps::{Array, MapData, PerCpuArray, RingBuf};
use aya::programs::{BtfTracePoint, FEntry, Lsm, RawTracePoint};
use aya::util::KernelVersion;
use aya::{Btf, Ebpf};
use common::btf_offsets::{slot, BTF_OFFSETS_ABSENT};
use common::epg::{self, cfg, counter, variant, GuardConfig, ResolvedLayout};
use tracing::{info, warn};

use crate::late_audit::{AuditHandle, LateAudit};

/// Which guard runs (`--exploit-guard`, `NN_EXPLOIT_GUARD`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    Off,
    Lite,
    Strict,
}

impl Variant {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Lite => "lite",
            Self::Strict => "strict",
        }
    }
}

/// What it does on a finding (`--exploit-guard-response`,
/// `NN_EXPLOIT_GUARD_RESPONSE`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Response {
    Detect,
    Enforce,
}

impl Response {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Detect => "detect",
            Self::Enforce => "enforce",
        }
    }
}

/// The environment variable of `--exploit-guard`. `off` is a weakening
/// (`self_integrity::WEAKENING_ENV`); `lite` and `strict` are not.
pub const MODE_ENV: &str = "NN_EXPLOIT_GUARD";
/// The environment variable of `--exploit-guard-response` (`enforce`
/// strengthens).
pub const RESPONSE_ENV: &str = "NN_EXPLOIT_GUARD_RESPONSE";
/// The environment variable of `--exploit-guard-tasks` (the task map size
/// of the variant that runs).
pub const TASKS_ENV: &str = "NN_EXPLOIT_GUARD_TASKS";

/// `true` for a value of [`MODE_ENV`] that turns the guard off.
pub fn turns_off(v: &str) -> bool {
    v.trim().eq_ignore_ascii_case("off")
}

/// Strict: mechanism hooks it cannot run without, `(program, function)`.
pub const STRICT_FENTRY: &[(&str, &str)] = &[
    ("epg_commit_creds", "commit_creds"),
    ("epg_switch_ns", "switch_task_namespaces"),
    ("epg_set_fs_root", "set_fs_root"),
];
/// Strict: root-epoch hook it can run without (the `sys_exit` fallback
/// covers a judged `pivot_root`).
pub const STRICT_OPTIONAL_FENTRY: (&str, &str) = ("epg_chroot_fs_refs", "chroot_fs_refs");
/// Strict: raw tracepoints, in attach order: cleanup, judge, snapshot.
pub const STRICT_RAW_TP: &[(&str, &str)] = &[
    ("epg_task_exit", "sched_process_exit"),
    ("epg_sys_exit", "sys_exit"),
    ("epg_sys_enter", "sys_enter"),
];
/// Lite: cleanup, then the fork baseline.
pub const LITE_TP_BTF: &[(&str, &str)] = &[
    ("epg_lite_task_exit", "sched_process_exit"),
    ("epg_lite_fork", "sched_process_fork"),
];
/// Lite: mechanism hooks.
pub const LITE_FENTRY: &[(&str, &str)] = &[
    ("epg_lite_commit_creds", "commit_creds"),
    ("epg_lite_switch_ns", "switch_task_namespaces"),
    ("epg_lite_set_fs_root", "set_fs_root"),
];
/// Lite: use points, last.
pub const LITE_LSM: &[(&str, &str)] = &[
    ("epg_lite_capable", "capable"),
    ("epg_lite_exec", "bprm_check_security"),
    ("epg_lite_file_open", "file_open"),
];

/// The first kernel whose BPF memory allocator makes strict's map (not
/// preallocated) safe in a raw tracepoint.
const STRICT_MIN_KERNEL: (u8, u8) = (6, 1);

/// Why strict cannot run on a kernel of version `v` (`None`: unreadable),
/// or `None` when it can. Before 6.1 a hash map that is not preallocated,
/// used from a raw tracepoint, allocates where the kernel's allocator is not
/// safe to enter; the verifier refuses it only on a PREEMPT_RT kernel, and
/// any other loads it with a kernel `WARN` (the kernel is tainted). Lab PR
/// 219's strict programs were refused on 5.15 for their size until the 6.1
/// verifier fixes made them fit: from then on only this check keeps strict
/// off a kernel without that allocator. A backport (RHEL 9) is not
/// detected: strict stays unavailable there too.
fn strict_unsupported(v: Option<KernelVersion>) -> Option<String> {
    let (major, minor) = STRICT_MIN_KERNEL;
    match v {
        Some(v) if v >= KernelVersion::new(major, minor, 0) => None,
        Some(v) => Some(format!(
            "strict needs Linux {major}.{minor} or later (its task map is not preallocated, which \
             a raw tracepoint can use safely only from {major}.{minor}); this kernel is {v}"
        )),
        None => Some(format!(
            "strict needs Linux {major}.{minor} or later and the running kernel's version could \
             not be read"
        )),
    }
}

pub const CONFIG_MAP: &str = "EPG_CONFIG";
pub const COUNTERS_MAP: &str = "EPG_COUNTERS";
pub const RING_MAP: &str = "EPG_EVENTS";
/// Strict's task map (sized at load, [`task_map_entries`]).
pub const STRICT_TASKS_MAP: &str = "EPG_TASKS";
/// Lite's task map (LRU hash, preallocated; sized at load,
/// [`lite_task_map_entries`]).
pub const LITE_TASKS_MAP: &str = "EPG_LITE_TASKS";
/// Pump label (`SensorMultiplexer::finished_pumps`).
pub const PUMP_LABEL: &str = "exploit_guard";

/// Counter sampling period.
pub const SAMPLE_SECS: u64 = 10;
/// At most one signed saturation entry per window.
pub const AUDIT_WINDOW_SECS: u64 = 600;
/// Audit op of a saturated strict task map.
pub const AUDIT_OP: &str = "exploit_guard_untracked";
/// Audit op of lite records lost to the LRU task map.
pub const LOST_AUDIT_OP: &str = "exploit_guard_baseline_lost";

#[repr(transparent)]
#[derive(Clone, Copy)]
struct AyaGuardConfig(GuardConfig);
// SAFETY: `GuardConfig` is `#[repr(C)]`, `Copy`, every field a plain
// integer with explicit padding: any byte pattern is a valid value.
unsafe impl aya::Pod for AyaGuardConfig {}

struct Control {
    map: Array<MapData, AyaGuardConfig>,
    config: GuardConfig,
    variant: Variant,
}

/// The running guard (R11c, lab PR 264): its kernel configuration, which
/// the start's response phase switches ([`Self::set_response`]), and the
/// sampler's audit log, which the attest phase binds
/// ([`Self::bind_audit_log`]). [`attach`] gives it to the start; they were
/// the process-wide `CONTROL` (set by the attach, read by the response
/// phase) and `AUDIT_LOG` (filled by `set_audit_log`).
#[derive(Clone)]
pub struct ExploitGuard {
    control: Arc<Mutex<Control>>,
    audit: LateAudit,
}

impl std::fmt::Debug for ExploitGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExploitGuard")
            .field("audit", &self.audit)
            .finish_non_exhaustive()
    }
}

static MODE_LINE: Mutex<String> = Mutex::new(String::new());
static COUNTERS: [AtomicU64; counter::SLOTS as usize] =
    [const { AtomicU64::new(0) }; counter::SLOTS as usize];

fn set_mode_line(s: impl Into<String>) {
    if let Ok(mut m) = MODE_LINE.lock() {
        *m = s.into();
    }
}

/// `lite detect`, `strict enforce`, `off`, `unavailable: <reason>`, or
/// `not started` (for `nn-admin status`).
pub fn mode_line() -> String {
    match MODE_LINE.lock() {
        Ok(m) if !m.is_empty() => m.clone(),
        _ => "not started".to_string(),
    }
}

/// Summed counter `slot` (`common::epg::counter`), as of the last sample.
pub fn counter_total(slot: u32) -> u64 {
    COUNTERS
        .get(slot as usize)
        .map(|c| c.load(Ordering::Relaxed))
        .unwrap_or(0)
}

/// The guard in `nn-admin status` (signed telemetry verb).
pub fn status() -> nn_proto::admin_protocol::ExploitGuardStatus {
    nn_proto::admin_protocol::ExploitGuardStatus {
        mode: mode_line(),
        checked_total: counter_total(counter::CHECKED),
        skipped_privileged_total: counter_total(counter::SKIPPED_PRIVILEGED),
        anomalies_total: counter_total(counter::ANOMALIES),
        kills_total: counter_total(counter::KILLS),
        // Strict's tasks a full map refused, or lite's records the LRU map
        // evicted (one variant runs: the other counter stays 0).
        untracked_total: counter_total(counter::UNTRACKED) + counter_total(counter::BASELINES_LOST),
        use_checks_total: counter_total(counter::USE_CHECKS),
        denied_total: counter_total(counter::DENIED),
    }
}

/// `/proc/sys/kernel/pid_max`.
pub fn pid_max() -> Option<u32> {
    std::fs::read_to_string("/proc/sys/kernel/pid_max")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
}

/// Strict's task map size: the operator's, else `pid_max` (every live task
/// has a pid, so the map cannot fill), bounded to [1024, 4194304] (the
/// kernel's `PID_MAX_LIMIT`). Not preallocated: it costs only the tracked
/// tasks.
pub fn task_map_entries(requested: Option<u32>, pid_max: Option<u32>) -> u32 {
    requested
        .or(pid_max)
        .unwrap_or(epg::TASKS_MAX)
        .clamp(1024, 4_194_304)
}

/// `/proc/sys/kernel/threads-max`.
pub fn threads_max() -> Option<u32> {
    std::fs::read_to_string("/proc/sys/kernel/threads-max")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
}

/// Lite's task map size. An LRU map is preallocated (about 150 bytes an
/// entry), so not `pid_max` (4194304 on systemd hosts): the operator's,
/// bounded to [1024, `LITE_TASKS_LIMIT`], else `min(pid_max, threads-max)`
/// — no more tasks can be alive at once, and records are deleted at exit,
/// so live tasks alone cannot fill it — capped at `LITE_TASKS_DEFAULT`
/// (about 10 MiB). A host or a flood above the cap makes the map evict:
/// counted, attested, degraded evidence (design note, "Lite").
pub fn lite_task_map_entries(
    requested: Option<u32>,
    pid_max: Option<u32>,
    threads_max: Option<u32>,
) -> u32 {
    match requested {
        Some(n) => n.clamp(1024, epg::LITE_TASKS_LIMIT),
        None => [pid_max, threads_max]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(epg::LITE_TASKS_DEFAULT)
            .clamp(1024, epg::LITE_TASKS_DEFAULT),
    }
}

/// The sizes the loader gives the two task maps
/// (`EbpfLoader::map_max_entries`), decided before the eBPF object is
/// loaded (R11c, lab PR 264: in the multiplexer's load plan; they were
/// process-wide values `set_task_map_entries` stored).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskMaps {
    /// Strict's.
    pub strict: u32,
    /// Lite's.
    pub lite: u32,
}

impl TaskMaps {
    /// Both sizes for a start that runs variant `v` (`requested`:
    /// `--exploit-guard-tasks`). Lite's gets one entry when lite does not
    /// run (it is preallocated); strict's costs nothing unused.
    pub fn for_variant(requested: Option<u32>, v: Variant) -> Self {
        Self {
            strict: task_map_entries(requested, pid_max()),
            lite: match v {
                Variant::Lite => lite_task_map_entries(requested, pid_max(), threads_max()),
                Variant::Strict | Variant::Off => 1,
            },
        }
    }
}

impl Default for TaskMaps {
    /// The sizes of a load nothing decided for (the lab's one-shot modes):
    /// strict's [`pid_max`], lite's its default.
    fn default() -> Self {
        Self {
            strict: task_map_entries(None, pid_max()),
            lite: lite_task_map_entries(None, pid_max(), threads_max()),
        }
    }
}

/// `CLOCK_MONOTONIC` in ns: the clock of `task_struct.start_time` (0 when
/// it cannot be read, which leaves no record called lost).
fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: a valid out-pointer for the duration of the call.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } != 0 {
        return 0;
    }
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}

/// The layout the running kernel's BTF gave the agent (`btf_revalidate`).
pub fn resolved_layout() -> Result<ResolvedLayout, String> {
    let r = crate::anti_tamper::btf_revalidate::resolved()
        .ok_or_else(|| "no kernel BTF (offsets not resolved)".to_string())?;
    let get = |s: u32| {
        r.values
            .iter()
            .find(|(k, _)| *k == s)
            .map(|(_, v)| *v)
            .filter(|v| *v != BTF_OFFSETS_ABSENT)
    };
    Ok(ResolvedLayout {
        task_cred: get(slot::TASK_STRUCT_CRED_OFFSET),
        task_nsproxy: get(slot::TASK_STRUCT_NSPROXY_OFFSET),
        task_fs: get(slot::TASK_STRUCT_FS_OFFSET),
        task_ti_status: get(slot::TASK_STRUCT_TI_STATUS_OFFSET),
        fs_root: get(slot::FS_STRUCT_ROOT_OFFSET),
        path_dentry: get(slot::PATH_DENTRY_OFFSET),
        cred_uid: get(slot::CRED_UID_OFFSET),
        cred_fsgid: get(slot::CRED_FSGID_OFFSET),
        cred_cap_permitted: get(slot::CRED_CAP_PERMITTED_OFFSET),
        cred_cap_effective: get(slot::CRED_CAP_EFFECTIVE_OFFSET),
        cred_user_ns: get(slot::CRED_USER_NS_OFFSET),
        nsproxy_mnt: get(slot::NSPROXY_MNT_NS_OFFSET),
        nsproxy_pid: get(slot::NSPROXY_PID_NS_FOR_CHILDREN_OFFSET),
        nsproxy_net: get(slot::NSPROXY_NET_NS_OFFSET),
        mnt_inum: get(slot::MNT_NAMESPACE_INUM_OFFSET),
        pid_inum: get(slot::PID_NAMESPACE_INUM_OFFSET),
        net_inum: get(slot::NET_INUM_OFFSET),
        user_inum: get(slot::USER_NAMESPACE_INUM_OFFSET),
        task_real_cred: get(slot::TASK_STRUCT_REAL_CRED_OFFSET),
        file_inode: get(slot::FILE_F_INODE_OFFSET),
        inode_mode: get(slot::INODE_I_MODE_OFFSET),
        inode_uid: get(slot::INODE_I_UID_OFFSET),
        task_start_time: get(slot::TASK_STRUCT_START_TIME_OFFSET),
        task_flags: get(slot::TASK_STRUCT_FLAGS_OFFSET),
    })
}

/// `/proc/sys/kernel/cap_last_cap`.
pub fn cap_last_cap() -> Result<u32, String> {
    let s = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .map_err(|e| format!("/proc/sys/kernel/cap_last_cap: {e}"))?;
    parse_cap_last_cap(&s)
}

fn parse_cap_last_cap(s: &str) -> Result<u32, String> {
    match s.trim().parse::<u32>() {
        Ok(n) if (30..=63).contains(&n) => Ok(n),
        Ok(n) => Err(format!("cap_last_cap {n} out of range")),
        Err(e) => Err(format!("cap_last_cap {s:?}: {e}")),
    }
}

fn write_config(map: &mut Array<MapData, AyaGuardConfig>, c: GuardConfig) -> Result<(), String> {
    map.set(0, AyaGuardConfig(c), 0)
        .map_err(|e| format!("writing {CONFIG_MAP}: {e}"))
}

fn take_config(ebpf: &mut Ebpf) -> Result<Array<MapData, AyaGuardConfig>, String> {
    let m = ebpf
        .take_map(CONFIG_MAP)
        .ok_or_else(|| format!("map {CONFIG_MAP} missing from the eBPF object"))?;
    Array::try_from(m).map_err(|e| format!("{CONFIG_MAP}: {e}"))
}

fn load_fentry(ebpf: &mut Ebpf, prog: &str, func: &str, btf: &Btf) -> Result<(), String> {
    let p: &mut FEntry = ebpf
        .program_mut(prog)
        .ok_or_else(|| format!("program {prog} missing from the eBPF object"))?
        .try_into()
        .map_err(|e| format!("{prog} is not an fentry program: {e}"))?;
    p.load(func, btf)
        .map_err(|e| format!("verifier rejected {prog} ({func}): {e:#}"))?;
    p.attach()
        .map_err(|e| format!("attaching {prog} to {func}: {e:#}"))?;
    Ok(())
}

fn load_raw_tp(ebpf: &mut Ebpf, prog: &str, tp: &str) -> Result<(), String> {
    let p: &mut RawTracePoint = ebpf
        .program_mut(prog)
        .ok_or_else(|| format!("program {prog} missing from the eBPF object"))?
        .try_into()
        .map_err(|e| format!("{prog} is not a raw tracepoint: {e}"))?;
    p.load()
        .map_err(|e| format!("verifier rejected {prog}: {e:#}"))?;
    p.attach(tp)
        .map_err(|e| format!("attaching {prog} to {tp}: {e:#}"))?;
    Ok(())
}

fn load_btf_tp(ebpf: &mut Ebpf, prog: &str, tp: &str, btf: &Btf) -> Result<(), String> {
    let p: &mut BtfTracePoint = ebpf
        .program_mut(prog)
        .ok_or_else(|| format!("program {prog} missing from the eBPF object"))?
        .try_into()
        .map_err(|e| format!("{prog} is not a BTF tracepoint: {e}"))?;
    p.load(tp, btf)
        .map_err(|e| format!("verifier rejected {prog} ({tp}): {e:#}"))?;
    p.attach()
        .map_err(|e| format!("attaching {prog} to {tp}: {e:#}"))?;
    Ok(())
}

fn load_lsm(ebpf: &mut Ebpf, prog: &str, hook: &str, btf: &Btf) -> Result<(), String> {
    let p: &mut Lsm = ebpf
        .program_mut(prog)
        .ok_or_else(|| format!("program {prog} missing from the eBPF object"))?
        .try_into()
        .map_err(|e| format!("{prog} is not an LSM program: {e}"))?;
    p.load(hook, btf)
        .map_err(|e| format!("verifier rejected {prog} ({hook}): {e:#}"))?;
    p.attach()
        .map_err(|e| format!("attaching {prog} to {hook}: {e:#}"))?;
    Ok(())
}

/// Detach and unload every guard program that is loaded (failure path).
fn unload_all(ebpf: &mut Ebpf) {
    let fentries = STRICT_FENTRY
        .iter()
        .chain(std::iter::once(&STRICT_OPTIONAL_FENTRY))
        .chain(LITE_FENTRY);
    for (prog, _) in fentries {
        if let Some(Ok(p)) = ebpf.program_mut(prog).map(<&mut FEntry>::try_from) {
            let _ = p.unload();
        }
    }
    for (prog, _) in STRICT_RAW_TP {
        if let Some(Ok(p)) = ebpf.program_mut(prog).map(<&mut RawTracePoint>::try_from) {
            let _ = p.unload();
        }
    }
    for (prog, _) in LITE_TP_BTF {
        if let Some(Ok(p)) = ebpf.program_mut(prog).map(<&mut BtfTracePoint>::try_from) {
            let _ = p.unload();
        }
    }
    for (prog, _) in LITE_LSM {
        if let Some(Ok(p)) = ebpf.program_mut(prog).map(<&mut Lsm>::try_from) {
            let _ = p.unload();
        }
    }
}

/// Load, attach and arm `variant` in detect mode. `Ok((ring, guard))`
/// hands the record ring to the caller's pump and the running guard to the
/// start; `Err(reason)` leaves the guard off (nothing attached) and is what
/// the caller attests.
pub fn attach(ebpf: &mut Ebpf, v: Variant) -> Result<(RingBuf<MapData>, ExploitGuard), String> {
    if v == Variant::Off {
        set_mode_line("off");
        return Err("off (--exploit-guard off)".to_string());
    }
    let result = attach_inner(ebpf, v);
    match &result {
        Ok(_) => {
            set_mode_line(format!("{} detect", v.as_str()));
            info!(
                variant = v.as_str(),
                "exploit post-condition guard attached (experimental; detect until the \
                 no-enforcement gate is resolved)"
            );
        }
        Err(e) => {
            unload_all(ebpf);
            set_mode_line(format!("unavailable: {e}"));
            warn!(
                variant = v.as_str(),
                reason = %e,
                "exploit post-condition guard NOT running — kernel exploit post-conditions \
                 are not watched on this host"
            );
        }
    }
    result
}

fn attach_inner(ebpf: &mut Ebpf, v: Variant) -> Result<(RingBuf<MapData>, ExploitGuard), String> {
    let wire_variant = match v {
        Variant::Lite => variant::LITE,
        Variant::Strict => variant::STRICT,
        Variant::Off => return Err("off".to_string()),
    };
    if v == Variant::Strict {
        if let Some(why) = strict_unsupported(KernelVersion::current().ok()) {
            return Err(why);
        }
    }
    let layout = resolved_layout()?;
    let config = epg::guard_config(&layout, cap_last_cap()?, cfg::MODE_DETECT, wire_variant)
        .map_err(|e| format!("kernel layout: {e}"))?;
    // Unarmed first: the programs do nothing until every one is attached.
    let mut map = take_config(ebpf)?;
    write_config(&mut map, config)?;
    let btf = Btf::from_sys_fs().map_err(|e| format!("vmlinux BTF: {e}"))?;
    match v {
        Variant::Lite => {
            for (prog, tp) in LITE_TP_BTF {
                load_btf_tp(ebpf, prog, tp, &btf)?;
            }
            for (prog, func) in LITE_FENTRY {
                load_fentry(ebpf, prog, func, &btf)?;
            }
            for (prog, hook) in LITE_LSM {
                load_lsm(ebpf, prog, hook, &btf)?;
            }
        }
        Variant::Strict => {
            for (prog, func) in STRICT_FENTRY {
                load_fentry(ebpf, prog, func, &btf)?;
            }
            let (prog, func) = STRICT_OPTIONAL_FENTRY;
            if let Err(e) = load_fentry(ebpf, prog, func, &btf) {
                warn!(
                    reason = %e,
                    "exploit guard (strict): chroot_fs_refs not hooked — a pivot_root by a \
                     task the guard skips can make other tasks' root changes look \
                     unexplained (sys_exit fallback only)"
                );
            }
            for (prog, tp) in STRICT_RAW_TP {
                load_raw_tp(ebpf, prog, tp)?;
            }
        }
        Variant::Off => {}
    }
    let ring = ebpf
        .take_map(RING_MAP)
        .ok_or_else(|| format!("map {RING_MAP} missing from the eBPF object"))
        .and_then(|m| RingBuf::try_from(m).map_err(|e| format!("{RING_MAP}: {e}")))?;
    let counters: PerCpuArray<MapData, u64> = ebpf
        .take_map(COUNTERS_MAP)
        .ok_or_else(|| format!("map {COUNTERS_MAP} missing from the eBPF object"))
        .and_then(|m| PerCpuArray::try_from(m).map_err(|e| format!("{COUNTERS_MAP}: {e}")))?;
    #[cfg(feature = "debug-trigger")]
    let config = with_lab_injection(config);
    let armed = GuardConfig { armed: 1, ..config };
    write_config(&mut map, armed)?;
    // Lite: every task started from now on had its baseline taken by the
    // armed fork program, so one found without a record later lost it
    // (`epg::baseline_lost`). Read after the arming write: a task that
    // started before it is only first seen.
    let armed = GuardConfig {
        armed_at_ns: monotonic_ns(),
        ..armed
    };
    write_config(&mut map, armed)?;
    let guard = ExploitGuard {
        control: Arc::new(Mutex::new(Control {
            map,
            config: armed,
            variant: v,
        })),
        audit: LateAudit::new(),
    };
    spawn_sampler(counters, guard.audit.clone());
    Ok((ring, guard))
}

/// `debug-trigger` builds only: the lab's fault-injection comm
/// ([`INJECT_ENV`], at most 15 bytes) — the guard then reports a strict
/// `getppid()` exit, or the first lite use point (`capable`, exec), of that
/// process as an anomaly marked injected (nothing changes).
#[cfg(feature = "debug-trigger")]
pub const INJECT_ENV: &str = "NN_EPG_INJECT_COMM";

#[cfg(feature = "debug-trigger")]
fn with_lab_injection(mut c: GuardConfig) -> GuardConfig {
    let Ok(v) = std::env::var(INJECT_ENV) else {
        return c;
    };
    match inject_words(&v) {
        Some((lo, hi)) => {
            c.inject_comm_lo = lo;
            c.inject_comm_hi = hi;
            warn!(
                comm = %nn_model::log_escape::Escaped(&v),
                "exploit guard: LAB fault injection armed (debug build) — this comm's strict \
                 getppid() or first lite use point is reported as an anomaly marked injected"
            );
        }
        None => warn!(
            env = INJECT_ENV,
            "exploit guard: injection comm empty or longer than 15 bytes — ignored"
        ),
    }
    c
}

/// The packed words of a comm of 1..=15 bytes.
#[cfg_attr(not(feature = "debug-trigger"), allow(dead_code))]
fn inject_words(comm: &str) -> Option<(u64, u64)> {
    let b = comm.as_bytes();
    if b.is_empty() || b.len() > 15 || b.contains(&0) {
        return None;
    }
    let mut buf = [0u8; 16];
    buf[..b.len()].copy_from_slice(b);
    Some(epg::pack_comm(&buf))
}

/// The response the kernel should apply: enforce only when asked for and
/// the global no-enforcement switch (`--detect-only`) is off.
pub fn effective_response(requested: Response, detect_only: bool) -> Response {
    match requested {
        Response::Enforce if detect_only => Response::Detect,
        r => r,
    }
}

/// Switch the guard, when it runs (`guard`: what [`attach`] gave), between
/// detect and enforce. `Err` when the guard is not running (off or
/// unavailable).
pub fn set_response(guard: Option<&ExploitGuard>, r: Response) -> Result<(), String> {
    guard
        .ok_or_else(|| "the exploit guard is not running".to_string())?
        .set_response(r)
}

impl ExploitGuard {
    /// Switch the running guard between detect and enforce.
    pub fn set_response(&self, r: Response) -> Result<(), String> {
        let mut c = self
            .control
            .lock()
            .map_err(|_| "exploit guard control poisoned".to_string())?;
        let next = GuardConfig {
            mode: match r {
                Response::Detect => cfg::MODE_DETECT,
                Response::Enforce => cfg::MODE_ENFORCE,
            },
            ..c.config
        };
        write_config(&mut c.map, next)?;
        c.config = next;
        set_mode_line(format!("{} {}", c.variant.as_str(), r.as_str()));
        Ok(())
    }

    /// Hand the signed audit log to the guard's sampler (the start's attest
    /// phase, once it exists): a saturation is signed from then on.
    pub fn bind_audit_log(&self, log: Option<AuditHandle>) {
        self.audit.bind(log);
    }
}

fn read_counters(map: &PerCpuArray<MapData, u64>) -> [u64; counter::SLOTS as usize] {
    let mut out = [0u64; counter::SLOTS as usize];
    for (i, o) in out.iter_mut().enumerate() {
        if let Ok(per_cpu) = map.get(&(i as u32), 0) {
            *o = per_cpu.iter().fold(0u64, |a, v| a.wrapping_add(*v));
        }
    }
    out
}

fn attest(audit: &LateAudit, op: &str, detail: String) {
    let Some(log) = audit.get() else { return };
    let draft = crate::audit::AuditEntryDraft {
        op: op.to_string(),
        extra: serde_json::json!({
            "kind": "subsystem_degraded",
            "detail": detail,
            "at_boot": false,
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
            "exploit-guard saturation audit entry failed"
        );
    }
}

/// The signed detail of strict tasks a full map refused.
fn untracked_detail(new: u64, total: u64) -> String {
    format!(
        "exploit guard (strict) task map full: {new} new tasks not tracked since the last \
         sample ({total} in all) — their system calls are not judged"
    )
}

/// The signed detail of lite records the LRU task map lost.
fn lost_detail(new: u64, total: u64) -> String {
    format!(
        "exploit guard (lite) task map evicted {new} task record(s) since the last sample \
         ({total} in all): each was re-taken at the task's next hook, and what a re-taken \
         credential holds is not attributed to a mechanism (degraded evidence; raise \
         --exploit-guard-tasks)"
    )
}

/// One sampled counter that must never rise unseen: a WARN at every rise,
/// a signed `subsystem_degraded` entry at most once per window.
struct Watched {
    slot: usize,
    op: &'static str,
    warn: &'static str,
    detail: fn(u64, u64) -> String,
    last_audit: Option<Instant>,
}

impl Watched {
    fn check(&mut self, audit: &LateAudit, prev: &[u64], now: &[u64]) {
        let (p, n) = (prev[self.slot], now[self.slot]);
        if n <= p {
            return;
        }
        warn!(new = n - p, total = n, "{}", self.warn);
        let due = self
            .last_audit
            .map(|t| t.elapsed() >= Duration::from_secs(AUDIT_WINDOW_SECS))
            .unwrap_or(true);
        if due {
            self.last_audit = Some(Instant::now());
            attest(audit, self.op, (self.detail)(n - p, n));
        }
    }
}

fn spawn_sampler(map: PerCpuArray<MapData, u64>, audit: LateAudit) {
    tokio::spawn(async move {
        let mut prev = [0u64; counter::SLOTS as usize];
        let mut watched = [
            Watched {
                slot: counter::UNTRACKED as usize,
                op: AUDIT_OP,
                warn: "exploit guard: task map full — new tasks are NOT judged",
                detail: untracked_detail,
                last_audit: None,
            },
            Watched {
                slot: counter::BASELINES_LOST as usize,
                op: LOST_AUDIT_OP,
                warn: "exploit guard: lite task map evicted task records — re-taken, their \
                       privileges at the re-take are degraded evidence",
                detail: lost_detail,
                last_audit: None,
            },
        ];
        loop {
            tokio::time::sleep(Duration::from_secs(SAMPLE_SECS)).await;
            let now = read_counters(&map);
            for (i, v) in now.iter().enumerate() {
                COUNTERS[i].store(*v, Ordering::Relaxed);
            }
            for w in watched.iter_mut() {
                w.check(&audit, &prev, &now);
            }
            let held = counter::REPORTS_HELD as usize;
            if now[held] > prev[held] {
                warn!(
                    held = now[held] - prev[held],
                    "exploit guard: anomalies beyond a task's record budget were counted, not recorded"
                );
            }
            prev = now;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_needs_6_1() {
        assert!(strict_unsupported(Some(KernelVersion::new(5, 15, 198))).is_some());
        assert!(strict_unsupported(Some(KernelVersion::new(5, 14, 0))).is_some());
        assert!(
            strict_unsupported(None).is_some(),
            "unknown version: unavailable"
        );
        for (a, b) in [(6, 1), (6, 8), (6, 12), (7, 0)] {
            assert_eq!(
                strict_unsupported(Some(KernelVersion::new(a, b, 0))),
                None,
                "{a}.{b}"
            );
        }
    }

    #[test]
    fn enforce_yields_to_detect_only() {
        assert_eq!(
            effective_response(Response::Enforce, true),
            Response::Detect
        );
        assert_eq!(
            effective_response(Response::Enforce, false),
            Response::Enforce
        );
        assert_eq!(
            effective_response(Response::Detect, false),
            Response::Detect
        );
    }

    #[test]
    fn cap_last_cap_is_parsed_and_bounded() {
        assert_eq!(parse_cap_last_cap("40\n"), Ok(40));
        assert!(parse_cap_last_cap("7").is_err());
        assert!(parse_cap_last_cap("64").is_err());
        assert!(parse_cap_last_cap("x").is_err());
    }

    /// Strict's task map: the operator's size, else `pid_max` (it cannot
    /// fill), bounded.
    #[test]
    fn strict_task_map_is_sized_from_pid_max() {
        assert_eq!(task_map_entries(None, Some(4_194_304)), 4_194_304);
        assert_eq!(task_map_entries(None, Some(32_768)), 32_768);
        assert_eq!(task_map_entries(Some(100_000), Some(32_768)), 100_000);
        assert_eq!(task_map_entries(None, None), epg::TASKS_MAX);
        assert_eq!(task_map_entries(Some(10), None), 1024);
        assert_eq!(task_map_entries(Some(u32::MAX), None), 4_194_304);
    }

    /// Lite's task map is preallocated: never `pid_max` (4194304 on a
    /// systemd host would be ~600 MiB), but the live-task bound
    /// `min(pid_max, threads-max)` capped, or the operator's, bounded.
    #[test]
    fn lite_task_map_is_bounded_not_pid_max() {
        // Debian 12 / systemd: pid_max 4194304, a 2 GiB guest's threads-max
        assert_eq!(
            lite_task_map_entries(None, Some(4_194_304), Some(15_000)),
            15_000,
            "no more tasks can be alive: live tasks cannot fill it"
        );
        // a big host: capped
        assert_eq!(
            lite_task_map_entries(None, Some(4_194_304), Some(1_000_000)),
            epg::LITE_TASKS_DEFAULT
        );
        assert_eq!(
            lite_task_map_entries(None, Some(32_768), Some(200_000)),
            32_768
        );
        assert_eq!(
            lite_task_map_entries(None, None, None),
            epg::LITE_TASKS_DEFAULT
        );
        assert_eq!(lite_task_map_entries(None, Some(100), None), 1024);
        // the operator's, bounded
        assert_eq!(
            lite_task_map_entries(Some(200_000), Some(4_194_304), Some(15_000)),
            200_000
        );
        assert_eq!(lite_task_map_entries(Some(1), None, None), 1024);
        assert_eq!(
            lite_task_map_entries(Some(u32::MAX), None, None),
            epg::LITE_TASKS_LIMIT
        );
    }

    /// The signed details name the variant, the counts and what was lost.
    #[test]
    fn saturation_details_say_what_is_not_judged() {
        let d = untracked_detail(3, 9);
        assert!(d.contains("(strict)") && d.contains("3 new tasks") && d.contains("9 in all"));
        let d = lost_detail(2, 5);
        assert!(
            d.contains("(lite)")
                && d.contains("evicted 2 task record(s)")
                && d.contains("5 in all")
                && d.contains("degraded evidence")
                && d.contains("--exploit-guard-tasks"),
            "{d}"
        );
        assert_ne!(AUDIT_OP, LOST_AUDIT_OP);
    }

    #[test]
    fn injection_comm_is_bounded_like_a_task_comm() {
        assert!(inject_words("nn-epg-probe").is_some());
        assert!(inject_words("").is_none());
        assert!(
            inject_words("0123456789abcdef").is_none(),
            "16 bytes do not fit TASK_COMM_LEN"
        );
        assert!(inject_words("a\0b").is_none());
        assert_eq!(inject_words("a"), Some((0x61, 0)));
    }

    #[test]
    fn only_off_is_a_weakening_value() {
        assert!(turns_off("off"));
        assert!(turns_off(" OFF "));
        assert!(!turns_off("lite"));
        assert!(!turns_off("strict"));
        assert!(!turns_off(""));
    }

    /// Each variant is all or nothing, baselines and mechanisms before the
    /// programs that judge.
    #[test]
    fn hook_tables_are_complete_and_ordered() {
        let funcs: Vec<&str> = STRICT_FENTRY.iter().map(|(_, f)| *f).collect();
        assert_eq!(
            funcs,
            ["commit_creds", "switch_task_namespaces", "set_fs_root"]
        );
        let lite: Vec<&str> = LITE_FENTRY.iter().map(|(_, f)| *f).collect();
        assert_eq!(funcs, lite, "lite judges the same mechanisms");
        assert_eq!(STRICT_RAW_TP.last().map(|(_, t)| *t), Some("sys_enter"));
        assert_eq!(
            STRICT_RAW_TP.first().map(|(_, t)| *t),
            Some("sched_process_exit")
        );
        let hooks: Vec<&str> = LITE_LSM.iter().map(|(_, h)| *h).collect();
        assert_eq!(hooks, ["capable", "bprm_check_security", "file_open"]);
        let tps: Vec<&str> = LITE_TP_BTF.iter().map(|(_, t)| *t).collect();
        assert_eq!(
            tps,
            ["sched_process_exit", "sched_process_fork"],
            "lite: cleanup, then baselines"
        );
        assert_eq!(STRICT_OPTIONAL_FENTRY.1, "chroot_fs_refs");
    }

    #[test]
    fn a_guard_that_never_started_says_so() {
        assert_eq!(mode_line(), "not started");
        assert!(set_response(None, Response::Enforce).is_err());
        assert_eq!(counter_total(counter::CHECKED), 0);
    }

    /// Lab PR 219: the embedded eBPF object declares lite's task map as an
    /// LRU hash (type 9, which aya loads: lite's first map, task
    /// storage, parsed here but made the agent refuse to start, "Unsupported
    /// map type found 29") keyed by the `task_struct` address with the
    /// `LiteState` value, strict's map not preallocated, and every program
    /// both variants attach. That every map of the object is one aya can
    /// load is `ebpf_object::tests::every_map_is_one_the_agents_aya_loads`.
    #[test]
    fn the_object_declares_the_guard_maps_and_programs() {
        let bytes = crate::sensors::ebpf_object::EBPF_BYTES;
        if bytes.is_empty() {
            eprintln!("no embedded eBPF object in this build: skipped");
            return;
        }
        let obj = aya_obj::Object::parse(bytes).expect("the eBPF object parses");
        let lite = obj.maps.get(LITE_TASKS_MAP).expect("lite task map");
        assert_eq!(
            lite.map_type(),
            aya_obj::generated::bpf_map_type::BPF_MAP_TYPE_LRU_HASH as u32
        );
        assert_eq!(lite.key_size(), 8, "the task_struct address");
        assert_eq!(
            lite.value_size() as usize,
            std::mem::size_of::<epg::LiteState>()
        );
        assert_eq!(lite.map_flags(), 0, "an LRU map is preallocated");
        assert_eq!(
            lite.max_entries(),
            epg::LITE_TASKS_COMPILED,
            "the compiled size, replaced at load"
        );
        let strict = obj.maps.get(STRICT_TASKS_MAP).expect("strict task map");
        assert_eq!(strict.map_flags(), 1, "not preallocated");
        let cfg_map = obj.maps.get(CONFIG_MAP).expect("config map");
        assert_eq!(
            cfg_map.value_size() as usize,
            std::mem::size_of::<GuardConfig>()
        );
        for (prog, _) in STRICT_FENTRY
            .iter()
            .chain(std::iter::once(&STRICT_OPTIONAL_FENTRY))
            .chain(STRICT_RAW_TP)
            .chain(LITE_TP_BTF)
            .chain(LITE_FENTRY)
            .chain(LITE_LSM)
        {
            assert!(obj.programs.contains_key(*prog), "{prog} missing");
        }
    }
}
