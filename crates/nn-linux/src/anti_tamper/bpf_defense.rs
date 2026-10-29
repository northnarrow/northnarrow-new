//! Userland half of the BPF self-defence (`agent-ebpf/src/bpf_defense.rs`).
//!
//! * attaches `bpf_map_guard` (deny set — counted in the fail-closed LSM
//!   health like every other deny hook) and `bpf_syscall_observe`
//!   (observe set);
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
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tracing::{error, info, warn};

use crate::audit::{AuditEntryDraft, AuditLog};

/// Set to `1` to run the map guard in observe mode (log, never deny).
pub const OBSERVE_ENV: &str = "NN_BPF_DEFENSE_OBSERVE";
/// Set to `1` to ENFORCE even in a `debug-trigger` build (lab tests of the deny path).
pub const ENFORCE_ENV: &str = "NN_BPF_DEFENSE_ENFORCE";

pub const GUARD_PROGRAM: &str = "bpf_map_guard";
pub const GUARD_HOOK: &str = "bpf_map";
pub const OBSERVE_PROGRAM: &str = "bpf_syscall_observe";
pub const OBSERVE_HOOK: &str = "bpf";

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
/// Prefix of the LSM link pins written by `antitamper_bpf::lsm_pin_paths`.
const LINK_PIN_PREFIX: &str = "link_";
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
}

impl BpfGuard {
    /// An empty record, for one eBPF object.
    pub fn new() -> Self {
        Self::default()
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
/// fail-closed outcome.
pub(crate) fn attach(
    guard: &BpfGuard,
    ebpf: &mut Ebpf,
    btf: &Btf,
    pin_root: Option<&Path>,
) -> BpfDefenseHealth {
    let mut health = BpfDefenseHealth::default();
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
    match antitamper_bpf::attach_transient(ebpf, OBSERVE_PROGRAM, OBSERVE_HOOK, btf) {
        Ok(()) => info!(
            program = OBSERVE_PROGRAM,
            hook = OBSERVE_HOOK,
            "BPF self-defence: bpf() syscall observer attached"
        ),
        Err(e) => {
            dump_verifier_log(OBSERVE_PROGRAM, &e);
            warn!(program = OBSERVE_PROGRAM, hook = OBSERVE_HOOK, error = format!("{e:#}"), "BPF self-defence: bpf() observer attach FAILED — foreign BPF activity not reported");
            health
                .observe_failures
                .push((OBSERVE_PROGRAM, format!("{e:#}")));
        }
    }
    health
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
    // Links: every loaded link whose program is ours (the LSM hooks, the
    // tracepoints, the kprobes). The kernel keeps map, program and link
    // ids in three separate spaces, hence the kind in the value.
    let link_ids = own_link_ids(&prog_ids, pin_root);
    for id in &link_ids {
        own.insert(own_key(KIND_LINK, *id), KIND_LINK, 0)
            .with_context(|| format!("registering own link id {id}"))?;
    }
    let _ = guard.0.own_links.set(OwnLinks {
        ids: link_ids.clone(),
        pin_root: pin_root.map(Path::to_path_buf),
    });
    // Pin names: the final component of every `link_*` pin under the pin
    // root whose link runs one of our programs, so `OBJ_GET` on a pinned
    // link is recognised without a path walk in the kernel. External audit
    // ATP-017 (NN-AUD-265): only those — every `link_*` entry used to go
    // in, so 64 planted ones (the map's size) refused the start, and a
    // planted name equal to another product's pin denied that product's
    // `OBJ_GET`. The others are reported (`foreign_pin`), never registered
    // or removed.
    let own_progs: HashSet<u32> = prog_ids.iter().copied().collect();
    let LinkPins {
        own: pin_names,
        foreign,
    } = link_pins(pin_root, &own_progs);
    for f in &foreign {
        warn!(
            pin = %f,
            "BPF self-defence: a link_* entry in the pin root is not one of the agent's links — \
             not registered, not removed"
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

/// External audit ATP-013: the programs and links attached after the
/// anti-tamper step — the FIM observers, the file-open sensor — added to
/// `OWN_BPF_IDS` in a second pass, so the set stays complete. Returns how
/// many ids were written (inserting one already there changes nothing).
pub fn register_late_objects(ebpf: &mut Ebpf) -> Result<usize> {
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
    // Their links are held by this process (not pinned): found through
    // its descriptors.
    let link_ids = own_link_ids(&prog_ids, None);
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
    let body = render_own_prog_ids(std::process::id(), &progs);
    crate::atomic_file::replace(path, body.as_bytes(), 0o600)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(progs.len())
}

/// The body of the [`OWN_IDS_FILE_NAME`] file. The scripts read the first
/// field of every line that starts with a digit.
fn render_own_prog_ids(pid: u32, progs: &[(u32, &str)]) -> String {
    let mut body = format!("# northnarrow-agent pid {pid}: loaded BPF programs (id name)\n");
    for (id, name) in progs {
        body.push_str(&format!("{id} {name}\n"));
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
/// (sensors, transient hooks) plus the pinned LSM links under the pin
/// root, kept when their program is one of ours. No `CAP_SYS_ADMIN` is
/// needed — `*_GET_NEXT_ID` would, and the unit does not grant it: every
/// link is reached through an fd and read from `/proc/self/fdinfo`.
fn own_link_ids(prog_ids: &[u32], pin_root: Option<&Path>) -> Vec<u32> {
    let own: HashSet<u32> = prog_ids.iter().copied().collect();
    let mut ids: Vec<u32> = live_links(pin_root)
        .into_iter()
        .filter(|(_, prog)| own.contains(prog))
        .map(|(id, _)| id)
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// `(link_id, prog_id)` of every link reachable from this process right
/// now: held fds and `link_*` pins. A link detached from outside keeps its
/// id but reports `prog_id` 0; a pin that is gone is simply absent.
fn live_links(pin_root: Option<&Path>) -> Vec<(u32, u32)> {
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
            if let Some(link) = link_from_fdinfo(fd) {
                out.push(link);
            }
        }
    }
    if let Some(root) = pin_root {
        if let Ok(entries) = std::fs::read_dir(root) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                if !name.starts_with(LINK_PIN_PREFIX) {
                    continue;
                }
                if let Some(fd) = obj_get_fd(&entry.path()) {
                    if let Some(link) = link_from_fdinfo(fd.as_raw_fd()) {
                        out.push(link);
                    }
                }
            }
        }
    }
    out
}

/// `(link_id, prog_id)` from `/proc/self/fdinfo/<fd>` when the fd is a BPF
/// link (the kernel prints `link_type`, `link_id`, `prog_id` for those).
fn link_from_fdinfo(fd: i32) -> Option<(u32, u32)> {
    let text = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")).ok()?;
    parse_link_fdinfo(&text)
}

fn parse_link_fdinfo(text: &str) -> Option<(u32, u32)> {
    let mut link_id = None;
    let mut prog_id = None;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("link_id:") {
            link_id = v.trim().parse::<u32>().ok();
        } else if let Some(v) = line.strip_prefix("prog_id:") {
            prog_id = v.trim().parse::<u32>().ok();
        }
    }
    Some((link_id?, prog_id.unwrap_or(0)))
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

/// External audit ATP-017 (NN-AUD-265): the `link_*` entries of the pin
/// root, split by owner — `own` holds the [`pin_name_key`] of each pin whose
/// link runs one of the agent's programs, `foreign` a description of each
/// other entry.
#[derive(Debug, Default)]
struct LinkPins {
    own: Vec<u64>,
    foreign: Vec<String>,
}

/// Kind of the signed `integrity_drift` for a `link_*` entry of the pin
/// root that is not one of the agent's links.
pub const FOREIGN_PIN_KIND: &str = "foreign_pin";

/// Whose link a `link_*` entry holds: `link` is its `(link_id, prog_id)`
/// (`None`: not a link, or not openable as one). `Err` says why it is not
/// one of the agent's.
fn link_pin_owner(link: Option<(u32, u32)>, own_progs: &HashSet<u32>) -> Result<(), String> {
    match link {
        None => Err("not a BPF link".to_string()),
        Some((id, 0)) => Err(format!("link {id} holds no program (detached)")),
        Some((id, prog)) if !own_progs.contains(&prog) => Err(format!(
            "link {id} runs program {prog}, not one of the agent's"
        )),
        Some(_) => Ok(()),
    }
}

/// The `link_*` entries under `pin_root`, each opened (`OBJ_GET`) and read
/// from `/proc/self/fdinfo` like [`own_link_ids`] does, split by owner
/// ([`link_pin_owner`]). Names that do not fit the key are skipped with a
/// WARN — none of ours is that long.
fn link_pins(pin_root: Option<&Path>, own_progs: &HashSet<u32>) -> LinkPins {
    let mut out = LinkPins::default();
    let Some(root) = pin_root else {
        return out;
    };
    let entries = match std::fs::read_dir(root) {
        Ok(e) => e,
        Err(e) => {
            warn!(error = %e, path = %root.display(), "BPF self-defence: cannot list the pin root — link pins not registered by name");
            return out;
        }
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with(LINK_PIN_PREFIX) {
            continue;
        }
        let link = obj_get_fd(&entry.path()).and_then(|fd| link_from_fdinfo(fd.as_raw_fd()));
        if let Err(why) = link_pin_owner(link, own_progs) {
            out.foreign
                .push(format!("{}: {why}", entry.path().display()));
            continue;
        }
        match pin_name_key(name) {
            Some(k) => out.own.push(k),
            None => warn!(
                name,
                "BPF self-defence: link pin name too long for OWN_PIN_NAMES — not registered"
            ),
        }
    }
    out
}

impl BpfGuard {
    /// One signed `integrity_drift` ([`FOREIGN_PIN_KIND`]) per `link_*` entry
    /// of the pin root found at boot that is not one of the agent's links (a
    /// stale pin of an earlier build, or one a root planted). Called by the
    /// start once the audit log is open.
    pub fn attest_foreign_pins(&self, audit_log: Option<&Arc<parking_lot::Mutex<AuditLog>>>) {
        let foreign = std::mem::take(&mut *self.0.foreign_pins.lock());
        if foreign.is_empty() {
            return;
        }
        error!(
            count = foreign.len(),
            "INTEGRITY DRIFT — link_* entries in the agent's pin root that are not its links \
         (not registered as its own, not removed)"
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
                        "{detail} — a link_* entry in the pin root that is not the agent's: not \
                         registered as its own, not removed"
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
fn map_data(m: &Map) -> &MapData {
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
    /// 64-entry `OWN_PIN_NAMES` and refuse the start.
    #[test]
    fn foreign_link_pin_is_not_registered() {
        let own: HashSet<u32> = [7u32, 9].into_iter().collect();
        assert_eq!(link_pin_owner(Some((3, 7)), &own), Ok(()));
        assert!(link_pin_owner(None, &own)
            .unwrap_err()
            .contains("not a BPF link"));
        assert!(link_pin_owner(Some((3, 0)), &own)
            .unwrap_err()
            .contains("detached"));
        assert!(link_pin_owner(Some((3, 8)), &own)
            .unwrap_err()
            .contains("program 8, not one of the agent's"));

        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("link_x"), "").unwrap();
        std::fs::create_dir(root.path().join("link_dir")).unwrap();
        std::fs::write(root.path().join("prog_task_kill"), "").unwrap();
        for i in 0..70 {
            std::fs::write(root.path().join(format!("link_planted_{i}")), "").unwrap();
        }
        let pins = link_pins(Some(root.path()), &own);
        assert!(pins.own.is_empty(), "no planted name is registered");
        assert_eq!(pins.foreign.len(), 72, "{:?}", pins.foreign);
        assert!(pins
            .foreign
            .iter()
            .any(|f| f.contains("link_x: not a BPF link")));
        assert!(!pins.foreign.iter().any(|f| f.contains("prog_task_kill")));
        assert!(link_pins(None, &own).foreign.is_empty());
    }

    #[test]
    fn fdinfo_parser_reads_link_and_prog_ids() {
        let text = "pos:\t0\nflags:\t02000002\nmnt_id:\t15\nino:\t1058\nlink_type:\ttracing\nlink_id:\t557\nprog_tag:\tdeadbeef\nprog_id:\t781\n";
        assert_eq!(parse_link_fdinfo(text), Some((557, 781)));
        // detached link: prog_id 0
        assert_eq!(
            parse_link_fdinfo("link_id:\t5\nprog_id:\t0\n"),
            Some((5, 0))
        );
        // not a link
        assert_eq!(parse_link_fdinfo("pos:\t0\nflags:\t02\n"), None);
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
        let body = render_own_prog_ids(4242, &[(17, "task_kill"), (305, "protected_open_deny")]);
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
}
