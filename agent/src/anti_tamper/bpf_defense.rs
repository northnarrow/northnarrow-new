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
use std::path::Path;
use tracing::{info, warn};

/// Set to `1` to run the map guard in observe mode (log, never deny).
pub const OBSERVE_ENV: &str = "NN_BPF_DEFENSE_OBSERVE";
/// Set to `1` to ENFORCE even in a `debug-trigger` build (lab tests of the deny path).
pub const ENFORCE_ENV: &str = "NN_BPF_DEFENSE_ENFORCE";

pub const GUARD_PROGRAM: &str = "bpf_map_guard";
pub const GUARD_HOOK: &str = "bpf_map";
pub const OBSERVE_PROGRAM: &str = "bpf_syscall_observe";
pub const OBSERVE_HOOK: &str = "bpf";

const OWN_IDS_MAP: &str = "OWN_BPF_IDS";
const OWN_EXE_MAP: &str = "OWN_EXE_INODES";
const MODE_MAP: &str = "BPF_DEFENSE_MODE";
const KIND_MAP: u8 = 1;
const KIND_PROG: u8 = 2;

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

/// Attach both hooks (deny + observe). Errors are reported to the caller's
/// health accounting, not returned: the anti-tamper health decides the
/// fail-closed outcome.
pub(crate) fn attach(ebpf: &mut Ebpf, btf: &Btf, pin_root: Option<&Path>) -> BpfDefenseHealth {
    let mut health = BpfDefenseHealth::default();
    match antitamper_bpf::reattach_fresh(ebpf, GUARD_PROGRAM, GUARD_HOOK, btf, pin_root) {
        Ok(()) => info!(
            program = GUARD_PROGRAM,
            hook = GUARD_HOOK,
            "BPF self-defence: map guard attached"
        ),
        Err(e) => {
            warn!(program = GUARD_PROGRAM, hook = GUARD_HOOK, error = %e, "BPF self-defence: map guard attach FAILED — the agent's maps are writable by root");
            health.deny_failures.push((GUARD_PROGRAM, format!("{e:#}")));
        }
    }
    match antitamper_bpf::attach_transient(ebpf, OBSERVE_PROGRAM, OBSERVE_HOOK, btf) {
        Ok(()) => info!(
            program = OBSERVE_PROGRAM,
            hook = OBSERVE_HOOK,
            "BPF self-defence: bpf() syscall observer attached"
        ),
        Err(e) => {
            warn!(program = OBSERVE_PROGRAM, hook = OBSERVE_HOOK, error = %e, "BPF self-defence: bpf() observer attach FAILED — foreign BPF activity not reported");
            health
                .observe_failures
                .push((OBSERVE_PROGRAM, format!("{e:#}")));
        }
    }
    health
}

/// Fill `OWN_BPF_IDS` with the ids of every map and program of this object
/// and arm the mode. Call once every program is loaded (after the
/// anti-tamper hooks), so the set is complete.
pub(crate) fn register_own_objects(ebpf: &mut Ebpf) -> Result<(usize, usize, bool)> {
    let mut map_ids: Vec<u32> = Vec::new();
    for (_, map) in ebpf.maps() {
        if let Ok(info) = map_data(map).info() {
            map_ids.push(info.id());
        }
    }
    let mut prog_ids: Vec<u32> = Vec::new();
    for (_, prog) in ebpf.programs() {
        if let Ok(info) = prog.info() {
            prog_ids.push(info.id());
        }
    }
    let own = ebpf
        .map_mut(OWN_IDS_MAP)
        .with_context(|| format!("{OWN_IDS_MAP} missing from the eBPF object"))?;
    let mut own: HashMap<&mut MapData, u32, u8> =
        HashMap::try_from(own).context("OWN_BPF_IDS is not a HashMap<u32, u8>")?;
    for id in &map_ids {
        own.insert(id, KIND_MAP, 0)
            .with_context(|| format!("registering own map id {id}"))?;
    }
    for id in &prog_ids {
        own.insert(id, KIND_PROG, 0)
            .with_context(|| format!("registering own program id {id}"))?;
    }
    // The agent's own binaries: this executable plus its siblings in the
    // same directory (watchdog, nn-admin). Registered by (dev, ino) so the
    // watchdog's self-registration write passes before it is a protected
    // pid; a copy elsewhere has another inode and stays foreign.
    let mut exe_keys: Vec<common::wire::InodeKey> = Vec::new();
    if let Ok(own) = std::env::current_exe().and_then(|p| p.canonicalize()) {
        let dir = own.parent().map(Path::to_path_buf);
        let mut paths = vec![own];
        if let Some(d) = dir {
            paths.push(d.join("northnarrow-watchdog"));
            paths.push(d.join("nn-admin"));
        }
        for path in paths {
            if let Ok(meta) = std::fs::metadata(&path) {
                use std::os::unix::fs::MetadataExt;
                exe_keys.push(common::wire::InodeKey {
                    dev: crate::anti_tamper::filesystem::stat_dev_to_kernel_dev(meta.dev()),
                    ino: meta.ino(),
                });
            }
        }
    }
    {
        let exe_map = ebpf
            .map_mut(OWN_EXE_MAP)
            .with_context(|| format!("{OWN_EXE_MAP} missing from the eBPF object"))?;
        let mut exe_map: HashMap<&mut MapData, crate::anti_tamper::filesystem::AyaInodeKey, u8> =
            HashMap::try_from(exe_map).context("OWN_EXE_INODES is not a HashMap<InodeKey, u8>")?;
        for k in &exe_keys {
            exe_map
                .insert(crate::anti_tamper::filesystem::AyaInodeKey(*k), 1u8, 0)
                .with_context(|| format!("registering own exe inode {}:{}", k.dev, k.ino))?;
        }
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
        exe_inodes = exe_keys.len(),
        mode = if enforce { "enforce" } else { "observe" },
        "BPF self-defence: own objects registered — foreign write handles on the agent's maps are {}",
        if enforce { "DENIED" } else { "observed only (debug-trigger build or NN_BPF_DEFENSE_OBSERVE=1)" }
    );
    Ok((map_ids.len(), prog_ids.len(), enforce))
}

/// The `MapData` behind any `Map` variant (aya 0.13 exposes `info()` on
/// `MapData` only).
fn map_data(m: &Map) -> &MapData {
    match m {
        Map::Array(d)
        | Map::BloomFilter(d)
        | Map::CpuMap(d)
        | Map::DevMap(d)
        | Map::DevMapHash(d)
        | Map::HashMap(d)
        | Map::LpmTrie(d)
        | Map::LruHashMap(d)
        | Map::PerCpuArray(d)
        | Map::PerCpuHashMap(d)
        | Map::PerCpuLruHashMap(d)
        | Map::PerfEventArray(d)
        | Map::ProgramArray(d)
        | Map::Queue(d)
        | Map::RingBuf(d)
        | Map::SockHash(d)
        | Map::SockMap(d)
        | Map::Stack(d)
        | Map::StackTraceMap(d)
        | Map::Unsupported(d)
        | Map::XskMap(d) => d,
    }
}
