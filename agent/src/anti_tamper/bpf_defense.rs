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
/// Width of an `OWN_PIN_NAMES` key (mirrors `PIN_NAME_LEN` in the eBPF crate).
const PIN_NAME_LEN: usize = 32;
/// Prefix of the LSM link pins written by `antitamper_bpf::lsm_pin_paths`.
const LINK_PIN_PREFIX: &str = "link_";
/// Period of the link self-check.
pub const LINK_CHECK_SECS: u64 = 10;
/// Audit op of a missing link (one entry per link, at the first miss).
pub const LINK_MISSING_AUDIT_OP: &str = "bpf_link_missing";

/// What the self-check needs, recorded at boot and read by the task spawned
/// later from `main` (the audit log does not exist yet when the hooks
/// attach).
#[derive(Debug, Clone)]
struct OwnLinks {
    ids: Vec<u32>,
    pin_root: Option<PathBuf>,
}

static OWN_LINKS: OnceLock<OwnLinks> = OnceLock::new();

/// `BPF_OBJ_GET` command number (uapi, stable).
const BPF_OBJ_GET_CMD: libc::c_long = 7;

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

/// Fill `OWN_BPF_IDS` with the ids of every map and program of this object
/// and arm the mode. Call once every program is loaded (after the
/// anti-tamper hooks), so the set is complete.
pub(crate) fn register_own_objects(ebpf: &mut Ebpf, pin_root: Option<&Path>) -> Result<OwnObjects> {
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
    let _ = OWN_LINKS.set(OwnLinks {
        ids: link_ids.clone(),
        pin_root: pin_root.map(Path::to_path_buf),
    });
    // Pin names: the final component of every `link_*` pin under the pin
    // root, so `OBJ_GET` on a pinned link is recognised without a path
    // walk in the kernel.
    let pin_names = link_pin_names(pin_root);
    {
        let names = ebpf
            .map_mut(PIN_NAMES_MAP)
            .with_context(|| format!("{PIN_NAMES_MAP} missing from the eBPF object"))?;
        let mut names: HashMap<&mut MapData, [u8; PIN_NAME_LEN], u8> =
            HashMap::try_from(names).context("OWN_PIN_NAMES is not a HashMap<[u8; 32], u8>")?;
        for key in &pin_names {
            names
                .insert(key, KIND_LINK, 0)
                .context("registering own link pin name")?;
        }
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
            BPF_OBJ_GET_CMD,
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

/// NUL-padded keys for the `link_*` pins under `pin_root` (names that do
/// not fit the key are skipped with a WARN — none of ours is that long).
fn link_pin_names(pin_root: Option<&Path>) -> Vec<[u8; PIN_NAME_LEN]> {
    let Some(root) = pin_root else {
        return Vec::new();
    };
    let entries = match std::fs::read_dir(root) {
        Ok(e) => e,
        Err(e) => {
            warn!(error = %e, path = %root.display(), "BPF self-defence: cannot list the pin root — link pins not registered by name");
            return Vec::new();
        }
    };
    let mut keys = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with(LINK_PIN_PREFIX) {
            continue;
        }
        match pin_name_key(name) {
            Some(k) => keys.push(k),
            None => warn!(
                name,
                "BPF self-defence: link pin name too long for OWN_PIN_NAMES — not registered"
            ),
        }
    }
    keys
}

/// The fixed-width key the kernel computes for the final path component.
fn pin_name_key(name: &str) -> Option<[u8; PIN_NAME_LEN]> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() >= PIN_NAME_LEN {
        return None;
    }
    let mut key = [0u8; PIN_NAME_LEN];
    key[..bytes.len()].copy_from_slice(bytes);
    Some(key)
}

/// Periodic proof that the agent's own links are still attached: every
/// link registered at boot must still be reachable (held fd or pin) with a
/// non-zero program. A link that is gone while the agent is alive was
/// unpinned or detached from outside (observe mode, a bypass of the pin
/// protection): ERROR in the journal and one signed audit entry per link.
/// Spawned from `main` once the audit log exists.
pub fn spawn_link_self_check(audit_log: Option<Arc<parking_lot::Mutex<AuditLog>>>) {
    let Some(own) = OWN_LINKS.get().cloned() else {
        return;
    };
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
            let live: HashSet<u32> = live_links(own.pin_root.as_deref())
                .into_iter()
                .filter(|(_, prog)| *prog != 0)
                .map(|(id, _)| id)
                .collect();
            for id in &ids {
                if live.contains(id) || !reported.insert(*id) {
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn pin_name_key_pads_and_rejects_long_names() {
        let k = pin_name_key("link_task_kill").unwrap();
        assert_eq!(&k[..14], b"link_task_kill");
        assert!(k[14..].iter().all(|b| *b == 0));
        assert!(pin_name_key("").is_none());
        assert!(pin_name_key(&"x".repeat(PIN_NAME_LEN)).is_none());
        assert!(pin_name_key(&"x".repeat(PIN_NAME_LEN - 1)).is_some());
    }
}
