//! Tappa 9 C8 — userland wiring for the six FIM observe BPF
//! programs + the `WATCHED_PATHS` map + the `FS_FIM_EVENTS`
//! ringbuf.
//!
//! Closes the C7 deferral: at C7 the programs were built into the
//! eBPF object and the WATCHED_PATHS map existed as a pinned
//! HashMap, but nothing attached the programs or populated the
//! map. C8 hooks them up.
//!
//! Design choices:
//!
//! - **Transient attach (no bpffs pin).** The anti-tamper deny
//!   hooks pin so a brief agent-restart window can't drop
//!   protection. FIM observe programs only EMIT events — they
//!   never -EPERM — so a restart-window gap is purely a missed
//!   telemetry window. Reattaching is fast (~10 ms per program)
//!   and avoids the per-hook pin-path collision with the deny
//!   programs sharing `inode_setattr` / `inode_unlink` /
//!   `inode_rename` (the anti-tamper deny path uses the same
//!   `(prog_<hook>, link_<hook>)` pin scheme).
//! - **Map name lookup, not take.** `WATCHED_PATHS` stays inside
//!   the `Ebpf` object via `map_mut` so the kernel-side BPF
//!   programs can keep reading it. The runtime population (stat
//!   each watched path → InodeKey → HashMap.insert) happens
//!   once at boot — operator-driven additions via
//!   `nn-admin fim baseline` go through the recompute task,
//!   which updates the InodePathMap; re-populating
//!   `WATCHED_PATHS` itself is a Tappa-9-followup.
//! - **Take the ringbuf.** `FS_FIM_EVENTS` is moved out of the
//!   `Ebpf` object into the drain task's `AsyncFd<RingBuf>` —
//!   exclusive ownership matches the existing sensor-pump
//!   pattern (`multiplexer::take_ringbuf`).

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use antitamper_bpf::attach_transient;
use anyhow::{anyhow, Context, Result};
use aya::maps::{ring_buf::RingBuf, HashMap as AyaHashMap, MapData};
use aya::{Btf, Ebpf};
use common::wire::InodeKey;
use tracing::{info, warn};

use crate::fim::drain::{InodePathMap, WatchClass};

/// The FIM observe programs, paired with their LSM hook
/// names. Names match the `#[lsm(hook = "...")]` attributes in
/// `agent-ebpf/src/fim_watch.rs`. Order is the operator-visible
/// boot-log order; rearranging would scramble the journald
/// `anti-tamper FS: …` lines that operators grep for in
/// `docs/integration-test-runbook.md`. The BUG-023 write-then-close
/// pair (`file_permission` + `file_free_security`) is APPENDED so the
/// original six keep their boot-log positions.
pub const FIM_OBSERVE_PROGRAMS: &[(&str, &str)] = &[
    ("fim_setattr_observe", "inode_setattr"),
    ("fim_create_observe", "inode_create"),
    ("fim_unlink_observe", "inode_unlink"),
    ("fim_rename_observe", "inode_rename"),
    ("fim_link_observe", "inode_link"),
    ("fim_file_open_observe", "file_open"),
    ("fim_write_intent_observe", "file_permission"),
    ("fim_close_emit_observe", "file_free_security"),
    // Tappa 10.9 step 1: invalidates the file-open sensor's directory
    // cache (agent-ebpf/src/open_sensor.rs); idle until the sensor is armed.
    ("open_sensor_rmdir", "inode_rmdir"),
    // Review 86: a file capability set (`security.capability`), reported
    // through the file-open sensor; idle until the sensor is armed.
    ("fim_file_cap_observe", "inode_post_setxattr"),
];

/// The `file_open` observer variant that also runs the Tappa 10.9 file-open
/// sensor (`agent-ebpf/src/fim_watch.rs`).
pub const OPEN_SENSOR_PROGRAM: &str = "fim_file_open_sensor";

/// BPF map name for the pinned `WATCHED_PATHS` HashMap. Matches
/// the `agent-ebpf/src/fim_watch.rs::WATCHED_PATHS` static.
pub const WATCHED_PATHS_MAP: &str = "WATCHED_PATHS";

/// Capacity of `WATCHED_PATHS`: `WATCHED_PATHS_MAX_ENTRIES` in
/// `agent-ebpf/src/fim_watch.rs` (kept equal by hand — the eBPF crate is
/// `no_std` and shares no constant with this one).
pub const WATCHED_PATHS_CAPACITY: usize = 8192;

/// BPF ringbuf name for the kernel→userland drift event channel.
/// Matches the `agent-ebpf/src/fim_watch.rs::FS_FIM_EVENTS`
/// static.
pub const FS_FIM_EVENTS_MAP: &str = "FS_FIM_EVENTS";

/// Convert the userland-encoded `dev_t` returned by `stat(2)` /
/// `MetadataExt::dev()` back into the kernel-internal `MKDEV`
/// form. Mirrors
/// [`crate::anti_tamper::filesystem::stat_dev_to_kernel_dev`]
/// (private there — duplicated here so the FIM module doesn't
/// reach into anti-tamper internals).
pub fn stat_dev_to_kernel_dev(st_dev: u64) -> u64 {
    let major = libc::major(st_dev) as u64;
    let minor = libc::minor(st_dev) as u64;
    (major << 20) | minor
}

/// Aya `Pod` wrapper for `InodeKey`. Same pattern as
/// `crate::anti_tamper::filesystem::AyaInodeKey` — orphan rule
/// prevents the agent crate from implementing aya's `Pod` for
/// the foreign `common::wire::InodeKey` type.
#[repr(transparent)]
#[derive(Copy, Clone)]
struct AyaInodeKey(InodeKey);

// SAFETY: InodeKey is `#[repr(C)]` over two u64s with no padding;
// AyaInodeKey is `#[repr(transparent)]` over it.
unsafe impl aya::Pod for AyaInodeKey {}

/// The whole error chain, with a long verifier log trimmed to its last
/// lines: the rejection reason is always at the end, and a soft WARN
/// that showed only the outer context ("verifier rejected `…`") left
/// the 5.15 lab guest without any way to see why.
fn chain_tail(e: &anyhow::Error) -> String {
    const KEEP: usize = 30;
    let full = format!("{e:#}");
    let lines: Vec<&str> = full.lines().collect();
    if lines.len() <= KEEP {
        return full;
    }
    let skipped = lines.len() - KEEP;
    format!(
        "… [{skipped} verifier lines elided]\n{}",
        lines[skipped..].join("\n")
    )
}

/// External audit FIMP-011: what the FIM cannot see this boot, in a
/// sentence for the signed audit chain; `None` when it sees what it was
/// configured to. No observer attached (a kernel without `bpf` in its
/// `lsm=` list, no BTF) or an empty watch set from a non-empty list means
/// no file change is seen at all; some observers missing means some kinds
/// of change are not.
pub fn coverage_shortfall(
    attached: usize,
    programs: usize,
    watched: usize,
    configured: usize,
) -> Option<String> {
    if attached == 0 {
        return Some(format!(
            "fim: 0/{programs} observe programs attached — no file change is seen this boot"
        ));
    }
    if watched == 0 && configured > 0 {
        return Some(format!(
            "fim: none of the {configured} configured paths could be watched — no file \
             change is seen this boot"
        ));
    }
    (attached < programs).then(|| {
        format!(
            "fim: {attached}/{programs} observe programs attached — some kinds of file \
             change are not seen this boot"
        )
    })
}

/// Attach the six FIM observe programs via [`attach_transient`].
/// Each program is loaded against its hook (the BTF lookup
/// produces the verifier-required type info) and attached;
/// failures of any one program are logged WARN and skipped —
/// the other five still fire. A complete attach failure (no
/// BTF, no LSM in kernel) leaves the FIM module functionally
/// disabled but the agent still runs (paths watched but no
/// kernel events to drain). Mirrors the
/// `anti_tamper::attach`'s degrade-not-fail posture.
pub fn attach_observe_programs(
    ebpf: &mut Ebpf,
    btf: &Btf,
    open_sensor: bool,
) -> Result<Vec<&'static str>> {
    let mut attached = Vec::new();
    for (program, hook) in FIM_OBSERVE_PROGRAMS {
        // Tappa 10.9 step 1: the file_open observer with the file-open
        // sensor, when wanted; the plain observer if the verifier refuses
        // it, so FIM never depends on the sensor.
        if open_sensor && *program == "fim_file_open_observe" {
            match attach_transient(ebpf, OPEN_SENSOR_PROGRAM, hook, btf) {
                Ok(()) => {
                    info!(
                        program = OPEN_SENSOR_PROGRAM,
                        hook, "fim: file_open observer with the file-open sensor attached"
                    );
                    attached.push(OPEN_SENSOR_PROGRAM);
                    continue;
                }
                Err(e) => warn!(
                    error = %chain_tail(&e),
                    "fim: the file_open observer with the file-open sensor was refused — \
                     attaching the plain observer (the agent stays on sys_enter_openat)"
                ),
            }
        }
        // Lab PR 164: the setattr observer reads the dentry at the position
        // the running kernel's prototype gives; unknown position, not
        // attached (the coverage shortfall is attested at boot).
        if let Some(Err(why)) = crate::anti_tamper::btf_revalidate::hook_attach_gate(hook) {
            warn!(
                program, hook, reason = %why,
                "fim: LSM observe program NOT attached — the dentry's position in the hook's \
                 prototype is unknown (chmod / chown / truncate of watched files are not seen)"
            );
            continue;
        }
        match attach_transient(ebpf, program, hook, btf) {
            Ok(()) => {
                info!(
                    program,
                    hook, "fim: LSM observe program attached (transient — re-attaches on restart)"
                );
                attached.push(*program);
            }
            Err(e) => {
                warn!(
                    error = %chain_tail(&e),
                    program,
                    hook,
                    "fim: LSM observe program attach FAILED — this hook will not fire"
                );
            }
        }
    }
    info!(
        attached = attached.len(),
        total = FIM_OBSERVE_PROGRAMS.len(),
        "fim: LSM observe-program attach complete"
    );
    Ok(attached)
}

/// Mount points that `ProtectHome=` masks. With `ProtectHome=yes`
/// systemd mounts an empty (and, in the strict variant, inaccessible)
/// tmpfs over each of these inside the service's mount namespace, so a
/// credential file beneath one is invisible to the agent's `stat(2)`
/// even though it exists on the host — the exact failure that left the
/// NN-L-FIM-011.. credential-read rules silently dead until the unit
/// switched to `ProtectHome=read-only`.
const PROTECTHOME_MASK_ROOTS: &[&str] = &["/root", "/home", "/run/user"];

/// If `path` lives *under* a `ProtectHome=`-masked root, return that
/// root. Lets the populate loop tell "credential file genuinely absent
/// on this host" (parent visible) apart from "credential file hidden
/// by the service mount namespace" (parent present-but-empty). Uses
/// component-wise `starts_with`, so `/rootkit` is not under `/root`.
fn protecthome_mask_root(path: &Path) -> Option<&'static Path> {
    for r in PROTECTHOME_MASK_ROOTS {
        let root = Path::new(*r);
        if path != root && path.starts_with(root) {
            return Some(root);
        }
    }
    None
}

/// Heuristic: does `root` look like a `ProtectHome=` mask rather than
/// the real host directory? The masking tmpfs is empty (or, for the
/// inaccessible variant, unreadable), so a present-but-empty or
/// permission-denied `read_dir` is the signature. A real, populated
/// /root or /home returns >= 1 entry → not hidden; a root that does not
/// exist at all → not hidden (genuine). Biased toward reporting hidden:
/// a genuinely-empty real /root would false-positive, but there the
/// credential files don't exist anyway and "check ProtectHome" is a
/// cheap rule-out — far better than re-introducing a silent hole.
fn mask_root_looks_hidden(root: &Path) -> bool {
    match std::fs::read_dir(root) {
        Ok(mut entries) => entries.next().is_none(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => true,
    }
}

/// Stat each path in `paths` and insert its `(kernel_dev, ino)`
/// into the pinned `WATCHED_PATHS` HashMap so the kernel-side
/// BPF programs can fast-skip non-watched inodes. Also populates
/// a fresh [`InodePathMap`] (userland (dev,ino) → path resolver)
/// that the drain loop consults to turn `FimDriftRaw` events
/// back into absolute paths.
///
/// Missing paths are WARN-logged and skipped — a curated
/// fim-paths.v1 list will inevitably name files that don't
/// exist on every deploy (`/usr/sbin/init` on a system that
/// uses `/sbin/init`, etc.). Per-path stat errors don't
/// derail the boot.
///
/// Returns the populated [`InodePathMap`] for sharing with the
/// drain loop + admin-socket status snapshot.
pub fn populate_watched_paths(
    ebpf: &mut Ebpf,
    paths: &BTreeSet<PathBuf>,
) -> Result<Arc<InodePathMap>> {
    let inode_map = Arc::new(InodePathMap::new());
    let map = ebpf
        .map_mut(WATCHED_PATHS_MAP)
        .ok_or_else(|| anyhow!("map {WATCHED_PATHS_MAP} missing from eBPF object"))?;
    let mut hmap: AyaHashMap<&mut MapData, AyaInodeKey, u8> = AyaHashMap::try_from(map)
        .with_context(|| format!("{WATCHED_PATHS_MAP} is not a HashMap<InodeKey, u8>"))?;

    let mut inserted = 0usize;
    let mut skipped = 0usize;
    let mut chain_entries = 0usize;
    let mut registered: std::collections::HashSet<InodeKey> = std::collections::HashSet::new();
    // Credential-coverage accounting for the regression guard below.
    // `cred_*` count ONLY paths under a ProtectHome-maskable home root
    // (/root, /home, /run/user) — i.e. the credential set (NN-L-FIM-011..)
    // that the `ProtectHome=yes` mount-namespace bug silently zeroed out.
    let mut cred_total = 0usize;
    let mut cred_watched = 0usize;
    let mut cred_masked = 0usize;
    let mut masked_example: Option<String> = None;
    // Probe each mask root at most once instead of re-stat'ing /root for
    // all ~17 of its credential children.
    let mut mask_root_hidden: BTreeMap<PathBuf, bool> = BTreeMap::new();
    for path in paths {
        let mask_root = protecthome_mask_root(path);
        if mask_root.is_some() {
            cred_total += 1;
        }
        let plan = match plan_path_watches(path) {
            Ok(p) => p,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // A genuinely-absent path on a curated list is normal
                // (debug) — the list names files not present on every
                // deploy. BUT if this is a credential path and its home
                // root is present-but-empty/inaccessible, the file is
                // almost certainly hidden by the service mount namespace
                // (ProtectHome) rather than truly missing — a SILENT
                // coverage hole. Tally those for the WARN after the loop.
                if let Some(root) = mask_root {
                    let hidden = *mask_root_hidden
                        .entry(root.to_path_buf())
                        .or_insert_with(|| mask_root_looks_hidden(root));
                    if hidden {
                        cred_masked += 1;
                        if masked_example.is_none() {
                            masked_example = Some(path.to_string_lossy().into_owned());
                        }
                    }
                }
                tracing::debug!(
                    path = %path.display(),
                    "fim populate_watched_paths: path absent on this host — skip"
                );
                skipped += 1;
                continue;
            }
            Err(e) => {
                warn!(
                    error = %e,
                    path = %path.display(),
                    "fim populate_watched_paths: stat failed — skip"
                );
                skipped += 1;
                continue;
            }
        };
        let key = plan.own;
        let path_str = path.to_string_lossy().into_owned();
        match hmap.insert(AyaInodeKey(key), 1u8, 0) {
            Ok(()) => {
                inserted += 1;
                registered.insert(key);
                if mask_root.is_some() {
                    cred_watched += 1;
                }
                inode_map.insert(key, path_str.clone());
                // External audit EBPF-016: a watch on overlayfs, FUSE or NFS
                // goes into the boot's signed identity record.
                crate::fs_type::note_identity(path);
            }
            Err(e) => {
                warn!(
                    error = %e,
                    path = %path.display(),
                    "fim populate_watched_paths: WATCHED_PATHS insert failed — skip"
                );
                skipped += 1;
                continue;
            }
        }
        // External audit NN-AUD-122 (FIMP-010): behind a symlink, each
        // further link and the final target are watched too, named by the
        // configured path — an in-place change of `python3.12`, or a
        // re-pointed `/etc/alternatives/nc`, touched no watched inode.
        if let Some(e) = &plan.chain_error {
            warn!(path = %path.display(), error = %e, "fim: the symlink chain behind a watched path is not followed");
        }
        let mut hops = Vec::new();
        for (hop, hop_key) in &plan.hops {
            match hmap.insert(AyaInodeKey(*hop_key), 1u8, 0) {
                Ok(()) => {
                    registered.insert(*hop_key);
                    inode_map.insert_as(*hop_key, path_str.clone(), WatchClass::ChainHop);
                    hops.push(*hop_key);
                    chain_entries += 1;
                    crate::fs_type::note_identity(hop);
                }
                Err(e) => warn!(
                    error = %e,
                    path = %nn_model::log_escape::Escaped(path.display()),
                    hop = %nn_model::log_escape::Escaped(hop.display()),
                    "fim populate_watched_paths: WATCHED_PATHS insert of a symlink hop failed"
                ),
            }
        }
        if !plan.hops.is_empty() || plan.broken {
            inode_map.set_chain(&path_str, hops);
        }
        if plan.broken {
            crate::fim::drain::await_chain_repair(&inode_map, &path_str);
        }
    }
    // Review 57: WATCHED_PATHS is pinned and outlives the agent. A child a
    // previous run enrolled (BUG-022) and that was deleted since keeps its
    // inode number watched, and the filesystem hands that number to
    // unrelated files: their writes reached the FIM rules under the deleted
    // path (a compiler's temporary file was killed as a "cron drop-in").
    // Keep only what this boot registers.
    let stale: Vec<AyaInodeKey> = hmap
        .keys()
        .filter_map(|k| k.ok())
        .filter(|k| !registered.contains(&k.0))
        .collect();
    for k in &stale {
        let _ = hmap.remove(k);
    }
    info!(
        inserted,
        chain_entries,
        skipped,
        stale_removed = stale.len(),
        configured = paths.len(),
        credentials_watched = cred_watched,
        credentials_total = cred_total,
        "fim: WATCHED_PATHS populated"
    );
    // Regression guard (silent-FIM screamer). A File Integrity Monitor
    // that watches NOTHING must scream, not whisper at debug. If any
    // credential path is unwatched *specifically* because its home root
    // is masked by the mount namespace, emit a single WARN naming the
    // most likely cause. This is distinct from genuine absence (parent
    // visible → stays debug above): it only fires on the hidden-parent
    // signature. After the `ProtectHome=read-only` fix the real home
    // dirs are visible, `cred_masked` is 0, and this stays quiet.
    if cred_masked > 0 {
        let cred_unwatched = cred_total.saturating_sub(cred_watched);
        warn!(
            credential_paths_total = cred_total,
            credential_paths_unwatched = cred_unwatched,
            masked_by_namespace = cred_masked,
            example = %masked_example.as_deref().unwrap_or("<unknown>"),
            "FIM credential coverage degraded: {}/{} credential paths unwatched \
             ({} with hidden-parent signature) — check ProtectHome/mount namespace. \
             ProtectHome=yes mounts /home,/root,/run/user as an empty tmpfs inside \
             this service's namespace, so credential stat()s return ENOENT, the \
             inodes never enter WATCHED_PATHS, and the NN-L-FIM-011.. credential-read \
             rules get no input and fire nothing",
            cred_unwatched,
            cred_total,
            cred_masked,
        );
    }
    Ok(inode_map)
}

/// External audit NN-AUD-122 (FIMP-010): what is watched for a configured
/// path that exists — its own inode and, behind a symlink, each further link
/// and the final target ([`crate::fim::baseline::symlink_chain`]), all
/// named by the configured path so a change there is compared with that
/// path's content row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathWatchPlan {
    /// The path's own inode (`lstat`: the link itself for a symlink).
    pub own: InodeKey,
    /// The links and the final target behind it, those that exist.
    pub hops: Vec<(PathBuf, InodeKey)>,
    /// The final target is missing: watched again once it is there.
    pub broken: bool,
    /// Why the chain was not followed (a loop, too many links).
    pub chain_error: Option<String>,
}

/// Plan the watches of `path` ([`PathWatchPlan`]). `Err` when the path
/// itself cannot be `lstat`ed.
pub fn plan_path_watches(path: &Path) -> std::io::Result<PathWatchPlan> {
    let meta = std::fs::symlink_metadata(path)?;
    let mut plan = PathWatchPlan {
        own: InodeKey {
            dev: stat_dev_to_kernel_dev(meta.dev()),
            ino: meta.ino(),
        },
        hops: Vec::new(),
        broken: false,
        chain_error: None,
    };
    if !meta.file_type().is_symlink() {
        return Ok(plan);
    }
    match crate::fim::baseline::symlink_chain(path) {
        Ok(chain) => {
            for hop in chain {
                match key_for_path(&hop) {
                    Ok(k) => plan.hops.push((hop, k)),
                    Err(_) => plan.broken = true,
                }
            }
        }
        Err(e) => plan.chain_error = Some(format!("{e:#}")),
    }
    Ok(plan)
}

/// Take ownership of the `FS_FIM_EVENTS` ringbuf out of the
/// `Ebpf` object so the drain task can wrap it in `AsyncFd` and
/// own the poll loop. After this call the map is no longer
/// reachable via `ebpf.map(...)` — the drain task is the only
/// reader for the lifetime of the agent. Mirrors
/// [`crate::sensors::multiplexer::take_ringbuf`].
pub fn take_fs_fim_events_ringbuf(ebpf: &mut Ebpf) -> Result<RingBuf<MapData>> {
    let map = ebpf
        .take_map(FS_FIM_EVENTS_MAP)
        .ok_or_else(|| anyhow!("ringbuf map `{FS_FIM_EVENTS_MAP}` missing from eBPF object"))?;
    RingBuf::try_from(map)
        .map_err(|e| anyhow!("expected `{FS_FIM_EVENTS_MAP}` to be a RINGBUF: {e}"))
}

/// Owned writable handle to the `WATCHED_PATHS` HashMap for runtime
/// child enrollment (Tappa 9 / BUG-022). Wrap in `Arc<Mutex<_>>` to
/// share with the drain loop — inserts are rare (only on a real drop
/// into a watched directory), so a coarse mutex is fine.
pub struct WatchedPathsHandle {
    map: WatchedPathsBacking,
}

enum WatchedPathsBacking {
    Kernel(AyaHashMap<MapData, AyaInodeKey, u8>),
    /// A kernel map stand-in with the same full-map refusal, for tests.
    #[cfg(any(test, feature = "test-util"))]
    Fake {
        keys: std::collections::HashSet<InodeKey>,
        capacity: usize,
    },
}

impl WatchedPathsHandle {
    /// Enroll an inode into `WATCHED_PATHS` so the kernel observe
    /// programs start watching it directly. Returns `true` on success
    /// (or already-present), `false` if the insert failed — almost
    /// always the [`WATCHED_PATHS_CAPACITY`] cap. External audit
    /// NN-AUD-120: callers go through [`crate::fim::drain::watch_inode`],
    /// which makes room by evicting runtime children and reports a
    /// refusal.
    pub fn enroll(&mut self, key: InodeKey) -> bool {
        match &mut self.map {
            WatchedPathsBacking::Kernel(m) => m.insert(AyaInodeKey(key), 1u8, 0).is_ok(),
            #[cfg(any(test, feature = "test-util"))]
            WatchedPathsBacking::Fake { keys, capacity } => {
                keys.contains(&key) || (keys.len() < *capacity && keys.insert(key))
            }
        }
    }

    /// Stop watching an inode whose file is gone (review 57).
    pub fn unenroll(&mut self, key: InodeKey) {
        match &mut self.map {
            WatchedPathsBacking::Kernel(m) => {
                let _ = m.remove(&AyaInodeKey(key));
            }
            #[cfg(any(test, feature = "test-util"))]
            WatchedPathsBacking::Fake { keys, .. } => {
                keys.remove(&key);
            }
        }
    }

    /// A stand-in for the kernel map holding at most `capacity` inodes.
    #[cfg(any(test, feature = "test-util"))]
    pub fn fake(capacity: usize) -> Self {
        Self {
            map: WatchedPathsBacking::Fake {
                keys: std::collections::HashSet::new(),
                capacity,
            },
        }
    }

    /// Whether the stand-in holds `key`.
    #[cfg(test)]
    pub(crate) fn holds(&self, key: &InodeKey) -> bool {
        match &self.map {
            WatchedPathsBacking::Fake { keys, .. } => keys.contains(key),
            WatchedPathsBacking::Kernel(_) => false,
        }
    }
}

/// External audit DEC-001: the drain's view of what is watched — the
/// inode→path map it resolves events with, and the kernel's
/// `WATCHED_PATHS` — for watches added at runtime. File canaries are
/// watched through it: the kernel emitted nothing for a decoy outside the
/// FIM path list, and the drain would have dropped an event for an inode
/// it could not name.
#[derive(Clone)]
pub struct FimWatch {
    pub path_map: std::sync::Arc<crate::fim::drain::InodePathMap>,
    pub watched_paths: Option<std::sync::Arc<parking_lot::Mutex<WatchedPathsHandle>>>,
}

impl FimWatch {
    /// No kernel map behind it (tests, or a boot without one).
    pub fn detached() -> Self {
        Self {
            path_map: std::sync::Arc::new(crate::fim::drain::InodePathMap::new()),
            watched_paths: None,
        }
    }

    /// Watch inode `key` as `path` of `class`. `false` when the kernel
    /// map refused it (full of what is never evicted, or absent): the
    /// kernel will not report it. External audit NN-AUD-120: a full map
    /// makes room by evicting the oldest runtime child, and a refusal is
    /// an ERROR and a signed `subsystem_degraded`.
    pub fn watch(&self, key: InodeKey, path: &str, class: WatchClass) -> bool {
        match &self.watched_paths {
            Some(wp) => crate::fim::drain::watch_inode(key, path, class, &self.path_map, Some(wp)),
            None => {
                let _ = self.path_map.insert_as(key, path.to_string(), class);
                false
            }
        }
    }

    /// Stop watching inode `key`.
    pub fn unwatch(&self, key: InodeKey) {
        self.path_map.remove(&key);
        if let Some(wp) = &self.watched_paths {
            wp.lock().unenroll(key);
        }
    }
}

/// Take an OWNED writable handle to the pinned `WATCHED_PATHS` map out
/// of the `Ebpf` object (call AFTER [`populate_watched_paths`]) so the
/// drain loop can enroll children of a watched directory on the fly —
/// a dropped `.ko`/`.service`/`.so` becomes individually watched, so a
/// later in-place edit is caught by the BUG-023 write-then-close hook.
/// Same `take_map` pattern as [`take_fs_fim_events_ringbuf`]: the map
/// is pinned, so the kernel-side observe programs keep reading it after
/// the userland handle moves out of `Ebpf`.
pub fn take_watched_paths_map(ebpf: &mut Ebpf) -> Result<WatchedPathsHandle> {
    let map = ebpf
        .take_map(WATCHED_PATHS_MAP)
        .ok_or_else(|| anyhow!("map `{WATCHED_PATHS_MAP}` missing from eBPF object"))?;
    let hmap = AyaHashMap::<MapData, AyaInodeKey, u8>::try_from(map)
        .with_context(|| format!("{WATCHED_PATHS_MAP} is not a HashMap<InodeKey, u8>"))?;
    Ok(WatchedPathsHandle {
        map: WatchedPathsBacking::Kernel(hmap),
    })
}

/// Tappa 9 C8 — diagnostic helper. Stat a candidate path and
/// return its kernel-form `InodeKey` for cross-checking against
/// `WATCHED_PATHS` map dumps. Used in privileged e2e tests.
pub fn key_for_path(path: &Path) -> Result<InodeKey> {
    let meta = std::fs::symlink_metadata(path)
        .with_context(|| format!("symlink_metadata({})", path.display()))?;
    Ok(InodeKey {
        dev: stat_dev_to_kernel_dev(meta.dev()),
        ino: meta.ino(),
    })
}

#[cfg(test)]
mod tests {
    use super::coverage_shortfall;

    /// External audit FIMP-011.
    #[test]
    fn a_fim_that_sees_nothing_says_so() {
        assert!(coverage_shortfall(0, 10, 0, 125)
            .unwrap()
            .contains("0/10 observe programs"));
        assert!(coverage_shortfall(10, 10, 0, 125)
            .unwrap()
            .contains("none of the 125 configured paths"));
        assert!(coverage_shortfall(7, 10, 90, 125).unwrap().contains("7/10"));
        assert_eq!(coverage_shortfall(10, 10, 90, 125), None);
        // an empty list was attested where it was loaded (FIMR-001)
        assert_eq!(coverage_shortfall(10, 10, 0, 0), None);
    }

    use super::*;

    /// C8 test: the 6-program list is anchored — order matters for
    /// the boot-log lines an operator greps for. A reorder ALSO
    /// shouldn't happen by accident because the kernel attaches
    /// hooks in this order on first agent boot.
    #[test]
    fn fim_observe_programs_match_design_table() {
        let expected: &[(&str, &str)] = &[
            ("fim_setattr_observe", "inode_setattr"),
            ("fim_create_observe", "inode_create"),
            ("fim_unlink_observe", "inode_unlink"),
            ("fim_rename_observe", "inode_rename"),
            ("fim_link_observe", "inode_link"),
            ("fim_file_open_observe", "file_open"),
            ("fim_write_intent_observe", "file_permission"),
            ("fim_close_emit_observe", "file_free_security"),
            ("open_sensor_rmdir", "inode_rmdir"),
            ("fim_file_cap_observe", "inode_post_setxattr"),
        ];
        assert_eq!(FIM_OBSERVE_PROGRAMS, expected);
    }

    /// C8 test: `key_for_path` recovers the same `InodeKey`
    /// the population loop derives, so a privileged e2e can
    /// stat a tempfile and assert the resulting key is in
    /// `WATCHED_PATHS` (the kernel-form `dev` is what the BPF
    /// program looks up against).
    #[test]
    fn key_for_path_round_trips_inode_key() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let k1 = key_for_path(tmp.path()).unwrap();
        let k2 = key_for_path(tmp.path()).unwrap();
        assert_eq!(k1, k2);
        // dev should be non-zero on any real filesystem (tmpfs +
        // ext4 + zfs all have non-zero superblock dev numbers).
        assert!(k1.dev != 0);
        assert!(k1.ino != 0);
    }

    /// External audit NN-AUD-122 (FIMP-010): a symlinked configured path
    /// is watched by its own inode, each further link and the final target;
    /// a regular file by its own inode only; a broken chain says so.
    #[test]
    fn populate_plan_enrolls_each_hop_and_target() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        std::fs::create_dir(d.join("alternatives")).unwrap();
        std::fs::write(d.join("nc.openbsd"), b"ELF").unwrap();
        std::os::unix::fs::symlink(d.join("nc.openbsd"), d.join("alternatives/nc")).unwrap();
        std::os::unix::fs::symlink(d.join("alternatives/nc"), d.join("nc")).unwrap();
        let plan = plan_path_watches(&d.join("nc")).unwrap();
        assert_eq!(
            plan.own,
            key_for_path(&d.join("nc")).unwrap(),
            "the link itself"
        );
        assert_eq!(
            plan.hops,
            vec![
                (
                    d.join("alternatives/nc"),
                    key_for_path(&d.join("alternatives/nc")).unwrap()
                ),
                (
                    d.join("nc.openbsd"),
                    key_for_path(&d.join("nc.openbsd")).unwrap()
                ),
            ]
        );
        assert!(!plan.broken && plan.chain_error.is_none());
        let regular = plan_path_watches(&d.join("nc.openbsd")).unwrap();
        assert!(regular.hops.is_empty() && !regular.broken);
        std::os::unix::fs::symlink(d.join("gone"), d.join("dangling")).unwrap();
        let broken = plan_path_watches(&d.join("dangling")).unwrap();
        assert!(broken.hops.is_empty() && broken.broken);
        assert_eq!(
            plan_path_watches(&d.join("absent")).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
    }

    /// External audit NN-AUD-120 (FIMP-008): a decoy finds room in a full
    /// watch map by evicting a runtime child, and is refused — which the
    /// canary deploy reports — only when nothing can be evicted, or there
    /// is no kernel map.
    #[test]
    fn a_decoy_watch_is_refused_only_when_nothing_can_make_room() {
        let watch = FimWatch {
            path_map: Arc::new(InodePathMap::with_child_cap(8)),
            watched_paths: Some(Arc::new(parking_lot::Mutex::new(WatchedPathsHandle::fake(
                2,
            )))),
        };
        let k = |ino| InodeKey { dev: 1, ino };
        assert!(watch.watch(k(1), "/etc/passwd", WatchClass::Configured));
        assert!(crate::fim::drain::watch_inode(
            k(2),
            "/etc/cron.d/x",
            WatchClass::RuntimeChild,
            &watch.path_map,
            watch.watched_paths.as_deref(),
        ));
        assert!(
            watch.watch(k(3), "/home/u/decoy", WatchClass::Decoy),
            "the child makes room"
        );
        assert!(watch.path_map.lookup(&k(2)).is_none());
        assert!(
            !watch.watch(k(4), "/home/u/decoy2", WatchClass::Decoy),
            "nothing left to evict"
        );
        assert!(
            !FimWatch::detached().watch(k(5), "/home/u/decoy3", WatchClass::Decoy),
            "no kernel map"
        );
    }

    /// Regression guard: the credential classifier must flag exactly
    /// the ProtectHome-maskable home paths and nothing else — counting
    /// /etc or /var/lib paths would dilute the "credential coverage"
    /// signal, and missing /root/.aws would re-hide the original bug.
    #[test]
    fn protecthome_mask_root_classifies_home_paths() {
        let cred = |p: &str| protecthome_mask_root(Path::new(p));
        // Under a masked root → Some(root).
        assert_eq!(cred("/root/.aws/credentials"), Some(Path::new("/root")));
        assert_eq!(
            cred("/home/alice/.config/gcloud/credentials.db"),
            Some(Path::new("/home"))
        );
        assert_eq!(cred("/run/user/1000/keyring"), Some(Path::new("/run/user")));
        // Not under a masked root → None. These FIM paths keep working
        // under ProtectHome=yes and must NOT count as credential
        // coverage (else the WARN's N/M denominator is wrong).
        assert_eq!(cred("/etc/passwd"), None);
        assert_eq!(cred("/var/lib/docker/credentials.json"), None);
        // The root itself is not "under" it, and the prefix is
        // component-wise so /rootkit is not mistaken for /root.
        assert_eq!(cred("/root"), None);
        assert_eq!(cred("/rootkit/evil"), None);
    }

    /// Regression guard: the namespace-masking signature must separate
    /// "empty/inaccessible (looks like a ProtectHome tmpfs)" from both
    /// "populated real dir" and "absent" — the WARN-vs-debug decision
    /// hinges on this.
    #[test]
    fn mask_root_looks_hidden_distinguishes_empty_from_populated() {
        // Absent root → not hidden (genuine absence, not masking).
        assert!(!mask_root_looks_hidden(Path::new(
            "/nonexistent-northnarrow-test-root"
        )));
        // Empty dir → looks like the ProtectHome empty-tmpfs mask.
        let empty = tempfile::tempdir().unwrap();
        assert!(mask_root_looks_hidden(empty.path()));
        // Populated dir (a real /root or /home has entries) → not
        // hidden; this is the state the read-only fix restores.
        let populated = tempfile::tempdir().unwrap();
        std::fs::write(populated.path().join(".bash_history"), b"x").unwrap();
        assert!(!mask_root_looks_hidden(populated.path()));
    }
}
