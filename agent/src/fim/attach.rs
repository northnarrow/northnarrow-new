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

use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use antitamper_bpf::attach_transient;
use anyhow::{anyhow, Context, Result};
use aya::maps::{ring_buf::RingBuf, HashMap as AyaHashMap, MapData};
use aya::{Btf, Ebpf};
use common::wire::InodeKey;
use tracing::{info, warn};

use crate::fim::drain::InodePathMap;

/// The six FIM observe programs, paired with their LSM hook
/// names. Names match the `#[lsm(hook = "...")]` attributes in
/// `agent-ebpf/src/fim_watch.rs`. Order is the operator-visible
/// boot-log order; rearranging would scramble the journald
/// `anti-tamper FS: …` lines that operators grep for in
/// `docs/integration-test-runbook.md`.
pub const FIM_OBSERVE_PROGRAMS: &[(&str, &str)] = &[
    ("fim_setattr_observe", "inode_setattr"),
    ("fim_create_observe", "inode_create"),
    ("fim_unlink_observe", "inode_unlink"),
    ("fim_rename_observe", "inode_rename"),
    ("fim_link_observe", "inode_link"),
    ("fim_file_open_observe", "file_open"),
];

/// BPF map name for the pinned `WATCHED_PATHS` HashMap. Matches
/// the `agent-ebpf/src/fim_watch.rs::WATCHED_PATHS` static.
pub const WATCHED_PATHS_MAP: &str = "WATCHED_PATHS";

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
fn stat_dev_to_kernel_dev(st_dev: u64) -> u64 {
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

/// Attach the six FIM observe programs via [`attach_transient`].
/// Each program is loaded against its hook (the BTF lookup
/// produces the verifier-required type info) and attached;
/// failures of any one program are logged WARN and skipped —
/// the other five still fire. A complete attach failure (no
/// BTF, no LSM in kernel) leaves the FIM module functionally
/// disabled but the agent still runs (paths watched but no
/// kernel events to drain). Mirrors the
/// `anti_tamper::attach`'s degrade-not-fail posture.
pub fn attach_observe_programs(ebpf: &mut Ebpf, btf: &Btf) -> Result<usize> {
    let mut attached = 0usize;
    for (program, hook) in FIM_OBSERVE_PROGRAMS {
        match attach_transient(ebpf, program, hook, btf) {
            Ok(()) => {
                info!(
                    program,
                    hook, "fim: LSM observe program attached (transient — re-attaches on restart)"
                );
                attached += 1;
            }
            Err(e) => {
                warn!(
                    error = %e,
                    program,
                    hook,
                    "fim: LSM observe program attach FAILED — this hook will not fire"
                );
            }
        }
    }
    info!(
        attached,
        total = FIM_OBSERVE_PROGRAMS.len(),
        "fim: LSM observe-program attach complete"
    );
    Ok(attached)
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
    for path in paths {
        let meta = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Curated list inevitably names paths not present
                // on every deploy — debug-log + skip.
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
        let key = InodeKey {
            dev: stat_dev_to_kernel_dev(meta.dev()),
            ino: meta.ino(),
        };
        match hmap.insert(AyaInodeKey(key), 1u8, 0) {
            Ok(()) => {
                inserted += 1;
                inode_map.insert(key, path.to_string_lossy().into_owned());
            }
            Err(e) => {
                warn!(
                    error = %e,
                    path = %path.display(),
                    "fim populate_watched_paths: WATCHED_PATHS insert failed — skip"
                );
                skipped += 1;
            }
        }
    }
    info!(
        inserted,
        skipped,
        configured = paths.len(),
        "fim: WATCHED_PATHS populated"
    );
    Ok(inode_map)
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
}
