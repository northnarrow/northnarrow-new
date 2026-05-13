//! Shared anti-tamper eBPF helpers for `northnarrow-agent` and
//! `northnarrow-watchdog`.
//!
//! The Tappa 7 task 6 design pins all anti-tamper kernel-side state
//! to bpffs at `/sys/fs/bpf/northnarrow/`, so the protective LSM
//! hooks keep firing across the gap between an agent process dying
//! and the watchdog respawning it. This crate is the single source
//! of truth for the pin/reuse logic, the multi-PID `PROTECTED_PIDS`
//! map manipulation, and the `/proc` validation that closes the
//! recycled-PID window on agent startup.
//!
//! ## Pinning model (verified against aya 0.13.1 source)
//!
//! There are four pinnable artifacts in aya 0.13; we use three.
//!
//! | Artifact | Aya API | Why we pin it |
//! |---|---|---|
//! | Map data | `EbpfLoader::map_pin_path(P)` | Map values (the PID set, the inode set) survive process death AND aya auto-reuses if `<P>/<MAP_NAME>` exists — built-in load-or-create. |
//! | LSM link | `FdLink::pin(P)` | **Operational keystone.** Doc: "the link will remain attached even after the link instance is dropped, and will only be detached once the pinned file is removed." This is what keeps the hook *firing* across process death — program loaded ≠ hook attached. |
//! | LSM program | `Lsm::pin(P)` | Belt-and-suspenders for admin recovery: lets a future process re-acquire a program handle via `Lsm::from_pin()` and re-attach if the pinned link has been removed. |
//!
//! Three distinct pin files exist per LSM hook under the bpffs root:
//!
//!   /sys/fs/bpf/northnarrow/
//!     ├── PROTECTED_PIDS         ← auto-pinned by map_pin_path
//!     ├── PROTECTED_INODES       ← auto-pinned by map_pin_path
//!     ├── KILL_OVERRIDE          ← auto-pinned by map_pin_path
//!     ├── PTRACE_OVERRIDE        ← auto-pinned by map_pin_path
//!     ├── FS_PROTECT_OVERRIDE    ← auto-pinned by map_pin_path
//!     ├── FS_PROTECT_EVENTS      ← auto-pinned by map_pin_path
//!     ├── prog_task_kill         ← Lsm::pin
//!     ├── link_task_kill         ← FdLink::pin   (this is the one that
//!     ├── prog_ptrace_check                       keeps the hook firing
//!     ├── link_ptrace_check                       in the death gap)
//!     ├── prog_inode_unlink
//!     ├── link_inode_unlink
//!     ├── … (one (prog, link) pair per hook)
//!
//! ## Stale pin recovery
//!
//! A crashed process can leave a pin file on disk that no longer
//! corresponds to a valid kernel object (e.g., bpffs was unmounted
//! and remounted, the kernel rebooted without /sys/fs/bpf cleanup,
//! the file was created on a non-bpffs filesystem by a bug). We
//! attempt `PinnedLink::from_pin` first; if it returns an error
//! we treat the pin file as garbage, unlink it, and fall through
//! to the fresh load+attach+pin path. This is the
//! "crashed-state pin files MUST NOT block agent startup"
//! contract.
//!
//! ## Recycled-PID window
//!
//! Pinning extends LSM coverage across process death — including
//! against the dying agent's own PID, which is now a stale entry
//! in `PROTECTED_PIDS`. Linux PID recycling can in principle
//! reassign that PID to an attacker process before the new agent
//! cleans up. The two-layer mitigation is:
//!
//!   1. **Agent startup** (this crate's
//!      [`AntiTamper::evict_stale_pids`]): walk the map, read
//!      `/proc/<pid>/comm` for each entry, evict mismatched.
//!   2. **Watchdog SIGCHLD** (commit #3): deterministic
//!      `bpf_map_delete_elem` at microsecond latency the moment
//!      the agent dies.
//!
//! Layer 1 ships in this commit; layer 2 in the next.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use aya::maps::{HashMap as AyaHashMap, MapData};
use aya::programs::links::PinnedLink;
use aya::programs::{Lsm, ProgramError};
use aya::{Btf, Ebpf, EbpfLoader};
use tracing::{debug, info, warn};

/// Default bpffs root for production. The agent and the watchdog
/// share this — both must agree or the pin reuse breaks.
pub const DEFAULT_BPFFS_ROOT: &str = "/sys/fs/bpf/northnarrow";

/// Name of the BPF map holding the protected PID set. Kept in sync
/// with `agent-ebpf/src/task_kill.rs::PROTECTED_PIDS`.
pub const PROTECTED_PIDS_MAP: &str = "PROTECTED_PIDS";

/// The 7 LSM hooks under anti-tamper coverage. Each entry is
/// `(program_name_in_elf, kernel_hook_name)`. Program names match
/// the `#[lsm(hook = "…")]` decorations in agent-ebpf; hook names
/// match the kernel's `bpf_lsm_<hook>` BTF symbols (validated by
/// the loader at attach time).
pub const LSM_HOOKS: &[(&str, &str)] = &[
    ("task_kill", "task_kill"),
    ("ptrace_access_check", "ptrace_access_check"),
    ("inode_unlink", "inode_unlink"),
    ("inode_rmdir", "inode_rmdir"),
    ("inode_rename", "inode_rename"),
    ("inode_setattr", "inode_setattr"),
    ("file_ioctl", "file_ioctl"),
];

/// Thin handle for the anti-tamper pin lifecycle. Intentionally
/// does NOT own the [`Ebpf`] instance — that lives inside the
/// agent's `SensorMultiplexer`, which is already the single-owner
/// of the loaded object. All methods take `&mut Ebpf` so this
/// handle can be cheaply cloned (or constructed per-call) by both
/// the agent and the watchdog without ownership friction.
///
/// In-memory `PinnedLink` instances are NOT tracked either — the
/// pin file on bpffs is the persistent source of truth; per
/// aya's docs, the in-process handle dropping does not detach the
/// link as long as the pin file exists. Letting them drop at
/// end-of-function keeps the API surface tiny.
#[derive(Debug, Clone)]
pub struct AntiTamper {
    bpffs_root: PathBuf,
}

impl AntiTamper {
    /// Build a handle pointing at `bpffs_root`. Creates the
    /// directory if it does not yet exist (does NOT mount bpffs —
    /// that is a host-config responsibility; see the runbook).
    /// Fails if the path exists and is not a directory.
    pub fn new(bpffs_root: PathBuf) -> Result<Self> {
        if bpffs_root.exists() {
            if !bpffs_root.is_dir() {
                return Err(anyhow!(
                    "{} exists and is not a directory",
                    bpffs_root.display()
                ));
            }
        } else {
            std::fs::create_dir_all(&bpffs_root)
                .with_context(|| format!("creating bpffs root {}", bpffs_root.display()))?;
        }
        Ok(Self { bpffs_root })
    }

    /// Mutate the supplied [`EbpfLoader`] so that all maps in the
    /// loaded object are auto-pinned to `<bpffs_root>/<MAP_NAME>`
    /// — and auto-reused on subsequent loads if the pin file
    /// already exists. This must be called BEFORE `loader.load()`.
    ///
    /// Returns `&mut EbpfLoader` so callers can keep chaining.
    pub fn configure_loader<'a, 'b>(
        &self,
        loader: &'a mut EbpfLoader<'b>,
    ) -> &'a mut EbpfLoader<'b> {
        loader.map_pin_path(&self.bpffs_root)
    }

    /// Path to the pinned link for `hook`. Stable across processes.
    pub fn link_pin_path(&self, hook: &str) -> PathBuf {
        self.bpffs_root.join(format!("link_{hook}"))
    }

    /// Path to the pinned program object for `hook`.
    pub fn program_pin_path(&self, hook: &str) -> PathBuf {
        self.bpffs_root.join(format!("prog_{hook}"))
    }

    /// For every entry in [`LSM_HOOKS`], attempt to reuse the
    /// pinned link from the previous agent generation. If the link
    /// pin file is missing or structurally invalid, fall through to
    /// a fresh load+attach+pin.
    ///
    /// Programs are pinned as a belt-and-suspenders independent
    /// of the link pin, so a future process can re-acquire the
    /// program via [`Lsm::from_pin`] for re-attach scenarios.
    ///
    /// Returns a per-hook [`HookAttachOutcome`] vector so the
    /// caller can log telemetry and (in the watchdog) decide
    /// whether to re-bootstrap.
    pub fn pin_or_attach_lsm_hooks(
        &self,
        ebpf: &mut Ebpf,
        btf: &Btf,
    ) -> Vec<(String, Result<HookAttachOutcome>)> {
        let mut out = Vec::with_capacity(LSM_HOOKS.len());
        for (program, hook) in LSM_HOOKS {
            let res = self.pin_or_attach_one(ebpf, btf, program, hook);
            out.push(((*hook).to_string(), res));
        }
        out
    }

    fn pin_or_attach_one(
        &self,
        ebpf: &mut Ebpf,
        btf: &Btf,
        program_name: &str,
        hook_name: &str,
    ) -> Result<HookAttachOutcome> {
        let link_path = self.link_pin_path(hook_name);
        let prog_path = self.program_pin_path(hook_name);

        // ── Phase 1: try to reuse an existing pinned link ──────────
        if link_path.exists() {
            match PinnedLink::from_pin(&link_path) {
                Ok(_link) => {
                    // PinnedLink drops here — pin file persists,
                    // kernel attachment persists.
                    debug!(
                        hook = hook_name,
                        path = %link_path.display(),
                        "anti-tamper: reused pinned LSM link"
                    );
                    return Ok(HookAttachOutcome::ReusedPin);
                }
                Err(e) => {
                    warn!(
                        hook = hook_name,
                        path = %link_path.display(),
                        error = ?e,
                        "anti-tamper: pinned link file present but unreadable — \
                         treating as stale, unlinking and re-attaching"
                    );
                    // Best-effort unlink. If the unlink itself fails,
                    // the subsequent `pin()` call will also fail and
                    // we'll surface that to the caller — at which
                    // point manual cleanup is the right escalation.
                    purge_stale_pin(&link_path);
                }
            }
        }

        // ── Phase 2: fresh load+attach+pin ─────────────────────────
        let prog: &mut Lsm = ebpf
            .program_mut(program_name)
            .ok_or_else(|| anyhow!("program {program_name} missing from eBPF object"))?
            .try_into()
            .with_context(|| format!("program {program_name} is not an LSM program"))?;

        prog.load(hook_name, btf)
            .with_context(|| format!("verifier rejected LSM program `{program_name}`"))?;

        let link_id = prog
            .attach()
            .with_context(|| format!("attaching `{program_name}` to LSM hook `{hook_name}`"))?;

        // Pin the program object first — even if link pinning fails
        // below, the program survives in the kernel and can be
        // re-attached by a future process.
        if let Err(e) = pin_program_if_absent(prog, &prog_path) {
            warn!(
                program = program_name,
                path = %prog_path.display(),
                error = ?e,
                "anti-tamper: program pin failed (continuing without it)"
            );
        }

        // Pin the link — this is the operational keystone.
        let owned_link = prog
            .take_link(link_id)
            .with_context(|| format!("taking ownership of link for `{program_name}`"))?;
        let fd_link: aya::programs::links::FdLink = owned_link.into();
        let _pinned: PinnedLink = fd_link.pin(&link_path).with_context(|| {
            format!(
                "pinning link for `{program_name}` at {}",
                link_path.display()
            )
        })?;
        debug!(
            hook = hook_name,
            link_path = %link_path.display(),
            prog_path = %prog_path.display(),
            "anti-tamper: LSM hook attached and pinned"
        );
        Ok(HookAttachOutcome::FreshlyAttached)
    }

    /// Insert each PID into `PROTECTED_PIDS`. `BPF_ANY` upsert
    /// semantics: an entry that already exists is overwritten, so
    /// re-registering after an eviction race is safe.
    pub fn register_pids(&self, ebpf: &mut Ebpf, pids: &[u32]) -> Result<()> {
        let mut hm = open_protected_pids(ebpf)?;
        for &pid in pids {
            hm.insert(pid, 1u8, 0)
                .with_context(|| format!("inserting PID {pid} into {PROTECTED_PIDS_MAP}"))?;
        }
        info!(
            pids = ?pids,
            map = PROTECTED_PIDS_MAP,
            "anti-tamper: PIDs registered"
        );
        Ok(())
    }

    /// Remove a single PID. Used by the watchdog's SIGCHLD handler
    /// (commit #3) to close the recycled-PID window at microsecond
    /// latency. Tolerates "key not present" as success (the map
    /// might have been cleared by a concurrent eviction).
    pub fn evict_pid(&self, ebpf: &mut Ebpf, pid: u32) -> Result<()> {
        let mut hm = open_protected_pids(ebpf)?;
        match hm.remove(&pid) {
            Ok(()) => {
                info!(pid, "anti-tamper: PID evicted from PROTECTED_PIDS");
                Ok(())
            }
            Err(e) if is_enoent(&e) => Ok(()),
            Err(e) => Err(anyhow!(e))
                .with_context(|| format!("removing PID {pid} from {PROTECTED_PIDS_MAP}")),
        }
    }

    /// Walk every entry in `PROTECTED_PIDS`. Evict any whose PID is
    /// dead OR whose `/proc/<pid>/comm` is not in `allowed_comms`.
    /// Returns the number of entries removed.
    pub fn evict_stale_pids(
        &self,
        ebpf: &mut Ebpf,
        allowed_comms: &HashSet<String>,
    ) -> Result<usize> {
        let mut hm = open_protected_pids(ebpf)?;
        let existing: Vec<u32> = hm.keys().filter_map(Result::ok).collect();
        let mut evicted = 0usize;
        for pid in existing {
            let alive_and_matching = match read_proc_comm(pid) {
                Some(comm) => allowed_comms.contains(&comm),
                None => false,
            };
            if alive_and_matching {
                continue;
            }
            match hm.remove(&pid) {
                Ok(()) => evicted += 1,
                Err(e) if is_enoent(&e) => {} // race-evicted by another caller
                Err(e) => warn!(
                    pid, error = ?e,
                    "anti-tamper: failed to evict stale PID (continuing)"
                ),
            }
        }
        Ok(evicted)
    }
}

/// Outcome of [`AntiTamper::pin_or_attach_lsm_hooks`] for a single
/// hook. The caller logs / aggregates these for telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookAttachOutcome {
    /// The pinned link from a previous generation was re-acquired;
    /// the LSM hook stayed firing across the process boundary.
    ReusedPin,
    /// No pin file (or unusable one); the program was freshly
    /// loaded, attached, and pinned.
    FreshlyAttached,
}

/// Read `/proc/self/comm`. Trailing newline stripped.
pub fn read_self_comm() -> Result<String> {
    let raw = std::fs::read_to_string("/proc/self/comm").context("reading /proc/self/comm")?;
    Ok(raw.trim_end_matches('\n').to_string())
}

/// Read `/proc/<pid>/comm`. Returns `None` for any read failure
/// (process gone, EACCES, etc.) so callers can treat absent and
/// inaccessible identically.
pub fn read_proc_comm(pid: u32) -> Option<String> {
    let path = format!("/proc/{pid}/comm");
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim_end_matches('\n').to_string())
}

/// Best-effort unlink of a stale pin file. Used when a recovered
/// pin path cannot be re-acquired and must be cleared before a
/// fresh `pin()` would succeed. Errors are logged but not
/// propagated — the pin attempt that follows will surface a
/// definitive error if recovery is impossible.
pub fn purge_stale_pin(path: &Path) {
    match std::fs::remove_file(path) {
        Ok(()) => debug!(path = %path.display(), "anti-tamper: stale pin file removed"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warn!(
            path = %path.display(),
            error = ?e,
            "anti-tamper: stale pin file removal failed (continuing)"
        ),
    }
}

// ── internals ───────────────────────────────────────────────────────

fn open_protected_pids(ebpf: &mut Ebpf) -> Result<AyaHashMap<&mut MapData, u32, u8>> {
    let map = ebpf
        .map_mut(PROTECTED_PIDS_MAP)
        .ok_or_else(|| anyhow!("map {PROTECTED_PIDS_MAP} missing from eBPF object"))?;
    AyaHashMap::try_from(map)
        .with_context(|| format!("{PROTECTED_PIDS_MAP} is not a HashMap<u32, u8>"))
}

/// `Lsm::pin` errors with `AlreadyExists` if the program was pinned
/// in a previous generation. We treat that as success — the pin file
/// is exactly what we wanted on disk.
fn pin_program_if_absent(prog: &mut Lsm, path: &Path) -> Result<(), ProgramError> {
    if path.exists() {
        return Ok(());
    }
    prog.pin(path)
        .map_err(|e| ProgramError::IOError(std::io::Error::other(e)))
}

/// Aya's map errors don't expose ENOENT cleanly; we string-match on
/// the underlying io::Error message. Brittle but contained.
fn is_enoent(e: &aya::maps::MapError) -> bool {
    format!("{e}").contains("No such file or directory") || format!("{e}").contains("ENOENT")
}

// ── tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn read_self_comm_returns_non_empty() {
        let c = read_self_comm().expect("read_self_comm should succeed");
        assert!(!c.is_empty());
        assert!(
            !c.ends_with('\n'),
            "trailing newline must be stripped: {c:?}"
        );
    }

    #[test]
    fn read_proc_comm_for_self_matches() {
        let mine = std::process::id();
        let via_self = read_self_comm().unwrap();
        let via_pid = read_proc_comm(mine).expect("must find own PID");
        assert_eq!(via_self, via_pid);
    }

    #[test]
    fn read_proc_comm_returns_none_for_impossibly_large_pid() {
        assert!(read_proc_comm(u32::MAX).is_none());
    }

    #[test]
    fn read_proc_comm_returns_none_for_pid_zero() {
        assert!(read_proc_comm(0).is_none());
    }

    #[test]
    fn antitamper_new_creates_dir_if_missing() {
        let parent = TempDir::new().unwrap();
        let bpffs = parent.path().join("northnarrow");
        assert!(!bpffs.exists());
        let _at = AntiTamper::new(bpffs.clone()).expect("new should succeed");
        assert!(bpffs.is_dir());
    }

    #[test]
    fn antitamper_new_accepts_existing_dir() {
        let dir = TempDir::new().unwrap();
        let _at = AntiTamper::new(dir.path().to_path_buf()).expect("existing dir is fine");
    }

    #[test]
    fn antitamper_new_rejects_existing_non_directory() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("notadir");
        std::fs::write(&file, b"oops").unwrap();
        let err = AntiTamper::new(file).unwrap_err();
        assert!(
            err.to_string().contains("not a directory"),
            "expected not-a-directory error, got: {err}"
        );
    }

    #[test]
    fn pin_paths_are_deterministic_and_distinct() {
        let dir = TempDir::new().unwrap();
        let at = AntiTamper::new(dir.path().to_path_buf()).unwrap();
        let lp = at.link_pin_path("task_kill");
        let pp = at.program_pin_path("task_kill");
        assert_eq!(lp, dir.path().join("link_task_kill"));
        assert_eq!(pp, dir.path().join("prog_task_kill"));
        assert_ne!(lp, pp);

        // Different hook → different paths.
        assert_ne!(lp, at.link_pin_path("ptrace_access_check"));
    }

    #[test]
    fn purge_stale_pin_removes_regular_file() {
        let dir = TempDir::new().unwrap();
        let stale = dir.path().join("link_task_kill");
        std::fs::write(&stale, b"this is not a real pin file").unwrap();
        assert!(stale.exists());
        purge_stale_pin(&stale);
        assert!(!stale.exists(), "purge_stale_pin must unlink the file");
    }

    #[test]
    fn purge_stale_pin_is_noop_when_file_missing() {
        let dir = TempDir::new().unwrap();
        let absent = dir.path().join("link_does_not_exist");
        // Must not panic, must not propagate an error.
        purge_stale_pin(&absent);
        assert!(!absent.exists());
    }

    /// Simulates the stale-pin-file recovery decision: a regular file
    /// at the pin path is NOT a valid bpffs pin, so PinnedLink::from_pin
    /// must fail; the code path must unlink + fall through. We can't
    /// drive the full attach without a real Ebpf instance + bpffs +
    /// root, but we CAN verify the file-purge half of the recovery
    /// (the half that determines whether commit #2 leaves the host in
    /// a working state if a prior crash left junk on disk).
    #[test]
    fn stale_pin_file_can_be_unlinked_for_recovery() {
        let dir = TempDir::new().unwrap();
        let at = AntiTamper::new(dir.path().to_path_buf()).unwrap();
        let stale = at.link_pin_path("inode_unlink");
        std::fs::write(&stale, b"corrupt").unwrap();

        // This is what pin_or_attach_one's stale-recovery arm does
        // when PinnedLink::from_pin returns Err: purge the file,
        // continue to fresh attach. We verify the purge step in
        // isolation; the fresh-attach half is covered by the
        // privileged e2e suite (commit #5 expansion).
        purge_stale_pin(&stale);
        assert!(!stale.exists());

        // After purge, the pin path is now "missing" → the same
        // helper recognises it as "must do fresh attach" because
        // `link_path.exists()` is false. No assertion to make in
        // isolation; the integration test covers it.
    }
}
