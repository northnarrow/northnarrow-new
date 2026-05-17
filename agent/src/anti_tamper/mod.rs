//! Userland half of the Tappa 7 anti-tamper kernel hooks.
//!
//! The kernel-side `task_kill` and `ptrace_access_check` LSM programs
//! (in `agent-ebpf/src/`) consult the [`PROTECTED_PIDS`] hash map and
//! return `-EPERM` to any caller — including `root` — whose target
//! `tgid` is present. This module is the userland half: at agent
//! startup it registers the agent's PID (and in Tappa 7 task 6 also
//! the watchdog's PID) into that map and attaches both LSM programs.
//!
//! ## Design notes
//!
//! - All LSM programs and anti-tamper maps (`PROTECTED_PIDS`,
//!   `KILL_OVERRIDE`, `PTRACE_OVERRIDE`, `PROTECTED_INODES`,
//!   `FS_PROTECT_OVERRIDE`, `FS_PROTECT_EVENTS`) live in the same
//!   eBPF object as the sensors. Loading that object twice would
//!   create two independent kernel copies of `PROTECTED_PIDS`, only
//!   one of which the in-kernel hooks would read, so attaching
//!   happens on the same [`Ebpf`] instance owned by
//!   [`SensorMultiplexer`].
//! - Per-hook failures are logged at WARN and tolerated. The hooks
//!   require `CONFIG_BPF_LSM=y` plus `bpf` in the kernel's runtime
//!   `lsm=` chain (see `docs/TAPPA7_PREREQ.md`); on a machine that
//!   doesn't have those, the agent still has to run with sensors
//!   active so we don't hard-fail.
//! - The map write happens *before* the attach calls so any time
//!   window in which the hook fires sees the protected set already
//!   populated.
//! - Stale-entry eviction: before registering new PIDs we walk the
//!   existing map and remove entries whose PID either no longer
//!   exists or whose `/proc/<pid>/comm` doesn't match the expected
//!   process name. This matters once eBPF programs and maps get
//!   pinned to bpffs (Tappa 7 task 6 commit #2) — a pinned map
//!   carries the dead agent's PID across the death/respawn gap,
//!   and an attacker who lands a process at the recycled PID
//!   would inherit LSM protection. Eviction closes that window
//!   on agent startup; the watchdog's `bpf_map_delete_elem` on
//!   SIGCHLD closes it during the death itself.

pub mod admin_auth;
pub mod filesystem;
pub mod network_isolate;

/// Test-only mint of an [`network_isolate::UnlockToken`] for unit
/// tests that exercise code paths consuming the capability (e.g.
/// `posture::admin_release_combat_with_token`). The production
/// capability invariant is unaffected — this helper is only
/// compiled under `cfg(test)`.
#[cfg(test)]
pub(crate) fn _test_mint_unlock_token() -> network_isolate::UnlockToken {
    network_isolate::mint_unlock_token()
}

use std::collections::HashSet;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use aya::{
    maps::{HashMap as AyaHashMap, MapData},
    programs::{
        links::{FdLink, PinnedLink},
        Lsm,
    },
    Btf, Ebpf,
};
use tracing::{info, warn};

/// Single bpffs directory holding every pinned anti-tamper object.
/// Commit #2 pins the six anti-tamper maps here; commit #2b adds the
/// seven LSM programs + links. One self-contained namespace lets the
/// watchdog and `nn-admin` enumerate the pinned set by listing it,
/// and keeps `EbpfLoader::map_pin_path` (maps) and the future
/// `FdLink::pin` (links) sharing one root.
pub const DEFAULT_BPFFS_ROOT: &str = "/sys/fs/bpf/northnarrow";

/// `statfs(2)` magic for a BPF filesystem mount (`uapi/linux/magic.h`
/// `BPF_FS_MAGIC`). Used to fail *soft* with an actionable message
/// when `/sys/fs/bpf` isn't a bpffs mount, rather than letting aya
/// surface an opaque `BPF_OBJ_PIN` errno from deep inside `load()`.
const BPF_FS_MAGIC: i64 = 0xcafe_4a11;

/// Mode for [`DEFAULT_BPFFS_ROOT`]. `0700`: only root may list or
/// unlink the pins. This matters beyond hygiene — in commit #2b an
/// unprivileged `unlink` of a pinned *link* would detach a live LSM
/// hook, and even in commit #2 unlinking a pinned *map* re-opens the
/// split-brain on the next agent restart.
const PIN_ROOT_MODE: u32 = 0o700;

// TODO(Tappa 8): the three override arrays — KILL_OVERRIDE,
// PTRACE_OVERRIDE, FS_PROTECT_OVERRIDE — are now `pinned` by-name
// (commit #2), so slot 0 now SURVIVES an agent restart. They are
// shipped empty and never written in Tappa 7, so this is inert
// today. When Tappa 8 wires the Ed25519 verifier that writes a
// capability token into slot 0, it MUST zero that slot on agent
// boot (`MapData::insert(0, &0, 0)`) before trusting it, or a
// pre-restart grant would silently outlive its window. No zeroing
// is added here in commit #2: it would be dead code with no
// Tappa-7 caller and is out of this commit's scope.

/// Prepare the bpffs pin directory and return the path to hand to
/// [`aya::EbpfLoader::map_pin_path`]. Returns `None` when bpffs is
/// unavailable: the caller then loads the eBPF object WITHOUT
/// pinning so the sensor half of the agent still runs (anti-tamper
/// cross-restart persistence is forfeited until the host gains a
/// bpffs mount). This mirrors the warn-and-continue stance the rest
/// of anti-tamper takes — losing persistence must not cost the
/// operator their telemetry.
pub fn prepare_pin_root() -> Option<&'static Path> {
    let root = Path::new(DEFAULT_BPFFS_ROOT);
    let mount = root.parent().unwrap_or_else(|| Path::new("/sys/fs/bpf"));

    if !is_bpffs(mount) {
        warn!(
            path = %mount.display(),
            "anti-tamper: {} is not a bpffs mount — anti-tamper maps will NOT \
             persist across restart (split-brain risk on respawn). Mount it: \
             `mount -t bpf bpf /sys/fs/bpf`. Continuing with sensors only.",
            mount.display()
        );
        return None;
    }

    match std::fs::DirBuilder::new()
        .mode(PIN_ROOT_MODE)
        .recursive(true)
        .create(root)
    {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => {
            warn!(
                error = %e, path = %root.display(),
                "anti-tamper: could not create bpffs pin dir — continuing \
                 unpinned (sensors only, no anti-tamper persistence)"
            );
            return None;
        }
    }

    // Re-assert mode unconditionally: a pre-existing dir from an
    // older build (or a loosened one) must not keep wider perms.
    // No chown — bpffs inodes are kernel-owned root:root and we
    // already required root to get this far.
    if let Ok(meta) = std::fs::metadata(root) {
        if (meta.permissions().mode() & 0o7777) != PIN_ROOT_MODE {
            if let Err(e) =
                std::fs::set_permissions(root, std::fs::Permissions::from_mode(PIN_ROOT_MODE))
            {
                warn!(
                    error = %e, path = %root.display(),
                    "anti-tamper: could not chmod 0700 the bpffs pin dir \
                     (pins still created; dir perms wider than intended)"
                );
            }
        }
    }

    Some(root)
}

/// `true` iff `p` resides on a bpffs mount. A `statfs` failure or a
/// non-bpffs magic both return `false` — the caller treats either as
/// "pinning unavailable" and degrades gracefully.
fn is_bpffs(p: &Path) -> bool {
    let Ok(c_path) = std::ffi::CString::new(p.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `c_path` is a valid NUL-terminated path; `s` is a
    // fully-owned `statfs` out-param the kernel initialises on
    // success. We only read `f_type` and only when the call
    // returned 0.
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c_path.as_ptr(), &mut s) } != 0 {
        return false;
    }
    s.f_type as i64 == BPF_FS_MAGIC
}

/// Names mirroring `#[map]` / `#[lsm(hook = "…")]` declarations in
/// `agent-ebpf/src/{task_kill,ptrace_check}.rs`. Kept here as
/// constants because aya looks them up by string at runtime.
const PROTECTED_PIDS_MAP: &str = "PROTECTED_PIDS";
const TASK_KILL_PROGRAM: &str = "task_kill";
const TASK_KILL_HOOK: &str = "task_kill";
const PTRACE_PROGRAM: &str = "ptrace_access_check";
const PTRACE_HOOK: &str = "ptrace_access_check";

/// Populate `PROTECTED_PIDS` and attach the two Tappa 7 LSM hooks.
///
/// A failure populating the map is fatal: the hooks would otherwise
/// fail open and we'd silently lose anti-tamper. Failure attaching
/// either LSM hook is logged and tolerated so the agent can still
/// run on kernels without BPF-LSM in the boot `lsm=` chain.
///
/// `pids` is a slice so callers can register multiple PIDs in one
/// call (Tappa 7 task 6: agent + watchdog). Stale entries from a
/// prior pinned-map load are evicted first — every entry whose PID
/// is dead or whose `/proc/<pid>/comm` is not in `allowed_comms`
/// is removed before `pids` is inserted.
pub fn attach(ebpf: &mut Ebpf, pids: &[u32], allowed_comms: &HashSet<String>) -> Result<()> {
    match evict_stale_pids(ebpf, allowed_comms) {
        Ok(0) => {}
        Ok(n) => info!(
            evicted = n,
            "anti-tamper: stale PIDs evicted from PROTECTED_PIDS"
        ),
        Err(e) => warn!(
            error = %e,
            "anti-tamper: stale-PID eviction failed, continuing (any leftover entries \
             will be overwritten by the registration step)"
        ),
    }
    register_protected_pids(ebpf, pids).context("populating PROTECTED_PIDS before LSM attach")?;
    info!(
        pids = ?pids,
        map = PROTECTED_PIDS_MAP,
        "anti-tamper: PIDs registered with kernel"
    );

    // `Btf::from_sys_fs()` reads `/sys/kernel/btf/vmlinux`. The Lsm
    // loader resolves `bpf_lsm_<hook>` against it to set the
    // `attach_btf_id` the kernel expects. If we can't read vmlinux
    // BTF, neither hook can attach — log once and skip both rather
    // than warning twice for the same root cause.
    let btf = match Btf::from_sys_fs() {
        Ok(b) => b,
        Err(e) => {
            warn!(
                error = %e,
                "anti-tamper: vmlinux BTF unavailable, skipping LSM attach \
                 (kernel BPF-LSM disabled or CONFIG_DEBUG_INFO_BTF=n)"
            );
            return Ok(());
        }
    };

    // Commit #2b: the bpffs root that holds the prog/link pins. Same
    // root the multiplexer handed to `map_pin_path`; `prepare_pin_root`
    // is idempotent (dir already created) and silent on the happy
    // path, so re-deriving it here keeps the change inside
    // `anti_tamper/` without threading a new param through the
    // multiplexer. `None` (no bpffs) ⇒ transient attach, no
    // persistence — `attach_lsm` handles the degrade + log.
    let pin_root = prepare_pin_root();

    // On success `attach_lsm` logs the disposition (reused / freshly
    // attached / purged-then-attached) itself — the call sites only
    // escalate the *failure* case with its operator-facing severity.
    if let Err(e) = attach_lsm(ebpf, TASK_KILL_PROGRAM, TASK_KILL_HOOK, &btf, pin_root) {
        warn!(
            program = TASK_KILL_PROGRAM,
            hook = TASK_KILL_HOOK,
            error = %e,
            "anti-tamper: LSM hook attach FAILED — agent killable by root"
        );
    }

    if let Err(e) = attach_lsm(ebpf, PTRACE_PROGRAM, PTRACE_HOOK, &btf, pin_root) {
        warn!(
            program = PTRACE_PROGRAM,
            hook = PTRACE_HOOK,
            error = %e,
            "anti-tamper: LSM hook attach FAILED — agent inspectable by root"
        );
    }

    // Tappa 7 task 5: directory + inode protection. Failure to
    // bootstrap (no /var/lib, read-only rootfs, permission denied
    // even as root) is warn-and-continue: process-level anti-tamper
    // already attached above, so the agent isn't worthless without
    // FS protection.
    if let Err(e) = filesystem::attach(ebpf, &btf, pin_root) {
        warn!(error = %e, "anti-tamper FS: bootstrap failed, continuing without FS protection");
    }

    Ok(())
}

/// Insert each PID into `PROTECTED_PIDS`. `BPF_ANY` upsert
/// semantics: an entry that already exists is overwritten, so
/// re-registering the same PID after an eviction race is fine.
fn register_protected_pids(ebpf: &mut Ebpf, pids: &[u32]) -> Result<()> {
    let map = ebpf
        .map_mut(PROTECTED_PIDS_MAP)
        .ok_or_else(|| anyhow!("map {PROTECTED_PIDS_MAP} missing from eBPF object"))?;
    let mut hm: AyaHashMap<&mut MapData, u32, u8> = AyaHashMap::try_from(map)
        .with_context(|| format!("{PROTECTED_PIDS_MAP} is not a HashMap<u32, u8>"))?;
    for &pid in pids {
        hm.insert(pid, 1u8, 0)
            .with_context(|| format!("inserting PID {pid} into {PROTECTED_PIDS_MAP}"))?;
    }
    Ok(())
}

/// Walk every PID currently in `PROTECTED_PIDS`. Evict any entry
/// whose PID is dead OR whose `/proc/<pid>/comm` is not in
/// `allowed_comms`. Returns the number of entries removed.
///
/// This is a no-op on a freshly-loaded eBPF object (the map is
/// empty); it becomes load-bearing once Tappa 7 task 6 commit #2
/// pins the map to bpffs, at which point a restarted agent inherits
/// the prior generation's entries and must clean up stale ones
/// before the new PIDs take effect.
fn evict_stale_pids(ebpf: &mut Ebpf, allowed_comms: &HashSet<String>) -> Result<usize> {
    let map = ebpf
        .map_mut(PROTECTED_PIDS_MAP)
        .ok_or_else(|| anyhow!("map {PROTECTED_PIDS_MAP} missing from eBPF object"))?;
    let mut hm: AyaHashMap<&mut MapData, u32, u8> = AyaHashMap::try_from(map)
        .with_context(|| format!("{PROTECTED_PIDS_MAP} is not a HashMap<u32, u8>"))?;

    // Materialise the key set up-front; aya's `keys()` iterator
    // holds a borrow of the map, and we need `&mut hm` to call
    // `remove()`.
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
            Err(e) => warn!(
                pid, error = %e,
                "anti-tamper: failed to evict stale PID (continuing)"
            ),
        }
    }
    Ok(evicted)
}

/// Read `/proc/self/comm` and return it as an owned `String` with
/// the trailing newline stripped. Returns an error if the file is
/// missing or unreadable — both shouldn't happen for our own PID.
pub fn read_self_comm() -> Result<String> {
    let raw = std::fs::read_to_string("/proc/self/comm").context("reading /proc/self/comm")?;
    Ok(raw.trim_end_matches('\n').to_string())
}

/// Read `/proc/<pid>/comm` and return it as an owned `String`.
/// Returns `None` if the file does not exist (process gone) or
/// cannot be read for any other reason — callers treat both
/// outcomes as "this PID is no longer ours."
///
/// `comm` is the kernel-stamped 15-char-plus-NUL `TASK_COMM_LEN`
/// field, set on exec and updatable via `prctl(PR_SET_NAME)`. We
/// use it rather than `cmdline` because comm is the value the
/// kernel itself uses internally; cmdline can be rewritten via
/// `/proc/self/cmdline` write from userland. Neither defeats a
/// motivated attacker — comm is a sanity check for PID recycling
/// race, not a security primitive.
pub fn read_proc_comm(pid: u32) -> Option<String> {
    let path = format!("/proc/{pid}/comm");
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim_end_matches('\n').to_string())
}

/// bpffs pin paths for one LSM hook. Commit #2b keeps the path key
/// the **human-readable hook name** (`task_kill`,
/// `ptrace_access_check`, …) so an operator listing
/// [`DEFAULT_BPFFS_ROOT`] sees self-describing names. The kernel
/// truncates aya's program *name* (the Rust fn symbol) to 15 chars,
/// so e.g. `bpftool prog show name` reports `ptrace_access_c` — that
/// truncation is a *verification-harness* concern only; nothing here
/// or in `bpf_get_object` cares about the kernel prog name.
///
/// Two **separate** pins per hook, both required:
/// - `prog_<hook>` keeps the kernel *program* object loaded.
/// - `link_<hook>` keeps the *attachment* live — this is the one
///   that makes the hook keep **firing** across the agent
///   death→respawn gap. A pinned program with no pinned link is a
///   loaded-but-inert program; the link pin is the survivability
///   primitive (see `aya` `programs/links.rs` `FdLink::pin` /
///   `PinnedLink::from_pin`).
fn lsm_pin_paths(root: &Path, hook_name: &str) -> (PathBuf, PathBuf) {
    (
        root.join(format!("prog_{hook_name}")),
        root.join(format!("link_{hook_name}")),
    )
}

/// Best-effort unlink of a stale/crashed-state pin. A leftover pin
/// file whose backing kernel object is gone (or is corrupt on disk)
/// must never wedge agent startup: we remove it and fall through to
/// a fresh attach. `NotFound` is success (already gone).
fn purge_stale_pin(path: &Path) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warn!(
            error = %e, path = %path.display(),
            "anti-tamper: could not unlink stale pin (continuing to fresh attach)"
        ),
    }
}

/// Load → attach → pin-program → take-link → pin-link for one hook.
/// On success the kernel holds: the program (pinned at `prog_path`)
/// and its LSM attachment (pinned at `link_path`). The `PinnedLink`
/// is intentionally dropped at end of scope — that closes only the
/// agent's dup fd; the bpffs pin file retains the kernel reference,
/// so the hook keeps firing after this process exits. That is the
/// entire point of commit #2b.
fn fresh_attach_and_pin(
    ebpf: &mut Ebpf,
    program_name: &str,
    hook_name: &str,
    btf: &Btf,
    prog_path: &Path,
    link_path: &Path,
) -> Result<()> {
    let prog: &mut Lsm = ebpf
        .program_mut(program_name)
        .ok_or_else(|| anyhow!("program {program_name} missing from eBPF object"))?
        .try_into()
        .with_context(|| format!("program {program_name} is not an LSM program"))?;
    prog.load(hook_name, btf)
        .with_context(|| format!("verifier rejected LSM program `{program_name}`"))?;
    let link_id = prog
        .attach()
        .with_context(|| format!("attaching LSM program `{program_name}` to hook `{hook_name}`"))?;
    prog.pin(prog_path).with_context(|| {
        format!(
            "pinning LSM program `{program_name}` to {}",
            prog_path.display()
        )
    })?;
    // `take_link` removes the link from the program's `LinkMap` so it
    // is NOT detached when `Ebpf` drops at agent exit; we then own it
    // and hand ownership to the bpffs pin.
    let link = prog
        .take_link(link_id)
        .with_context(|| format!("taking ownership of `{hook_name}` LSM link for pinning"))?;
    let fd_link: FdLink = link.into();
    let _pinned: PinnedLink = fd_link
        .pin(link_path)
        .with_context(|| format!("pinning LSM link `{hook_name}` to {}", link_path.display()))?;
    Ok(())
}

/// Transient attach (pre-#2b behaviour) used only when bpffs is
/// unavailable: the hook works for *this* boot but is detached on
/// agent exit. Mirrors the "degrade, keep telemetry" stance the rest
/// of anti-tamper takes — no bpffs ⇒ no cross-restart persistence,
/// but the agent still defends itself while it is alive.
fn attach_transient(
    ebpf: &mut Ebpf,
    program_name: &str,
    hook_name: &str,
    btf: &Btf,
) -> Result<()> {
    let prog: &mut Lsm = ebpf
        .program_mut(program_name)
        .ok_or_else(|| anyhow!("program {program_name} missing from eBPF object"))?
        .try_into()
        .with_context(|| format!("program {program_name} is not an LSM program"))?;
    prog.load(hook_name, btf)
        .with_context(|| format!("verifier rejected LSM program `{program_name}`"))?;
    prog.attach()
        .with_context(|| format!("attaching LSM program `{program_name}` to hook `{hook_name}`"))?;
    Ok(())
}

/// Attach an LSM hook with cross-restart persistence (#2b), or reuse
/// the prior boot's still-firing kernel hook if its link pin is
/// present and valid.
///
/// Per hook, given a usable bpffs `pin_root`:
/// - `link_<hook>` exists and re-opens (`PinnedLink::from_pin`) ⇒
///   the prior boot's hook never stopped firing (the pin held it
///   across the death→respawn gap). Validate and return; the program
///   for this boot is left unloaded. Log: *reused pinned LSM link*.
/// - `link_<hook>` exists but `from_pin` fails (object gone / pin
///   corrupt) ⇒ purge both stale pins, then fresh attach+pin. Log:
///   *purged stale pin and freshly attached*.
/// - no `link_<hook>` ⇒ fresh attach+pin. Log: *freshly attached +
///   pinned*.
///
/// `pin_root == None` (no bpffs) ⇒ [`attach_transient`]: works this
/// boot, no persistence. The three success log messages are stable
/// strings the #2b verification harness greps.
pub(crate) fn attach_lsm(
    ebpf: &mut Ebpf,
    program_name: &str,
    hook_name: &str,
    btf: &Btf,
    pin_root: Option<&Path>,
) -> Result<()> {
    let Some(root) = pin_root else {
        attach_transient(ebpf, program_name, hook_name, btf)?;
        warn!(
            hook = hook_name,
            "anti-tamper: LSM hook attached WITHOUT pin (no bpffs) — will \
             NOT survive agent restart"
        );
        return Ok(());
    };

    let (prog_path, link_path) = lsm_pin_paths(root, hook_name);

    if link_path.exists() {
        match PinnedLink::from_pin(&link_path) {
            Ok(pinned) => {
                // Dropping `pinned` closes only our dup fd; the bpffs
                // pin file keeps the kernel link (hook) alive. Do NOT
                // touch the program — the prior boot's is still live
                // and bound to the (2a-pinned) PROTECTED_PIDS map.
                drop(pinned);
                info!(
                    hook = hook_name,
                    link_pin = %link_path.display(),
                    "anti-tamper: reused pinned LSM link"
                );
                return Ok(());
            }
            Err(e) => {
                warn!(
                    hook = hook_name, error = %e,
                    link_pin = %link_path.display(),
                    "anti-tamper: pinned LSM link stale/corrupt — purging \
                     and re-attaching"
                );
                purge_stale_pin(&link_path);
                purge_stale_pin(&prog_path);
                fresh_attach_and_pin(
                    ebpf,
                    program_name,
                    hook_name,
                    btf,
                    &prog_path,
                    &link_path,
                )?;
                info!(
                    hook = hook_name,
                    "anti-tamper: purged stale pin and freshly attached"
                );
                return Ok(());
            }
        }
    }

    fresh_attach_and_pin(ebpf, program_name, hook_name, btf, &prog_path, &link_path)?;
    info!(
        hook = hook_name,
        prog_pin = %prog_path.display(),
        link_pin = %link_path.display(),
        "anti-tamper: LSM hook freshly attached + pinned"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_self_comm_returns_non_empty_string() {
        let c = read_self_comm().expect("read_self_comm should succeed for our own /proc");
        assert!(!c.is_empty(), "self comm should be non-empty");
        // Trailing newline must be stripped — every assertion below
        // depends on the trim contract.
        assert!(
            !c.ends_with('\n'),
            "trailing newline must be stripped: {c:?}"
        );
    }

    #[test]
    fn read_proc_comm_for_self_matches_read_self_comm() {
        let mine = std::process::id();
        let via_self = read_self_comm().unwrap();
        let via_pid = read_proc_comm(mine).expect("read_proc_comm should find our own PID");
        assert_eq!(via_self, via_pid);
    }

    #[test]
    fn read_proc_comm_returns_none_for_impossibly_large_pid() {
        // Linux's pid_max ceiling is 2^22 on 64-bit systems; u32::MAX
        // is firmly above that, so /proc/<u32::MAX>/comm cannot exist
        // for any live process.
        let res = read_proc_comm(u32::MAX);
        assert!(res.is_none(), "expected None for u32::MAX, got {res:?}");
    }

    #[test]
    fn read_proc_comm_returns_none_for_pid_zero() {
        // PID 0 is the kernel's swapper, not exposed via /proc.
        let res = read_proc_comm(0);
        assert!(res.is_none(), "expected None for PID 0, got {res:?}");
    }
}
