//! Shared aya-handling primitives for the NorthNarrow XDR anti-tamper
//! layer (ISSUE_002 extraction from `agent/src/anti_tamper/mod.rs`).
//!
//! This crate exists so the forthcoming **watchdog binary**
//! (`docs/design/TAPPA7_TASK6_WATCHDOG_DESIGN.md` §2.2) can consume
//! the canonical bpffs pin contract WITHOUT pulling the rest of the
//! agent (tokio, posture machine, decision engine, …).
//! Watchdog needs only a handful of primitives — bpffs presence check,
//! pin-root prep, LSM hook attach, and the ability to delete a
//! PID from the pinned `PROTECTED_PIDS` map by path — and that's
//! exactly what lives here.
//!
//! ## Public surface
//!
//! - [`DEFAULT_BPFFS_ROOT`] — `/sys/fs/bpf/northnarrow`
//! - [`prepare_pin_root`] — verify bpffs + ensure `0700` root dir;
//!   [`pin_root_refusal`] — why a pin root on bpffs is not used (a
//!   symbolic link, external audit ATP-007)
//! - [`read_self_comm`] / [`read_proc_comm`] — `/proc/.../comm` reads
//!   (used by the agent's stale-PID eviction and by the watchdog's
//!   future PID-tracking work; aya-free but kept here so the
//!   anti-tamper helpers cluster in one crate).
//! - [`reattach_fresh`] — the LSM attach with cross-restart
//!   persistence: this boot's program attached before the prior boot's
//!   pins are purged, then pinned (zero-window). It never adopts a
//!   pinned link. External audit EBPF-020 (NN-AUD-271): `attach_lsm`,
//!   which reused any `link_<hook>` pin that re-opened without checking
//!   whose program it held, is removed with `fresh_attach_and_pin`, its
//!   only user. A consumer that ever needs reuse must check the link's
//!   `prog_id` and `attach_btf_id` first, in a new function.
//! - [`attach_transient`] — this boot only (no bpffs, or an observe
//!   hook that must not outlive the agent)
//! - [`lsm_pin_paths`], [`purge_stale_pin`] — pin-path helpers
//!
//! ## What's intentionally NOT here
//!
//! - `AdminAuth`, `NetworkIsolator`, posture machine, decision rules,
//!   sensors — all stay in `agent`.
//! - The agent's eBPF-object program / map name constants
//!   (`PROTECTED_PIDS_MAP`, `TASK_KILL_PROGRAM`, etc) — they belong
//!   alongside the agent-side orchestration that knows about the
//!   specific eBPF object the agent loads.
//! - The agent's `attach()` orchestrator function — it stays in
//!   `crates/nn-linux/src/anti_tamper/mod.rs` as a thin shim that calls into
//!   this crate's helpers with the agent-specific names.
//!
//! ## Re-export contract
//!
//! `crates/nn-linux/src/anti_tamper/mod.rs` `pub use`s every item in this
//! crate's public surface so existing callers
//! (`crate::anti_tamper::reattach_fresh`, `crate::anti_tamper::prepare_pin_root`,
//! `crate::anti_tamper::read_self_comm`, …) compile byte-identically.
//! This is the "zero functional changes" contract from ISSUE_002.
//!
//! ## Linux base shared with the watchdog
//!
//! Wave 4 restructure, R03 (lab PR 240): [`atomic_file`] and
//! [`sd_notify`], which both daemons use, moved here from `common` (plan
//! §2.4), so `common` keeps no Unix-only module and the crates above it
//! build for every target of the CI job `portable-core`.

/// Replacing a file without writing through a planted link (external
/// audit AUT-003, WDG-015).
pub mod atomic_file;

/// The `sd_notify(3)` datagram of the agent and the watchdog (external
/// audit MAIN-016: abstract sockets).
#[cfg(target_os = "linux")]
pub mod sd_notify;

use std::borrow::{Borrow, BorrowMut};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use aya::{
    maps::{Array as AyaArray, HashMap as AyaHashMap, Map as AyaMap, MapData},
    programs::{
        links::{FdLink, PinnedLink},
        Lsm,
    },
    Btf, Ebpf,
};
use tracing::{error, info, warn};

/// Name of the pinned `PROTECTED_PIDS` map (mirrors the
/// `#[map]` declaration in `agent-ebpf/src/task_kill.rs`). The
/// agent's eBPF object pins this map under [`DEFAULT_BPFFS_ROOT`]
/// via `EbpfLoader::default_map_pin_directory`, and the watchdog opens it by
/// joining this name onto the bpffs root.
pub const PROTECTED_PIDS_MAP_NAME: &str = "PROTECTED_PIDS";

/// External audit EBPF-002: name of the pinned `ROLE_TGIDS` map (mirrors
/// `agent-ebpf/src/bpf_defense.rs`): the tgid of the live watchdog (slot
/// [`ROLE_SLOT_WATCHDOG`]) and agent (slot [`ROLE_SLOT_AGENT`]). While a
/// slot holds a live tgid, a fresh process running that binary takes no
/// write handle on the agent's maps until it is a protected pid.
pub const ROLE_TGIDS_MAP_NAME: &str = "ROLE_TGIDS";
pub const ROLE_SLOT_WATCHDOG: u32 = 0;
pub const ROLE_SLOT_AGENT: u32 = 1;

/// Write `tgid` into slot `slot` of the pinned `ROLE_TGIDS` map at
/// `<bpffs_root>/ROLE_TGIDS`. The caller must already be a protected pid
/// (the map guard denies anyone else a write handle).
pub fn claim_role(bpffs_root: &Path, slot: u32, tgid: u32) -> Result<()> {
    let pin_path = bpffs_root.join(ROLE_TGIDS_MAP_NAME);
    let map_data = MapData::from_pin(&pin_path).with_context(|| {
        format!(
            "opening pinned {ROLE_TGIDS_MAP_NAME} at {}",
            pin_path.display()
        )
    })?;
    let mut arr: AyaArray<MapData, u32> = AyaArray::try_from(AyaMap::Array(map_data))
        .with_context(|| format!("{ROLE_TGIDS_MAP_NAME} is not an Array<u32>"))?;
    arr.set(slot, tgid, 0)
        .with_context(|| format!("setting {ROLE_TGIDS_MAP_NAME}[{slot}] = {tgid}"))?;
    Ok(())
}

/// BUG-011 (PHASE 15.1): name of the pinned `PROTECTED_OBSERVERS`
/// map (mirrors the `#[map]` declaration in
/// `agent-ebpf/src/ptrace_check.rs`). The agent's
/// `spawn_watchdog_exempt_refresh` timer writes verified observer
/// PIDs here; the `ptrace_access_check` LSM hook reads it on each
/// fire. Pinned by-name so the registration survives agent restart.
pub const PROTECTED_OBSERVERS_MAP_NAME: &str = "PROTECTED_OBSERVERS";

/// Single bpffs directory holding every pinned anti-tamper object.
/// Pre-extraction commit history (Tappa 7 task 6 #2 / #2b) pinned the
/// six anti-tamper maps + the seven LSM programs + links here. One
/// self-contained namespace lets the watchdog and `nn-admin`
/// enumerate the pinned set by listing it, and keeps
/// `EbpfLoader::default_map_pin_directory` (maps) and `FdLink::pin` (links)
/// sharing one root.
pub const DEFAULT_BPFFS_ROOT: &str = "/sys/fs/bpf/northnarrow";

/// `statfs(2)` magic for a BPF filesystem mount (`uapi/linux/magic.h`
/// `BPF_FS_MAGIC`). Used to fail *soft* with an actionable message
/// when `/sys/fs/bpf` isn't a bpffs mount, rather than letting aya
/// surface an opaque `BPF_OBJ_PIN` errno from deep inside `load()`.
const BPF_FS_MAGIC: i64 = 0xcafe_4a11;

/// Mode for [`DEFAULT_BPFFS_ROOT`]. `0700`: only root may list or
/// unlink the pins. This matters beyond hygiene — an unprivileged
/// `unlink` of a pinned *link* would detach a live LSM hook, and
/// unlinking a pinned *map* re-opens the split-brain on the next
/// agent restart.
const PIN_ROOT_MODE: u32 = 0o700;

/// Prepare the bpffs pin directory and return the path to hand to
/// [`aya::EbpfLoader::default_map_pin_directory`]. Returns `None` when bpffs is
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

    // External audit ATP-007 (NN-AUD-260): a pin root that is a symbolic
    // link is never followed — the chmod below and the agent's
    // registration of every pin under the root would have reached the
    // link's target (another product's pin directory). Not used: the
    // hooks attach without pins, and the agent refuses to start
    // (`pin_root_refusal`).
    if let Some(why) = pin_root_refusal_at(root) {
        error!("anti-tamper: {why}");
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
    // already required root to get this far. The directory itself
    // (`lstat`): a link created after the check above is not chmodded
    // through.
    if let Ok(meta) = std::fs::symlink_metadata(root) {
        if meta.is_dir() && (meta.permissions().mode() & 0o7777) != PIN_ROOT_MODE {
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

/// External audit ATP-007 (NN-AUD-260): why the pin root is not used
/// although bpffs is mounted — [`DEFAULT_BPFFS_ROOT`] is a symbolic link,
/// or something other than a directory. `None` when it is a directory, is
/// absent (created at the first [`prepare_pin_root`]), or bpffs is not
/// mounted (that degraded mode is logged by [`prepare_pin_root`]). The
/// agent counts `Some` as a failed protection step and refuses to start.
pub fn pin_root_refusal() -> Option<String> {
    let root = Path::new(DEFAULT_BPFFS_ROOT);
    let mount = root.parent().unwrap_or_else(|| Path::new("/sys/fs/bpf"));
    if !is_bpffs(mount) {
        return None;
    }
    pin_root_refusal_at(root)
}

/// [`pin_root_refusal`] for `root`, whatever filesystem holds it.
pub fn pin_root_refusal_at(root: &Path) -> Option<String> {
    let meta = std::fs::symlink_metadata(root).ok()?;
    if meta.file_type().is_symlink() {
        let target = std::fs::read_link(root)
            .map(|t| t.display().to_string())
            .unwrap_or_else(|_| "?".to_string());
        return Some(format!(
            "the bpffs pin root {} is a symbolic link (-> {target}): not followed — the agent \
             would set its mode on, pin into and protect the link's target. Remove the link (it \
             goes with a remount of /sys/fs/bpf)",
            root.display()
        ));
    }
    (!meta.is_dir()).then(|| {
        format!(
            "the bpffs pin root {} exists and is not a directory: not used",
            root.display()
        )
    })
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

/// bpffs pin paths for one LSM hook. Keeps the path key the
/// **human-readable hook name** (`task_kill`, `ptrace_access_check`,
/// …) so an operator listing [`DEFAULT_BPFFS_ROOT`] sees
/// self-describing names. The kernel truncates aya's program *name*
/// (the Rust fn symbol) to 15 chars, so e.g. `bpftool prog show
/// name` reports `ptrace_access_c` — that truncation is a
/// *verification-harness* concern only; nothing here or in
/// `bpf_get_object` cares about the kernel prog name.
///
/// Two **separate** pins per hook, both required:
/// - `prog_<hook>` keeps the kernel *program* object loaded.
/// - `link_<hook>` keeps the *attachment* live — this is the one
///   that makes the hook keep **firing** across the agent
///   death→respawn gap. A pinned program with no pinned link is a
///   loaded-but-inert program; the link pin is the survivability
///   primitive (see `aya` `programs/links.rs` `FdLink::pin` /
///   `PinnedLink::from_pin`).
pub fn lsm_pin_paths(root: &Path, hook_name: &str) -> (PathBuf, PathBuf) {
    (
        root.join(format!("prog_{hook_name}")),
        root.join(format!("link_{hook_name}")),
    )
}

/// Best-effort unlink of a stale/crashed-state pin. A leftover pin
/// file whose backing kernel object is gone (or is corrupt on disk)
/// must never wedge agent startup: we remove it and fall through to
/// a fresh attach. `NotFound` is success (already gone).
pub fn purge_stale_pin(path: &Path) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warn!(
            error = %e, path = %path.display(),
            "anti-tamper: could not unlink stale pin (continuing to fresh attach)"
        ),
    }
}

/// Transient attach used only when bpffs is unavailable: the hook
/// works for *this* boot but is detached on agent exit. Mirrors the
/// "degrade, keep telemetry" stance the rest of anti-tamper takes —
/// no bpffs ⇒ no cross-restart persistence, but the agent still
/// defends itself while it is alive.
pub fn attach_transient(
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

/// Attach an LSM **deny** hook with cross-restart persistence, ALWAYS
/// freshly — never reusing the prior boot's pinned link. This is the
/// BUG-024 fix for the `FS_PROTECT_EVENTS` producers (the `inode_*` deny
/// hooks): reusing the pinned link kept the prior boot's program bound to
/// the prior (pinned) ring, desyncing the new boot's consumer. Here each
/// boot loads + attaches a FRESH program (bound to this boot's fresh,
/// process-local ring), then retires the old pin.
///
/// ZERO-WINDOW ORDERING CONTRACT — **attach-NEW strictly precedes
/// purge-OLD**:
///   1. load + attach the fresh program. The prior boot's link pin (if
///      any) is STILL firing across the death→respawn gap (split-brain),
///      so now BOTH the old and new deny programs are attached — overlap,
///      never a gap. (BPF-LSM permits multiple programs per hook; any
///      non-zero verdict denies, so a double-attach is idempotent.)
///   2. ONLY THEN purge the prior boot's link + program pins. Removing the
///      old link pin detaches the OLD program; the NEW one (held by our fd
///      via `link_id`) keeps firing — a deny program is attached at every
///      instant.
///   3. pin the NEW program + link, so THIS boot's hook survives the next
///      death→respawn gap (persistence preserved).
///
/// If purge ever preceded attach, a tamper could slip through the gap — so
/// the 1→2 order is load-bearing. It is also fail-safe: if the fresh attach
/// errors, we return BEFORE purging, leaving the prior boot's pinned hook
/// intact (still protecting).
///
/// `pin_root == None` (no bpffs) ⇒ [`attach_transient`] (this boot only).
pub fn reattach_fresh(
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
            "anti-tamper: deny hook attached WITHOUT pin (no bpffs) — no \
             cross-restart persistence"
        );
        return Ok(());
    };
    let (prog_path, link_path) = lsm_pin_paths(root, hook_name);

    // Step 1 — load + attach the FRESH program. A prior boot's pinned link
    // (if present) is still firing here, so old + new overlap: zero gap.
    let prog: &mut Lsm = ebpf
        .program_mut(program_name)
        .ok_or_else(|| anyhow!("program {program_name} missing from eBPF object"))?
        .try_into()
        .with_context(|| format!("program {program_name} is not an LSM program"))?;
    prog.load(hook_name, btf)
        .with_context(|| format!("verifier rejected LSM program `{program_name}`"))?;
    let link_id = prog.attach().with_context(|| {
        format!("attaching fresh LSM program `{program_name}` to hook `{hook_name}`")
    })?;

    // Step 2 — ONLY NOW retire the prior boot's pins (MUST follow Step 1 —
    // the zero-window invariant). The new program, held by our fd via
    // `link_id`, keeps firing while the old one detaches.
    purge_stale_pin(&link_path);
    purge_stale_pin(&prog_path);

    // Step 3 — pin the fresh program + link so this boot's hook survives the
    // next death→respawn gap (split-brain persistence preserved).
    prog.pin(&prog_path).with_context(|| {
        format!(
            "pinning fresh LSM program `{program_name}` to {}",
            prog_path.display()
        )
    })?;
    let link = prog
        .take_link(link_id)
        .with_context(|| format!("taking ownership of fresh `{hook_name}` LSM link"))?;
    let fd_link: FdLink = link.into();
    let _pinned: PinnedLink = fd_link.pin(&link_path).with_context(|| {
        format!(
            "pinning fresh LSM link `{hook_name}` to {}",
            link_path.display()
        )
    })?;
    info!(
        hook = hook_name,
        "anti-tamper: deny hook re-attached FRESH (attach-before-purge, zero-window) + re-pinned"
    );
    Ok(())
}

// ────────────────────────────────────────────────────────────────────
// Tappa 7 task 6 Watchdog W1 — ProtectedPidsHandle (design §6.3)
// ────────────────────────────────────────────────────────────────────

/// Typed handle to the pinned `PROTECTED_PIDS` BPF map, the
/// kernel-side source of truth for which PIDs the agent's
/// `task_kill` + `ptrace_access_check` LSM hooks treat as
/// "untouchable by root".
///
/// Two construction paths cover the two consumer shapes:
/// - [`Self::open`] opens the map by **bpffs path**
///   (`MapData::from_pin`). No `Ebpf` instance, no aya loader, no
///   eBPF object load — just a path string. This is the
///   **watchdog**-facing API per design §6.3: the watchdog binary
///   never loads any program, but needs to delete the agent's PID
///   from the map on agent death (the layer-2 recycled-PID race
///   close).
/// - [`Self::from_ebpf`] borrows the already-loaded `MapData`
///   from an existing `Ebpf` instance. This is the
///   **agent**-facing API: the agent has already loaded its eBPF
///   object (which contains `PROTECTED_PIDS`); reusing that
///   in-process `MapData` avoids opening a second userspace fd on
///   the same kernel map AND supports the no-bpffs degraded path
///   where the map is loaded but not pinned.
///
/// Both constructors yield the same surface
/// (`insert`/`evict`/`contains`/`pids`); the generic storage
/// parameter [`T`] hides the differing aya borrow shapes from
/// callers.
#[derive(Debug)]
pub struct ProtectedPidsHandle<T = MapData> {
    map: AyaHashMap<T, u32, u8>,
}

impl ProtectedPidsHandle<MapData> {
    /// Watchdog-facing constructor. Opens the pinned
    /// `PROTECTED_PIDS` map at
    /// `<bpffs_root>/PROTECTED_PIDS` (default
    /// `/sys/fs/bpf/northnarrow/PROTECTED_PIDS`). Fails if the
    /// pin file is missing (no agent has loaded a pinned map at
    /// this bpffs yet) or if the file exists but is not a valid
    /// pinned BPF map of shape `HashMap<u32, u8>`.
    ///
    /// The returned handle owns its `MapData` (a fresh userspace
    /// fd on the kernel map); dropping the handle drops the fd
    /// but leaves the pinned kernel object intact — the bpffs
    /// pin is the persistence mechanism, the userspace handle is
    /// just a window onto it.
    pub fn open(bpffs_root: &Path) -> Result<Self> {
        let pin_path = bpffs_root.join(PROTECTED_PIDS_MAP_NAME);
        let map_data = MapData::from_pin(&pin_path).with_context(|| {
            format!(
                "opening pinned {} at {}",
                PROTECTED_PIDS_MAP_NAME,
                pin_path.display()
            )
        })?;
        // aya's `HashMap::try_from` accepts the `Map` enum (not
        // `MapData` directly), so wrap the freshly-opened
        // `MapData` in `Map::HashMap` before the cast. The
        // resulting handle owns the `Map::HashMap(_)` storage
        // — a single `MapData` worth of state, just wrapped.
        let map = AyaMap::HashMap(map_data);
        let map = AyaHashMap::try_from(map)
            .with_context(|| format!("{} is not a HashMap<u32, u8>", PROTECTED_PIDS_MAP_NAME))?;
        Ok(Self { map })
    }
}

impl<'a> ProtectedPidsHandle<&'a mut MapData> {
    /// Agent-facing constructor. Borrows the
    /// already-loaded `PROTECTED_PIDS` map from an existing
    /// `Ebpf` instance. Works regardless of whether the map is
    /// pinned (which matters for the no-bpffs degraded path the
    /// agent supports). Fails if the eBPF object doesn't contain
    /// a map named [`PROTECTED_PIDS_MAP_NAME`] or if the map's
    /// key/value types don't match `HashMap<u32, u8>`.
    pub fn from_ebpf(ebpf: &'a mut Ebpf) -> Result<Self> {
        let map = ebpf
            .map_mut(PROTECTED_PIDS_MAP_NAME)
            .ok_or_else(|| anyhow!("map {PROTECTED_PIDS_MAP_NAME} missing from eBPF object"))?;
        let map = AyaHashMap::try_from(map)
            .with_context(|| format!("{PROTECTED_PIDS_MAP_NAME} is not a HashMap<u32, u8>"))?;
        Ok(Self { map })
    }
}

// Write-side methods require BorrowMut<MapData>. Both Open
// (`MapData` owned) and FromEbpf (`&mut MapData` borrowed)
// satisfy this — owned types impl BorrowMut for themselves.
impl<T> ProtectedPidsHandle<T>
where
    T: BorrowMut<MapData>,
{
    /// Insert `pid` into `PROTECTED_PIDS`. `BPF_ANY` upsert
    /// semantics: an entry that already exists is overwritten,
    /// so re-inserting the same PID after an eviction race is
    /// fine. Value is always `1u8`; the map's value type is
    /// `u8` rather than `()` to align with the aya HashMap API.
    pub fn insert(&mut self, pid: u32) -> Result<()> {
        self.map
            .insert(pid, 1u8, 0)
            .with_context(|| format!("inserting PID {pid} into {PROTECTED_PIDS_MAP_NAME}"))?;
        Ok(())
    }

    /// Remove `pid` from `PROTECTED_PIDS`. Returns Ok if the PID
    /// was present and removed, OR if it was already absent
    /// (idempotent eviction — the watchdog's pidfd-driven death
    /// detection may race against the agent's own
    /// `evict_stale_pids` at startup, and either order is fine).
    /// Other errors (e.g. kernel rejecting the syscall) propagate.
    pub fn evict(&mut self, pid: u32) -> Result<()> {
        match self.map.remove(&pid) {
            Ok(()) => Ok(()),
            Err(e) => {
                // aya (0.13 and 0.14) surfaces "key not found" via a
                // SyscallError carrying io_error == NotFound.
                // Treat that as idempotent success.
                if is_not_found_err(&e) {
                    Ok(())
                } else {
                    Err(anyhow!(e)).with_context(|| {
                        format!("evicting PID {pid} from {PROTECTED_PIDS_MAP_NAME}")
                    })
                }
            }
        }
    }
}

// Read-side methods only need Borrow<MapData>.
impl<T> ProtectedPidsHandle<T>
where
    T: Borrow<MapData>,
{
    /// `true` if `pid` is currently in the map. Any aya error
    /// other than "key not found" propagates so callers can
    /// distinguish "definitely absent" from "lookup failed."
    pub fn contains(&self, pid: u32) -> Result<bool> {
        match self.map.get(&pid, 0) {
            Ok(_) => Ok(true),
            Err(e) => {
                if is_not_found_err(&e) {
                    Ok(false)
                } else {
                    Err(anyhow!(e)).with_context(|| {
                        format!("looking up PID {pid} in {PROTECTED_PIDS_MAP_NAME}")
                    })
                }
            }
        }
    }

    /// Snapshot of every PID currently in the map. Materialised
    /// into a `Vec` up front because aya's `keys()` iterator
    /// holds a borrow on the map, and the agent's
    /// `evict_stale_pids` walk needs to call [`Self::evict`]
    /// (which needs `&mut`) for each stale entry. Returning a
    /// `Vec` also matches the watchdog's diagnostic use cases
    /// (dump the protected set to a log line).
    pub fn pids(&self) -> Result<Vec<u32>> {
        Ok(self.map.keys().filter_map(Result::ok).collect())
    }
}

// ────────────────────────────────────────────────────────────────────
// BUG-011 (PHASE 15.1) — ProtectedObserversHandle
// ────────────────────────────────────────────────────────────────────

/// Typed handle to the pinned `PROTECTED_OBSERVERS` BPF map. Same
/// shape as [`ProtectedPidsHandle`] (`HashMap<u32, u8>` with
/// presence-as-signal semantics) but a distinct map name AND a
/// distinct security contract:
///
/// - `PROTECTED_PIDS` ⇒ target may not be killed/ptraced; caller-side
///   reciprocal grants observer rights to other PROTECTED_PIDS members.
/// - `PROTECTED_OBSERVERS` ⇒ caller may ptrace-read PROTECTED_PIDS
///   targets, but is NOT itself shielded from kill/ptrace by anyone.
///
/// Writers: ONLY the agent. The watchdog never writes this map (the
/// watchdog is a CONSUMER — its read of `/proc/<agent>/exe` is what
/// the carve-out exists to permit). Construction mirrors
/// `ProtectedPidsHandle`: [`Self::open`] for path-based callers,
/// [`Self::from_ebpf`] for the agent's in-process Ebpf instance.
#[derive(Debug)]
pub struct ProtectedObserversHandle<T = MapData> {
    map: AyaHashMap<T, u32, u8>,
}

impl ProtectedObserversHandle<MapData> {
    /// Open the pinned `PROTECTED_OBSERVERS` map at
    /// `<bpffs_root>/PROTECTED_OBSERVERS`. Same failure modes as
    /// [`ProtectedPidsHandle::open`] (pin missing, wrong shape).
    pub fn open(bpffs_root: &Path) -> Result<Self> {
        let pin_path = bpffs_root.join(PROTECTED_OBSERVERS_MAP_NAME);
        let map_data = MapData::from_pin(&pin_path).with_context(|| {
            format!(
                "opening pinned {} at {}",
                PROTECTED_OBSERVERS_MAP_NAME,
                pin_path.display()
            )
        })?;
        let map = AyaMap::HashMap(map_data);
        let map = AyaHashMap::try_from(map).with_context(|| {
            format!("{} is not a HashMap<u32, u8>", PROTECTED_OBSERVERS_MAP_NAME)
        })?;
        Ok(Self { map })
    }
}

impl<'a> ProtectedObserversHandle<&'a mut MapData> {
    /// Agent-facing constructor — borrow the `PROTECTED_OBSERVERS`
    /// map from an already-loaded `Ebpf` instance.
    pub fn from_ebpf(ebpf: &'a mut Ebpf) -> Result<Self> {
        let map = ebpf.map_mut(PROTECTED_OBSERVERS_MAP_NAME).ok_or_else(|| {
            anyhow!("map {PROTECTED_OBSERVERS_MAP_NAME} missing from eBPF object")
        })?;
        let map = AyaHashMap::try_from(map)
            .with_context(|| format!("{PROTECTED_OBSERVERS_MAP_NAME} is not a HashMap<u32, u8>"))?;
        Ok(Self { map })
    }
}

impl<T> ProtectedObserversHandle<T>
where
    T: BorrowMut<MapData>,
{
    /// Register `pid` as a trusted observer. `BPF_ANY` upsert; safe
    /// to call repeatedly for the same PID.
    pub fn insert(&mut self, pid: u32) -> Result<()> {
        self.map
            .insert(pid, 1u8, 0)
            .with_context(|| format!("inserting PID {pid} into {PROTECTED_OBSERVERS_MAP_NAME}"))?;
        Ok(())
    }

    /// Remove `pid`. Absent ⇒ Ok (idempotent — the agent's refresh
    /// timer may race with watchdog teardown).
    pub fn evict(&mut self, pid: u32) -> Result<()> {
        match self.map.remove(&pid) {
            Ok(()) => Ok(()),
            Err(e) => {
                if is_not_found_err(&e) {
                    Ok(())
                } else {
                    Err(anyhow!(e)).with_context(|| {
                        format!("evicting PID {pid} from {PROTECTED_OBSERVERS_MAP_NAME}")
                    })
                }
            }
        }
    }
}

impl<T> ProtectedObserversHandle<T>
where
    T: Borrow<MapData>,
{
    /// `true` if `pid` is currently registered as a trusted observer.
    pub fn contains(&self, pid: u32) -> Result<bool> {
        match self.map.get(&pid, 0) {
            Ok(_) => Ok(true),
            Err(e) => {
                if is_not_found_err(&e) {
                    Ok(false)
                } else {
                    Err(anyhow!(e)).with_context(|| {
                        format!("looking up PID {pid} in {PROTECTED_OBSERVERS_MAP_NAME}")
                    })
                }
            }
        }
    }

    /// Snapshot of every registered observer PID.
    pub fn pids(&self) -> Result<Vec<u32>> {
        Ok(self.map.keys().filter_map(Result::ok).collect())
    }
}

/// Helper: does this aya `MapError` represent "key not found"?
/// aya (0.13 and 0.14) surfaces `ENOENT` from the kernel BPF syscalls
/// through `MapError::SyscallError { io_error, .. }` where
/// `io_error.kind() == NotFound`. Centralised here so both
/// `evict` and `contains` share one check and a future aya
/// upgrade (e.g. an explicit `KeyNotFound` variant) only has
/// one site to update.
fn is_not_found_err(e: &aya::maps::MapError) -> bool {
    match e {
        aya::maps::MapError::SyscallError(syscall_err) => {
            syscall_err.io_error.kind() == std::io::ErrorKind::NotFound
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// External audit ATP-007 (NN-AUD-260): a pin root that is a link is
    /// refused, naming the link, and its target is not touched; a real
    /// directory and an absent root are used.
    #[test]
    fn pin_root_link_is_refused_and_target_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("other-product");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let link = dir.path().join("northnarrow");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let why = pin_root_refusal_at(&link).expect("a link must be refused");
        assert!(why.contains("symbolic link"), "{why}");
        assert!(why.contains(&target.display().to_string()), "{why}");
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o755, "the target's mode must not change");

        assert_eq!(
            pin_root_refusal_at(&target),
            None,
            "a real directory is used"
        );
        assert_eq!(pin_root_refusal_at(&dir.path().join("absent")), None);
        let file = dir.path().join("file");
        std::fs::write(&file, "x").unwrap();
        assert!(
            pin_root_refusal_at(&file).is_some(),
            "a file is not a pin root"
        );
    }

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

    #[test]
    fn lsm_pin_paths_uses_hook_name_for_both_pins() {
        let root = Path::new("/sys/fs/bpf/northnarrow");
        let (prog, link) = lsm_pin_paths(root, "task_kill");
        assert_eq!(prog, Path::new("/sys/fs/bpf/northnarrow/prog_task_kill"));
        assert_eq!(link, Path::new("/sys/fs/bpf/northnarrow/link_task_kill"));
    }

    #[test]
    fn purge_stale_pin_swallows_not_found() {
        // Path that definitely doesn't exist — purge must not panic
        // or error; NotFound is success for the helper's contract.
        let p = std::path::PathBuf::from("/tmp/this-path-does-not-exist-and-never-will");
        purge_stale_pin(&p); // returns ()
    }

    #[test]
    fn purge_stale_pin_removes_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("stale_pin");
        std::fs::write(&f, b"garbage").unwrap();
        assert!(f.exists());
        purge_stale_pin(&f);
        assert!(!f.exists(), "purge_stale_pin should unlink a regular file");
    }

    // ── Watchdog W1: ProtectedPidsHandle (design §6.3, §12 row W1)
    //
    // Full insert/evict/contains/pids round-trips on a real BPF
    // map require root + a kernel with `bpf` in the boot lsm=
    // chain — exercised by `agent/tests/privileged_e2e.rs` today
    // and by the future W8 watchdog privileged e2e test. The
    // unit tests below cover everything that's testable WITHOUT
    // root: error paths (file missing, wrong kind), pin-path
    // construction, and a compile-time guard that both
    // constructors yield a handle satisfying the read-side and
    // write-side trait bounds.

    /// Required W1 test 1 ("open"): a nonexistent bpffs root
    /// surfaces a clear error from [`ProtectedPidsHandle::open`]
    /// rather than panicking. Error chain references both
    /// `PROTECTED_PIDS` (the map name) and the failed path so the
    /// operator log line points at the right thing.
    #[test]
    fn protected_pids_handle_open_fails_when_pin_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        // dir exists but no `PROTECTED_PIDS` pin file inside.
        let err = ProtectedPidsHandle::open(dir.path()).unwrap_err();
        let chain = format!("{err:#}");
        assert!(
            chain.contains(PROTECTED_PIDS_MAP_NAME),
            "error chain should mention the map name, got: {chain}"
        );
        assert!(
            chain.contains(dir.path().to_str().unwrap()),
            "error chain should mention the attempted path, got: {chain}"
        );
    }

    /// Required W1 test 2 ("open"): a path that points to a
    /// regular file (not a valid pinned BPF map) also surfaces
    /// `from_pin`'s error rather than panicking. Documents that
    /// the open() path does NOT silently accept "any file at the
    /// pin location" — only a real pinned BPF map.
    #[test]
    fn protected_pids_handle_open_fails_when_path_is_a_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let fake_pin = dir.path().join(PROTECTED_PIDS_MAP_NAME);
        std::fs::write(&fake_pin, b"not a pinned bpf map").unwrap();
        let err = ProtectedPidsHandle::open(dir.path()).unwrap_err();
        // The exact error shape depends on aya's from_pin
        // internals — we just assert the chain is non-empty AND
        // mentions the map name (the surrounding context).
        let chain = format!("{err:#}");
        assert!(!chain.is_empty());
        assert!(
            chain.contains(PROTECTED_PIDS_MAP_NAME),
            "context should mention {PROTECTED_PIDS_MAP_NAME}, got: {chain}"
        );
    }

    /// Required W1 test 3 ("path construction"): the pin path
    /// `<bpffs_root>/PROTECTED_PIDS` is built from the published
    /// [`PROTECTED_PIDS_MAP_NAME`] constant. Locks the
    /// constant-name vs the path convention so a future rename
    /// breaks this test loudly (vs silently breaking the
    /// watchdog↔agent contract).
    #[test]
    fn protected_pids_pin_path_is_bpffs_root_joined_with_map_name() {
        assert_eq!(PROTECTED_PIDS_MAP_NAME, "PROTECTED_PIDS");
        assert_eq!(DEFAULT_BPFFS_ROOT, "/sys/fs/bpf/northnarrow");
        // Operator-facing path the watchdog will open at runtime.
        let expected = Path::new(DEFAULT_BPFFS_ROOT).join(PROTECTED_PIDS_MAP_NAME);
        assert_eq!(
            expected,
            Path::new("/sys/fs/bpf/northnarrow/PROTECTED_PIDS")
        );
    }

    /// Required W1 test 4 ("compile-time API shape"): both
    /// constructors (`open` and `from_ebpf`) yield a handle that
    /// supports the full insert/evict/contains/pids surface.
    /// This is a pure compile-test — failure shows up at build
    /// time, not at runtime — guarding against a future trait
    /// constraint regression that would silently strip one side
    /// (e.g. accidentally requiring `BorrowMut` for `contains`).
    #[test]
    fn protected_pids_handle_constructors_and_method_surface_compile() {
        // Owned variant (open path — watchdog).
        fn _exercise_owned(h: &mut ProtectedPidsHandle<MapData>) -> Result<()> {
            h.insert(1)?;
            h.evict(1)?;
            let _: bool = h.contains(1)?;
            let _: Vec<u32> = h.pids()?;
            Ok(())
        }
        // Borrowed variant (from_ebpf path — agent).
        fn _exercise_borrowed(h: &mut ProtectedPidsHandle<&mut MapData>) -> Result<()> {
            h.insert(1)?;
            h.evict(1)?;
            let _: bool = h.contains(1)?;
            let _: Vec<u32> = h.pids()?;
            Ok(())
        }
        // No runtime invocations — these functions exist solely
        // to compile-check the API surface. Reference them so
        // dead-code lint doesn't fire.
        let _ = _exercise_owned as fn(&mut ProtectedPidsHandle<MapData>) -> Result<()>;
        let _ = _exercise_borrowed as fn(&mut ProtectedPidsHandle<&mut MapData>) -> Result<()>;
    }
}
