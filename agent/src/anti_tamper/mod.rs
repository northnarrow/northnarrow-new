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
pub mod bootstrap;
pub mod combat_allow;
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
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use aya::{maps::Array as AyaArray, Btf, Ebpf};
use rand::RngCore;
use tracing::{info, warn};

// ISSUE_002: bpffs root / pin / LSM-attach primitives were
// extracted from this module into the `antitamper-bpf` workspace
// crate so the forthcoming watchdog binary can consume them
// without pulling the rest of `agent`. Re-exported here so
// every pre-extraction caller (sensors/multiplexer.rs,
// filesystem.rs, main.rs, tests) keeps compiling byte-identically.
pub use antitamper_bpf::{
    attach_lsm, attach_transient, fresh_attach_and_pin, lsm_pin_paths, prepare_pin_root,
    purge_stale_pin, read_proc_comm, read_self_comm, DEFAULT_BPFFS_ROOT,
    PROTECTED_OBSERVERS_MAP_NAME, PROTECTED_PIDS_MAP_NAME,
};

// Watchdog W1: PROTECTED_PIDS userspace manipulation now goes
// through the typed handle in `antitamper-bpf` so both the agent
// (in-process, has the `Ebpf`) and the future watchdog binary
// (cross-process, opens by bpffs path) use the same code path.
use antitamper_bpf::{ProtectedObserversHandle, ProtectedPidsHandle};

/// Watchdog W6: TASK_COMM_LEN-truncated comm of the watchdog
/// binary. The watchdog's W2 boot sequence calls
/// `prctl(PR_SET_NAME, "northnarrow-wat")` (15 chars + NUL fits
/// the kernel's 16-byte field exactly), so this is the literal
/// string `/proc/<watchdog_pid>/comm` produces.
///
/// Adding this to `attach()`'s `allowed_comms` set means
/// `evict_stale_pids` will NOT evict the watchdog's
/// `PROTECTED_PIDS` entry on the agent's next restart —
/// preserves the LSM kill/ptrace protection for the watchdog
/// across the agent death→respawn gap (per design §7.1).
pub const WATCHDOG_COMM: &str = "northnarrow-wat";

/// Watchdog W6: best-effort read of the watchdog's PID file.
/// Returns `Some(pid)` when the file exists AND parses as a
/// `u32`; returns `None` for every failure mode (file absent,
/// permission denied, garbage content, empty) AFTER logging.
/// Failure is NEVER propagated — a deployment that hasn't yet
/// rolled out the watchdog binary must boot the agent
/// unchanged (per design §7.1 "the agent runs without a
/// watchdog before W6 lands").
///
/// Trims a single trailing newline (the watchdog's atomic
/// pidfile writer emits `<pid>\n`); rejects multi-line content
/// because the canonical writer never produces such bytes.
pub fn read_watchdog_pid_optional(path: &Path) -> Option<u32> {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            info!(
                target: "anti_tamper.watchdog_pid",
                path = %path.display(),
                "no watchdog pidfile present — agent boots without watchdog co-protection"
            );
            return None;
        }
        Err(e) => {
            warn!(
                target: "anti_tamper.watchdog_pid",
                error = %e,
                path = %path.display(),
                "watchdog pidfile read failed — falling back to agent-only protection"
            );
            return None;
        }
    };
    let trimmed = raw.trim();
    match trimmed.parse::<u32>() {
        Ok(pid) => {
            info!(
                target: "anti_tamper.watchdog_pid",
                path = %path.display(),
                watchdog_pid = pid,
                "watchdog pidfile present — co-registering watchdog PID in PROTECTED_PIDS"
            );
            Some(pid)
        }
        Err(e) => {
            warn!(
                target: "anti_tamper.watchdog_pid",
                error = %e,
                path = %path.display(),
                content = %trimmed,
                "watchdog pidfile content is not a valid u32 — falling back to agent-only"
            );
            None
        }
    }
}

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
//
// BUG-010 (PHASE 15.1) supersedes the KILL_OVERRIDE TODO above:
// `arm_kill_override` below writes a fresh per-boot session nonce
// into BOTH `KILL_OVERRIDE` and `AGENT_SESSION` before LSM attach.
// The hook accepts the PID-1 carve-out only when both slots match
// AND are non-zero, so a leftover `KILL_OVERRIDE` value from a prior
// install can't unlock the new agent (different session nonce).

/// BUG-010 (PHASE 15.1): map names for the PID-1 carve-out, mirroring
/// the `#[map] pub static …` declarations in
/// `agent-ebpf/src/task_kill.rs`. Kept here because aya looks maps up
/// by string at runtime.
const KILL_OVERRIDE_MAP_NAME: &str = "KILL_OVERRIDE";
const AGENT_SESSION_MAP_NAME: &str = "AGENT_SESSION";

/// Names mirroring `#[lsm(hook = "…")]` declarations in
/// `agent-ebpf/src/{task_kill,ptrace_check}.rs`. Kept here as
/// constants because aya looks them up by string at runtime. The
/// map-name constant lives in `antitamper-bpf::PROTECTED_PIDS_MAP_NAME`
/// (Watchdog W1) since both agent and watchdog reference it; these
/// hook/program names stay agent-side because only the agent
/// loads the LSM hooks.
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
        map = PROTECTED_PIDS_MAP_NAME,
        "anti-tamper: PIDs registered with kernel"
    );

    // PHASE_D_001: pin PROTECTED_PIDS by name to bpffs. The eBPF
    // source declares `HashMap::pinned(16, 0)` and the loader
    // calls `map_pin_path(root)`, which is documented to handle
    // by-name pinning automatically — empirically on aya 0.13.1 +
    // kernel 6.8 it does not, leaving the watchdog's
    // `ProtectedPidsHandle::open(bpffs_root)` unable to find the
    // map. Explicit pin here closes the gap. purge_stale_pin +
    // pin mirrors the W1 attach_lsm idiom: a leftover pin from a
    // prior wedged boot may point at a dead kernel map, so we
    // always re-pin against the live map this boot loaded.
    if let Some(root) = prepare_pin_root() {
        let map_pin_path = root.join(PROTECTED_PIDS_MAP_NAME);
        purge_stale_pin(&map_pin_path);
        ebpf.map_mut(PROTECTED_PIDS_MAP_NAME)
            .ok_or_else(|| {
                anyhow::anyhow!("map {PROTECTED_PIDS_MAP_NAME} missing from eBPF object")
            })?
            .pin(&map_pin_path)
            .with_context(|| {
                format!(
                    "pinning {PROTECTED_PIDS_MAP_NAME} to {}",
                    map_pin_path.display()
                )
            })?;
        info!(
            map = PROTECTED_PIDS_MAP_NAME,
            map_pin = %map_pin_path.display(),
            "anti-tamper: PROTECTED_PIDS pinned by-name to bpffs (PHASE_D_001)"
        );

        // BUG-011 (PHASE 15.1): pin PROTECTED_OBSERVERS by-name to
        // bpffs alongside PROTECTED_PIDS. The watchdog never reads
        // this map (it's a CONSUMER of the carve-out, not a writer),
        // so the pin is for survival-across-agent-restart only — the
        // ptrace_access_check hook needs a stable kernel object on
        // every boot. purge_stale_pin handles the leftover-pin case
        // (a prior wedged boot may have pointed at a dead map).
        let obs_pin_path = root.join(PROTECTED_OBSERVERS_MAP_NAME);
        purge_stale_pin(&obs_pin_path);
        ebpf.map_mut(PROTECTED_OBSERVERS_MAP_NAME)
            .ok_or_else(|| {
                anyhow::anyhow!("map {PROTECTED_OBSERVERS_MAP_NAME} missing from eBPF object")
            })?
            .pin(&obs_pin_path)
            .with_context(|| {
                format!(
                    "pinning {PROTECTED_OBSERVERS_MAP_NAME} to {}",
                    obs_pin_path.display()
                )
            })?;
        info!(
            map = PROTECTED_OBSERVERS_MAP_NAME,
            map_pin = %obs_pin_path.display(),
            "anti-tamper: PROTECTED_OBSERVERS pinned by-name to bpffs (BUG-011)"
        );

        // BUG-011: evict any leftover observer PIDs from prior boots.
        // A pinned map survives agent restart; without eviction a
        // recycled PID belonging to some other binary would inherit
        // observer rights. We re-verify each PID's
        // /proc/<pid>/exe against the watchdog binary on the agent's
        // refresh-timer tick (separate task in main.rs) but the
        // boot-time scrub closes the window before the first tick.
        if let Err(e) = evict_stale_observers(ebpf) {
            warn!(
                error = %e,
                "anti-tamper: stale PROTECTED_OBSERVERS eviction failed, continuing \
                 (refresh timer will catch up)"
            );
        }
    }

    // BUG-010 (PHASE 15.1): arm the PID-1 carve-out BEFORE the LSM
    // hook attaches. The hook checks `caller_tgid == 1 &&
    // KILL_OVERRIDE[0] == AGENT_SESSION[0] && != 0` — both maps must
    // be populated with the same fresh per-boot nonce or the carve-out
    // stays dormant (deny path). Doing this PRE-attach means the very
    // first hook firing already honours systemd's SIGTERM; doing it
    // POST-attach would leave a microsecond window where systemctl
    // restart could race the arming write and get denied.
    //
    // Pin both maps by-name so the slots survive agent restart (the
    // hook itself is also pinned, so a fresh agent boot's hook reads
    // the prior install's slot until we overwrite — which is exactly
    // what the session-nonce mismatch defends against).
    if let Err(e) = arm_kill_override(ebpf) {
        warn!(
            error = %e,
            "anti-tamper: KILL_OVERRIDE arming FAILED — systemctl restart will hang \
             (BUG-010 mitigation absent this boot)"
        );
    }

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

/// BUG-010 (PHASE 15.1): arm the PID-1 carve-out by writing a fresh
/// per-boot session nonce into both `KILL_OVERRIDE` and `AGENT_SESSION`.
/// The kernel hook only honours the carve-out when both slots are
/// equal AND non-zero, so:
///
/// - A stale `KILL_OVERRIDE` value pinned by a prior install does NOT
///   unlock this boot (new nonce won't match).
/// - An attacker who writes only `KILL_OVERRIDE` after boot (without
///   reading `AGENT_SESSION`) gets no match.
/// - An attacker who can write both is one who already has the kernel
///   power to unpin the LSM hook outright — V1-scope out of scope.
///
/// Both slots are also pinned by-name so they survive the agent's own
/// graceful exit; the next agent boot overwrites them before LSM
/// attach completes, so the carve-out is always "armed for this boot"
/// and never "armed for prior boot but stale."
///
/// We rely on `rand::thread_rng().next_u32()` (OS-seeded ChaCha) for
/// the nonce; predictability would only matter to an attacker who has
/// also gained BPF write privilege, in which case prediction adds
/// nothing — see Authentication discussion in
/// `docs/design/ANTITAMPER_TRUST_MODEL.md` §BUG-010.
fn arm_kill_override(ebpf: &mut Ebpf) -> Result<()> {
    // u32::MAX (4 billion) of possible nonces; collision odds across
    // an agent restart are ~2^-32 per boot. Re-roll on zero so we
    // never accidentally write the "disarmed" sentinel.
    let mut nonce: u32 = 0;
    while nonce == 0 {
        nonce = rand::thread_rng().next_u32();
    }

    // AGENT_SESSION is the "ground truth" — write it FIRST so a
    // partial-failure (AGENT_SESSION written, KILL_OVERRIDE write
    // fails) leaves the carve-out dormant (slots unequal). The
    // alternative ordering would leave a stale nonce in
    // KILL_OVERRIDE matching the prior install's AGENT_SESSION,
    // re-arming the prior carve-out unintentionally.
    write_array_u32(ebpf, AGENT_SESSION_MAP_NAME, nonce)
        .with_context(|| format!("writing {AGENT_SESSION_MAP_NAME}[0]"))?;
    write_array_u32(ebpf, KILL_OVERRIDE_MAP_NAME, nonce)
        .with_context(|| format!("writing {KILL_OVERRIDE_MAP_NAME}[0]"))?;

    // Pin both maps so the slots survive agent restart and the
    // kernel-side hook can reference one persistent map object.
    // prepare_pin_root() is idempotent / silent on the happy path;
    // None ⇒ no bpffs ⇒ skip pinning (the in-process Ebpf map still
    // works for the lifetime of this process, just won't survive
    // restart). The hook's empty-map fallback returns zero, so a
    // restart without pinning means the carve-out goes dormant after
    // the agent exits — a safer degraded mode than persisting a
    // mismatched nonce.
    if let Some(root) = prepare_pin_root() {
        for map_name in [AGENT_SESSION_MAP_NAME, KILL_OVERRIDE_MAP_NAME] {
            let map_pin_path = root.join(map_name);
            purge_stale_pin(&map_pin_path);
            ebpf.map_mut(map_name)
                .ok_or_else(|| anyhow!("map {map_name} missing from eBPF object"))?
                .pin(&map_pin_path)
                .with_context(|| format!("pinning {map_name} to {}", map_pin_path.display()))?;
        }
    }

    info!(
        kill_override = KILL_OVERRIDE_MAP_NAME,
        agent_session = AGENT_SESSION_MAP_NAME,
        "anti-tamper: KILL_OVERRIDE armed for PID-1 carve-out (BUG-010)"
    );
    Ok(())
}

/// Internal: write `value` to slot 0 of the named `Array<u32>` map
/// in `ebpf`. Wraps the aya `Array::try_from` + `set` boilerplate so
/// [`arm_kill_override`] reads as the two-line essence (AGENT_SESSION
/// first, then KILL_OVERRIDE).
fn write_array_u32(ebpf: &mut Ebpf, map_name: &str, value: u32) -> Result<()> {
    let map = ebpf
        .map_mut(map_name)
        .ok_or_else(|| anyhow!("map {map_name} missing from eBPF object"))?;
    let mut arr: AyaArray<_, u32> = AyaArray::try_from(map)
        .with_context(|| format!("{map_name} is not an Array<u32>"))?;
    arr.set(0, value, 0)
        .with_context(|| format!("setting {map_name}[0] = {value}"))?;
    Ok(())
}

/// Insert each PID into `PROTECTED_PIDS`. Watchdog W1: this is now
/// a thin wrapper over [`ProtectedPidsHandle::insert`] so the agent
/// and the watchdog share one canonical map-mutation code path.
/// `BPF_ANY` upsert semantics are preserved by the handle — an
/// entry that already exists is overwritten.
fn register_protected_pids(ebpf: &mut Ebpf, pids: &[u32]) -> Result<()> {
    let mut handle = ProtectedPidsHandle::from_ebpf(ebpf)?;
    for &pid in pids {
        handle.insert(pid)?;
    }
    Ok(())
}

/// Walk every PID currently in `PROTECTED_PIDS`. Evict any entry
/// whose PID is dead OR whose `/proc/<pid>/comm` is not in
/// `allowed_comms`. Returns the number of entries removed.
///
/// This is a no-op on a freshly-loaded eBPF object (the map is
/// empty); it becomes load-bearing once the BPF pinning sprint
/// pins the map to bpffs, at which point a restarted agent inherits
/// the prior generation's entries and must clean up stale ones
/// before the new PIDs take effect.
///
/// Watchdog W1: walk + evict now go through the
/// [`ProtectedPidsHandle`] surface. Snapshot the PID set up front
/// via [`ProtectedPidsHandle::pids`] (which materialises a `Vec`
/// internally) so the eviction loop can call
/// [`ProtectedPidsHandle::evict`] without fighting an iterator
/// borrow on the underlying map.
fn evict_stale_pids(ebpf: &mut Ebpf, allowed_comms: &HashSet<String>) -> Result<usize> {
    let mut handle = ProtectedPidsHandle::from_ebpf(ebpf)?;
    let existing = handle.pids()?;
    let mut evicted = 0usize;
    for pid in existing {
        let alive_and_matching = match read_proc_comm(pid) {
            Some(comm) => allowed_comms.contains(&comm),
            None => false,
        };
        if alive_and_matching {
            continue;
        }
        match handle.evict(pid) {
            Ok(()) => evicted += 1,
            Err(e) => warn!(
                pid, error = %e,
                "anti-tamper: failed to evict stale PID (continuing)"
            ),
        }
    }
    Ok(evicted)
}

/// BUG-011 (PHASE 15.1): boot-time scrub of PROTECTED_OBSERVERS.
///
/// On a fresh boot of an existing install, the pinned map carries
/// observer PIDs from the prior agent. Each PID was verified at
/// registration time, but PIDs are recycled — the prior watchdog
/// PID may now be some other process. Evict every entry whose
/// `/proc/<pid>/exe` does not still match the watchdog binary; the
/// refresh timer in main.rs will re-register the LIVE watchdog PID
/// on its first tick. Failure here is logged-and-tolerated: the
/// refresh timer's per-tick verification is the authoritative
/// guard, so a missed boot-time scrub at worst widens the
/// recycled-PID window from 0 to 30 seconds.
fn evict_stale_observers(ebpf: &mut Ebpf) -> Result<usize> {
    let mut handle = ProtectedObserversHandle::from_ebpf(ebpf)?;
    let existing = handle.pids()?;
    let mut evicted = 0usize;
    for pid in existing {
        // No exe check here — we don't have the expected_exe path
        // threaded through anti_tamper::attach. The refresh timer
        // in main.rs DOES do the exe check; here we evict
        // unconditionally and let the timer re-register. This is
        // the safer default: a stale-but-still-live PID with the
        // wrong exe would otherwise outlive boot.
        match handle.evict(pid) {
            Ok(()) => evicted += 1,
            Err(e) => warn!(
                pid, error = %e,
                "anti-tamper: failed to evict stale observer (continuing)"
            ),
        }
    }
    if evicted > 0 {
        info!(
            evicted,
            map = PROTECTED_OBSERVERS_MAP_NAME,
            "anti-tamper: stale observer PIDs scrubbed at boot (BUG-011)"
        );
    }
    Ok(evicted)
}

/// BUG-011 (PHASE 15.1): register `pid` as a trusted observer.
///
/// Called by the `spawn_watchdog_exempt_refresh` timer in main.rs
/// AFTER the timer has confirmed `/proc/<pid>/exe` matches the
/// installed watchdog binary via [`crate::posture::exempt::resolve_verified_watchdog_pid`].
/// Opens the pinned map by bpffs path (not the in-process Ebpf
/// handle) so the agent's tokio refresh task doesn't need a borrow
/// on the multiplexer's Ebpf instance — the timer is its own
/// independent writer.
///
/// `bpffs_root` is `None` ⇒ no bpffs ⇒ no-op (the pinning step
/// was also skipped at boot; the map only exists in-process and
/// the kernel hook has no map binding). Logs degraded-mode at
/// info; refresh continues to try every tick in case bpffs becomes
/// available (e.g. operator mounts it post-boot).
pub fn register_protected_observer(bpffs_root: Option<&Path>, pid: u32) -> Result<()> {
    let Some(root) = bpffs_root else {
        // No bpffs ⇒ no pinned map to write. The kernel hook will
        // see an empty PROTECTED_OBSERVERS and deny — watchdog
        // observation degrades, but the agent still runs.
        return Ok(());
    };
    let mut handle = ProtectedObserversHandle::open(root)
        .with_context(|| format!("opening {PROTECTED_OBSERVERS_MAP_NAME} for register"))?;
    handle.insert(pid)?;
    Ok(())
}

/// BUG-011 (PHASE 15.1): symmetric eviction. Called by the refresh
/// timer when the watchdog's verification flips from Verified back
/// to NotPresent / Unverifiable / ExeMismatch — withdraws observer
/// rights so a recycled or substituted PID can't keep them.
pub fn evict_protected_observer(bpffs_root: Option<&Path>, pid: u32) -> Result<()> {
    let Some(root) = bpffs_root else {
        return Ok(());
    };
    let mut handle = ProtectedObserversHandle::open(root)
        .with_context(|| format!("opening {PROTECTED_OBSERVERS_MAP_NAME} for evict"))?;
    handle.evict(pid)?;
    Ok(())
}

// ISSUE_002 extraction note: read_self_comm, read_proc_comm,
// lsm_pin_paths, purge_stale_pin, fresh_attach_and_pin,
// attach_transient, attach_lsm — plus their unit tests — all moved
// to `northnarrow-antitamper-bpf` and are re-exported via the
// `pub use` block at the top of this module. Functional behaviour
// is byte-identical; the only delta is the home crate.

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // ── Watchdog W6: pidfile reader + comm constant ────────────────

    /// Required W6 test 1: read_watchdog_pid_optional returns
    /// the PID when the watchdog pidfile is present and contains
    /// a valid u32 (with the canonical `<pid>\n` shape the
    /// watchdog's W2 atomic writer emits).
    #[test]
    fn read_watchdog_pid_optional_returns_pid_when_file_present() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("watchdog.pid");
        std::fs::write(&p, "4242\n").unwrap();
        assert_eq!(read_watchdog_pid_optional(&p), Some(4242));

        // No-newline shape also works (forward-compat with
        // alternate writers).
        let p2 = dir.path().join("watchdog2.pid");
        std::fs::write(&p2, "9999").unwrap();
        assert_eq!(read_watchdog_pid_optional(&p2), Some(9999));
    }

    /// Required W6 test 2: read_watchdog_pid_optional returns
    /// None — NOT an error — when the file is absent. Anchors
    /// the "agent boots without watchdog" no-op contract: a
    /// deployment that hasn't rolled out the watchdog binary
    /// MUST still boot the agent unchanged.
    #[test]
    fn read_watchdog_pid_optional_returns_none_when_file_missing() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("does-not-exist.pid");
        assert!(!p.exists());
        assert_eq!(read_watchdog_pid_optional(&p), None);
    }

    // ── Supplementary W6 tests ─────────────────────────────────────

    /// Garbage content surfaces as None (logged WARN), not an
    /// error. Documents that a corrupted pidfile degrades the
    /// agent to "no watchdog co-protection" rather than
    /// failing boot — a missing or wrong watchdog should never
    /// take the agent down.
    #[test]
    fn read_watchdog_pid_optional_returns_none_on_garbage() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("garbage.pid");
        std::fs::write(&p, "this is definitely not a pid\n").unwrap();
        assert_eq!(read_watchdog_pid_optional(&p), None);

        // Empty file also surfaces as None.
        let p2 = dir.path().join("empty.pid");
        std::fs::write(&p2, "").unwrap();
        assert_eq!(read_watchdog_pid_optional(&p2), None);

        // Whitespace-only also None.
        let p3 = dir.path().join("ws.pid");
        std::fs::write(&p3, "   \n\t\n").unwrap();
        assert_eq!(read_watchdog_pid_optional(&p3), None);
    }

    // ── BUG-010 (PHASE 15.1): kernel hook predicate documentation
    //
    // The actual LSM hook in `agent-ebpf/src/task_kill.rs` runs
    // in kernel-space and can't be reached by a userland unit test.
    // What we CAN do here is mirror the predicate as a pure Rust
    // function and assert its truth table — a regression in the
    // kernel-side hook would not be caught by this test BUT the
    // test serves as executable documentation of the security
    // contract, and a CI grep across the repo for `pid1_carveout`
    // would surface any divergence between BPF source and this
    // mirror.
    //
    // Truth table (kill_override_val, agent_session_val, caller_tgid)
    // → allow?
    //   - (0, 0, anything): deny (carve-out dormant)
    //   - (N, N, 1) where N≠0: ALLOW (PID 1 + matching nonce)
    //   - (N, N, 999): deny (not PID 1)
    //   - (1, N, 1) where N≠1: deny (attacker wrote KILL_OVERRIDE=1
    //     without knowing AGENT_SESSION's value)
    //   - (N, 0, 1): deny (AGENT_SESSION never armed; stale KILL_OVERRIDE)

    /// Mirror of the BPF `task_kill` hook's PID-1 carve-out
    /// predicate. Returns `true` ⇒ allow signal; `false` ⇒ deny.
    /// Keep in lock-step with `agent-ebpf/src/task_kill.rs`.
    fn pid1_carveout_predicate(
        caller_tgid: u32,
        kill_override_val: u32,
        agent_session_val: u32,
    ) -> bool {
        caller_tgid == 1 && kill_override_val != 0 && kill_override_val == agent_session_val
    }

    #[test]
    fn bug010_carveout_dormant_when_either_slot_zero() {
        // Default state: both slots zero (no agent has armed) → deny.
        assert!(!pid1_carveout_predicate(1, 0, 0));
        // Agent armed AGENT_SESSION but not KILL_OVERRIDE (partial
        // failure path that `arm_kill_override` orders to leave dormant
        // rather than active) → deny.
        assert!(!pid1_carveout_predicate(1, 0, 0xCAFE));
        // KILL_OVERRIDE written but AGENT_SESSION never armed (stale
        // pin from prior install) → deny.
        assert!(!pid1_carveout_predicate(1, 0xCAFE, 0));
    }

    #[test]
    fn bug010_carveout_allows_only_pid1_with_matching_nonce() {
        // Happy path: PID 1, both slots equal & non-zero → allow.
        assert!(pid1_carveout_predicate(1, 0xDEADBEEF, 0xDEADBEEF));
        // Same slots but a non-PID-1 caller → deny.
        assert!(!pid1_carveout_predicate(999, 0xDEADBEEF, 0xDEADBEEF));
        assert!(!pid1_carveout_predicate(0, 0xDEADBEEF, 0xDEADBEEF));
        assert!(!pid1_carveout_predicate(2, 0xDEADBEEF, 0xDEADBEEF));
    }

    /// ATTACK CASE: root attacker writes `KILL_OVERRIDE = 1` (a
    /// natural guess for a "boolean" override) without reading the
    /// agent's session nonce. Carve-out stays dormant.
    #[test]
    fn bug010_carveout_rejects_attacker_who_only_wrote_kill_override() {
        // Agent armed N=0xABCD; attacker writes 1 to KILL_OVERRIDE.
        // 1 != 0xABCD ⇒ no match ⇒ deny.
        assert!(!pid1_carveout_predicate(1, 1, 0xABCD));
    }

    /// ATTACK CASE: root attacker who replays a STALE KILL_OVERRIDE
    /// value from a prior install. The new agent's AGENT_SESSION is
    /// freshly random and won't match.
    #[test]
    fn bug010_carveout_rejects_stale_nonce_from_prior_install() {
        // Prior install's nonce was 0xPRIOR; the agent rebooted and
        // armed AGENT_SESSION with a fresh 0xFRESH. The pinned
        // KILL_OVERRIDE still has 0xPRIOR (we re-write at boot, but
        // imagine a window between map open and arm). The hook
        // refuses.
        assert!(!pid1_carveout_predicate(1, 0x1111_AAAA, 0xBBBB_2222));
    }

    /// Cross-crate consistency anchor: WATCHDOG_COMM must match
    /// the literal string the watchdog's W2 `harden_self` sets
    /// via prctl(PR_SET_NAME). TASK_COMM_LEN is 16 bytes
    /// (including NUL terminator), so the value fits exactly
    /// with 15 chars + NUL. A future rename of the watchdog
    /// binary that changes its prctl name MUST update this
    /// constant in lock-step, or evict_stale_pids would silently
    /// evict the watchdog's PROTECTED_PIDS entry.
    #[test]
    fn watchdog_comm_constant_is_task_comm_len_safe() {
        assert_eq!(WATCHDOG_COMM, "northnarrow-wat");
        // 15 chars + implicit NUL = 16 bytes (TASK_COMM_LEN).
        assert_eq!(WATCHDOG_COMM.len(), 15);
        assert!(
            WATCHDOG_COMM.len() < 16,
            "TASK_COMM_LEN is 16 (incl. NUL); name must be ≤15"
        );
    }
}
