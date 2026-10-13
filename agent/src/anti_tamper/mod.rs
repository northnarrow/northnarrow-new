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
//!   `KILL_GRANT`, `PTRACE_OVERRIDE`, `PROTECTED_INODES`,
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
pub mod bpf_defense;
/// BUG-036: boot-time revalidation of the compiled-in kernel struct
/// offsets against the running kernel's BTF (refuse-to-start on drift).
pub mod btf_revalidate;
pub mod combat_allow;
pub mod filesystem;
pub mod network_isolate;
/// FIM-009 self-upgrade (§15.1): userland arming path for the
/// trusted-installer FS-pin override (fills the `FS_PROTECT_OVERRIDE`
/// stub the recon flagged).
pub mod trusted_installer;

/// Test-only mint of an [`network_isolate::UnlockToken`] for unit
/// tests that exercise code paths consuming the capability (e.g.
/// `posture::admin_release_combat_with_token`). The production
/// capability invariant is unaffected — this helper is only
/// compiled under `cfg(test)`.
#[cfg(test)]
pub(crate) fn _test_mint_unlock_token() -> network_isolate::UnlockToken {
    network_isolate::mint_unlock_token()
}

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use aya::{
    maps::{Array as AyaArray, MapData},
    Btf, Ebpf,
};
use common::wire::{InodeKey, KillGrant};
use rand::RngCore;
use tracing::{debug, error, info, warn};

// ISSUE_002: bpffs root / pin / LSM-attach primitives were
// extracted from this module into the `antitamper-bpf` workspace
// crate so the forthcoming watchdog binary can consume them
// without pulling the rest of `agent`. Re-exported here so
// every pre-extraction caller (sensors/multiplexer.rs,
// filesystem.rs, main.rs, tests) keeps compiling byte-identically.
pub use antitamper_bpf::{
    attach_lsm, attach_transient, fresh_attach_and_pin, lsm_pin_paths, prepare_pin_root,
    purge_stale_pin, read_proc_comm, read_self_comm, reattach_fresh, DEFAULT_BPFFS_ROOT,
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

// The override maps (`FS_PROTECT_OVERRIDE`, `PTRACE_OVERRIDE`) and
// `KILL_GRANT` are pinned by name, so slot 0 survives an agent restart:
// [`arm_session`] rolls a fresh per-boot `AGENT_SESSION` nonce, and every
// slot is zeroed at boot and only honoured by the hooks while it carries
// that nonce.

/// Map names mirroring the `#[map] pub static …` declarations in
/// `agent-ebpf/src/task_kill.rs` (aya looks maps up by string).
/// External audit EBPF-001: `KILL_GRANT` replaces BUG-010's
/// `KILL_OVERRIDE`, which was armed at boot for the agent's whole life.
pub(crate) const KILL_GRANT_MAP_NAME: &str = "KILL_GRANT";
pub(crate) const SHUTDOWN_EXE_MAP_NAME: &str = "SHUTDOWN_EXE";
pub(crate) const AGENT_SESSION_MAP_NAME: &str = "AGENT_SESSION";
/// FIM-009 self-upgrade (§15.1): the trusted-installer FS-pin override
/// map (mirrors `#[map] pub static FS_PROTECT_OVERRIDE` in
/// `agent-ebpf/src/inode_protect.rs`). Boot-zeroed + pinned by-name in
/// [`boot_zero_fs_override`]; armed/disarmed cross-task by
/// [`trusted_installer::TrustedInstallerOverride`] via its bpffs path.
pub(crate) const FS_PROTECT_OVERRIDE_MAP_NAME: &str = "FS_PROTECT_OVERRIDE";
/// External audit EBPF-003: the ptrace override map (mirrors `#[map] pub
/// static PTRACE_OVERRIDE` in `agent-ebpf/src/ptrace_check.rs`). Boot-zeroed
/// and pinned like [`FS_PROTECT_OVERRIDE_MAP_NAME`].
const PTRACE_OVERRIDE_MAP_NAME: &str = "PTRACE_OVERRIDE";

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
/// is dead or does not run one of `keep` ([`ExeIdentity`]) is removed
/// before `pids` is inserted.
pub fn attach(ebpf: &mut Ebpf, pids: &[u32], keep: &[ExeIdentity]) -> Result<()> {
    // The agent first: the scan below reads `/proc/<pid>/exe` of protected
    // processes, which the previous agent's pinned ptrace_access_check
    // hook allows only to a protected caller. Unregistered, the agent
    // would read nothing and evict the live watchdog.
    register_protected_pids(ebpf, &[std::process::id()])
        .context("registering the agent in PROTECTED_PIDS before the stale scan")?;
    match evict_stale_pids(ebpf, keep) {
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

    // Roll this boot's session nonce, zero `KILL_GRANT` and record
    // `systemd-shutdown`'s identity BEFORE the hooks attach (pinned, so a
    // restarted agent's hooks read them too). External audit EBPF-001:
    // PID 1 no longer gets a carve-out for the agent's whole life — only
    // a grant for a signed trusted-installer window, or the final stage
    // of a shutdown.
    if let Err(e) = arm_session(ebpf) {
        warn!(
            error = %e,
            "anti-tamper: session nonce / KILL_GRANT / SHUTDOWN_EXE setup FAILED — \
             overrides and grants stay dormant this boot (systemctl stop is refused \
             even inside a trusted-installer window)"
        );
    }

    // FIM-009 self-upgrade (§15.1): boot-zero + pin FS_PROTECT_OVERRIDE
    // AFTER arm_session (which rolls AGENT_SESSION) so the override
    // starts dormant this boot and the kernel's session-nonce compare in
    // inode_protect::override_active has a fresh nonce to anchor against.
    if let Err(e) = boot_zero_fs_override(ebpf) {
        warn!(
            error = %e,
            "anti-tamper: FS_PROTECT_OVERRIDE boot-zero/pin FAILED — trusted-installer \
             override may carry a stale value this boot (FIM-009 §15.1; kernel session-nonce \
             compare still bounds any stale value to a prior boot)"
        );
    }
    // External audit EBPF-003: the same for the ptrace override. It was
    // never written nor zeroed, and the hook accepted any non-zero value:
    // one write to the pinned map lifted the ptrace protection for every
    // later agent until a reboot. A failure counts as a deny shortfall.
    let ptrace_override_zeroed = boot_zero_override(ebpf, PTRACE_OVERRIDE_MAP_NAME);
    if let Err(e) = &ptrace_override_zeroed {
        warn!(
            error = %e,
            "anti-tamper: PTRACE_OVERRIDE boot-zero/pin FAILED (the kernel's session-nonce \
             compare still keeps a stale value inert)"
        );
    }

    // `Btf::from_sys_fs()` reads `/sys/kernel/btf/vmlinux`. The Lsm
    // loader resolves `bpf_lsm_<hook>` against it to set the
    // `attach_btf_id` the kernel expects, so without it no deny hook can
    // attach. Review 53: that is the same state as every deny hook
    // failing, so it goes through the same fail-closed decision — it used
    // to be a WARN and an early `Ok`, and only the net sensor's own BTF
    // load kept such an agent from running (a tmpfs over /sys/kernel/btf
    // before a restart is enough to hide the file).
    let btf = match Btf::from_sys_fs() {
        Ok(b) => b,
        Err(e) => {
            return deny_shortfall(
                0,
                &[format!(
                    "vmlinux BTF unavailable ({e:#}) — no LSM hook can attach: kernel built \
                     without CONFIG_DEBUG_INFO_BTF, or /sys/kernel/btf hidden"
                )],
            );
        }
    };

    // Commit #2b: the bpffs root that holds the prog/link pins. Same
    // root the multiplexer handed to `map_pin_path`; `prepare_pin_root`
    // is idempotent (dir already created) and silent on the happy
    // path, so re-deriving it here keeps the change inside
    // `anti_tamper/` without threading a new param through the
    // multiplexer. `None` (no bpffs) ⇒ transient attach, no
    // persistence — `reattach_fresh` handles the degrade + log.
    let pin_root = prepare_pin_root();

    // On success `reattach_fresh` logs the disposition (re-attached fresh,
    // prior pin purged) itself — the call sites only escalate the
    // *failure* case with its operator-facing severity.
    // Audit `ebpf-lsm-1`: every deny-hook attach failure used to be a
    // lone WARN while the agent kept reporting healthy. Collect them all,
    // emit ONE aggregate health line, and fail closed by default.
    let mut deny_failures: Vec<(&'static str, String)> = Vec::new();
    if let Err(e) = ptrace_override_zeroed {
        deny_failures.push(("ptrace_override_boot_zero", format!("{e:#}")));
    }

    // Review 62: task_kill and ptrace_access_check emit their denials on
    // the FS_PROTECT_EVENTS ring (`inode_protect::emit_task_denial`), so
    // they are attached fresh every boot like the FS deny hooks (BUG-024).
    // Reusing the prior boot's pinned link kept the prior program bound
    // to the prior ring: after any agent restart, kill and ptrace attempts
    // on the agent were still denied but left no evidence.
    if let Err(e) = reattach_fresh(ebpf, TASK_KILL_PROGRAM, TASK_KILL_HOOK, &btf, pin_root) {
        warn!(
            program = TASK_KILL_PROGRAM,
            hook = TASK_KILL_HOOK,
            error = %e,
            "anti-tamper: LSM hook attach FAILED — agent killable by root"
        );
        deny_failures.push((TASK_KILL_PROGRAM, format!("{e:#}")));
    }

    if let Err(e) = reattach_fresh(ebpf, PTRACE_PROGRAM, PTRACE_HOOK, &btf, pin_root) {
        warn!(
            program = PTRACE_PROGRAM,
            hook = PTRACE_HOOK,
            error = %e,
            "anti-tamper: LSM hook attach FAILED — agent inspectable by root"
        );
        deny_failures.push((PTRACE_PROGRAM, format!("{e:#}")));
    }

    // Tappa 7 task 5: directory + inode protection. A bootstrap failure
    // (no /var/lib, read-only rootfs, permission denied even as root)
    // means EVERY FS deny hook is absent, so it is counted as a deny
    // shortfall like a verifier reject of a single hook.
    let mut observe_failures: Vec<(&'static str, String)> = Vec::new();
    match filesystem::attach(ebpf, &btf, pin_root) {
        Ok(fs) => {
            deny_failures.extend(fs.deny_failures);
            observe_failures.extend(fs.observe_failures);
        }
        Err(e) => {
            warn!(error = %e, "anti-tamper FS: bootstrap failed — no FS deny hook attached");
            deny_failures.push(("filesystem::attach", format!("{e:#}")));
        }
    }

    // BPF self-defence (Tappa 10.8): map guard (deny) + bpf() observer.
    let bd = bpf_defense::attach(ebpf, &btf, pin_root);
    deny_failures.extend(bd.deny_failures);
    observe_failures.extend(bd.observe_failures);
    // Every program is loaded now: register the agent's own object ids
    // and arm the mode. A failure leaves the guard with an empty set
    // (nothing denied) and counts as a deny-hook failure.
    match bpf_defense::register_own_objects(ebpf, pin_root) {
        Ok(o) => {
            debug!(
                maps = o.maps,
                programs = o.programs,
                links = o.links,
                pin_names = o.pin_names,
                enforce = o.enforce,
                "BPF self-defence armed"
            );
            // External audit ATP-009: a guard that only observes refuses
            // nothing; in a production build it is a missing deny hook,
            // and starts only with the degraded-mode override. (A
            // debug-trigger build observes by design; its signed boot
            // entry says so.)
            if let Some(why) =
                bpf_defense::observe_shortfall(o.enforce, cfg!(feature = "debug-trigger"))
            {
                deny_failures.push(("bpf_map_guard", why));
            }
        }
        Err(e) => {
            warn!(error = format!("{e:#}"), "BPF self-defence: own-object registration FAILED — the map guard has nothing to protect");
            deny_failures.push(("bpf_defense::register_own_objects", format!("{e:#}")));
        }
    }
    // Review entry 39: now that every pin of this boot exists, protect the
    // pin root against unlink/rename by foreign callers.
    if let Some(root) = pin_root {
        if let Err(e) = filesystem::register_bpffs_pins(ebpf, root) {
            warn!(
                error = format!("{e:#}"),
                "anti-tamper FS: bpffs pins NOT registered — the pin root stays removable by root"
            );
            deny_failures.push(("filesystem::register_bpffs_pins", format!("{e:#}")));
        }
    }
    // Review 63: every inode this boot protects is registered now; the
    // earlier boots' keys go (the map is pinned and used to fill up).
    match filesystem::prune_stale_inodes(ebpf) {
        Ok(0) => {}
        Ok(removed) => info!(
            removed,
            "anti-tamper FS: PROTECTED_INODES keys of earlier boots removed"
        ),
        Err(e) => warn!(
            error = format!("{e:#}"),
            "anti-tamper FS: PROTECTED_INODES keys of earlier boots NOT removed"
        ),
    }

    report_lsm_health(&deny_failures, &observe_failures)
}

/// Deny hooks expected on a healthy boot: task_kill + ptrace +
/// the six `inode_protect` programs.
const LSM_DENY_HOOKS_EXPECTED: usize = 2 + 6 + 1;

/// Escape hatch for a host where a deny hook is known not to attach
/// (e.g. a kernel the eBPF half has not been validated against) and the
/// operator accepts running with partial anti-tamper. Logged at ERROR on
/// every boot it is used.
pub const ALLOW_DEGRADED_ENV: &str = "NN_ANTI_TAMPER_ALLOW_DEGRADED";

/// One aggregate, machine-readable health line (audit `ebpf-lsm-1`), then
/// the fail-closed decision: any missing DENY hook refuses to start unless
/// [`ALLOW_DEGRADED_ENV`] is `1`. Missing OBSERVE hooks (module-load) are
/// reported but never fatal — no protection is absent, only R018's input.
fn report_lsm_health(
    deny_failures: &[(&'static str, String)],
    observe_failures: &[(&'static str, String)],
) -> Result<()> {
    let deny_attached = LSM_DENY_HOOKS_EXPECTED.saturating_sub(deny_failures.len());
    if deny_failures.is_empty() && observe_failures.is_empty() {
        info!(
            deny_attached,
            deny_expected = LSM_DENY_HOOKS_EXPECTED,
            "anti-tamper: all LSM hooks attached"
        );
        return Ok(());
    }
    let failed: Vec<String> = deny_failures
        .iter()
        .chain(observe_failures.iter())
        .map(|(p, e)| format!("{p}: {e}"))
        .collect();
    if deny_failures.is_empty() {
        warn!(
            deny_attached,
            deny_expected = LSM_DENY_HOOKS_EXPECTED,
            observe_failed = ?failed,
            "anti-tamper: OBSERVE HOOK SHORTFALL — module-load telemetry absent (R018 blind)"
        );
        return Ok(());
    }
    deny_shortfall(deny_attached, &failed)
}

/// The fail-closed decision on a deny-hook shortfall, shared by the
/// per-hook report and the no-BTF path (review 53): refuse to start
/// unless [`ALLOW_DEGRADED_ENV`] is `1`.
fn deny_shortfall(deny_attached: usize, failed: &[String]) -> Result<()> {
    let allow_degraded = std::env::var(ALLOW_DEGRADED_ENV)
        .map(|v| v == "1")
        .unwrap_or(false);
    error!(
        deny_attached,
        deny_expected = LSM_DENY_HOOKS_EXPECTED,
        failed = ?failed,
        allow_degraded,
        "anti-tamper: DENY HOOK SHORTFALL — a protection is silently absent"
    );
    if allow_degraded {
        error!(
            "anti-tamper: running DEGRADED because {ALLOW_DEGRADED_ENV}=1 — \
             {} of {} deny hooks attached",
            deny_attached, LSM_DENY_HOOKS_EXPECTED
        );
        return Ok(());
    }
    anyhow::bail!(
        "anti-tamper deny hook shortfall: {} of {} attached ({}). Refusing to run with a \
         silently-absent protection; set {ALLOW_DEGRADED_ENV}=1 to start degraded.",
        deny_attached,
        LSM_DENY_HOOKS_EXPECTED,
        failed.join("; ")
    )
}

/// Roll this boot's session nonce into `AGENT_SESSION`, zero
/// `KILL_GRANT`, record `systemd-shutdown` in `SHUTDOWN_EXE`, and pin
/// the three maps by name.
///
/// - Every override and grant the hooks honour must carry the nonce, so
///   a value pinned by an earlier run is dead after a restart.
/// - External audit EBPF-001: `KILL_GRANT` starts empty. PID 1 may signal
///   the agent or the watchdog only once a signed trusted-installer
///   window writes it ([`trusted_installer`]), or as `systemd-shutdown`
///   (`SHUTDOWN_EXE`, kept current by [`refresh_shutdown_exe`]).
///
/// `rand::thread_rng().next_u32()` (OS-seeded ChaCha) draws the nonce;
/// an attacker able to read it already holds BPF write privilege — see
/// `docs/design/ANTITAMPER_TRUST_MODEL.md` §BUG-010.
fn arm_session(ebpf: &mut Ebpf) -> Result<()> {
    // Re-roll on zero: zero is the "disarmed" value of every slot.
    let mut nonce: u32 = 0;
    while nonce == 0 {
        nonce = rand::thread_rng().next_u32();
    }
    write_array_u32(ebpf, AGENT_SESSION_MAP_NAME, nonce)
        .with_context(|| format!("writing {AGENT_SESSION_MAP_NAME}[0]"))?;
    {
        let map = ebpf
            .map_mut(KILL_GRANT_MAP_NAME)
            .ok_or_else(|| anyhow!("map {KILL_GRANT_MAP_NAME} missing from eBPF object"))?;
        let mut arr: AyaArray<_, AyaKillGrant> = AyaArray::try_from(map)
            .with_context(|| format!("{KILL_GRANT_MAP_NAME} is not an Array<KillGrant>"))?;
        arr.set(0, AyaKillGrant(KillGrant::default()), 0)
            .with_context(|| format!("zeroing {KILL_GRANT_MAP_NAME}[0]"))?;
    }
    let shutdown = shutdown_exe_key();
    {
        let map = ebpf
            .map_mut(SHUTDOWN_EXE_MAP_NAME)
            .ok_or_else(|| anyhow!("map {SHUTDOWN_EXE_MAP_NAME} missing from eBPF object"))?;
        let mut arr: AyaArray<_, filesystem::AyaInodeKey> = AyaArray::try_from(map)
            .with_context(|| format!("{SHUTDOWN_EXE_MAP_NAME} is not an Array<InodeKey>"))?;
        arr.set(
            0,
            filesystem::AyaInodeKey(shutdown.unwrap_or(InodeKey { dev: 0, ino: 0 })),
            0,
        )
        .with_context(|| format!("writing {SHUTDOWN_EXE_MAP_NAME}[0]"))?;
    }

    // Pinned so a restarted agent's hooks — and `trusted_installer`,
    // through the bpffs path — use the same kernel objects. No bpffs:
    // the in-process maps serve this run only.
    if let Some(root) = prepare_pin_root() {
        for map_name in [
            AGENT_SESSION_MAP_NAME,
            KILL_GRANT_MAP_NAME,
            SHUTDOWN_EXE_MAP_NAME,
        ] {
            let map_pin_path = root.join(map_name);
            purge_stale_pin(&map_pin_path);
            ebpf.map_mut(map_name)
                .ok_or_else(|| anyhow!("map {map_name} missing from eBPF object"))?
                .pin(&map_pin_path)
                .with_context(|| format!("pinning {map_name} to {}", map_pin_path.display()))?;
        }
    }

    info!(
        systemd_shutdown = ?shutdown.map(|k| (k.dev, k.ino)),
        "anti-tamper: session armed — PID 1 may signal the agent only inside a signed \
         trusted-installer window or as systemd-shutdown (external audit EBPF-001)"
    );
    Ok(())
}

/// Where `systemd-shutdown` lives (merged `/usr` makes the two one file).
const SHUTDOWN_EXE_PATHS: &[&str] = &[
    "/usr/lib/systemd/systemd-shutdown",
    "/lib/systemd/systemd-shutdown",
];

/// `(dev, ino)` of `systemd-shutdown` in the kernel's `s_dev` encoding,
/// or `None` on a host without it (no systemd: no carve-out needed).
fn shutdown_exe_key() -> Option<InodeKey> {
    use std::os::unix::fs::MetadataExt;
    SHUTDOWN_EXE_PATHS.iter().find_map(|p| {
        std::fs::metadata(p).ok().map(|m| InodeKey {
            dev: filesystem::stat_dev_to_kernel_dev(m.dev()),
            ino: m.ino(),
        })
    })
}

/// External audit EBPF-001: keep `SHUTDOWN_EXE` on the file a shutdown
/// would run — a systemd upgrade replaces `systemd-shutdown` (new inode),
/// and a stale identity would make the final stage's SIGTERM wait out
/// its timeout. Returns the new identity when it changed.
pub fn refresh_shutdown_exe(bpffs_root: &Path) -> Result<Option<InodeKey>> {
    let want = shutdown_exe_key().unwrap_or(InodeKey { dev: 0, ino: 0 });
    let pin_path = bpffs_root.join(SHUTDOWN_EXE_MAP_NAME);
    let map_data = MapData::from_pin(&pin_path).with_context(|| {
        format!(
            "opening pinned {SHUTDOWN_EXE_MAP_NAME} at {}",
            pin_path.display()
        )
    })?;
    let mut arr: AyaArray<_, filesystem::AyaInodeKey> =
        AyaArray::try_from(aya::maps::Map::Array(map_data))
            .with_context(|| format!("{SHUTDOWN_EXE_MAP_NAME} is not an Array<InodeKey>"))?;
    let have = arr.get(&0, 0).map(|k| k.0).ok();
    if have == Some(want) {
        return Ok(None);
    }
    arr.set(0, filesystem::AyaInodeKey(want), 0)
        .with_context(|| format!("writing {SHUTDOWN_EXE_MAP_NAME}[0]"))?;
    Ok(Some(want))
}

/// aya view of [`KillGrant`].
#[repr(transparent)]
#[derive(Clone, Copy)]
pub(crate) struct AyaKillGrant(pub(crate) KillGrant);

// SAFETY: `KillGrant` is `#[repr(C)]` over u32, u32, u64 — no padding,
// every bit pattern valid; `AyaKillGrant` is `#[repr(transparent)]`.
unsafe impl aya::Pod for AyaKillGrant {}

/// FIM-009 self-upgrade (§15.1): boot-zero + pin the trusted-installer
/// FS-pin override map. Writing slot 0 to zero on every boot guarantees
/// the override NEVER survives a restart — the exact caveat the original
/// `FS_PROTECT_OVERRIDE` stub flagged ("must be zeroed on boot"). A
/// grant must be re-presented after a reboot. Pinning by-name lets the
/// `trusted_installer` userland arm/disarm the SAME kernel object via
/// its bpffs path after boot, without re-borrowing the `Ebpf` instance.
///
/// MUST run after [`arm_session`] (which rolls AGENT_SESSION): the
/// kernel `override_active` compares `FS_PROTECT_OVERRIDE[0]` against the
/// session nonce, so a fresh nonce must already be in place.
fn boot_zero_fs_override(ebpf: &mut Ebpf) -> Result<()> {
    boot_zero_override(ebpf, FS_PROTECT_OVERRIDE_MAP_NAME)
}

/// Zero slot 0 of the override map `map_name` and pin it by name, so an
/// override never survives a restart and userland can arm it through its
/// bpffs path. Runs after [`arm_session`]: the hooks compare the
/// slot against the fresh session nonce.
fn boot_zero_override(ebpf: &mut Ebpf, map_name: &'static str) -> Result<()> {
    write_array_u32(ebpf, map_name, 0).with_context(|| format!("boot-zeroing {map_name}[0]"))?;

    if let Some(root) = prepare_pin_root() {
        let map_pin_path = root.join(map_name);
        purge_stale_pin(&map_pin_path);
        ebpf.map_mut(map_name)
            .ok_or_else(|| anyhow!("map {map_name} missing from eBPF object"))?
            .pin(&map_pin_path)
            .with_context(|| format!("pinning {map_name} to {}", map_pin_path.display()))?;
    }

    info!(
        map = map_name,
        "anti-tamper: override map boot-zeroed + pinned"
    );
    Ok(())
}

/// Internal: write `value` to slot 0 of the named `Array<u32>` map
/// in `ebpf`.
fn write_array_u32(ebpf: &mut Ebpf, map_name: &str, value: u32) -> Result<()> {
    let map = ebpf
        .map_mut(map_name)
        .ok_or_else(|| anyhow!("map {map_name} missing from eBPF object"))?;
    let mut arr: AyaArray<_, u32> =
        AyaArray::try_from(map).with_context(|| format!("{map_name} is not an Array<u32>"))?;
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

/// A program's identity: the device and inode of its executable — what
/// `/proc/<pid>/exe` of a process running it resolves to, whatever the
/// process calls itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExeIdentity {
    pub dev: u64,
    pub ino: u64,
}

impl ExeIdentity {
    /// The file at `path` (symlinks followed).
    pub fn of_file(path: &Path) -> Option<Self> {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).ok().map(|m| Self {
            dev: m.dev(),
            ino: m.ino(),
        })
    }

    /// The program `pid` runs; `None` when it is gone or unreadable.
    pub fn of_process(pid: u32) -> Option<Self> {
        Self::of_file(Path::new(&format!("/proc/{pid}/exe")))
    }
}

/// Walk every PID currently in `PROTECTED_PIDS` and evict any entry
/// that is dead or does not run one of `keep` (the agent's and the
/// watchdog's executables).
///
/// External audit ATP-002: the check used to be `/proc/<pid>/comm`
/// against `{agent comm, "northnarrow-wat"}`. A process names itself
/// (`prctl(PR_SET_NAME)`), so one that landed on a recycled pid left in
/// the pinned map kept the entry across agent restarts — immunity to
/// kill and ptrace, and exemption from every inode deny hook.
///
/// Snapshot the PID set up front via [`ProtectedPidsHandle::pids`] (which
/// materialises a `Vec` internally) so the eviction loop can call
/// [`ProtectedPidsHandle::evict`] without fighting an iterator borrow on
/// the underlying map.
fn evict_stale_pids(ebpf: &mut Ebpf, keep: &[ExeIdentity]) -> Result<usize> {
    let mut handle = ProtectedPidsHandle::from_ebpf(ebpf)?;
    let existing = handle.pids()?;
    let mut evicted = 0usize;
    for pid in existing {
        if ExeIdentity::of_process(pid).is_some_and(|id| keep.contains(&id)) {
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

/// Insert `pid` into the pinned `PROTECTED_PIDS` (a watchdog the agent
/// verified). No bpffs ⇒ no pinned map ⇒ no-op.
pub fn register_protected_pid(bpffs_root: Option<&Path>, pid: u32) -> Result<()> {
    let Some(root) = bpffs_root else {
        return Ok(());
    };
    let mut handle = ProtectedPidsHandle::open(root)
        .with_context(|| format!("opening {PROTECTED_PIDS_MAP_NAME} for register"))?;
    handle.insert(pid)?;
    Ok(())
}

/// External audit EBPF-002: record the verified watchdog `pid` as the live
/// watchdog in the pinned `ROLE_TGIDS` (it records itself too; this covers
/// a watchdog that started before the agent pinned the map). No bpffs ⇒
/// no-op.
pub fn claim_watchdog_role(bpffs_root: Option<&Path>, pid: u32) -> Result<()> {
    let Some(root) = bpffs_root else {
        return Ok(());
    };
    antitamper_bpf::claim_role(root, antitamper_bpf::ROLE_SLOT_WATCHDOG, pid)
}

/// Remove `pid` from the pinned `PROTECTED_PIDS` (external audit
/// MAIN-001: a watchdog pid that no longer runs the watchdog binary).
/// No bpffs ⇒ no pinned map ⇒ no-op.
pub fn evict_protected_pid(bpffs_root: Option<&Path>, pid: u32) -> Result<()> {
    let Some(root) = bpffs_root else {
        return Ok(());
    };
    let mut handle = ProtectedPidsHandle::open(root)
        .with_context(|| format!("opening {PROTECTED_PIDS_MAP_NAME} for evict"))?;
    handle.evict(pid)?;
    Ok(())
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

    /// External audit ATP-002: a protected pid is told by the file it
    /// runs, not by the name it gives itself.
    #[test]
    fn exe_identity_is_the_file_a_process_runs() {
        let me = ExeIdentity::of_process(std::process::id()).expect("own exe");
        assert_eq!(Some(me), ExeIdentity::of_file(Path::new("/proc/self/exe")));
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("5")
            .spawn()
            .unwrap();
        // `spawn` can return before the child has exec'd.
        let want = ExeIdentity::of_file(Path::new("/bin/sleep"));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while ExeIdentity::of_process(child.id()) != want {
            assert!(std::time::Instant::now() < deadline, "never exec'd sleep");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let other = ExeIdentity::of_process(child.id());
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(other, ExeIdentity::of_file(Path::new("/bin/sleep")));
        assert_ne!(other, Some(me));
        assert_eq!(ExeIdentity::of_process(u32::MAX), None);
    }
    use tempfile::TempDir;

    /// Review 53: the no-BTF path and a per-hook shortfall share one
    /// decision — refuse to start without the explicit degraded opt-in,
    /// naming the cause.
    #[test]
    fn deny_shortfall_refuses_without_the_degraded_opt_in() {
        if std::env::var(ALLOW_DEGRADED_ENV).as_deref() == Ok("1") {
            return; // a dev shell that opted in; nothing to assert here
        }
        let err = deny_shortfall(0, &["vmlinux BTF unavailable (test)".to_string()])
            .expect_err("a deny-hook shortfall must refuse to start");
        let msg = format!("{err:#}");
        assert!(msg.contains("0 of"), "{msg}");
        assert!(msg.contains("vmlinux BTF unavailable"), "{msg}");
        assert!(msg.contains(ALLOW_DEGRADED_ENV), "{msg}");
    }

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

    /// External audit EBPF-001: the grant the agent writes for a window
    /// lets PID 1 stop the units (the predicate itself is tested with
    /// `KillGrant` in `northnarrow_common`), and `systemd-shutdown` is
    /// found where systemd installs it.
    #[test]
    fn the_window_grant_covers_systemds_stop_signals() {
        let g = KillGrant {
            nonce: 7,
            sig_mask: KillGrant::STOP_SIGNALS,
            expires_ns: u64::MAX,
        };
        for (sig, what) in [
            (15, "KillSignal"),
            (18, "SIGCONT after it"),
            (9, "FinalKillSignal"),
        ] {
            assert!(g.allows(sig, 0, 7), "{what} must be granted");
        }
        assert!(!g.allows(19, 0, 7), "SIGSTOP is never part of a stop");
        assert_eq!(
            std::mem::size_of::<KillGrant>(),
            16,
            "the eBPF map value and the userland view must agree"
        );
        assert!(SHUTDOWN_EXE_PATHS
            .iter()
            .all(|p| p.ends_with("/systemd-shutdown")));
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
