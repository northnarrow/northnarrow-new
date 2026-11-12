//! Lot 273: the protected units' cgroups — the agent's half.
//!
//! On systemd 257 and later `systemctl kill -s SIGKILL` of the agent ends
//! in a write to its unit's `cgroup.kill` once the `task_kill` hook refused
//! the signal to the main process: the kernel kills the cgroup, and no hook
//! saw a signal. Any root shell can do the same, or freeze the unit through
//! `cgroup.freeze`, or move the agent to a cgroup of its own and kill that
//! one. This module closes the three:
//!
//! * the unit cgroups of the agent and of the watchdog (and their ancestor
//!   slices' kill and freeze) go into `PROTECTED_INODES`
//!   ([`antitamper_bpf::cgroup_guard`] says which inode with which flags):
//!   a write-open of `cgroup.kill` / `cgroup.freeze` is refused and signed
//!   `cgroup_kill` / `cgroup_freeze`, a child cgroup, a `chown` and an
//!   `rmdir` (but PID 1's) of the unit's directory are refused;
//! * the move guard — `cgroup_move_stash` (fexit
//!   `cgroup_procs_write_start`) and `cgroup_move_deny` (LSM
//!   `inode_permission`) — refuses moving a protected process to another
//!   cgroup, signed `cgroup_move`.
//!
//! Outside a signed trusted-installer window only; inside one, the hooks
//! refuse nothing (an upgrade's or an uninstall's `systemctl kill -s
//! SIGKILL` writes `cgroup.kill` on systemd 257). Host shutdown is not
//! touched: systemd stops the units through signals, which `systemd-shutdown`
//! delivers at the end, and its removal of the empty unit cgroups is let
//! through (`FS_PROTECT_INIT_RMDIR`).
//!
//! The move guard is an optional deny set: attached where the kernel's
//! BTF has `cgroup_procs_write_start` in the shape the fexit reads and
//! `cgroup_file_write` (every kernel from 5.14), and signed degraded where
//! it has not. Lot 273b: its third program, `cgroup_move_clear`, drops a
//! thread's stashed move when the write ends — lot 303: at the return of
//! `cgroup_file_write` (fexit), the kernfs `write` operation of every
//! cgroup file, which no compiler can inline; lot 273b's fentry on
//! `cgroup_procs_write_finish` saw no cgroup v2 write on 7.0, which inlines
//! that function into its v2 caller, and a write the DAC refused left its
//! record for the thread's next check (the nightly's 7.0 guest: the
//! thread's own move refused). The stash is a map that
//! never evicts; the refusal consumes a stashed move only on a cgroup v2
//! `cgroup.procs` / `cgroup.threads`; and the boot's self-test checks the
//! guard refuses a move (`agent/src/boot/deny_selftest.rs`).
//!
//! Lot 273b also enters the units' and slices' directories with
//! `FS_PROTECT_LIMIT_DIR` (their resource files refused but PID 1's, whose
//! write must put back the value registered in `LIMIT_VALUES`), and arms the
//! refusal of cgroup v1 writes where systemd runs the unified hierarchy
//! only ([`arm_v1_policy`]).

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use aya::maps::{Array as AyaArray, HashMap as AyaHashMap, MapData};
use aya::{Btf, Ebpf};
use common::btf_offsets::{CGROUP_MOVE_FINISH, CGROUP_MOVE_TARGET};
use common::cgroup_limits::LimitValue;
use common::wire::{InodeKey, CGROUP_POLICY_V1_REFUSE};
use tracing::{info, warn};

pub use antitamper_bpf::cgroup_guard::{UnitCgroup, V1Policy};
use antitamper_bpf::cgroup_guard::{CGROUP_POLICY_MAP_NAME, LIMIT_VALUES_MAP_NAME};

/// The move guard's lookup half and the kernel function it is attached to
/// (its pins carry the function's name: `prog_cgroup_procs_write_start`,
/// `link_cgroup_procs_write_start`).
pub(crate) const MOVE_STASH_PROGRAM: &str = "cgroup_move_stash";
pub const MOVE_STASH_HOOK: &str = CGROUP_MOVE_TARGET.func;
/// The move guard's refusal half and its LSM hook.
pub(crate) const MOVE_DENY_PROGRAM: &str = "cgroup_move_deny";
pub const MOVE_DENY_HOOK: &str = "inode_permission";

/// Lot 273b: the move guard's third program, which drops a thread's
/// stashed move when the write ends, and its kernel function (lot 303:
/// `cgroup_file_write`, fexit).
pub(crate) const MOVE_CLEAR_PROGRAM: &str = "cgroup_move_clear";
pub const MOVE_CLEAR_HOOK: &str = CGROUP_MOVE_FINISH;
/// Lot 303: the function lot 273b's agents attached the clear to (fentry):
/// a pin of theirs (`prog_` / `link_cgroup_procs_write_finish`) goes at
/// this start, as a prior boot's pins of a hook do.
pub(crate) const MOVE_CLEAR_LEGACY_HOOK: &str = "cgroup_procs_write_finish";

/// The three "hooks" of the move guard, as `OPTIONAL_DENY_HOOKS` names them.
pub const GUARD_HOOKS: [&str; 3] = [MOVE_DENY_HOOK, MOVE_STASH_HOOK, MOVE_CLEAR_HOOK];

/// What is lost when the move guard is not attached.
pub const MOVE_GUARD_ABSENT_EFFECT: &str =
    "the cgroup move guard is not attached: a protected process can be moved out of its \
     unit's cgroup (and killed or frozen through the new one)";

/// How the move guard counted this boot.
#[derive(Debug, Default)]
pub(crate) struct MoveGuardHealth {
    /// The guard's hooks this kernel has (0 or 3): expected deny hooks.
    pub present: usize,
    /// `(program, why)` of a program that the kernel has a hook for and
    /// that did not load or attach: deny-hook shortfalls.
    pub failures: Vec<(&'static str, String)>,
    /// Why the guard is not attached at all on this kernel (its attach
    /// point is absent or of another shape): a signed degradation.
    pub absent: Option<String>,
}

/// Attach the move guard: the refusal half first (it refuses nothing until
/// the lookup half records a move), then (lot 273b) the program that drops
/// a record at the end of the write, then the lookup half — each attached
/// fresh before the prior boot's pins go ([`super::reattach_fresh`]).
pub(crate) fn attach_move_guard(
    ebpf: &mut Ebpf,
    btf: &Btf,
    pin_root: Option<&Path>,
) -> MoveGuardHealth {
    let mut health = MoveGuardHealth::default();
    let in_btf = super::btf_revalidate::optional_hook_in_kernel(MOVE_STASH_HOOK);
    if in_btf == Some(false) {
        let why = super::btf_revalidate::resolved()
            .and_then(|r| r.cgroup_move_target_mismatch())
            .map(str::to_string)
            .unwrap_or_else(|| format!("the kernel's BTF has no {}", CGROUP_MOVE_TARGET.func));
        warn!(reason = %why, effect = MOVE_GUARD_ABSENT_EFFECT, "anti-tamper cgroup: move guard not attached");
        // A prior boot's pins of the pair go too: a program of an older
        // agent must not stay attached where this one would not attach.
        if let Some(root) = pin_root {
            for hook in GUARD_HOOKS.iter().chain([&MOVE_CLEAR_LEGACY_HOOK]) {
                let (prog, link) = antitamper_bpf::lsm_pin_paths(root, hook);
                antitamper_bpf::purge_stale_pin(&link);
                antitamper_bpf::purge_stale_pin(&prog);
            }
        }
        health.absent = Some(why);
        return health;
    }
    health.present = GUARD_HOOKS.len();
    if let Err(e) = super::reattach_fresh(ebpf, MOVE_DENY_PROGRAM, MOVE_DENY_HOOK, btf, pin_root) {
        warn!(program = MOVE_DENY_PROGRAM, hook = MOVE_DENY_HOOK, error = %format!("{e:#}"), "anti-tamper cgroup: LSM hook attach FAILED");
        health.failures.push((MOVE_DENY_PROGRAM, format!("{e:#}")));
        // Without the refusal half the lookup half refuses nothing: not
        // attached either, and counted missing.
        health.failures.push((
            MOVE_CLEAR_PROGRAM,
            "not attached: its refusal half did not attach".into(),
        ));
        health.failures.push((
            MOVE_STASH_PROGRAM,
            "not attached: its refusal half did not attach".into(),
        ));
        return health;
    }
    // Lot 303: an older agent's clear (fentry, pinned under its function's
    // name) goes first: this one is attached elsewhere.
    if let Some(root) = pin_root {
        let (prog, link) = antitamper_bpf::lsm_pin_paths(root, MOVE_CLEAR_LEGACY_HOOK);
        antitamper_bpf::purge_stale_pin(&link);
        antitamper_bpf::purge_stale_pin(&prog);
    }
    if let Err(e) = antitamper_bpf::reattach_fresh_fexit(
        ebpf,
        MOVE_CLEAR_PROGRAM,
        MOVE_CLEAR_HOOK,
        btf,
        pin_root,
    ) {
        warn!(program = MOVE_CLEAR_PROGRAM, function = MOVE_CLEAR_HOOK, error = %format!("{e:#}"), "anti-tamper cgroup: fexit attach FAILED");
        health.failures.push((MOVE_CLEAR_PROGRAM, format!("{e:#}")));
        // Without it a record a write left behind would stay: the lookup
        // half is not attached either (the refusal half alone refuses
        // nothing).
        health.failures.push((
            MOVE_STASH_PROGRAM,
            "not attached: the program that clears its records did not attach".into(),
        ));
        return health;
    }
    if let Err(e) = antitamper_bpf::reattach_fresh_fexit(
        ebpf,
        MOVE_STASH_PROGRAM,
        MOVE_STASH_HOOK,
        btf,
        pin_root,
    ) {
        warn!(program = MOVE_STASH_PROGRAM, function = MOVE_STASH_HOOK, error = %format!("{e:#}"), "anti-tamper cgroup: fexit attach FAILED");
        health.failures.push((MOVE_STASH_PROGRAM, format!("{e:#}")));
    }
    health
}

/// What the registration of the unit cgroups found, for the journal and
/// the signed chain.
#[derive(Debug, Default)]
pub(crate) struct CgroupRegistration {
    /// `(pid, cgroup, entries)` of each process whose unit cgroup is
    /// protected now.
    pub protected: Vec<(u32, String, usize)>,
    /// Why a process's cgroup could not be protected (no cgroup v2, an
    /// unreadable cgroup): a signed degradation.
    pub unavailable: Vec<(u32, String)>,
}

/// Register the unit cgroups of `pids` (the agent and the watchdog) in
/// `PROTECTED_INODES` through the boot's registration (its keys survive
/// the stale-key prune). A process outside a systemd service's cgroup (a
/// privileged test, an agent started by hand) is left alone.
pub(crate) fn register_unit_cgroups(ebpf: &mut Ebpf, pids: &[u32]) -> Result<CgroupRegistration> {
    let mut out = CgroupRegistration::default();
    for &pid in pids {
        match antitamper_bpf::cgroup_guard::unit_cgroup_of(pid) {
            UnitCgroup::Service {
                cgroup,
                entries,
                values,
            } => {
                for e in &entries {
                    super::filesystem::register_cgroup_inode(ebpf, &e.key, e.flags)?;
                }
                for f in &values {
                    register_value(ebpf, &f.key, &f.value)?;
                }
                // Lot 273c (the review of #490): a value below its floor —
                // the fresh cgroup's, systemd's copy of a refused
                // `set-property` — replaced by the floor: registered, written,
                // read back; reported at the integrity check.
                let unit = UnitCgroup::Service {
                    cgroup: cgroup.clone(),
                    entries: entries.clone(),
                    values: Vec::new(),
                };
                let due = antitamper_bpf::cgroup_floors::floors_due(
                    &antitamper_bpf::cgroup_guard::limit_dirs(&unit),
                );
                if !due.is_empty() {
                    let restores = antitamper_bpf::cgroup_floors::restore_floors(due, |k, v| {
                        register_value(ebpf, k, v)
                    });
                    for r in &restores {
                        warn!(detail = %r.detail(), "anti-tamper cgroup: a resource value below its floor");
                    }
                    antitamper_bpf::cgroup_floors::note_restores(&restores);
                }
                info!(
                    pid,
                    cgroup = %nn_model::log_escape::Escaped(&cgroup),
                    entries = entries.len(),
                    values = values.len(),
                    "anti-tamper cgroup: unit cgroup registered in PROTECTED_INODES (kill, freeze, \
                     resource limits, child cgroups and rmdir refused outside a trusted-installer \
                     window)"
                );
                remember_unit(&cgroup);
                out.protected.push((pid, cgroup, entries.len()));
            }
            UnitCgroup::NotAService { cgroup } => info!(
                pid,
                cgroup = %nn_model::log_escape::Escaped(&cgroup),
                "anti-tamper cgroup: not a systemd service's cgroup — not protected"
            ),
            UnitCgroup::Unavailable { why } => {
                warn!(pid, reason = %why, "anti-tamper cgroup: unit cgroup NOT protected");
                out.unavailable.push((pid, why));
            }
        }
    }
    Ok(out)
}

/// Lot 273b: the unit cgroups this agent registered (its own and the
/// watchdog's at the attach, the watchdog's at a verified restart), for
/// [`refresh_values`].
static REGISTERED_UNITS: parking_lot::Mutex<Vec<String>> = parking_lot::Mutex::new(Vec::new());

fn remember_unit(cgroup: &str) {
    let mut units = REGISTERED_UNITS.lock();
    if !units.iter().any(|u| u == cgroup) {
        units.push(cgroup.to_string());
    }
}

/// Lot 273b: at the close of a trusted-installer window, the values the
/// registered units' resource files (and their slices') hold now, into
/// `LIMIT_VALUES`: a change made inside the window (`systemctl
/// set-property`) is then the value PID 1 writes back when it realises the
/// unit again (a reload), not a refusal. The window's grant is zeroed
/// first: nothing but PID 1's write of these values changes them after.
/// The number of values registered; `0` without a bpffs.
pub fn refresh_values(bpffs_root: Option<&Path>) -> usize {
    let Some(root) = bpffs_root else {
        return 0;
    };
    let units = REGISTERED_UNITS.lock().clone();
    let mut n = 0;
    for cgroup in &units {
        match antitamper_bpf::cgroup_guard::refresh_unit_values(root, cgroup) {
            Ok(k) => n += k,
            Err(e) => warn!(
                cgroup = %nn_model::log_escape::Escaped(cgroup),
                error = %format!("{e:#}"),
                "anti-tamper cgroup: the values of a unit's resource files NOT registered again \
                 at the window's close — systemd's next write of a value changed inside it is \
                 refused"
            ),
        }
    }
    if n > 0 {
        info!(
            values = n,
            units = units.len(),
            "anti-tamper cgroup: the units' resource values registered again at the window's \
             close (a change made inside it is what systemd may write back)"
        );
    }
    n
}

/// Lot 273d (the review of #492): after a confirmed reload, each file this
/// agent restored to its floor goes back to its configured value — the
/// unit's property in systemd's copy, now the unit's files — when that
/// value is not below the floor: written (the agent is exempt), then the
/// units' values registered again ([`refresh_values`]), so that PID 1's
/// next write of the configured value is let through. Before, the floor
/// stayed until the next window's close. Returns one line per file moved.
pub fn back_to_configured(bpffs_root: Option<&Path>, socket: &Path) -> Vec<String> {
    use antitamper_bpf::cgroup_floors::{at_floor, below_floor, floor_of, floor_role, left_floor};
    let mut moved = Vec::new();
    for path in at_floor() {
        let configured = match antitamper_bpf::unit_props::configured_text(
            socket,
            std::time::Duration::from_secs(5),
            &path,
        ) {
            Ok(Some(v)) => v,
            Ok(None) => {
                left_floor(&path);
                continue;
            }
            Err(e) => {
                warn!(path = %path.display(), error = %e, "anti-tamper cgroup: the configured value of a file at its floor not read");
                continue;
            }
        };
        let (Some(dir), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str()))
        else {
            continue;
        };
        let Some(floor) = floor_of(floor_role(dir), name) else {
            left_floor(&path);
            continue;
        };
        if below_floor(
            common::cgroup_limits::limit_kind_of(name),
            &configured,
            &floor,
        ) {
            // the units' files set it below: the floor stays
            continue;
        }
        let current = std::fs::read_to_string(&path).unwrap_or_default();
        if current.trim() != configured {
            if let Err(e) = std::fs::write(&path, format!("{configured}\n")) {
                warn!(path = %path.display(), error = %e, "anti-tamper cgroup: a file at its floor NOT put back to its configured value");
                continue;
            }
            moved.push(format!(
                "{}: back from its floor {:?} to the configured {:?}",
                path.display(),
                current.trim(),
                configured
            ));
        }
        left_floor(&path);
    }
    if !moved.is_empty() {
        refresh_values(bpffs_root);
        info!(files = moved.len(), "anti-tamper cgroup: files at their floors back at their configured values after a confirmed reload");
    }
    moved
}

/// Lot 273b: the values this boot registered, for [`prune_stale_values`].
static BOOT_VALUE_KEYS: parking_lot::Mutex<Option<std::collections::HashSet<(u64, u64)>>> =
    parking_lot::Mutex::new(None);

fn values_map(ebpf: &mut Ebpf) -> Result<AyaHashMap<&mut MapData, ValueKey, LimitValue>> {
    let map = ebpf
        .map_mut(LIMIT_VALUES_MAP_NAME)
        .ok_or_else(|| anyhow!("map {LIMIT_VALUES_MAP_NAME} missing from eBPF object"))?;
    AyaHashMap::try_from(map)
        .with_context(|| format!("{LIMIT_VALUES_MAP_NAME} is not a HashMap<InodeKey, [u64; 4]>"))
}

/// `LIMIT_VALUES`'s key, as the map stores it.
#[repr(transparent)]
#[derive(Clone, Copy)]
struct ValueKey(InodeKey);
// SAFETY: `InodeKey` is `#[repr(C)]`, two `u64`, no padding.
unsafe impl aya::Pod for ValueKey {}

/// Lot 273b: the value of a resource file into `LIMIT_VALUES` (kept by the
/// stale-key prune).
fn register_value(ebpf: &mut Ebpf, key: &InodeKey, value: &LimitValue) -> Result<()> {
    values_map(ebpf)?
        .insert(ValueKey(*key), *value, 0)
        .with_context(|| {
            format!(
                "inserting the value of (dev={}, ino={}) into {LIMIT_VALUES_MAP_NAME}",
                key.dev, key.ino
            )
        })?;
    BOOT_VALUE_KEYS
        .lock()
        .get_or_insert_with(Default::default)
        .insert((key.dev, key.ino));
    Ok(())
}

/// Lot 273b: remove every `LIMIT_VALUES` key this boot has not registered
/// (earlier boots' unit cgroups, gone with their restart), as
/// `filesystem::prune_stale_inodes` does for `PROTECTED_INODES`. The
/// number removed.
pub(crate) fn prune_stale_values(ebpf: &mut Ebpf) -> Result<usize> {
    let keep = BOOT_VALUE_KEYS.lock().clone().unwrap_or_default();
    let mut map = values_map(ebpf)?;
    let stale: Vec<ValueKey> = map
        .keys()
        .filter_map(|k| k.ok())
        .filter(|k| !keep.contains(&(k.0.dev, k.0.ino)))
        .collect();
    for k in &stale {
        let _ = map.remove(k);
    }
    Ok(stale.len())
}

/// Lot 273b: the processes whose unit cgroups the attach registers — the
/// boot's (`boot`: the agent, and a watchdog it was handed) and every live
/// `PROTECTED_PIDS` entry (`live`) that runs one of the installed binaries
/// (`installed(pid)`): the watchdog, which registered its own cgroup at its
/// start, and whose keys this boot's prune would drop otherwise.
pub(crate) fn cgroup_pids(boot: &[u32], live: &[u32], installed: impl Fn(u32) -> bool) -> Vec<u32> {
    let mut out: Vec<u32> = boot.to_vec();
    for &pid in live {
        if !out.contains(&pid) && installed(pid) {
            out.push(pid);
        }
    }
    out
}

/// Lot 273b: write [`V1Policy`] into the pinned `CGROUP_POLICY` — refuse
/// cgroup v1 writes outside a window where this host's systemd runs the
/// unified hierarchy only. The policy, for the journal and the signed
/// degradations.
pub(crate) fn arm_v1_policy(ebpf: &mut Ebpf, pin_root: Option<&Path>) -> Result<V1Policy> {
    let unified = antitamper_bpf::cgroup_guard::cgroup2_root()
        .is_some_and(|p| p == Path::new(antitamper_bpf::cgroup_guard::CGROUP2_MOUNTS[0]));
    // lot 311 (bug hunt 1.4, F4): read as bytes — a user's FUSE mount named
    // with bytes that are not UTF-8 made the table unreadable, and the
    // policy was judged on an empty one; a table that cannot be read at
    // all is said so (the policy then sees no v1 hierarchy: the stricter
    // answer where systemd runs the unified one)
    let mountinfo = match crate::state_read::read_state("/proc/self/mountinfo") {
        Ok(text) => text,
        Err(e) => {
            crate::state_read::LastGood::new("cgroup_guard", "the mount table").failed(&e);
            String::new()
        }
    };
    let policy = antitamper_bpf::cgroup_guard::v1_policy(unified, &mountinfo);
    let bits = match &policy {
        V1Policy::Refused { .. } => CGROUP_POLICY_V1_REFUSE,
        V1Policy::NotRefused { .. } => 0,
    };
    {
        let map = ebpf
            .map_mut(CGROUP_POLICY_MAP_NAME)
            .ok_or_else(|| anyhow!("map {CGROUP_POLICY_MAP_NAME} missing from eBPF object"))?;
        let mut arr: AyaArray<&mut MapData, u32> = AyaArray::try_from(map)
            .with_context(|| format!("{CGROUP_POLICY_MAP_NAME} is not an Array<u32>"))?;
        arr.set(0, bits, 0)
            .with_context(|| format!("writing {CGROUP_POLICY_MAP_NAME}[0]"))?;
    }
    if let Some(root) = pin_root {
        for name in [CGROUP_POLICY_MAP_NAME, LIMIT_VALUES_MAP_NAME] {
            let path = root.join(name);
            antitamper_bpf::purge_stale_pin(&path);
            ebpf.map_mut(name)
                .ok_or_else(|| anyhow!("map {name} missing from eBPF object"))?
                .pin(&path)
                .with_context(|| format!("pinning {name} to {}", path.display()))?;
        }
    }
    match &policy {
        V1Policy::Refused { mounted } if mounted.is_empty() => info!(
            "anti-tamper cgroup: cgroup v1 writes refused outside a trusted-installer window \
             (systemd runs the unified hierarchy; no v1 hierarchy mounted)"
        ),
        V1Policy::Refused { mounted } => warn!(
            mounted = %mounted.join("; "),
            "anti-tamper cgroup: cgroup v1 writes refused outside a trusted-installer window — \
             v1 hierarchies are mounted on a host whose systemd does not use them"
        ),
        V1Policy::NotRefused { why } => warn!(
            reason = %why,
            "anti-tamper cgroup: cgroup v1 writes NOT refused"
        ),
    }
    Ok(policy)
}

/// The watchdog's unit cgroup, registered by the agent once it has
/// verified the watchdog's pid (the watchdog registers it itself at its
/// start; this covers one that could not). `previous`: the keys registered
/// for the former watchdog, released when they are not the new one's.
/// Returns the keys registered now.
pub fn protect_watchdog_cgroup(
    bpffs_root: Option<&Path>,
    pid: u32,
    previous: &[InodeKey],
) -> Vec<InodeKey> {
    let Some(root) = bpffs_root else {
        return Vec::new();
    };
    let keys = match antitamper_bpf::cgroup_guard::protect_unit_cgroup(root, pid) {
        Ok(unit @ UnitCgroup::Service { .. }) => {
            if let UnitCgroup::Service {
                cgroup,
                entries,
                values,
            } = &unit
            {
                info!(
                    watchdog_pid = pid,
                    cgroup = %nn_model::log_escape::Escaped(cgroup),
                    entries = entries.len(),
                    values = values.len(),
                    "anti-tamper cgroup: watchdog unit cgroup registered in PROTECTED_INODES"
                );
                remember_unit(cgroup);
            }
            unit.keys()
        }
        Ok(UnitCgroup::NotAService { cgroup }) => {
            info!(watchdog_pid = pid, cgroup = %nn_model::log_escape::Escaped(&cgroup), "anti-tamper cgroup: watchdog not in a systemd service's cgroup — not protected");
            Vec::new()
        }
        Ok(UnitCgroup::Unavailable { why }) => {
            warn!(watchdog_pid = pid, reason = %why, "anti-tamper cgroup: watchdog unit cgroup NOT protected");
            Vec::new()
        }
        Err(e) => {
            warn!(watchdog_pid = pid, error = %format!("{e:#}"), "anti-tamper cgroup: watchdog unit cgroup registration FAILED");
            Vec::new()
        }
    };
    let gone = released(previous, &keys);
    if !gone.is_empty() {
        if let Err(e) = antitamper_bpf::cgroup_guard::release_keys(root, &gone) {
            warn!(error = %format!("{e:#}"), "anti-tamper cgroup: the former watchdog's cgroup keys not released");
        }
    }
    keys
}

/// Lot 273b: what the kernel's BTF lacking an optional offset of lot 273b
/// costs (`absent`: the names of the offsets not found), one signed
/// degradation each: the `oom_score_adj` deny unarmed without the proc
/// offsets, PID 1's every write of a protected resource file refused
/// without the syscall's arguments (another architecture than x86-64).
pub(crate) fn offsets_degraded<'a>(absent: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let absent: Vec<&str> = absent.into_iter().collect();
    let any = |names: &[&'static str]| -> Vec<&'static str> {
        names
            .iter()
            .filter(|n| absent.contains(n))
            .copied()
            .collect()
    };
    let mut out = Vec::new();
    let proc = any(&[
        "PROC_INODE_PID_OFFSET",
        "PROC_INODE_VFS_INODE_OFFSET",
        "PID_TASKS_OFFSET",
        "TASK_STRUCT_PID_LINKS_OFFSET",
    ]);
    if !proc.is_empty() {
        out.push(format!(
            "anti-tamper: a write of a protected process's oom_score_adj is not refused (the \
             kernel's BTF has no {}): root can make the agent the OOM killer's first victim",
            proc.join(", ")
        ));
    }
    // The review of #490 (B): the resource files recognised by their
    // kernfs node, not by a dentry a handle-opened file may not have.
    let kernfs = any(&[
        "INODE_I_PRIVATE_OFFSET",
        "KERNFS_NODE_NAME_OFFSET",
        "KERNFS_NODE_PARENT_OFFSET",
        "KERNFS_NODE_ID_OFFSET",
    ]);
    if !kernfs.is_empty() {
        out.push(format!(
            "anti-tamper cgroup: the units' resource files are recognised by their dentry (the \
             kernel's BTF has no {}): one opened through a handle (open_by_handle_at) after its \
             dentry was dropped is not refused unless its value was registered",
            kernfs.join(", ")
        ));
    }
    let regs = any(&[
        "PT_REGS_SI_OFFSET",
        "PT_REGS_DX_OFFSET",
        "PT_REGS_ORIG_AX_OFFSET",
    ]);
    if !regs.is_empty() {
        out.push(format!(
            "anti-tamper cgroup: PID 1's writes of the units' resource files are all refused \
             (no {} on this architecture: the value systemd writes back cannot be read) — \
             systemd logs a failed write of its own values at a reload",
            regs.join(", ")
        ));
    }
    out
}

/// Lot 273b: the keys of a former watchdog's cgroup to release — those of
/// `previous` the new one's (`now`) does not have.
pub(crate) fn released(previous: &[InodeKey], now: &[InodeKey]) -> Vec<InodeKey> {
    previous
        .iter()
        .copied()
        .filter(|k| !now.contains(k))
        .collect()
}

/// The agent's own unit cgroup, in the pinned `PROTECTED_INODES` before
/// the boot loads anything (as `preregister_self` does for its pid): the
/// prior boot's pinned deny hooks protect the new unit cgroup from the
/// first instant. `Ok(None)` when there is no pinned map (a first boot).
pub fn preregister_own_cgroup(bpffs_root: &Path) -> Result<Option<UnitCgroup>> {
    if !bpffs_root
        .join(antitamper_bpf::cgroup_guard::PROTECTED_INODES_MAP_NAME)
        .exists()
    {
        return Ok(None);
    }
    antitamper_bpf::cgroup_guard::protect_unit_cgroup(bpffs_root, std::process::id()).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The guard's pin names are the hooks' (the privileged pin test reads
    /// `prog_<hook>` / `link_<hook>`), and both are optional deny hooks with
    /// a fail-open slot.
    #[test]
    fn the_move_guard_is_an_optional_deny_pair() {
        assert_eq!(MOVE_STASH_HOOK, "cgroup_procs_write_start");
        assert_eq!(MOVE_DENY_HOOK, "inode_permission");
        assert_eq!(MOVE_CLEAR_HOOK, "cgroup_file_write");
        assert_eq!(MOVE_CLEAR_LEGACY_HOOK, "cgroup_procs_write_finish");
        assert!(!GUARD_HOOKS.contains(&MOVE_CLEAR_LEGACY_HOOK));
        assert_eq!(GUARD_HOOKS.len(), 3);
        for h in GUARD_HOOKS {
            assert!(super::super::OPTIONAL_DENY_HOOKS.contains(&h), "{h}");
            assert!(common::fail_open::FAIL_OPEN_HOOKS.contains(&h), "{h}");
            assert!(!super::super::DENY_HOOKS.contains(&h), "{h}");
        }
    }

    /// Lot 273b: a window's close registers again the values of every unit
    /// registered, each once; without a bpffs there is nothing to write.
    #[test]
    fn a_windows_close_refreshes_each_registered_unit_once() {
        let unit = "/test.slice/remember-unit-test.service";
        remember_unit(unit);
        remember_unit(unit);
        remember_unit("/test.slice/remember-unit-other.service");
        let units = REGISTERED_UNITS.lock().clone();
        assert_eq!(units.iter().filter(|u| *u == unit).count(), 1);
        assert!(units
            .iter()
            .any(|u| u == "/test.slice/remember-unit-other.service"));
        assert_eq!(refresh_values(None), 0);
    }

    /// Lot 273b (the review of #489, R5): the attach registers the cgroup of
    /// the boot's processes and of every live protected process that runs
    /// an installed binary — the watchdog, whose own registration the
    /// boot's prune would drop — and of no other.
    #[test]
    fn the_attach_registers_the_live_watchdogs_cgroup() {
        let installed = |pid: u32| pid == 300 || pid == 100;
        assert_eq!(
            cgroup_pids(&[100], &[100, 300, 400], installed),
            vec![100, 300]
        );
        assert_eq!(cgroup_pids(&[100], &[], installed), vec![100]);
        assert_eq!(cgroup_pids(&[100, 200], &[400], installed), vec![100, 200]);
        assert_eq!(cgroup_pids(&[], &[300, 300], installed), vec![300]);
    }

    /// Lot 273b: an optional offset the kernel lacks is a signed cost.
    #[test]
    fn a_missing_offset_is_a_signed_degradation() {
        assert!(offsets_degraded(["TASK_STRUCT_TGID_OFFSET"]).is_empty());
        let d = offsets_degraded(["PID_TASKS_OFFSET", "PT_REGS_SI_OFFSET"]);
        assert_eq!(d.len(), 2, "{d:?}");
        assert!(
            d[0].contains("oom_score_adj") && d[0].contains("PID_TASKS_OFFSET"),
            "{d:?}"
        );
        assert!(
            d[1].contains("PID 1's writes") && d[1].contains("PT_REGS_SI_OFFSET"),
            "{d:?}"
        );
        // The review of #490 (B): without the kernfs node's offsets the
        // resource files are recognised by their dentry.
        for name in [
            "INODE_I_PRIVATE_OFFSET",
            "KERNFS_NODE_NAME_OFFSET",
            "KERNFS_NODE_PARENT_OFFSET",
            "KERNFS_NODE_ID_OFFSET",
        ] {
            let d = offsets_degraded([name]);
            assert_eq!(d.len(), 1, "{name}: {d:?}");
            assert!(
                d[0].contains("open_by_handle_at") && d[0].contains(name),
                "{d:?}"
            );
        }
    }

    /// Lot 273b (R7): a former watchdog's keys the new one's cgroup does not
    /// have are released; the shared ones (the slices') are kept.
    #[test]
    fn the_former_watchdogs_keys_are_released() {
        let k = |ino| InodeKey { dev: 0x1f, ino };
        assert_eq!(
            released(&[k(1), k(2), k(3)], &[k(2), k(4)]),
            vec![k(1), k(3)]
        );
        assert_eq!(released(&[k(1)], &[k(1)]), vec![]);
        assert_eq!(released(&[], &[k(1)]), vec![]);
        assert_eq!(released(&[k(5)], &[]), vec![k(5)]);
    }
}
