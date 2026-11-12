//! `BlockOutbound` — drop every outbound packet originating from a
//! single PID.
//!
//! Strategy: cgroup v2 + nftables `socket cgroupv2` match.
//!
//! 1. Ensure `<cgroup_root>/<slice>/blocked.scope` exists.
//! 2. Move the target PID into that cgroup by writing its tgid to
//!    `cgroup.procs` (idempotent: writing a PID that's already there
//!    is a no-op).
//! 3. Install (idempotent) the nftables ruleset that drops every
//!    output socket originating from that cgroup.
//!
//! All three steps are idempotent on their own; the whole function
//! is therefore safe to re-run. `unblock_pid` reverses step 2 by
//! moving the PID back to the cgroup root. The drop chain itself is
//! kept around — keeping a known-good ruleset around is harmless and
//! avoids a window during which a still-blocked PID could escape.
//!
//! **Library vs `nft` shell-out.** The Rust `nftables` crate is a
//! thin wrapper around the same `nft` binary's JSON dialect; using
//! it would buy us a typed AST but cost a heavier dependency tree
//! and a learning-curve spike. Shelling out to `nft -f -` with a
//! short text ruleset is exactly what every reference example does
//! and stays readable in PR diffs. Documented choice.

use std::collections::HashSet;
use std::fs;
use std::io::{ErrorKind, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use nn_core::response::cgroup::{cgroup_at, cgroup_at_or_under, unified_path};
use tracing::{debug, info, warn};

use super::{config::ExecutorConfig, ExecutionOutcome};

/// External audit CMB-011: the drop ruleset goes in once per COMBAT
/// episode, not once per blocked process — a fork storm by an offender
/// made a fork and exec of `nft` for every child, each repeating a rule
/// already in place (a child forked after its parent was moved is in
/// `blocked.scope` already).
static RULESET: RulesetOnce = RulesetOnce::new();

/// Apply the ruleset again at the next block (a new COMBAT episode: the
/// chain may have been flushed in between).
pub fn forget_applied_ruleset() {
    RULESET.forget();
}

/// A ruleset applied at most once per cgroup until [`RulesetOnce::forget`].
///
/// Lot 312 (F5, "by cgroup id"): the drop rule names the scope from the
/// root (`socket cgroupv2 level 2 "northnarrow.slice/blocked.scope"`), and
/// nft resolves that name to the cgroup's id when the rule goes in. A scope
/// removed and made again since is another cgroup, which the rule does not
/// match: the ruleset is applied once per id of the scope, not once.
pub(crate) struct RulesetOnce(parking_lot::Mutex<Option<u64>>);

impl RulesetOnce {
    pub(crate) const fn new() -> Self {
        Self(parking_lot::const_mutex(None))
    }

    /// Run `apply` unless it already succeeded for the cgroup `id` (its
    /// inode number on cgroup2, the id nft resolves) since the last
    /// `forget`.
    pub(crate) fn ensure(
        &self,
        id: u64,
        apply: impl FnOnce() -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        let mut applied = self.0.lock();
        if *applied == Some(id) {
            return Ok(());
        }
        apply()?;
        *applied = Some(id);
        Ok(())
    }

    pub(crate) fn forget(&self) {
        *self.0.lock() = None;
    }
}

/// Public entry point used by [`super::Executor::execute`].
/// R12c (lab PR 270): only for an action whose intent is signed (`_intent`).
pub fn block_outbound_for_pid(
    pid: u32,
    protected: &HashSet<u32>,
    cfg: &ExecutorConfig,
    _intent: &super::journal::Intent,
) -> ExecutionOutcome {
    if pid == 0 {
        return ExecutionOutcome::Refused {
            pid,
            reason: "PID 0 invalid",
        };
    }
    if protected.contains(&pid) {
        return ExecutionOutcome::Refused {
            pid,
            reason: "PID is protected",
        };
    }

    // External audit CMB-020: detect-only touches nothing and says so —
    // `Blocked` here was a containment that never happened.
    if cfg.dry_run {
        info!(pid, "dry-run: would block outbound for pid");
        return ExecutionOutcome::WouldExecute { pid };
    }

    if let Err(e) = ensure_blocked_cgroup(cfg) {
        return io_failed(pid, "ensure_blocked_cgroup", &e);
    }
    let scope_id = match fs::metadata(cfg.blocked_cgroup_dir()) {
        Ok(m) => m.ino(),
        Err(e) => return io_failed(pid, "stat the blocked scope", &e),
    };
    // External audit CMB-014: the drop rule first. Moving the process
    // into `blocked.scope` and then failing to install the rule (no `nft`
    // on the host) left it there unblocked, counted as contained.
    if let Err(e) = RULESET.ensure(scope_id, || apply_block_ruleset(cfg)) {
        return io_failed(pid, "apply_block_ruleset", &e);
    }
    // External audit CMB-011: a process already in the scope (a child
    // forked after its parent was moved) needs no write — nor one in a
    // kill cgroup below it (CMB-019): moving it would take it out of a kill.
    // Lot 312 (BUG-91): the agent's scope from the root, by components —
    // a namesake in a user's delegated subtree is not it.
    if pid_under_blocked_scope(pid, cfg) {
        debug!(pid, "already in the blocked scope");
        return match in_effect(pid, cfg, scope_id) {
            Ok(()) => blocked(pid),
            Err(reason) => not_in_effect(pid, reason),
        };
    }
    // External audit CMB-010: where it came from, read before the move —
    // a release returns it there.
    let origin = super::containment::origin_of(pid);
    let start_ticks = proc_start_ticks(pid);
    if let Err(e) = move_pid_to_blocked(pid, cfg) {
        // ESRCH from the cgroup write means the process exited; treat
        // it the same as the kill path's AlreadyGone.
        if matches!(e.raw_os_error(), Some(libc::ESRCH)) {
            return ExecutionOutcome::AlreadyGone { pid };
        }
        return io_failed(pid, "move_pid_to_blocked", &e);
    }
    if let Some(origin) = origin {
        if let Err(e) = super::containment::record(
            cfg,
            super::containment::Contained {
                pid,
                start_ticks,
                scope: "blocked".into(),
                origin,
                since: super::containment::now(),
            },
        ) {
            tracing::warn!(pid, error = %e, "the containment record could not be written — a release will leave it contained");
        }
    }
    // Lot 312 (F5): what the host holds now, not what was written.
    if let Err(reason) = in_effect(pid, cfg, scope_id) {
        return not_in_effect(pid, reason);
    }
    info!(pid, cgroup = %cfg.blocked_cgroup_match(), "blocked outbound traffic");
    blocked(pid)
}

/// Lot 312 (review F2): `Blocked` only for a process that holds no inet
/// socket: the drop matches a socket's cgroup at its creation, so a socket
/// it opened before the move keeps sending — partial, said with the count.
fn blocked(pid: u32) -> ExecutionOutcome {
    match inet_sockets_of(Path::new("/proc"), pid) {
        0 => ExecutionOutcome::Blocked { pid },
        sockets => {
            warn!(
                pid,
                sockets,
                "block outbound: new sockets dropped, the ones opened before the move are not"
            );
            ExecutionOutcome::BlockedNewOnly { pid, sockets }
        }
    }
}

/// The inet sockets (TCP, UDP, raw, v4 and v6) process `pid` holds: its
/// descriptors that are sockets, found in its network namespace's tables
/// (`<proc>/<pid>/net/{tcp,udp,raw,…}`, by inode). No descriptor table
/// (the process gone): none. A table this kernel does not have (`ENOENT`):
/// no socket of it. A table that cannot be read otherwise: every socket the
/// process holds is counted — the block is never said whole on a read that
/// failed.
fn inet_sockets_of(proc: &Path, pid: u32) -> usize {
    let dir = proc.join(pid.to_string());
    let Ok(fds) = fs::read_dir(dir.join("fd")) else {
        return 0;
    };
    let held: HashSet<u64> = fds
        .flatten()
        .filter_map(|e| fs::read_link(e.path()).ok())
        .filter_map(|l| {
            l.to_str()?
                .strip_prefix("socket:[")?
                .trim_end_matches(']')
                .parse()
                .ok()
        })
        .collect();
    if held.is_empty() {
        return 0;
    }
    let mut n = 0;
    for table in [
        "tcp", "tcp6", "udp", "udp6", "raw", "raw6", "udplite", "udplite6",
    ] {
        let text = match crate::state_read::read_state(dir.join("net").join(table)) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                warn!(pid, table, error = %e, "block outbound: a socket table could not be read, every socket held counted");
                return held.len();
            }
        };
        n += text
            .lines()
            .skip(1)
            .filter_map(|l| l.split_whitespace().nth(9)?.parse::<u64>().ok())
            .filter(|ino| held.contains(ino))
            .count();
    }
    n
}

/// Lot 312 (external bug hunt 1.4, F5): the block read back. The process
/// is in the agent's blocked scope or below it — `/proc/<pid>/cgroup` read
/// again, compared by components from the root — and the scope is still
/// the cgroup the drop rule was loaded for (its id, `scope_id`). `Err`
/// says which does not hold.
fn in_effect(pid: u32, cfg: &ExecutorConfig, scope_id: u64) -> Result<(), &'static str> {
    let Ok(text) = crate::state_read::read_state(format!("/proc/{pid}/cgroup")) else {
        return Err("its cgroup could not be read back");
    };
    let now = fs::metadata(cfg.blocked_cgroup_dir()).ok().map(|m| m.ino());
    judge_effect(&text, &cfg.blocked_cgroup_match(), now, scope_id)
}

/// [`in_effect`]'s judgement: `text` the process's `/proc/<pid>/cgroup`,
/// `rel` the scope (`northnarrow.slice/blocked.scope`), `now` the scope's
/// id as read now, `rule_id` the one the drop rule was loaded for.
fn judge_effect(text: &str, rel: &str, now: Option<u64>, rule_id: u64) -> Result<(), &'static str> {
    if !cgroup_is_or_below(text, rel) {
        return Err("moved, but /proc/<pid>/cgroup does not place it in the agent's blocked scope");
    }
    if now != Some(rule_id) {
        return Err("the blocked scope is no longer the cgroup the drop rule was loaded for");
    }
    Ok(())
}

fn not_in_effect(pid: u32, reason: &'static str) -> ExecutionOutcome {
    warn!(pid, reason, "block outbound: NOT in effect");
    ExecutionOutcome::NotInEffect { pid, reason }
}

/// What [`release_blocked_pid`] did.
pub use super::containment::Release;

/// External audit CMB-010: release a process this agent blocked back to
/// the cgroup it came from (the containment record) — only while
/// `/proc/<pid>/cgroup` still shows it in `blocked.scope` and its start time
/// is the one recorded when it was blocked. It is never written to the root
/// cgroup: without a record, or when its cgroup is gone or no longer a leaf,
/// it stays contained.
pub fn release_blocked_pid(
    pid: u32,
    start_ticks: Option<u64>,
    cfg: &ExecutorConfig,
) -> std::io::Result<Release> {
    super::containment::release_to_origin(
        pid,
        start_ticks,
        "blocked",
        cfg,
        &super::containment::Probe {
            in_scope: &|p| pid_in_blocked_scope(p, cfg),
            start_of: &proc_start_ticks,
            cgroup_of: &super::containment::origin_of,
        },
    )
}

/// Whether `/proc/<pid>/cgroup` places the process in the blocked scope.
pub fn pid_in_blocked_scope(pid: u32, cfg: &ExecutorConfig) -> bool {
    crate::state_read::read_state(format!("/proc/{pid}/cgroup"))
        .is_ok_and(|c| cgroup_is(&c, &cfg.blocked_cgroup_match()))
}

/// Whether the process is in the blocked scope or in a cgroup below it (a
/// kill cgroup, `neutralize-*`): the drop holds in both.
pub fn pid_under_blocked_scope(pid: u32, cfg: &ExecutorConfig) -> bool {
    crate::state_read::read_state(format!("/proc/{pid}/cgroup"))
        .is_ok_and(|c| cgroup_is_or_below(&c, &cfg.blocked_cgroup_match()))
}

/// Whether a `/proc/<pid>/cgroup` text puts the process in the cgroup v2
/// path `/<rel>` (`northnarrow.slice/blocked.scope`) or below it. Lot 312
/// (external bug hunt 1.4, BUG-91): by components from the root
/// ([`cgroup_at_or_under`]) — `contains("/<rel>/")` took a user's
/// `…/user@1000.service/northnarrow.slice/blocked.scope/x` for it.
fn cgroup_is_or_below(proc_cgroup: &str, rel: &str) -> bool {
    unified_path(proc_cgroup).is_some_and(|p| cgroup_at_or_under(p, &format!("/{rel}")))
}

/// Whether a `/proc/<pid>/cgroup` text puts the process in the cgroup v2
/// path `/<rel>` itself. Lot 312 (BUG-91): by components from the root
/// ([`cgroup_at`]) — `ends_with("/<rel>")` took a namesake a user made in
/// its delegated subtree for the agent's scope: the block answered
/// `Blocked`, moved nothing, and the drop rule, which names the scope from
/// the root, filtered nothing.
fn cgroup_is(proc_cgroup: &str, rel: &str) -> bool {
    unified_path(proc_cgroup).is_some_and(|p| cgroup_at(p, &format!("/{rel}")))
}

pub use super::proc_ref::proc_start_ticks;

/// Construct the canonical idempotent ruleset for the block chain.
/// Pure: takes only the config and returns a string. Unit-tested
/// without touching the system.
pub fn block_ruleset(cfg: &ExecutorConfig) -> String {
    format!(
        "add table inet {table}\n\
         add chain inet {table} output_blocked {{ type filter hook output priority 0; policy accept; }}\n\
         flush chain inet {table} output_blocked\n\
         add rule inet {table} output_blocked socket cgroupv2 level 2 \"{cgroup}\" drop comment \"NN-BlockOutbound\"\n",
        table = cfg.nft_table,
        cgroup = cfg.blocked_cgroup_match(),
    )
}

fn ensure_blocked_cgroup(cfg: &ExecutorConfig) -> std::io::Result<()> {
    let dir = cfg.blocked_cgroup_dir();
    create_cgroup_dir(&dir)
}

fn move_pid_to_blocked(pid: u32, cfg: &ExecutorConfig) -> std::io::Result<()> {
    let procs = cfg.blocked_cgroup_dir().join("cgroup.procs");
    write_pid(&procs, pid)
}

fn apply_block_ruleset(cfg: &ExecutorConfig) -> std::io::Result<()> {
    nft_apply(&block_ruleset(cfg))
}

/// Create a cgroup directory by `mkdir`-ing the parent slice and the
/// scope. `cgroupv2` allows mkdir at any depth; both calls are
/// idempotent (`AlreadyExists` is silently ignored).
pub(crate) fn create_cgroup_dir(dir: &Path) -> std::io::Result<()> {
    if let Some(parent) = dir.parent() {
        if let Err(e) = fs::create_dir(parent) {
            if e.kind() != ErrorKind::AlreadyExists {
                return Err(e);
            }
        }
    }
    if let Err(e) = fs::create_dir(dir) {
        if e.kind() != ErrorKind::AlreadyExists {
            return Err(e);
        }
    }
    debug!(dir = %dir.display(), "ensured cgroup dir");
    Ok(())
}

/// Write a PID into `cgroup.procs`. The cgroupfs accepts only one
/// PID per write; we follow that contract literally.
pub(crate) fn write_pid(path: &Path, pid: u32) -> std::io::Result<()> {
    let mut f = fs::OpenOptions::new().write(true).open(path)?;
    f.write_all(format!("{pid}").as_bytes())?;
    Ok(())
}

/// Lab follow-up (lab PR 165): the boot check. Without `nft` neither a
/// BlockOutbound verdict nor the COMBAT soft egress block can drop a
/// process's traffic, and that used to show only at the first block. The
/// returned text is the boot ERROR and the signed `subsystem_degraded`
/// detail; `None` when `lookup` finds an `nft` [`nft_apply`] would run.
///
/// External audit ATP-014 (NN-AUD-262): that is the `nft` of the system
/// directories ([`crate::trusted_bin`]), not the first one on `PATH`.
pub fn nft_gap(lookup: &crate::trusted_bin::Lookup) -> Option<String> {
    let why = lookup.resolve("nft").err()?;
    let missing = if why.is_missing() {
        "nft missing"
    } else {
        "nft missing (not trusted)"
    };
    Some(format!(
        "block_outbound unavailable: {missing} ({why}) — a BlockOutbound verdict and the \
         COMBAT soft egress block cannot drop a process's traffic; each episode records the \
         failure and shortens INVESTIGATE to 10 s. Install nftables"
    ))
}

/// [`nft_gap`] for this host, where [`nft_apply`] looks.
pub fn nft_gap_at_boot() -> Option<String> {
    nft_gap(&crate::trusted_bin::Lookup::system())
}

/// External audit ATP-014 (NN-AUD-262): the `nft` the agent runs — the
/// system directories' ([`crate::trusted_bin`]), verified, never a `PATH`
/// search. None there is `ENOENT`, as a missing `nft` always was (the
/// ladder's "is nftables installed?"), with the reason logged.
pub(crate) fn trusted_nft() -> std::io::Result<crate::trusted_bin::SystemBin> {
    crate::trusted_bin::resolve("nft").map_err(|e| {
        tracing::warn!(error = %e, "nft not run: none trusted in the system directories");
        std::io::Error::from_raw_os_error(libc::ENOENT)
    })
}

/// Pipe `ruleset` to `nft -f -` and propagate its stderr on failure.
/// Lab PR 217 (capability C18): waited for at most
/// [`crate::bounded_cmd::EXTERNAL_CMD_TIMEOUT`] — a hung `nft` fails the
/// block (`ETIMEDOUT`) instead of holding the ladder's worker.
pub(crate) fn nft_apply(ruleset: &str) -> std::io::Result<()> {
    let mut cmd = trusted_nft()?.command();
    cmd.arg("-f").arg("-");
    let out = crate::bounded_cmd::run_bounded(
        cmd,
        Some(ruleset.as_bytes()),
        crate::bounded_cmd::EXTERNAL_CMD_TIMEOUT,
        "nft -f -",
    )?;
    if !out.status.success() {
        return Err(std::io::Error::other(format!(
            "nft -f failed (exit {:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(())
}

fn io_failed(pid: u32, step: &str, e: &std::io::Error) -> ExecutionOutcome {
    tracing::warn!(pid, step, error = %e, "block_outbound failed");
    ExecutionOutcome::Failed {
        pid,
        errno: e.raw_os_error().unwrap_or(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn cfg_for(tmp: &TempDir) -> ExecutorConfig {
        ExecutorConfig::for_test(tmp.path())
    }

    #[test]
    fn ruleset_includes_correct_cgroup_path() {
        let cfg = ExecutorConfig {
            cgroup_slice: "northnarrow.slice".into(),
            nft_table: "northnarrow".into(),
            ..ExecutorConfig::default()
        };
        let r = block_ruleset(&cfg);
        assert!(r.contains("table inet northnarrow"));
        assert!(r.contains("chain inet northnarrow output_blocked"));
        assert!(r.contains("flush chain inet northnarrow output_blocked"));
        assert!(r.contains("\"northnarrow.slice/blocked.scope\""));
        assert!(r.contains("drop comment \"NN-BlockOutbound\""));
    }

    /// External audit CMB-020: detect-only reports `WouldExecute`, never
    /// `Blocked`.
    #[test]
    fn dry_run_returns_would_execute_without_touching_system() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        let protected: HashSet<u32> = HashSet::new();
        let out = block_outbound_for_pid(
            1234,
            &protected,
            &cfg,
            &super::super::journal::test_intent(),
        );
        assert!(
            matches!(out, ExecutionOutcome::WouldExecute { pid: 1234 }),
            "{out:?}"
        );
        // No cgroup directories touched in dry-run mode.
        assert!(!cfg.blocked_cgroup_dir().exists());
    }

    #[test]
    fn refuses_protected_pid_even_in_dry_run() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        let mut protected: HashSet<u32> = HashSet::new();
        protected.insert(1);
        let out =
            block_outbound_for_pid(1, &protected, &cfg, &super::super::journal::test_intent());
        assert!(matches!(
            out,
            ExecutionOutcome::Refused {
                pid: 1,
                reason: "PID is protected"
            }
        ));
    }

    #[test]
    fn ensure_blocked_cgroup_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let cfg = ExecutorConfig {
            cgroup_root: tmp.path().to_path_buf(),
            cgroup_slice: "northnarrow.slice".into(),
            ..ExecutorConfig::for_test(tmp.path())
        };
        // First call creates the directory; second call is a no-op.
        ensure_blocked_cgroup(&cfg).expect("first create");
        ensure_blocked_cgroup(&cfg).expect("second create");
        assert!(cfg.blocked_cgroup_dir().exists());
    }

    /// External audit CMB-011: one `nft` run per episode, not per process.
    #[test]
    fn one_ruleset_apply_per_episode() {
        let once = RulesetOnce::new();
        let runs = std::cell::Cell::new(0);
        for _ in 0..500 {
            once.ensure(77, || {
                runs.set(runs.get() + 1);
                Ok(())
            })
            .unwrap();
        }
        assert_eq!(runs.get(), 1);
        once.forget();
        once.ensure(77, || {
            runs.set(runs.get() + 1);
            Ok(())
        })
        .unwrap();
        assert_eq!(runs.get(), 2, "a new episode applies it again");
        // a failed apply is retried at the next block
        let once = RulesetOnce::new();
        assert!(once
            .ensure(77, || Err(std::io::Error::other("no nft")))
            .is_err());
        once.ensure(77, || Ok(())).unwrap();
        let mut again = false;
        once.ensure(77, || {
            again = true;
            Ok(())
        })
        .unwrap();
        assert!(!again);
    }

    /// Lot 312 (F5, by cgroup id): the scope made again is another cgroup —
    /// nft resolved the rule's name to the old one's id — so the ruleset
    /// goes in again; the same scope does not take it twice. Id 0 and
    /// `u64::MAX` are ids like the others.
    #[test]
    fn a_scope_made_again_takes_the_ruleset_again() {
        let once = RulesetOnce::new();
        let runs = std::cell::Cell::new(0);
        let apply = || {
            runs.set(runs.get() + 1);
            Ok(())
        };
        for id in [5, 5, 6, 6, 5, 0, 0, u64::MAX, u64::MAX] {
            once.ensure(id, apply).unwrap();
        }
        assert_eq!(runs.get(), 5, "5, 6, 5 again, 0, MAX");
    }

    /// Lab follow-up (lab PR 165): a host without `nft` is reported at
    /// boot, not only at the first block; only an executable regular file
    /// named `nft` in a system directory counts. External audit ATP-014
    /// (NN-AUD-262): one in `/usr/local/sbin` (first on systemd's default
    /// service `PATH`) does not, nor one others can write.
    #[test]
    fn a_missing_nft_is_reported_at_boot() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let tmp = TempDir::new().unwrap();
        let r = tmp.path();
        fs::set_permissions(r, fs::Permissions::from_mode(0o755)).unwrap();
        for d in ["usr/sbin", "usr/bin", "usr/local/sbin"] {
            fs::create_dir_all(r.join(d)).unwrap();
            fs::set_permissions(r.join(d), fs::Permissions::from_mode(0o755)).unwrap();
        }
        fs::set_permissions(r.join("usr"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(r.join("usr/local"), fs::Permissions::from_mode(0o755)).unwrap();
        let lookup = crate::trusted_bin::Lookup::new(r, fs::metadata(r).unwrap().uid());
        let gap = nft_gap(&lookup).expect("no nft: reported");
        assert!(
            gap.starts_with("block_outbound unavailable: nft missing ("),
            "{gap}"
        );
        assert!(
            gap.contains("/usr/sbin, /usr/bin, /sbin, /bin"),
            "names the directories searched: {gap}"
        );
        // the first entry of systemd's default PATH: not a system directory
        let exe = |p: &Path, mode| {
            fs::write(p, b"#!/bin/sh\n").unwrap();
            fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
        };
        exe(&r.join("usr/local/sbin/nft"), 0o755);
        assert!(nft_gap(&lookup).is_some());
        // a file without an execute bit, a directory: nothing `nft -f` runs
        exe(&r.join("usr/sbin/nft"), 0o644);
        fs::create_dir(r.join("usr/bin/nft")).unwrap();
        let gap = nft_gap(&lookup).expect("not runnable: reported");
        assert!(gap.contains("nft missing (not trusted)"), "{gap}");
        assert!(gap.contains("not executable"), "{gap}");
        // group-writable: refused
        exe(&r.join("usr/sbin/nft"), 0o775);
        assert!(nft_gap(&lookup).is_some());
        // the system directory's executable, root's (here: the tree's owner)
        exe(&r.join("usr/sbin/nft"), 0o755);
        assert!(nft_gap(&lookup).is_none());
    }

    /// External audit CMB-010: only a process still in the blocked scope
    /// is released.
    #[test]
    fn release_skips_a_pid_not_in_blocked_scope() {
        let rel = "northnarrow.slice/blocked.scope";
        assert!(cgroup_is("0::/northnarrow.slice/blocked.scope\n", rel));
        assert!(!cgroup_is("0::/system.slice/ssh.service\n", rel));
        assert!(!cgroup_is("0::/\n", rel));
        assert!(!cgroup_is("0::/northnarrow.slice/blocked.scope.bak\n", rel));
        // a kill cgroup below the scope: under it, not in it (a release
        // does not take it out of a kill)
        let kill = "0::/northnarrow.slice/blocked.scope/neutralize-7-0\n";
        assert!(!cgroup_is(kill, rel));
        assert!(cgroup_is_or_below(kill, rel));
        assert!(cgroup_is_or_below(
            "0::/northnarrow.slice/blocked.scope\n",
            rel
        ));
        assert!(!cgroup_is_or_below(
            "0::/northnarrow.slice/blocked.scope.bak/x\n",
            rel
        ));
        // our own process is in none of the agent's scopes
        let cfg = ExecutorConfig {
            dry_run: false,
            ..ExecutorConfig::default()
        };
        let me = std::process::id();
        assert_eq!(
            release_blocked_pid(me, proc_start_ticks(me), &cfg).unwrap(),
            Release::Skipped("not in the scope")
        );
    }

    /// External audit CMB-010 (privileged: root, systemd, cgroup v2,
    /// nftables): a unit's process blocked and released goes back to its
    /// unit (and its stop). Before, the release wrote it to the root
    /// cgroup, out of its unit for good.
    #[test]
    #[ignore = "privileged: root, systemd, cgroup v2, nft"]
    fn a_released_process_returns_to_its_unit() {
        use std::process::Command;
        if Command::new("nft").arg("--version").output().is_err() {
            eprintln!("no nft on this host: skipped (the block needs it)");
            return;
        }
        let unit = format!("nn-victim-{}", std::process::id());
        let ok = Command::new("systemd-run")
            .args(["--unit", &unit, "--quiet", "sleep", "300"])
            .status()
            .unwrap();
        assert!(ok.success());
        std::thread::sleep(std::time::Duration::from_millis(500));
        let out = Command::new("systemctl")
            .args(["show", "-p", "MainPID", "--value", &unit])
            .output()
            .unwrap();
        let pid: u32 = String::from_utf8_lossy(&out.stdout).trim().parse().unwrap();
        let tmp = TempDir::new().unwrap();
        let cfg = ExecutorConfig {
            dry_run: false,
            cgroup_root: "/sys/fs/cgroup".into(),
            cgroup_slice: "northnarrow-test.slice".into(),
            ..ExecutorConfig::for_test(tmp.path())
        };
        let origin = super::super::containment::origin_of(pid).unwrap();
        assert!(origin.ends_with(&format!("{unit}.service")), "{origin}");
        let blocked = block_outbound_for_pid(
            pid,
            &HashSet::new(),
            &cfg,
            &super::super::journal::test_intent(),
        );
        assert!(
            matches!(blocked, ExecutionOutcome::Blocked { .. }),
            "{blocked:?}"
        );
        assert!(pid_in_blocked_scope(pid, &cfg));
        let released = release_blocked_pid(pid, proc_start_ticks(pid), &cfg).unwrap();
        let now = super::super::containment::origin_of(pid).unwrap();
        let _ = Command::new("systemctl").args(["stop", &unit]).status();
        std::thread::sleep(std::time::Duration::from_millis(300));
        let alive = std::path::Path::new(&format!("/proc/{pid}")).exists();
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", &cfg.nft_table])
            .status();
        let _ = std::fs::remove_dir(cfg.blocked_cgroup_dir());
        let _ = std::fs::remove_dir("/sys/fs/cgroup/northnarrow-test.slice");
        assert_eq!(released, Release::Released);
        assert_eq!(now, origin, "back in its unit");
        assert!(!alive, "the unit's stop reaches it");
    }

    #[test]
    fn write_pid_writes_decimal_form() {
        let tmp = TempDir::new().unwrap();
        let p: PathBuf = tmp.path().join("cgroup.procs");
        // Pre-create as an empty file so write_all has something to
        // open. cgroupfs auto-creates this; in tests we mock with a
        // plain file.
        fs::write(&p, b"").unwrap();
        write_pid(&p, 4242).unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "4242");
    }
}

/// Lot 312 (external bug hunt 1.4, BUG-91): the blocked scope was
/// recognised by suffix.
#[cfg(test)]
mod bug91 {
    use super::*;

    const REL: &str = "northnarrow.slice/blocked.scope";

    /// Promise (`pid_in_blocked_scope` / `pid_under_blocked_scope`, and the
    /// drop rule `socket cgroupv2 level 2 "northnarrow.slice/blocked.scope"`):
    /// only the agent's scope from the cgroup root, and the cgroups below
    /// it. A namesake a user made in a delegated subtree
    /// (`user@1000.service`) is neither.
    #[test]
    fn bug91_a_nested_namesake_is_not_the_blocked_scope() {
        let rule = block_ruleset(&ExecutorConfig::default());
        assert!(
            rule.contains("socket cgroupv2 level 2 \"northnarrow.slice/blocked.scope\" drop"),
            "{rule}"
        );
        let namesake =
            "0::/user.slice/user-1000.slice/user@1000.service/northnarrow.slice/blocked.scope\n";
        let below =
            "0::/user.slice/user-1000.slice/user@1000.service/northnarrow.slice/blocked.scope/x\n";
        let got = (
            cgroup_is(namesake, REL),
            cgroup_is_or_below(namesake, REL),
            cgroup_is_or_below(below, REL),
        );
        assert_eq!(
            got,
            (false, false, false),
            "BUG-91: (in scope, under scope, under scope /x) of a namesake the drop rule does not match"
        );
        // the other spellings of the same evasion
        for other in [
            "0::/system.slice/nn-x.service/northnarrow.slice/blocked.scope\n",
            "0::/northnarrow.slice/x/northnarrow.slice/blocked.scope\n",
            "0::/x/northnarrow.slice/blocked.scope/northnarrow.slice/blocked.scope\n",
            "0::/northnarrow.slice/blocked.scope.bak\n",
            "0::/northnarrow.slice.bak/blocked.scope\n",
            "0::/../northnarrow.slice/blocked.scope\n",
            "0::northnarrow.slice/blocked.scope\n",
            "1:name=systemd:/northnarrow.slice/blocked.scope\n",
        ] {
            assert!(!cgroup_is(other, REL), "{other}");
            assert!(!cgroup_is_or_below(other, REL), "{other}");
        }
    }

    /// Guard (must stay): the agent's own scope and its kill cgroups.
    #[test]
    fn bug91_guard_the_real_scope_and_its_kill_cgroups() {
        assert!(cgroup_is("0::/northnarrow.slice/blocked.scope\n", REL));
        assert!(cgroup_is_or_below(
            "0::/northnarrow.slice/blocked.scope/neutralize-7-0\n",
            REL
        ));
        assert!(!cgroup_is_or_below("0::/system.slice/ssh.service\n", REL));
    }

    /// Lot 312 (F5): the block read back — in the agent's scope or below
    /// it, and the scope the cgroup the rule was loaded for; otherwise the
    /// reason.
    #[test]
    fn bug91_the_block_is_judged_on_what_is_read_back() {
        let ok = "0::/northnarrow.slice/blocked.scope\n";
        let kill = "0::/northnarrow.slice/blocked.scope/neutralize-7-0\n";
        let namesake =
            "0::/user.slice/user-1000.slice/user@1000.service/northnarrow.slice/blocked.scope\n";
        assert_eq!(judge_effect(ok, REL, Some(7), 7), Ok(()));
        assert_eq!(judge_effect(kill, REL, Some(7), 7), Ok(()));
        for (text, now) in [(namesake, Some(7)), ("0::/\n", Some(7)), ("", Some(7))] {
            assert_eq!(
                judge_effect(text, REL, now, 7),
                Err("moved, but /proc/<pid>/cgroup does not place it in the agent's blocked scope"),
                "{text:?}"
            );
        }
        for now in [Some(8), None] {
            assert_eq!(
                judge_effect(ok, REL, now, 7),
                Err("the blocked scope is no longer the cgroup the drop rule was loaded for")
            );
        }
        // a cgroup that cannot be read back (no such process) is no block
        // in effect
        assert_eq!(
            in_effect(u32::MAX, &ExecutorConfig::default(), 7),
            Err("its cgroup could not be read back")
        );
    }

    /// Lot 312 (F5): a move the cgroupfs took but that does not place the
    /// process in the scope (here a plain directory stands for the cgroup
    /// root: the write lands in a file) is not `Blocked` — the row says
    /// it is not in effect. The rule is taken as loaded for that scope.
    #[test]
    fn bug91_a_move_that_did_not_take_is_not_blocked() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cfg = ExecutorConfig {
            dry_run: false,
            ..ExecutorConfig::for_test(tmp.path())
        };
        fs::create_dir_all(&cfg.cgroup_root).unwrap();
        ensure_blocked_cgroup(&cfg).unwrap();
        fs::write(cfg.blocked_cgroup_dir().join("cgroup.procs"), b"").unwrap();
        let id = fs::metadata(cfg.blocked_cgroup_dir()).unwrap().ino();
        RULESET.ensure(id, || Ok(())).unwrap();
        let me = std::process::id();
        let out = block_outbound_for_pid(
            me,
            &HashSet::new(),
            &cfg,
            &super::super::journal::test_intent(),
        );
        forget_applied_ruleset();
        assert_eq!(
            out,
            ExecutionOutcome::NotInEffect {
                pid: me,
                reason:
                    "moved, but /proc/<pid>/cgroup does not place it in the agent's blocked scope"
            }
        );
        assert_eq!(
            fs::read_to_string(cfg.blocked_cgroup_dir().join("cgroup.procs")).unwrap(),
            me.to_string(),
            "premise: the write went through"
        );
    }

    /// Lot 312 (BUG-91, privileged: root, systemd, cgroup v2, nftables,
    /// bash): a unit delegated to `nobody` (`Delegate=yes`, as systemd
    /// delegates `user@<uid>.service` to its user) makes, as that user, a
    /// cgroup named as the agent's blocked scope inside its own subtree and
    /// moves itself there. The block must not take it for the agent's
    /// scope: the process is moved into the real scope and its new sockets
    /// are dropped — or the outcome is a failure. On main it answered
    /// `Blocked`, moved nothing, and the traffic went on.
    #[test]
    #[ignore = "privileged: root, systemd, cgroup v2, nft"]
    fn bug91_a_delegated_users_namesake_is_moved_and_filtered() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::Command;
        if Command::new("nft").arg("--version").output().is_err() {
            eprintln!("no nft on this host: skipped (the block needs it)");
            return;
        }
        const SLICE: &str = "northnarrow-test312.slice";
        let tmp = tempfile::TempDir::new().unwrap();
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o777)).unwrap();
        let status = tmp.path().join("status");
        let unit = format!("nn-namesake-{}", std::process::id());
        let script = format!(
            "d=/sys/fs/cgroup$(sed -n 's/^0:://p' /proc/self/cgroup); \
             mkdir -p \"$d/{SLICE}/blocked.scope\" || exit 3; \
             echo $$ > \"$d/{SLICE}/blocked.scope/cgroup.procs\" || exit 4; \
             while :; do if (echo x > /dev/udp/127.0.0.1/9) 2>/dev/null; \
             then echo open > {st}.new; else echo dropped > {st}.new; fi; \
             mv -f {st}.new {st}; sleep 0.1; done",
            st = status.display()
        );
        // a file, not `bash -c`: systemd turns `$$` of a command line into `$`
        let victim = tmp.path().join("victim.sh");
        fs::write(&victim, &script).unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o755)).unwrap();
        let ok = Command::new("systemd-run")
            .args([
                "--unit",
                &unit,
                "--quiet",
                "-p",
                "Delegate=yes",
                "-p",
                "User=nobody",
                "/bin/bash",
            ])
            .arg(&victim)
            .status()
            .unwrap();
        assert!(ok.success());
        let stop = || {
            let _ = Command::new("systemctl").args(["stop", &unit]).status();
        };
        let mut pid = 0u32;
        let mut text = String::new();
        let want_tail = format!("/{SLICE}/blocked.scope");
        for _ in 0..100 {
            let out = Command::new("systemctl")
                .args(["show", "-p", "MainPID", "--value", &unit])
                .output()
                .unwrap();
            pid = String::from_utf8_lossy(&out.stdout)
                .trim()
                .parse()
                .unwrap_or(0);
            text = fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap_or_default();
            let st = fs::read_to_string(&status).unwrap_or_default();
            if pid > 0 && text.trim_end().ends_with(&want_tail) && st.trim() == "open" {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let premise = pid > 0
            && text.trim_end().ends_with(&want_tail)
            && fs::read_to_string(&status).unwrap_or_default().trim() == "open";
        if !premise {
            let unit_status = Command::new("systemctl")
                .args(["status", "--no-pager", "-l", &unit])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
                .unwrap_or_default();
            let st = fs::read_to_string(&status).unwrap_or_default();
            stop();
            panic!(
                "premise: the delegated namesake (pid {pid}, cgroup {text:?}, status {st:?}) with \
                 traffic out\n{unit_status}"
            );
        }
        assert!(
            !cgroup_is(&text, &format!("{SLICE}/blocked.scope")),
            "the namesake is not the scope: {text}"
        );

        let cfg = ExecutorConfig {
            dry_run: false,
            cgroup_root: "/sys/fs/cgroup".into(),
            cgroup_slice: SLICE.into(),
            ..ExecutorConfig::for_test(tmp.path())
        };
        forget_applied_ruleset();
        let out = block_outbound_for_pid(
            pid,
            &HashSet::new(),
            &cfg,
            &super::super::journal::test_intent(),
        );
        let after = fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap_or_default();
        let mut dropped = false;
        for _ in 0..30 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            if fs::read_to_string(&status).unwrap_or_default().trim() == "dropped" {
                dropped = true;
                break;
            }
        }
        stop();
        std::thread::sleep(std::time::Duration::from_millis(300));
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", &cfg.nft_table])
            .status();
        let _ = fs::remove_dir(cfg.blocked_cgroup_dir());
        let _ = fs::remove_dir(format!("/sys/fs/cgroup/{SLICE}"));
        forget_applied_ruleset();
        match &out {
            ExecutionOutcome::Blocked { .. } | ExecutionOutcome::BlockedNewOnly { .. } => {
                assert_eq!(
                    after.trim_end(),
                    format!("0::/{SLICE}/blocked.scope"),
                    "BUG-91: Blocked, so moved into the agent's scope"
                );
                assert!(dropped, "BUG-91: Blocked, so its new sockets are dropped");
            }
            other => {
                let (result, _, _) =
                    super::super::journal_outcome(&super::super::ExecutionReport {
                        action: nn_model::ResponseAction::BlockOutbound,
                        primary: other.clone(),
                        additional: Vec::new(),
                        elapsed: std::time::Duration::from_micros(1),
                    });
                assert_eq!(
                    result,
                    super::super::journal::ActionResult::Failure,
                    "not blocked, so the row says failure: {other:?}"
                );
            }
        }
    }
}

/// Lot 312 (review F2): a block that leaves sockets opened before the move
/// is partial, never a success.
#[cfg(test)]
mod review_f2 {
    use super::*;

    /// The inet sockets of a process, from a `/proc` tree of the test's own:
    /// its descriptors that are sockets, found by inode in the tables.
    #[test]
    fn the_sockets_a_process_holds_are_counted_by_inode() {
        let tmp = tempfile::TempDir::new().unwrap();
        let p = tmp.path().join("4242");
        fs::create_dir_all(p.join("fd")).unwrap();
        fs::create_dir_all(p.join("net")).unwrap();
        std::os::unix::fs::symlink("socket:[555]", p.join("fd/3")).unwrap();
        std::os::unix::fs::symlink("socket:[777]", p.join("fd/4")).unwrap();
        std::os::unix::fs::symlink("socket:[888]", p.join("fd/5")).unwrap();
        std::os::unix::fs::symlink("/dev/null", p.join("fd/0")).unwrap();
        let header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
        let row = |ino: u64| {
            format!("   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 {ino} 1 0000000000000000 100 0 0 10 0\n")
        };
        fs::write(
            p.join("net/tcp"),
            format!("{header}{}{}", row(555), row(999)),
        )
        .unwrap();
        fs::write(p.join("net/udp6"), format!("{header}{}", row(777))).unwrap();
        // 888: a unix socket, in no inet table
        assert_eq!(inet_sockets_of(tmp.path(), 4242), 2);
        // a table that exists and cannot be read (a directory: EISDIR):
        // every socket held is counted, the unix one too
        fs::create_dir(p.join("net/raw")).unwrap();
        assert_eq!(
            inet_sockets_of(tmp.path(), 4242),
            3,
            "an unreadable table never makes the block whole"
        );
        assert_eq!(
            inet_sockets_of(tmp.path(), 1),
            0,
            "no such process: none known"
        );
    }

    /// The test process holding a UDP socket: the block of such a process
    /// is `BlockedNewOnly`, signed partial with the count and what escapes.
    #[test]
    fn a_process_holding_a_socket_is_blocked_new_only() {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let me = std::process::id();
        assert!(inet_sockets_of(Path::new("/proc"), me) >= 1);
        let out = blocked(me);
        let ExecutionOutcome::BlockedNewOnly { sockets, .. } = out else {
            panic!("{out:?}");
        };
        assert!(sockets >= 1);
        drop(sock);
        let (result, _, reason) = super::super::journal_outcome(&super::super::ExecutionReport {
            action: nn_model::ResponseAction::BlockOutbound,
            primary: ExecutionOutcome::BlockedNewOnly {
                pid: me,
                sockets: 2,
            },
            additional: Vec::new(),
            elapsed: std::time::Duration::from_micros(1),
        });
        assert_eq!(result, super::super::journal::ActionResult::Partial);
        let reason = reason.unwrap();
        assert!(
            reason.starts_with("new connections blocked; 2 inet socket(s) opened before the move")
                && reason.contains("SCM_RIGHTS"),
            "{reason}"
        );
        // the ladder: partial, released at the stand-down, window shortened
        assert!(matches!(
            crate::combat::actuator::SystemActuator::soft_block_of(
                ExecutionOutcome::BlockedNewOnly {
                    pid: me,
                    sockets: 2
                }
            ),
            nn_core::combat::actuator::SoftBlock::Partial(_)
        ));
    }
}
