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
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};

use tracing::{debug, info};

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

/// A ruleset applied at most once until [`RulesetOnce::forget`].
pub(crate) struct RulesetOnce(AtomicBool);

impl RulesetOnce {
    pub(crate) const fn new() -> Self {
        Self(AtomicBool::new(false))
    }

    /// Run `apply` unless it already succeeded since the last `forget`.
    pub(crate) fn ensure(
        &self,
        apply: impl FnOnce() -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        if self.0.load(Ordering::Acquire) {
            return Ok(());
        }
        apply()?;
        self.0.store(true, Ordering::Release);
        Ok(())
    }

    pub(crate) fn forget(&self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Public entry point used by [`super::Executor::execute`].
pub fn block_outbound_for_pid(
    pid: u32,
    protected: &HashSet<u32>,
    cfg: &ExecutorConfig,
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
    // External audit CMB-014: the drop rule first. Moving the process
    // into `blocked.scope` and then failing to install the rule (no `nft`
    // on the host) left it there unblocked, counted as contained.
    if let Err(e) = RULESET.ensure(|| apply_block_ruleset(cfg)) {
        return io_failed(pid, "apply_block_ruleset", &e);
    }
    // External audit CMB-011: a process already in the scope (a child
    // forked after its parent was moved) needs no write — nor one in a
    // kill cgroup below it (CMB-019): moving it would take it out of a kill.
    if pid_under_blocked_scope(pid, cfg) {
        debug!(pid, "already in the blocked scope");
        return ExecutionOutcome::Blocked { pid };
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
    info!(pid, cgroup = %cfg.blocked_cgroup_match(), "blocked outbound traffic");
    ExecutionOutcome::Blocked { pid }
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
        },
    )
}

/// Whether `/proc/<pid>/cgroup` places the process in the blocked scope.
pub fn pid_in_blocked_scope(pid: u32, cfg: &ExecutorConfig) -> bool {
    fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .is_ok_and(|c| cgroup_is(&c, &cfg.blocked_cgroup_match()))
}

/// Whether the process is in the blocked scope or in a cgroup below it (a
/// kill cgroup, `neutralize-*`): the drop holds in both.
pub fn pid_under_blocked_scope(pid: u32, cfg: &ExecutorConfig) -> bool {
    fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .is_ok_and(|c| cgroup_is_or_below(&c, &cfg.blocked_cgroup_match()))
}

fn cgroup_is_or_below(proc_cgroup: &str, rel: &str) -> bool {
    cgroup_is(proc_cgroup, rel)
        || proc_cgroup.lines().any(|l| {
            l.strip_prefix("0::")
                .is_some_and(|path| path.contains(&format!("/{rel}/")))
        })
}

/// Whether a `/proc/<pid>/cgroup` text puts the process in the cgroup v2
/// path that ends with `rel` (`northnarrow.slice/blocked.scope`).
fn cgroup_is(proc_cgroup: &str, rel: &str) -> bool {
    proc_cgroup.lines().any(|l| {
        l.strip_prefix("0::").is_some_and(|path| {
            path.trim_end() == format!("/{rel}") || path.trim_end().ends_with(&format!("/{rel}"))
        })
    })
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
pub(crate) fn nft_apply(ruleset: &str) -> std::io::Result<()> {
    let mut child = trusted_nft()?
        .command()
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(ruleset.as_bytes())?;
    }
    let out = child.wait_with_output()?;
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
        let out = block_outbound_for_pid(1234, &protected, &cfg);
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
        let out = block_outbound_for_pid(1, &protected, &cfg);
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
            once.ensure(|| {
                runs.set(runs.get() + 1);
                Ok(())
            })
            .unwrap();
        }
        assert_eq!(runs.get(), 1);
        once.forget();
        once.ensure(|| {
            runs.set(runs.get() + 1);
            Ok(())
        })
        .unwrap();
        assert_eq!(runs.get(), 2, "a new episode applies it again");
        // a failed apply is retried at the next block
        let once = RulesetOnce::new();
        assert!(once
            .ensure(|| Err(std::io::Error::other("no nft")))
            .is_err());
        once.ensure(|| Ok(())).unwrap();
        let mut again = false;
        once.ensure(|| {
            again = true;
            Ok(())
        })
        .unwrap();
        assert!(!again);
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
        let blocked = block_outbound_for_pid(pid, &HashSet::new(), &cfg);
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
