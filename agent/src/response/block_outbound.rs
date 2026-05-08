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
use std::process::{Command, Stdio};

use tracing::{debug, info};

use super::{config::ExecutorConfig, ExecutionOutcome};

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

    if cfg.dry_run {
        info!(pid, "dry-run: would block outbound for pid");
        return ExecutionOutcome::Blocked { pid };
    }

    if let Err(e) = ensure_blocked_cgroup(cfg) {
        return io_failed(pid, "ensure_blocked_cgroup", &e);
    }
    if let Err(e) = move_pid_to_blocked(pid, cfg) {
        // ESRCH from the cgroup write means the process exited; treat
        // it the same as the kill path's AlreadyGone.
        if matches!(e.raw_os_error(), Some(libc::ESRCH)) {
            return ExecutionOutcome::AlreadyGone { pid };
        }
        return io_failed(pid, "move_pid_to_blocked", &e);
    }
    if let Err(e) = apply_block_ruleset(cfg) {
        return io_failed(pid, "apply_block_ruleset", &e);
    }
    info!(pid, cgroup = %cfg.blocked_cgroup_match(), "blocked outbound traffic");
    ExecutionOutcome::Blocked { pid }
}

/// Move a PID out of the blocked cgroup (back to the root). Used by
/// the integration test and exposed for future CLI commands.
pub fn unblock_pid(pid: u32, cfg: &ExecutorConfig) -> std::io::Result<()> {
    if cfg.dry_run {
        return Ok(());
    }
    let root_procs = cfg.cgroup_root.join("cgroup.procs");
    write_pid(&root_procs, pid)?;
    Ok(())
}

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

/// Pipe `ruleset` to `nft -f -` and propagate its stderr on failure.
pub(crate) fn nft_apply(ruleset: &str) -> std::io::Result<()> {
    let mut child = Command::new("nft")
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

    #[test]
    fn dry_run_returns_blocked_without_touching_system() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        let protected: HashSet<u32> = HashSet::new();
        let out = block_outbound_for_pid(1234, &protected, &cfg);
        assert!(matches!(out, ExecutionOutcome::Blocked { pid: 1234 }));
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
