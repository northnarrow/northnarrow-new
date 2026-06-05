//! Runtime configuration for the response executor.
//!
//! Default values match the production layout described in the Tappa
//! 5 spec. Tests override them with temp-dir paths via
//! [`ExecutorConfig::for_test`]. Any module that touches the system
//! reads the relevant field from this struct so behaviour is
//! configurable + dry-runnable from one place.

use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct ExecutorConfig {
    /// Vault for quarantined binaries. Layout:
    /// `<dir>/index.json` (atomic) and `<dir>/vault/<id>.{bin,meta}`.
    pub quarantine_dir: PathBuf,
    /// 32-byte master key. Generated mode 0600 if absent.
    pub master_key_file: PathBuf,
    /// Cap on file size (bytes) we'll quarantine in one go. Bigger
    /// targets get a `Failed { errno = EFBIG }` outcome.
    pub quarantine_max_bytes: u64,

    /// Cgroup v2 root mount.
    pub cgroup_root: PathBuf,
    /// Slice we own under the cgroup root (sub-cgroups for blocked /
    /// throttled PIDs hang off this).
    pub cgroup_slice: String,

    /// nft table name. All rules live under this single table so we
    /// never collide with a host's existing nftables config.
    pub nft_table: String,

    /// Path to the persistence flag for `FullNetworkIsolation`. While
    /// this file exists at startup, the agent re-engages isolation.
    pub isolation_flag_file: PathBuf,
    /// IPv4 endpoints (`addr:port`) that stay reachable while
    /// isolated — placeholder for the Tappa 13 C2 backend.
    pub c2_endpoints: Vec<String>,

    /// **The agent-wide detect-only / no-enforcement gate.** When
    /// `true`, NOTHING touches the system: the [`Executor`](super::Executor)
    /// dispatcher suppresses every response action (kill, block,
    /// quarantine, throttle, isolation) and returns
    /// [`WouldExecute`](super::ExecutionOutcome::WouldExecute); `main.rs`
    /// gates COMBAT-posture network isolation on the same flag. The
    /// agent logs the verdict it WOULD have enforced and executes
    /// nothing — posture-independent (BUG-033). Set by `--detect-only`
    /// (canonical), or env `NN_DETECT_ONLY` / legacy `NORTHNARROW_DRY_RUN`
    /// (the legacy name now gates ALL enforcement, including kill +
    /// COMBAT, closing the old "dry-run that still kills" trap).
    pub dry_run: bool,
}

impl ExecutorConfig {
    /// Production defaults; `dry_run` may be flipped at construction
    /// time by reading the env var.
    pub fn from_env() -> Self {
        // One gate, multiple inputs: `--detect-only` is OR-ed in by
        // main; here we honour the canonical `NN_DETECT_ONLY` and the
        // legacy `NORTHNARROW_DRY_RUN` alias. Either one now suppresses
        // ALL enforcement (kill + COMBAT included).
        let dry_run = env_flag("NN_DETECT_ONLY") || env_flag("NORTHNARROW_DRY_RUN");
        Self {
            dry_run,
            ..Self::default()
        }
    }

    /// Build a config with paths rooted under `tmp_root`. Used by
    /// integration tests to keep system state untouched.
    pub fn for_test(tmp_root: &Path) -> Self {
        Self {
            quarantine_dir: tmp_root.join("quarantine"),
            master_key_file: tmp_root.join("master.key"),
            isolation_flag_file: tmp_root.join("isolated"),
            cgroup_root: tmp_root.join("cgroup"),
            cgroup_slice: "northnarrow.slice".into(),
            nft_table: "northnarrow_test".into(),
            c2_endpoints: Vec::new(),
            quarantine_max_bytes: 100 * 1024 * 1024,
            dry_run: true,
        }
    }

    /// Convenience: full path of the cgroup directory that holds
    /// PIDs blocked from outbound traffic.
    pub fn blocked_cgroup_dir(&self) -> PathBuf {
        self.cgroup_root
            .join(&self.cgroup_slice)
            .join("blocked.scope")
    }

    /// Convenience: full path of the cgroup directory for throttled
    /// PIDs.
    pub fn throttled_cgroup_dir(&self) -> PathBuf {
        self.cgroup_root
            .join(&self.cgroup_slice)
            .join("throttled.scope")
    }

    /// Cgroup-v2 socket-match name for the blocked scope, relative
    /// to the cgroup root, as nftables expects it.
    pub fn blocked_cgroup_match(&self) -> String {
        format!("{}/blocked.scope", self.cgroup_slice)
    }
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            quarantine_dir: PathBuf::from("/var/lib/northnarrow/quarantine"),
            master_key_file: PathBuf::from("/etc/northnarrow/master.key"),
            quarantine_max_bytes: 100 * 1024 * 1024,
            cgroup_root: PathBuf::from("/sys/fs/cgroup"),
            cgroup_slice: "northnarrow.slice".into(),
            nft_table: "northnarrow".into(),
            isolation_flag_file: PathBuf::from("/var/lib/northnarrow/isolated"),
            c2_endpoints: Vec::new(),
            dry_run: false,
        }
    }
}

/// True when env `var` is set to a truthy value (`1` / `true` / `yes`).
/// Shared by the detect-only inputs so `NN_DETECT_ONLY` and the legacy
/// `NORTHNARROW_DRY_RUN` parse identically.
fn env_flag(var: &str) -> bool {
    matches!(
        std::env::var(var).ok().as_deref(),
        Some("1") | Some("true") | Some("yes")
    )
}
