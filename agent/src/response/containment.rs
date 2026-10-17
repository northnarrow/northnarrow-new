//! The containment record (external audit CMB-010): which processes the
//! agent moved into its `blocked` or `throttled` scope, and the cgroup each
//! one came from.
//!
//! A release used to write the PID to the root cgroup: the process left its
//! systemd unit for good (its accounting and limits gone, `systemctl
//! status` no longer listing it, a stop reaching only a main process), and
//! the cgroup it came from was never recorded. Every move is now recorded
//! first — the process's start time (with the PID, the process) and its
//! cgroup as `/proc/<pid>/cgroup` shows it — in
//! `/run/northnarrow/containment.json`, written atomically (temporary
//! file, fsync, rename). On tmpfs: the record lives as long as the cgroups
//! it describes, one boot (the state directory, `chattr +i`, takes no new
//! file — found in the lab). A release writes the process back to
//! that cgroup; when it no longer exists or is no longer a leaf, the
//! process stays contained and the release says so. Nothing is written to
//! the root cgroup. At boot, [`reconcile`] drops the records of processes
//! that are gone and reports the ones still contained.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use super::config::ExecutorConfig;

/// One contained process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contained {
    pub pid: u32,
    /// `starttime` of `/proc/<pid>/stat` when it was moved.
    pub start_ticks: Option<u64>,
    /// `blocked` or `throttled`.
    pub scope: String,
    /// Its cgroup before the move, as `/proc/<pid>/cgroup` showed it
    /// (`/system.slice/foo.service`).
    pub origin: String,
    /// Unix time of the move.
    pub since: u64,
}

/// Read-modify-write of the record is serialised (the executor runs on
/// blocking threads of its own).
static LOCK: parking_lot::Mutex<()> = parking_lot::const_mutex(());

/// The cgroup v2 path `/proc/<pid>/cgroup` shows for `pid`.
pub fn origin_of(pid: u32) -> Option<String> {
    fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("0::").map(|p| p.trim_end().to_string()))
}

/// The records (missing file: none). A file that does not parse is kept
/// aside and treated as empty, with a warning.
pub fn load(cfg: &ExecutorConfig) -> Vec<Contained> {
    let path = &cfg.containment_file;
    match fs::read_to_string(path) {
        Ok(s) => match serde_json::from_str(&s) {
            Ok(v) => v,
            Err(e) => {
                let kept = path.with_extension(format!("json.corrupt-{}", now()));
                let _ = fs::rename(path, &kept);
                warn!(
                    error = %e,
                    kept = %kept.display(),
                    "containment record did not parse — kept aside; contained processes are found again at boot"
                );
                Vec::new()
            }
        },
        Err(_) => Vec::new(),
    }
}

fn store(cfg: &ExecutorConfig, entries: &[Contained]) -> std::io::Result<()> {
    let path = &cfg.containment_file;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    let body = serde_json::to_string_pretty(entries).map_err(std::io::Error::other)?;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(body.as_bytes())?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent().and_then(|d| fs::File::open(d).ok()) {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Record a move into `scope` (replacing an earlier record of the same
/// process and scope).
pub fn record(cfg: &ExecutorConfig, entry: Contained) -> std::io::Result<()> {
    let _g = LOCK.lock();
    let mut all = load(cfg);
    all.retain(|e| !(e.pid == entry.pid && e.scope == entry.scope));
    all.push(entry);
    store(cfg, &all)
}

/// The record of `pid` in `scope`.
pub fn find(cfg: &ExecutorConfig, pid: u32, scope: &str) -> Option<Contained> {
    let _g = LOCK.lock();
    load(cfg)
        .into_iter()
        .find(|e| e.pid == pid && e.scope == scope)
}

/// Drop the record of `pid` in `scope`.
pub fn remove(cfg: &ExecutorConfig, pid: u32, scope: &str) -> std::io::Result<()> {
    let _g = LOCK.lock();
    let mut all = load(cfg);
    let before = all.len();
    all.retain(|e| !(e.pid == pid && e.scope == scope));
    if all.len() != before {
        store(cfg, &all)?;
    }
    Ok(())
}

/// What a release did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Release {
    /// Back in the cgroup it came from.
    Released,
    /// Left contained, with the reason.
    Skipped(&'static str),
}

/// How a release checks the process (injected by the tests).
pub(crate) struct Probe<'a> {
    /// Is `pid` in the scope now?
    pub in_scope: &'a dyn Fn(u32) -> bool,
    /// The start ticks of the process `pid` names now.
    pub start_of: &'a dyn Fn(u32) -> Option<u64>,
}

/// Write `pid` back to the cgroup it came from, if it is still the process
/// that was moved into `scope` (`scope_name`: `blocked` / `throttled`) and
/// that cgroup can take it. The record is dropped once released, or once
/// the process is gone.
pub(crate) fn release_to_origin(
    pid: u32,
    start_ticks: Option<u64>,
    scope_name: &str,
    cfg: &ExecutorConfig,
    probe: &Probe,
) -> std::io::Result<Release> {
    if cfg.dry_run {
        return Ok(Release::Skipped("detect-only"));
    }
    if !(probe.in_scope)(pid) {
        let _ = remove(cfg, pid, scope_name);
        return Ok(Release::Skipped("not in the scope"));
    }
    let now_start = (probe.start_of)(pid);
    if now_start.is_none() || (start_ticks.is_some() && now_start != start_ticks) {
        return Ok(Release::Skipped("the pid now names another process"));
    }
    let Some(rec) = find(cfg, pid, scope_name) else {
        warn!(
            pid,
            scope = scope_name,
            "no record of the cgroup it came from — left contained"
        );
        return Ok(Release::Skipped("no record of the cgroup it came from"));
    };
    if rec.start_ticks.is_some() && rec.start_ticks != now_start {
        let _ = remove(cfg, pid, scope_name);
        return Ok(Release::Skipped("the pid now names another process"));
    }
    let dest = cfg
        .cgroup_root
        .join(rec.origin.trim_start_matches('/'))
        .join("cgroup.procs");
    if !dest.exists() {
        warn!(pid, origin = %common::log_escape::Escaped(&rec.origin), "the cgroup it came from is gone — left contained");
        return Ok(Release::Skipped("the cgroup it came from is gone"));
    }
    match super::block_outbound::write_pid(&dest, pid) {
        Ok(()) => {
            let _ = remove(cfg, pid, scope_name);
            info!(pid, origin = %common::log_escape::Escaped(&rec.origin), scope = scope_name, "released back to the cgroup it came from");
            Ok(Release::Released)
        }
        Err(e)
            if matches!(
                e.raw_os_error(),
                Some(libc::EBUSY) | Some(libc::EOPNOTSUPP) | Some(libc::ENOENT)
            ) =>
        {
            warn!(pid, origin = %common::log_escape::Escaped(&rec.origin), error = %e, "the cgroup it came from no longer takes processes — left contained");
            Ok(Release::Skipped(
                "the cgroup it came from no longer takes processes",
            ))
        }
        Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {
            let _ = remove(cfg, pid, scope_name);
            Ok(Release::Skipped("the process has exited"))
        }
        Err(e) => Err(e),
    }
}

/// What [`reconcile`] found at boot.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Reconciled {
    /// Records kept: the process is still contained.
    pub still_contained: Vec<Contained>,
    /// Records dropped: the process has exited (or the PID names another).
    pub dropped: usize,
}

/// At boot: drop the records of processes that are gone; keep and report
/// the ones still contained (a COMBAT episode does not survive an agent
/// restart: these have no automatic release).
pub fn reconcile(cfg: &ExecutorConfig) -> Reconciled {
    reconcile_with(cfg, &super::block_outbound::proc_start_ticks)
}

fn reconcile_with(cfg: &ExecutorConfig, start_of: &dyn Fn(u32) -> Option<u64>) -> Reconciled {
    let _g = LOCK.lock();
    let all = load(cfg);
    let mut out = Reconciled::default();
    for e in all {
        let now = start_of(e.pid);
        if now.is_some() && (e.start_ticks.is_none() || now == e.start_ticks) {
            out.still_contained.push(e);
        } else {
            out.dropped += 1;
        }
    }
    if out.dropped > 0 {
        let _ = store(cfg, &out.still_contained);
    }
    for e in &out.still_contained {
        warn!(
            pid = e.pid,
            scope = %e.scope,
            origin = %common::log_escape::Escaped(&e.origin),
            since = e.since,
            "contained by an earlier run of the agent — still in its scope (no automatic release after a restart)"
        );
    }
    out
}

pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn cfg(tmp: &TempDir) -> ExecutorConfig {
        ExecutorConfig {
            dry_run: false,
            ..ExecutorConfig::for_test(tmp.path())
        }
    }

    fn entry(pid: u32, origin: &str) -> Contained {
        Contained {
            pid,
            start_ticks: Some(u64::from(pid) * 10),
            scope: "blocked".into(),
            origin: origin.into(),
            since: 1,
        }
    }

    /// External audit CMB-010: a release writes the process back to the
    /// cgroup it came from, never to the root, and drops the record.
    #[test]
    fn release_returns_the_pid_to_its_unit() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg(&tmp);
        let unit = cfg.cgroup_root.join("system.slice/nn-victim.service");
        fs::create_dir_all(&unit).unwrap();
        fs::write(unit.join("cgroup.procs"), b"").unwrap();
        fs::write(cfg.cgroup_root.join("cgroup.procs"), b"").unwrap();
        record(&cfg, entry(4242, "/system.slice/nn-victim.service")).unwrap();
        let probe = Probe {
            in_scope: &|_| true,
            start_of: &|pid| Some(u64::from(pid) * 10),
        };
        let r = release_to_origin(4242, Some(42420), "blocked", &cfg, &probe).unwrap();
        assert_eq!(r, Release::Released);
        assert_eq!(
            fs::read_to_string(unit.join("cgroup.procs")).unwrap(),
            "4242"
        );
        assert_eq!(
            fs::read_to_string(cfg.cgroup_root.join("cgroup.procs")).unwrap(),
            ""
        );
        assert!(find(&cfg, 4242, "blocked").is_none());
    }

    /// External audit CMB-010: no record, a vanished unit, another process
    /// behind the PID: the process stays where it is.
    #[test]
    fn a_release_that_cannot_return_the_process_leaves_it_contained() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg(&tmp);
        fs::create_dir_all(&cfg.cgroup_root).unwrap();
        fs::write(cfg.cgroup_root.join("cgroup.procs"), b"").unwrap();
        let probe = Probe {
            in_scope: &|_| true,
            start_of: &|pid| Some(u64::from(pid) * 10),
        };
        assert_eq!(
            release_to_origin(7, Some(70), "blocked", &cfg, &probe).unwrap(),
            Release::Skipped("no record of the cgroup it came from")
        );
        record(&cfg, entry(7, "/system.slice/gone.service")).unwrap();
        assert_eq!(
            release_to_origin(7, Some(70), "blocked", &cfg, &probe).unwrap(),
            Release::Skipped("the cgroup it came from is gone")
        );
        let other = Probe {
            in_scope: &|_| true,
            start_of: &|_| Some(1),
        };
        assert_eq!(
            release_to_origin(7, Some(70), "blocked", &cfg, &other).unwrap(),
            Release::Skipped("the pid now names another process")
        );
        let outside = Probe {
            in_scope: &|_| false,
            start_of: &|pid| Some(u64::from(pid) * 10),
        };
        assert_eq!(
            release_to_origin(7, Some(70), "blocked", &cfg, &outside).unwrap(),
            Release::Skipped("not in the scope")
        );
        assert_eq!(
            fs::read_to_string(cfg.cgroup_root.join("cgroup.procs")).unwrap(),
            ""
        );
    }

    /// External audit CMB-010: at boot the records of exited processes go,
    /// the still-contained ones stay.
    #[test]
    fn reconcile_drops_the_gone_and_keeps_the_contained() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg(&tmp);
        record(&cfg, entry(1, "/a")).unwrap();
        record(&cfg, entry(2, "/b")).unwrap();
        record(&cfg, entry(3, "/c")).unwrap();
        // 1 runs on, 2 is gone, 3 is another process now
        let r = reconcile_with(&cfg, &|pid| match pid {
            1 => Some(10),
            3 => Some(99),
            _ => None,
        });
        assert_eq!(r.dropped, 2);
        assert_eq!(r.still_contained, vec![entry(1, "/a")]);
        assert_eq!(load(&cfg), vec![entry(1, "/a")]);
    }

    #[test]
    fn a_corrupt_record_is_kept_aside() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg(&tmp);
        fs::create_dir_all(cfg.containment_file.parent().unwrap()).unwrap();
        fs::write(&cfg.containment_file, b"{ nope").unwrap();
        assert!(load(&cfg).is_empty());
        assert!(!cfg.containment_file.exists());
        record(&cfg, entry(5, "/x")).unwrap();
        assert_eq!(load(&cfg), vec![entry(5, "/x")]);
    }
}
