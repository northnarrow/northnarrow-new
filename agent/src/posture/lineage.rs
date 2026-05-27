//! T7.13 — sudo-mediated process lineage tracking (Beta Step 5).
//!
//! The agent's posture machine has two trigger arms that fire on
//! legitimate `sudo` activity:
//!
//! 1. [`super::triggers::sensitive_file_access`] — sudo's PAM auth
//!    chain opens `/etc/shadow` while the kernel is still at the
//!    caller's `uid=1000`; the LSM `file_open` observe hook captures
//!    the original `fsuid`, not the post-setuid one.
//! 2. [`super::triggers::confirmed_intrusion`] mass-write arm — sudo
//!    and its elevated child (apt, systemctl, an editor, …) write
//!    ≥20 files inside the 60 s mass-write window during routine
//!    administration, identical in shape to a ransomware burst.
//!
//! Both behaviours are legitimate administration. The previous fixes
//! (PR #123, Beta Step 3) excluded the NorthNarrow stack's own PIDs;
//! T7.13 requires extending the exclusion surface to **operator-driven
//! setuid administration** without granting blanket immunity.
//!
//! [`AuthSessionTracker`] tags a PID as *auth-mediated* if any
//! ancestor's `/proc/<pid>/exe` (a kernel-resolved symlink — not
//! forgeable from userspace) matches the hard-coded
//! [`AUTH_BINARY_EXES`] allowlist of canonical setuid administration
//! binaries. Only [`super::triggers::sensitive_file_access`] and the
//! mass-write arm of [`super::triggers::confirmed_intrusion`] consult
//! the tracker; every other COMBAT-tier trigger (FsProtectDenial,
//! exec from `/tmp` or `/dev/shm`, persistence_mechanism,
//! critical_file_modification, lateral_movement,
//! exfiltration_pattern, exploit_attempt, lolbas_pattern) fires
//! unchanged. An attacker who has compromised an admin's sudo
//! password and is dropping a `/tmp` payload still trips
//! ConfirmedIntrusion via the exec-from-`/tmp` arm.
//!
//! ## Why exe-path, not comm
//!
//! `comm` is attacker-controllable (`prctl(PR_SET_NAME, …)`), so
//! exempting by comm would let any process rename itself `sudo` to
//! gain trigger immunity — the same bypass class the watchdog
//! supervisor model exists to prevent. We instead key on
//! `/proc/<pid>/exe`, which the kernel resolves from the task's
//! `mm->exe_file` and exposes as a symlink that userspace cannot
//! forge. The in-memory cache populated from `Event::ProcessSpawn`
//! records the same path the kernel-side hook reads from the task
//! at exec time.

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::RwLock;

/// Hard-coded allowlist of installed setuid/setgid binaries whose
/// children we treat as auth-mediated. Covers Debian/Ubuntu,
/// Fedora/RHEL, Arch, and openSUSE conventions for the canonical
/// administrative escalation paths. Adding paths is a soft change
/// (expands exemption); removing is a hard change (operators on a
/// distro that uses only the removed path lose all sudo coverage).
///
/// Sorted alphabetically for review legibility; lookup is a linear
/// scan over <30 entries, well under any per-event budget.
pub const AUTH_BINARY_EXES: &[&str] = &[
    "/bin/login",
    "/bin/su",
    "/bin/sudo",
    "/usr/bin/chfn",
    "/usr/bin/chsh",
    "/usr/bin/doas",
    "/usr/bin/gpasswd",
    "/usr/bin/login",
    "/usr/bin/machinectl",
    "/usr/bin/passwd",
    "/usr/bin/pkexec",
    "/usr/bin/su",
    "/usr/bin/sudo",
    "/usr/bin/sudoedit",
    "/usr/bin/systemd-run",
    "/usr/lib/polkit-1/polkit-agent-helper-1",
    "/usr/libexec/openssh/sshd",
    "/usr/libexec/polkit-1/polkit-agent-helper-1",
    "/usr/sbin/sshd",
];

/// Bounded FIFO cap for the in-memory pid→Entry map. At ~64 bytes
/// per entry (pid + ppid + spawn_ns + short PathBuf) the cap is
/// ~128 KiB worst case — comfortably inside the agent's per-task
/// RAM ceiling, sized to cover the long tail of long-lived sudo
/// sessions on a busy workstation. Overflow falls back to the
/// `/proc/<pid>/exe`+`/proc/<pid>/status` walk so a miss is never
/// fatal — just one extra `read_link` + small file read.
const TRACKER_CAP: usize = 2048;

/// Hard ceiling on the per-`is_auth_mediated` lineage walk. A
/// pathological cycle in `/proc` (or a fabricated chain that never
/// reaches PID 0/1) must not hang the trigger detector. 32 is well
/// past the deepest real process tree on a healthy host.
const LINEAGE_DEPTH_CAP: usize = 32;

/// PID→{ppid, exe, spawn_ns} cache entry recorded from
/// `Event::ProcessSpawn`. `spawn_ns` is retained for forward
/// compatibility with a `(pid, start_ns)` PID-reuse disambiguator;
/// today we simply overwrite the entry on a fresh spawn.
#[derive(Debug, Clone)]
struct Entry {
    ppid: u32,
    exe: PathBuf,
    #[allow(dead_code)]
    spawn_ns: u64,
}

/// Mutex-shielded state. A single lock guards both the map and the
/// FIFO eviction queue so the two never observe each other in an
/// inconsistent state mid-ingest.
#[derive(Debug)]
struct InnerState {
    map: HashMap<u32, Entry>,
    /// Insertion order — pushed on first insert, popped on
    /// eviction. We deliberately do NOT re-promote on overwrite:
    /// strict LRU would cost O(N) per overwrite without buying
    /// correctness, because [`AuthSessionTracker::is_auth_mediated`]
    /// falls back to `/proc` on miss. Any over-eager eviction of a
    /// hot entry simply pays a single readlink+read_to_string on
    /// the next lookup.
    order: VecDeque<u32>,
}

#[derive(Debug)]
struct Inner {
    state: RwLock<InnerState>,
    /// Injectable for tests; `"/proc"` in production.
    proc_root: PathBuf,
}

/// Cheap, `Clone`-able shared handle. The tracker is `Send + Sync`
/// so both the per-event trigger detector and (future) background
/// pruning tasks can hold one without further plumbing.
#[derive(Clone, Debug)]
pub struct AuthSessionTracker {
    inner: Arc<Inner>,
}

impl AuthSessionTracker {
    /// Construct a tracker reading `/proc` from `proc_root`. The
    /// indirection is the test seam: production uses
    /// [`Self::with_proc`]; unit tests point at a fixture tree.
    pub fn new(proc_root: impl Into<PathBuf>) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: RwLock::new(InnerState {
                    map: HashMap::with_capacity(TRACKER_CAP),
                    order: VecDeque::with_capacity(TRACKER_CAP),
                }),
                proc_root: proc_root.into(),
            }),
        }
    }

    /// Production constructor — reads the live `/proc`.
    pub fn with_proc() -> Self {
        Self::new("/proc")
    }

    /// Record a `ProcessSpawn` observation. Overwrites any prior
    /// entry for `pid` (PID reuse — the new spawn replaces the old
    /// lineage). Evicts the oldest first-inserted entry when the
    /// cache reaches [`TRACKER_CAP`].
    ///
    /// PID 0 is the kernel "no process" sentinel and is never
    /// recorded.
    pub fn ingest_spawn(&self, pid: u32, ppid: u32, exe: &str, spawn_ns: u64) {
        if pid == 0 {
            return;
        }
        let mut s = self.inner.state.write();
        let had_prior = s
            .map
            .insert(
                pid,
                Entry {
                    ppid,
                    exe: PathBuf::from(exe),
                    spawn_ns,
                },
            )
            .is_some();
        if !had_prior {
            s.order.push_back(pid);
            while s.order.len() > TRACKER_CAP {
                if let Some(evict) = s.order.pop_front() {
                    // Possible-stale guard: only remove if the
                    // map still maps this pid to ANY entry. (A
                    // future PID-reuse handler could promote on
                    // overwrite; today we simply evict whatever
                    // is there, and the `/proc` fallback covers
                    // the rare case where the evicted entry was
                    // freshly overwritten.)
                    s.map.remove(&evict);
                }
            }
        }
    }

    /// Walk the lineage of `pid` upward through (ppid, exe) pairs
    /// and return true if any ancestor's exe matches
    /// [`AUTH_BINARY_EXES`]. Cache miss falls back to
    /// `/proc/<pid>/exe` (symlink read, kernel-resolved) plus
    /// `/proc/<pid>/status` `PPid:` parsing. Capped at
    /// [`LINEAGE_DEPTH_CAP`] hops to bound the worst-case cost.
    ///
    /// PIDs 0 and 1 (kernel / init) are never auth-mediated and
    /// are an unconditional terminator.
    pub fn is_auth_mediated(&self, pid: u32) -> bool {
        if pid == 0 || pid == 1 {
            return false;
        }
        let mut cur = pid;
        let mut visited = 0usize;
        loop {
            if visited >= LINEAGE_DEPTH_CAP {
                return false;
            }
            visited += 1;

            let (ppid, exe) = match self.lookup_cache(cur) {
                Some(pair) => pair,
                None => match self.lookup_proc(cur) {
                    Some(pair) => pair,
                    None => return false,
                },
            };
            if is_auth_binary(&exe) {
                return true;
            }
            if ppid == 0 || ppid == 1 || ppid == cur {
                return false;
            }
            cur = ppid;
        }
    }

    fn lookup_cache(&self, pid: u32) -> Option<(u32, PathBuf)> {
        let s = self.inner.state.read();
        s.map.get(&pid).map(|e| (e.ppid, e.exe.clone()))
    }

    fn lookup_proc(&self, pid: u32) -> Option<(u32, PathBuf)> {
        let pid_str = pid.to_string();
        let exe_link = self.inner.proc_root.join(&pid_str).join("exe");
        let exe = fs::read_link(&exe_link).ok()?;
        // `/proc/<pid>/exe` carries a ` (deleted)` suffix when the
        // on-disk binary was unlinked while the process is still
        // running. Treat that as a mismatch — a deleted/swapped
        // auth binary is exactly the case we must not trust.
        let exe_str = exe.to_string_lossy();
        if exe_str.ends_with(" (deleted)") {
            return None;
        }
        let status_path = self.inner.proc_root.join(&pid_str).join("status");
        let text = fs::read_to_string(&status_path).ok()?;
        let ppid = parse_ppid(&text)?;
        Some((ppid, exe))
    }

    #[cfg(test)]
    fn entry_count(&self) -> usize {
        self.inner.state.read().map.len()
    }
}

impl Default for AuthSessionTracker {
    fn default() -> Self {
        Self::with_proc()
    }
}

fn is_auth_binary(exe: &Path) -> bool {
    let s = exe.to_string_lossy();
    AUTH_BINARY_EXES.iter().any(|p| s == *p)
}

/// Extract the `PPid: <n>` value from a `/proc/<pid>/status` body.
fn parse_ppid(status_text: &str) -> Option<u32> {
    for line in status_text.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    fn write_status(dir: &Path, pid: u32, ppid: u32) {
        let pid_dir = dir.join(pid.to_string());
        fs::create_dir_all(&pid_dir).unwrap();
        fs::write(
            pid_dir.join("status"),
            format!("Name:\tx\nPid:\t{pid}\nPPid:\t{ppid}\n"),
        )
        .unwrap();
    }

    fn write_exe(dir: &Path, pid: u32, target: &str) {
        let pid_dir = dir.join(pid.to_string());
        fs::create_dir_all(&pid_dir).unwrap();
        let exe_path = pid_dir.join("exe");
        // tempfile lifetime is per-test; ensure no stale symlink.
        let _ = fs::remove_file(&exe_path);
        symlink(target, &exe_path).unwrap();
    }

    #[test]
    fn ingest_records_entry() {
        let t = AuthSessionTracker::new("/proc");
        t.ingest_spawn(100, 1, "/usr/bin/sudo", 1_000);
        assert_eq!(t.entry_count(), 1);
    }

    #[test]
    fn pid_zero_is_never_recorded_or_auth_mediated() {
        let t = AuthSessionTracker::new("/proc");
        t.ingest_spawn(0, 0, "/usr/bin/sudo", 0);
        assert_eq!(t.entry_count(), 0);
        assert!(!t.is_auth_mediated(0));
    }

    #[test]
    fn pid_one_is_never_auth_mediated() {
        let t = AuthSessionTracker::new("/proc");
        // Even if some weirdness lands PID 1 in the cache, the
        // terminator short-circuit blocks it before the walk.
        assert!(!t.is_auth_mediated(1));
    }

    #[test]
    fn direct_sudo_pid_is_auth_mediated() {
        let t = AuthSessionTracker::new("/proc");
        t.ingest_spawn(100, 50, "/usr/bin/sudo", 1);
        assert!(t.is_auth_mediated(100));
    }

    #[test]
    fn subprocess_of_sudo_is_auth_mediated_via_lineage() {
        let t = AuthSessionTracker::new("/proc");
        t.ingest_spawn(100, 50, "/usr/bin/sudo", 1);
        t.ingest_spawn(200, 100, "/usr/bin/apt", 2);
        assert!(t.is_auth_mediated(200));
    }

    #[test]
    fn nested_sudo_chain_is_auth_mediated_at_depth() {
        let t = AuthSessionTracker::new("/proc");
        // user shell (50) -> sudo (100) -> bash (200) -> apt (300).
        t.ingest_spawn(100, 50, "/usr/bin/sudo", 1);
        t.ingest_spawn(200, 100, "/bin/bash", 2);
        t.ingest_spawn(300, 200, "/usr/bin/apt", 3);
        assert!(t.is_auth_mediated(300));
    }

    #[test]
    fn unrelated_pid_with_no_auth_ancestor_is_not_auth_mediated() {
        let t = AuthSessionTracker::new("/proc");
        // user shell (50) -> firefox (200). No sudo anywhere.
        t.ingest_spawn(200, 50, "/usr/bin/firefox", 1);
        t.ingest_spawn(50, 1, "/bin/bash", 0);
        assert!(!t.is_auth_mediated(200));
    }

    #[test]
    fn pid_reuse_invalidates_lineage() {
        let t = AuthSessionTracker::new("/proc");
        t.ingest_spawn(100, 50, "/usr/bin/sudo", 1);
        assert!(t.is_auth_mediated(100));
        // Same PID re-spawned as something innocuous; lineage drops.
        t.ingest_spawn(100, 50, "/bin/cat", 2);
        // Parent pid=50 has no entry; lookup_proc on templess "/proc"
        // for pid 50 will fail; net result: not auth-mediated.
        assert!(!t.is_auth_mediated(100));
    }

    // ── Test #11: cold-start /proc fallback ────────────────────────
    #[test]
    fn lineage_cold_start_falls_back_to_proc() {
        let tmp = TempDir::new().unwrap();
        let proc_root = tmp.path();
        // Build a fake /proc fixture:
        //   pid 123 -> exe /usr/bin/sudo, ppid=1
        //   pid 124 -> exe /usr/bin/apt,  ppid=123
        write_exe(proc_root, 123, "/usr/bin/sudo");
        write_status(proc_root, 123, 1);
        write_exe(proc_root, 124, "/usr/bin/apt");
        write_status(proc_root, 124, 123);

        let t = AuthSessionTracker::new(proc_root);
        // Cache is empty — the walk must reconstruct from /proc.
        assert!(t.is_auth_mediated(124));
        assert!(t.is_auth_mediated(123));
    }

    // ── Test #12: /proc unavailable returns false ───────────────────
    #[test]
    fn proc_unavailable_returns_false_on_miss() {
        let tmp = TempDir::new().unwrap();
        // proc_root points at an empty tempdir — every readlink fails.
        let t = AuthSessionTracker::new(tmp.path());
        assert!(!t.is_auth_mediated(99_999));
    }

    // ── Test #13: deleted-suffix exe is rejected ────────────────────
    #[test]
    fn auth_binary_with_deleted_suffix_rejected() {
        let tmp = TempDir::new().unwrap();
        let proc_root = tmp.path();
        // Mimic a /proc/<pid>/exe whose target is sudo but suffixed
        // " (deleted)" — the kernel appends this when the on-disk
        // file has been unlinked. We must NOT trust it as
        // auth-mediated, since a deleted/swapped binary is exactly
        // the supply-chain attack class we have to refuse.
        write_exe(proc_root, 123, "/usr/bin/sudo (deleted)");
        write_status(proc_root, 123, 1);
        let t = AuthSessionTracker::new(proc_root);
        assert!(!t.is_auth_mediated(123));
    }

    // ── Test #14: bounded FIFO eviction on cap overflow ─────────────
    #[test]
    fn ingest_overwrites_lru_when_cap_exceeded() {
        let t = AuthSessionTracker::new("/proc");
        // Fill past TRACKER_CAP with distinct pids.
        for pid in 1..=(TRACKER_CAP as u32 + 5) {
            t.ingest_spawn(pid, 1, "/usr/bin/cat", pid as u64);
        }
        // Map must not exceed the cap.
        assert!(t.entry_count() <= TRACKER_CAP);
        assert!(t.entry_count() >= TRACKER_CAP - 5);
    }

    #[test]
    fn lineage_depth_capped_prevents_cycle_hang() {
        let t = AuthSessionTracker::new("/proc");
        // Build a chain longer than LINEAGE_DEPTH_CAP with no
        // auth binary anywhere.
        for i in 1..=(LINEAGE_DEPTH_CAP as u32 + 5) {
            // chain: i -> (i+1)
            t.ingest_spawn(i, i + 1, "/usr/bin/cat", i as u64);
        }
        // pid=1 walks up to LINEAGE_DEPTH_CAP+5; must terminate
        // with `false`, not loop.
        assert!(!t.is_auth_mediated(1));
    }

    #[test]
    fn self_referential_lineage_does_not_loop() {
        let t = AuthSessionTracker::new("/proc");
        // pid 100 lists itself as its own ppid — corrupt /proc
        // synthesis would do this. Must terminate, not hang.
        t.ingest_spawn(100, 100, "/usr/bin/cat", 1);
        assert!(!t.is_auth_mediated(100));
    }

    #[test]
    fn parse_ppid_extracts_value() {
        let body =
            "Name:\tbash\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t12\nPid:\t12\nPPid:\t1\n";
        assert_eq!(parse_ppid(body), Some(1));
    }

    #[test]
    fn parse_ppid_returns_none_on_missing_line() {
        let body = "Name:\tbash\nPid:\t12\n";
        assert_eq!(parse_ppid(body), None);
    }

    #[test]
    fn is_auth_binary_matches_exact_paths_only() {
        assert!(is_auth_binary(Path::new("/usr/bin/sudo")));
        assert!(is_auth_binary(Path::new("/usr/bin/sudoedit")));
        assert!(is_auth_binary(Path::new("/usr/sbin/sshd")));
        assert!(!is_auth_binary(Path::new("/tmp/sudo")));
        assert!(!is_auth_binary(Path::new("/usr/local/bin/sudo")));
        assert!(!is_auth_binary(Path::new("/usr/bin/sudo-helper")));
    }

    #[test]
    fn clone_shares_state() {
        let a = AuthSessionTracker::new("/proc");
        let b = a.clone();
        a.ingest_spawn(100, 1, "/usr/bin/sudo", 1);
        // Clone observes the ingest — same Arc-backed state.
        assert!(b.is_auth_mediated(100));
    }
}
