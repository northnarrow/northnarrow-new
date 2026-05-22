//! Tappa 9.5.1 D3 — anti-tamper honeypot privileged e2e.
//!
//! Drives the NN-L-FIM-024 bait files END-TO-END on a live kernel: a
//! real agent watches the (real) `HONEYPOT_PATHS`, an EXTERNAL process
//! tampers one, and we assert the Critical verdict + KillProcessTree +
//! COMBAT posture transition. Also covers the boot integrity sweep
//! (RFC Q5) and the PROTECTED_PIDS self-write negative.
//!
//! The rule keys on the hard-coded `/etc/northnarrow/...`,
//! `/var/lib/northnarrow/...`, `/run/northnarrow/...` paths, so unlike
//! the tempdir-based FIM tests this one touches the REAL filesystem.
//! [`RealBaitGuard`] records which baits/dirs pre-existed and removes
//! only those the test (or the agent's boot recreate) created.
//!
//! The tamper is performed by a DISPOSABLE `sh -c` child, never the test
//! harness — the rule's KillProcessTree targets the modifier PID, which
//! must not be us. (Mirrors the T10.6 D9 external-helper pattern + the
//! post-hotfix path-safe install.)
//!
//! Run:
//!   sudo -E env "PATH=$PATH" cargo test --release \
//!     -p northnarrow-agent --test honeypot_tamper_e2e \
//!     --features "test-privileged debug-trigger" \
//!     -- --include-ignored --test-threads=1

#![cfg(feature = "test-privileged")]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use northnarrow_agent::fim::rules::HONEYPOT_PATHS;

mod common;
use common::EniIptablesGuard;

const SOCKET_POLL_TIMEOUT: Duration = Duration::from_secs(15);
const VERDICT_POLL_TIMEOUT: Duration = Duration::from_secs(20);
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const PRIV_BIN_DIR: &str = "/usr/local/bin";
const REAL_SUDO: &str = "/usr/bin/sudo";

fn agent_bin() -> &'static str {
    env!("CARGO_BIN_EXE_northnarrow-agent")
}
fn nn_admin_bin() -> &'static str {
    env!("CARGO_BIN_EXE_nn-admin")
}
fn combat_rules_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("configs")
        .join("combat-rules.v4")
}
fn canary_templates_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("configs")
        .join("canary-templates")
}

// ── path-safe install (post-T10.6 hotfix: absolute sudo) ────────────

struct InstalledBin {
    path: PathBuf,
}
impl Drop for InstalledBin {
    fn drop(&mut self) {
        let _ = Command::new(REAL_SUDO)
            .arg("rm")
            .arg("-f")
            .arg(&self.path)
            .status();
    }
}
fn install_to_priv_bin(src: &Path) -> InstalledBin {
    let basename = src.file_name().and_then(|s| s.to_str()).expect("basename");
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dst = PathBuf::from(format!(
        "{PRIV_BIN_DIR}/{basename}-e2etest-{ts}-{}",
        std::process::id()
    ));
    let status = Command::new(REAL_SUDO)
        .args(["install", "-m", "755", "-o", "root", "-g", "root"])
        .arg(src)
        .arg(&dst)
        .status()
        .expect("spawn sudo install");
    assert!(status.success(), "sudo install of {} failed", src.display());
    InstalledBin { path: dst }
}

/// SIGQUIT-on-drop (Tappa 7 LSM blocks SIGKILL/SIGTERM).
struct AgentGuard(Option<Child>);
impl Drop for AgentGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            unsafe {
                libc::kill(c.id() as i32, libc::SIGQUIT);
            }
            let _ = c.wait();
        }
    }
}

const BPFFS_PIN_ROOT: &str = "/sys/fs/bpf/northnarrow";
fn wipe_pin_tree() {
    let pin = Path::new(BPFFS_PIN_ROOT);
    if let Ok(entries) = std::fs::read_dir(pin) {
        for e in entries.flatten() {
            let _ = std::fs::remove_file(e.path());
        }
    }
    let _ = std::fs::remove_dir(pin);
}

/// RAII cleanup for the REAL bait files + their dirs. Records which of
/// the 10 paths (and the three parent dirs) existed at construction;
/// on drop removes only those the test/agent created, restoring the
/// host. Robust against an interrupted run leaving inert config behind.
struct RealBaitGuard {
    preexisting_files: Vec<bool>,
    preexisting_dirs: Vec<(PathBuf, bool)>,
}
impl RealBaitGuard {
    fn capture() -> Self {
        // Clear any prior test's anti-tamper LSM FIRST. The LSM pins
        // survive an agent SIGQUIT (anti-tamper persists by design), and
        // a stale agent's PROTECTED_PIDS would -EPERM our seeding of the
        // protected /etc + /var/lib northnarrow dirs (and block the next
        // agent's own writes). Removing the pins detaches the dead
        // agent's LSM. Called before any seed_real_bait.
        wipe_pin_tree();
        let dirs = [
            "/etc/northnarrow",
            "/var/lib/northnarrow",
            "/run/northnarrow",
        ];
        Self {
            preexisting_files: HONEYPOT_PATHS
                .iter()
                .map(|p| Path::new(p).exists())
                .collect(),
            preexisting_dirs: dirs
                .iter()
                .map(|d| (PathBuf::from(d), Path::new(d).exists()))
                .collect(),
        }
    }
}
impl Drop for RealBaitGuard {
    fn drop(&mut self) {
        for (i, p) in HONEYPOT_PATHS.iter().enumerate() {
            if !self.preexisting_files[i] {
                let _ = Command::new(REAL_SUDO).arg("rm").arg("-f").arg(p).status();
                // a Renamed test may have left <path>.moved
                let _ = Command::new(REAL_SUDO)
                    .arg("rm")
                    .arg("-f")
                    .arg(format!("{p}.moved"))
                    .status();
            }
        }
        for (dir, existed) in &self.preexisting_dirs {
            if !existed {
                let _ = Command::new(REAL_SUDO).arg("rmdir").arg(dir).status();
            }
        }
    }
}

/// Remove a single real bait path (root) — used to set up the
/// "missing at boot" integrity case.
fn sudo_rm(path: &str) {
    let _ = Command::new(REAL_SUDO)
        .arg("rm")
        .arg("-f")
        .arg(path)
        .status();
}

// ── agent fixture ───────────────────────────────────────────────────

struct Fixture {
    _tempdir: tempfile::TempDir,
    agent_log: PathBuf,
    _agent_guard: AgentGuard,
    _installed_agent: InstalledBin,
    _installed_admin: InstalledBin,
}

impl Fixture {
    /// Spawn an agent watching the given `fim_watch_paths`. Empty
    /// allow/blocklists; ADE off; COMBAT rules wired so a Critical
    /// verdict drives the posture transition.
    fn setup(fim_watch_paths: &[&str]) -> Self {
        wipe_pin_tree();
        let tempdir = tempfile::tempdir().expect("tempdir");
        let dir = tempdir.path().to_path_buf();

        let installed_agent = install_to_priv_bin(Path::new(agent_bin()));
        let installed_admin = install_to_priv_bin(Path::new(nn_admin_bin()));

        // Per-test admin keypair.
        let admin_pub = dir.join("admin.pub");
        let admin_priv = dir.join("admin.priv");
        let tmp_pub = dir.join("admin.pub.tmp");
        let init_status = Command::new(&installed_admin.path)
            .args(["init", "--priv-out"])
            .arg(&admin_priv)
            .arg("--pub-append")
            .arg(&tmp_pub)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("spawn nn-admin init");
        assert!(init_status.success(), "nn-admin init failed");
        let tmp_body = std::fs::read_to_string(&tmp_pub).expect("read tmp pubkey");
        let hex = tmp_body
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with('#'))
            .expect("init pub file has no hex line");
        let mut pub_file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&admin_pub)
            .expect("create admin.pub");
        writeln!(pub_file, "{hex} all").expect("write admin.pub");
        drop(pub_file);
        let _ = std::fs::remove_file(&tmp_pub);

        let combat = dir.join("combat-rules.v4");
        std::fs::copy(combat_rules_path(), &combat).expect("copy combat rules");

        let fim_paths_v1 = dir.join("fim-paths.v1");
        let body: String = fim_watch_paths.iter().map(|p| format!("{p}\n")).collect();
        std::fs::write(&fim_paths_v1, body).expect("write fim-paths.v1");
        let fim_paths_local = dir.join("fim-paths.local");
        std::fs::write(&fim_paths_local, "").expect("write fim-paths.local");

        let templates_dir = dir.join("canary-templates");
        std::fs::create_dir(&templates_dir).expect("mkdir canary-templates");
        for entry in std::fs::read_dir(canary_templates_dir()).expect("read templates") {
            let path = entry.expect("template dirent").path();
            if path.extension().and_then(|e| e.to_str()) == Some("tmpl") {
                let base = path.file_name().expect("template basename");
                std::fs::copy(&path, templates_dir.join(base)).expect("copy template");
            }
        }

        let write_empty = |name: &str| {
            let p = dir.join(name);
            std::fs::write(&p, "").unwrap_or_else(|_| panic!("write {name}"));
            p
        };
        let nb_v1 = write_empty("netflow-blocklist.v1");
        let nb_local = write_empty("netflow-blocklist.local");
        let ja3_v1 = write_empty("netflow-ja3-blocklist.v1");
        let ja3_local = write_empty("netflow-ja3-blocklist.local");
        let pca_v1 = write_empty("process-comm-allowlist.v1");
        let pca_local = write_empty("process-comm-allowlist.local");
        let nca_v1 = write_empty("netflow-comm-allowlist.v1");
        let nca_local = write_empty("netflow-comm-allowlist.local");

        let agent_log = dir.join("agent.log");
        let log_file = std::fs::File::create(&agent_log).expect("create agent.log");
        let log_file_err = log_file.try_clone().expect("clone log handle");

        let child = Command::new(REAL_SUDO)
            .arg(&installed_agent.path)
            .arg("--combat-rules")
            .arg(&combat)
            .arg("--admin-pub")
            .arg(&admin_pub)
            .arg("--admin-socket")
            .arg(dir.join("admin.sock"))
            .arg("--agent-id-file")
            .arg(dir.join("agent_id"))
            .arg("--audit-log-file")
            .arg(dir.join("audit.log"))
            .arg("--signing-key-file")
            .arg(dir.join("agent.sig.key"))
            .arg("--shutdown-marker-file")
            .arg(dir.join("agent.shutdown_authorised"))
            .arg("--fim-paths-v1")
            .arg(&fim_paths_v1)
            .arg("--fim-paths-local")
            .arg(&fim_paths_local)
            .arg("--fim-baseline-file")
            .arg(dir.join("fim_baseline.jsonl"))
            .arg("--fim-drift-file")
            .arg(dir.join("fim_drift.jsonl"))
            .arg("--canary-registry-file")
            .arg(dir.join("canaries.jsonl"))
            .arg("--canary-access-file")
            .arg(dir.join("canary_access.jsonl"))
            .arg("--canary-template-dir")
            .arg(&templates_dir)
            .arg("--netflow-file")
            .arg(dir.join("netflow.jsonl"))
            .arg("--netflow-listeners-file")
            .arg(dir.join("netflow_listeners.jsonl"))
            .arg("--netflow-blocklist-v1")
            .arg(&nb_v1)
            .arg("--netflow-blocklist-local")
            .arg(&nb_local)
            .arg("--netflow-ja3-blocklist-v1")
            .arg(&ja3_v1)
            .arg("--netflow-ja3-blocklist-local")
            .arg(&ja3_local)
            .arg("--process-comm-allowlist-v1")
            .arg(&pca_v1)
            .arg("--process-comm-allowlist-local")
            .arg(&pca_local)
            .arg("--netflow-comm-allowlist-v1")
            .arg(&nca_v1)
            .arg("--netflow-comm-allowlist-local")
            .arg(&nca_local)
            .arg("--no-ade")
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(log_file_err))
            .spawn()
            .expect("spawn northnarrow-agent for honeypot e2e");

        let admin_socket = dir.join("admin.sock");
        let guard = AgentGuard(Some(child));
        wait_for_socket(&admin_socket);

        Self {
            _tempdir: tempdir,
            agent_log,
            _agent_guard: guard,
            _installed_agent: installed_agent,
            _installed_admin: installed_admin,
        }
    }

    fn log_contains(&self, needle: &str) -> bool {
        std::fs::read_to_string(&self.agent_log)
            .map(|s| s.contains(needle))
            .unwrap_or(false)
    }

    fn wait_for(&self, needle: &str) {
        let deadline = Instant::now() + VERDICT_POLL_TIMEOUT;
        while Instant::now() < deadline {
            if self.log_contains(needle) {
                return;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        let log = std::fs::read_to_string(&self.agent_log).unwrap_or_default();
        let lines: Vec<&str> = log.lines().collect();
        let head = lines
            .iter()
            .take(50)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");
        let tail = lines
            .iter()
            .rev()
            .take(15)
            .rev()
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");
        panic!(
            "agent.log never contained {needle:?} within {VERDICT_POLL_TIMEOUT:?}\n\
             --- head(50) ---\n{head}\n--- tail(15) ---\n{tail}"
        );
    }

    fn assert_absent(&self, needle: &str, window: Duration) {
        std::thread::sleep(window);
        assert!(
            !self.log_contains(needle),
            "{needle:?} unexpectedly present in agent.log"
        );
    }
}

fn wait_for_socket(path: &Path) {
    let deadline = Instant::now() + SOCKET_POLL_TIMEOUT;
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    panic!("agent never opened admin socket at {}", path.display());
}

/// Poll for a path to exist within `timeout`.
fn wait_for_file(path: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if Path::new(path).exists() {
            return true;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    Path::new(path).exists()
}

/// Create a real bait path (with its dir) as root, watch-ready, with the
/// canonical content — the baseline an external tamper then mutates.
fn seed_real_bait(path: &str) {
    let parent = Path::new(path).parent().unwrap().to_str().unwrap();
    // `mkdir -p` (not `install -d`) — never chmod/chown an EXISTING dir
    // (/var/lib/northnarrow ships at 0700; `install -d` would try to
    // reset it to 0755, which fails on a protected dir).
    let _ = Command::new(REAL_SUDO)
        .args(["mkdir", "-p", parent])
        .status();
    let content = northnarrow_agent::fim::honeypot::bait_content(path).expect("bait content");
    // tee as root so the file is root-owned (matches install.sh).
    let mut c = Command::new(REAL_SUDO)
        .args(["tee", path])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn sudo tee");
    c.stdin
        .take()
        .unwrap()
        .write_all(content.as_bytes())
        .unwrap();
    assert!(c.wait().expect("tee wait").success(), "seed {path} failed");
}

/// Tamper a real bait from a DISPOSABLE external `sh -c` child (so the
/// rule's KillProcessTree targets it, not the test harness).
fn external_tamper(cmd: &str) {
    let _ = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

const VERDICT_ID: &str = "NN-L-FIM-024_AntiTamperHoneypotModified";

// NOTE on the tamper op: these tests use DELETE (`rm`) as the tamper —
// the canonical "disable NN" action (remove a fake kill-switch / lock)
// AND the FIM op that fires deterministically on this kernel
// (inode_unlink → FIM_OP_DELETED). chmod→Modified (inode_setattr) and
// mv→Renamed (inode_rename) of a watched FILE do NOT reliably emit a
// drift event here — a pre-existing FIM eBPF/kernel-ABI gap the older
// FIM e2e masks by accepting Modified OR Opened; tracked as a T9.5.1
// follow-up. Delete coverage across /etc, /var/lib and /run exercises
// the rule on every bait dir.

/// #1 — external DELETE of kill_switch.conf (/etc) → Critical verdict +
/// KillProcessTree + COMBAT.
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn delete_kill_switch_conf_trips_fim024_combat() {
    let _eni = EniIptablesGuard::install();
    let _baits = RealBaitGuard::capture();
    let path = "/etc/northnarrow/kill_switch.conf";
    seed_real_bait(path);
    let fx = Fixture::setup(&[path]);
    external_tamper(&format!("rm -f '{path}'"));
    fx.wait_for(VERDICT_ID);
    fx.wait_for("KillProcessTree");
    fx.wait_for("COMBAT");
}

/// #2 — external DELETE of debug_disable.flag (second /etc bait).
///
/// NOTE: the three /var/lib/northnarrow baits are deliberately NOT
/// tamper-tested here. /var/lib/northnarrow is the agent STATE_DIR and
/// is already inside the Tappa-7 anti-tamper DENY zone (PROTECTED_INODES)
/// — an external process cannot create/modify/delete files there at all
/// (the LSM -EPERMs it before FIM-024 would ever observe a *successful*
/// tamper). Those baits are defence-in-depth (deny + the FIM-024 watch);
/// the externally-tamperable FIM-024 detection lives on the /etc + /run
/// baits, which is what these e2e tests exercise.
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn delete_debug_disable_flag_trips_fim024() {
    let _eni = EniIptablesGuard::install();
    let _baits = RealBaitGuard::capture();
    let path = "/etc/northnarrow/debug_disable.flag";
    seed_real_bait(path);
    let fx = Fixture::setup(&[path]);
    external_tamper(&format!("rm -f '{path}'"));
    fx.wait_for(VERDICT_ID);
}

/// #3 — external DELETE of pause.flag (/run path coverage).
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn delete_pause_flag_trips_fim024() {
    let _eni = EniIptablesGuard::install();
    let _baits = RealBaitGuard::capture();
    let path = "/run/northnarrow/pause.flag";
    seed_real_bait(path);
    let fx = Fixture::setup(&[path]);
    external_tamper(&format!("rm -f '{path}'"));
    fx.wait_for(VERDICT_ID);
}

/// #4 — external DELETE of maintenance.mode (second /etc bait).
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn delete_maintenance_mode_trips_fim024() {
    let _eni = EniIptablesGuard::install();
    let _baits = RealBaitGuard::capture();
    let path = "/etc/northnarrow/maintenance.mode";
    seed_real_bait(path);
    let fx = Fixture::setup(&[path]);
    external_tamper(&format!("rm -f '{path}'"));
    fx.wait_for(VERDICT_ID);
}

/// #5 — the agent's own boot recreate (PROTECTED_PIDS) must NOT fire
/// NN-L-FIM-024. Start with the bait MISSING; the boot integrity sweep
/// recreates it; assert the integrity log fired but the Critical verdict
/// did NOT.
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn agent_boot_recreate_does_not_trip_fim024() {
    let _eni = EniIptablesGuard::install();
    let _baits = RealBaitGuard::capture();
    // A REAL, deny-free honeypot path (/run is tmpfs, not in the
    // anti-tamper deny zone) so an external rm sets up the "missing at
    // boot" case and the agent can recreate it.
    let path = "/run/northnarrow/unload.signal";
    let parent = Path::new(path).parent().unwrap().to_str().unwrap();
    let _ = Command::new(REAL_SUDO)
        .args(["mkdir", "-p", parent])
        .status();
    sudo_rm(path);
    let fx = Fixture::setup(&[path]);
    // Boot integrity recreates the missing bait + logs the Medium event.
    fx.wait_for("NN-L-FIM-024-INTEGRITY");
    // Functional Q5 outcome: the missing bait is restored at boot.
    assert!(
        wait_for_file(path, Duration::from_secs(5)),
        "agent boot integrity must recreate the missing bait"
    );
    // The recreate is a PROTECTED_PIDS agent write — no Critical verdict.
    fx.assert_absent(VERDICT_ID, Duration::from_secs(3));
}

/// #6 — the boot integrity sweep RUNS and the agent's own bait writes
/// don't self-trip FIM-024. We don't pre-seed (the /var/lib baits live
/// in the anti-tamper deny zone and can't be written by the test): the
/// agent's sweep either finds the baits present or recreates the missing
/// ones — either way it logs `Honeypot integrity:` and, being a
/// PROTECTED_PIDS write, fires NO Critical verdict.
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn agent_boot_integrity_sweep_runs_without_self_trip() {
    let _eni = EniIptablesGuard::install();
    let _baits = RealBaitGuard::capture();
    let fx = Fixture::setup(&[]);
    // Matches both "…N/N present" (Info) and "…recreated N…" (Medium).
    fx.wait_for("Honeypot integrity:");
    // The sweep's own writes are PROTECTED_PIDS → no Critical verdict.
    fx.assert_absent(VERDICT_ID, Duration::from_secs(2));
}
