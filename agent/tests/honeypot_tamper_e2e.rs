//! Tappa 9.5.1 D3 — anti-tamper honeypot privileged e2e.
//!
//! Drives the NN-L-FIM-024 bait files END-TO-END on a live kernel: a
//! real agent watches the (real) `HONEYPOT_PATHS`, an EXTERNAL process
//! tampers one, and we assert, on ONE signed detection record, the
//! Critical verdict, the KillProcessTree response carried out and the
//! tamperer as its principal — and that the tamperer and its child died
//! by SIGKILL. Also covers the boot integrity sweep (RFC Q5) and the
//! PROTECTED_PIDS self-write negative.
//!
//! External audit NN-AUD-227: the assertions were three independent
//! substring searches of the agent's log. Nothing tied `KillProcessTree`
//! to the verdict, and `COMBAT` matched the boot line "COMBAT
//! graduated-response ladder armed". Lab PR 162: the posture is asserted
//! again, now that a trigger reads the tamper (`ControlSurfaceTamper`):
//! the record's `posture_at` is COMBAT, and the agent's log holds the
//! locked transition line naming that trigger. The agent's own writes
//! draw neither the record nor the transition.
//!
//! The rule keys on the hard-coded `/etc/northnarrow/...`,
//! `/var/lib/northnarrow/...`, `/run/northnarrow/...` paths (the agent
//! has no flag to move them), so unlike the tempdir-based FIM tests this
//! one rewrites the REAL files. External audit NN-AUD-233: every test
//! starts with [`RealBaitGuard::capture`], which refuses to run
//! - without root;
//! - on a host that is not an nn-lab guest (`/var/lib/nn-lab-provisioned`,
//!   written by the lab's cloud-init) unless `NN_TEST_DISPOSABLE_HOST=1`
//!   says the host can be thrown away;
//! - while any NorthNarrow agent or watchdog runs (stop the units first;
//!   `nn-lab.sh test-ignored` does). An installed, stopped agent is fine:
//!   its baits are put back byte for byte, with mode, owner and mtime,
//!   and checked, when the test ends, pass or fail.
//!
//! The suite does not touch the pin root.
//!
//! The tamper is performed by a DISPOSABLE child, never the test
//! harness — the rule's KillProcessTree targets the modifier PID, which
//! must not be us. (Mirrors the T10.6 D9 external-helper pattern + the
//! post-hotfix path-safe install.) The child is a `python3` that unlinks
//! the bait itself and then waits ([`Tamperer`]): a `sh -c 'rm …'` child
//! was gone before any response could reach it, so a kill could not be
//! told from a kill recorded but never landed.
//!
//! Requires `python3` on the guest (as the net and D7 suites do).
//!
//! Run:
//!   sudo -E env "PATH=$PATH" cargo test --release \
//!     -p northnarrow-agent --test honeypot_tamper_e2e \
//!     --features "test-privileged debug-trigger" \
//!     -- --include-ignored --test-threads=1

#![cfg(feature = "test-privileged")]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use northnarrow_agent::fim::rules::HONEYPOT_PATHS;

mod common;
use common::{install_to_priv_bin, EniIptablesGuard, InstalledBin};

const SOCKET_POLL_TIMEOUT: Duration = Duration::from_secs(15);
const VERDICT_POLL_TIMEOUT: Duration = Duration::from_secs(20);
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const REAL_SUDO: &str = "/usr/bin/sudo";

fn agent_bin() -> &'static str {
    env!("CARGO_BIN_EXE_northnarrow-agent")
}
fn nn_admin_bin() -> &'static str {
    env!("CARGO_BIN_EXE_nn-admin")
}
fn combat_rules_path() -> PathBuf {
    PathBuf::from(env!("NN_REPO_ROOT"))
        .join("configs")
        .join("combat-rules.v4")
}
fn canary_templates_dir() -> PathBuf {
    PathBuf::from(env!("NN_REPO_ROOT"))
        .join("configs")
        .join("canary-templates")
}

// Path-safe install (post-T10.6 hotfix: absolute sudo):
// `common::install_to_priv_bin`.

/// Stops the agent on drop (`common::quit_agent`: evicts the sudo subtree
/// from PROTECTED_PIDS, then SIGQUITs it; the task_kill hook refuses every
/// signal from the test runner while the pid is protected). An agent that
/// survives fails the test.
struct AgentGuard(Option<Child>);
impl Drop for AgentGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            // Unprotect + SIGQUIT the whole sudo subtree, bounded wait
            // (sudo 1.9.9 does not relay our signal, see common::quit_agent).
            common::quit_agent(&mut c);
        }
    }
}

/// The directories of the baits.
const BAIT_DIRS: [&str; 3] = [
    "/etc/northnarrow",
    "/var/lib/northnarrow",
    "/run/northnarrow",
];

/// RAII guard for the REAL bait files and their directories (external
/// audit NN-AUD-233). `capture` refuses to run without root, on a host
/// that is not disposable ([`common::require_disposable_host`]) or while a
/// NorthNarrow agent or watchdog runs, and it refuses a bait that is not a
/// regular file (the agent's boot sweep would replace it, and it could not
/// be put back). It records each bait's content, mode, owner and mtime; on
/// drop every bait that existed is put back and checked (recreated if it
/// was deleted), and what the run created is removed.
///
/// It used to record only which baits existed and remove the others: a
/// pre-existing bait (an installed, stopped agent's) was overwritten by
/// [`seed_real_bait`] and deleted by the tamperer, and never put back. It
/// also removed the pin root first, which on a host whose pins were not
/// protected detached a stopped install's hooks; the suite no longer
/// touches the pin root (a previous fixture's pins are protected anyway,
/// review entry 39, and the next agent purges them at boot as a
/// protected pid).
struct RealBaitGuard {
    baits: Vec<(&'static str, common::PathState)>,
    dirs: Vec<(&'static str, bool)>,
}

impl RealBaitGuard {
    fn capture() -> Self {
        let what = "rewrite the real honeypot baits";
        common::require_root(what);
        common::require_disposable_host(what);
        common::refuse_if_northnarrow_running(what);
        let baits: Vec<(&'static str, common::PathState)> = HONEYPOT_PATHS
            .iter()
            .map(|&p| {
                let state = common::PathState::read(Path::new(p))
                    .unwrap_or_else(|e| panic!("refusing to {what}: cannot read {p}: {e}"));
                (p, state)
            })
            .collect();
        for (p, state) in &baits {
            if let common::PathState::Other(kind) = state {
                panic!(
                    "refusing to {what}: {p} is a {kind}, not a regular file; the agent's \
                     boot sweep would replace it and it could not be restored"
                );
            }
        }
        Self {
            baits,
            dirs: BAIT_DIRS
                .iter()
                .map(|&d| (d, Path::new(d).exists()))
                .collect(),
        }
    }
}

impl Drop for RealBaitGuard {
    fn drop(&mut self) {
        // A running agent would answer the restore writes as a tamper of
        // the baits it watches (FIM-024, the runner killed): restore
        // nothing and say what is left to put back.
        let running = common::northnarrow_daemons();
        if !running.is_empty() {
            let pending: Vec<String> = self
                .baits
                .iter()
                .filter(|(p, s)| common::PathState::read(Path::new(p)).ok().as_ref() != Some(s))
                .map(|(p, s)| format!("{p}: was {}", s.describe()))
                .collect();
            common::fail_teardown(&format!(
                "honeypot baits NOT restored: NorthNarrow processes still run ({running:?}). \
                 To put back by hand: {pending:?}"
            ));
            return;
        }
        let mut failed = Vec::new();
        let mut left = Vec::new();
        for (p, state) in &self.baits {
            if let Err(e) = common::restore_path(Path::new(p), state) {
                if *state == common::PathState::Absent {
                    // A bait the run (or the agent's boot sweep) created:
                    // the test agent's own protection of its state dir can
                    // keep it until its pins are purged. Inert content,
                    // the same an install writes.
                    left.push(e);
                } else {
                    failed.push(format!("{e} (it was {})", state.describe()));
                }
            }
        }
        for (dir, existed) in &self.dirs {
            if !existed && Path::new(dir).exists() {
                if let Err(e) = std::fs::remove_dir(dir) {
                    left.push(format!("{dir}: {e}"));
                }
            }
        }
        if !left.is_empty() {
            eprintln!("honeypot suite: created by the run and left in place: {left:?}");
        }
        if !failed.is_empty() {
            common::fail_teardown(&format!(
                "honeypot baits that existed before the run were NOT restored: {failed:?}"
            ));
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
    /// Per-test detection chain (`--detections-file`): the assertions read
    /// the signed records, not the log (external audit NN-AUD-227).
    detections_log: PathBuf,
    baseline_log: PathBuf,
    drift_log: PathBuf,
    /// A watched file that is not a bait, written by the barrier
    /// ([`Self::assert_absent_after_barrier`]).
    sentinel: PathBuf,
    _agent_guard: AgentGuard,
    _installed_agent: InstalledBin,
    _installed_admin: InstalledBin,
}

impl Fixture {
    /// Spawn an agent watching the given `fim_watch_paths` and the
    /// sentinel. Empty allow/blocklists; COMBAT rules wired;
    /// responses enforced (no `--detect-only`).
    fn setup(fim_watch_paths: &[&str]) -> Self {
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

        let sentinel = dir.join("sentinel.txt");
        std::fs::write(&sentinel, b"sentinel\n").expect("seed the sentinel");
        let fim_paths_v1 = dir.join("fim-paths.v1");
        let body: String = fim_watch_paths
            .iter()
            .map(|p| format!("{p}\n"))
            .chain(std::iter::once(format!("{}\n", sentinel.display())))
            .collect();
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
        let detections_log = dir.join("detections.jsonl");
        let baseline_log = dir.join("fim_baseline.jsonl");
        let drift_log = dir.join("fim_drift.jsonl");

        common::require_bpftool();
        let child = Command::new(REAL_SUDO)
            .arg("env")
            .arg(common::OWN_DEFAULT_LISTS_ASSIGNMENT)
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
            .arg("--detections-file")
            .arg(&detections_log)
            .arg("--status-events-file")
            .arg(dir.join("status_events.jsonl"))
            .arg("--fim-paths-v1")
            .arg(&fim_paths_v1)
            .arg("--fim-paths-local")
            .arg(&fim_paths_local)
            .arg("--fim-baseline-file")
            .arg(&baseline_log)
            .arg("--fim-drift-file")
            .arg(&drift_log)
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
            detections_log,
            baseline_log,
            drift_log,
            sentinel,
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

    /// External audit NN-AUD-228: `rule_id` was asserted absent after a
    /// bare sleep, which a slow pipeline passes as well as a correct one.
    /// Now after a barrier through both pipelines a FIM-024 verdict comes
    /// from: a write to the watched sentinel, waited for in the drift log
    /// (the FIM drain is past the window, its ring is read in order), then
    /// an exec barrier waited for in the detection log (the event loop has
    /// handled what the drain forwarded before it).
    fn assert_absent_after_barrier(&self, rule_id: &str) {
        let sentinel = self.sentinel.to_string_lossy().into_owned();
        // A write before the sentinel's first-boot baseline would be
        // folded into it and leave no row.
        common::wait_jsonl_row(
            &self.baseline_log,
            VERDICT_POLL_TIMEOUT,
            "baseline row of the sentinel",
            |r| r["path"].as_str() == Some(sentinel.as_str()),
        );
        let modified = || {
            common::read_jsonl_strict(&self.drift_log)
                .iter()
                .filter(|r| r["path"].as_str() == Some(sentinel.as_str()) && r["op"] == 1)
                .count()
        };
        let before = modified();
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::fs::write(&self.sentinel, format!("barrier {stamp}\n")).expect("write the sentinel");
        common::wait_until(VERDICT_POLL_TIMEOUT, || (modified() > before).then_some(()))
            .unwrap_or_else(|| {
                panic!(
                    "no Modified drift row for the sentinel within {VERDICT_POLL_TIMEOUT:?}; rows: {:?}",
                    common::read_jsonl_strict(&self.drift_log)
                )
            });
        common::exec_barrier(&self.detections_log, VERDICT_POLL_TIMEOUT);
        let records = common::records_of(&self.detections_log, rule_id);
        assert!(records.is_empty(), "{rule_id} recorded: {records:?}");
        assert!(
            !self.log_contains(rule_id),
            "{rule_id:?} unexpectedly present in agent.log"
        );
    }

    /// External audit NN-AUD-227: the FIM-024 record of `tamperer`'s
    /// tamper of `path`, asserted as one record — Critical, KillProcessTree
    /// carried out (the bare action name, NN-AUD-234), the tamperer as its
    /// principal — and the kill itself: the tamperer and its child died by
    /// SIGKILL while the harness, their parent, runs on. Returns the record.
    fn assert_tamper_contained(&self, tamperer: &mut Tamperer, path: &str) -> serde_json::Value {
        let pid = u64::from(tamperer.child.id());
        let rec = common::wait_jsonl_row(
            &self.detections_log,
            VERDICT_POLL_TIMEOUT,
            "FIM-024 record of the tamperer",
            |r| {
                r["rule_id"].as_str() == Some(VERDICT_ID)
                    && r["principal"]["pid"].as_u64() == Some(pid)
            },
        );
        assert_eq!(rec["severity"], "Critical", "record: {rec}");
        assert_eq!(
            rec["verdict"],
            serde_json::json!({"Rule": "KillProcessTree"}),
            "record: {rec}"
        );
        assert_eq!(rec["file"].as_str(), Some(path), "record: {rec}");
        assert_eq!(rec["response"], "KillProcessTree", "record: {rec}");
        let status =
            common::wait_exit(&mut tamperer.child, VERDICT_POLL_TIMEOUT).unwrap_or_else(|| {
                panic!("the tamperer still runs: the kill did not land; record: {rec}")
            });
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "the tamperer ended otherwise: {status:?}; record: {rec}"
        );
        let descendant = tamperer.descendant;
        let child_gone = common::wait_until(Duration::from_secs(5), || {
            common::pid_gone(descendant).then_some(())
        });
        assert!(
            child_gone.is_some(),
            "the tamperer's child {descendant} survived the tree kill; record: {rec}"
        );
        rec
    }

    /// The agent's log without colour codes (the fixture does not set
    /// `NO_COLOR`; sudo would drop it anyway).
    fn log_text(&self) -> String {
        common::strip_ansi(&std::fs::read_to_string(&self.agent_log).unwrap_or_default())
    }

    /// Lab PR 162: the tamper `rec` records drove the posture to a locked
    /// COMBAT, by one of `triggers`. The record is written after the
    /// posture saw the event, so its `posture_at` is COMBAT; the log holds
    /// the transition line, locked (both triggers are decisive). The line
    /// precedes the rule's verdict line in the log: the posture observes
    /// an event before the rules judge it. An `/etc/northnarrow` bait is
    /// under the FS deny, which refuses the tamper and raises
    /// `AntiTamperDenial` first (the Debian 12 gate); a `/run/northnarrow`
    /// one is not, and only the control-surface trigger can answer it.
    fn assert_combat_by_tamper(&self, rec: &serde_json::Value, triggers: &[&str]) {
        assert_eq!(rec["posture_at"], "Combat", "record: {rec}");
        let line = common::wait_until(VERDICT_POLL_TIMEOUT, || {
            self.log_text()
                .lines()
                .find(|l| {
                    l.contains("POSTURE TRANSITION")
                        && l.contains("state=COMBAT")
                        && triggers.iter().any(|t| l.contains(t))
                })
                .map(str::to_owned)
        })
        .unwrap_or_else(|| {
            let log = self.log_text();
            let posture: Vec<&str> = log.lines().filter(|l| l.contains("POSTURE")).collect();
            panic!(
                "no POSTURE TRANSITION to COMBAT with one of {triggers:?} in agent.log; record: \
                 {rec}; posture lines: {posture:?}"
            )
        });
        assert!(line.contains("locked=true"), "{line}");
    }

    /// Lab PR 162: no transition by the control-surface trigger (checked
    /// after [`Self::assert_absent_after_barrier`]).
    fn assert_no_tamper_trigger(&self) {
        let log = self.log_text();
        let hits: Vec<&str> = log.lines().filter(|l| l.contains(TAMPER_TRIGGER)).collect();
        assert!(
            hits.is_empty(),
            "the agent's own write raised the posture: {hits:?}"
        );
    }
}

/// How the agent logs the trigger that a control-surface tamper raises
/// (`trigger = ?Some(TriggerType::ControlSurfaceTamper)`).
const TAMPER_TRIGGER: &str = "trigger=Some(ControlSurfaceTamper)";
/// The triggers that answer the tamper of an `/etc/northnarrow` bait: the
/// FS deny's `AntiTamperDenial` when it refused the unlink, or the
/// control-surface trigger (see [`Fixture::assert_combat_by_tamper`]).
const ETC_BAIT_TRIGGERS: &[&str] = &[TAMPER_TRIGGER, "trigger=Some(AntiTamperDenial)"];

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

/// The tamperer's program: start a child (the tree the kill must take
/// with it), say its pid, unlink the bait, wait to be killed. The `sleep`
/// ends by itself if nothing kills it.
const TAMPER_PY: &str = "\
import os, signal, subprocess, sys
child = subprocess.Popen(['sleep', '60'])
print(child.pid, flush=True)
try:
    os.unlink(sys.argv[1])
except OSError as e:
    print('unlink refused:', e, file=sys.stderr, flush=True)
signal.pause()
";

/// External audit NN-AUD-227: a DISPOSABLE tamperer that stays alive until
/// killed, so the test sees whether the rule's KillProcessTree landed on it
/// (not on the test harness, its parent). Killed and reaped on drop if the
/// agent did not. A refused unlink (the bait is in a directory the agent
/// protects) does not end it: the attempt is the tamper FIM-024 answers.
struct Tamperer {
    child: Child,
    /// The tamperer's own child.
    descendant: u32,
}

impl Tamperer {
    fn unlink(path: &str) -> Self {
        let mut child = Command::new("python3")
            .arg("-c")
            .arg(TAMPER_PY)
            .arg(path)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn the python3 tamperer");
        let mut line = String::new();
        BufReader::new(child.stdout.take().expect("tamperer stdout"))
            .read_line(&mut line)
            .expect("read the tamperer's child pid");
        let descendant = line
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("the tamperer said {line:?}"));
        Self { child, descendant }
    }
}

impl Drop for Tamperer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

const VERDICT_ID: &str = "NN-L-FIM-024_AntiTamperHoneypotModified";

// NOTE on the tamper op: these tests use DELETE (unlink) as the tamper —
// the canonical "disable NN" action (remove a fake kill-switch / lock)
// AND the FIM op that fires deterministically on this kernel
// (inode_unlink → FIM_OP_DELETED). chmod→Modified (inode_setattr) and
// mv→Renamed (inode_rename) of a watched FILE do NOT reliably emit a
// drift event here — a pre-existing FIM eBPF/kernel-ABI gap the older
// FIM e2e masks by accepting Modified OR Opened; tracked as a T9.5.1
// follow-up. Delete coverage across /etc, /var/lib and /run exercises
// the rule on every bait dir.

/// #1 — external DELETE of kill_switch.conf (/etc) → one Critical
/// record naming the tamperer, KillProcessTree carried out, the tamperer
/// and its child killed, and the posture in a locked COMBAT by the
/// control-surface trigger (lab PR 162). (Was `…_trips_fim024_combat`: its
/// `COMBAT` check matched the boot line, see the module doc.)
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn delete_kill_switch_conf_trips_fim024_and_kills_the_tamperer() {
    let _eni = EniIptablesGuard::install();
    let _baits = RealBaitGuard::capture();
    let path = "/etc/northnarrow/kill_switch.conf";
    seed_real_bait(path);
    let fx = Fixture::setup(&[path]);
    let mut tamperer = Tamperer::unlink(path);
    let rec = fx.assert_tamper_contained(&mut tamperer, path);
    fx.assert_combat_by_tamper(&rec, ETC_BAIT_TRIGGERS);
    fx.wait_for(VERDICT_ID);
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
    let mut tamperer = Tamperer::unlink(path);
    let rec = fx.assert_tamper_contained(&mut tamperer, path);
    fx.assert_combat_by_tamper(&rec, ETC_BAIT_TRIGGERS);
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
    let mut tamperer = Tamperer::unlink(path);
    let rec = fx.assert_tamper_contained(&mut tamperer, path);
    fx.assert_combat_by_tamper(&rec, &[TAMPER_TRIGGER]);
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
    let mut tamperer = Tamperer::unlink(path);
    let rec = fx.assert_tamper_contained(&mut tamperer, path);
    fx.assert_combat_by_tamper(&rec, ETC_BAIT_TRIGGERS);
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
    // The recreate is a PROTECTED_PIDS agent write — no Critical verdict,
    // and no posture trigger.
    fx.assert_absent_after_barrier(VERDICT_ID);
    fx.assert_no_tamper_trigger();
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
    // The sweep's own writes are PROTECTED_PIDS → no Critical verdict,
    // and no posture trigger.
    fx.assert_absent_after_barrier(VERDICT_ID);
    fx.assert_no_tamper_trigger();
}
