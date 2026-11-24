//! Lot 379 (pre-alpha Phase 7, F7-1 and F7-2 / Phase 8b, F8b-1): what the
//! status of a real agent says of what it signed.
//!
//! - **F8b-1 / F7-2**: a mount-guard program refused by the verifier at its
//!   load. The test build's fault injection (`NN_TEST_VERIFIER_REFUSE`,
//!   read only with `test-privileged`: never in a release) refuses
//!   `mount_guard_sb_mount` at its load as the verifier refuses a program
//!   past its budget; the agent starts all the same, the other four hooks
//!   attached, and the refusal is a SIGNED degradation — the audit row
//!   (`integrity_drift` `subsystem_degraded`, source `anti_tamper`,
//!   verified with the agent's key), `nn-admin capabilities` (the signed
//!   manifest's degradations) and `nn-admin status` (`sensors: DEGRADED`).
//!   Never silent.
//! - **F7-1**: the fixture's agent loads its own unsigned overlays (the
//!   escape hatch every fixture uses) and signs each as
//!   `unauthorized_overlay`; `nn-admin status` lists them as held
//!   integrity findings with their row, and `nn-admin integrity
//!   acknowledge --through <row>` — signed, its row in the chain — ends
//!   them; one through a row not signed yet is refused (exit 9).
//!
//! Run (lab guest, units stopped, pins purged — `nn-lab.sh test-ignored`
//! does both):
//!   sudo -E env "PATH=$PATH" cargo test --release \
//!     -p northnarrow-agent --test integrity_status_privileged_e2e \
//!     --features "test-privileged debug-trigger" \
//!     -- --ignored --test-threads=1

#![cfg(feature = "test-privileged")]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

mod common;
use common::agent_state::{AgentState, InstalledAgent, Launch};
use common::{InstalledBin, install_to_priv_bin};

const SOCKET_POLL_TIMEOUT: Duration = Duration::from_secs(30);
/// A degradation is signed within the registry's bound
/// (`boot::degradation::SIGNED_WITHIN`, 60 s) and the manifest revised.
const SIGNED_TIMEOUT: Duration = Duration::from_secs(90);
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// The program the fault injection refuses, and its hook.
const REFUSED_PROGRAM: &str = "mount_guard_sb_mount";
const REFUSED_HOOK: &str = "sb_mount";

fn nn_admin_bin() -> &'static str {
    env!("CARGO_BIN_EXE_nn-admin")
}

fn combat_rules_path() -> PathBuf {
    PathBuf::from(env!("NN_REPO_ROOT"))
        .join("configs")
        .join("combat-rules.v4")
}

/// The agent's production pin root. A test agent pins there; an agent
/// that quit leaves its pins (by design: its hooks outlive it), and the
/// next start of this suite met them. Wiped before each agent starts, as
/// `canary_privileged_e2e` and `fim_privileged_e2e` do.
const BPFFS_PIN_ROOT: &str = "/sys/fs/bpf/northnarrow";

fn wipe_pin_tree() {
    let pin = Path::new(BPFFS_PIN_ROOT);
    if !pin.exists() {
        return;
    }
    if let Ok(entries) = std::fs::read_dir(pin) {
        for entry in entries.flatten() {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    let _ = std::fs::remove_dir(pin);
}

/// SIGQUIT-on-drop (the task_kill hook refuses SIGKILL/SIGTERM).
struct AgentGuard(Option<Child>);
impl Drop for AgentGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            common::quit_agent(&mut c);
        }
    }
}

struct Fixture {
    state: AgentState,
    agent_log: PathBuf,
    nn_admin: PathBuf,
    admin_priv: PathBuf,
    guard: AgentGuard,
    _tempdir: tempfile::TempDir,
    _installed_agent: InstalledAgent,
    _installed_admin: InstalledBin,
}

impl Fixture {
    /// An agent whose files live in a tempdir, its own (unsigned) lists and
    /// overlays loaded through the escape hatch, `env` added; a key with
    /// every role.
    fn setup(env: &[(&str, &str)]) -> Self {
        common::require_root("start a test agent");
        common::require_bpftool();
        common::refuse_if_northnarrow_running("start a test agent");
        wipe_pin_tree();
        let tempdir = tempfile::tempdir().expect("tempdir");
        let dir = tempdir.path().to_path_buf();
        let state = AgentState::new(&dir);
        let installed_agent = InstalledAgent::install();
        let installed_admin = install_to_priv_bin(Path::new(nn_admin_bin()));

        let admin_priv = dir.join("admin.priv");
        let tmp_pub = dir.join("admin.pub.tmp");
        let init = Command::new(&installed_admin.path)
            .args(["init", "--priv-out"])
            .arg(&admin_priv)
            .arg("--pub-append")
            .arg(&tmp_pub)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("spawn nn-admin init");
        assert!(init.success(), "nn-admin init failed");
        let body = std::fs::read_to_string(&tmp_pub).expect("read tmp pubkey");
        let hex = body
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with('#'))
            .expect("init pub file has no hex line");
        let mut f = std::fs::File::create(state.admin_pub()).expect("create admin.pub");
        writeln!(f, "{hex} all").expect("write admin.pub");
        drop(f);
        let _ = std::fs::remove_file(&tmp_pub);

        let combat = dir.join("combat-rules.v4");
        std::fs::copy(combat_rules_path(), &combat).expect("copy combat rules");
        let mut lists = Vec::new();
        for (flag, name) in [
            ("--fim-paths-v1", "fim-paths.v1"),
            ("--fim-paths-local", "fim-paths.local"),
            ("--netflow-blocklist-v1", "netflow-blocklist.v1"),
            ("--netflow-blocklist-local", "netflow-blocklist.local"),
            ("--netflow-ja3-blocklist-v1", "netflow-ja3-blocklist.v1"),
            (
                "--netflow-ja3-blocklist-local",
                "netflow-ja3-blocklist.local",
            ),
            ("--process-comm-allowlist-v1", "process-comm-allowlist.v1"),
            (
                "--process-comm-allowlist-local",
                "process-comm-allowlist.local",
            ),
            ("--netflow-comm-allowlist-v1", "netflow-comm-allowlist.v1"),
            (
                "--netflow-comm-allowlist-local",
                "netflow-comm-allowlist.local",
            ),
        ] {
            let p = dir.join(name);
            std::fs::write(&p, "").unwrap_or_else(|e| panic!("write {name}: {e}"));
            lists.push((flag, p));
        }

        let agent_log = dir.join("agent.log");
        let log = std::fs::File::create(&agent_log).expect("create agent.log");
        let log_err = log.try_clone().expect("clone log handle");
        let mut all_env = vec![common::OWN_DEFAULT_LISTS_ENV];
        all_env.extend_from_slice(env);
        let mut cmd = installed_agent.command(&state, Launch::Sudo, &all_env);
        cmd.arg("--combat-rules").arg(&combat);
        for (flag, p) in &lists {
            cmd.arg(flag).arg(p);
        }
        let child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err))
            .spawn()
            .expect("spawn northnarrow-agent");
        let fx = Self {
            nn_admin: installed_admin.path.clone(),
            state,
            agent_log,
            admin_priv,
            guard: AgentGuard(Some(child)),
            _tempdir: tempdir,
            _installed_agent: installed_agent,
            _installed_admin: installed_admin,
        };
        fx.wait_until(SOCKET_POLL_TIMEOUT, "the admin socket", || {
            fx.state.admin_socket().exists().then_some(())
        });
        fx
    }

    /// The agent's output without the ANSI colour codes.
    fn log_text(&self) -> String {
        let raw = std::fs::read_to_string(&self.agent_log).unwrap_or_default();
        let mut out = String::with_capacity(raw.len());
        let mut chars = raw.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' && chars.peek() == Some(&'[') {
                for d in chars.by_ref() {
                    if d.is_ascii_alphabetic() {
                        break;
                    }
                }
                continue;
            }
            out.push(c);
        }
        out
    }

    fn log_tail(&self) -> String {
        let text = self.log_text();
        let lines: Vec<&str> = text.lines().collect();
        lines[lines.len().saturating_sub(30)..].join("\n")
    }

    /// `f`'s first `Some` within `timeout`; panics (with the agent's log)
    /// otherwise, or when the agent exited.
    fn wait_until<T>(&self, timeout: Duration, what: &str, mut f: impl FnMut() -> Option<T>) -> T {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(v) = f() {
                return v;
            }
            self.assert_running(what);
            assert!(
                Instant::now() < deadline,
                "{what}: not within {timeout:?}\n{}",
                self.log_tail()
            );
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    /// The agent is still running (a refused or crashed start is a failure).
    fn assert_running(&self, what: &str) {
        let pid = self.guard.0.as_ref().map(Child::id).expect("the agent");
        assert!(
            Path::new(&format!("/proc/{pid}")).exists(),
            "{what}: the agent's process {pid} is gone\n{}",
            self.log_tail()
        );
    }

    /// `nn-admin <args> --key <every role> <the agent's id and socket>`.
    fn admin(&self, args: &[&str]) -> std::process::Output {
        Command::new(&self.nn_admin)
            .args(args)
            .arg("--key")
            .arg(&self.admin_priv)
            .args(self.state.client_args())
            .stdin(Stdio::null())
            .output()
            .unwrap_or_else(|e| panic!("spawn nn-admin {args:?}: {e}"))
    }

    fn admin_stdout(&self, args: &[&str]) -> String {
        let out = self.admin(args);
        assert!(
            out.status.success(),
            "nn-admin {args:?}: {:?}\n{}{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// The audit chain verified with the agent's key (`nn-admin audit
    /// verify`, the operator's check).
    fn assert_chain_verifies(&self) {
        let verify = Command::new(&self.nn_admin)
            .args(["audit", "verify", "--from"])
            .arg(self.state.audit_log())
            .arg("--agent-sig-key")
            .arg(self.state.signing_key())
            .stdin(Stdio::null())
            .output()
            .expect("nn-admin audit verify");
        assert!(
            verify.status.success(),
            "nn-admin audit verify: {:?}\n{}{}",
            verify.status.code(),
            String::from_utf8_lossy(&verify.stdout),
            String::from_utf8_lossy(&verify.stderr)
        );
    }
}

/// The `integrity:` lines of a status, with the newest audit row each
/// names (the review of #586: an overlay the start refused names the
/// round's row of the same file too; lot 384: read by the rule that
/// writes it, the line counting the findings past the cap included).
fn held_lines(status: &str) -> Vec<(String, u64)> {
    status
        .lines()
        .filter_map(|l| l.trim_start().strip_prefix("- integrity: "))
        .map(|l| {
            let row = nn_evidence::held::rows_named(l)
                .max()
                .unwrap_or_else(|| panic!("no audit row in {l:?}"));
            (l.to_string(), row)
        })
        .collect()
}

/// F8b-1 / F7-2: a mount-guard program the verifier refuses at its load is
/// a signed degradation — in the audit chain, the capability manifest and
/// the status — and the agent runs with the guard's other hooks. Before
/// lot 379 this was argued from the code only (`attach`'s error path) and
/// the Phase 7 lab could not inject it (the BTF provenance check stopped
/// the start first).
#[test]
#[ignore = "root, bpftool and the BPF LSM: nn-lab.sh test-ignored"]
fn a_verifier_refusal_of_the_mount_guard_is_a_signed_degradation() {
    let fx = Fixture::setup(&[("NN_TEST_VERIFIER_REFUSE", REFUSED_PROGRAM)]);
    let want = format!(
        "mount guard: 4 of 5 hooks attached ({REFUSED_HOOK}: verifier rejected LSM program \
         `{REFUSED_PROGRAM}`"
    );
    // the start went on: the injection was honoured, the rest attached
    fx.wait_until(SOCKET_POLL_TIMEOUT, "the injected refusal", || {
        let log = fx.log_text();
        (log.contains("TEST FAULT INJECTION") && log.contains("hook NOT attached")).then_some(())
    });
    // the signed row: `subsystem_degraded`, source `anti_tamper`
    let row = fx.wait_until(SIGNED_TIMEOUT, "the signed degradation", || {
        common::read_jsonl_strict(&fx.state.audit_log())
            .into_iter()
            .find(|r| {
                r["op"] == "integrity_drift"
                    && r["extra"]["kind"] == "subsystem_degraded"
                    && r["extra"]["source"] == "anti_tamper"
                    && r["extra"]["detail"]
                        .as_str()
                        .is_some_and(|d| d.contains(&want))
            })
    });
    assert_eq!(row["result"], "detected", "{row}");
    assert_eq!(row["key_fp"], "agent-self", "{row}");
    let detail = row["extra"]["detail"].as_str().unwrap();
    assert!(
        detail.contains("injected by NN_TEST_VERIFIER_REFUSE"),
        "the row says the refusal was injected: {detail}"
    );
    fx.assert_chain_verifies();
    // the signed capability manifest lists it
    let line = format!("anti_tamper: {want}");
    let caps = fx.wait_until(SIGNED_TIMEOUT, "the manifest's degradation", || {
        let out = fx.admin(&["capabilities", "--json"]);
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        (out.status.success() && text.contains(&line)).then_some(text)
    });
    let manifest: serde_json::Value =
        serde_json::from_str(caps.trim()).expect("capabilities --json");
    assert!(
        manifest["manifest"]["degradations"]
            .as_array()
            .is_some_and(|d| d
                .iter()
                .any(|l| l.as_str().is_some_and(|l| l.contains(&line)))),
        "{manifest:#}"
    );
    // and the status
    let status = fx.admin_stdout(&["status"]);
    assert!(status.contains("sensors           : DEGRADED"), "{status}");
    assert!(status.contains(&line), "{status}");
    fx.assert_running("after the checks");
}

/// F7-1: the unauthorized overlays the agent signed are held integrity
/// findings of its status, with their audit row; a signed acknowledgement
/// through that row ends them (its own row in the chain), one through a
/// row not signed yet is refused. On main the status said `degradations`
/// without them.
#[test]
#[ignore = "root, bpftool and the BPF LSM: nn-lab.sh test-ignored"]
fn an_unauthorized_overlay_is_held_in_the_status_until_acknowledged() {
    let fx = Fixture::setup(&[]);
    let held = fx.wait_until(SIGNED_TIMEOUT, "the held overlay findings", || {
        let out = fx.admin(&["status"]);
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let held = held_lines(&text);
        held.iter()
            .any(|(l, _)| l.starts_with("unauthorized_overlay"))
            .then_some((text, held))
    });
    let (status, lines) = held;
    assert!(status.contains("sensors           : DEGRADED"), "{status}");
    assert!(
        lines
            .iter()
            .any(|(l, _)| l.contains("process-comm-allowlist") && l.contains("held while found")),
        "{lines:#?}"
    );
    let through = lines.iter().map(|(_, r)| *r).max().unwrap();
    assert!(
        status.contains(&format!(
            "nn-admin integrity acknowledge --through {through} "
        )),
        "{status}"
    );
    // a row not signed yet: refused, nothing ended
    let future = fx.admin(&["integrity", "acknowledge", "--through", "999999999"]);
    assert_eq!(future.status.code(), Some(9), "{future:?}");
    // the acknowledgement through the newest held row
    let through_s = through.to_string();
    let out = fx.admin_stdout(&[
        "integrity",
        "acknowledge",
        "--through",
        &through_s,
        "--note",
        "lot 379 e2e: the fixture's own overlays",
    ]);
    assert!(out.contains("acknowledged through audit row"), "{out}");
    let row = common::read_jsonl_strict(&fx.state.audit_log())
        .into_iter()
        .rev()
        .find(|r| r["op"] == "integrity_acknowledged" && r["result"] == "success")
        .expect("the acknowledgement's row");
    assert_eq!(row["extra"]["through_row"], through, "{row}");
    assert_ne!(row["key_fp"], "", "{row}");
    fx.assert_chain_verifies();
    // what it covered is gone; anything still held was signed after it
    let after = fx.admin_stdout(&["status"]);
    for (line, r) in held_lines(&after) {
        assert!(r > through, "still held through {through}: {line}");
        assert!(!line.starts_with("unauthorized_overlay"), "{line}");
    }
}
