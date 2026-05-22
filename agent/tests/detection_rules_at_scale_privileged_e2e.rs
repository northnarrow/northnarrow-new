//! Tappa 10.5 (D7) — privileged end-to-end smoke tests for the
//! Detection-Rules-at-Scale rule families (D2 process / D3 FIM /
//! D4 net / D5 chain).
//!
//! Spawns the real `northnarrow-agent` against a per-test tempdir,
//! drives a kernel-side trigger for one representative rule per
//! family, and asserts the rule FIRED end-to-end. Two observation
//! mechanisms (per the D7 design ruling):
//!
//! - **Verdict log capture** (all families): the agent's stderr is
//!   redirected to `agent.log`; a fired rule emits a
//!   `warn!(rule = %verdict.rule_id, … "VERDICT (rule)")` line
//!   (`agent/src/main.rs`). [`Fixture::wait_for_verdict`] polls the
//!   log for the rule's (unique) id. This is the only end-to-end
//!   signal for process + chain rules, which have no on-disk event
//!   chain.
//! - **On-disk event row** (FIM + net, where a chain exists): the
//!   `fim_drift.jsonl` / `netflow.jsonl` / `netflow_listeners.jsonl`
//!   row is asserted too, pinning the kernel→drain→persist wire.
//!
//! ## Critical rules + COMBAT
//!
//! FIM-021 (PAM module) and NN-L-CHAIN-002 (/tmp exec → egress) are
//! Critical → the posture FSM enters COMBAT → the NetworkIsolator
//! installs the production `NORTHNARROW_COMBAT` iptables chain. Each
//! such test instantiates [`EniIptablesGuard`] (RAII cleanup so the
//! chain never persists past the test + the management interface is
//! preserved during the COMBAT window — loopback is RETURN-exempt so
//! the admin socket + test traffic survive). FIM-022's exact-path
//! `/etc/ld.so.preload` predicate can't use a temp analog without
//! modifying a live system file, so FIM-021 (temp `/security/*.so`)
//! is the Critical-FIM representative per the D7 ruling.
//!
//! ## Why a cc-compiled chain helper
//!
//! NN-L-CHAIN-002's `/tmp` exec precursor is also R001's trigger
//! (KillProcess). The chain rule only fires once a same-PID egress
//! flow is observed, so the helper must complete its connect BEFORE
//! the agent's kill roundtrip lands. A tiny C helper that connects
//! as its first syscalls wins that race deterministically (a python
//! helper's ~100 ms startup can lose it). The workspace already
//! requires a C toolchain to link, so `cc` is present.
//!
//! Requirements (operator-runnable per
//! `docs/integration-test-runbook.md`): root + bpf LSM + bpffs;
//! workspace built `--release --features test-privileged`; `cc` on
//! PATH; `cat` + `python3` present.
//!
//! Run:
//!   sudo -E env "PATH=$PATH" cargo test --release \
//!     -p northnarrow-agent --test detection_rules_at_scale_privileged_e2e \
//!     --features "test-privileged debug-trigger" \
//!     -- --include-ignored --test-threads=1

#![cfg(feature = "test-privileged")]

use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

mod common;
use common::EniIptablesGuard;

const SOCKET_POLL_TIMEOUT: Duration = Duration::from_secs(15);
const JSONL_POLL_TIMEOUT: Duration = Duration::from_secs(30);
const VERDICT_POLL_TIMEOUT: Duration = Duration::from_secs(20);
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Loopback port the NET-010 / CHAIN-002 helpers connect to. 4444 is
/// in NN-L-NET-010's high-risk-C2 set (Metasploit default).
const C2_PORT: u16 = 4444;
/// Uncommon listener port for NN-L-NET-019 (outside the §7 common
/// set {22,53,80,443,8080,8443}); high ephemeral to dodge collisions.
const WILDCARD_LISTEN_PORT: u16 = 42019;

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

// ── RAII fixtures (same shape as net_privileged_e2e) ────────────────

const PRIV_BIN_DIR: &str = "/usr/local/bin";

/// Off-PATH scratch dir for comm-named helpers (see
/// `install_named_to_priv_bin`). Deliberately NOT on `$PATH`: an
/// exact-name install (e.g. comm=="sudo") left behind by an
/// interrupted run must never shadow a real system binary. Still
/// outside `/tmp`, so R001..R010 location rules don't match.
const PRIV_NAMED_DIR: &str = "/usr/local/lib/nn-e2etest";

/// Absolute path to the real sudo. Cleanup and install must never go
/// through a bare `sudo` PATH lookup — a leaked comm-named helper could
/// otherwise shadow it and silently no-op the very cleanup meant to
/// remove it (observed: an interrupted run left a `sudo`-named helper
/// in `/usr/local/bin`, bricking `sudo` VM-wide).
const REAL_SUDO: &str = "/usr/bin/sudo";

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

/// Install `src` to a UNIQUE name under `/usr/local/bin` (R009-safe;
/// not /tmp so R001..R010 don't match the agent/admin binaries).
fn install_to_priv_bin(src: &Path) -> InstalledBin {
    let basename = src
        .file_name()
        .and_then(|s| s.to_str())
        .expect("binary path has a UTF-8 basename");
    let ts_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let dst = PathBuf::from(format!("{PRIV_BIN_DIR}/{basename}-e2etest-{ts_ns}-{pid}"));
    install_file(src, &dst);
    InstalledBin { path: dst }
}

/// Install `src` to `<PRIV_NAMED_DIR>/<exact_name>` so the kernel
/// `comm` (basename, TASK_COMM_LEN-truncated) is exactly `exact_name`
/// — needed for the comm-matching rules (R011 wants comm="insmod",
/// R017 wants comm="bash", CHAIN-008 wants comm="sudo"). The directory
/// is off `$PATH` and outside `/tmp`: the comm is the basename only, so
/// no rule keys on the location, while keeping the file off `$PATH`
/// guarantees an interrupted run can't leave a binary that shadows a
/// system command of the same name (e.g. `sudo`).
fn install_named_to_priv_bin(src: &Path, exact_name: &str) -> InstalledBin {
    let dst = PathBuf::from(format!("{PRIV_NAMED_DIR}/{exact_name}"));
    install_file(src, &dst);
    InstalledBin { path: dst }
}

fn install_file(src: &Path, dst: &Path) {
    // `-D` creates any missing leading directories (PRIV_NAMED_DIR).
    let status = Command::new(REAL_SUDO)
        .args(["install", "-D", "-m", "755", "-o", "root", "-g", "root"])
        .arg(src)
        .arg(dst)
        .status()
        .expect("spawn sudo install");
    assert!(
        status.success(),
        "sudo install of {} to {} failed",
        src.display(),
        dst.display()
    );
}

/// SIGQUIT-on-drop guard (Tappa 7 LSM blocks SIGKILL + SIGTERM).
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

/// Per-test agent fixture. Spawns the agent with a tempdir layout,
/// EMPTY comm-allowlists (so the comm-gated rules fire on the test's
/// helper comms) and the caller-supplied FIM watch paths, and
/// redirects the agent's stderr to `agent.log` for verdict capture.
struct Fixture {
    _tempdir: tempfile::TempDir,
    agent_log: PathBuf,
    netflow_log: PathBuf,
    netflow_listeners_log: PathBuf,
    drift_log: PathBuf,
    // Signed-op handles for runtime canary deploys (CHAIN-006).
    nn_admin_path: PathBuf,
    admin_priv: PathBuf,
    agent_id: PathBuf,
    admin_socket: PathBuf,
    _agent_guard: AgentGuard,
    _installed_agent: InstalledBin,
    _installed_admin: InstalledBin,
}

impl Fixture {
    /// `fim_watch_paths` are written verbatim into `fim-paths.v1`
    /// (one per line). They must already exist on disk before this
    /// is called — the agent stat()s each path once at boot and
    /// silently skips any that are absent.
    fn setup(fim_watch_paths: &[&Path]) -> Self {
        wipe_pin_tree();
        let tempdir = tempfile::tempdir().expect("tempdir");
        let dir = tempdir.path().to_path_buf();

        let installed_agent = install_to_priv_bin(Path::new(agent_bin()));
        let installed_admin = install_to_priv_bin(Path::new(nn_admin_bin()));

        // Per-test admin keypair (same shape as the net/canary fixtures).
        let admin_pub = dir.join("admin.pub");
        let admin_priv = dir.join("admin.priv");
        let tmp_pub = dir.join("admin.pub.tmp");
        let init_status = Command::new(&installed_admin.path)
            .args(["init", "--priv-out"])
            .arg(&admin_priv)
            .arg("--pub-append")
            .arg(&tmp_pub)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
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
        writeln!(pub_file, "{hex} all").expect("write admin.pub line");
        drop(pub_file);
        let _ = std::fs::remove_file(&tmp_pub);

        let combat = dir.join("combat-rules.v4");
        std::fs::copy(combat_rules_path(), &combat).expect("copy combat rules");

        // FIM paths: caller-supplied watch set.
        let fim_paths_v1 = dir.join("fim-paths.v1");
        let body: String = fim_watch_paths
            .iter()
            .map(|p| format!("{}\n", p.display()))
            .collect();
        std::fs::write(&fim_paths_v1, body).expect("write fim-paths.v1");
        let fim_paths_local = dir.join("fim-paths.local");
        std::fs::write(&fim_paths_local, "").expect("write fim-paths.local");

        // Canary template dir — required by the agent flag even
        // though no canary is deployed here.
        let templates_dir = dir.join("canary-templates");
        std::fs::create_dir(&templates_dir).expect("mkdir canary-templates");
        for entry in std::fs::read_dir(canary_templates_dir()).expect("read templates") {
            let path = entry.expect("template dirent").path();
            if path.extension().and_then(|e| e.to_str()) == Some("tmpl") {
                let base = path.file_name().expect("template basename");
                std::fs::copy(&path, templates_dir.join(base)).expect("copy template");
            }
        }

        // Empty blocklists (so NN-L-NET-001/003 never match) + EMPTY
        // comm-allowlists (so the comm-gated process + net rules fire
        // on the test helper comms — nothing is exempt).
        let write_empty = |name: &str| {
            let p = dir.join(name);
            std::fs::write(&p, "").unwrap_or_else(|_| panic!("write {name}"));
            p
        };
        let netflow_blocklist_v1 = write_empty("netflow-blocklist.v1");
        let netflow_blocklist_local = write_empty("netflow-blocklist.local");
        let netflow_ja3_blocklist_v1 = write_empty("netflow-ja3-blocklist.v1");
        let netflow_ja3_blocklist_local = write_empty("netflow-ja3-blocklist.local");
        let process_comm_allowlist_v1 = write_empty("process-comm-allowlist.v1");
        let process_comm_allowlist_local = write_empty("process-comm-allowlist.local");
        let netflow_comm_allowlist_v1 = write_empty("netflow-comm-allowlist.v1");
        let netflow_comm_allowlist_local = write_empty("netflow-comm-allowlist.local");

        let audit_log = dir.join("audit.log");
        let signing_key = dir.join("agent.sig.key");
        let agent_id = dir.join("agent_id");
        let admin_socket = dir.join("admin.sock");
        let marker = dir.join("agent.shutdown_authorised");
        let baseline_log = dir.join("fim_baseline.jsonl");
        let drift_log = dir.join("fim_drift.jsonl");
        let canary_registry = dir.join("canaries.jsonl");
        let canary_access = dir.join("canary_access.jsonl");
        let netflow_log = dir.join("netflow.jsonl");
        let netflow_listeners_log = dir.join("netflow_listeners.jsonl");
        let agent_log = dir.join("agent.log");

        // Redirect the agent's stderr (tracing default sink) to a
        // file so the test can grep for VERDICT lines.
        // The agent's `tracing_subscriber::fmt()` writes to STDOUT;
        // capture both stdout (where VERDICT lines land) and stderr
        // into the same log file.
        let log_file = std::fs::File::create(&agent_log).expect("create agent.log");
        let log_file_err = log_file.try_clone().expect("clone agent.log handle");

        let child = Command::new("sudo")
            .arg(&installed_agent.path)
            .arg("--combat-rules")
            .arg(&combat)
            .arg("--admin-pub")
            .arg(&admin_pub)
            .arg("--admin-socket")
            .arg(&admin_socket)
            .arg("--agent-id-file")
            .arg(&agent_id)
            .arg("--audit-log-file")
            .arg(&audit_log)
            .arg("--signing-key-file")
            .arg(&signing_key)
            .arg("--shutdown-marker-file")
            .arg(&marker)
            .arg("--fim-paths-v1")
            .arg(&fim_paths_v1)
            .arg("--fim-paths-local")
            .arg(&fim_paths_local)
            .arg("--fim-baseline-file")
            .arg(&baseline_log)
            .arg("--fim-drift-file")
            .arg(&drift_log)
            .arg("--canary-registry-file")
            .arg(&canary_registry)
            .arg("--canary-access-file")
            .arg(&canary_access)
            .arg("--canary-template-dir")
            .arg(&templates_dir)
            .arg("--netflow-file")
            .arg(&netflow_log)
            .arg("--netflow-listeners-file")
            .arg(&netflow_listeners_log)
            .arg("--netflow-blocklist-v1")
            .arg(&netflow_blocklist_v1)
            .arg("--netflow-blocklist-local")
            .arg(&netflow_blocklist_local)
            .arg("--netflow-ja3-blocklist-v1")
            .arg(&netflow_ja3_blocklist_v1)
            .arg("--netflow-ja3-blocklist-local")
            .arg(&netflow_ja3_blocklist_local)
            .arg("--process-comm-allowlist-v1")
            .arg(&process_comm_allowlist_v1)
            .arg("--process-comm-allowlist-local")
            .arg(&process_comm_allowlist_local)
            .arg("--netflow-comm-allowlist-v1")
            .arg(&netflow_comm_allowlist_v1)
            .arg("--netflow-comm-allowlist-local")
            .arg(&netflow_comm_allowlist_local)
            .arg("--no-ade")
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(log_file_err))
            .spawn()
            .expect("spawn northnarrow-agent for D7 e2e");
        let guard = AgentGuard(Some(child));

        wait_for_socket(&admin_socket);

        Self {
            _tempdir: tempdir,
            agent_log,
            netflow_log,
            netflow_listeners_log,
            drift_log,
            nn_admin_path: installed_admin.path.clone(),
            admin_priv,
            agent_id,
            admin_socket,
            _agent_guard: guard,
            _installed_agent: installed_agent,
            _installed_admin: installed_admin,
        }
    }

    /// Deploy a file-canary on `decoy_path` against the running agent
    /// via a signed `nn-admin canary deploy file` op, so subsequent
    /// opens of that inode emit `Event::CanaryTripped` (the CHAIN-006
    /// precursor). `decoy_path` must already exist on disk.
    fn deploy_file_canary(&self, name: &str, decoy_path: &Path) {
        let out = Command::new(&self.nn_admin_path)
            .arg("canary")
            .arg("deploy")
            .arg("--name")
            .arg(name)
            .arg("--key")
            .arg(&self.admin_priv)
            .arg("--agent-id-file")
            .arg(&self.agent_id)
            .arg("--socket")
            .arg(&self.admin_socket)
            .arg("file")
            .arg("--path")
            .arg(decoy_path)
            .stderr(Stdio::inherit())
            .output()
            .expect("spawn nn-admin canary deploy file");
        assert!(
            out.status.success(),
            "nn-admin canary deploy file: exit {:?}, stdout {:?}",
            out.status,
            String::from_utf8_lossy(&out.stdout)
        );
    }

    /// Poll `agent.log` until a `VERDICT (rule)` line for `rule_id`
    /// appears (the rule id is unique + only logged on a fire), or
    /// panic after [`VERDICT_POLL_TIMEOUT`].
    fn wait_for_verdict(&self, rule_id: &str) {
        let deadline = Instant::now() + VERDICT_POLL_TIMEOUT;
        while Instant::now() < deadline {
            if self.log_contains(rule_id) {
                return;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        let tail = std::fs::read_to_string(&self.agent_log).unwrap_or_default();
        panic!(
            "agent never logged a VERDICT for {rule_id} within {VERDICT_POLL_TIMEOUT:?}\n\
             --- agent.log tail ---\n{}",
            tail.lines().rev().take(40).collect::<Vec<_>>().join("\n")
        );
    }

    /// Assert `rule_id` is NOT logged within `window` (bounded
    /// negative — proves a missing precursor/trigger doesn't fire).
    fn assert_no_verdict(&self, rule_id: &str, window: Duration) {
        std::thread::sleep(window);
        assert!(
            !self.log_contains(rule_id),
            "{rule_id} unexpectedly fired (no precursor/trigger present)"
        );
    }

    fn log_contains(&self, needle: &str) -> bool {
        std::fs::read_to_string(&self.agent_log)
            .map(|s| s.contains(needle))
            .unwrap_or(false)
    }

    fn wait_netflow_matching<F>(&self, n: usize, predicate: F) -> Vec<serde_json::Value>
    where
        F: Fn(&serde_json::Value) -> bool,
    {
        wait_jsonl_matching(&self.netflow_log, n, predicate)
    }
    fn wait_listeners_matching<F>(&self, n: usize, predicate: F) -> Vec<serde_json::Value>
    where
        F: Fn(&serde_json::Value) -> bool,
    {
        wait_jsonl_matching(&self.netflow_listeners_log, n, predicate)
    }
    fn wait_drift_matching<F>(&self, n: usize, predicate: F) -> Vec<serde_json::Value>
    where
        F: Fn(&serde_json::Value) -> bool,
    {
        wait_jsonl_matching(&self.drift_log, n, predicate)
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

fn read_jsonl(path: &Path) -> Vec<serde_json::Value> {
    match std::fs::read_to_string(path) {
        Ok(s) => s
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect(),
        Err(_) => Vec::new(),
    }
}

fn wait_jsonl_matching<F>(path: &Path, n: usize, predicate: F) -> Vec<serde_json::Value>
where
    F: Fn(&serde_json::Value) -> bool,
{
    let deadline = Instant::now() + JSONL_POLL_TIMEOUT;
    while Instant::now() < deadline {
        let matched: Vec<_> = read_jsonl(path)
            .into_iter()
            .filter(|r| predicate(r))
            .collect();
        if matched.len() >= n {
            return matched;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    panic!(
        "log {} never held {n} matching rows; all rows: {:?}",
        path.display(),
        read_jsonl(path)
    );
}

/// Settle delay (µs) baked into the cross-PID connect child before it
/// egresses. The child's `ProcessSpawn` (which records the lineage edge
/// the cross-PID rules walk) and the egress `NetFlow` arrive via two
/// *separate* BPF ringbufs drained by independent tasks; under load the
/// net drain can overtake the process drain, so a bare connect can be
/// evaluated before the child→parent edge exists → the cross-PID rule
/// misses. Sleeping here lets the spawn event (and `observe_spawn`) land
/// first. 1 s is comfortably inside the rules' 300 s correlation window.
const CHILD_SETTLE_US: u32 = 1_000_000;

/// Compile a tiny C helper that connects to `127.0.0.1:<port>` then
/// exits, at `<dir>/<name>`. `connect_delay_us` is `usleep`'d before the
/// connect: pass `0` for the same-PID NN-L-CHAIN-002 helper (the connect
/// must beat the R001 kill, so no startup delay); pass [`CHILD_SETTLE_US`]
/// for a cross-PID connect child (see that const). Returns the binary path.
fn compile_connect_helper(dir: &Path, name: &str, port: u16, connect_delay_us: u32) -> PathBuf {
    let src = dir.join(format!("{name}.c"));
    let bin = dir.join(name);
    std::fs::write(
        &src,
        format!(
            r#"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
int main(void) {{
    usleep({connect_delay_us}); /* settle (0 = none): let our spawn drain first */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 1;
    struct sockaddr_in a;
    a.sin_family = AF_INET;
    a.sin_port = htons({port});
    a.sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */
    connect(fd, (struct sockaddr *)&a, sizeof(a));
    close(fd);
    return 0;
}}
"#
        ),
    )
    .expect("write chain helper source");
    let status = Command::new("cc")
        .arg("-O0")
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .expect("spawn cc to build chain helper");
    assert!(status.success(), "cc failed to build the chain helper");
    bin
}

/// Compile the connect child in `compile_dir` (a `/tmp` scratch dir is
/// fine — only *executing* from `/tmp` matters) and install it to a
/// root-owned, non-`/tmp` path via `install_to_priv_bin`.
///
/// This is load-bearing for the cross-PID chains (CHAIN-004/005/006/008):
/// the descendant egress must fall through to the *cross-PID* rule. If
/// the child ran from `/tmp` (as a bare `tempfile::tempdir()` child
/// does — that dir lives under `/tmp`), the child's own exec would trip
/// the **same-PID** TmpExec rule (CHAIN-002) and R009; the engine is
/// first-match-wins (see `decision::engine`), so the same-PID verdict
/// would short-circuit the cross-PID rule and the chain under test would
/// never fire. Running the child from `/usr/local/bin` keeps its exec
/// off both the `/tmp` (TmpExec) and user-writable (R009) predicates.
fn install_connect_child(compile_dir: &Path) -> InstalledBin {
    install_to_priv_bin(&compile_connect_helper(
        compile_dir,
        "nnx_connect",
        C2_PORT,
        CHILD_SETTLE_US,
    ))
}

/// Bind a loopback receiver on `port` and accept ONE connection in a
/// background thread, bounded by `timeout`. Returns the join handle.
///
/// The bound matters: a descendant that never egresses (e.g. killed by
/// the precursor's response before it connects) must make the test fail
/// *cleanly* via the verdict timeout — not hang `join()` forever on a
/// blocking `accept()`. The listener is released when the thread returns
/// (on a connection or at the deadline), so the next sequential test can
/// rebind the port.
fn spawn_oneshot_acceptor(port: u16, timeout: Duration) -> std::thread::JoinHandle<()> {
    let listener = TcpListener::bind(("127.0.0.1", port)).expect("bind receiver");
    listener
        .set_nonblocking(true)
        .expect("set listener non-blocking");
    std::thread::spawn(move || {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((s, _)) => {
                    drop(s);
                    return;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(POLL_INTERVAL);
                }
                Err(_) => return,
            }
        }
    })
}

/// Acceptor bound for the cross-PID chain tests: longer than
/// [`VERDICT_POLL_TIMEOUT`] so a connection that does arrive is always
/// caught, but finite so a non-egressing descendant can't hang the run.
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(25);

/// Compile + install the CHAIN-006 **daemonizing** connect child. The
/// canary-ancestor execs this as a direct child (recording the edge
/// child→ancestor while the ancestor is alive); it then double-forks so
/// its egress survives the canary trip's `KillProcessTree` (which would
/// otherwise kill the whole ancestor tree, the egressing process
/// included — unlike CHAIN-004/005/008 whose precursors kill only the
/// parent PID):
///
///   phase 1 (the exec'd child / intermediate): fork a grandchild that
///     re-execs THIS binary as `go` — recording the edge
///     grandchild→intermediate while we are still alive — then linger
///     briefly so that exec is observed, then `_exit(0)` so the
///     grandchild reparents to init and leaves the ancestor's live
///     process tree. The `AncestryTree` edges
///     (grandchild→intermediate→ancestor) are keyed by `ProcKey` and
///     survive the reparenting.
///   phase 2 (`go`, the grandchild): settle so the ancestor's
///     `CanaryTrip` is recorded first (precursor-before-egress) and our
///     own spawn drains (lineage edge), then egress.
fn compile_daemon_connect_helper(dir: &Path, name: &str, port: u16) -> PathBuf {
    let src = dir.join(format!("{name}.c"));
    let bin = dir.join(name);
    std::fs::write(
        &src,
        format!(
            r#"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
int main(int argc, char **argv) {{
    if (argc < 2) {{
        pid_t g = fork();
        if (g == 0) {{ execl(argv[0], argv[0], "go", (char *)0); _exit(127); }}
        usleep(250000); /* let the grandchild's exec be observed (edge g->us) */
        _exit(0);        /* exit → grandchild reparents to init, escapes the tree */
    }}
    usleep({settle}); /* settle: ancestor CanaryTrip recorded first; spawn drained */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 1;
    struct sockaddr_in a;
    a.sin_family = AF_INET;
    a.sin_port = htons({port});
    a.sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */
    connect(fd, (struct sockaddr *)&a, sizeof(a));
    close(fd);
    return 0;
}}
"#,
            settle = CHILD_SETTLE_US + 500_000,
        ),
    )
    .expect("write daemon connect helper source");
    let status = Command::new("cc")
        .arg("-O0")
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .expect("spawn cc to build daemon connect helper");
    assert!(
        status.success(),
        "cc failed to build the daemon connect helper"
    );
    bin
}

fn install_daemon_connect_child(compile_dir: &Path) -> InstalledBin {
    install_to_priv_bin(&compile_daemon_connect_helper(
        compile_dir,
        "nnx_daemon",
        C2_PORT,
    ))
}

/// Compile the CHAIN-006 canary **ancestor**: `argv[1]` = the
/// daemonizing connect binary, `argv[2]` = the canary decoy path.
///
/// Spawn the descendant FIRST and give it time to daemonize (reparent to
/// init, leaving our tree) BEFORE tripping the canary — the canary's
/// `KillProcessTree` targets our live descendants, so the egressing
/// grandchild must have escaped first. Then open the decoy: the
/// `CanaryTrip` precursor is recorded on us (the ancestor), and the
/// already-escaped grandchild survives to egress and back-correlate.
fn compile_canary_ancestor_helper(dir: &Path, name: &str) -> PathBuf {
    let src = dir.join(format!("{name}.c"));
    let bin = dir.join(name);
    std::fs::write(
        &src,
        r#"
#include <unistd.h>
#include <fcntl.h>
int main(int argc, char **argv) {
    pid_t p = fork();
    if (p == 0) { execl(argv[1], argv[1], (char *)0); _exit(127); }
    usleep(800000); /* descendant execs + double-forks + reparents to init */
    int f = open(argv[2], O_RDONLY); /* canary trip → KillProcessTree(us) */
    if (f >= 0) { char b[64]; ssize_t r = read(f, b, sizeof b); (void)r; close(f); }
    usleep(2500000);
    return 0;
}
"#,
    )
    .expect("write canary ancestor helper source");
    let status = Command::new("cc")
        .arg("-O0")
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .expect("spawn cc to build canary ancestor helper");
    assert!(
        status.success(),
        "cc failed to build the canary ancestor helper"
    );
    bin
}

// ════════════════════════════════════════════════════════════════════
// D2 — process rules
// ════════════════════════════════════════════════════════════════════

/// R011 — kernel-module tooling exec. Install a benign binary as
/// `/usr/local/bin/insmod` (comm == "insmod"; /usr/local/bin matches
/// no R001..R010 path rule), exec it, assert R011 fires.
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn process_kernel_module_tooling_trips_r011() {
    let _eni = EniIptablesGuard::install();
    let fx = Fixture::setup(&[]);

    // R011 fires KillProcess on the spawn, so the helper may exit
    // via signal — the verdict is logged regardless of the kill
    // landing, so we don't assert the helper's exit status.
    let helper = install_named_to_priv_bin(Path::new("/bin/true"), "insmod");
    let _ = Command::new(&helper.path).stdout(Stdio::null()).status();

    fx.wait_for_verdict("R011_KernelModuleTooling");
}

/// R017 — shell binary from a non-standard path. Install a benign
/// binary as `/usr/local/bin/bash` (comm == "bash"; /usr/local/bin
/// is outside {/bin,/usr/bin}), exec it, assert R017 fires.
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn process_shell_from_nonstandard_path_trips_r017() {
    let _eni = EniIptablesGuard::install();
    let fx = Fixture::setup(&[]);

    // R017 fires KillProcess; ignore the helper's exit status.
    let helper = install_named_to_priv_bin(Path::new("/bin/true"), "bash");
    let _ = Command::new(&helper.path).stdout(Stdio::null()).status();

    fx.wait_for_verdict("R017_ShellFromNonstandardPath");
}

// ════════════════════════════════════════════════════════════════════
// D3 — FIM rules
// ════════════════════════════════════════════════════════════════════

/// FIM-015 — browser stored credentials accessed by a non-browser
/// process. Pre-create a watched file whose path contains the
/// `/Login Data` fragment, then `cat` it (FimOp::Opened by a
/// non-browser comm) → FIM-015 fires (High).
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn fim_browser_cred_access_trips_fim_015() {
    let _eni = EniIptablesGuard::install();
    // The fragment match is on "/Login Data"; the watched inode must
    // exist before agent boot.
    let creddir = tempfile::tempdir().expect("cred tempdir");
    let cred = creddir.path().join("Login Data");
    std::fs::write(&cred, b"placeholder\n").expect("seed cred file");

    let fx = Fixture::setup(&[&cred]);

    // `cat` (a subprocess, so KillProcess targets cat, not the test
    // harness) opens the watched cred file → FimOp::Opened → FIM-015.
    // cat may be killed; ignore its status. Verdict-grep is the
    // authoritative fired-signal (the Opened op is not necessarily
    // persisted to the drift chain, so we don't assert a row here).
    let _ = Command::new("cat")
        .arg(&cred)
        .stdout(Stdio::null())
        .status();

    fx.wait_for_verdict("NN-L-FIM-015_BrowserCredsAccessed");
}

/// FIM-021 — PAM module modified (Critical → COMBAT). Pre-create a
/// watched `*.so` under a `security/` dir (so the agent baselines its
/// SHA-256 at boot), then TRUNCATE-OVERWRITE it from a subprocess →
/// `inode_setattr` (size change) → `FimOp::Modified` carrying the
/// module's own path → FIM-021 fires Critical. EniIptablesGuard
/// cleans up the resulting NORTHNARROW_COMBAT chain.
///
/// Mechanism notes (both observed while building this test):
///   - An APPEND (`>>`) surfaces as `FimOp::Opened` (file-open hook),
///     which FIM-021 (Created|Modified) does not match. A TRUNCATE
///     (`>` over an existing file) goes through `inode_setattr` →
///     `Modified` (same path the `fim_baseline_then_modify` priv-e2e
///     exercises).
///   - Watching the DIRECTORY instead yields a `Created` event whose
///     path is the *directory*, not the child `.so` — FIM-021's
///     `.so`-suffix predicate can't match that. Watching the FILE
///     makes the event carry the file's path.
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn fim_pam_module_modify_trips_fim_021_combat() {
    let _eni = EniIptablesGuard::install();
    let secdir = tempfile::tempdir().expect("security tempdir");
    let sec = secdir.path().join("security");
    std::fs::create_dir(&sec).expect("mkdir security");
    let module = sec.join("pam_evil.so");
    std::fs::write(&module, b"\x7fELF original-module\n").expect("seed pam module");

    // Watch the FILE (exists at boot → baselined).
    let fx = Fixture::setup(&[&module]);

    // Truncate-overwrite FROM A SUBPROCESS (KillProcessTree targets
    // the subprocess, not the test harness). `>` truncates →
    // inode_setattr → FimOp::Modified.
    let overwrite = format!("echo tampered-module > '{}'", module.display());
    let _ = Command::new("sh")
        .arg("-c")
        .arg(&overwrite)
        .stdout(Stdio::null())
        .status();

    // On-disk wire: a Modified-op drift row for the module + verdict.
    fx.wait_drift_matching(1, |r| {
        r["path"].as_str() == Some(module.to_str().unwrap()) && r["op"].as_u64() == Some(1)
    });
    fx.wait_for_verdict("NN-L-FIM-021_PamModuleModified");
}

// ════════════════════════════════════════════════════════════════════
// D4 — net rules
// ════════════════════════════════════════════════════════════════════

/// NN-L-NET-010 — outbound to a high-risk C2 port. Pre-bind a
/// loopback listener on 4444, run a python helper that connects +
/// closes, assert the flow row + NET-010 fires (High).
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn net_outbound_high_risk_c2_port_trips_net_010() {
    let _eni = EniIptablesGuard::install();
    let fx = Fixture::setup(&[]);

    let accept = spawn_oneshot_acceptor(C2_PORT, ACCEPT_TIMEOUT);

    let helper = format!(
        r#"
import socket
s = socket.socket(); s.settimeout(2)
try: s.connect(("127.0.0.1", {C2_PORT}))
except Exception: pass
try: s.shutdown(socket.SHUT_RDWR)
except Exception: pass
s.close()
"#
    );
    // python3 (subprocess) connects → NET-010 KillProcess targets
    // python3, not the test; ignore its exit status.
    let _ = Command::new("python3")
        .arg("-c")
        .arg(&helper)
        .stdout(Stdio::null())
        .status();
    let _ = accept.join();

    // On-disk wire: the flow row (proven reliable on loopback by the
    // N9.1 fixture) + the verdict.
    fx.wait_netflow_matching(1, |r| {
        r["dst_port"].as_u64() == Some(C2_PORT as u64)
            && r["dst_addr"].as_str() == Some("127.0.0.1")
    });
    fx.wait_for_verdict("NN-L-NET-010_OutboundToHighRiskC2Port");
}

/// NN-L-NET-019 — wildcard-bind listener on an uncommon port. Bind
/// `0.0.0.0:<WILDCARD_LISTEN_PORT>`, assert the listener row +
/// NET-019 fires (Medium → ALERTED, no COMBAT).
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn net_wildcard_listener_trips_net_019() {
    let _eni = EniIptablesGuard::install();
    let fx = Fixture::setup(&[]);

    // NN-L-NET-019 is Medium → Log (no kill), so binding from the
    // test process itself is safe.
    {
        let _l = TcpListener::bind(("0.0.0.0", WILDCARD_LISTEN_PORT))
            .expect("bind 0.0.0.0:<port> wildcard listener");
        std::thread::sleep(Duration::from_millis(50));
    }

    fx.wait_listeners_matching(1, |r| {
        r["bind_port"].as_u64() == Some(WILDCARD_LISTEN_PORT as u64)
            && r["bind_addr"].as_str() == Some("0.0.0.0")
    });
    fx.wait_for_verdict("NN-L-NET-019_WildcardListener");
}

// ════════════════════════════════════════════════════════════════════
// D5 — chain rule
// ════════════════════════════════════════════════════════════════════

/// NN-L-CHAIN-002 — /tmp exec followed by same-PID egress (Critical
/// → COMBAT). A cc-compiled helper at `/tmp` connects to a loopback
/// listener as its first syscalls (winning the race against R001's
/// kill), so the agent sees ProcessSpawn(/tmp) [precursor recorded]
/// then the NetFlow [trigger] from the same PID → CHAIN-002 fires.
/// The negative half: a /tmp exec that does NOT connect leaves
/// CHAIN-002 silent.
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn chain_tmp_exec_then_egress_trips_chain_002() {
    let _eni = EniIptablesGuard::install();
    let fx = Fixture::setup(&[]);

    // Receiver for the helper's connect.
    let accept = spawn_oneshot_acceptor(C2_PORT, ACCEPT_TIMEOUT);

    // Build + exec the connecting helper from /tmp (its dir is a
    // tempdir under /tmp on a standard host).
    let tmproot = tempfile::Builder::new()
        .prefix("nnchain")
        .tempdir_in("/tmp")
        .expect("tempdir under /tmp");
    let helper = compile_connect_helper(tmproot.path(), "nnchain_drop", C2_PORT, 0);
    assert!(
        helper.starts_with("/tmp/"),
        "chain helper must live under /tmp/ to trigger the precursor; got {}",
        helper.display()
    );
    let status = Command::new(&helper)
        .stdout(Stdio::null())
        .status()
        .expect("exec /tmp chain helper");
    // The helper may be killed by R001 AFTER it connects; either a
    // clean exit or a signal-kill is acceptable — the connect (and
    // thus the trigger flow) already happened.
    let _ = status;
    let _ = accept.join();

    fx.wait_for_verdict("NN-L-CHAIN-002_TmpExecThenEgress");
}

/// NN-L-CHAIN-002 negative — a /tmp exec with NO egress must not
/// fire the chain (the precursor is recorded but the trigger never
/// arrives). Separate agent instance so the positive test's recorded
/// precursor can't bleed in.
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn chain_tmp_exec_without_egress_does_not_trip_chain_002() {
    let _eni = EniIptablesGuard::install();
    let fx = Fixture::setup(&[]);

    // A /tmp exec that does nothing network-y (a copy of /bin/true).
    let tmproot = tempfile::Builder::new()
        .prefix("nnchain")
        .tempdir_in("/tmp")
        .expect("tempdir under /tmp");
    let quiet = tmproot.path().join("nnchain_quiet");
    std::fs::copy("/bin/true", &quiet).expect("copy /bin/true");
    let mut perms = std::fs::metadata(&quiet).unwrap().permissions();
    use std::os::unix::fs::PermissionsExt;
    perms.set_mode(0o755);
    std::fs::set_permissions(&quiet, perms).unwrap();
    let _ = Command::new(&quiet).stdout(Stdio::null()).status();

    // No egress from that PID → CHAIN-002 must stay silent.
    fx.assert_no_verdict("NN-L-CHAIN-002_TmpExecThenEgress", Duration::from_secs(3));
}

// ════════════════════════════════════════════════════════════════════
// Tappa 10.6 D9 — cross-PID + N-event kill chains (CHAIN-004..008)
// ════════════════════════════════════════════════════════════════════
//
// Reproduce the D6 chains END-TO-END on a live kernel: the D2 BPF refit
// populates ppid + parent_start_ns on every spawn, CHAIN-002's
// observe_spawn (D4) builds the ancestry tree, and a descendant's real
// NetFlow trigger correlates back to an ancestor's precursor via the
// shared CorrelationStore (D3).
//
// Helper shape: a tiny cc-compiled PARENT performs the precursor (its
// own exec name/location, or a file read) then fork+execs a fast
// connect CHILD. The child is a distinct PID placed OUTSIDE /tmp (so it
// doesn't itself trip R001/TmpExec), and it connects in its first
// syscalls — beating the precursor rule's KillProcess roundtrip the
// same way the CHAIN-002 helper does. The child's egress is the
// cross-PID trigger.

/// Compile the cross-PID PARENT helper at `<dir>/<name>`:
///   argv[1] = connect-child binary to fork+exec
///   argv[2] = a file to read first ("-" to skip) — the cred/canary
///             precursor for CHAIN-004/006
/// For CHAIN-005/008 the precursor is the parent's own exec
/// (location=/tmp / name=sudo), so argv[2] is "-".
fn compile_xpid_helper(dir: &Path, name: &str) -> PathBuf {
    let src = dir.join(format!("{name}.c"));
    let bin = dir.join(name);
    std::fs::write(
        &src,
        r#"
#include <unistd.h>
#include <fcntl.h>
int main(int argc, char **argv) {
    if (argc > 2 && argv[2][0] != '-') {
        int f = open(argv[2], O_RDONLY);
        if (f >= 0) { char b[64]; ssize_t r = read(f, b, sizeof b); (void)r; close(f); }
    }
    pid_t p = fork();
    if (p == 0) { execl(argv[1], argv[1], (char *)0); _exit(127); }
    /* Outlive the child's settled egress (CHILD_SETTLE_US) so the tree
       stays intact through the connect when we aren't killed first. */
    usleep(2000000);
    return 0;
}
"#,
    )
    .expect("write xpid helper source");
    let status = Command::new("cc")
        .arg("-O0")
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .expect("spawn cc for xpid helper");
    assert!(status.success(), "cc failed to build the xpid helper");
    bin
}

/// Compile the same-PID 3-step helper (CHAIN-007): read `argv[1]` (the
/// cred precursor) then connect to 127.0.0.1:<C2_PORT> — all one PID.
/// Run from /tmp so its own exec is the TmpExec precursor; the read is
/// the CredRead precursor; the connect is the trigger.
fn compile_seq_helper(dir: &Path, name: &str, port: u16) -> PathBuf {
    let src = dir.join(format!("{name}.c"));
    let bin = dir.join(name);
    std::fs::write(
        &src,
        format!(
            r#"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
int main(int argc, char **argv) {{
    if (argc > 1) {{
        int f = open(argv[1], O_RDONLY);
        if (f >= 0) {{ char b[64]; ssize_t r = read(f, b, sizeof b); (void)r; close(f); }}
    }}
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 1;
    struct sockaddr_in a;
    a.sin_family = AF_INET;
    a.sin_port = htons({port});
    a.sin_addr.s_addr = htonl(0x7f000001);
    connect(fd, (struct sockaddr *)&a, sizeof a);
    close(fd);
    return 0;
}}
"#
        ),
    )
    .expect("write seq helper source");
    let status = Command::new("cc")
        .arg("-O0")
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .expect("spawn cc for seq helper");
    assert!(status.success(), "cc failed to build the seq helper");
    bin
}

/// CHAIN-008 — `sudo`/`su` privesc by a parent, descendant egresses
/// (T1548 → T1041). Cleanest cross-PID repro: no rule kills the `sudo`
/// comm, so the parent survives to fork the connect child.
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn chain_privesc_then_descendant_egress_trips_chain_008() {
    let _eni = EniIptablesGuard::install();
    let fx = Fixture::setup(&[]);
    let accept = spawn_oneshot_acceptor(C2_PORT, ACCEPT_TIMEOUT);

    // Connect child OUTSIDE /tmp (no TmpExec on the child).
    let childdir = tempfile::tempdir().expect("child tempdir");
    let connect_child = install_connect_child(childdir.path());
    // Parent installed as a binary named exactly "sudo" → comm == sudo.
    let parent = install_named_to_priv_bin(&compile_xpid_helper(childdir.path(), "xpid"), "sudo");
    let _ = Command::new(&parent.path)
        .arg(&connect_child.path)
        .arg("-")
        .stdout(Stdio::null())
        .status();
    let _ = accept.join();

    fx.wait_for_verdict("NN-L-CHAIN-008_CrossPidPrivEscExfil");
}

/// CHAIN-005 — `/tmp` exec by a parent, descendant egress to a non-DNS
/// port (T1059 → T1571). R001 KillProcess targets the parent PID only,
/// so the already-forked child survives to connect.
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn chain_tmp_parent_then_descendant_egress_trips_chain_005() {
    let _eni = EniIptablesGuard::install();
    let fx = Fixture::setup(&[]);
    let accept = spawn_oneshot_acceptor(C2_PORT, ACCEPT_TIMEOUT);

    // Child connect helper OUTSIDE /tmp; parent UNDER /tmp (TmpExec).
    let childdir = tempfile::tempdir().expect("child tempdir");
    let connect_child = install_connect_child(childdir.path());
    let tmproot = tempfile::Builder::new()
        .prefix("nnchain")
        .tempdir_in("/tmp")
        .expect("tempdir under /tmp");
    let parent = compile_xpid_helper(tmproot.path(), "xpid");
    assert!(parent.starts_with("/tmp/"), "parent must be under /tmp");
    let _ = Command::new(&parent)
        .arg(&connect_child.path)
        .arg("-")
        .stdout(Stdio::null())
        .status();
    let _ = accept.join();

    fx.wait_for_verdict("NN-L-CHAIN-005_CrossPidTmpC2");
}

/// CHAIN-004 — credential read by a parent, descendant egress
/// (T1555 → T1041). Parent reads a FIM-watched browser-cred file; the
/// FIM-015 KillProcess targets the parent PID only, so the forked child
/// egresses and the lineage walk finds the ancestor's CredRead.
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn chain_cred_read_parent_then_descendant_egress_trips_chain_004() {
    let _eni = EniIptablesGuard::install();
    let creddir = tempfile::tempdir().expect("cred tempdir");
    let cred = creddir.path().join("Login Data");
    std::fs::write(&cred, b"placeholder\n").expect("seed cred file");
    let fx = Fixture::setup(&[&cred]);

    let accept = spawn_oneshot_acceptor(C2_PORT, ACCEPT_TIMEOUT);

    // Parent OUTSIDE /tmp (so only CredRead, not TmpExec). It reads the
    // watched cred, then fork+execs the connect child.
    let childdir = tempfile::tempdir().expect("child tempdir");
    let connect_child = install_connect_child(childdir.path());
    let parent = install_to_priv_bin(&compile_xpid_helper(childdir.path(), "xpidcred"));
    let _ = Command::new(&parent.path)
        .arg(&connect_child.path)
        .arg(&cred)
        .stdout(Stdio::null())
        .status();
    let _ = accept.join();

    fx.wait_for_verdict("NN-L-CHAIN-004_CrossPidCredExfil");
}

/// CHAIN-007 — same-PID 3-step: `/tmp` exec → cred read → egress
/// (T1059 → T1555 → T1041), all one process, via the D3 N-event
/// has_sequence.
///
/// DEFERRED to T10.6.2 — known-flaky, **structural** same-PID
/// double-kill race: the single process must outrun BOTH the R001
/// (`/tmp` exec) and the FIM-015 (cred read) `KillProcess` responses to
/// reach the egress. Unlike the cross-PID chains there is no descendant
/// to escape via daemonize — the egressing process *is* the kill target,
/// so the tree-escape technique used for CHAIN-006 does not apply. Under
/// sequential load the kills win before the connect. Needs a
/// retry-with-fresh-state harness (or a production rule-semantics
/// refinement); the rule logic itself is covered by the chain.rs unit
/// tests. The repro below is retained as the T10.6.2 starting point and
/// is EXCLUDED from the D9 gating run (filter on `descendant_egress`).
#[test]
#[ignore = "T10.6.2: same-PID tmp+cred+egress double-kill race (flaky) — deferred; rule logic unit-tested in chain.rs"]
fn chain_tmp_then_cred_then_egress_trips_chain_007() {
    let _eni = EniIptablesGuard::install();
    let creddir = tempfile::tempdir().expect("cred tempdir");
    let cred = creddir.path().join("Login Data");
    std::fs::write(&cred, b"placeholder\n").expect("seed cred file");
    let fx = Fixture::setup(&[&cred]);

    let accept = spawn_oneshot_acceptor(C2_PORT, ACCEPT_TIMEOUT);

    // Single helper under /tmp: exec (TmpExec) → read cred (CredRead) →
    // connect (trigger), all one PID.
    let tmproot = tempfile::Builder::new()
        .prefix("nnseq")
        .tempdir_in("/tmp")
        .expect("tempdir under /tmp");
    let seq = compile_seq_helper(tmproot.path(), "nnseq_drop", C2_PORT);
    let _ = Command::new(&seq).arg(&cred).stdout(Stdio::null()).status();
    let _ = accept.join();

    fx.wait_for_verdict("NN-L-CHAIN-007_TmpCredExfilSequence");
}

/// CHAIN-006 — canary trip by an ancestor, descendant egress (deception
/// → T1041). Cross-PID form of CHAIN-003.
///
/// Unlike CHAIN-004/005/008 (whose precursor responses kill only the
/// parent PID, so a direct child survives to egress), a canary trip
/// responds with `KillProcessTree` — it kills the whole ancestor tree,
/// the egressing process included. So the descendant must **escape the
/// tree** before the trip: the canary-ancestor spawns a daemonizing
/// connect child that double-forks (grandchild re-execs, intermediate
/// exits → grandchild reparents to init) so the grandchild leaves the
/// ancestor's live tree while the `AncestryTree` edges
/// (grandchild→intermediate→ancestor) — keyed by `ProcKey`, recorded at
/// each exec while the parent was alive — persist. The ancestor then
/// trips the canary; the escaped grandchild egresses afterward and the
/// lineage walk back-correlates to the ancestor's `CanaryTrip`. Real
/// post-detection malware daemonizes for exactly this reason.
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn chain_canary_trip_parent_then_descendant_egress_trips_chain_006() {
    let _eni = EniIptablesGuard::install();
    // The decoy must exist on disk before the canary is deployed (the
    // agent stat()s the inode at deploy time).
    let canarydir = tempfile::tempdir().expect("canary tempdir");
    let decoy = canarydir.path().join("Q4 Secret Plans.docx");
    std::fs::write(&decoy, b"decoy\n").expect("seed canary decoy");
    // The decoy must be in WATCHED_PATHS at boot: the canary detector
    // intercepts `inode_file_open` only for watched inodes (a file
    // canary that isn't FIM-watched never traps the open). Mirrors
    // canary_privileged_e2e's `setup(&[&decoy])`.
    let fx = Fixture::setup(&[&decoy]);
    // Register the file-canary so opens of the decoy inode emit
    // Event::CanaryTripped.
    fx.deploy_file_canary("nnchain006", &decoy);

    let accept = spawn_oneshot_acceptor(C2_PORT, ACCEPT_TIMEOUT);

    // Ancestor + daemonizing descendant, both OUTSIDE /tmp (only the
    // CanaryTrip precursor fires, not TmpExec/R009). The ancestor opens
    // the decoy after the descendant has daemonized clear of the tree.
    let childdir = tempfile::tempdir().expect("child tempdir");
    let daemon_child = install_daemon_connect_child(childdir.path());
    let ancestor = install_to_priv_bin(&compile_canary_ancestor_helper(
        childdir.path(),
        "xpidcanary",
    ));
    let _ = Command::new(&ancestor.path)
        .arg(&daemon_child.path)
        .arg(&decoy)
        .stdout(Stdio::null())
        .status();
    let _ = accept.join();

    fx.wait_for_verdict("NN-L-CHAIN-006_CrossPidCanaryExfil");
}
