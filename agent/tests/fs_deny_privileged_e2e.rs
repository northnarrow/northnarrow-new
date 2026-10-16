//! External audit EBPF-015 (NN-AUD-107) — privileged e2e of the
//! new-entry and extended-attribute denies.
//!
//! A real agent registers its own directories with `FS_PROTECT_NOCREATE`
//! (`/etc/northnarrow`, the state directory's `detections/`, the bpffs pin
//! root; the paths are fixed in the agent, so this test touches the REAL
//! filesystem). A root process outside the agent's family then tries every
//! way to add an entry — create, mkdir, mknod (a FIFO), symlink, hard
//! link — and to set or remove an extended attribute on a protected
//! inode:
//!
//! - outside a trusted-installer window each one fails with `EPERM` and
//!   the agent logs an `ANTI-TAMPER DENIAL` with the operation;
//! - inside the window (opened with `nn-admin trusted-installer-grant`,
//!   as `install.sh` does) each one succeeds, and nothing is denied.
//!
//! Each attempt runs in a disposable child (`sh`, `mkdir`, `ln`,
//! `mkfifo`, `python3`): a refused tamper raises COMBAT, whose ladder
//! targets the actor, never the test harness. Entries are named
//! `.nn-e2e-152-*` and removed inside the window.
//!
//! Run (lab guest, units stopped, pins purged — `nn-lab.sh test-ignored`
//! does both):
//!   sudo -E env "PATH=$PATH" cargo test --release \
//!     -p northnarrow-agent --test fs_deny_privileged_e2e \
//!     --features "test-privileged debug-trigger" \
//!     -- --ignored --test-threads=1

#![cfg(feature = "test-privileged")]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

mod common;
use common::EniIptablesGuard;

const SOCKET_POLL_TIMEOUT: Duration = Duration::from_secs(20);
const LOG_POLL_TIMEOUT: Duration = Duration::from_secs(20);
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const PRIV_BIN_DIR: &str = "/usr/local/bin";
const REAL_SUDO: &str = "/usr/bin/sudo";

const ETC: &str = "/etc/northnarrow";
const DETECTIONS: &str = "/var/lib/northnarrow/detections";
const PIN_ROOT: &str = "/sys/fs/bpf/northnarrow";
const XATTR: &str = "user.nn_e2e_152";

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

// ── path-safe install (R009: no root exec from a user path) ─────────

struct InstalledBin {
    path: PathBuf,
}
impl Drop for InstalledBin {
    fn drop(&mut self) {
        let _ = Command::new(REAL_SUDO)
            .args(["rm", "-f"])
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

/// SIGQUIT-on-drop (the task_kill hook refuses SIGKILL/SIGTERM).
struct AgentGuard(Option<Child>);
impl Drop for AgentGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            common::quit_agent(&mut c);
        }
    }
}

// ── agent fixture ───────────────────────────────────────────────────

struct Fixture {
    dir: PathBuf,
    agent_log: PathBuf,
    nn_admin: PathBuf,
    admin_priv: PathBuf,
    _tempdir: tempfile::TempDir,
    _agent_guard: AgentGuard,
    _installed_agent: InstalledBin,
    _installed_admin: InstalledBin,
}

impl Fixture {
    /// Spawn an agent whose own files live in a tempdir; the directories
    /// it protects are the fixed ones (`/etc/northnarrow`, the state
    /// directory, the pin root). Per-test admin key with every role.
    fn setup() -> Self {
        // /etc/northnarrow is registered only if it exists at boot.
        let _ = Command::new(REAL_SUDO).args(["mkdir", "-p", ETC]).status();
        let tempdir = tempfile::tempdir().expect("tempdir");
        let dir = tempdir.path().to_path_buf();
        let installed_agent = install_to_priv_bin(Path::new(agent_bin()));
        let installed_admin = install_to_priv_bin(Path::new(nn_admin_bin()));

        let admin_pub = dir.join("admin.pub");
        let admin_priv = dir.join("admin.priv");
        let tmp_pub = dir.join("admin.pub.tmp");
        let init = Command::new(&installed_admin.path)
            .args(["init", "--priv-out"])
            .arg(&admin_priv)
            .arg("--pub-append")
            .arg(&tmp_pub)
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
        let mut f = std::fs::File::create(&admin_pub).expect("create admin.pub");
        writeln!(f, "{hex} all").expect("write admin.pub");
        drop(f);
        let _ = std::fs::remove_file(&tmp_pub);

        let combat = dir.join("combat-rules.v4");
        std::fs::copy(combat_rules_path(), &combat).expect("copy combat rules");
        let write_empty = |name: &str| {
            let p = dir.join(name);
            std::fs::write(&p, "").unwrap_or_else(|_| panic!("write {name}"));
            p
        };
        let fim_v1 = write_empty("fim-paths.v1");
        let fim_local = write_empty("fim-paths.local");
        let nb_v1 = write_empty("netflow-blocklist.v1");
        let nb_local = write_empty("netflow-blocklist.local");
        let ja3_v1 = write_empty("netflow-ja3-blocklist.v1");
        let ja3_local = write_empty("netflow-ja3-blocklist.local");
        let pca_v1 = write_empty("process-comm-allowlist.v1");
        let pca_local = write_empty("process-comm-allowlist.local");
        let nca_v1 = write_empty("netflow-comm-allowlist.v1");
        let nca_local = write_empty("netflow-comm-allowlist.local");

        let agent_log = dir.join("agent.log");
        let log = std::fs::File::create(&agent_log).expect("create agent.log");
        let log_err = log.try_clone().expect("clone log handle");
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
            .arg("--fim-paths-v1")
            .arg(&fim_v1)
            .arg("--fim-paths-local")
            .arg(&fim_local)
            .arg("--fim-baseline-file")
            .arg(dir.join("fim_baseline.jsonl"))
            .arg("--fim-drift-file")
            .arg(dir.join("fim_drift.jsonl"))
            .arg("--canary-registry-file")
            .arg(dir.join("canaries.jsonl"))
            .arg("--canary-access-file")
            .arg(dir.join("canary_access.jsonl"))
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
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err))
            .spawn()
            .expect("spawn northnarrow-agent");
        let guard = AgentGuard(Some(child));
        let fx = Self {
            nn_admin: installed_admin.path.clone(),
            dir,
            agent_log,
            admin_priv,
            _tempdir: tempdir,
            _agent_guard: guard,
            _installed_agent: installed_agent,
            _installed_admin: installed_admin,
        };
        fx.wait_for_path(&fx.dir.join("admin.sock"), SOCKET_POLL_TIMEOUT);
        // The agent's own line once every filesystem deny hook attached.
        fx.wait_for_log("all inode_protect deny hooks attached");
        fx
    }

    fn wait_for_path(&self, p: &Path, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if p.exists() {
                return;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        panic!("{} never appeared\n{}", p.display(), self.log_tail());
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
        lines[lines.len().saturating_sub(25)..].join("\n")
    }

    fn wait_for_log(&self, needle: &str) {
        let deadline = Instant::now() + LOG_POLL_TIMEOUT;
        while Instant::now() < deadline {
            if self.log_text().contains(needle) {
                return;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        panic!("agent log never contained {needle:?}\n{}", self.log_tail());
    }

    /// `ANTI-TAMPER DENIAL` lines naming `op=<op>`.
    fn denials(&self, op: &str) -> usize {
        let want = format!("op={op}");
        self.log_text()
            .lines()
            .filter(|l| l.contains("ANTI-TAMPER DENIAL"))
            .filter(|l| l.split_whitespace().any(|w| w == want))
            .count()
    }

    fn wait_for_denial(&self, op: &str) {
        let deadline = Instant::now() + LOG_POLL_TIMEOUT;
        while Instant::now() < deadline {
            if self.denials(op) > 0 {
                return;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        panic!("no ANTI-TAMPER DENIAL op={op}\n{}", self.log_tail());
    }

    /// Open the trusted-installer window the way `install.sh` does.
    fn grant_window(&self, secs: u32) {
        let out = Command::new(&self.nn_admin)
            .arg("trusted-installer-grant")
            .arg("--key")
            .arg(&self.admin_priv)
            .arg("--window-secs")
            .arg(secs.to_string())
            .arg("--agent-id-file")
            .arg(self.dir.join("agent_id"))
            .arg("--socket")
            .arg(self.dir.join("admin.sock"))
            .output()
            .expect("spawn nn-admin trusted-installer-grant");
        assert!(
            out.status.success(),
            "trusted-installer-grant failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// One attempt, by a disposable child: `(operation, program, args)`.
struct Attempt {
    op: &'static str,
    argv: Vec<String>,
}

fn attempts(link_src: &Path) -> Vec<Attempt> {
    let a = |op: &'static str, argv: &[&str]| Attempt {
        op,
        argv: argv.iter().map(|s| s.to_string()).collect(),
    };
    let file = format!("{ETC}/.nn-e2e-152-file");
    let state_file = format!("{DETECTIONS}/.nn-e2e-152-file");
    let dir = format!("{ETC}/.nn-e2e-152-dir");
    let pin_dir = format!("{PIN_ROOT}/nn-e2e-152");
    let fifo = format!("{ETC}/.nn-e2e-152-fifo");
    let sym = format!("{ETC}/.nn-e2e-152-sym");
    let link = format!("{ETC}/.nn-e2e-152-link");
    let setx = format!("import os; os.setxattr('{ETC}', '{XATTR}', b'1')");
    let rmx = format!("import os; os.removexattr('{ETC}', '{XATTR}')");
    vec![
        a("create", &["sh", "-c", &format!(": > {file}")]),
        a("create", &["sh", "-c", &format!(": > {state_file}")]),
        a("mkdir", &["mkdir", &dir]),
        a("mkdir", &["mkdir", &pin_dir]),
        a("mknod", &["mkfifo", &fifo]),
        a("symlink", &["ln", "-s", "/etc/hostname", &sym]),
        a("link", &["ln", link_src.to_str().unwrap(), &link]),
        a("xattr", &["python3", "-c", &setx]),
        a("xattr", &["python3", "-c", &rmx]),
    ]
}

fn run(argv: &[String]) -> (bool, String) {
    use std::os::unix::process::CommandExt;
    // Its own process group: the COMBAT ladder a refusal raises acts on
    // the actor, which must not share anything with the test harness.
    let out = Command::new(&argv[0])
        .args(&argv[1..])
        .process_group(0)
        .output()
        .unwrap_or_else(|e| panic!("spawn {argv:?}: {e}"));
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

/// Remove what the attempts made (inside a window: the parents refuse it
/// otherwise) and the hard link's source.
fn cleanup(link_src: &Path) {
    for p in ["file", "fifo", "sym", "link"] {
        let _ = std::fs::remove_file(format!("{ETC}/.nn-e2e-152-{p}"));
    }
    let _ = std::fs::remove_file(format!("{DETECTIONS}/.nn-e2e-152-file"));
    let _ = std::fs::remove_dir(format!("{ETC}/.nn-e2e-152-dir"));
    let _ = std::fs::remove_dir(format!("{PIN_ROOT}/nn-e2e-152"));
    let _ = Command::new("python3")
        .args([
            "-c",
            &format!("import os; os.removexattr('{ETC}', '{XATTR}')"),
        ])
        .stderr(Stdio::null())
        .status();
    let _ = std::fs::remove_file(link_src);
}

/// The hard link's source: a file on the same filesystem as
/// `/etc/northnarrow` (`/etc` itself is not protected).
fn link_source() -> PathBuf {
    let p = PathBuf::from(format!("/etc/.nn-e2e-152-src-{}", std::process::id()));
    std::fs::write(&p, "nn-e2e-152\n").expect("write the link source");
    p
}

/// Outside a trusted-installer window every new entry in the agent's
/// directories, and an extended attribute set or removed on a protected
/// inode, is refused with EPERM and reported by operation.
#[test]
#[ignore = "requires root + bpf LSM; lab: nn-lab.sh test-ignored"]
fn new_entries_and_xattrs_are_denied_outside_the_window() {
    let _eni = EniIptablesGuard::install();
    let fx = Fixture::setup();
    // The agent's own creates at boot (its pins, its chain logs, the
    // baits it recreates) are exempt: nothing denied before the attempts.
    std::thread::sleep(Duration::from_secs(3));
    assert!(
        !fx.log_text().contains("ANTI-TAMPER DENIAL"),
        "the agent's own boot was denied\n{}",
        fx.log_tail()
    );
    let src = link_source();
    for at in attempts(&src) {
        let (ok, text) = run(&at.argv);
        assert!(
            !ok && text.contains("Operation not permitted"),
            "{:?} was not refused with EPERM: ok={ok} {text}\n{}",
            at.argv,
            fx.log_tail()
        );
    }
    for op in ["create", "mkdir", "mknod", "symlink", "link", "xattr"] {
        fx.wait_for_denial(op);
    }
    assert!(fx.denials("create") >= 2, "both creates reported");
    assert!(fx.denials("mkdir") >= 2, "both mkdirs reported");
    assert!(fx.denials("xattr") >= 2, "set and remove reported");
    let _ = std::fs::remove_file(&src);
}

/// Inside the window (`nn-admin trusted-installer-grant`, the install.sh
/// path) the same operations succeed and nothing is denied.
#[test]
#[ignore = "requires root + bpf LSM; lab: nn-lab.sh test-ignored"]
fn new_entries_and_xattrs_are_allowed_inside_the_window() {
    let _eni = EniIptablesGuard::install();
    let fx = Fixture::setup();
    let src = link_source();
    fx.grant_window(60);
    fx.wait_for_log("trusted-installer override ARMED");
    for at in attempts(&src) {
        let (ok, text) = run(&at.argv);
        assert!(
            ok,
            "{:?} ({}) refused inside the window: {text}\n{}",
            at.argv,
            at.op,
            fx.log_tail()
        );
    }
    cleanup(&src);
    std::thread::sleep(Duration::from_secs(2));
    assert!(
        !fx.log_text().contains("ANTI-TAMPER DENIAL"),
        "a denial inside the window\n{}",
        fx.log_tail()
    );
}
