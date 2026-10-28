// Lab PR 256 — the one way a test starts an agent, and where its state goes.
//
// No `//!` and no `#![…]` here: the watchdog's tests `include!` this file
// (`watchdog/tests/privileged_e2e.rs`), which takes items only. The agent's
// tests name it `common::agent_state`. Standard library only, for the same
// reason.
//
// An agent writes its evidence where its command line says, and at the
// installed agent's paths for whatever the command line leaves out. The
// privileged suites run as root on lab guests and in the KVM CI, where an
// agent is installed: fixtures that gave their agent a signing key of its
// own but no detection log appended rows under that key to the installed
// agent's chains, and every boot of the installed agent then reported
// `chain_verify_failed` (lot 255); fixtures that gave neither wrote the
// installed agent's audit chain with the installed agent's key (84
// `nn-admin-e2etest-*` rows on one guest).
//
// [`AgentState`] puts every path the agent writes, and what makes it this
// agent, in the test's directory: [`STATE_FLAGS`]. [`INPUT_FLAGS`] name
// what the agent only reads — the test passes its own file or leaves the
// host's. [`HOST_PATHS`] are the paths the agent uses with no flag: every
// agent a test starts shares them with the installed one, and none of them
// is an evidence chain. `xtask/tests/test_state_isolation.rs` holds the two
// flag lists to the agent's command line (`agent/src/boot/cli.rs`, `Cli`) and
// the test sources to this file: an agent is started through
// [`InstalledAgent::command`] or not at all.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// One flag of the agent's command line that names a file the agent
/// writes, or one that makes it this agent, and the file it gets in the
/// test's directory.
pub struct StateFlag {
    pub flag: &'static str,
    /// Its name in the test's directory.
    pub file: &'static str,
    /// Kept by every agent of one directory ([`AgentState::named`]): the
    /// install's identity and its administrators' keys.
    pub shared: bool,
    pub what: &'static str,
}

/// Every flag of the agent's command line that names a file the agent
/// writes, or one that makes it this agent. [`AgentState::args`] passes
/// each one, in the test's directory.
pub const STATE_FLAGS: &[StateFlag] = &[
    StateFlag {
        flag: "--agent-id-file",
        file: "agent_id",
        shared: true,
        what: "the install's id: minted at the first start, bound into every signed request",
    },
    StateFlag {
        flag: "--admin-pub",
        file: "admin.pub",
        shared: true,
        what: "the administrators' keys: the test writes them, rotate-keys rewrites them, and \
               a signed overlay is stored next to them",
    },
    StateFlag {
        flag: "--signing-key-file",
        file: "agent.sig.key",
        shared: false,
        what: "the key every chain is signed with (and agent.sig.pub beside it)",
    },
    StateFlag {
        flag: "--audit-log-file",
        file: "audit.log",
        shared: false,
        what: "the audit chain",
    },
    StateFlag {
        flag: "--chain-heads-file",
        file: "chain_heads.json",
        shared: false,
        what: "the anchor of every chain's head (beside the audit log without the flag: \
               named, so two agents of one directory keep one each)",
    },
    StateFlag {
        flag: "--detections-file",
        file: "detections.jsonl",
        shared: false,
        what: "the detection chain, its archives and manifest",
    },
    StateFlag {
        flag: "--status-events-file",
        file: "status_events.jsonl",
        shared: false,
        what: "the triage status chain, its archives and manifest",
    },
    StateFlag {
        flag: "--netflow-file",
        file: "netflow.jsonl",
        shared: false,
        what: "the netflow chain, its archives and manifest",
    },
    StateFlag {
        flag: "--netflow-listeners-file",
        file: "netflow_listeners.jsonl",
        shared: false,
        what: "the listener chain",
    },
    StateFlag {
        flag: "--fim-baseline-file",
        file: "fim_baseline.jsonl",
        shared: false,
        what: "the FIM baseline chain",
    },
    StateFlag {
        flag: "--fim-drift-file",
        file: "fim_drift.jsonl",
        shared: false,
        what: "the FIM drift chain, its archives and manifest",
    },
    StateFlag {
        flag: "--canary-registry-file",
        file: "canaries.jsonl",
        shared: false,
        what: "the canary registry chain",
    },
    StateFlag {
        flag: "--canary-access-file",
        file: "canary_access.jsonl",
        shared: false,
        what: "the canary access chain",
    },
    StateFlag {
        flag: "--admin-socket",
        file: "admin.sock",
        shared: false,
        what: "the admin socket (a debug build's triggers are read beside it)",
    },
    StateFlag {
        flag: "--shutdown-marker-file",
        file: "agent.shutdown_authorised",
        shared: false,
        what: "the marker of a signed shutdown, which the watchdog reads",
    },
    StateFlag {
        flag: "--pid-file",
        file: "agent.pid",
        shared: false,
        what: "written once every hook is attached; the ids of the agent's BPF programs \
               (bpf-own-ids) go beside it, and the refused starts the audit log could not take \
               (boot-refusals.jsonl, lab PR 262)",
    },
    StateFlag {
        flag: "--watchdog-pidfile",
        file: "watchdog.pid",
        shared: false,
        what: "where the agent looks for its watchdog's pid (absent: no watchdog), which it \
               then protects",
    },
];

/// The agent's other path flags: files it only reads. The test passes its
/// own (`--combat-rules`, the lists, the templates) or leaves the host's.
/// A signed `config overlay set` stores the overlay beside `--admin-pub`,
/// in the test's directory; no suite sends one.
pub const INPUT_FLAGS: &[(&str, &str)] = &[
    ("--btf-check", "a mode: checks a BTF file and exits"),
    ("--combat-rules", "the COMBAT ruleset (IPv4)"),
    ("--combat-rules-v6", "the COMBAT ruleset (IPv6)"),
    ("--combat-allow-cidrs", "the COMBAT carve-out"),
    (
        "--watchdog-exe",
        "the binary a watchdog must run to be protected",
    ),
    (
        "--install-manifest",
        "the hashes the self-integrity check compares",
    ),
    ("--fim-paths-v1", "the watched paths"),
    ("--fim-paths-local", "the watched paths' overlay"),
    ("--canary-template-dir", "the canary templates"),
    ("--netflow-blocklist-v1", "the IP blocklist"),
    ("--netflow-blocklist-local", "the IP blocklist's overlay"),
    ("--netflow-ja3-blocklist-v1", "the JA3 blocklist"),
    (
        "--netflow-ja3-blocklist-local",
        "the JA3 blocklist's overlay",
    ),
    ("--process-comm-allowlist-v1", "the process comm allowlist"),
    (
        "--process-comm-allowlist-local",
        "the process comm allowlist's overlay",
    ),
    ("--netflow-comm-allowlist-v1", "the netflow comm allowlist"),
    (
        "--netflow-comm-allowlist-local",
        "the netflow comm allowlist's overlay",
    ),
    ("--exec-quarantine-scanner", "the exec quarantine's scanner"),
    ("--execq-hashes-local", "the exec quarantine's hash list"),
    ("--exec-policy-local", "the exec policy"),
    ("--rule-policy-local", "the per-rule response policy"),
];

/// The paths an agent uses with no flag to move them. Every agent a test
/// starts shares them with the installed one; none is an evidence chain
/// (every chain flag is in [`STATE_FLAGS`]). The lab stops the installed
/// units and purges the pin root before the suites
/// (`deploy/lab/nn-lab.sh`, `lab_purge_pins`).
pub const HOST_PATHS: &[(&str, &str)] = &[
    (
        "/sys/fs/bpf/northnarrow",
        "the pin root: maps, programs and links (the suites that need a clean one purge it \
         before their agent starts)",
    ),
    (
        "/var/lib/northnarrow",
        "the state directory of the anti-tamper attach: created 0700, protected (NOCREATE, \
         chattr +i); the quarantine vault's directories; last_boot_id; the baits re-created \
         there; combat-audit.jsonl (unsigned, a stale COMBAT's reconcile only)",
    ),
    (
        "/etc/northnarrow",
        "the configuration directory and its files, protected; the baits re-created there; \
         master.key (a quarantine only); .bootstrap, which a rotate-keys dispatch removes \
         when the test's admin.pub holds two keys",
    ),
    (
        "/run/northnarrow",
        "the telemetry probe's directory; containment.json (a block or throttle only); the \
         baits; the watchdog's refused-marker and hold records and install.sh's rollback \
         marker, read and removed (signed into the test's audit log)",
    ),
];

/// The real sudo, by absolute path (`common::REAL_SUDO`).
const SUDO: &str = "/usr/bin/sudo";

/// Where an agent of a test keeps every file of [`STATE_FLAGS`].
#[derive(Debug, Clone)]
pub struct AgentState {
    dir: PathBuf,
    /// `"<name>."` for the agents of one directory ([`AgentState::named`]).
    prefix: String,
}

impl AgentState {
    /// Every file in `dir` (the test's temporary directory) under its name
    /// in [`STATE_FLAGS`].
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
            prefix: String::new(),
        }
    }

    /// One of several agents of the same directory: its own files are
    /// `<name>.<file>`; the [`StateFlag::shared`] ones (the id, the
    /// administrators' keys) are the directory's, one install.
    pub fn named(dir: &Path, name: &str) -> Self {
        Self {
            dir: dir.to_path_buf(),
            prefix: format!("{name}."),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The file `flag` names; panics on a flag that is not in
    /// [`STATE_FLAGS`].
    pub fn path(&self, flag: &str) -> PathBuf {
        let f = STATE_FLAGS
            .iter()
            .find(|f| f.flag == flag)
            .unwrap_or_else(|| panic!("{flag} is not a state flag of the agent"));
        if f.shared {
            self.dir.join(f.file)
        } else {
            self.dir.join(format!("{}{}", self.prefix, f.file))
        }
    }

    pub fn agent_id_file(&self) -> PathBuf {
        self.path("--agent-id-file")
    }
    pub fn admin_pub(&self) -> PathBuf {
        self.path("--admin-pub")
    }
    pub fn signing_key(&self) -> PathBuf {
        self.path("--signing-key-file")
    }
    pub fn audit_log(&self) -> PathBuf {
        self.path("--audit-log-file")
    }
    pub fn detections(&self) -> PathBuf {
        self.path("--detections-file")
    }
    pub fn status_events(&self) -> PathBuf {
        self.path("--status-events-file")
    }
    pub fn netflow(&self) -> PathBuf {
        self.path("--netflow-file")
    }
    pub fn netflow_listeners(&self) -> PathBuf {
        self.path("--netflow-listeners-file")
    }
    pub fn fim_baseline(&self) -> PathBuf {
        self.path("--fim-baseline-file")
    }
    pub fn fim_drift(&self) -> PathBuf {
        self.path("--fim-drift-file")
    }
    pub fn canary_registry(&self) -> PathBuf {
        self.path("--canary-registry-file")
    }
    pub fn canary_access(&self) -> PathBuf {
        self.path("--canary-access-file")
    }
    pub fn admin_socket(&self) -> PathBuf {
        self.path("--admin-socket")
    }
    pub fn shutdown_marker(&self) -> PathBuf {
        self.path("--shutdown-marker-file")
    }
    pub fn pid_file(&self) -> PathBuf {
        self.path("--pid-file")
    }
    pub fn watchdog_pidfile(&self) -> PathBuf {
        self.path("--watchdog-pidfile")
    }

    /// Every flag of [`STATE_FLAGS`] with its file: the agent's state
    /// arguments.
    pub fn args(&self) -> Vec<OsString> {
        STATE_FLAGS
            .iter()
            .flat_map(|f| [OsString::from(f.flag), self.path(f.flag).into_os_string()])
            .collect()
    }

    /// What a signed `nn-admin` request to this agent names: its id
    /// (bound into the signature) and its socket.
    pub fn client_args(&self) -> Vec<OsString> {
        vec![
            "--agent-id-file".into(),
            self.agent_id_file().into_os_string(),
            "--socket".into(),
            self.admin_socket().into_os_string(),
        ]
    }

    /// The watchdog's view of this agent: its pid file and socket, the
    /// watchdog's own pid file (the one the agent looks for), and the
    /// marker of a signed shutdown with the keys and id it is checked
    /// against.
    pub fn watchdog_args(&self) -> Vec<OsString> {
        [
            ("--agent-pidfile", self.pid_file()),
            ("--admin-socket", self.admin_socket()),
            ("--pidfile", self.watchdog_pidfile()),
            ("--shutdown-marker", self.shutdown_marker()),
            ("--admin-pub", self.admin_pub()),
            ("--agent-id-file", self.agent_id_file()),
        ]
        .into_iter()
        .flat_map(|(flag, path)| [OsString::from(flag), path.into_os_string()])
        .collect()
    }
}

/// How the test starts the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Launch {
    /// Through the real sudo (`/usr/bin/sudo`); the environment goes
    /// through `env(1)`, since sudo resets it.
    Sudo,
    /// Directly: the test runs as root.
    Direct,
    /// Lab PR 262: as [`Launch::Sudo`], under `setpriv(1)` with these
    /// capabilities (`kill`, …) dropped from the bounding and inheritable
    /// sets, so the agent's effective set lacks them (a unit's
    /// `CapabilityBoundingSet=` without them).
    SudoWithout(&'static [&'static str]),
}

/// The agent of this build: `CARGO_BIN_EXE_northnarrow-agent` in the
/// agent's tests; in the watchdog's, which cargo gives only their own
/// package's binaries, the sibling release output (`CARGO_TARGET_DIR`, or
/// the repository's `target`).
fn agent_build() -> PathBuf {
    if let Some(exe) = option_env!("CARGO_BIN_EXE_northnarrow-agent") {
        return PathBuf::from(exe);
    }
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("NN_REPO_ROOT")).join("target"));
    target.join("release").join("northnarrow-agent")
}

/// A root-owned copy of the agent under `/usr/local/bin`
/// (`northnarrow-agent-e2etest-<ns>-<pid>`: the lab's purge finds
/// leftovers by `-e2etest`), the one a test starts: R009 kills a root
/// process started from `target/` under /home, and an agent run from a
/// path its user can rewrite is not the agent under test. Drop removes it
/// and fails the test when it cannot (only printed when the test is
/// already failing). Keep it alive as long as the agent runs.
#[derive(Debug)]
pub struct InstalledAgent {
    path: PathBuf,
    /// The directory of its own [`InstalledAgent::install_as_northnarrow_agent`]
    /// created, removed with the copy.
    dir: Option<PathBuf>,
}

/// A name no other copy has (the time's nanoseconds).
fn unique() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// `sudo install -D -m 755 -o root -g root <this build> <path>`; panics
/// when it fails.
fn install_at(path: &Path) {
    let src = agent_build();
    let status = Command::new(SUDO)
        .args(["install", "-D", "-m", "755", "-o", "root", "-g", "root"])
        .arg(&src)
        .arg(path)
        .stdin(Stdio::null())
        .status()
        .expect("spawn sudo install");
    assert!(
        status.success(),
        "sudo install of {} to {} failed",
        src.display(),
        path.display()
    );
}

impl InstalledAgent {
    /// Install this build's agent; panics when that fails.
    pub fn install() -> Self {
        let path = PathBuf::from(format!(
            "/usr/local/bin/northnarrow-agent-e2etest-{}-{}",
            unique(),
            std::process::id()
        ));
        install_at(&path);
        Self { path, dir: None }
    }

    /// Lab PR 262: this build's agent installed under the installed agent's
    /// own name, `northnarrow-agent`, in a root-owned directory of its own
    /// (`/usr/local/bin/northnarrow-agent-e2etest-<ns>-<pid>.d/`), so that an
    /// install manifest whose `bin_dir` is that directory describes it — the
    /// boot's binary integrity check compares only that name. Drop removes
    /// the directory.
    pub fn install_as_northnarrow_agent() -> Self {
        let dir = PathBuf::from(format!(
            "/usr/local/bin/northnarrow-agent-e2etest-{}-{}.d",
            unique(),
            std::process::id()
        ));
        let path = dir.join("northnarrow-agent");
        install_at(&path);
        Self {
            path,
            dir: Some(dir),
        }
    }

    /// The installed copy's path, for what checks the agent's identity
    /// (the watchdog's `--agent-bin`, `/proc/<pid>/exe`). A test starts
    /// the agent with [`InstalledAgent::command`], never from this path.
    pub fn agent_exe(&self) -> &Path {
        &self.path
    }

    /// The agent's command: `launch`, the variables `env`, the installed
    /// copy and every state flag of `state` ([`AgentState::args`]). The
    /// test adds its own flags (the inputs, `--detect-only`, …), the
    /// output and spawns it.
    pub fn command(&self, state: &AgentState, launch: Launch, env: &[(&str, &str)]) -> Command {
        let mut cmd = match launch {
            Launch::Sudo => {
                let mut c = Command::new(SUDO);
                if !env.is_empty() {
                    c.arg("env");
                    for (k, v) in env {
                        c.arg(format!("{k}={v}"));
                    }
                }
                c.arg(&self.path);
                c
            }
            Launch::Direct => {
                let mut c = Command::new(&self.path);
                for (k, v) in env {
                    c.env(k, v);
                }
                c
            }
            Launch::SudoWithout(caps) => {
                let drop: Vec<String> = caps.iter().map(|c| format!("-{c}")).collect();
                let mut c = Command::new(SUDO);
                c.arg("setpriv")
                    .arg(format!("--inh-caps={}", drop.join(",")))
                    .arg(format!("--bounding-set={}", drop.join(",")))
                    .arg("--")
                    .arg("env");
                for (k, v) in env {
                    c.arg(format!("{k}={v}"));
                }
                c.arg(&self.path);
                c
            }
        };
        cmd.args(state.args());
        cmd
    }
}

impl Drop for InstalledAgent {
    fn drop(&mut self) {
        let mut rm = Command::new(SUDO);
        rm.args(["rm", "-f"]).arg(&self.path);
        if let Some(dir) = &self.dir {
            // the copy, then its directory (empty: `rmdir`, never `rm -r`)
            rm = Command::new(SUDO);
            rm.arg("sh")
                .arg("-c")
                .arg("rm -f -- \"$1\" && rmdir -- \"$2\"")
                .arg("sh")
                .arg(&self.path)
                .arg(dir);
        }
        let out = rm.stdin(Stdio::null()).output();
        let failed = match &out {
            Ok(o) if o.status.success() => None,
            Ok(o) => Some(format!(
                "exit {:?}: {}",
                o.status.code(),
                String::from_utf8_lossy(&o.stderr).trim()
            )),
            Err(e) => Some(format!("could not run sudo: {e}")),
        };
        if let Some(why) = failed {
            let msg = format!(
                "InstalledAgent: removing {} failed ({why}); remove it by hand",
                self.path.display()
            );
            if std::thread::panicking() {
                eprintln!("{msg}");
            } else {
                panic!("{msg}");
            }
        }
    }
}
