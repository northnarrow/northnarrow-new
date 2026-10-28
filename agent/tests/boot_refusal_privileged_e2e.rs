//! Lab PR 262 (Wave 4 restructure, R11b): a start refused by an integrity
//! check leaves a signed refusal and nothing in the kernel.
//!
//! The real agent, started as the fixtures start it (`common::agent_state`:
//! every file it writes in the test's directory), each time with one
//! integrity check made to fail:
//!
//! - a tampered binary: the agent installed under its own name in a
//!   directory of its own, an install manifest that records its hash, then
//!   one more line appended to it;
//! - an audit log that cannot be written (a directory where it goes);
//! - a broken audit chain (a line that is not a row before the end);
//! - a failed capability gate (`CAP_KILL` dropped from the bounding set by
//!   `setpriv`, the enforcing agent's gate).
//!
//! Each start exits 78 with its gate's refusal signed — an `agent_boot` row
//! with `result: refused` and `refused_by` the gate, in the audit log or,
//! when the audit log is the gate, in a fallback chain of its own beside
//! `--pid-file` (`boot-refusals/`) — which `nn-admin audit verify` accepts with the agent's
//! key; and the host's BPF objects are what they were before it: no program
//! or link that nothing holds (pinned, or attached through a pinned link),
//! the pin root as it was (absent: never created; present: the same names
//! on the same inodes), no list of the agent's program ids, and no pid of
//! the refused start left in the pinned `PROTECTED_PIDS`.
//!
//! Root and `bpftool` (the lab's `test-ignored` runs it single-threaded as
//! root); `#[ignore]`d otherwise.

#![cfg(feature = "test-privileged")]

use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

mod common;
use common::agent_state::{AgentState, InstalledAgent, Launch};

/// A refusal comes before anything is loaded: seconds. An agent still
/// running after this did start (the regression this suite is for).
const REFUSAL_TIMEOUT: Duration = Duration::from_secs(60);

/// The exit status of a refused start (`EX_CONFIG`).
const EX_CONFIG: i32 = 78;

fn nn_admin_bin() -> &'static str {
    env!("CARGO_BIN_EXE_nn-admin")
}

fn combat_rules(dir: &Path) -> PathBuf {
    let rules = dir.join("combat-rules.v4");
    std::fs::copy(
        PathBuf::from(env!("NN_REPO_ROOT")).join("configs/combat-rules.v4"),
        &rules,
    )
    .expect("copy combat rules");
    rules
}

/// An install manifest that describes another copy (`NotApplicable`): the
/// binary integrity check passes whatever the host has installed, so the
/// gate under test is the one that refuses.
fn manifest_of_another_copy(dir: &Path) -> PathBuf {
    let manifest = dir.join("install-manifest.json");
    std::fs::write(
        &manifest,
        serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "provenance": "source-tree",
            "bin_dir": dir.join("another-copy"),
            "files": {},
        })
        .to_string(),
    )
    .unwrap();
    manifest
}

/// The pin root the agent's load creates (`/sys/fs/bpf/northnarrow`).
fn pin_root() -> PathBuf {
    PathBuf::from(northnarrow_agent::anti_tamper::DEFAULT_BPFFS_ROOT)
}

/// One BPF program or link and the live processes that hold it.
#[derive(Debug, Clone)]
struct Object {
    /// bpftool's `type` (`lsm`, `kprobe`, … `cgroup_skb`; a link's `cgroup`).
    ty: String,
    what: String,
    holders: Vec<u32>,
}

/// The host's BPF objects and the agent's pin root.
#[derive(Debug)]
struct Kernel {
    progs: BTreeMap<u32, Object>,
    links: BTreeMap<u32, Object>,
    /// The pin root's entries and their inodes; `None`: no pin root.
    pins: Option<BTreeMap<String, u64>>,
}

/// `bpftool -j <kind> show`: each object by id, with what it is and the
/// pids bpftool lists as holding it.
fn bpftool_objects(kind: &str) -> BTreeMap<u32, Object> {
    let out = Command::new("bpftool")
        .args(["-j", kind, "show"])
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("bpftool -j {kind} show: {e}"));
    assert!(
        out.status.success(),
        "bpftool -j {kind} show: {:?} {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let list: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("bpftool -j {kind} show: not JSON ({e})"));
    list.into_iter()
        .filter_map(|o| {
            let id = u32::try_from(o["id"].as_u64()?).ok()?;
            let holders = o["pids"]
                .as_array()
                .map(|ps| {
                    ps.iter()
                        .filter_map(|p| p["pid"].as_u64())
                        .filter_map(|p| u32::try_from(p).ok())
                        .collect()
                })
                .unwrap_or_default();
            let ty = o["type"].as_str().unwrap_or("?").to_string();
            let what = format!("{kind} {ty} {}", o["name"].as_str().unwrap_or(""));
            Some((id, Object { ty, what, holders }))
        })
        .collect()
}

fn kernel() -> Kernel {
    let pins = match std::fs::read_dir(pin_root()) {
        Ok(dir) => Some(
            dir.flatten()
                .map(|e| {
                    let ino = e.metadata().map(|m| m.ino()).unwrap_or(0);
                    (e.file_name().to_string_lossy().into_owned(), ino)
                })
                .collect(),
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => panic!("{}: {e}", pin_root().display()),
    };
    Kernel {
        progs: bpftool_objects("prog"),
        links: bpftool_objects("link"),
        pins,
    }
}

/// What a start left in the kernel: a program or link `after` has that
/// `before` had not and that no live process holds (only a pin, or a pinned
/// link, keeps an object alive once its process is gone), and any change of
/// the pin root. A cgroup's programs and links are left out: systemd
/// attaches its units' firewall and device programs (`sd_fw_*`,
/// `sd_devices`) to their cgroups, which hold them with no process, as a
/// unit starts (seen on the lab guest at a `daemon-reload`); the agent
/// loads no program of a cgroup type.
fn left_behind(before: &Kernel, after: &Kernel) -> Vec<String> {
    let mut left = Vec::new();
    for (kind, b, a) in [
        ("program", &before.progs, &after.progs),
        ("link", &before.links, &after.links),
    ] {
        for (id, o) in a {
            if b.contains_key(id) || o.ty.starts_with("cgroup") {
                continue;
            }
            let held = o
                .holders
                .iter()
                .any(|p| Path::new(&format!("/proc/{p}")).exists());
            if !held {
                left.push(format!("{kind} {id} ({}) held by nothing", o.what));
            }
        }
    }
    if before.pins != after.pins {
        left.push(format!(
            "the pin root changed: {:?} -> {:?}",
            before.pins, after.pins
        ));
    }
    left
}

/// A start of `installed` with `state`, its log in `log`; waits for it to
/// exit. One that does not exit within [`REFUSAL_TIMEOUT`] started: it is
/// stopped and the test fails.
fn run_until_exit(
    installed: &InstalledAgent,
    state: &AgentState,
    launch: Launch,
    extra: &[&std::ffi::OsStr],
    log: &Path,
) -> ExitStatus {
    let out = std::fs::File::create(log).expect("the agent's log");
    let err = out.try_clone().expect("the agent's log");
    let mut child = installed
        .command(state, launch, &[])
        .args(extra)
        .stdin(Stdio::null())
        .stdout(out)
        .stderr(err)
        .spawn()
        .expect("spawn the agent");
    let deadline = Instant::now() + REFUSAL_TIMEOUT;
    loop {
        match child.try_wait().expect("wait for the agent") {
            Some(status) => return status,
            None if Instant::now() >= deadline => {
                common::quit_agent(&mut child);
                panic!(
                    "the agent did not refuse its start within {REFUSAL_TIMEOUT:?}:\n{}",
                    tail(log)
                );
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

fn read_log(log: &Path) -> String {
    common::strip_ansi(&std::fs::read_to_string(log).unwrap_or_default())
}

fn tail(log: &Path) -> String {
    let text = read_log(log);
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(40)..].join("\n")
}

/// The pid the refused start withdrew from the pinned `PROTECTED_PIDS`, as
/// its log says (no pinned map: none).
fn withdrawn_pid(log: &str) -> Option<u32> {
    log.lines()
        .find(|l| l.contains("the refused start's pid withdrawn"))
        .and_then(|l| l.split("pid=").nth(1))
        .and_then(|s| s.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|s| s.parse().ok())
}

/// The refusal's `agent_boot` row in `chain`, and the chain verified with
/// the agent's key (`nn-admin audit verify`, the operator's check).
fn signed_refusal(chain: &Path, state: &AgentState, gate: &str) -> serde_json::Value {
    let rows = common::read_jsonl_strict(chain);
    let row = rows
        .iter()
        .rev()
        .find(|r| r["op"] == "agent_boot")
        .unwrap_or_else(|| panic!("{}: no agent_boot row: {rows:#?}", chain.display()))
        .clone();
    assert_eq!(row["result"], "refused", "{row}");
    assert_eq!(row["extra"]["refused_by"], gate, "{row}");
    let verify = Command::new(nn_admin_bin())
        .args(["audit", "verify", "--from"])
        .arg(chain)
        .arg("--agent-sig-key")
        .arg(state.signing_key())
        .stdin(Stdio::null())
        .output()
        .expect("nn-admin audit verify");
    assert!(
        verify.status.success(),
        "nn-admin audit verify --from {}: {:?}\n{}{}",
        chain.display(),
        verify.status.code(),
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
    row
}

/// The one fallback chain a refused start wrote beside the pid file: a file
/// of its own in `boot-refusals/` (review #466 F1).
fn fallback_chain(state: &AgentState) -> PathBuf {
    let dir = state.pid_file().parent().unwrap().join("boot-refusals");
    let files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .flatten()
        .map(|e| e.path())
        .collect();
    assert_eq!(files.len(), 1, "{files:?}");
    files[0].clone()
}

/// What every refused start shows: exit 78, the start's refusal lines, none
/// of the load's, nothing left in the kernel, no own program-id list, its
/// pid not left protected.
fn assert_refused_before_the_load(
    status: ExitStatus,
    log: &Path,
    state: &AgentState,
    before: &Kernel,
    gate: &str,
) -> String {
    let text = read_log(log);
    assert_eq!(status.code(), Some(EX_CONFIG), "{}", tail(log));
    assert!(
        text.lines()
            .any(|l| l.contains("start refused") && l.contains(gate)),
        "no `start refused` for {gate}:\n{}",
        tail(log)
    );
    for loaded in [
        "BTF_OFFSETS map armed",
        "sensor multiplexer attached",
        "anti-tamper: PIDs registered with kernel",
        "boot phase done phase=preflight",
    ] {
        assert!(
            !text.contains(loaded),
            "`{loaded}` in a refused start's log:\n{}",
            tail(log)
        );
    }
    let after = kernel();
    let left = left_behind(before, &after);
    assert!(left.is_empty(), "the refused start left: {left:#?}");
    let own_ids = state
        .pid_file()
        .parent()
        .unwrap()
        .join(northnarrow_agent::anti_tamper::bpf_defense::OWN_IDS_FILE_NAME);
    assert!(!own_ids.exists(), "{} written", own_ids.display());
    if let Some(pid) = withdrawn_pid(&text) {
        let lookup = Command::new("bpftool")
            .args(["map", "lookup", "pinned"])
            .arg(common::protected_pids_pin())
            .arg("key")
            .args(common::pid_key_bytes(pid))
            .stdin(Stdio::null())
            .output()
            .expect("bpftool map lookup");
        assert!(
            !lookup.status.success(),
            "pid {pid} still in PROTECTED_PIDS: {}",
            String::from_utf8_lossy(&lookup.stdout)
        );
    } else {
        assert!(
            !common::protected_pids_pin().exists(),
            "a pinned PROTECTED_PIDS and no withdrawal in the log:\n{}",
            tail(log)
        );
    }
    text
}

/// The preconditions every case shares: root, bpftool, no NorthNarrow
/// daemon running (a refused start shares the pin root with any agent).
fn preconditions(what: &str) {
    common::require_root(what);
    common::require_bpftool();
    common::refuse_if_northnarrow_running(what);
}

/// A tampered binary: the install manifest records the agent's hash, one
/// more line is appended to it, the start refuses before the load and
/// signs `install_manifest` (`mismatch`) in the audit log.
#[test]
#[ignore = "root and bpftool: nn-lab.sh test-ignored"]
fn a_tampered_binary_is_refused_before_the_load() {
    preconditions("start a tampered agent");
    let dir = tempfile::tempdir().unwrap();
    let state = AgentState::new(dir.path());
    let installed = InstalledAgent::install_as_northnarrow_agent();
    let binary = installed.agent_exe().to_path_buf();
    let sha = Command::new("sha256sum")
        .arg(&binary)
        .output()
        .expect("sha256sum");
    let sha = String::from_utf8_lossy(&sha.stdout)
        .split_whitespace()
        .next()
        .expect("a hash")
        .to_string();
    let manifest = dir.path().join("install-manifest.json");
    std::fs::write(
        &manifest,
        serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "provenance": "source-tree",
            "bin_dir": binary.parent().unwrap(),
            "files": { "northnarrow-agent": sha },
        })
        .to_string(),
    )
    .unwrap();
    let tampered = Command::new("sh")
        .arg("-c")
        .arg("printf '\\n# lab PR 262: one line more than install.sh recorded\\n' >> \"$1\"")
        .arg("sh")
        .arg(&binary)
        .status()
        .expect("append to the copy");
    assert!(tampered.success());
    let rules = combat_rules(dir.path());
    let before = kernel();
    let log = dir.path().join("agent.log");
    let status = run_until_exit(
        &installed,
        &state,
        Launch::Sudo,
        &[
            "--install-manifest".as_ref(),
            manifest.as_os_str(),
            "--combat-rules".as_ref(),
            rules.as_os_str(),
        ],
        &log,
    );
    let text = assert_refused_before_the_load(status, &log, &state, &before, "install_manifest");
    assert!(text.contains("binary integrity MISMATCH"), "{}", tail(&log));
    let row = signed_refusal(&state.audit_log(), &state, "install_manifest");
    assert_eq!(row["extra"]["binary_integrity"], "mismatch", "{row}");
    assert!(
        row["extra"]["detail"]
            .as_str()
            .is_some_and(|d| d.contains(&format!("northnarrow-agent: expected {sha} got"))),
        "{row}"
    );
}

/// An audit log that cannot be written: the start refuses before the load,
/// and the refusal is signed in the fallback chain beside `--pid-file`.
#[test]
#[ignore = "root and bpftool: nn-lab.sh test-ignored"]
fn an_unwritable_audit_log_is_refused_before_the_load_and_signed_beside_the_pid_file() {
    preconditions("start an agent whose audit log cannot be written");
    let dir = tempfile::tempdir().unwrap();
    let state = AgentState::new(dir.path());
    std::fs::create_dir(state.audit_log()).unwrap();
    let installed = InstalledAgent::install();
    let rules = combat_rules(dir.path());
    let manifest = manifest_of_another_copy(dir.path());
    let before = kernel();
    let log = dir.path().join("agent.log");
    let status = run_until_exit(
        &installed,
        &state,
        Launch::Sudo,
        &[
            "--install-manifest".as_ref(),
            manifest.as_os_str(),
            "--combat-rules".as_ref(),
            rules.as_os_str(),
        ],
        &log,
    );
    let text = assert_refused_before_the_load(status, &log, &state, &before, "audit_log");
    assert!(text.contains("audit log NOT writable"), "{}", tail(&log));
    assert!(
        text.contains("refused boot recorded in the fallback chain"),
        "{}",
        tail(&log)
    );
    let fallback = fallback_chain(&state);
    let row = signed_refusal(&fallback, &state, "audit_log");
    assert!(
        row["extra"]["detail"]
            .as_str()
            .is_some_and(|d| d.contains("is not writable")),
        "{row}"
    );
}

/// A broken audit chain (a line before the end that is not a row): found
/// when the log is opened, now before the load (it was after the attach),
/// and signed in the fallback chain — the chain cannot take it.
#[test]
#[ignore = "root and bpftool: nn-lab.sh test-ignored"]
fn a_broken_audit_chain_is_refused_before_the_load() {
    preconditions("start an agent whose audit chain is broken");
    let dir = tempfile::tempdir().unwrap();
    let state = AgentState::new(dir.path());
    std::fs::write(
        state.audit_log(),
        "{\"not\": \"a row\"}\n{\"not\": \"a row either\"}\n",
    )
    .unwrap();
    let installed = InstalledAgent::install();
    let rules = combat_rules(dir.path());
    let manifest = manifest_of_another_copy(dir.path());
    let before = kernel();
    let log = dir.path().join("agent.log");
    let status = run_until_exit(
        &installed,
        &state,
        Launch::Sudo,
        &[
            "--install-manifest".as_ref(),
            manifest.as_os_str(),
            "--combat-rules".as_ref(),
            rules.as_os_str(),
        ],
        &log,
    );
    let text = assert_refused_before_the_load(status, &log, &state, &before, "audit_log");
    assert!(text.contains("audit log open failed"), "{}", tail(&log));
    let fallback = fallback_chain(&state);
    let row = signed_refusal(&fallback, &state, "audit_log");
    assert!(
        row["extra"]["detail"]
            .as_str()
            .is_some_and(|d| d.contains("cannot be opened")),
        "{row}"
    );
    // the broken chain is left as it was found
    assert_eq!(
        std::fs::read_to_string(state.audit_log()).unwrap(),
        "{\"not\": \"a row\"}\n{\"not\": \"a row either\"}\n"
    );
}

/// Review #466 F1, the reviewer's four probes on the real agent: an audit
/// log that cannot take the refusal, and where its fallback directory goes
/// a symbolic link to the agent's key, one to a file without a final
/// newline, a dangling one, a FIFO. Each start refuses before the load
/// (exit 78, nothing in the kernel), at once, the refusal in the journal
/// alone; the key is in no line of its log and unchanged, the file
/// unchanged, the dangling link's target not created.
#[test]
#[ignore = "root and bpftool: nn-lab.sh test-ignored"]
fn names_planted_where_the_fallback_goes_are_never_followed() {
    preconditions("start agents with names planted where their fallback goes");
    let dir = tempfile::tempdir().unwrap();
    let state = AgentState::new(dir.path());
    std::fs::create_dir(state.audit_log()).unwrap();
    northnarrow_agent::audit::AgentSigningKey::load_or_bootstrap(&state.signing_key()).unwrap();
    let key_text = std::fs::read_to_string(state.signing_key()).unwrap();
    let target = dir.path().join("protected.json");
    let body = b"{\"first\":1}\n{\"second\": \"no newline\"";
    std::fs::write(&target, body).unwrap();
    let elsewhere = dir.path().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    let installed = InstalledAgent::install();
    let rules = combat_rules(dir.path());
    let manifest = manifest_of_another_copy(dir.path());
    let fallback = state.pid_file().parent().unwrap().join("boot-refusals");
    for (case, plant) in [
        ("a link to the key", 0),
        ("a link to a file without a final newline", 1),
        ("a dangling link", 2),
        ("a FIFO", 3),
    ] {
        match plant {
            0 => std::os::unix::fs::symlink(state.signing_key(), &fallback).unwrap(),
            1 => std::os::unix::fs::symlink(&target, &fallback).unwrap(),
            2 => std::os::unix::fs::symlink(elsewhere.join("planted"), &fallback).unwrap(),
            _ => {
                let st = Command::new("mkfifo")
                    .arg(&fallback)
                    .status()
                    .expect("mkfifo");
                assert!(st.success());
            }
        }
        let before = kernel();
        let log = dir.path().join(format!("agent-{plant}.log"));
        let status = run_until_exit(
            &installed,
            &state,
            Launch::Sudo,
            &[
                "--install-manifest".as_ref(),
                manifest.as_os_str(),
                "--combat-rules".as_ref(),
                rules.as_os_str(),
            ],
            &log,
        );
        let text = assert_refused_before_the_load(status, &log, &state, &before, "audit_log");
        assert!(
            text.contains("could not record the refused boot in a signed chain"),
            "{case}: {}",
            tail(&log)
        );
        assert!(
            !text.contains(key_text.trim()),
            "{case}: the key in the log"
        );
        assert!(
            !text.contains("no newline"),
            "{case}: the file's line in the log"
        );
        assert_eq!(
            std::fs::read_to_string(state.signing_key()).unwrap(),
            key_text
        );
        assert_eq!(std::fs::read(&target).unwrap(), body, "{case}");
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0, "{case}");
        std::fs::remove_file(&fallback).unwrap();
    }
}

/// Review #466 F4: a signing key that is there but is not one — the key's
/// name a link to `/dev/null`, as a bind mount of it shows the name — is an
/// audit log that cannot be written: the start refuses before the load
/// (exit 78, nothing in the kernel, the pid withdrawn), and since nothing
/// can sign it the journal alone holds the refusal; no row is written.
#[test]
#[ignore = "root and bpftool: nn-lab.sh test-ignored"]
fn a_key_that_cannot_be_loaded_is_refused_before_the_load() {
    preconditions("start an agent whose signing key is /dev/null");
    let dir = tempfile::tempdir().unwrap();
    let state = AgentState::new(dir.path());
    std::os::unix::fs::symlink("/dev/null", state.signing_key()).unwrap();
    let installed = InstalledAgent::install();
    let rules = combat_rules(dir.path());
    let manifest = manifest_of_another_copy(dir.path());
    let before = kernel();
    let log = dir.path().join("agent.log");
    let status = run_until_exit(
        &installed,
        &state,
        Launch::Sudo,
        &[
            "--install-manifest".as_ref(),
            manifest.as_os_str(),
            "--combat-rules".as_ref(),
            rules.as_os_str(),
        ],
        &log,
    );
    let text = assert_refused_before_the_load(status, &log, &state, &before, "audit_log");
    assert!(
        text.contains("agent signing key cannot be loaded"),
        "{}",
        tail(&log)
    );
    assert!(
        text.contains("could not record the refused boot in a signed chain"),
        "{}",
        tail(&log)
    );
    let rows = std::fs::read_to_string(state.audit_log()).unwrap_or_default();
    assert!(!rows.contains("agent_boot"), "a row was signed: {rows}");
    assert!(
        std::fs::symlink_metadata(state.signing_key())
            .unwrap()
            .file_type()
            .is_symlink(),
        "the key's name left as it was"
    );
}

/// The capability gate: an enforcing agent without CAP_KILL refuses before
/// the load (it used to exit 1 with no row) and signs `capabilities`.
#[test]
#[ignore = "root and bpftool: nn-lab.sh test-ignored"]
fn a_failed_capability_gate_is_refused_before_the_load() {
    preconditions("start an agent without CAP_KILL");
    let dir = tempfile::tempdir().unwrap();
    let state = AgentState::new(dir.path());
    let installed = InstalledAgent::install();
    let rules = combat_rules(dir.path());
    let manifest = manifest_of_another_copy(dir.path());
    let before = kernel();
    let log = dir.path().join("agent.log");
    let status = run_until_exit(
        &installed,
        &state,
        Launch::SudoWithout(&["kill"]),
        &[
            "--install-manifest".as_ref(),
            manifest.as_os_str(),
            "--combat-rules".as_ref(),
            rules.as_os_str(),
        ],
        &log,
    );
    let text = assert_refused_before_the_load(status, &log, &state, &before, "capabilities");
    assert!(text.contains("CAP_KILL missing"), "{}", tail(&log));
    let row = signed_refusal(&state.audit_log(), &state, "capabilities");
    assert_eq!(row["extra"]["binary_integrity"], "unchecked", "{row}");
}

/// The kernel snapshot's own logic: an object held by a live process is
/// not left behind, one held by nothing is, a changed pin root is.
#[test]
fn left_behind_counts_only_what_nothing_holds() {
    let obj = |holders: Vec<u32>| Object {
        ty: "lsm".into(),
        what: "prog lsm x".into(),
        holders,
    };
    let before = Kernel {
        progs: BTreeMap::from([(1, obj(vec![]))]),
        links: BTreeMap::new(),
        pins: None,
    };
    let me = std::process::id();
    let systemd = Object {
        ty: "cgroup_skb".into(),
        what: "prog cgroup_skb sd_fw_egress".into(),
        holders: vec![],
    };
    let after = Kernel {
        progs: BTreeMap::from([
            (1, obj(vec![])),
            (2, obj(vec![me])),
            (3, obj(vec![])),
            (4, systemd),
        ]),
        links: BTreeMap::new(),
        pins: Some(BTreeMap::from([("PROTECTED_PIDS".to_string(), 7)])),
    };
    let left = left_behind(&before, &after);
    assert_eq!(left.len(), 2, "{left:?}");
    assert!(left[0].starts_with("program 3 "), "{left:?}");
    assert!(left[1].starts_with("the pin root changed"), "{left:?}");
}
