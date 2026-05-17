//! Privileged invariant test for Tappa 7 task 6 **commit #2** — the
//! anti-tamper map-pinning bug fix.
//!
//! ## What this proves (the §4 kernel-ID stability invariant)
//!
//! The commit-#1 → commit-#2 regression was: `EbpfLoader::map_pin_path`
//! is consulted by aya **only** for maps whose ELF def carries
//! `LIBBPF_PIN_BY_NAME` (`aya-0.13.1` `bpf.rs:494`). The six
//! anti-tamper maps were declared with the non-pinning constructors,
//! so every agent boot created a *fresh* kernel `PROTECTED_PIDS`
//! while the (then-pinned, commit-#2b) LSM hook still referenced the
//! previous boot's map — a split brain that left a respawned agent
//! unprotected.
//!
//! Commit #2 switches the six declarations to `::pinned(..)`. This
//! test asserts the resulting invariant end-to-end:
//!
//! 1. Boot the real agent; it pins `PROTECTED_PIDS` to
//!    `<DEFAULT_BPFFS_ROOT>/PROTECTED_PIDS`. Record its kernel map
//!    id and assert a live anti-tamper LSM program is bound to that
//!    id (`bpftool prog show … map_ids`).
//! 2. Stop the agent (SIGQUIT — SIGKILL/SIGTERM are denied by the
//!    very hook under test). Assert the pin **survives process
//!    exit** — direct evidence the kernel object outlived the agent.
//! 3. Restart the agent. Assert the pinned map id is **unchanged**
//!    (same kernel object reused via `bpf_get_object`, not a fresh
//!    one) and that the *new* boot's LSM hooks are bound to that
//!    same id. Equal ids ⇒ split brain closed.
//!
//! In commit #2 the LSM **programs/links are not yet pinned** (that
//! is commit #2b), so the in-kernel LSM hook is located while the
//! agent is alive by scanning loaded programs for the one whose
//! `map_ids` references the pinned `PROTECTED_PIDS` object — *not*
//! by program name (aya names programs after the truncated Rust fn
//! symbol, not the `#[lsm]` hook, so a name lookup is brittle; see
//! `find_lsm_prog_using_map`). The pinned-program form of step-1/3's
//! assertion is deferred to commit #2b's harness.
//!
//! ## Requirements (Hetzner verify box only)
//!
//! - root; `/sys/fs/bpf` mounted as bpffs; `CONFIG_BPF_LSM=y` with
//!   `bpf` in the boot `lsm=` chain (see `docs/TAPPA7_PREREQ.md`);
//!   `bpftool` on PATH; the eBPF object built (`cargo xtask
//!   build-ebpf`) so the agent embeds a real program.
//! - The workspace built with `--features test-privileged`.
//!
//! ## Destructive precondition
//!
//! This test **removes `DEFAULT_BPFFS_ROOT` recursively at start** so
//! a stale pin from a prior run cannot make the id assertion pass
//! against an unrelated object. That detaches anything pinned there.
//! **Do not run this on a host with a live production agent.** It is
//! `#[ignore]`d so it only runs when invoked deliberately
//! (`cargo test --features test-privileged --test privileged_map_pin
//! -- --ignored`), exactly as the commit-#2 verify protocol does.
//!
//! CI compiles this via `cargo test --no-run` (bit-rot guard) but
//! never executes it.

#![cfg(feature = "test-privileged")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use northnarrow_agent::anti_tamper::DEFAULT_BPFFS_ROOT;

const PIN_APPEAR_TIMEOUT: Duration = Duration::from_secs(20);
/// Aya's `Ebpf::load_from_bytes` only *creates* maps (which is when
/// the `PROTECTED_PIDS` pin file appears); each LSM program is loaded
/// into the kernel and attached afterwards by per-hook
/// `program.load()` + `attach()` calls. The pin-file gate therefore
/// races the prog-load step, so we additionally poll until an LSM
/// program is actually bound to the pinned map. 20s is generous
/// headroom over the typical sub-200ms attach (slow/cold CI), and a
/// genuine non-attach within 20s is itself a failure worth surfacing.
const LSM_ATTACH_TIMEOUT: Duration = Duration::from_secs(20);
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const POST_EXIT_SETTLE: Duration = Duration::from_millis(500);

/// `<DEFAULT_BPFFS_ROOT>/PROTECTED_PIDS` — the map whose kernel-id
/// stability across restart is the entire point of commit #2.
fn protected_pids_pin() -> PathBuf {
    Path::new(DEFAULT_BPFFS_ROOT).join("PROTECTED_PIDS")
}

fn combat_rules_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("configs")
        .join("combat-rules.v4")
}

/// RAII guard: SIGQUIT-on-drop so a failed assertion never leaks a
/// daemon. SIGKILL/SIGTERM are denied by the `task_kill` hook the
/// agent attaches to its own PID, so we shell out `kill -QUIT`
/// (SIGQUIT is not on the deny list — see `agent-ebpf/src/task_kill.rs`).
/// Shelling out keeps this test free of any new dev-dependency.
struct AgentGuard(Option<Child>);

impl AgentGuard {
    /// Stop the agent and block until it has actually exited.
    fn stop(&mut self) {
        if let Some(mut c) = self.0.take() {
            sigquit(c.id());
            let _ = c.wait();
        }
    }
}

impl Drop for AgentGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            sigquit(c.id());
            let _ = c.wait();
        }
    }
}

fn sigquit(pid: u32) {
    // `kill` from coreutils/util-linux; SIGQUIT(3) is the documented
    // anti-tamper escape hatch. Running as root on the verify box,
    // so signalling the (self-protected) agent is permitted.
    let _ = Command::new("kill")
        .args(["-QUIT", &pid.to_string()])
        .status();
}

/// Spawn the real agent against per-test tempdir paths. Mirrors
/// `privileged_e2e::spawn_agent`'s flag set; `--no-ade` keeps the
/// model/inference path out of a test that only exercises eBPF load.
fn spawn_agent(tempdir: &Path) -> AgentGuard {
    let rules = tempdir.join("combat-rules.v4");
    std::fs::copy(combat_rules_path(), &rules).expect("copy combat rules into tempdir");

    let child = Command::new(env!("CARGO_BIN_EXE_northnarrow-agent"))
        .arg("--combat-rules")
        .arg(&rules)
        .arg("--admin-pub")
        .arg(tempdir.join("admin.pub"))
        .arg("--admin-socket")
        .arg(tempdir.join("admin.sock"))
        .arg("--no-ade")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn northnarrow-agent");
    AgentGuard(Some(child))
}

/// Block until the `PROTECTED_PIDS` pin file exists, or panic with
/// an actionable message. The agent pins maps inside
/// `SensorMultiplexer::start()`, well before it is otherwise ready,
/// so this also serves as a "agent reached eBPF load" gate.
fn wait_for_pin(path: &Path) {
    let deadline = Instant::now() + PIN_APPEAR_TIMEOUT;
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    panic!(
        "pin {} never appeared within {:?}. Checklist: running as root? \
         /sys/fs/bpf is bpffs? CONFIG_BPF_LSM + `bpf` in lsm= chain? \
         eBPF object built via `cargo xtask build-ebpf`?",
        path.display(),
        PIN_APPEAR_TIMEOUT
    );
}

/// Kernel map id of a pinned map, parsed from
/// `bpftool map show pinned <path>`. First whitespace/`:`-delimited
/// token of line 1 is the id, e.g. `189: hash  name PROTECTED_PIDS`.
fn pinned_map_id(pin: &Path) -> u64 {
    let out = Command::new("bpftool")
        .args(["map", "show", "pinned"])
        .arg(pin)
        .output()
        .expect("spawn `bpftool map show pinned` — is bpftool on PATH?");
    assert!(
        out.status.success(),
        "bpftool map show pinned {} failed: {}",
        pin.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.lines().next().unwrap_or_default();
    first
        .split(|c: char| c == ':' || c.is_whitespace())
        .find(|t| !t.is_empty())
        .and_then(|t| t.parse::<u64>().ok())
        .unwrap_or_else(|| panic!("could not parse map id from bpftool output: {stdout:?}"))
}

/// One `bpftool prog show` record, reduced to the fields this test
/// reasons about. `name` is captured for diagnostics **only** — it
/// is deliberately never matched on (see `find_lsm_prog_using_map`).
#[derive(Debug)]
struct ProgInfo {
    id: u64,
    prog_type: String,
    name: Option<String>,
    map_ids: Vec<u64>,
}

/// Full `bpftool prog show` (every loaded program, plain text). We do
/// **not** pass `--json`: parsing JSON would mean a new dev-dependency
/// (`serde_json` is a normal dep of the crate, not reachable from an
/// integration-test crate), and the module contract above is to stay
/// dev-dependency-free. The plain-text record grammar is stable and
/// trivially block-parseable, so it carries the same information.
fn bpftool_prog_show_all() -> Result<String, String> {
    let out = Command::new("bpftool")
        .args(["prog", "show"])
        .output()
        .map_err(|e| format!("spawn `bpftool prog show`: {e} — is bpftool on PATH?"))?;
    if !out.status.success() {
        return Err(format!(
            "`bpftool prog show` exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Block-parse `bpftool prog show` plain text. A record starts at a
/// line whose first token is `<id>:`; its `prog_type` is the next
/// token; continuation lines (anything until the next header) may
/// carry a `map_ids a,b,c` token and an optional `name <n>`.
fn parse_progs(text: &str) -> Vec<ProgInfo> {
    let mut progs = Vec::new();
    let mut cur: Option<ProgInfo> = None;
    for line in text.lines() {
        let trimmed = line.trim_start();
        let toks: Vec<&str> = trimmed.split_whitespace().collect();
        let Some(&first) = toks.first() else { continue };

        // Header line? `<id>:` then the program type.
        if let Some(id_str) = first.strip_suffix(':') {
            if let Ok(id) = id_str.parse::<u64>() {
                if let Some(p) = cur.take() {
                    progs.push(p);
                }
                let prog_type = toks.get(1).copied().unwrap_or_default().to_string();
                let name = toks
                    .iter()
                    .position(|&t| t == "name")
                    .and_then(|i| toks.get(i + 1))
                    .map(|s| s.to_string());
                cur = Some(ProgInfo {
                    id,
                    prog_type,
                    name,
                    map_ids: Vec::new(),
                });
                continue;
            }
        }

        // Continuation line of the current record: harvest map_ids.
        if let Some(p) = cur.as_mut() {
            if let Some(i) = toks.iter().position(|&t| t == "map_ids") {
                if let Some(list) = toks.get(i + 1) {
                    p.map_ids = list
                        .split(',')
                        .filter_map(|t| t.trim().parse::<u64>().ok())
                        .collect();
                }
            }
        }
    }
    if let Some(p) = cur.take() {
        progs.push(p);
    }
    progs
}

/// Locate the loaded **LSM** program bound to the pinned
/// `PROTECTED_PIDS` kernel object, identified by that object's map
/// **id** (`map_id`, as returned by [`pinned_map_id`]).
///
/// Why by map id and not by program name: aya derives the kernel
/// program name from the Rust function symbol, truncated to
/// `BPF_OBJ_NAME_LEN-1` = 15 bytes — *not* from the `#[lsm(hook =
/// …)]` attach point. `bpftool prog show name <X>` therefore can't
/// be driven from the hook name, and hard-coding the truncated
/// symbol is brittle (it silently rots if anyone renames the eBPF
/// fn). Matching on `type == lsm` + `map_ids ∋ map_id` needs neither:
/// it asks exactly the question the §4 invariant cares about — *is
/// some in-kernel LSM hook actually wired to the pinned object?* —
/// and is the genuine split-brain discriminator: a freshly-created
/// (un-pinned) map would carry a different id, so a split-brained
/// boot yields **no** match and the lookup fails loudly.
///
/// `PROTECTED_PIDS` is shared by three LSM hooks (`task_kill`,
/// `ptrace_access_check`, and the `inode_*`/`file_ioctl` family);
/// any one of them referencing the pinned id proves the binding, so
/// the first match is returned.
fn find_lsm_prog_using_map(map_id: u64) -> Result<ProgInfo, String> {
    let text = bpftool_prog_show_all()?;
    let progs = parse_progs(&text);

    if let Some(p) = progs
        .into_iter()
        .find(|p| p.prog_type == "lsm" && p.map_ids.contains(&map_id))
    {
        return Ok(p);
    }

    // Re-parse for an actionable diagnostic: which LSM programs *are*
    // loaded, and what maps do they point at?
    let lsm: Vec<String> = parse_progs(&text)
        .into_iter()
        .filter(|p| p.prog_type == "lsm")
        .map(|p| {
            format!(
                "  id={} name={:?} map_ids={:?}",
                p.id, p.name, p.map_ids
            )
        })
        .collect();
    Err(format!(
        "no loaded LSM program references pinned PROTECTED_PIDS id \
         {map_id}. Either no anti-tamper hook attached (agent down / \
         BPF-LSM not in lsm= chain) or the agent created a FRESH map \
         instead of reusing the pinned one (split brain). LSM programs \
         currently loaded:\n{}",
        if lsm.is_empty() {
            "  <none>".to_string()
        } else {
            lsm.join("\n")
        }
    ))
}

/// Readiness gate bridging the pin-file gate and the `map_ids`
/// assertion: poll [`find_lsm_prog_using_map`] until an LSM program
/// is bound to the pinned map, or time out. Closes the race where
/// the `PROTECTED_PIDS` pin appears at map-create time
/// (`Ebpf::load_from_bytes`) but no program is in the kernel yet
/// (per-hook `program.load()` + `attach()` run afterwards). Mirrors
/// the deadline/poll shape of [`wait_for_pin`] and
/// `privileged_e2e::wait_for_socket`.
fn wait_for_lsm_attach(map_id: u64) -> Result<(), String> {
    let deadline = Instant::now() + LSM_ATTACH_TIMEOUT;
    let mut last_err = String::new();
    while Instant::now() < deadline {
        match find_lsm_prog_using_map(map_id) {
            Ok(_) => return Ok(()),
            Err(e) => last_err = e,
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    Err(format!(
        "timeout waiting for any LSM prog bound to map_id {map_id} \
         after {LSM_ATTACH_TIMEOUT:?}. Last lookup error: {last_err}"
    ))
}

/// Best-effort recursive removal of the pin root. See the module
/// "Destructive precondition" note.
fn purge_pin_root() {
    let _ = std::fs::remove_dir_all(DEFAULT_BPFFS_ROOT);
}

#[test]
#[ignore = "privileged: root + bpffs + BPF-LSM + bpftool + built eBPF \
            object; destructively purges DEFAULT_BPFFS_ROOT. Run \
            deliberately on the commit-#2 Hetzner verify box: \
            `cargo test --features test-privileged --test \
            privileged_map_pin -- --ignored`"]
fn protected_pids_kernel_id_is_stable_across_agent_restart() {
    let pin = protected_pids_pin();

    // Clean slate so a stale pin can't trivially satisfy the id
    // assertion against an unrelated kernel object.
    purge_pin_root();
    assert!(
        !pin.exists(),
        "pin {} still present after purge — refusing to run against \
         a dirty/locked bpffs (is a production agent holding it?)",
        pin.display()
    );

    // ---- Boot 1: first-ever load creates + pins the map. --------
    let dir1 = tempfile::tempdir().expect("tempdir boot1");
    let mut agent1 = spawn_agent(dir1.path());
    wait_for_pin(&pin);

    let id1 = pinned_map_id(&pin);
    wait_for_lsm_attach(id1).unwrap_or_else(|e| {
        panic!(
            "boot-1: no anti-tamper LSM hook is bound to the pinned \
             PROTECTED_PIDS id {id1} — relocation/binding broken.\n{e}"
        )
    });

    // ---- Stop boot 1; the pinned map must outlive the process. --
    agent1.stop();
    std::thread::sleep(POST_EXIT_SETTLE);
    assert!(
        pin.exists(),
        "pin {} vanished when the agent exited — map was NOT actually \
         pinned (the exact commit-#1 regression this fix targets)",
        pin.display()
    );

    // ---- Boot 2: must REUSE the pinned kernel object. -----------
    let dir2 = tempfile::tempdir().expect("tempdir boot2");
    let mut agent2 = spawn_agent(dir2.path());
    wait_for_pin(&pin);

    let id2 = pinned_map_id(&pin);
    assert_eq!(
        id1, id2,
        "PROTECTED_PIDS kernel id changed across restart ({id1} → \
         {id2}): the agent created a FRESH map instead of reusing the \
         pinned one — split brain NOT closed"
    );

    wait_for_lsm_attach(id2).unwrap_or_else(|e| {
        panic!(
            "boot-2: no anti-tamper LSM hook is bound to the reused \
             pinned id {id2} — restarted agent is split-brained off \
             its own protection map.\n{e}"
        )
    });

    agent2.stop();
    // Leave the pin in place: the verify protocol's subsequent
    // `bpftool map show` / kill-9 sanity checks expect it. A later
    // run's `purge_pin_root()` (or 2b teardown) reclaims it. The
    // tempdirs are held to here so the agents' paths stay valid.
    drop((dir1, dir2));
}
