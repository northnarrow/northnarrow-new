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
//! The in-kernel LSM hooks are found through the agent's pins
//! (`prog_<hook>`, named after the `#[lsm]` hook) — *not* by program
//! name (aya names programs after the truncated Rust fn symbol, so a
//! name lookup is brittle) — and a hook is bound when its pinned
//! program's `map_ids` holds the pinned `PROTECTED_PIDS` id.
//!
//! ## Commit #2b extension
//!
//! #2b pins each anti-tamper LSM **program** (`prog_<hook>`) and its
//! **link** (`link_<hook>`). The deny hooks are re-attached FRESH every
//! boot since BUG-024 and review 62 (a reused link kept producing into
//! the previous boot's ring); the `PROTECTED_PIDS` map is the object a
//! restart must reuse.
//!
//! External audit NN-AUD-230 (TST-009): this used to count every LSM
//! program and link on the HOST against `>= 7`, while the agent attaches
//! nine deny hooks. Any seven LSM programs passed, a missing deny hook
//! did not fail the test. It now reads the agent's own objects through
//! its pins: for every hook of `anti_tamper::DENY_HOOKS`, `prog_<hook>`
//! is an LSM program and `link_<hook>` is pinned (the agent's guard refuses
//! a foreign handle on its links, so they are not opened); task_kill and
//! ptrace are bound to the pinned `PROTECTED_PIDS`; the agent logged
//! every deny hook attached (`deny_attached=N deny_expected=N`, N = the
//! sixteen of `DENY_HOOKS` plus the optional ACL hooks the kernel has).
//! The pins outlive boot 1 with the same objects behind them, and after
//! the restart every deny hook has a fresh program. The behavioural gap
//! proof (a sentinel PID protected by the still-firing hook while no
//! agent is alive) lived in the #2b verification harness,
//! `docs/verify-2b.sh`, retired because its normal stop was the
//! PROTECTED_PIDS eviction (external audit LAB-001); it is not
//! re-implemented yet.
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

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use northnarrow_agent::anti_tamper::{
    lsm_pin_paths, DEFAULT_BPFFS_ROOT, DENY_HOOKS, OPTIONAL_DENY_HOOKS,
};

mod common;

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
/// The deny hooks that read `PROTECTED_PIDS` directly: their pinned
/// programs must reference the pinned map's id.
const PID_HOOKS: [&str; 2] = ["task_kill", "ptrace_access_check"];

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

/// RAII guard: stops the agent on drop so a failed assertion never
/// leaks a daemon (`stop_agent`: eviction from PROTECTED_PIDS, then
/// SIGQUIT; the `task_kill` hook refuses every signal from the test
/// runner while the pid is protected).
struct AgentGuard(Option<Child>);

/// How long `stop()` waits for the agent to exit before failing the
/// test. Before this bound the test hung for hours on the lab guest
/// when the signal was denied (see `stop_agent`).
const AGENT_EXIT_TIMEOUT: Duration = Duration::from_secs(20);

impl AgentGuard {
    /// Stop the agent and block until it has actually exited.
    fn stop(&mut self) {
        if let Some(c) = self.0.take() {
            stop_agent(c);
        }
    }
}

impl Drop for AgentGuard {
    fn drop(&mut self) {
        if let Some(c) = self.0.take() {
            stop_agent(c);
        }
    }
}

/// Evict the agent (and any children) from PROTECTED_PIDS, SIGQUIT it
/// and wait — bounded. task-kill-signals-1 made the `task_kill` hook
/// deny EVERY userspace signal towards a protected pid, SIGQUIT
/// included, so a bare `kill -QUIT` from the (unprotected) test runner
/// is refused with EPERM and the old unbounded `wait()` never returned:
/// the first nightly after that change sat in this test for 6 h. Same
/// recipe as the other fixtures (`common::try_quit_agent`); an agent
/// that survives it fails the test, from `Drop` too unless the test is
/// already failing (external audit TST-010).
fn stop_agent(mut c: Child) {
    if let Err(msg) = common::try_quit_agent(&mut c, AGENT_EXIT_TIMEOUT) {
        common::fail_teardown(&msg);
    }
}

/// Spawn the real agent against per-test tempdir paths. Mirrors
/// `privileged_e2e::spawn_agent`'s flag set; `--no-ade` keeps the
/// model/inference path out of a test that only exercises eBPF load.
/// Its log goes to `<tempdir>/agent.log`, uncoloured, for the attach line.
fn spawn_agent(tempdir: &Path) -> AgentGuard {
    let rules = tempdir.join("combat-rules.v4");
    std::fs::copy(combat_rules_path(), &rules).expect("copy combat rules into tempdir");
    let log = std::fs::File::create(agent_log(tempdir)).expect("create agent.log");
    let log_err = log.try_clone().expect("clone the log handle");

    common::require_bpftool();
    let child = Command::new(env!("CARGO_BIN_EXE_northnarrow-agent"))
        .arg("--combat-rules")
        .arg(&rules)
        .arg("--admin-pub")
        .arg(tempdir.join("admin.pub"))
        .arg("--admin-socket")
        .arg(tempdir.join("admin.sock"))
        .arg("--no-ade")
        .env("NO_COLOR", "1")
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err))
        .spawn()
        .expect("spawn northnarrow-agent");
    AgentGuard(Some(child))
}

fn agent_log(tempdir: &Path) -> PathBuf {
    tempdir.join("agent.log")
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
/// reasons about. No name: aya names a program after the truncated Rust
/// symbol, so the pins, named after the hook, are what identifies it.
#[derive(Debug)]
struct ProgInfo {
    id: u64,
    prog_type: String,
    map_ids: Vec<u64>,
}

/// `bpftool <kind> show pinned <pin>` (plain text). We do **not** pass
/// `--json`: the plain-text record grammar is stable and trivially
/// block-parseable.
fn show_pinned(kind: &str, pin: &Path) -> Result<String, String> {
    let out = Command::new("bpftool")
        .args([kind, "show", "pinned"])
        .arg(pin)
        .output()
        .map_err(|e| format!("spawn `bpftool {kind} show`: {e} — is bpftool on PATH?"))?;
    if !out.status.success() {
        return Err(format!(
            "`bpftool {kind} show pinned {}` exited {}: {}",
            pin.display(),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Block-parse `bpftool prog show` plain text. A record starts at a
/// line whose first token is `<id>:`; its `prog_type` is the next
/// token; continuation lines (anything until the next header) may
/// carry a `map_ids a,b,c` token.
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
                cur = Some(ProgInfo {
                    id,
                    prog_type,
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

/// `(link id, program id)` from `bpftool link show` plain text: the
/// header `<id>: <type>  prog <prog_id>`. The kernel models an LSM
/// attachment as a tracing link, so the type is not checked.
fn parse_link_header(text: &str) -> Option<(u64, u64)> {
    let line = text.lines().find(|l| !l.trim().is_empty())?;
    let toks: Vec<&str> = line.split_whitespace().collect();
    let link = toks.first()?.strip_suffix(':')?.parse().ok()?;
    let prog = toks
        .iter()
        .position(|&t| t == "prog")
        .and_then(|i| toks.get(i + 1))
        .and_then(|s| s.parse().ok())?;
    Some((link, prog))
}

/// One deny hook's pinned kernel objects.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HookPins {
    prog: u64,
    map_ids: Vec<u64>,
}

/// The pinned objects of every [`DENY_HOOKS`] entry under the pin root:
/// `prog_<hook>` is an LSM program and `link_<hook>` is pinned beside it. `Err` names each hook that falls short (pin missing, wrong
/// program type, link bound to another program). Only the agent's own
/// pins are read: other LSM programs on the host do not count.
fn deny_hook_pins() -> Result<BTreeMap<&'static str, HookPins>, String> {
    let root = Path::new(DEFAULT_BPFFS_ROOT);
    let mut pins = BTreeMap::new();
    let mut errors = Vec::new();
    for hook in DENY_HOOKS {
        let (prog_pin, link_pin) = lsm_pin_paths(root, hook);
        let prog = match show_pinned("prog", &prog_pin).and_then(|t| {
            parse_progs(&t)
                .into_iter()
                .next()
                .ok_or_else(|| format!("no program parsed from {t:?}"))
        }) {
            Ok(p) => p,
            Err(e) => {
                errors.push(format!("{hook}: prog_{hook}: {e}"));
                continue;
            }
        };
        if prog.prog_type != "lsm" {
            errors.push(format!(
                "{hook}: prog_{hook} is {prog:?}, not an LSM program"
            ));
            continue;
        }
        // The link pin is checked by its presence only: the agent's BPF
        // guard refuses a foreign handle on its pinned links (that refusal
        // is the protection), so `bpftool link show pinned` cannot open it
        // while the hooks are attached. The attach line in the agent's log
        // (`deny_attached=N`) attests the links.
        if std::fs::symlink_metadata(&link_pin).is_err() {
            errors.push(format!("{hook}: link_{hook} is not pinned"));
            continue;
        }
        pins.insert(
            hook,
            HookPins {
                prog: prog.id,
                map_ids: prog.map_ids,
            },
        );
    }
    if errors.is_empty() {
        Ok(pins)
    } else {
        Err(errors.join("; "))
    }
}

/// The names under the pin root, for failure messages.
fn pin_listing() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(DEFAULT_BPFFS_ROOT)
        .map(|d| {
            d.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

/// The agent's attach-health line with every deny hook attached: the
/// `deny_attached=N deny_expected=N` fields release-check.sh reads, in
/// "all LSM hooks attached" or in the observe-hook shortfall line (the
/// module-load observe hooks are not this test's subject).
fn logged_all_deny_hooks(log: &str) -> bool {
    let wants: Vec<String> = (DENY_HOOKS.len()..=DENY_HOOKS.len() + OPTIONAL_DENY_HOOKS.len())
        .map(|n| format!("deny_attached={n} deny_expected={n}"))
        .collect();
    log.lines()
        .any(|l| l.contains("anti-tamper:") && wants.iter().any(|w| l.contains(w.as_str())))
}

/// The last lines of an agent log, ANSI-stripped, for failure messages.
fn log_tail(log: &Path) -> String {
    let text = common::strip_ansi(&std::fs::read_to_string(log).unwrap_or_default());
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(25)..].join("\n")
}

/// Readiness gate: the agent logged every deny hook attached, each deny
/// hook has its pins ([`deny_hook_pins`]), task_kill and ptrace are bound
/// to the pinned `PROTECTED_PIDS` (`map_id`), and — after a restart,
/// `previous` given — every deny hook runs a program other than the
/// previous boot's (re-attached fresh, BUG-024 / review 62). Until boot 2
/// re-attaches, boot 1's pins still satisfy the rest, hence the poll.
fn wait_for_deny_hooks(
    map_id: u64,
    log: &Path,
    previous: Option<&BTreeMap<&'static str, HookPins>>,
) -> Result<BTreeMap<&'static str, HookPins>, String> {
    let deadline = Instant::now() + LSM_ATTACH_TIMEOUT;
    let mut last;
    loop {
        let text = common::strip_ansi(&std::fs::read_to_string(log).unwrap_or_default());
        last = match deny_hook_pins() {
            Err(e) => e,
            Ok(_) if !logged_all_deny_hooks(&text) => format!(
                "no `deny_attached={n} deny_expected={n}` line in the agent log",
                n = DENY_HOOKS.len()
            ),
            Ok(pins) => {
                let unbound: Vec<&str> = PID_HOOKS
                    .iter()
                    .copied()
                    .filter(|h| !pins[h].map_ids.contains(&map_id))
                    .collect();
                let reused: Vec<&str> = previous
                    .map(|prev| {
                        DENY_HOOKS
                            .iter()
                            .copied()
                            .filter(|h| pins[h].prog == prev[h].prog)
                            .collect()
                    })
                    .unwrap_or_default();
                if unbound.is_empty() && reused.is_empty() {
                    return Ok(pins);
                }
                format!(
                    "not bound to PROTECTED_PIDS id {map_id}: {unbound:?}; still the previous \
                     boot's program (a reused link produces into the previous boot's ring, \
                     review 62): {reused:?}; pins: {pins:?}"
                )
            }
        };
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    Err(format!(
        "after {LSM_ATTACH_TIMEOUT:?}: {last}\n--- pins under {DEFAULT_BPFFS_ROOT} ---\n{:?}\n\
         --- agent log (tail) ---\n{}",
        pin_listing(),
        log_tail(log)
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

    // ---- Boot 1: fresh load pins the map and every deny hook. ----
    let dir1 = tempfile::tempdir().expect("tempdir boot1");
    let mut agent1 = spawn_agent(dir1.path());
    wait_for_pin(&pin);

    let id1 = pinned_map_id(&pin);
    let boot1 = wait_for_deny_hooks(id1, &agent_log(dir1.path()), None)
        .unwrap_or_else(|e| panic!("boot-1: the deny hooks are not all attached and pinned.\n{e}"));

    // ---- Stop boot 1; the pins and the objects behind them stay. ----
    agent1.stop();
    std::thread::sleep(POST_EXIT_SETTLE);
    assert!(
        pin.exists(),
        "pin {} vanished when the agent exited — map was NOT actually \
         pinned (the exact commit-#1 regression this fix targets)",
        pin.display()
    );
    let after_exit = deny_hook_pins();
    assert_eq!(
        after_exit.as_ref(),
        Ok(&boot1),
        "the deny hooks' pins did not outlive boot 1 with the same objects behind them; \
         the hooks would stop firing across the respawn gap (the #2b regression this \
         guards). Pins: {:?}",
        pin_listing()
    );

    // ---- Boot 2: must REUSE the pinned map, re-attach every hook. ----
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

    wait_for_deny_hooks(id2, &agent_log(dir2.path()), Some(&boot1)).unwrap_or_else(|e| {
        panic!(
            "boot-2: the deny hooks are not all re-attached fresh, pinned and bound to the \
             reused PROTECTED_PIDS id {id2}.\n{e}"
        )
    });

    agent2.stop();
    // Leave the pins in place: the verify protocol's subsequent
    // `bpftool` sanity checks expect them. A later run's
    // `purge_pin_root()` reclaims them. The tempdirs are held to here so
    // the agents' paths stay valid.
    drop((dir1, dir2));
}

/// The parsers against `bpftool` 7.x plain-text output (no privilege
/// needed; runs without `--ignored`).
#[test]
fn bpftool_pinned_output_parses() {
    let prog = "\
42: lsm  name task_kill  tag 0123456789abcdef  gpl
\tloaded_at 2026-10-15T10:00:00+0000  uid 0
\txlated 1024B  jited 640B  memlock 4096B  map_ids 7,9,12
\tbtf_id 88
\tpids northnarrow-age(1234)
";
    let p = parse_progs(prog);
    assert_eq!(p.len(), 1);
    assert_eq!((p[0].id, p[0].prog_type.as_str()), (42, "lsm"));
    assert_eq!(p[0].map_ids, vec![7, 9, 12]);
    let link = "\
5: tracing  prog 42
\tprog_type lsm  attach_type lsm_mac
\ttarget_obj_id 1  target_btf_id 120345
";
    assert_eq!(parse_link_header(link), Some((5, 42)));
    assert_eq!(parse_link_header("Error: bpf obj get: No such file"), None);
}

#[test]
fn the_attach_line_must_count_every_deny_hook() {
    let n = DENY_HOOKS.len();
    let ok = format!(
        "2026-10-15T10:00:00Z  INFO anti-tamper: all LSM hooks attached deny_attached={n} \
         deny_expected={n}"
    );
    assert!(logged_all_deny_hooks(&ok));
    let observe = format!(
        "WARN anti-tamper: OBSERVE HOOK SHORTFALL — module-load telemetry absent (R018 blind) \
         deny_attached={n} deny_expected={n} observe_failed=[\"x\"]"
    );
    assert!(logged_all_deny_hooks(&observe));
    let short = format!(
        "ERROR anti-tamper: DENY HOOK SHORTFALL deny_attached={} deny_expected={n}",
        n - 1
    );
    assert!(!logged_all_deny_hooks(&short));
    assert_eq!(n, 16, "sixteen deny hooks on every supported kernel");
    let acl = DENY_HOOKS.len() + OPTIONAL_DENY_HOOKS.len();
    assert!(logged_all_deny_hooks(&format!(
        "INFO anti-tamper: all LSM hooks attached deny_attached={acl} deny_expected={acl}"
    )));
}
