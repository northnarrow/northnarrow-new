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
//! The in-kernel LSM hook is located by scanning loaded programs for
//! the one whose `map_ids` references the pinned `PROTECTED_PIDS`
//! object — *not* by program name (aya names programs after the
//! truncated Rust fn symbol, not the `#[lsm]` hook, so a name lookup
//! is brittle; see `find_lsm_prog_using_map`).
//!
//! ## Commit #2b extension
//!
//! #2b pins each of the seven LSM **programs** (`prog_<hook>`) and
//! their **links** (`link_<hook>`) so a restarted agent reuses the
//! prior boot's kernel objects instead of re-attaching. This test is
//! extended (not replaced) to assert the strengthened invariant: not
//! only the `PROTECTED_PIDS` map id but also the **set of LSM
//! program ids** and the **set of LSM link ids** are unchanged
//! across the restart, and the `prog_`/`link_` pin files survive the
//! agent's exit. Link ids are found by cross-referencing each link's
//! `prog <id>` against the LSM program id set — never by the link's
//! own type string, which the kernel reports as `tracing` for LSM
//! attachments (the same format-assumption trap the 2a name lookup
//! fell into). The behavioural gap proof (a sentinel PID protected
//! by the still-firing hook while no agent is alive) lives in the
//! #2b verification harness, not here.
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
/// The seven anti-tamper LSM hooks: `task_kill`,
/// `ptrace_access_check`, `inode_unlink`, `inode_rmdir`,
/// `inode_rename`, `inode_setattr`, `file_ioctl`. #2b pins one
/// program + one link per hook, so a fully-attached agent exposes
/// exactly this many `type lsm` programs and LSM-driving links.
const EXPECTED_LSM_HOOKS: usize = 7;

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

/// `bpftool link show` (every loaded BPF link, plain text). Same
/// no-`--json` / no-dev-dependency rationale as
/// [`bpftool_prog_show_all`].
fn bpftool_link_show_all() -> Result<String, String> {
    let out = Command::new("bpftool")
        .args(["link", "show"])
        .output()
        .map_err(|e| format!("spawn `bpftool link show`: {e} — is bpftool on PATH?"))?;
    if !out.status.success() {
        return Err(format!(
            "`bpftool link show` exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Sorted, de-duplicated kernel ids of every loaded `type lsm`
/// program. `bpftool prog show` reliably tags LSM *programs* `lsm`
/// (2a established this), so we lean on that rather than on program
/// names. With #2b prog-pinning these ids are stable across an agent
/// restart — the kernel object is reused via the `prog_<hook>` pin.
fn lsm_prog_ids() -> Vec<u64> {
    let Ok(text) = bpftool_prog_show_all() else {
        return Vec::new();
    };
    let mut ids: Vec<u64> = parse_progs(&text)
        .into_iter()
        .filter(|p| p.prog_type == "lsm")
        .map(|p| p.id)
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// Sorted, de-duplicated kernel ids of every BPF **link** that
/// drives one of the loaded LSM programs.
///
/// This deliberately does **not** filter on the link's own type
/// string: the kernel models an LSM attachment as a *tracing*-class
/// link (`BPF_LINK_TYPE_TRACING` + `attach_type lsm_mac`), so
/// `bpftool link show` prints `tracing`, not `lsm`, for these — the
/// exact format assumption that bit the 2a name lookup. Instead a
/// link is treated as an LSM-hook link iff its `prog <id>` is one of
/// [`lsm_prog_ids`]. With #2b link-pinning these link ids are stable
/// across restart (link object reused via `PinnedLink::from_pin`).
fn lsm_link_ids() -> Vec<u64> {
    let prog_ids: std::collections::HashSet<u64> = lsm_prog_ids().into_iter().collect();
    let Ok(text) = bpftool_link_show_all() else {
        return Vec::new();
    };
    let mut ids: Vec<u64> = Vec::new();
    for line in text.lines() {
        // `split_whitespace` already skips leading indentation.
        let toks: Vec<&str> = line.split_whitespace().collect();
        let Some(&first) = toks.first() else { continue };
        // Link record header: `<id>: <type> … prog <prog_id> …`.
        let Some(id_str) = first.strip_suffix(':') else {
            continue;
        };
        let Ok(link_id) = id_str.parse::<u64>() else {
            continue;
        };
        let prog_id = toks
            .iter()
            .position(|&t| t == "prog")
            .and_then(|i| toks.get(i + 1))
            .and_then(|s| s.parse::<u64>().ok());
        if prog_id.is_some_and(|pid| prog_ids.contains(&pid)) {
            ids.push(link_id);
        }
    }
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// Count pin files directly under [`DEFAULT_BPFFS_ROOT`] whose name
/// starts with `prefix` (`"prog_"` or `"link_"`). The 2b mechanism
/// creates one of each per hook; the six map pins carry no such
/// prefix, so this isolates exactly the #3/#4 pins.
fn count_pins(prefix: &str) -> usize {
    let Ok(dir) = std::fs::read_dir(DEFAULT_BPFFS_ROOT) else {
        return 0;
    };
    dir.filter_map(Result::ok)
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.starts_with(prefix))
        })
        .count()
}

/// 2b readiness gate. Strengthens the 2a "≥1 LSM prog bound to the
/// pinned map" gate with the condition the extended invariant needs:
/// that gate **and** all seven LSM programs **and** all seven
/// LSM-driving links visible, so the cross-boot id-set snapshot is
/// complete and apples-to-apples. Closes the race where the
/// `PROTECTED_PIDS` pin appears at map-create time
/// (`Ebpf::load_from_bytes`) but the per-hook `load()`/`attach()`/
/// `pin()` calls have not all completed yet. Same deadline/poll
/// shape as [`wait_for_pin`].
fn wait_for_full_lsm_attach(map_id: u64) -> Result<(), String> {
    let deadline = Instant::now() + LSM_ATTACH_TIMEOUT;
    let mut last = String::new();
    while Instant::now() < deadline {
        match find_lsm_prog_using_map(map_id) {
            Ok(_) => {
                let np = lsm_prog_ids().len();
                let nl = lsm_link_ids().len();
                if np >= EXPECTED_LSM_HOOKS && nl >= EXPECTED_LSM_HOOKS {
                    return Ok(());
                }
                last = format!(
                    "bound OK but only {np}/{EXPECTED_LSM_HOOKS} LSM progs \
                     and {nl}/{EXPECTED_LSM_HOOKS} LSM links visible"
                );
            }
            Err(e) => last = e,
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    Err(format!(
        "timeout after {LSM_ATTACH_TIMEOUT:?} waiting for full LSM attach \
         (map_id {map_id}). Last state: {last}"
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

    // ---- Boot 1: fresh load pins map + 7 progs + 7 links. -------
    let dir1 = tempfile::tempdir().expect("tempdir boot1");
    let mut agent1 = spawn_agent(dir1.path());
    wait_for_pin(&pin);

    let id1 = pinned_map_id(&pin);
    wait_for_full_lsm_attach(id1).unwrap_or_else(|e| {
        panic!(
            "boot-1: full LSM attach never reached for pinned \
             PROTECTED_PIDS id {id1} — relocation/binding broken.\n{e}"
        )
    });

    // 2b: snapshot the kernel object id sets while boot-1 is live.
    let prog_ids1 = lsm_prog_ids();
    let link_ids1 = lsm_link_ids();
    assert!(
        prog_ids1.len() >= EXPECTED_LSM_HOOKS,
        "boot-1: {} LSM programs visible, expected ≥{EXPECTED_LSM_HOOKS}: {prog_ids1:?}",
        prog_ids1.len()
    );
    assert!(
        link_ids1.len() >= EXPECTED_LSM_HOOKS,
        "boot-1: {} LSM links visible, expected ≥{EXPECTED_LSM_HOOKS}: {link_ids1:?}",
        link_ids1.len()
    );
    let (p1, l1) = (count_pins("prog_"), count_pins("link_"));
    assert!(
        p1 >= EXPECTED_LSM_HOOKS && l1 >= EXPECTED_LSM_HOOKS,
        "boot-1: expected ≥{EXPECTED_LSM_HOOKS} prog_ and ≥{EXPECTED_LSM_HOOKS} link_ \
         pins under {DEFAULT_BPFFS_ROOT}, found prog_={p1} link_={l1}"
    );

    // ---- Stop boot 1; map + prog + link pins must outlive it. ---
    agent1.stop();
    std::thread::sleep(POST_EXIT_SETTLE);
    assert!(
        pin.exists(),
        "pin {} vanished when the agent exited — map was NOT actually \
         pinned (the exact commit-#1 regression this fix targets)",
        pin.display()
    );
    let (p_after, l_after) = (count_pins("prog_"), count_pins("link_"));
    assert!(
        p_after >= EXPECTED_LSM_HOOKS && l_after >= EXPECTED_LSM_HOOKS,
        "prog_/link_ pins vanished when boot-1 exited (prog_={p_after} \
         link_={l_after}) — links were NOT actually pinned; the hook \
         would stop firing across the respawn gap (the #2b regression \
         this guards)"
    );

    // ---- Boot 2: must REUSE the pinned kernel objects. ----------
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

    wait_for_full_lsm_attach(id2).unwrap_or_else(|e| {
        panic!(
            "boot-2: full LSM attach never reached for reused pinned id \
             {id2} — restarted agent is split-brained off its own \
             protection map.\n{e}"
        )
    });

    // 2b core invariant: pinned ⇒ the SAME kernel program and link
    // objects are reused, not freshly created. Equal id *sets* ⇒
    // every hook's prog and link survived the death→respawn gap.
    let prog_ids2 = lsm_prog_ids();
    let link_ids2 = lsm_link_ids();
    assert_eq!(
        prog_ids1, prog_ids2,
        "LSM program id set changed across restart ({prog_ids1:?} → \
         {prog_ids2:?}): programs were re-created, not reused via the \
         prog_<hook> pin — #2b program pinning broken"
    );
    assert_eq!(
        link_ids1, link_ids2,
        "LSM link id set changed across restart ({link_ids1:?} → \
         {link_ids2:?}): links were re-created, not reused via the \
         link_<hook> pin / PinnedLink::from_pin — the hook stopped \
         firing across the gap; #2b link pinning broken"
    );

    agent2.stop();
    // Leave the pins in place: the verify protocol's subsequent
    // `bpftool` / sentinel kill-9 sanity checks expect them. A later
    // run's `purge_pin_root()` (or 2b teardown) reclaims them. The
    // tempdirs are held to here so the agents' paths stay valid.
    drop((dir1, dir2));
}
