//! Lot 374: a start of the agent or the watchdog runs with nothing given to
//! it before its `main` — the units and every transient unit the product
//! starts unset the loader's and the C library's variables, and each start
//! checks its own environment and mappings before it takes its role.
//!
//! * The libraries a start may map are the release gate's
//!   (`deploy/release/glibc-baseline.sh`, `ALLOWED_LIBS`): one list.
//! * Every `systemd-run` the product runs passes
//!   `start_check::systemd_run_unset()` (the units' `UnsetEnvironment=`).
//! * The two daemons check themselves first: the watchdog before it
//!   registers its pid, the agent's preflight refuses before its gates.

mod support;

use std::fs;

use support::{product_code, repo_root};

/// The string literals between `start` and the next `end` in `text`.
fn literals_between(text: &str, start: &str, end: &str) -> Vec<String> {
    let at = text
        .find(start)
        .unwrap_or_else(|| panic!("{start} not found"));
    let body = &text[at + start.len()..];
    let body = &body[..body.find(end).unwrap_or_else(|| panic!("{end} not found"))];
    body.split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect()
}

#[test]
fn a_start_maps_only_the_libraries_the_release_gate_allows() {
    let root = repo_root();
    let rs = fs::read_to_string(root.join("antitamper-bpf/src/start_check.rs")).unwrap();
    let mut expected = literals_between(&rs, "pub const EXPECTED_LIBS: &[&str] = &[", "];");
    let sh = fs::read_to_string(root.join("deploy/release/glibc-baseline.sh")).unwrap();
    let line = sh
        .lines()
        .find(|l| l.starts_with("ALLOWED_LIBS=("))
        .expect("ALLOWED_LIBS");
    let mut allowed: Vec<String> = line
        .trim_start_matches("ALLOWED_LIBS=(")
        .trim_end_matches(')')
        .split_whitespace()
        .map(str::to_string)
        .collect();
    assert!(!expected.is_empty());
    expected.sort();
    allowed.sort();
    assert_eq!(
        expected, allowed,
        "start_check::EXPECTED_LIBS is not the release gate's ALLOWED_LIBS"
    );
}

#[test]
fn every_transient_unit_the_product_starts_unsets_the_loader_variables() {
    let root = repo_root();
    let mut starters = Vec::new();
    let mut bad = Vec::new();
    for (rel, code) in product_code(&root) {
        if !code.contains("\"systemd-run\"") {
            continue;
        }
        starters.push(rel.clone());
        let runs = code.matches("\"systemd-run\"").count();
        let unsets = code.matches("start_check::systemd_run_unset()").count();
        if unsets < runs {
            bad.push(format!(
                "{rel}: {runs} systemd-run, {unsets} systemd_run_unset()"
            ));
        }
    }
    assert!(
        bad.is_empty(),
        "a transient unit started without the units' UnsetEnvironment=:\n{}",
        bad.join("\n")
    );
    assert!(
        starters
            .iter()
            .any(|f| f == "crates/nn-linux/src/anti_tamper/pin_lock.rs"),
        "the scan sees the pin lock's transient unit: {starters:?}"
    );
}

#[test]
fn both_daemons_check_themselves_before_they_take_their_role() {
    let root = repo_root();
    let code = product_code(&root);
    let wd = &code["watchdog/src/main.rs"];
    let check = wd
        .find("start_check::check_self()")
        .expect("the watchdog's check");
    let refuse = wd[check..]
        .find("return refuse_start(")
        .map(|i| i + check)
        .expect("refused");
    let register = wd.find("register_self_pid(").expect("register");
    let oom = wd.find("pin_oom_score_adj()").expect("the OOM pin");
    assert!(
        check < refuse && refuse < register && refuse < oom,
        "the watchdog checks itself first"
    );
    let main = &code["agent/src/boot/mod.rs"];
    let check = main
        .find("start_check::check_self()")
        .expect("the agent's check");
    let runtime = main.find("tokio::runtime::Builder").unwrap_or(usize::MAX);
    assert!(
        check < runtime,
        "the agent checks itself before its runtime starts"
    );
    let pre = &code["agent/src/boot/preflight.rs"];
    let refusal = pre
        .find("self_check_refusal(self_check)")
        .expect("the preflight refuses on it");
    let first_gate = pre.find("checks::ebpf_object(").expect("first gate");
    assert!(refusal < first_gate, "refused before the other gates");
    assert!(pre.contains("Refusal::new(SELF_CHECK_GATE, why)"));
    // the two daemons and nothing else check themselves
    let callers: Vec<&String> = code
        .iter()
        .filter(|(_, c)| c.contains("start_check::check_self()"))
        .map(|(f, _)| f)
        .collect();
    assert_eq!(
        callers,
        ["agent/src/boot/mod.rs", "watchdog/src/main.rs"],
        "{callers:?}"
    );
}

/// The review of #582 (F2 d): every start of the agent the watchdog makes —
/// the respawn after a vacancy and a hold's retry, its only two — is
/// preceded by the host's judgement, and held (or skipped) on its verdict.
#[test]
fn every_start_the_watchdog_makes_is_judged_first() {
    let root = repo_root();
    let code = product_code(&root);
    let wd = &code["watchdog/src/main.rs"];
    assert_eq!(
        wd.matches("respawn_cycle(").count(),
        2,
        "one call and its definition"
    );
    assert_eq!(
        wd.matches("respawn_agent_off_runtime(").count(),
        2,
        "respawn_cycle's and the retry's"
    );
    assert_eq!(
        code["watchdog/src/lib.rs"]
            .matches("respawn_agent_off_runtime(")
            .count(),
        1,
        "its definition, and no other start"
    );
    // the re-check of #582 (N2, N3): judged with the window's state, the
    // judgement's end kept for the successor
    let gate = wd
        .find("let (host, adopted, judged_in_window) = judge_host(&cli.bpffs_root).await;")
        .expect("the gate before the respawn");
    let hold_at = wd[gate..]
        .find("if let Some(why) = &host.hold {")
        .map(|i| i + gate)
        .expect("its verdict");
    assert!(
        wd[gate..hold_at].contains("let judged_at = antitamper_bpf::start_check::boot_ns_now();")
    );
    let held = wd[gate..]
        .find("REASON_RESPAWN_HELD")
        .map(|i| i + gate)
        .expect("held");
    let respawn = wd.find("r = respawn_cycle(").expect("the respawn");
    assert!(
        gate < held && held < respawn,
        "judged and held before the respawn"
    );
    assert!(wd[respawn..].contains("(!judged_in_window).then_some(judged_at),"));
    let retry = wd.find("fn hold_supervision(").expect("the hold's retries");
    let r = &wd[retry..];
    let judged = r
        .find("northnarrow_watchdog::respawn_gate::judge_now_keeping(in_window)")
        .expect("the retry judged");
    let skipped = r
        .find("if let Some(why) = host.hold {")
        .expect("skipped on a change");
    let start = r
        .find("} else if let Err(e) = respawn_agent_off_runtime(backend).await {")
        .expect("started only otherwise");
    assert!(judged < skipped && skipped < start);
}

/// The review of #582 (F6): each role's start judges the other role's
/// process when the kernel marked that role vacated earlier this boot —
/// and (the re-check 3, R2-1) at every start, the timing rule deciding only
/// whether a given verdict is recorded.
#[test]
fn each_role_s_start_judges_the_other_after_a_vacancy_this_boot() {
    let root = repo_root();
    let code = product_code(&root);
    let wd = &code["watchdog/src/main.rs"];
    let found = wd
        .find("open_agent_pidfd_with_retry(&cli.agent_pidfile")
        .expect("the agent found");
    let judged = wd
        .find("judge_agent_at_start(&cli, &mut witness, agent_pid);")
        .expect("judged");
    assert!(found < judged);
    // the re-check of #582 (N4, N5): judged once — only a process that took
    // its role while this role was vacant (the kernel's exit time), what is
    // not read judged and recorded
    let f = &wd[wd.find("fn judge_agent_at_start(").unwrap()..];
    let f = &f[..f.find("\n}\n").unwrap()];
    for needle in [
        "role_marks(root, ROLE_SLOT_AGENT)",
        "role_exit_ns(root, ROLE_SLOT_WATCHDOG)",
        "antitamper_bpf::succession_to_judge(",
        "antitamper_bpf::start_check::start_boot_ns(pid)",
        "pin_handle_failed(",
        "antitamper_bpf::at_start(why.is_some(), judged.given)",
    ] {
        assert!(f.contains(needle), "{needle}");
    }
    // the re-check 3 of #582 (R2-1): judged whatever the timing rule says —
    // its "no succession" skips the record of a given verdict only
    let judged = f.find("judge_successor(0, pid)").expect("judged");
    assert!(judged < f.find("antitamper_bpf::at_start(").unwrap());
    assert!(
        !f[..judged].contains("return"),
        "a return before the judgement"
    );
    let tasks = &code["agent/src/boot/tasks.rs"];
    let t = tasks
        .find("let at_start = nn_linux::witness::roles_at_start();")
        .expect("the agent's start");
    let rest = &tasks[t..];
    let first = rest
        .find("let found_first = std::mem::take(&mut first_found);")
        .expect("the watchdog found first");
    let rest = &rest[first..];
    for needle in [
        "ROLE_MARKS_DEGRADATION",
        "antitamper_bpf::succession_to_judge(",
        "antitamper_bpf::start_check::start_boot_ns(p)",
        "succession_pending = true;",
    ] {
        assert!(rest[..1500].contains(needle), "{needle}");
    }
    // the re-check 3 (R2-1): the one judgement of the watchdog is
    // `successor_step`'s, told the watchdog found first — never skipped by
    // the timing rule — and a refusal returns before any registration
    let step = rest
        .find("nn_linux::witness::successor_step(")
        .expect("successor_step");
    assert!(rest[step..step + 200].contains("found_first,"));
    assert_eq!(
        tasks
            .matches("nn_linux::witness::judge_watchdog_successor(")
            .count(),
        1
    );
    let judge = rest
        .find("nn_linux::witness::judge_watchdog_successor(")
        .unwrap();
    let foreign = rest
        .find("nn_linux::witness::SuccessorStep::Foreign(v) => {")
        .expect("the refusal");
    let register = rest
        .find("anti_tamper::register_protected_pid(bpffs_root, p)")
        .expect("the registration");
    assert!(step < judge && judge < foreign && foreign < register);
    assert!(
        rest[foreign..register].contains("last = None;")
            && rest[foreign..register].contains("return;")
    );
    // the rule itself is antitamper_bpf's, one for both roles
    let lib = &code["antitamper-bpf/src/lib.rs"];
    assert_eq!(lib.matches("pub fn succession_to_judge(").count(), 1);
    assert_eq!(lib.matches("pub fn at_start(").count(), 1);
    let w = &code["crates/nn-linux/src/witness.rs"];
    let s = &w[w.find("pub fn successor_step(").expect("successor_step")..];
    assert!(s[..s.find("\n}\n").unwrap()].contains("antitamper_bpf::at_start("));
}

/// The re-check of #582 (N0, N2, N3, N8): where the new rules are wired —
/// the agent's start reads `MemoryDenyWriteExecute` from systemd's copy;
/// the gate's reference moves only inside a signed window; a successor
/// that started before the gate's judgement is not given the role and is
/// recorded as a start the watchdog did not make; a vacancy's window is the
/// kernel's mark of the exit.
#[test]
fn the_re_check_s_rules_are_wired_where_they_hold() {
    let root = repo_root();
    let code = product_code(&root);
    let boot = &code["agent/src/boot/mod.rs"];
    let init = boot
        .find("antitamper_bpf::kernel_roots::init()")
        .expect("the kernel's views anchored");
    let mdwe = boot
        .find("nn_linux::host_dropins::note_units_mdwe();")
        .expect("the units' MDWE read at the start");
    let runtime = boot.find("tokio::runtime::Builder").expect("the runtime");
    assert!(init < mdwe && mdwe < runtime);
    let gate = &code["watchdog/src/respawn_gate.rs"];
    let j = &gate[gate.find("pub fn judge_now(").unwrap()..];
    assert!(j[..400].contains("let adopted = if in_window { adopt(&host) } else { None };"));
    let k = &gate[gate.find("pub fn judge_now_keeping(").unwrap()..];
    assert!(
        !k[..300].contains("adopt("),
        "the retry never moves the reference"
    );
    let wd = &code["watchdog/src/main.rs"];
    let a = &wd[wd.find("async fn adopt_in_window(").unwrap()..];
    let a = &a[..a.find("\n}\n").unwrap()];
    let open = a
        .find("window_open(&cli.bpffs_root)")
        .expect("the window asked");
    let back = a.find("return;").expect("outside one, nothing");
    let adopt = a.find("adopt_now").expect("inside one, adopted");
    assert!(open < back && back < adopt);
    let c = &wd[wd.find("async fn respawn_cycle(").unwrap()..];
    let c = &c[..c.find("\n}\n").unwrap()];
    assert!(c.contains("antitamper_bpf::start_check::started_before("));
    assert!(c.contains("let given = judged.given && !judged.unmade;"));
    assert!(wd.contains("nn_proto::witness::KIND_UNMADE_START,"));
    assert!(wd.contains("let in_window = exit_in_window(&cli.bpffs_root);"));
    let e = &wd[wd.find("fn exit_in_window(").unwrap()..];
    assert!(e[..400].contains("ROLE_SLOT_AGENT") && e[..400].contains("ROLE_MARK_IN_WINDOW"));
}
