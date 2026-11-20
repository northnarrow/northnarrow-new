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
    let gate = wd
        .find("let host = judge_host().await;\n                if let Some(why) = &host.hold {")
        .expect("the gate before the respawn");
    let held = wd[gate..]
        .find("REASON_RESPAWN_HELD")
        .map(|i| i + gate)
        .expect("held");
    let respawn = wd.find("r = respawn_cycle(").expect("the respawn");
    assert!(
        gate < held && held < respawn,
        "judged and held before the respawn"
    );
    let retry = wd.find("fn hold_supervision(").expect("the hold's retries");
    let r = &wd[retry..];
    let judged = r
        .find("let host = judge_host().await;")
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
/// process when the kernel marked that role vacated earlier this boot.
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
    let f = &wd[wd.find("fn judge_agent_at_start(").unwrap()..];
    assert!(
        f.contains("antitamper_bpf::role_marks(&cli.bpffs_root, antitamper_bpf::ROLE_SLOT_AGENT)")
    );
    assert!(f.contains("Ok(m) if m & antitamper_bpf::ROLE_MARK_VACATED != 0 => {"));
    let tasks = &code["agent/src/boot/tasks.rs"];
    let t = tasks
        .find("let mut succession_pending = bpffs_root")
        .expect("the agent's start");
    let rest = &tasks[t..];
    assert!(rest.contains("antitamper_bpf::role_marks(r, antitamper_bpf::ROLE_SLOT_WATCHDOG)"));
    assert!(rest[..300].contains("ROLE_MARK_VACATED != 0"));
}
