//! Lot 388 (the triage of #595, a): the watchdog's death (`watchdog_gone`,
//! held until acknowledged since lot 379) has one writer,
//! `nn_linux::self_integrity::watchdog_exit_finding`, which tells the
//! host's or the operator's stop from a death: a clean stop of the watchdog
//! in the host's shutdown (`systemd-shutdown` signals the agent and the
//! watchdog at once), inside a signed trusted-installer window or during the
//! agent's own stop is a note (`watchdog_stopped`). The agent's round signed
//! the death directly, and a normal reboot left `nn-admin status` DEGRADED
//! now and then. A second writer of the kind would bring that back: this
//! scan fails on one, and the rule is shown failing on a planted writer.

mod support;

use std::collections::BTreeMap;

use support::{product_code, repo_root, string_literals};

/// The death's kind.
const KIND: &str = "watchdog_gone";

/// Its one writer's file.
const HOME: &str = "crates/nn-linux/src/self_integrity.rs";

/// The file that classifies the kinds (`DEATH_KINDS`): no writer.
const TABLE: &str = "crates/nn-evidence/src/held.rs";

/// The production files (comments and tests blanked) that write the kind as
/// a string literal, the classification table left out.
fn writers(code: &BTreeMap<String, String>) -> Vec<String> {
    code.iter()
        .filter(|(rel, _)| rel.as_str() != TABLE)
        .filter(|(_, text)| string_literals(text).iter().any(|l| l == KIND))
        .map(|(rel, _)| rel.clone())
        .collect()
}

/// In its home, the literal is the private `watchdog_gone`'s, and that
/// function is called once: by `watchdog_exit_finding`, after its rule.
fn home_problems(home: &str) -> Vec<String> {
    let mut out = Vec::new();
    if string_literals(home).iter().filter(|l| *l == KIND).count() != 1 {
        out.push(format!("{HOME}: the kind written more than once"));
    }
    if !home.contains("\nfn watchdog_gone(") {
        out.push(format!(
            "{HOME}: `watchdog_gone` is not private (a caller could sign the death without the rule)"
        ));
    }
    let calls = home.matches("watchdog_gone(").count();
    if calls != 2 {
        out.push(format!(
            "{HOME}: `watchdog_gone(` appears {calls} times (its definition and one call expected)"
        ));
    }
    match (
        home.find("pub fn watchdog_exit_finding("),
        home.find("None => watchdog_gone(prev, now)"),
    ) {
        (Some(f), Some(c)) if c > f => {
            let body = &home[f..c];
            if !body.contains("e.stop_not_death()") {
                out.push(format!(
                    "{HOME}: `watchdog_exit_finding` signs the death without its rule"
                ));
            }
        }
        _ => out.push(format!(
            "{HOME}: the death is not signed by `watchdog_exit_finding`'s rule"
        )),
    }
    out
}

#[test]
fn the_watchdog_s_death_has_one_writer_that_tells_a_stop_from_a_death() {
    let code = product_code(&repo_root());
    assert_eq!(
        writers(&code),
        vec![HOME.to_string()],
        "`{KIND}` is written only by {HOME}'s `watchdog_exit_finding`"
    );
    let problems = home_problems(&code[HOME]);
    assert!(problems.is_empty(), "{problems:#?}");
    // the agent's round signs through it, with the three facts
    let tasks = &code["agent/src/boot/tasks.rs"];
    for needle in [
        "self_integrity::watchdog_exit_finding(",
        "host_shutdown: crate::pipeline::pid1_is_systemd_shutdown(),",
        "window_open: installer_window.is_window_open(),",
        "agent_stopping: stop_begun.has_begun(),",
        "self_integrity::report_or_note(log, &f);",
    ] {
        assert!(tasks.contains(needle), "the watchdog round: {needle}");
    }
}

#[test]
fn a_planted_second_writer_or_a_public_death_is_found() {
    let mut code = product_code(&repo_root());
    // a second writer planted in another file of the agent
    code.get_mut("agent/src/boot/posture.rs")
        .expect("the posture phase's file")
        .push_str(
            "fn f() -> Finding { Finding { kind: \"watchdog_gone\", detail: String::new() } }",
        );
    assert_eq!(writers(&code).len(), 2);
    let home = code[HOME].replace("\nfn watchdog_gone(", "\npub fn watchdog_gone(");
    assert!(!home_problems(&home).is_empty());
    let home = code[HOME].replace("e.stop_not_death()", "None::<&str>");
    assert!(!home_problems(&home).is_empty());
}
