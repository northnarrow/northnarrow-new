//! Lot 2.0 — a stop signal the agent or the watchdog did not request is no
//! clean stop. The rule is one (`antitamper_bpf::stop_signal::judge`: the
//! host's shutdown or a signed window in force), and its unit tests judge
//! it; here the code is read: every stop signal of the agent's event loop
//! and every one that ends the watchdog's restart loop goes through it, so
//! that a new arm cannot take a signal for a clean stop unjudged.

mod support;

use std::fs;

use support::{repo_root, strip_comments};

fn code(rel: &str) -> String {
    strip_comments(
        &fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}")),
    )
}

/// The body of `fn name` (to its matching brace).
fn body<'a>(code: &'a str, name: &str) -> &'a str {
    let start = code
        .find(&format!("fn {name}("))
        .unwrap_or_else(|| panic!("fn {name} not found"));
    let open = start + code[start..].find('{').expect("a body");
    let len = support::matching_brace(&code[open..]);
    &code[open..open + len]
}

/// The agent: each stop signal's clean reason is named once, as what the
/// judgement returns when the stop was requested; the reason of a stop
/// nobody requested is a failure (`shutdown::stop_result`).
#[test]
fn the_agent_s_stop_signals_are_judged() {
    let r = code("agent/src/run_loop.rs");
    let w = body(&r, "watch_loop");
    for (sig, clean) in [
        ("libc::SIGINT", "\"sigint\""),
        ("libc::SIGTERM", "\"sigterm\""),
        ("libc::SIGHUP", "\"sighup\""),
    ] {
        let call = format!("return signal_stop({sig}, {clean}, window, audit_log);");
        assert_eq!(w.matches(&call).count(), 1, "{call}");
        assert_eq!(w.matches(clean).count(), 1, "{clean} named elsewhere:\n{w}");
    }
    assert_eq!(w.matches(".recv() => {").count(), 3, "{w}");
    let s = body(&r, "signal_stop");
    for needle in [
        "let stop = stop_signal::judge(stop_signal::host_shutdown(), in_window);",
        "let reason = stop_reason_of(stop, clean);",
        "if stop.requested() {",
        "northnarrow_agent::self_integrity::UNREQUESTED_STOP",
    ] {
        assert!(s.contains(needle), "{needle}:\n{s}");
    }
    let o = body(&r, "stop_reason_of");
    assert!(
        o.contains("nn_proto::watchdog_hold::UNREQUESTED_STOP_REASON"),
        "{o}"
    );
    let sh = code("agent/src/shutdown.rs");
    assert!(
        body(&sh, "stop_result")
            .contains("if stop_reason == nn_proto::watchdog_hold::UNREQUESTED_STOP_REASON {")
    );
    // the senders are kept before the signal streams exist
    let t = code("agent/src/boot/tasks.rs");
    let cap = t
        .find("antitamper_bpf::stop_signal::capture(signo)")
        .expect("captured");
    let first = t
        .find("signal(SignalKind::interrupt())")
        .expect("the streams");
    assert!(cap < first);
}

/// The watchdog: every way out of its restart loop is a failure, the
/// admin quorum's signed shutdown, or a stop signal it then judges — a
/// requested one exits 0, any other is `ExitReason::UnrequestedSignal`
/// (restarted by systemd).
#[test]
fn the_watchdog_s_stop_signals_are_judged() {
    let m = code("watchdog/src/main.rs");
    let run = body(&m, "run");
    let breaks: Vec<usize> = run
        .match_indices("break 'restart_loop")
        .map(|(i, _)| i)
        .collect();
    assert!(breaks.len() >= 8, "{}", breaks.len());
    let mut judged = 0;
    for at in breaks {
        let before = &run[at.saturating_sub(160)..at];
        if before.contains("stop_signal = Some(") {
            judged += 1;
        } else {
            assert!(
                before.contains("failure = Some(")
                    || before.contains("admin-authorised shutdown observed"),
                "a way out of the restart loop that is neither a failure, the signed shutdown, \
                 nor a judged stop signal:\n{before}"
            );
        }
    }
    // the loop's select, the respawn's two arms, the backoff, three holds
    assert_eq!(judged, 7);
    assert_eq!(run.matches("stop_signal = Some(").count(), 7);
    let after = &run[run.rfind("break 'restart_loop").unwrap()..];
    let judge = after
        .find("failure = unrequested_stop(&cli.bpffs_root, name, agent_pid);")
        .expect("judged after the loop");
    let teardown = after
        .find("unregister_self_pid(&cli.bpffs_root, own_pid)")
        .expect("teardown");
    assert!(judge < teardown, "judged while still a protected pid");
    let h = body(&m, "hold");
    assert!(h.contains("HoldOutcome::Shutdown(name) => {"), "{h}");
    assert!(h.contains("Err(name)"), "{h}");
    let u = body(&m, "unrequested_stop");
    for needle in [
        "let stop = stop_signal::judge(",
        "stop_signal::host_shutdown(),",
        "stop_signal::window_in_force(bpffs_root, at),",
        "if stop.requested() {",
        "return None;",
        "ExitReason::UnrequestedSignal,",
    ] {
        assert!(u.contains(needle), "{needle}:\n{u}");
    }
    let cap = run
        .find("antitamper_bpf::stop_signal::capture(signo)")
        .expect("captured");
    let first = run
        .find("signal(SignalKind::interrupt())")
        .expect("the streams");
    assert!(cap < first);
}
