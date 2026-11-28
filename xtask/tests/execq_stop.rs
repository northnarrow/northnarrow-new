//! Lot 317 (the review of #541, F3): the exec quarantine's kernel half
//! stops only a process its map of stopped processes names.
//!
//! `maybe_stop` (`agent-ebpf/src/execq.rs`) sent `SIGSTOP` and then wrote
//! `EXECQ_STOPPED`, ignoring the write's result. The map is not an LRU (4096
//! entries): past it, a process was stopped that no stop, no crash's next
//! start and no boot's recovery could find — it stayed in state T. Now the
//! entry is written first, its result read, and a process the map cannot
//! name is not stopped (`stop_flags::MAP_FULL`, counted, a signed fail-open
//! degradation in userland). Lexical: the function's text, comments
//! blanked; shown failing on a planted reversal.

mod support;

use std::fs;

use support::{matching_brace, repo_root, strip_comments};

/// The body of `fn maybe_stop` in `code`.
fn maybe_stop(code: &str) -> Option<&str> {
    let at = code.find("unsafe fn maybe_stop(")?;
    let open = at + code[at..].find('{')?;
    Some(&code[open..open + matching_brace(&code[open..])])
}

/// What is wrong with `maybe_stop`'s order, if anything.
fn order(code: &str) -> Result<(), String> {
    let body = maybe_stop(code).ok_or("no `fn maybe_stop`")?;
    let insert = body
        .find("EXECQ_STOPPED.insert(")
        .ok_or("no write of EXECQ_STOPPED")?;
    let stop = body
        .find("bpf_send_signal(SIGSTOP)")
        .ok_or("no SIGSTOP sent")?;
    if insert > stop {
        return Err("SIGSTOP is sent before the map names the process".into());
    }
    let checked = &body[insert..stop];
    if !checked.contains(".is_err()") || !checked.contains("stop_flags::MAP_FULL") {
        return Err(
            "the write's result is not read, or a failed write does not set MAP_FULL before \
             the stop"
                .into(),
        );
    }
    Ok(())
}

#[test]
fn the_kernel_stops_only_a_process_its_map_names() {
    let path = repo_root().join("agent-ebpf/src/execq.rs");
    let code = strip_comments(&fs::read_to_string(&path).unwrap());
    order(&code).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let wire = fs::read_to_string(repo_root().join("common/src/wire/execq.rs")).unwrap();
    assert!(
        wire.contains("| stop_flags::MAP_FULL)"),
        "`ExecqStopRaw::stopped()` does not read MAP_FULL as not stopped"
    );
}

#[test]
fn a_planted_reversal_fails_the_rule() {
    let good = "unsafe fn maybe_stop(t: u64) {\n    if EXECQ_STOPPED.insert(&tgid, &v, 0).is_err() {\n        flags |= stop_flags::MAP_FULL;\n    } else {\n        let rc = generated::bpf_send_signal(SIGSTOP);\n    }\n}\n";
    assert!(order(good).is_ok());
    let reversed = "unsafe fn maybe_stop(t: u64) {\n    let rc = generated::bpf_send_signal(SIGSTOP);\n    let _ = EXECQ_STOPPED.insert(&tgid, &v, 0);\n}\n";
    assert!(order(reversed).is_err());
    let unchecked = "unsafe fn maybe_stop(t: u64) {\n    let _ = EXECQ_STOPPED.insert(&tgid, &v, 0);\n    let rc = generated::bpf_send_signal(SIGSTOP);\n}\n";
    assert!(order(unchecked).is_err());
}

// ── lot M4 (#633): the stop's release does not wait on the controller ──

/// The body of the first `fn <name>` in `code`.
fn body_of<'a>(code: &'a str, name: &str) -> Option<&'a str> {
    let at = code
        .find(&format!("fn {name}("))
        .or_else(|| code.find(&format!("fn {name}<")))?;
    let open = at + code[at..].find('{')?;
    Some(&code[open..open + matching_brace(&code[open..])])
}

/// What breaks the stop's release in the four files (paths relative to
/// the repo), if anything. Lexical, comments blanked.
fn release_rule(
    kernel: &str,
    module: &str,
    release: &str,
    shutdown: &str,
    deadline: &str,
) -> Vec<String> {
    let mut bad = Vec::new();
    // 1. the heartbeat and the stopped map are written only through the
    //    shared maps (`Held`: its latch refuses a beat after the stop's
    //    clear) — one impl writes them, `KernelMaps`'s
    let maps_impl = kernel
        .find("impl super::release::HeldMaps for KernelMaps")
        .map(|at| {
            let open = at + kernel[at..].find('{').unwrap_or(0);
            (at, open + matching_brace(&kernel[open..]))
        });
    for write in [".alive.set(", ".stopped.remove(", ".stopped.insert("] {
        for (at, _) in kernel.match_indices(write) {
            if !maps_impl.is_some_and(|(a, b)| a < at && at < b) {
                bad.push(format!(
                    "agent/src/execq/kernel.rs writes `{write}` outside KernelMaps's HeldMaps impl"
                ));
            }
        }
    }
    // 2. the stop hands the controller's thread to the bounded wait and
    //    the sweep — never a join of its own
    match body_of(module, "shutdown") {
        Some(b) if b.contains("release::stop_then_sweep(") && !b.contains(".join()") => {}
        _ => bad.push(
            "agent/src/execq/mod.rs: `shutdown` does not hand the controller to \
             release::stop_then_sweep (or joins it itself)"
                .into(),
        ),
    }
    // a handle dropped without the stop (a start that failed later)
    // releases too
    let dropped = module
        .find("impl Drop for Handle")
        .and_then(|at| body_of(&module[at..], "drop"));
    if !dropped.is_some_and(|b| b.contains("release::stop_then_sweep(")) {
        bad.push(
            "agent/src/execq/mod.rs: a Handle dropped without `shutdown` does not release what \
             the kernel holds"
                .into(),
        );
    }
    // the deadline's exit has the sweep the start made, and runs it
    if !body_of(module, "start").is_some_and(|b| b.contains("EXIT_SWEEPER.set(")) {
        bad.push(
            "agent/src/execq/mod.rs: `start` does not hand its sweep to the deadline's exit \
             (EXIT_SWEEPER)"
                .into(),
        );
    }
    if !body_of(module, "release_at_exit").is_some_and(|b| b.contains(".sweep_at_exit()")) {
        bad.push("agent/src/execq/mod.rs: `release_at_exit` does not sweep".into());
    }
    // lot M7: the stop's sweep signs by the time the stop gives it — what
    // its deadline leaves before the note, less SIGN_MARGIN
    // (`release::signing_time`; a `shutdown` without the sweep is the rule
    // above's)
    if body_of(module, "shutdown").is_some_and(|b| {
        b.contains("release::stop_then_sweep(")
            && !(b.contains("release::signing_time(") && b.contains("Some(sign_by)"))
    }) {
        bad.push(
            "agent/src/execq/mod.rs: `shutdown` gives the sweep no signing time before the \
             deadline's note (release::signing_time, Some(sign_by))"
                .into(),
        );
    }
    match body_of(release, "stop_then_sweep") {
        Some(b) => {
            let wait = b.find("while !thread.is_finished()");
            let sweep = b.rfind("sweeper.sweep(");
            let signs = sweep.is_some_and(|s| {
                b[s..]
                    .find(");")
                    .is_some_and(|e| b[s..s + e].contains("sign_by"))
            });
            if !signs {
                bad.push(
                    "agent/src/execq/release.rs: `stop_then_sweep` does not hand its signing \
                     time to the sweep"
                        .into(),
                );
            }
            let guarded = sweep.is_some_and(|s| {
                let before = &b[..s];
                let line_start = before.rfind('\n').map_or(0, |i| i + 1);
                before[line_start..].trim().starts_with("if ") || before.trim_end().ends_with('{')
            });
            if !matches!((wait, sweep), (Some(w), Some(s)) if w < s) || guarded {
                bad.push(
                    "agent/src/execq/release.rs: `stop_then_sweep` does not sweep after its \
                     bounded wait, whatever the controller does"
                        .into(),
                );
            }
        }
        None => bad.push("agent/src/execq/release.rs: no `fn stop_then_sweep`".into()),
    }
    // 3. the wait comes from the stop's deadline, and the deadline's exit
    //    releases before it ends the process
    let call = shutdown.find("execq::shutdown(");
    if !call.is_some_and(|c| {
        shutdown[c..].find(')').is_some_and(|_| {
            let args = &shutdown[c..c + shutdown[c..].find(";").unwrap_or(0)];
            args.contains("deadline.drain_bound(")
        })
    }) {
        bad.push(
            "agent/src/shutdown.rs: execq::shutdown is not bounded by the stop's deadline".into(),
        );
    }
    // lot M7: and told what the deadline leaves before its note
    if !call.is_some_and(|c| {
        shutdown[c..c + shutdown[c..].find(';').unwrap_or(0)].contains("deadline.left()")
    }) {
        bad.push(
            "agent/src/shutdown.rs: execq::shutdown is not told what the deadline leaves before \
             its note (deadline.left())"
                .into(),
        );
    }
    match body_of(deadline, "start") {
        Some(b) => {
            let rel = b.find("execq::release_at_exit()");
            let exit = b.find("exit_now(");
            if !matches!((rel, exit), (Some(r), Some(e)) if r < e) {
                bad.push(
                    "agent/src/stop_deadline.rs: the deadline's exit does not release what the \
                     exec quarantine holds before it ends the process"
                        .into(),
                );
            }
        }
        None => bad.push("agent/src/stop_deadline.rs: no `fn start`".into()),
    }
    bad
}

fn read(rel: &str) -> String {
    strip_comments(&fs::read_to_string(repo_root().join(rel)).unwrap())
}

/// #633: on AlmaLinux 9 the controller was seconds into a pass (`rpm -qf`
/// per report) when the agent stopped; the stop waited 2 s for it, the
/// stop's deadline ended the agent first, and every held process stayed in
/// state T. The stop now waits within its deadline, then sweeps the
/// kernel's map from the stopping thread; the deadline's exit sweeps too;
/// the heartbeat and the map are written only through the shared maps.
#[test]
fn the_stop_releases_what_the_kernel_holds_whatever_the_controller_does() {
    let bad = release_rule(
        &read("agent/src/execq/kernel.rs"),
        &read("agent/src/execq/mod.rs"),
        &read("agent/src/execq/release.rs"),
        &read("agent/src/shutdown.rs"),
        &read("agent/src/stop_deadline.rs"),
    );
    assert!(bad.is_empty(), "{bad:#?}");
}

#[test]
fn planted_breaks_of_the_stops_release_fail_the_rule() {
    let kernel = "impl super::release::HeldMaps for KernelMaps {\n    fn set_beat(&mut self, ns: u64) {\n        let _ = self.alive.set(0, &ns, 0);\n    }\n}\n";
    let module = "impl Drop for Handle {\n    fn drop(&mut self) {\n        let _ = release::stop_then_sweep(&STOPPING, w, t, &self.sweeper, DROP_WAIT);\n    }\n}\npub fn start() -> R {\n    let _ = EXIT_SWEEPER.set(Arc::clone(&sweeper));\n}\npub fn shutdown(h: Option<Handle>, wait: Duration, to_note: Duration) {\n    let sign_by = release::signing_time(Instant::now(), to_note);\n    let _ = release::stop_then_sweep(&STOPPING, wake, h.thread, &h.sweeper, wait, Some(sign_by));\n}\npub fn release_at_exit() {\n    match s.sweep_at_exit() {}\n}\n";
    let release = "pub fn stop_then_sweep() -> Option<J> {\n    while !thread.is_finished() && Instant::now() < deadline {\n        sleep();\n    }\n    sweeper.sweep(by, sign_by);\n    running\n}\n";
    let shutdown = "fn stop() {\n    northnarrow_agent::execq::shutdown(\n        execq_handle,\n        deadline.drain_bound(STOP_WAIT),\n        deadline.left(),\n    );\n}\n";
    let deadline = "pub(crate) fn start() -> Self {\n    Self::start_with(BUDGET, Arc::new(|s| {\n        northnarrow_agent::execq::release_at_exit();\n        exit_now(s)\n    }))\n}\n";
    assert!(release_rule(kernel, module, release, shutdown, deadline).is_empty());
    // a second writer of the heartbeat, past the latch
    let k2 = format!(
        "{kernel}impl Kernel {{\n    pub fn beat(&mut self, ns: u64) {{\n        let _ = self.alive.set(0, &ns, 0);\n    }}\n}}\n"
    );
    assert_eq!(
        release_rule(&k2, module, release, shutdown, deadline).len(),
        1
    );
    // the old stop: a fixed wait and a join of its own
    let m2 = module.replace(
        "    let _ = release::stop_then_sweep(&STOPPING, wake, h.thread, &h.sweeper, wait, Some(sign_by));",
        "    while !h.thread.is_finished() { sleep(); }\n    let _ = h.thread.join();",
    );
    assert_eq!(
        release_rule(kernel, &m2, release, shutdown, deadline).len(),
        1
    );
    // a handle dropped without the stop that releases nothing
    let m3 = module.replace(
        "        let _ = release::stop_then_sweep(&STOPPING, w, t, &self.sweeper, DROP_WAIT);",
        "        STOPPING.store(true, Ordering::Relaxed);",
    );
    assert_eq!(
        release_rule(kernel, &m3, release, shutdown, deadline).len(),
        1
    );
    // the deadline's exit without the start's sweep, or not sweeping
    let m4 = module.replace("    let _ = EXIT_SWEEPER.set(Arc::clone(&sweeper));\n", "");
    assert_eq!(
        release_rule(kernel, &m4, release, shutdown, deadline).len(),
        1
    );
    let m5 = module.replace("    match s.sweep_at_exit() {}\n", "    return;\n");
    assert_eq!(
        release_rule(kernel, &m5, release, shutdown, deadline).len(),
        1
    );
    // a sweep only when the controller finished
    let r2 = release.replace(
        "    sweeper.sweep(by, sign_by);",
        "    if running.is_none() { sweeper.sweep(by, sign_by); }",
    );
    assert_eq!(
        release_rule(kernel, module, &r2, shutdown, deadline).len(),
        1
    );
    // an unbounded wait
    let s2 = "fn stop() {\n    northnarrow_agent::execq::shutdown(execq_handle, STOP_WAIT, deadline.left());\n}\n";
    assert_eq!(release_rule(kernel, module, release, s2, deadline).len(), 1);
    // lot M7: a sweep given no signing time — by the agent's stop, by the
    // module, or not handed on to the sweep
    let s3 = shutdown.replace("        deadline.left(),\n", "        STOP_WAIT,\n");
    assert_eq!(
        release_rule(kernel, module, release, &s3, deadline).len(),
        1
    );
    let m6 = module.replace(
        "&h.sweeper, wait, Some(sign_by));",
        "&h.sweeper, wait, None);",
    );
    assert_eq!(
        release_rule(kernel, &m6, release, shutdown, deadline).len(),
        1
    );
    let r3 = release.replace("sweeper.sweep(by, sign_by);", "sweeper.sweep(by, None);");
    assert_eq!(
        release_rule(kernel, module, &r3, shutdown, deadline).len(),
        1
    );
    // the deadline's exit without the release
    let d2 =
        "pub(crate) fn start() -> Self {\n    Self::start_with(BUDGET, Arc::new(exit_now))\n}\n";
    assert_eq!(release_rule(kernel, module, release, shutdown, d2).len(), 1);
}
