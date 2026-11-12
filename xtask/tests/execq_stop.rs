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
