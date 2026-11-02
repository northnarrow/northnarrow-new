//! R14b (plan §3.1, §5 "Cosa NON fare"): the core never parses hostile bytes
//! itself. nn-parse's parsers — the DNS names, the DNS answers, the TLS
//! ClientHello — run in the parse worker (`nn_linux::worker::serve`, and
//! the compromised worker of the lab builds, `worker::hostile`); the core
//! reaches them through `nn_linux::worker::parse::ParseClient` and does
//! without when the worker does not answer.
//!
//! The production sources of the core — the agent, nn-linux, nn-core,
//! nn-evidence — name `nn_parse` nowhere else (test code aside: files of
//! tests, `#[cfg(test)]` modules, the fuzz harness's own test module). A
//! fallback that parses in the core when the worker is down would have to
//! name it — or call the worker's own code in the core's process: review of
//! #481 (R14b-3, the reviewer's planting P1) — `worker::serve::answer`
//! runs the parsers in its caller. It is `pub(crate)`, and no production
//! source but the worker's names `serve::answer`, nor any of
//! `worker::serve::` but its entry (`worker::serve::main(`, the worker
//! mode of `main`); the worker's side re-exports no parser (`pub use
//! nn_parse`).

mod support;

use std::fs;
use std::path::PathBuf;

use support::{production, repo_root, strip_comments};

const TREES: &[&str] = &[
    "agent/src",
    "crates/nn-linux/src",
    "crates/nn-core/src",
    "crates/nn-evidence/src",
];

/// Where the parsers run: the worker's side.
const WORKER_SIDE: &[&str] = &[
    "crates/nn-linux/src/worker/serve.rs",
    "crates/nn-linux/src/worker/hostile.rs",
];

fn rs_files(dir: &std::path::Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    support::rs_files(dir, &mut out);
    out.sort();
    out
}

fn is_test_file(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    name == "tests.rs" || name.ends_with("_tests.rs") || rel.contains("/tests/")
}

#[test]
fn the_core_names_no_parser_outside_the_worker() {
    let mut bad = Vec::new();
    let mut worker_names = 0;
    for tree in TREES {
        for f in rs_files(&repo_root().join(tree)) {
            let rel = f.strip_prefix(repo_root()).unwrap().display().to_string();
            if is_test_file(&rel) {
                continue;
            }
            let code = strip_comments(&fs::read_to_string(&f).unwrap());
            let code = production(&code);
            let n = code.matches("nn_parse").count();
            if WORKER_SIDE.contains(&rel.as_str()) {
                worker_names += n;
                if code.contains("pub use nn_parse") {
                    bad.push(format!("{rel}: re-exports a parser"));
                }
            } else {
                bad.extend(core_reaches_a_parser(&code).map(|why| format!("{rel}: {why}")));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "the core parses hostile bytes outside the worker:\n{}",
        bad.join("\n")
    );
    assert!(
        worker_names >= 4,
        "the worker runs the parsers: {worker_names}"
    );
}

/// What in a production source of the core reaches a parser in its own
/// process: nn-parse itself, or the worker's answer (review of #481,
/// R14b-3).
fn core_reaches_a_parser(code: &str) -> Option<String> {
    let parse = code.matches("nn_parse").count();
    if parse > 0 {
        return Some(format!("names nn_parse {parse} time(s)"));
    }
    if code.contains("serve::answer") {
        return Some("calls the worker's answer (its parsers) in the core".to_string());
    }
    let serve = code.matches("worker::serve::").count();
    let entry = code.matches("worker::serve::main(").count();
    if serve > entry {
        return Some(format!(
            "reaches worker::serve:: {} time(s) beyond the worker's entry",
            serve - entry
        ));
    }
    None
}

/// The DNS pump hands its names to the worker and builds its events from
/// the worker's decode, or none.
#[test]
fn the_dns_pump_asks_the_worker() {
    let mux =
        fs::read_to_string(repo_root().join("crates/nn-linux/src/sensors/multiplexer.rs")).unwrap();
    let code = strip_comments(&mux);
    let pass = &code[code.find("fn dns_pass(").unwrap()..];
    let pass = &pass[..pass.find("\n}\n").unwrap()];
    assert!(pass.contains("parse.names(raws.iter().map(name_request).collect())"));
    let sensor = strip_comments(
        &fs::read_to_string(repo_root().join("crates/nn-linux/src/sensors/dns_sensor.rs")).unwrap(),
    );
    let sensor = production(&sensor);
    for gone in ["decode_dns_qname", "qname_wire_end", "nss_presentation"] {
        assert!(
            !sensor.contains(gone),
            "dns_sensor.rs decodes itself: {gone}"
        );
    }
}

#[test]
fn a_planted_parser_in_the_core_fails() {
    let planted = "fn f(b: &[u8]) -> String { nn_parse::dns_qname::decode_dns_qname(b) }\n";
    let code = strip_comments(planted);
    assert!(production(&code).contains("nn_parse"));
    let in_test = format!("fn g() {{}}\n#[cfg(test)]\nmod tests {{\n{planted}}}\n");
    assert!(!production(&strip_comments(&in_test)).contains("nn_parse"));
    // review of #481 (R14b-3): the reviewer's P1 and its variants
    for planted in [
        "fn f(r: &Request) -> Answer { nn_linux::worker::serve::answer(r) }\n",
        "use nn_linux::worker::serve::answer;\n",
        "fn f(r: &Request) -> Answer { crate::worker::serve::answer(r) }\n",
        "use crate::worker::serve;\nfn f(r: &Request) -> Answer { serve::answer(r) }\n",
        "use nn_linux::worker::serve::*;\n",
    ] {
        let code = strip_comments(planted);
        assert!(
            core_reaches_a_parser(&production(&code)).is_some(),
            "{planted}"
        );
    }
    // the worker's entry is not a parser
    assert!(
        core_reaches_a_parser("std::process::exit(nn_linux::worker::serve::main(&args));")
            .is_none()
    );
}
