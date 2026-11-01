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
//! name it.

mod support;

use std::fs;
use std::path::PathBuf;

use support::{repo_root, strip_comments};

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

/// The code of `text` without its test module (`#[cfg(test)]` on a `mod`
/// and what follows it: the convention of this tree, the module last).
fn production(text: &str) -> &str {
    text.find("\n#[cfg(test)]\nmod ")
        .map_or(text, |at| &text[..at])
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
            } else if n > 0 {
                bad.push(format!("{rel}: names nn_parse {n} time(s)"));
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
}
