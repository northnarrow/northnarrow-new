//! The help texts — every subcommand, found by walking the binary's own
//! `-h` — and clap's errors.

use std::process::Command;

use crate::fixtures;
use crate::harness::{Case, BIN};

/// One subcommand path, its `-h` text parsed.
struct Node {
    path: Vec<String>,
    subcommands: Vec<String>,
    /// Long options: the flag, whether it takes a value.
    options: Vec<(String, bool)>,
    /// Its usage line names a required argument.
    requires: bool,
    positionals: bool,
}

fn short_help(path: &[String]) -> String {
    let out = Command::new(BIN)
        .args(path)
        .arg("-h")
        .env_clear()
        .output()
        .expect("nn-admin -h");
    assert!(out.status.success(), "nn-admin {path:?} -h: {out:?}");
    String::from_utf8(out.stdout).unwrap()
}

fn parse(path: Vec<String>) -> Node {
    let text = short_help(&path);
    let mut section = "";
    let mut subcommands = Vec::new();
    let mut options = Vec::new();
    let mut requires = false;
    let mut positionals = false;
    for line in text.lines() {
        if let Some(u) = line.strip_prefix("Usage: ") {
            // `nn-admin canary deploy [OPTIONS] --name <NAME> …`: a required
            // argument is outside the brackets.
            let mut depth = 0;
            let mut outside = String::new();
            for c in u.chars() {
                match c {
                    '[' => depth += 1,
                    ']' => depth -= 1,
                    _ if depth == 0 => outside.push(c),
                    _ => {}
                }
            }
            requires = outside.contains('<');
            continue;
        }
        if line.ends_with(':') && !line.starts_with(' ') {
            section = match line {
                "Commands:" => "commands",
                "Options:" => "options",
                "Arguments:" => "arguments",
                _ => "",
            };
            continue;
        }
        match section {
            "commands" => {
                if let Some(rest) = line.strip_prefix("  ") {
                    if !rest.starts_with(' ') {
                        let name = rest.split_whitespace().next().unwrap().to_string();
                        if name != "help" {
                            subcommands.push(name);
                        }
                    }
                }
            }
            "options" => {
                let t = line.trim_start();
                let t = t.split_once(", ").map(|(_, b)| b).unwrap_or(t);
                if let Some(rest) = t.strip_prefix("--") {
                    let mut it = rest.split_whitespace();
                    let flag = format!("--{}", it.next().unwrap());
                    let value = it.next().is_some_and(|w| w.starts_with('<'));
                    if flag != "--help" && flag != "--version" {
                        options.push((flag, value));
                    }
                }
            }
            "arguments"
                if line.trim_start().starts_with('<') || line.trim_start().starts_with('[') =>
            {
                positionals = true;
            }
            _ => {}
        }
    }
    Node {
        path,
        subcommands,
        options,
        requires,
        positionals,
    }
}

/// Every subcommand path, the root first, depth first in help order.
fn walk() -> &'static [Node] {
    static NODES: std::sync::OnceLock<Vec<Node>> = std::sync::OnceLock::new();
    NODES.get_or_init(walk_uncached)
}

fn walk_uncached() -> Vec<Node> {
    let mut out = Vec::new();
    let mut todo = vec![Vec::<String>::new()];
    while let Some(p) = todo.pop() {
        let n = parse(p);
        for s in n.subcommands.iter().rev() {
            let mut q = n.path.clone();
            q.push(s.clone());
            todo.push(q);
        }
        out.push(n);
    }
    out
}

fn id_of(path: &[String]) -> String {
    if path.is_empty() {
        "root".to_string()
    } else {
        path.join(".")
    }
}

pub fn help() -> Vec<Case> {
    let mut out = Vec::new();
    for (name, args) in [
        ("no-arguments", vec![]),
        ("version-long", vec!["--version"]),
        ("version-short", vec!["-V"]),
        ("help-alone", vec!["help"]),
        ("help-of-help", vec!["help", "help"]),
        ("help-of-unknown", vec!["help", "nosuch"]),
        ("help-of-nested-unknown", vec!["help", "audit", "nosuch"]),
        (
            "help-flag-after-subcommand-args",
            vec!["audit", "read", "--json", "--help"],
        ),
        ("version-of-a-subcommand", vec!["audit", "--version"]),
    ] {
        out.push(Case::new("help", format!("help.{name}"), &args));
    }
    for n in walk() {
        let id = id_of(&n.path);
        let mut long = n.path.clone();
        long.push("--help".to_string());
        out.push(Case::args_owned("help", format!("help.{id}.long"), long));
        let mut short = n.path.clone();
        short.push("-h".to_string());
        out.push(Case::args_owned("help", format!("help.{id}.short"), short));
        if !n.path.is_empty() {
            let mut sub = vec!["help".to_string()];
            sub.extend(n.path.clone());
            out.push(Case::args_owned(
                "help",
                format!("help.{id}.subcommand"),
                sub,
            ));
        }
        if !n.subcommands.is_empty() && !n.path.is_empty() {
            // A group without its subcommand: clap prints its help, exit 2.
            out.push(Case::args_owned(
                "help",
                format!("help.{id}.without-subcommand"),
                n.path.clone(),
            ));
        }
    }
    out
}

pub fn errors() -> Vec<Case> {
    let mut out = Vec::new();
    for n in walk() {
        let id = id_of(&n.path);
        let with = |extra: &[&str]| {
            let mut a = n.path.clone();
            a.extend(extra.iter().map(|s| s.to_string()));
            a
        };
        out.push(Case::args_owned(
            "clap-errors",
            format!("clap.{id}.unknown-flag"),
            with(&["--no-such-flag"]),
        ));
        if !n.subcommands.is_empty() {
            out.push(Case::args_owned(
                "clap-errors",
                format!("clap.{id}.unknown-subcommand"),
                with(&["nosuch"]),
            ));
            continue;
        }
        if n.requires {
            out.push(Case::args_owned(
                "clap-errors",
                format!("clap.{id}.missing-required"),
                n.path.clone(),
            ));
        }
        if !n.positionals && n.requires {
            out.push(Case::args_owned(
                "clap-errors",
                format!("clap.{id}.stray-positional"),
                with(&["stray-argument"]),
            ));
        }
        for (flag, value) in &n.options {
            let f = flag.trim_start_matches("--");
            if *value {
                out.push(Case::args_owned(
                    "clap-errors",
                    format!("clap.{id}.{f}.missing-value"),
                    with(&[flag]),
                ));
            } else {
                out.push(Case::args_owned(
                    "clap-errors",
                    format!("clap.{id}.{f}.given-twice"),
                    with(&[flag, flag]),
                ));
                out.push(Case::args_owned(
                    "clap-errors",
                    format!("clap.{id}.{f}.with-a-value"),
                    with(&[&format!("{flag}=yes")]),
                ));
            }
        }
    }
    // Values clap refuses, every other argument given (an error of the
    // value, not of a missing argument).
    let signed = [
        "--key",
        "key-a",
        "--agent-id-file",
        "agent_id",
        "--socket",
        "admin.sock",
    ];
    let s = |a: &[&str]| -> Vec<String> {
        a.iter()
            .chain(signed.iter())
            .map(|x| x.to_string())
            .collect()
    };
    let values: Vec<(&str, Vec<String>)> = vec![
        (
            "detections.limit-not-a-number",
            s(&["detections", "--limit", "many"]),
        ),
        (
            "detections.limit-negative",
            s(&["detections", "--limit", "-1"]),
        ),
        (
            "detections.limit-over-u32",
            s(&["detections", "--limit", "4294967296"]),
        ),
        (
            "detections.since-not-a-number",
            s(&["detections", "--since", "2025-06-15"]),
        ),
        (
            "detections.until-not-a-number",
            s(&["detections", "--until", "later"]),
        ),
        (
            "detections.min-severity-unknown",
            s(&["detections", "--min-severity", "extreme"]),
        ),
        (
            "detections.min-severity-case",
            s(&["detections", "--min-severity", "High"]),
        ),
        (
            "detections.status-unknown",
            s(&["detections", "--status", "closed"]),
        ),
        (
            "detections.sensor-unknown",
            s(&["detections", "--sensor", "gpu"]),
        ),
        (
            "detection-set-status.id-not-a-number",
            s(&["detection-set-status", "--id", "x", "--status", "resolved"]),
        ),
        (
            "detection-set-status.status-open",
            s(&["detection-set-status", "--id", "1", "--status", "open"]),
        ),
        (
            "shutdown.grace-negative",
            s(&["shutdown", "--cosign-key", "key-b", "--grace-secs", "-5"]),
        ),
        (
            "force-posture.target-unknown",
            s(&["force-posture", "panic"]),
        ),
        ("force-posture.target-missing", s(&["force-posture"])),
        (
            "trusted-installer-grant.window-not-a-number",
            s(&["trusted-installer-grant", "--window-secs", "ten"]),
        ),
        (
            "response-release.pid-not-a-number",
            s(&["response", "release", "--pid", "init"]),
        ),
        (
            "remediate-ransomware.pid-not-a-number",
            s(&["remediate", "ransomware", "--pid", "x"]),
        ),
        (
            "net-flows.since-unix-not-a-number",
            s(&["net", "flows", "--since-unix", "now"]),
        ),
        (
            "fim-report.since-not-a-number",
            s(&["fim", "report", "--since", "yesterday"]),
        ),
        ("canary-deploy.bind-port-over-u16", {
            let mut a = s(&["canary", "deploy", "--name", "n"]);
            a.extend(
                ["network", "--bind-addr", "0.0.0.0", "--bind-port", "70000"].map(String::from),
            );
            a
        }),
        (
            "canary-deploy.kind-missing",
            s(&["canary", "deploy", "--name", "n"]),
        ),
        ("canary-deploy.kind-unknown", {
            let mut a = s(&["canary", "deploy", "--name", "n"]);
            a.push("smtp".to_string());
            a
        }),
        (
            "audit-verify.min-seq-not-a-number",
            vec![
                "audit",
                "verify",
                "--from",
                "audit.log",
                "--min-seq",
                "first",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
        ),
        (
            "chain-verify.log-unknown",
            vec!["chain", "verify", "--log", "journal"]
                .into_iter()
                .map(String::from)
                .collect(),
        ),
        (
            "chain-verify.log-case",
            vec!["chain", "verify", "--log", "Audit"]
                .into_iter()
                .map(String::from)
                .collect(),
        ),
        ("top.typo-suggests", vec!["statu".to_string()]),
        (
            "top.typo-nested-suggests",
            vec!["audit".to_string(), "verfy".to_string()],
        ),
        ("top.unknown", vec!["nosuch".to_string()]),
        (
            "top.debug-not-in-this-build",
            vec![
                "debug".to_string(),
                "force-posture".to_string(),
                "combat".to_string(),
            ],
        ),
        (
            "top.double-dash",
            vec!["--".to_string(), "status".to_string()],
        ),
        ("top.empty-argument", vec!["".to_string()]),
        ("top.not-utf8-like", vec!["st\u{e4}tus".to_string()]),
    ];
    for (name, args) in values {
        out.push(
            Case::args_owned("clap-errors", format!("clap.value.{name}"), args)
                .with(fixtures::base()),
        );
    }
    out
}
