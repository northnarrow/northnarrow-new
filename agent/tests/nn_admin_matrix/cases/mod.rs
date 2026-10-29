//! The cases, by area (one golden file each).

mod cli;
mod local;
mod policy;
pub mod socket;

use crate::fixtures;
use crate::harness::{Case, Put, Special};
use crate::mock::{Reply, Script};

/// The areas, and the fewest cases each may hold: what this lot wrote, so
/// a case dropped by accident fails `the_matrix_covers_lab_pr_259s_areas`.
pub const AREAS: &[(&str, usize)] = &[
    ("help", 182),
    ("clap-errors", 323),
    ("init", 13),
    ("verify-keys", 17),
    ("host-check", 2),
    ("audit", 58),
    ("chain", 45),
    ("overlay", 56),
    ("policy", 548),
    ("socket", 789),
    ("key-identity", 544),
    ("pipes", 48),
    ("defaults", 78),
];

pub fn all() -> Vec<Case> {
    let mut v = Vec::new();
    v.extend(cli::help());
    v.extend(cli::errors());
    v.extend(local::init());
    v.extend(local::verify_keys());
    v.extend(local::host_check());
    v.extend(local::audit());
    v.extend(local::chain());
    v.extend(local::overlay());
    v.extend(policy::cases());
    v.extend(socket::cases());
    v.extend(key_identity());
    v.extend(pipes());
    v.extend(defaults());
    v
}

/// `args` with the value of `flag` replaced (or the flag removed).
fn replace_flag(args: &[String], flag: &str, value: Option<&str>) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag {
            if let Some(v) = value {
                out.push(flag.to_string());
                out.push(v.to_string());
            }
            i += 2;
            continue;
        }
        out.push(args[i].clone());
        i += 1;
    }
    out
}

/// One key error: its name, the files it adds, the `--key` it passes, the
/// environment.
type KeyError = (
    &'static str,
    Vec<Put>,
    &'static str,
    Vec<(&'static str, &'static str)>,
);

/// The key and identity errors through every signed verb: what each verb
/// reads first, and when (a key read before the connection, an overlay
/// before the key).
fn key_identity() -> Vec<Case> {
    let key_errors: Vec<KeyError> = vec![
        ("key-missing", vec![], "absent.key", vec![]),
        (
            "key-group-readable",
            vec![Put::file("loose.key", key_a_line(), 0o640)],
            "loose.key",
            vec![],
        ),
        (
            "key-world-readable",
            vec![Put::file("loose.key", key_a_line(), 0o644)],
            "loose.key",
            vec![],
        ),
        (
            "key-loose-allowed",
            vec![Put::file("loose.key", key_a_line(), 0o644)],
            "loose.key",
            vec![("NN_ADMIN_ALLOW_LOOSE_KEY", "1")],
        ),
        (
            "key-loose-allow-not-1",
            vec![Put::file("loose.key", key_a_line(), 0o644)],
            "loose.key",
            vec![("NN_ADMIN_ALLOW_LOOSE_KEY", "yes")],
        ),
        (
            "key-empty",
            vec![Put::file("bad.key", "\n\n", 0o600)],
            "bad.key",
            vec![],
        ),
        (
            "key-short",
            vec![Put::file("bad.key", "abcd\n", 0o600)],
            "bad.key",
            vec![],
        ),
        (
            "key-not-hex",
            vec![Put::file(
                "bad.key",
                format!("{}\n", "zz".repeat(32)),
                0o600,
            )],
            "bad.key",
            vec![],
        ),
        (
            "key-a-directory",
            vec![Put::Dir("key.d".into())],
            "key.d",
            vec![],
        ),
        ("key-not-installed", vec![], "key-c", vec![]),
    ];
    let id_errors: Vec<(&str, Vec<Put>, &str)> = vec![
        ("agent-id-missing", vec![], "absent_id"),
        (
            "agent-id-all-zero",
            vec![Put::file("bad_id", format!("{}\n", "0".repeat(32)), 0o644)],
            "bad_id",
        ),
        (
            "agent-id-short",
            vec![Put::file("bad_id", "1111\n", 0o644)],
            "bad_id",
        ),
        (
            "agent-id-not-hex",
            vec![Put::file("bad_id", format!("{}\n", "zz".repeat(16)), 0o644)],
            "bad_id",
        ),
        (
            "agent-id-two-lines",
            vec![Put::file(
                "bad_id",
                format!("{}\n{}\n", "1".repeat(32), "2".repeat(32)),
                0o644,
            )],
            "bad_id",
        ),
        (
            "agent-id-a-directory",
            vec![Put::Dir("id.d".into())],
            "id.d",
        ),
    ];
    let mut out = Vec::new();
    for verb in socket::verbs().into_iter().filter(|v| v.signed) {
        let first = verb.success.first().map(|(_, m)| m.clone()).unwrap();
        let script = || {
            Script::signed(Reply::send(
                format!(
                    "{} (the verb's first success)",
                    socket::variant_name(&first)
                ),
                first.clone(),
            ))
        };
        for (name, put, key, env) in &key_errors {
            let mut c = Case::args_owned(
                "key-identity",
                format!("keyid.{}.{name}", verb.name),
                replace_flag(&verb.args, "--key", Some(key)),
            )
            .with(fixtures::base())
            .with(verb.put.clone())
            .with(put.clone())
            .mock(script())
            .special(verb.special);
            for (k, v) in env {
                c = c.env(k, v);
            }
            out.push(c);
        }
        for (name, put, file) in &id_errors {
            out.push(
                Case::args_owned(
                    "key-identity",
                    format!("keyid.{}.{name}", verb.name),
                    replace_flag(&verb.args, "--agent-id-file", Some(file)),
                )
                .with(fixtures::base())
                .with(verb.put.clone())
                .with(put.clone())
                .mock(script())
                .special(verb.special),
            );
        }
        if verb.args.iter().any(|a| a == "--cosign-key") {
            for (name, put, key) in [
                ("cosign-missing", vec![], "absent.key"),
                (
                    "cosign-world-readable",
                    vec![Put::file("loose.key", key_a_line(), 0o644)],
                    "loose.key",
                ),
                (
                    "cosign-short",
                    vec![Put::file("bad.key", "abcd\n", 0o600)],
                    "bad.key",
                ),
                ("cosign-not-installed", vec![], "key-c"),
            ] {
                out.push(
                    Case::args_owned(
                        "key-identity",
                        format!("keyid.{}.{name}", verb.name),
                        replace_flag(&verb.args, "--cosign-key", Some(key)),
                    )
                    .with(fixtures::base())
                    .with(verb.put.clone())
                    .with(put)
                    .mock(script()),
                );
            }
        }
    }
    out
}

fn key_a_line() -> String {
    format!("{}\n", hex::encode(fixtures::admin("key-a").to_bytes()))
}

/// Output into a pipe whose reader is gone (lab PR 188: exit 141, no
/// panic), stdout and stderr.
fn pipes() -> Vec<Case> {
    let mut out = Vec::new();
    let local: Vec<(&str, Vec<&str>, Vec<Put>, Special)> = vec![
        ("help", vec!["--help"], vec![], Special::None),
        (
            "help-sub",
            vec!["help", "audit", "read"],
            vec![],
            Special::None,
        ),
        ("version", vec!["--version"], vec![], Special::None),
        (
            "host-check",
            vec!["host-check"],
            vec![],
            Special::HostChecks,
        ),
        (
            "host-check-json",
            vec!["host-check", "--json"],
            vec![],
            Special::HostChecks,
        ),
        (
            "verify-keys",
            vec!["verify-keys", "--path", "admin.pub"],
            fixtures::base(),
            Special::None,
        ),
        (
            "audit-read",
            vec!["audit", "read", "--path", "audit.log"],
            vec![Put::file("audit.log", fixtures::pin_audit_log(), 0o600)],
            Special::None,
        ),
        (
            "audit-read-json",
            vec!["audit", "read", "--path", "audit.log", "--json"],
            vec![Put::file("audit.log", fixtures::pin_audit_log(), 0o600)],
            Special::None,
        ),
        (
            "audit-verify",
            vec![
                "audit",
                "verify",
                "--from",
                "audit.log",
                "--agent-sig-key",
                "agent.sig.key",
            ],
            [
                vec![Put::file("audit.log", fixtures::pin_audit_log(), 0o600)],
                fixtures::agent_keys(),
            ]
            .concat(),
            Special::None,
        ),
        (
            "chain-verify",
            vec![
                "chain",
                "verify",
                "--state-dir",
                ".",
                "--audit-log",
                "audit.log",
                "--agent-sig-key",
                "agent.sig.key",
            ],
            [
                vec![Put::file("audit.log", fixtures::pin_audit_log(), 0o600)],
                fixtures::agent_keys(),
            ]
            .concat(),
            Special::None,
        ),
        (
            "overlay-status",
            vec![
                "config",
                "overlay",
                "status",
                "--dir",
                ".",
                "--admin-pub",
                "admin.pub",
                "--agent-id-file",
                "agent_id",
                "--audit-log",
                "audit.log",
                "--agent-sig-key",
                "agent.sig.key",
            ],
            [fixtures::base(), fixtures::agent_keys()].concat(),
            Special::None,
        ),
        (
            "policy-show",
            vec![
                "policy",
                "show",
                "--file",
                "rule-policy.local",
                "--admin-pub",
                "admin.pub",
                "--agent-id-file",
                "agent_id",
                "--audit-log",
                "audit.log",
                "--agent-sig-key",
                "agent.sig.key",
            ],
            [fixtures::base(), fixtures::agent_keys()].concat(),
            Special::None,
        ),
        (
            "policy-test",
            vec![
                "policy",
                "test",
                "--events",
                "events.json",
                "--config-dir",
                "empty",
            ],
            vec![
                Put::File(
                    "events.json".into(),
                    fixtures::read_repo("agent/tests/golden/cases/r020-shell-socket-stdio.json"),
                    0o644,
                ),
                Put::Dir("empty".into()),
            ],
            Special::None,
        ),
        (
            "policy-test-json",
            vec![
                "policy",
                "test",
                "--events",
                "events.json",
                "--config-dir",
                "empty",
                "--json",
            ],
            vec![
                Put::File(
                    "events.json".into(),
                    fixtures::read_repo("agent/tests/golden/cases/r020-shell-socket-stdio.json"),
                    0o644,
                ),
                Put::Dir("empty".into()),
            ],
            Special::None,
        ),
        (
            "clap-error",
            vec!["audit", "--no-such-flag"],
            vec![],
            Special::None,
        ),
        (
            "missing-key",
            vec![
                "unlock",
                "--key",
                "absent.key",
                "--agent-id-file",
                "agent_id",
                "--socket",
                "admin.sock",
            ],
            fixtures::base(),
            Special::None,
        ),
    ];
    for (name, args, put, special) in local {
        for (which, closed_out) in [("stdout", true), ("stderr", false)] {
            let c = Case::new("pipes", format!("pipe.{which}.{name}"), &args)
                .with(put.clone())
                .special(special);
            out.push(if closed_out {
                c.stdout_closed()
            } else {
                c.stderr_closed()
            });
        }
    }
    // Through the mock agent: the table, the JSONL stream and its summary.
    for verb in socket::verbs() {
        if ![
            "status",
            "status-key",
            "detections",
            "fim-report",
            "canary-list",
            "net-flows",
            "response-status",
            "remediate-ransomware",
        ]
        .contains(&verb.name.as_str())
        {
            continue;
        }
        let (label, reply) = verb.success.first().cloned().unwrap();
        let script = || {
            let r = Reply::send(
                format!("{} ({label})", socket::variant_name(&reply)),
                reply.clone(),
            );
            if verb.signed {
                Script::signed(r)
            } else {
                Script::unsigned(r)
            }
        };
        for (which, closed_out) in [("stdout", true), ("stderr", false)] {
            let c = Case::args_owned(
                "pipes",
                format!("pipe.{which}.sock.{}", verb.name),
                verb.args.clone(),
            )
            .with(fixtures::base())
            .special(verb.special)
            .mock(script());
            out.push(if closed_out {
                c.stdout_closed()
            } else {
                c.stderr_closed()
            });
        }
    }
    out
}

/// nn-admin's default paths, with nothing installed: what each command
/// says when the file or the socket it reads by default is not there. Run
/// only where none of `/etc/northnarrow`, `/run/northnarrow`,
/// `/var/lib/northnarrow` exists.
fn defaults() -> Vec<Case> {
    let mut out = Vec::new();
    for (name, args) in [
        ("status", vec!["status"]),
        ("status-json", vec!["status", "--json"]),
        ("net-status", vec!["net", "status"]),
        ("verify-keys", vec!["verify-keys"]),
        ("audit-read", vec!["audit", "read"]),
        (
            "audit-verify",
            vec!["audit", "verify", "--from", "audit.log"],
        ),
        ("chain-verify", vec!["chain", "verify"]),
        (
            "chain-verify-pubkey",
            vec![
                "chain",
                "verify",
                "--agent-pubkey",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            ],
        ),
        ("overlay-status", vec!["config", "overlay", "status"]),
        ("policy-show", vec!["policy", "show"]),
        ("init-pub-append", vec!["init", "--priv-out", "new.key"]),
        (
            "policy-test-config-dir",
            vec!["policy", "test", "--events", "events.jsonl"],
        ),
    ] {
        out.push(
            Case::new("defaults", format!("default.{name}"), &args)
                .with(fixtures::base())
                .with([Put::file("audit.log", fixtures::pin_audit_log(), 0o600)])
                .with([Put::file(
                    "events.jsonl",
                    fixtures::event_stream(false).0,
                    0o644,
                )])
                .host_defaults(),
        );
    }
    // Every signed verb with only its key: the default identity file; and
    // with the identity, the default socket.
    for verb in socket::verbs().into_iter().filter(|v| v.signed) {
        let no_id = replace_flag(
            &replace_flag(&verb.args, "--agent-id-file", None),
            "--socket",
            None,
        );
        out.push(
            Case::args_owned("defaults", format!("default.{}.agent-id", verb.name), no_id)
                .with(fixtures::base())
                .with(verb.put.clone())
                .host_defaults(),
        );
        let no_socket = replace_flag(&verb.args, "--socket", None);
        out.push(
            Case::args_owned(
                "defaults",
                format!("default.{}.socket", verb.name),
                no_socket,
            )
            .with(fixtures::base())
            .with(verb.put.clone())
            .host_defaults(),
        );
    }
    out
}

/// Each socket verb meets every refusal and every transport fault, and a
/// missing and a refusing socket (lab PR 259's 647 socket cases).
pub fn check_socket_coverage(cases: &[Case]) {
    let ids: std::collections::BTreeSet<&str> = cases.iter().map(|c| c.id.as_str()).collect();
    for verb in socket::verbs() {
        let mut want: Vec<String> = Vec::new();
        if verb.signed {
            want.extend(
                socket::refusals()
                    .iter()
                    .map(|(n, _)| format!("refused.{n}")),
            );
            want.extend(
                socket::signed_faults()
                    .iter()
                    .map(|(n, _)| format!("fault.{n}")),
            );
        } else {
            want.extend(
                socket::unsigned_faults()
                    .iter()
                    .map(|(n, _)| format!("fault.{n}")),
            );
        }
        want.push("no-socket".to_string());
        want.push("refused-connection".to_string());
        want.extend(verb.success.iter().map(|(n, _)| n.clone()));
        for w in want {
            let id = format!("sock.{}.{w}", verb.name);
            assert!(ids.contains(id.as_str()), "missing case {id}");
        }
    }
}
