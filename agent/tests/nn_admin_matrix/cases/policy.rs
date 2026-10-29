//! `policy show` and `policy test` (lab PR 259's 520 replays and 16 errors;
//! `policy set` is a socket verb).
//!
//! `policy test`: the 24 golden cases of the decision replay, and their 205
//! events as two streams (plain and `{"event": …}`-wrapped) — 26 inputs —
//! under the built-in defaults, the three golden candidates and one that is
//! refused (it exempts uid 0) — 5 policies —, with the shipped lists and
//! with none, as a table and as JSON: 26 × 5 × 2 × 2 = 520.

use nn_proto::admin_signed_payload::OverlayKind;

use crate::fixtures::{self, AGENT_ID, FIXTURE_TS};
use crate::harness::{Case, Put};

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

pub fn cases() -> Vec<Case> {
    let mut out = show();
    out.extend(test());
    out
}

fn show() -> Vec<Case> {
    let args = s(&[
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
    ]);
    let base = || -> Vec<Put> {
        [
            fixtures::base(),
            fixtures::agent_keys(),
            vec![Put::File(
                "audit.log".into(),
                fixtures::audit_log(4, false),
                0o600,
            )],
        ]
        .concat()
    };
    let signed = |text: &str, signers: &[&str], id: [u8; 16]| -> Vec<Put> {
        vec![
            Put::file("rule-policy.local", text, 0o644),
            Put::File(
                "rule-policy.local.sig".into(),
                fixtures::overlay_sig(
                    OverlayKind::RulePolicy,
                    text.as_bytes(),
                    signers,
                    FIXTURE_TS,
                    id,
                )
                .into_bytes(),
                0o644,
            ),
        ]
    };
    let c = |name: &str, put: Vec<Put>| {
        Case::args_owned("policy", format!("policy-show.{name}"), args.clone())
            .with(base())
            .with(put)
    };
    let mut out = vec![
        c("absent", vec![]),
        c("signed", signed("# matrix\nenforce NN-L-IMP-001\nalert R020\n", &["key-a"], AGENT_ID)),
        c("signed-every-mode", signed(
            "enforce NN-L-IMP-001\nalert R020\naudit NN-L-FIM-004\noff NN-L-NET-026\nexempt R020 uid 33\n",
            &["key-a"],
            AGENT_ID,
        )),
        c("signed-but-refused-exempts-uid-0", signed("enforce R020\nexempt R020 uid 0\n", &["key-a"], AGENT_ID)),
        c("signed-for-another-install", signed("enforce NN-L-IMP-001\n", &["key-a"], [0x22; 16])),
        c("signed-by-key-b", signed("enforce NN-L-IMP-001\n", &["key-b"], AGENT_ID)),
        c("unsigned", vec![Put::file("rule-policy.local", "enforce NN-L-IMP-001\n", 0o644)]),
        c(
            "content-changed",
            {
                let mut p = signed("enforce NN-L-IMP-001\n", &["key-a"], AGENT_ID);
                p[0] = Put::file("rule-policy.local", "enforce NN-L-IMP-001\nenforce R020\n", 0o644);
                p
            },
        ),
    ];
    out.push(
        Case::args_owned("policy", "policy-show.agent-id-missing", {
            let mut a = args.clone();
            let i = a.iter().position(|x| x == "agent_id").unwrap();
            a[i] = "absent_id".into();
            a
        })
        .with(base()),
    );
    out.push(
        Case::args_owned("policy", "policy-show.audit-log-missing", args.clone())
            .with([fixtures::base(), fixtures::agent_keys()].concat())
            .with(signed("enforce NN-L-IMP-001\n", &["key-a"], AGENT_ID)),
    );
    out
}

fn test() -> Vec<Case> {
    let (plain, n_plain) = fixtures::event_stream(false);
    let (wrapped, n_wrapped) = fixtures::event_stream(true);
    assert_eq!(n_plain, n_wrapped);
    let mut inputs: Vec<(String, Vec<u8>)> = fixtures::golden_cases()
        .into_iter()
        .map(|(name, bytes)| (format!("case.{name}"), bytes))
        .collect();
    inputs.push(("stream.plain".to_string(), plain.into_bytes()));
    inputs.push(("stream.wrapped".to_string(), wrapped.into_bytes()));
    let mut policies: Vec<(String, Option<String>)> = vec![("builtin".to_string(), None)];
    for (name, text) in fixtures::golden_candidates() {
        policies.push((format!("candidate.{name}"), Some(text)));
    }
    policies.push((
        "refused.exempts-uid-0".to_string(),
        Some("enforce R020\nexempt R020 uid 0\n".to_string()),
    ));
    let mut out = Vec::new();
    for (input, events) in &inputs {
        for (pname, policy) in &policies {
            for (lists, dir) in [("shipped-lists", "configs"), ("no-lists", "empty")] {
                for json in [false, true] {
                    let mut args = s(&[
                        "policy",
                        "test",
                        "--events",
                        "events.json",
                        "--config-dir",
                        dir,
                    ]);
                    let mut put = vec![Put::File("events.json".into(), events.clone(), 0o644)];
                    if let Some(p) = policy {
                        args.extend(s(&["--policy", "candidate.local"]));
                        put.push(Put::file("candidate.local", p, 0o644));
                    }
                    if json {
                        args.push("--json".to_string());
                    }
                    if dir == "configs" {
                        put.extend(fixtures::shipped_lists());
                    } else {
                        put.push(Put::Dir("empty".into()));
                    }
                    out.push(
                        Case::args_owned(
                            "policy",
                            format!(
                                "policy-test.{input}.{pname}.{lists}.{}",
                                if json { "json" } else { "table" }
                            ),
                            args,
                        )
                        .with(put),
                    );
                }
            }
        }
    }
    // The errors.
    let e = |name: &str, args: &[&str], put: Vec<Put>| {
        Case::new("policy", format!("policy-test.error.{name}"), args).with(put)
    };
    let ev = || {
        Put::File(
            "events.json".into(),
            fixtures::event_stream(false).0.into_bytes(),
            0o644,
        )
    };
    let t = [
        "policy",
        "test",
        "--events",
        "events.json",
        "--config-dir",
        "empty",
    ];
    let dir = || Put::Dir("empty".into());
    let with = |extra: &[&'static str]| -> Vec<&'static str> {
        let mut v: Vec<&'static str> = t.to_vec();
        v.extend_from_slice(extra);
        v
    };
    out.extend([
        e("events-missing", &t, vec![dir()]),
        e(
            "events-a-directory",
            &t,
            vec![dir(), Put::Dir("events.json".into())],
        ),
        e(
            "events-empty",
            &t,
            vec![dir(), Put::file("events.json", "", 0o644)],
        ),
        e(
            "events-not-json",
            &t,
            vec![dir(), Put::file("events.json", "not json\n", 0o644)],
        ),
        e(
            "events-a-line-not-an-event",
            &t,
            vec![
                dir(),
                Put::file("events.json", "{\"kind\":\"nothing\"}\n", 0o644),
            ],
        ),
        e(
            "events-wrapped-not-an-event",
            &t,
            vec![
                dir(),
                Put::file("events.json", "{\"event\":{\"x\":1}}\n", 0o644),
            ],
        ),
        e(
            "events-blank-lines",
            &t,
            vec![dir(), Put::file("events.json", "\n\n\n", 0o644)],
        ),
        e(
            "events-not-utf8",
            &t,
            vec![dir(), Put::file("events.json", [0xff, 0xfe, b'\n'], 0o644)],
        ),
        e(
            "case-without-items",
            &t,
            vec![
                dir(),
                Put::file("events.json", "{\"about\":\"none\",\"items\":[]}\n", 0o644),
            ],
        ),
        e(
            "case-only-non-events",
            &t,
            vec![
                dir(),
                Put::file(
                    "events.json",
                    "{\"about\":\"x\",\"items\":[{\"tcp_sweep\":{}}]}\n",
                    0o644,
                ),
            ],
        ),
        e(
            "policy-missing",
            &with(&["--policy", "absent.local"]),
            vec![dir(), ev()],
        ),
        e(
            "policy-bad-line",
            &with(&["--policy", "candidate.local"]),
            vec![
                dir(),
                ev(),
                Put::file("candidate.local", "enforce\n", 0o644),
            ],
        ),
        e(
            "policy-unknown-rule",
            &with(&["--policy", "candidate.local"]),
            vec![
                dir(),
                ev(),
                Put::file("candidate.local", "enforce NO-SUCH-RULE\n", 0o644),
            ],
        ),
        e(
            "policy-unknown-mode",
            &with(&["--policy", "candidate.local"]),
            vec![
                dir(),
                ev(),
                Put::file("candidate.local", "panic R020\n", 0o644),
            ],
        ),
        e(
            "policy-empty",
            &with(&["--policy", "candidate.local"]),
            vec![dir(), ev(), Put::file("candidate.local", "", 0o644)],
        ),
        e(
            "config-dir-missing",
            &[
                "policy",
                "test",
                "--events",
                "events.json",
                "--config-dir",
                "no/such",
            ],
            vec![ev()],
        ),
        e(
            "config-dir-a-file",
            &[
                "policy",
                "test",
                "--events",
                "events.json",
                "--config-dir",
                "events.json",
            ],
            vec![ev()],
        ),
        e(
            "crlf-stream",
            &t,
            vec![
                dir(),
                Put::File(
                    "events.json".into(),
                    fixtures::event_stream(false)
                        .0
                        .replace('\n', "\r\n")
                        .into_bytes(),
                    0o644,
                ),
            ],
        ),
    ]);
    out
}
