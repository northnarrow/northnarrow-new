//! The commands that need no agent: `init`, `verify-keys`, `host-check`,
//! `audit read|verify`, `chain verify`, `config overlay status|sign`.

use nn_proto::admin_signed_payload::OverlayKind;

use crate::fixtures::{self, AGENT_ID, FIXTURE_TS};
use crate::harness::{Case, Put, Special};

/// A rotating log's files, by name.
type Files = Vec<(String, Vec<u8>)>;

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

pub fn init() -> Vec<Case> {
    let c = |name: &str, args: &[&str], put: Vec<Put>| {
        Case::new("init", format!("init.{name}"), args).with(put)
    };
    let key = "# an old key\n".to_string();
    vec![
        c(
            "fresh-pub-appended",
            &["init", "--priv-out", "new.key", "--pub-append", "admin.pub"],
            fixtures::base(),
        ),
        c(
            "fresh-pub-created",
            &["init", "--priv-out", "new.key", "--pub-append", "new.pub"],
            vec![],
        ),
        c(
            "priv-exists",
            &["init", "--priv-out", "key-a", "--pub-append", "admin.pub"],
            fixtures::base(),
        ),
        c(
            "priv-exists-forced-mode-reset",
            &[
                "init",
                "--priv-out",
                "old.key",
                "--pub-append",
                "admin.pub",
                "--force",
            ],
            vec![
                Put::file("old.key", key.clone(), 0o644),
                Put::file("admin.pub", fixtures::admin_pub(), 0o644),
            ],
        ),
        c(
            "priv-dir-missing",
            &[
                "init",
                "--priv-out",
                "no/such/dir/new.key",
                "--pub-append",
                "new.pub",
            ],
            vec![],
        ),
        c(
            "pub-dir-missing",
            &[
                "init",
                "--priv-out",
                "new.key",
                "--pub-append",
                "no/such/dir/admin.pub",
            ],
            vec![],
        ),
        c(
            "priv-a-symlink",
            &["init", "--priv-out", "link.key", "--pub-append", "new.pub"],
            vec![
                Put::file("target.key", key.clone(), 0o600),
                Put::Link("link.key".into(), "target.key".into()),
            ],
        ),
        c(
            "priv-a-symlink-forced",
            &[
                "init",
                "--priv-out",
                "link.key",
                "--pub-append",
                "new.pub",
                "--force",
            ],
            vec![
                Put::file("target.key", key.clone(), 0o600),
                Put::Link("link.key".into(), "target.key".into()),
            ],
        ),
        c(
            "priv-a-dangling-symlink",
            &["init", "--priv-out", "link.key", "--pub-append", "new.pub"],
            vec![Put::Link("link.key".into(), "nowhere.key".into())],
        ),
        c(
            "pub-a-directory",
            &["init", "--priv-out", "new.key", "--pub-append", "pub.d"],
            vec![Put::Dir("pub.d".into())],
        ),
        c(
            "priv-a-directory-forced",
            &[
                "init",
                "--priv-out",
                "key.d",
                "--pub-append",
                "new.pub",
                "--force",
            ],
            vec![Put::Dir("key.d".into())],
        ),
        c(
            "pub-kept-0600",
            &["init", "--priv-out", "new.key", "--pub-append", "admin.pub"],
            vec![Put::file("admin.pub", fixtures::admin_pub(), 0o600)],
        ),
        c(
            "pub-without-final-newline",
            &["init", "--priv-out", "new.key", "--pub-append", "admin.pub"],
            vec![Put::file(
                "admin.pub",
                fixtures::admin_pub().trim_end(),
                0o644,
            )],
        ),
    ]
}

pub fn verify_keys() -> Vec<Case> {
    let a = fixtures::pub_hex(&fixtures::admin("key-a"));
    let b = fixtures::pub_hex(&fixtures::admin("key-b"));
    let roles = [
        "unlock",
        "shutdown",
        "force-posture",
        "rotate-keys",
        "audit-read",
        "fim-manage",
        "fim-read",
        "canary-read",
        "canary-manage",
        "net-read",
        "net-manage",
        "trusted-installer",
        "telemetry-read",
        "triage",
        "config-manage",
        "response-manage",
    ]
    .join(",");
    let files: Vec<(&str, Vec<u8>)> = vec![
        ("installed", fixtures::admin_pub().into_bytes()),
        ("bare-keys", format!("{a}\n{b}\n").into_bytes()),
        ("every-role", format!("{a} {roles}\n").into_bytes()),
        ("comments-only", b"# nothing installed\n\n".to_vec()),
        ("empty", Vec::new()),
        ("short-key", format!("abcd unlock\n{a} all\n").into_bytes()),
        ("not-hex", format!("{} all\n", "zz".repeat(32)).into_bytes()),
        (
            "not-a-point",
            format!("{} all\n{b}\n", "ff".repeat(32)).into_bytes(),
        ),
        ("unknown-role", format!("{a} unlock,root\n").into_bytes()),
        (
            "empty-role",
            format!("{a} unlock,,audit-read\n").into_bytes(),
        ),
        (
            "roles-without-comma",
            format!("{a} unlock audit-read\n").into_bytes(),
        ),
        (
            "duplicate-key",
            format!("{a} all\n{a} unlock\n").into_bytes(),
        ),
        ("crlf", format!("{a} all\r\n{b} unlock\r\n").into_bytes()),
        (
            "indented-and-trailing-space",
            format!("   {a}   all   \n").into_bytes(),
        ),
        ("not-utf8", vec![0xff, 0xfe, b'\n']),
    ];
    let mut out: Vec<Case> = files
        .into_iter()
        .map(|(name, bytes)| {
            Case::new(
                "verify-keys",
                format!("verify-keys.{name}"),
                &["verify-keys", "--path", "admin.pub"],
            )
            .with([Put::File("admin.pub".into(), bytes, 0o644)])
        })
        .collect();
    out.push(Case::new(
        "verify-keys",
        "verify-keys.missing",
        &["verify-keys", "--path", "absent.pub"],
    ));
    out.push(
        Case::new(
            "verify-keys",
            "verify-keys.a-directory",
            &["verify-keys", "--path", "pub.d"],
        )
        .with([Put::Dir("pub.d".into())]),
    );
    out
}

pub fn host_check() -> Vec<Case> {
    vec![
        Case::new("host-check", "host-check.table", &["host-check"]).special(Special::HostChecks),
        Case::new("host-check", "host-check.json", &["host-check", "--json"])
            .special(Special::HostChecks),
    ]
}

/// The lines of `bytes`, each with its newline.
fn lines(bytes: &[u8]) -> Vec<Vec<u8>> {
    bytes
        .split_inclusive(|b| *b == b'\n')
        .map(<[u8]>::to_vec)
        .collect()
}

/// The classes of a damaged flat chain (lab PR 256's, and a torn tail),
/// made from a good log: by name, the file.
fn flat_classes(good: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    let l = lines(good);
    assert!(l.len() >= 3, "a log of three rows at least");
    let join = |v: &[Vec<u8>]| v.concat();
    let altered = {
        let mut v = l.clone();
        let t = String::from_utf8(v[1].clone()).unwrap();
        // one character of a field changed: the hash no longer recomputes
        let t = t.replacen("\"result\":\"", "\"result\":\"X", 1);
        v[1] = t.into_bytes();
        join(&v)
    };
    let unlinked = join(&[l[0].clone(), l[2].clone()]);
    let malformed = join(&[
        l[0].clone(),
        b"not a row at all\n".to_vec(),
        l[1].clone(),
        l[2].clone(),
    ]);
    let torn = {
        let mut v = join(&l);
        v.truncate(v.len() - 20);
        v
    };
    let not_canonical = {
        let mut v = l.clone();
        let row: serde_json::Value = serde_json::from_slice(&v[1]).unwrap();
        let mut t = serde_json::to_string_pretty(&row)
            .unwrap()
            .replace('\n', " ");
        t.push('\n');
        v[1] = t.into_bytes();
        join(&v)
    };
    let reordered = join(&[l[1].clone(), l[0].clone(), l[2].clone()]);
    let duplicated = join(&[l[0].clone(), l[1].clone(), l[1].clone(), l[2].clone()]);
    let not_utf8 = join(&[l[0].clone(), vec![0xff, 0xfe, b'\n'], l[1].clone()]);
    vec![
        ("content-altered", altered),
        ("link-broken", unlinked),
        ("malformed-line", malformed),
        ("torn-last-line", torn),
        ("not-canonical", not_canonical),
        ("rows-reordered", reordered),
        ("row-duplicated", duplicated),
        ("not-utf8-line", not_utf8),
        ("empty", Vec::new()),
    ]
}

pub fn audit() -> Vec<Case> {
    let pin = fixtures::pin_audit_log();
    let mine = fixtures::audit_log(4, false);
    let other = fixtures::audit_log(4, true);
    let log = |b: &[u8]| Put::File("audit.log".into(), b.to_vec(), 0o600);
    let mut out = Vec::new();
    let read = |name: &str, extra: &[&str], b: &[u8]| {
        let mut a = s(&["audit", "read", "--path", "audit.log"]);
        a.extend(s(extra));
        Case::args_owned("audit", format!("audit-read.{name}"), a).with([log(b)])
    };
    out.push(read("pin", &[], &pin));
    out.push(read("pin-json", &["--json"], &pin));
    out.push(read("matrix-log", &[], &mine));
    out.push(read("matrix-log-json", &["--json"], &mine));
    out.push(read(
        "since-before-every-row",
        &["--since", "2020-01-01T00:00:00Z"],
        &pin,
    ));
    out.push(read(
        "since-after-every-row",
        &["--since", "2030-01-01T00:00:00Z"],
        &pin,
    ));
    out.push(read(
        "since-between-rows",
        &["--since", "2026-10-22T16:33:43.44"],
        &pin,
    ));
    out.push(read("since-not-a-time", &["--since", "yesterday"], &pin));
    out.push(read(
        "since-json",
        &["--since", "2025-06-15T15:06:42Z", "--json"],
        &mine,
    ));
    for (name, b) in flat_classes(&pin) {
        out.push(read(name, &[], &b));
        out.push(read(&format!("{name}-json"), &["--json"], &b));
    }
    {
        // more lines skipped than are listed
        let mut b = pin.clone();
        for i in 0..105 {
            b.extend_from_slice(format!("junk line {i}\n").as_bytes());
        }
        out.push(read("many-lines-skipped", &[], &b));
    }
    {
        let mut b = pin.clone();
        b.extend(std::iter::repeat_n(b'x', 16 * 1024 * 1024 + 1));
        b.push(b'\n');
        out.push(read("line-over-16-mib", &[], &b));
    }
    out.push(Case::new(
        "audit",
        "audit-read.missing",
        &["audit", "read", "--path", "absent.log"],
    ));
    out.push(
        Case::new(
            "audit",
            "audit-read.a-directory",
            &["audit", "read", "--path", "log.d"],
        )
        .with([Put::Dir("log.d".into())]),
    );

    // audit verify
    let agent_pub = fixtures::pub_hex(&fixtures::agent_key());
    let verify = |name: &str, extra: &[&str], b: &[u8], put: Vec<Put>| {
        let mut a = s(&["audit", "verify", "--from", "audit.log"]);
        a.extend(s(extra));
        Case::args_owned("audit", format!("audit-verify.{name}"), a)
            .with([log(b)])
            .with(put)
    };
    let by_pub = ["--agent-pubkey", agent_pub.as_str()];
    out.push(verify("pin-by-pubkey", &by_pub, &pin, vec![]));
    out.push(verify(
        "pin-by-published-key",
        &["--agent-sig-key", "agent.sig.key"],
        &pin,
        fixtures::agent_keys(),
    ));
    out.push(verify(
        "pin-by-private-key-only",
        &["--agent-sig-key", "agent.sig.key"],
        &pin,
        vec![fixtures::agent_keys().remove(0)],
    ));
    out.push(verify(
        "no-key-file",
        &["--agent-sig-key", "agent.sig.key"],
        &pin,
        vec![],
    ));
    out.push(verify(
        "pubkey-short",
        &["--agent-pubkey", "abcd"],
        &pin,
        vec![],
    ));
    out.push(verify(
        "pubkey-not-hex",
        &["--agent-pubkey", &"zz".repeat(32)],
        &pin,
        vec![],
    ));
    out.push(verify(
        "pubkey-not-a-point",
        &["--agent-pubkey", &"ff".repeat(32)],
        &pin,
        vec![],
    ));
    out.push(verify(
        "pubkey-with-newline",
        &["--agent-pubkey", &format!("{agent_pub}\n")],
        &pin,
        vec![],
    ));
    out.push(verify(
        "wrong-key",
        &[
            "--agent-pubkey",
            &fixtures::pub_hex(&fixtures::admin("key-a")),
        ],
        &pin,
        vec![],
    ));
    out.push(verify("matrix-log", &by_pub, &mine, vec![]));
    out.push(verify("another-agents-key", &by_pub, &other, vec![]));
    let heads: Vec<String> = lines(&pin)
        .iter()
        .map(|l| {
            serde_json::from_slice::<serde_json::Value>(l).unwrap()["entry_hash"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    let with_pub = |extra: &[&str]| -> Vec<String> {
        let mut v = by_pub.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        v.extend(s(extra));
        v
    };
    for (name, extra) in [
        (
            "expect-head-the-last",
            with_pub(&["--expect-head", &heads[2]]),
        ),
        (
            "expect-head-an-earlier",
            with_pub(&["--expect-head", &heads[0]]),
        ),
        (
            "expect-head-gone",
            with_pub(&["--expect-head", &"ee".repeat(32)]),
        ),
        ("min-seq-held", with_pub(&["--min-seq", "2"])),
        ("min-seq-not-reached", with_pub(&["--min-seq", "3"])),
        (
            "expect-head-and-min-seq",
            with_pub(&["--expect-head", &heads[1], "--min-seq", "1"]),
        ),
    ] {
        let extra: Vec<&str> = extra.iter().map(String::as_str).collect();
        out.push(verify(name, &extra, &pin, vec![]));
    }
    for (name, b) in flat_classes(&pin) {
        out.push(verify(name, &by_pub, &b, vec![]));
    }
    out.push(Case::new(
        "audit",
        "audit-verify.missing",
        &[
            "audit",
            "verify",
            "--from",
            "absent.log",
            "--agent-pubkey",
            &agent_pub,
        ],
    ));
    out
}

/// The head anchor of `files`' audit log at its last row, written and
/// signed by the agent key, as the agent writes it.
fn heads_for(audit: &[u8]) -> Vec<u8> {
    use northnarrow_agent::chain_anchor::{AnchoredHead, FileHead, HeadsSnapshot, HeadsStore};
    let last: serde_json::Value = serde_json::from_slice(lines(audit).last().unwrap()).unwrap();
    let snap = HeadsSnapshot {
        counter: 1,
        ts: "2025-06-15T15:06:40.000000Z".to_string(),
        agent_id: hex::encode(AGENT_ID),
        second_key_added: false,
        heads: vec![AnchoredHead {
            chain: "audit".to_string(),
            path: "audit.log".to_string(),
            generation: None,
            head: FileHead {
                bytes: audit.len() as u64,
                tail_hash: last["entry_hash"].as_str().unwrap().to_string(),
                seq: last["seq"].as_u64(),
            },
        }],
    };
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("chain_heads.json");
    let kd = tempfile::tempdir().unwrap();
    let kp = kd.path().join("k");
    std::fs::write(&kp, format!("{}\n", fixtures::AGENT_KEY_HEX)).unwrap();
    let key = northnarrow_agent::audit::read_signing_key(&kp).unwrap();
    HeadsStore::write(&p, &key, &snap).unwrap();
    std::fs::read(&p).unwrap()
}

pub fn chain() -> Vec<Case> {
    let pin = fixtures::pin_audit_log();
    let agent_pub = fixtures::pub_hex(&fixtures::agent_key());
    let base_args = |extra: &[&str]| {
        let mut a = s(&[
            "chain",
            "verify",
            "--state-dir",
            ".",
            "--audit-log",
            "audit.log",
        ]);
        a.extend(s(extra));
        a
    };
    let by_key = ["--agent-sig-key", "agent.sig.key"];
    let c = |name: &str, args: Vec<String>, put: Vec<Put>| {
        Case::args_owned("chain", format!("chain.{name}"), args)
            .with(fixtures::agent_keys())
            .with(put)
    };
    let audit = |b: &[u8]| Put::File("audit.log".into(), b.to_vec(), 0o600);
    let fim = |files: Files| -> Vec<Put> {
        files
            .into_iter()
            .map(|(n, b)| Put::File(n, b, 0o600))
            .collect()
    };
    let mut out = vec![
        c("pin-audit-only", base_args(&by_key), vec![audit(&pin)]),
        c(
            "pin-audit-by-pubkey",
            base_args(&["--agent-pubkey", &agent_pub]),
            vec![audit(&pin)],
        ),
        c(
            "pin-heads-of-another-layout",
            base_args(&by_key),
            vec![
                audit(&pin),
                Put::File("chain_heads.json".into(), fixtures::pin_heads(), 0o600),
            ],
        ),
        c(
            "heads-reached",
            base_args(&by_key),
            vec![
                audit(&pin),
                Put::File("chain_heads.json".into(), heads_for(&pin), 0o600),
            ],
        ),
    ];
    {
        let cut: Vec<u8> = lines(&pin)[..2].concat();
        out.push(c(
            "heads-not-reached-chain-truncated",
            base_args(&by_key),
            vec![
                audit(&cut),
                Put::File("chain_heads.json".into(), heads_for(&pin), 0o600),
            ],
        ));
    }
    out.push(c(
        "heads-named-elsewhere",
        base_args(&[by_key[0], by_key[1], "--heads", "anchors/heads.json"]),
        vec![
            audit(&pin),
            Put::File("anchors/heads.json".into(), heads_for(&pin), 0o600),
        ],
    ));
    out.push(c(
        "heads-absent-named",
        base_args(&[by_key[0], by_key[1], "--heads", "absent.json"]),
        vec![audit(&pin)],
    ));
    out.push(c(
        "heads-not-json",
        base_args(&by_key),
        vec![
            audit(&pin),
            Put::file("chain_heads.json", "{not json\n", 0o600),
        ],
    ));
    out.push(c("no-audit-log", base_args(&by_key), vec![]));
    for (name, b) in flat_classes(&pin) {
        out.push(c(
            &format!("audit.{name}"),
            base_args(&by_key),
            vec![audit(&b)],
        ));
    }
    out.push(c(
        "audit.another-agents-key",
        base_args(&by_key),
        vec![audit(&fixtures::audit_log(4, true))],
    ));
    // Every chain on its own, and two together.
    for log in [
        "audit",
        "canary-registry",
        "canary-access",
        "detections",
        "status-events",
        "netflow",
        "fim-drift",
        "all",
    ] {
        out.push(c(
            &format!("only.{log}"),
            base_args(&[by_key[0], by_key[1], "--log", log]),
            [vec![audit(&pin)], fim(fixtures::fim_drift_log(12, false))].concat(),
        ));
    }
    out.push(c(
        "only.audit-and-fim-drift",
        base_args(&[by_key[0], by_key[1], "--log", "audit", "--log", "fim-drift"]),
        [vec![audit(&pin)], fim(fixtures::fim_drift_log(12, false))].concat(),
    ));
    out.push(c(
        "only.all-and-audit",
        base_args(&[by_key[0], by_key[1], "--log", "all", "--log", "audit"]),
        vec![audit(&pin)],
    ));
    // The rotating FIM drift log: intact, and its classes.
    let good = fixtures::fim_drift_log(12, false);
    out.push(c(
        "fim-drift.intact",
        base_args(&by_key),
        [vec![audit(&pin)], fim(good.clone())].concat(),
    ));
    out.push(c(
        "fim-drift.another-agents-key",
        base_args(&by_key),
        [vec![audit(&pin)], fim(fixtures::fim_drift_log(12, true))].concat(),
    ));
    let mutate = |name: &str, f: &dyn Fn(&mut Files)| {
        let mut files = good.clone();
        f(&mut files);
        c(
            &format!("fim-drift.{name}"),
            base_args(&by_key),
            [vec![audit(&pin)], fim(files)].concat(),
        )
    };
    let active = |files: &mut Files| -> usize {
        files
            .iter()
            .position(|(n, _)| n == "fim_drift.jsonl")
            .expect("the active file")
    };
    out.push(mutate("active-row-altered", &|files| {
        let i = active(files);
        let t = String::from_utf8(files[i].1.clone()).unwrap();
        files[i].1 = t.replacen("vim", "vix", 1).into_bytes();
    }));
    out.push(mutate("active-row-removed", &|files| {
        let i = active(files);
        let mut l = lines(&files[i].1);
        if l.len() > 1 {
            l.remove(0);
        }
        files[i].1 = l.concat();
    }));
    out.push(mutate("active-torn", &|files| {
        let i = active(files);
        let n = files[i].1.len();
        files[i].1.truncate(n.saturating_sub(15));
    }));
    out.push(mutate("active-malformed-line", &|files| {
        let i = active(files);
        let mut l = lines(&files[i].1);
        l.insert(0, b"garbage\n".to_vec());
        files[i].1 = l.concat();
    }));
    out.push(mutate("archive-missing", &|files| {
        files.retain(|(n, _)| !n.ends_with(".000001"));
    }));
    out.push(mutate("archive-altered", &|files| {
        if let Some(f) = files.iter_mut().find(|(n, _)| n.ends_with(".000001")) {
            let t = String::from_utf8(f.1.clone()).unwrap();
            f.1 = t.replacen("file0", "file9", 1).into_bytes();
        }
    }));
    out.push(mutate("manifest-missing", &|files| {
        files.retain(|(n, _)| !n.ends_with(".manifest.jsonl"));
    }));
    out.push(mutate("manifest-altered", &|files| {
        if let Some(f) = files
            .iter_mut()
            .find(|(n, _)| n.ends_with(".manifest.jsonl"))
        {
            let t = String::from_utf8(f.1.clone()).unwrap();
            f.1 = t.replacen("\"records\":", "\"records\":1", 1).into_bytes();
        }
    }));
    out.push(mutate("manifest-last-row-removed", &|files| {
        if let Some(f) = files
            .iter_mut()
            .find(|(n, _)| n.ends_with(".manifest.jsonl"))
        {
            let mut l = lines(&f.1);
            l.pop();
            f.1 = l.concat();
        }
    }));
    out.push(mutate("active-not-canonical", &|files| {
        let i = active(files);
        let mut l = lines(&files[i].1);
        if let Some(first) = l.first_mut() {
            let v: serde_json::Value = serde_json::from_slice(first).unwrap();
            let mut t = serde_json::to_string_pretty(&v).unwrap().replace('\n', " ");
            t.push('\n');
            *first = t.into_bytes();
        }
        files[i].1 = l.concat();
    }));
    out.push(mutate("only-the-active-file", &|files| {
        files.retain(|(n, _)| n == "fim_drift.jsonl");
    }));
    // A key nn-admin cannot read: the chain is not verified.
    out.push(Case::args_owned("chain", "chain.no-key", base_args(&by_key)).with([audit(&pin)]));
    out.push(
        Case::args_owned("chain", "chain.published-key-not-hex", base_args(&by_key))
            .with([audit(&pin), Put::file("agent.sig.pub", "not hex\n", 0o444)]),
    );
    out.push(
        Case::args_owned("chain", "chain.state-dir-missing", {
            let mut a = s(&[
                "chain",
                "verify",
                "--state-dir",
                "no/such",
                "--audit-log",
                "audit.log",
            ]);
            a.extend(s(&by_key));
            a
        })
        .with(fixtures::agent_keys())
        .with([audit(&pin)]),
    );
    out
}

pub fn overlay() -> Vec<Case> {
    let mut out = Vec::new();
    let status_args = s(&[
        "config",
        "overlay",
        "status",
        "--dir",
        "etc",
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
            vec![
                Put::Dir("etc".into()),
                Put::File("audit.log".into(), fixtures::audit_log(4, false), 0o600),
            ],
        ]
        .concat()
    };
    let content = b"# matrix overlay\nbackup-tool\n".to_vec();
    let pcl = OverlayKind::ProcessCommAllowlist;
    let signed =
        |kind: OverlayKind, content: &[u8], signers: &[&str], ts: u64, id: [u8; 16]| -> Vec<Put> {
            vec![
                Put::File(format!("etc/{}", kind.file_name()), content.to_vec(), 0o644),
                Put::File(
                    format!("etc/{}.sig", kind.file_name()),
                    fixtures::overlay_sig(kind, content, signers, ts, id).into_bytes(),
                    0o644,
                ),
            ]
        };
    let st = |name: &str, put: Vec<Put>| {
        Case::args_owned(
            "overlay",
            format!("overlay-status.{name}"),
            status_args.clone(),
        )
        .with(base())
        .with(put)
    };
    out.push(st("nothing-present", vec![]));
    out.push(st(
        "signed-by-key-a",
        signed(pcl, &content, &["key-a"], FIXTURE_TS, AGENT_ID),
    ));
    out.push(st(
        "signed-by-two-keys",
        signed(pcl, &content, &["key-a", "key-b"], FIXTURE_TS, AGENT_ID),
    ));
    out.push(st(
        "signed-by-key-b-without-config-manage",
        signed(pcl, &content, &["key-b"], FIXTURE_TS, AGENT_ID),
    ));
    out.push(st(
        "signed-by-an-uninstalled-key",
        signed(pcl, &content, &["key-c"], FIXTURE_TS, AGENT_ID),
    ));
    out.push(st(
        "signed-for-another-install",
        signed(pcl, &content, &["key-a"], FIXTURE_TS, [0x22; 16]),
    ));
    out.push(st(
        "signed-at-time-zero",
        signed(pcl, &content, &["key-a"], 0, AGENT_ID),
    ));
    {
        let mut p = signed(pcl, &content, &["key-a"], FIXTURE_TS, AGENT_ID);
        p[0] = Put::File(
            format!("etc/{}", pcl.file_name()),
            b"# matrix overlay\nbackup-tool\nnc\n".to_vec(),
            0o644,
        );
        out.push(st("content-changed-after-signing", p));
    }
    out.push(st(
        "unsigned",
        vec![Put::File(
            format!("etc/{}", pcl.file_name()),
            content.clone(),
            0o644,
        )],
    ));
    out.push(st(
        "signature-not-json",
        vec![
            Put::File(format!("etc/{}", pcl.file_name()), content.clone(), 0o644),
            Put::file(
                &format!("etc/{}.sig", pcl.file_name()),
                "{not json\n",
                0o644,
            ),
        ],
    ));
    {
        // a signature of another kind's payload over the same bytes
        let mut p = signed(
            OverlayKind::FimPaths,
            &content,
            &["key-a"],
            FIXTURE_TS,
            AGENT_ID,
        );
        p[0] = Put::File(format!("etc/{}", pcl.file_name()), content.clone(), 0o644);
        p[1] = Put::File(
            format!("etc/{}.sig", pcl.file_name()),
            fixtures::overlay_sig(
                OverlayKind::FimPaths,
                &content,
                &["key-a"],
                FIXTURE_TS,
                AGENT_ID,
            )
            .into_bytes(),
            0o644,
        );
        out.push(st("signature-of-another-kind", p));
    }
    out.push(st(
        "not-utf8",
        signed(pcl, &[0xff, 0xfe, b'\n'], &["key-a"], FIXTURE_TS, AGENT_ID),
    ));
    out.push(st(
        "shipped-combat-defaults",
        vec![
            Put::File(
                "etc/combat-rules.v4".into(),
                fixtures::read_repo("configs/combat-rules.v4"),
                0o644,
            ),
            Put::File(
                "etc/combat-rules.v6".into(),
                fixtures::read_repo("configs/combat-rules.v6"),
                0o644,
            ),
            Put::File(
                "etc/combat-allow.cidrs".into(),
                fixtures::read_repo("configs/combat-allow.cidrs"),
                0o644,
            ),
        ],
    ));
    out.push(st(
        "combat-allow-unsigned",
        vec![Put::file("etc/combat-allow.cidrs", "10.0.0.0/8\n", 0o644)],
    ));
    out.push(st(
        "combat-allow-signed-with-dropped-lines",
        signed(
            OverlayKind::CombatAllow,
            b"0.0.0.0/0\n10.0.0.0/8\n",
            &["key-a"],
            FIXTURE_TS,
            AGENT_ID,
        ),
    ));
    {
        let mut p = Vec::new();
        for kind in OverlayKind::ALL {
            p.extend(signed(
                kind,
                b"# matrix: comments only\n",
                &["key-a"],
                FIXTURE_TS,
                AGENT_ID,
            ));
        }
        out.push(st("every-kind-signed", p));
    }
    out.push(
        Case::args_owned(
            "overlay",
            "overlay-status.audit-log-missing",
            status_args.clone(),
        )
        .with(
            [
                fixtures::base(),
                fixtures::agent_keys(),
                vec![Put::Dir("etc".into())],
            ]
            .concat(),
        )
        .with(signed(pcl, &content, &["key-a"], FIXTURE_TS, AGENT_ID)),
    );
    out.push(
        Case::args_owned(
            "overlay",
            "overlay-status.audit-chain-broken",
            status_args.clone(),
        )
        .with(
            [
                fixtures::base(),
                fixtures::agent_keys(),
                vec![Put::Dir("etc".into())],
            ]
            .concat(),
        )
        .with([Put::File(
            "audit.log".into(),
            flat_classes(&fixtures::audit_log(4, false))[0].1.clone(),
            0o600,
        )])
        .with(signed(pcl, &content, &["key-a"], FIXTURE_TS, AGENT_ID)),
    );
    out.push(
        Case::args_owned(
            "overlay",
            "overlay-status.agent-key-missing",
            status_args.clone(),
        )
        .with(
            [
                fixtures::base(),
                vec![
                    Put::Dir("etc".into()),
                    Put::File("audit.log".into(), fixtures::audit_log(4, false), 0o600),
                ],
            ]
            .concat(),
        )
        .with(signed(pcl, &content, &["key-a"], FIXTURE_TS, AGENT_ID)),
    );
    out.push(
        Case::args_owned(
            "overlay",
            "overlay-status.admin-pub-missing",
            status_args.clone(),
        )
        .with(base())
        .with([Put::file("admin.pub", "", 0o644)])
        .with(signed(pcl, &content, &["key-a"], FIXTURE_TS, AGENT_ID)),
    );
    out.push(
        Case::args_owned("overlay", "overlay-status.agent-id-missing", {
            let mut a = status_args.clone();
            let i = a.iter().position(|x| x == "agent_id").unwrap();
            a[i] = "absent_id".to_string();
            a
        })
        .with(base()),
    );
    out.push(
        Case::args_owned("overlay", "overlay-status.dir-missing", {
            let mut a = status_args.clone();
            let i = a.iter().position(|x| x == "etc").unwrap();
            a[i] = "no/such".to_string();
            a
        })
        .with(base()),
    );

    // config overlay sign (offline)
    let sign = |name: &str, kind: &str, extra: &[&str], put: Vec<Put>| {
        let mut a = s(&[
            "config",
            "overlay",
            "sign",
            kind,
            "--file",
            "overlay.local",
            "--key",
            "key-a",
            "--agent-id-file",
            "agent_id",
        ]);
        a.extend(s(extra));
        Case::args_owned("overlay", format!("overlay-sign.{name}"), a)
            .with(fixtures::base())
            .with(put)
    };
    let comments = || {
        vec![Put::file(
            "overlay.local",
            "# matrix: comments only\n",
            0o644,
        )]
    };
    for kind in OverlayKind::ALL {
        out.push(sign(
            &format!("kind.{}", kind.keyword()),
            kind.keyword(),
            &[],
            comments(),
        ));
    }
    out.push(sign(
        "to-out",
        "fim-paths",
        &["--out", "elsewhere.sig"],
        comments(),
    ));
    out.push(sign(
        "out-dir-missing",
        "fim-paths",
        &["--out", "no/such/x.sig"],
        comments(),
    ));
    out.push(sign(
        "with-cosigner",
        "fim-paths",
        &["--cosign-key", "key-b"],
        comments(),
    ));
    out.push(sign(
        "cosigner-missing",
        "fim-paths",
        &["--cosign-key", "absent.key"],
        comments(),
    ));
    out.push(sign("unknown-kind", "no-such-list", &[], comments()));
    out.push(sign(
        "kind-by-file-name",
        "process-comm-allowlist.local",
        &[],
        comments(),
    ));
    out.push(sign("file-missing", "fim-paths", &[], vec![]));
    out.push(sign(
        "file-too-big",
        "fim-paths",
        &[],
        vec![Put::file("overlay.local", "#".repeat(32 * 1024 + 1), 0o644)],
    ));
    out.push(sign(
        "file-not-utf8",
        "fim-paths",
        &[],
        vec![Put::file("overlay.local", [0xff, 0xfe, b'\n'], 0o644)],
    ));
    out.push(sign(
        "rule-policy-bad-line",
        "rule-policy",
        &[],
        vec![Put::file("overlay.local", "enforce NO-SUCH-RULE\n", 0o644)],
    ));
    out.push(sign(
        "rule-policy-exempts-uid-0",
        "rule-policy",
        &[],
        vec![Put::file(
            "overlay.local",
            "enforce R020\nexempt R020 uid 0\n",
            0o644,
        )],
    ));
    out.push(sign(
        "rule-policy-good",
        "rule-policy",
        &[],
        vec![Put::file("overlay.local", "enforce NN-L-IMP-001\n", 0o644)],
    ));
    out.push(sign(
        "fim-paths-relative",
        "fim-paths",
        &[],
        vec![Put::file("overlay.local", "etc/passwd\n", 0o644)],
    ));
    out.push(sign(
        "combat-rules-v4-garbage",
        "combat-rules-v4",
        &[],
        vec![Put::file(
            "overlay.local",
            "-A INPUT -j DROP; rm -rf /\n",
            0o644,
        )],
    ));
    out.push(sign(
        "combat-allow-wide",
        "combat-allow",
        &[],
        vec![Put::file("overlay.local", "0.0.0.0/0\n", 0o644)],
    ));
    out.push(sign(
        "netflow-blocklist-bad-cidr",
        "netflow-blocklist",
        &[],
        vec![Put::file("overlay.local", "300.1.2.3/40\n", 0o644)],
    ));
    out.push(sign(
        "execq-hashes-bad",
        "execq-hashes",
        &[],
        vec![Put::file("overlay.local", "not-a-hash\n", 0o644)],
    ));
    out.push(
        sign("key-missing", "fim-paths", &[], comments()).with([Put::file("key-a", "", 0o600)]),
    );
    {
        let mut a = s(&[
            "config",
            "overlay",
            "sign",
            "fim-paths",
            "--file",
            "overlay.local",
            "--key",
            "key-a",
            "--agent-id-file",
            "absent_id",
        ]);
        a.truncate(a.len());
        out.push(
            Case::args_owned("overlay", "overlay-sign.agent-id-missing", a)
                .with(fixtures::base())
                .with(comments()),
        );
    }
    out
}
