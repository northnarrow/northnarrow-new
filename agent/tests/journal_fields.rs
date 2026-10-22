//! External audit, Wave 3: journal line injection (NN-AUD-413, lab PR 167).
//!
//! Two checks. A log line with a file name that holds `\n` and a forged
//! `ANTI-TAMPER DENIAL` stays one line, formatted the way the agent formats
//! it (fmt layer, no target, no colours, through `OneLine`). And no field
//! that carries a value another user names is logged with `%` (Display)
//! unless it goes through `nn_model::log_escape::Escaped`: a source scan of
//! every workspace member (`cargo metadata`; the agent and the watchdog
//! until lab PR 239), so a new `comm = %comm` fails here.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use nn_model::log_escape::{Escaped, OneLine};

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl io::Write for Buf {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// What `f` logs, formatted as the agent's subscriber formats it.
fn logged(f: impl FnOnce()) -> String {
    let buf = Buf::default();
    let sink = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_target(false)
        .with_ansi(false)
        .with_writer(move || OneLine::new(sink.clone(), false))
        .finish();
    tracing::subscriber::with_default(subscriber, f);
    let out = buf.0.lock().unwrap().clone();
    String::from_utf8(out).unwrap()
}

const FORGED: &str = "/tmp/x\n2026-10-16T00:00:00.000000Z  WARN ANTI-TAMPER DENIAL pid=1 uid=0 \
                      comm=bash op=signal target_dev=9 target_ino=1";

fn assert_one_line(out: &str) {
    // one event, one line: the forged entry is text inside it, never the
    // start of a line of its own
    assert_eq!(out.matches('\n').count(), 1, "{out:?}");
    assert!(out.ends_with('\n'), "{out:?}");
    assert!(!out.contains("\n2026-10-16T00:00:00.000000Z"), "{out:?}");
    assert!(!out.contains("\nANTI-TAMPER"), "{out:?}");
}

#[test]
fn a_file_name_with_a_newline_stays_on_its_line() {
    let out = logged(|| {
        tracing::warn!(
            rule = "R001_ExecFromTmp",
            target_pid = 4242u32,
            target_filename = %Escaped(FORGED),
            comm = %Escaped("x\nVERDICT"),
            "VERDICT (rule)"
        )
    });
    assert_one_line(&out);
    assert!(
        out.contains(
            r#"target_filename="/tmp/x\n2026-10-16T00:00:00.000000Z  WARN ANTI-TAMPER DENIAL pid=1"#
        ),
        "{out}"
    );
    assert!(out.contains(r#"comm="x\nVERDICT""#), "{out}");
    // a plain value prints as it did
    let out =
        logged(|| tracing::warn!(comm = %Escaped("bash"), path = %Escaped("/etc/passwd"), "x"));
    assert!(out.contains("comm=bash path=/etc/passwd"), "{out}");
}

/// The line guard holds for what no field rule covers: a raw `%` value, a
/// message built with `format!`, an error that quotes a path.
#[test]
fn the_line_guard_catches_what_a_field_does_not() {
    let out = logged(|| tracing::warn!(target_filename = %FORGED, "VERDICT (rule)"));
    assert_one_line(&out);
    let out = logged(|| tracing::warn!("open {} failed", FORGED));
    assert_one_line(&out);
    let err = io::Error::other(format!("rename {FORGED}: EPERM"));
    let out = logged(|| tracing::warn!(error = %err, "quarantine I/O failed"));
    assert_one_line(&out);
    let out = logged(|| tracing::warn!(nul = %"a\0b\rc", "x"));
    assert_one_line(&out);
    assert!(out.contains(r"nul=a\x00b\rc"), "{out}");
}

// ── the source scan ─────────────────────────────────────────────────────

/// Field names whose value another user names: the `comm` of any process,
/// the files it runs, opens or writes, its DNS names, the canaries it
/// touches, the rule and model text that quotes them, the cgroup it left.
fn attacker_named(file: &str, name: &str) -> bool {
    const NAMES: &[&str] = &[
        "comm",
        "filename",
        "query",
        "query_name",
        "canary_name",
        "reasoning",
        "argv",
        "cmdline",
        "image",
        "hop",
        "origin",
    ];
    // Files where every `path` is a path another user named: the FIM
    // drain (files in watched directories), the quarantine (the binary a
    // process ran).
    const PATH_FILES: &[(&str, &[&str])] = &[
        ("src/fim/drain.rs", &["path"]),
        ("src/response/quarantine.rs", &["path", "out"]),
    ];
    NAMES.contains(&name)
        || name.ends_with("_comm")
        || name.ends_with("_filename")
        || PATH_FILES
            .iter()
            .any(|(f, names)| file.ends_with(f) && names.contains(&name))
}

const MACROS: &[&str] = &["trace!(", "debug!(", "info!(", "warn!(", "error!("];

/// The bodies of the tracing macro calls in `src` (string-aware paren
/// matching), with their line numbers. Line comments are dropped first.
fn macro_bodies(src: &str) -> Vec<(usize, String)> {
    let text: String = src
        .lines()
        .map(|l| {
            if l.trim_start().starts_with("//") {
                ""
            } else {
                l
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let Some(m) = MACROS.iter().find(|m| bytes[i..].starts_with(m.as_bytes())) else {
            i += 1;
            continue;
        };
        // a whole identifier: `warn!(`, `tracing::warn!(`, not `my_warn!(`
        if i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_') {
            i += 1;
            continue;
        }
        let start = i + m.len();
        let (mut depth, mut j, mut in_str, mut esc) = (1usize, start, false, false);
        while j < bytes.len() && depth > 0 {
            let c = bytes[j];
            if in_str {
                if esc {
                    esc = false;
                } else if c == b'\\' {
                    esc = true;
                } else if c == b'"' {
                    in_str = false;
                }
            } else if c == b'"' {
                in_str = true;
            } else if b"([{".contains(&c) {
                depth += 1;
            } else if b")]}".contains(&c) {
                depth -= 1;
            }
            j += 1;
        }
        let line = text[..i].matches('\n').count() + 1;
        let body = if depth == 0 {
            &text[start..j - 1]
        } else {
            &text[start..]
        };
        out.push((line, body.to_string()));
        i = j;
    }
    out
}

/// `name = %expr` fields of one macro body, and `{name}` captures in its
/// string literals, that log an attacker-named value without `Escaped`.
fn violations(file: &str, src: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (line, body) in macro_bodies(src) {
        let b = body.as_bytes();
        let mut k = 0;
        while let Some(off) = body[k..].find('%') {
            let p = k + off;
            k = p + 1;
            // `name = %expr`: walk back over spaces, `=`, spaces, the name
            let mut q = p;
            while q > 0 && b[q - 1].is_ascii_whitespace() {
                q -= 1;
            }
            if q == 0 || b[q - 1] != b'=' {
                continue;
            }
            q -= 1;
            while q > 0 && b[q - 1].is_ascii_whitespace() {
                q -= 1;
            }
            let end = q;
            while q > 0 && (b[q - 1].is_ascii_alphanumeric() || b[q - 1] == b'_') {
                q -= 1;
            }
            let name = &body[q..end];
            let expr = body[p + 1..].trim_start();
            if attacker_named(file, name)
                && !expr.starts_with("Escaped(")
                && !expr.starts_with("nn_model::log_escape::Escaped(")
            {
                out.push(format!("{file}:{line}: `{name} = %…` without Escaped"));
            }
        }
        // inline captures: "… {comm} …" / "{filename:?}" is Debug, allowed
        let mut s = 0;
        while let Some(off) = body[s..].find('{') {
            let open = s + off;
            s = open + 1;
            let Some(close) = body[open..].find('}') else {
                break;
            };
            let inner = &body[open + 1..open + close];
            let (name, spec) = inner.split_once(':').unwrap_or((inner, ""));
            if !spec.contains('?') && attacker_named(file, name) {
                out.push(format!("{file}:{line}: `{{{name}}}` in a log message"));
            }
        }
    }
    out
}

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            rs_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

#[test]
fn the_scan_finds_what_it_must() {
    let f = "src/x.rs";
    assert_eq!(violations(f, r#"warn!(pid, comm = %comm, "x");"#).len(), 1);
    assert_eq!(
        violations(f, "tracing::info!(\n  focal_comm = %c,\n  \"x\"\n)").len(),
        1
    );
    assert_eq!(
        violations(f, r#"warn!(reasoning = %v.reasoning, "x")"#).len(),
        1
    );
    assert_eq!(violations(f, r#"info!("ran {comm}")"#).len(), 1);
    assert!(violations(f, r#"warn!(comm = %Escaped(comm), "x")"#).is_empty());
    assert!(violations(
        f,
        r#"warn!(comm = %nn_model::log_escape::Escaped(&c), "x")"#
    )
    .is_empty());
    assert!(violations(f, r#"warn!(comm = ?comm, path = %p.display(), "x")"#).is_empty());
    assert!(violations(f, r#"info!("ran {comm:?} at {}", 5)"#).is_empty());
    assert!(violations(f, "// warn!(comm = %comm)\nlet x = 5 % 3;").is_empty());
    assert!(violations(f, r#"my_warn!(comm = %comm)"#).is_empty());
    // the per-file `path` rule
    assert_eq!(
        violations("src/fim/drain.rs", r#"debug!(path = %path, "x")"#).len(),
        1
    );
    assert!(violations("src/main.rs", r#"info!(path = %cli.audit.display(), "x")"#).is_empty());
}

/// The workspace members, `(package, directory)`, from `cargo metadata`
/// (Wave 4 restructure R00, lab PR 239): the scan follows the crates as
/// modules move between them, where a list of directories written here
/// would go on scanning the old ones and pass with nothing to read.
fn members() -> Vec<(String, PathBuf)> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let out = std::process::Command::new(cargo)
        .current_dir(env!("NN_REPO_ROOT"))
        .args([
            "metadata",
            "--no-deps",
            "--offline",
            "--format-version",
            "1",
        ])
        .output()
        .expect("cargo metadata runs");
    assert!(
        out.status.success(),
        "cargo metadata: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let meta: serde_json::Value = serde_json::from_slice(&out.stdout).expect("metadata JSON");
    let ids: Vec<&str> = meta["workspace_members"]
        .as_array()
        .expect("workspace_members")
        .iter()
        .filter_map(|m| m.as_str())
        .collect();
    let mut members: Vec<(String, PathBuf)> = meta["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .filter(|p| ids.contains(&p["id"].as_str().unwrap_or("")))
        .map(|p| {
            let manifest = Path::new(p["manifest_path"].as_str().expect("manifest_path"));
            (
                p["name"].as_str().expect("name").to_string(),
                manifest.parent().expect("package directory").to_path_buf(),
            )
        })
        .collect();
    members.sort();
    assert!(
        members.iter().any(|(n, _)| n == "northnarrow-agent")
            && members.iter().any(|(n, _)| n == "northnarrow-watchdog"),
        "{members:?}"
    );
    members
}

#[test]
fn no_attacker_named_field_is_logged_raw() {
    let root = Path::new(env!("NN_REPO_ROOT"));
    let mut files = Vec::new();
    for (_, dir) in members() {
        if dir.join("src").is_dir() {
            rs_files(&dir.join("src"), &mut files);
        }
    }
    assert!(files.len() > 50, "the scan found {} files", files.len());
    let (mut bad, mut calls) = (Vec::new(), 0);
    for p in &files {
        let rel = p
            .strip_prefix(root)
            .unwrap_or(p)
            .to_string_lossy()
            .into_owned();
        let src = std::fs::read_to_string(p).unwrap();
        calls += macro_bodies(&src).len();
        bad.extend(violations(&rel, &src));
    }
    // not vacuous: the agent and the watchdog log from some 900 calls
    assert!(calls > 500, "the scan found {calls} log calls");
    assert!(
        bad.is_empty(),
        "log these through nn_model::log_escape::Escaped (or `?`):\n{}",
        bad.join("\n")
    );
}

/// The agent and the watchdog write their log through the line guard: the
/// statement that installs the process's subscriber
/// (`tracing_subscriber::fmt()…init()`), in whichever file of the daemon's
/// sources it lives (R00: `main.rs` today, a boot phase after R11a).
#[test]
fn both_daemons_log_through_the_line_guard() {
    for (pkg, dir) in members() {
        if pkg != "northnarrow-agent" && pkg != "northnarrow-watchdog" {
            continue;
        }
        let mut files = Vec::new();
        rs_files(&dir.join("src"), &mut files);
        let mut installs = 0;
        for f in &files {
            let src = std::fs::read_to_string(f).unwrap();
            for stmt in src.split("tracing_subscriber::fmt()").skip(1) {
                let stmt = &stmt[..stmt.find(';').unwrap_or(stmt.len())];
                if !(stmt.contains(".init()") || stmt.contains(".try_init()")) {
                    continue; // a test's own subscriber (`with_default`)
                }
                installs += 1;
                assert!(
                    stmt.contains(".with_writer(nn_model::log_escape::stdout_one_line)")
                        && stmt.contains(".with_ansi(nn_model::log_escape::stdout_ansi())"),
                    "{}: the fmt layer must write through nn_model::log_escape::stdout_one_line",
                    f.display()
                );
            }
        }
        assert!(installs >= 1, "{pkg}: no file installs the fmt subscriber");
    }
}
