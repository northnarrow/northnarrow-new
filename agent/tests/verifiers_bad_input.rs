//! External audit, Wave 3: the verifiers and the forensic reader on damaged
//! and large input (EVD-017 NN-AUD-280, MAIN-014 NN-AUD-256, EVD-022
//! NN-AUD-283; lab PR 190).
//!
//! Runs the shipped `nn-admin` on files in a temporary directory,
//! unprivileged, and reads each run's exit code and peak RSS (`wait4`).
//! The memory runs also cap the process's data segment (`RLIMIT_DATA`,
//! heap and private writable mappings): a reader that keeps the file in
//! memory fails its allocation there and aborts. They are spawned by
//! `fork` (a `pre_exec` hook), whose child starts from this process's
//! current RSS; a `posix_spawn` child would carry this process's peak RSS
//! into its `ru_maxrss`.
//! - `chain verify` with an empty sealed archive reports that chain BROKEN
//!   and every chain after it (it aborted on an `expect`);
//! - `audit read` prints every row around lines that are not rows, names
//!   each of those lines and exits 8 (it stopped at the first one, exit 1);
//! - `audit verify` names the first damaged line and the rows verified
//!   before it, exit 8 (exit 1, "parsing audit-log line");
//! - a large chain and a line of 96 MiB are read one line at a time: the
//!   peak RSS stays far below the file (the verifiers kept every row, or
//!   the whole line, in memory).

use std::fs::{self, File};
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};

use northnarrow_agent::audit::{AgentSigningKey, AuditEntry, AuditEntryDraft, AuditLog};

/// One `nn-admin` run.
struct Run {
    code: i32,
    stdout: String,
    stderr: String,
    /// Peak resident set of the process, KiB (`ru_maxrss`).
    max_rss_kib: i64,
}

/// Data segment cap of the memory runs: a quarter of the large chain.
const DATA_LIMIT: u64 = 64 * 1024 * 1024;

fn nn_admin(dir: &Path, args: &[&str]) -> Run {
    nn_admin_limited(dir, args, None)
}

fn nn_admin_limited(dir: &Path, args: &[&str], data_limit: Option<u64>) -> Run {
    let out = dir.join("nn-admin.stdout");
    let err = dir.join("nn-admin.stderr");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_nn-admin"));
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(File::create(&out).unwrap())
        .stderr(File::create(&err).unwrap());
    // SAFETY: the hook runs in the forked child before `exec` and calls
    // only `setrlimit`, which is async-signal-safe.
    unsafe {
        cmd.pre_exec(move || {
            if let Some(limit) = data_limit {
                let lim = libc::rlimit {
                    rlim_cur: limit,
                    rlim_max: limit,
                };
                if libc::setrlimit(libc::RLIMIT_DATA, &lim) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let child = cmd.spawn().expect("spawn nn-admin");
    let pid = child.id() as libc::pid_t;
    let mut status: libc::c_int = 0;
    // SAFETY: an all-zero `rusage` is a valid value of the C struct.
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `pid` is our child, not waited for yet (the `Child` is never
    // waited on); `status` and `ru` are valid for writes.
    let r = unsafe { libc::wait4(pid, &mut status, 0, &mut ru) };
    assert_eq!(r, pid, "wait4: {}", std::io::Error::last_os_error());
    drop(child);
    let code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        128 + libc::WTERMSIG(status)
    };
    Run {
        code,
        stdout: String::from_utf8_lossy(&fs::read(&out).unwrap()).into_owned(),
        stderr: String::from_utf8_lossy(&fs::read(&err).unwrap()).into_owned(),
        max_rss_kib: ru.ru_maxrss,
    }
}

/// A fresh agent key in `dir` and the hex of its public half.
fn key(dir: &Path) -> (AgentSigningKey, String) {
    let k = AgentSigningKey::load_or_bootstrap(&dir.join("agent.sig.key")).unwrap();
    let hex = hex::encode(k.verifying_key().to_bytes());
    (k, hex)
}

fn draft(i: usize, blob: &str) -> AuditEntryDraft {
    AuditEntryDraft {
        op: format!("test_op_{i}"),
        extra: if blob.is_empty() {
            serde_json::json!({ "i": i })
        } else {
            serde_json::json!({ "i": i, "blob": blob })
        },
        key_fp: format!("{i:08x}"),
        cosigner_fps: vec![],
        result: "success".to_string(),
        client_pid: 1000 + i as u32,
        client_uid: 0,
        client_comm: "nn-admin".to_string(),
        client_exe: None,
    }
}

/// `n` signed rows at `path`; their lines, newline included.
fn audit_rows(dir: &Path, path: &Path, n: usize, blob: &str) -> (Vec<String>, String) {
    let (k, hex) = key(dir);
    let mut log = AuditLog::open(path, k, [0x21; 16]).unwrap();
    for i in 0..n {
        log.append(draft(i, blob)).unwrap();
    }
    drop(log);
    let body = fs::read_to_string(path).unwrap();
    (body.lines().map(|l| format!("{l}\n")).collect(), hex)
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

/// EVD-017: an empty `<base>.000001` next to the detection log made
/// `verify_log_set` hit `.expect("sealed archive ends in a terminator")`:
/// `chain verify` died (abort in a release build) and reported no chain.
#[test]
fn chain_verify_reports_an_empty_archive_and_every_chain_after_it() {
    let dir = tempfile::tempdir().unwrap();
    let (_k, hex) = key(dir.path());
    let state = dir.path().join("state");
    fs::create_dir_all(state.join("detections")).unwrap();
    File::create(state.join("detections").join("detections.jsonl.000001")).unwrap();
    let audit = dir.path().join("audit.log");
    let heads = dir.path().join("chain_heads.json");
    let r = nn_admin(
        dir.path(),
        &[
            "chain",
            "verify",
            "--state-dir",
            s(&state),
            "--audit-log",
            s(&audit),
            "--heads",
            s(&heads),
            "--agent-pubkey",
            &hex,
        ],
    );
    assert_eq!(r.code, 8, "stdout={} stderr={}", r.stdout, r.stderr);
    let broken: Vec<&str> = r
        .stdout
        .lines()
        .filter(|l| l.starts_with("BROKEN"))
        .collect();
    assert_eq!(broken.len(), 1, "{}", r.stdout);
    assert!(
        broken[0].contains("detections") && broken[0].contains("no terminator"),
        "{}",
        r.stdout
    );
    for chain in [
        "audit",
        "canary_registry",
        "canary_access",
        "status_events",
        "netflow",
        "fim_drift",
        "heads",
    ] {
        assert!(
            r.stdout
                .lines()
                .any(|l| l.starts_with("OK") && l.split_whitespace().nth(1) == Some(chain)),
            "{chain} not reported OK: {}",
            r.stdout
        );
    }
}

/// MAIN-014: one line that is not a row stopped `audit read` (exit 1):
/// every row after it was hidden. Now every row is printed, each skipped
/// line is named on stderr with its number, and the exit code is 8.
#[test]
fn audit_read_prints_every_row_around_damaged_lines() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("audit.log");
    let (rows, _) = audit_rows(dir.path(), &log, 5, "");
    let mut body = Vec::new();
    body.extend_from_slice(rows[0].as_bytes());
    body.extend_from_slice(rows[1].as_bytes());
    body.extend_from_slice(b"not an audit row\n"); // line 3
    body.extend_from_slice(rows[2].as_bytes());
    body.extend_from_slice(rows[3].as_bytes());
    body.extend_from_slice(b"\xff\xfe{\"ts\":1}\n"); // line 6, not UTF-8
    body.extend_from_slice(rows[4].as_bytes());
    body.extend_from_slice(br#"{"ts":"2026-10-20T00:00:00.000000Z","agent_id":"#); // line 8, torn
    fs::write(&log, &body).unwrap();

    let r = nn_admin(dir.path(), &["audit", "read", "--path", s(&log), "--json"]);
    assert_eq!(r.code, 8, "stdout={} stderr={}", r.stdout, r.stderr);
    let printed: Vec<&str> = r.stdout.lines().collect();
    let want: Vec<&str> = rows.iter().map(|l| l.trim_end()).collect();
    assert_eq!(printed, want, "every row is printed, in order");
    for n in ["line 3 ", "line 6 ", "line 8 "] {
        assert!(r.stderr.contains(n), "{n} not named: {}", r.stderr);
    }
    assert!(r.stderr.contains("3 line(s) skipped"), "{}", r.stderr);

    // The human form prints the same rows.
    let r = nn_admin(dir.path(), &["audit", "read", "--path", s(&log)]);
    assert_eq!(r.code, 8, "{}", r.stderr);
    assert_eq!(r.stdout.lines().count(), 5, "{}", r.stdout);
}

/// MAIN-014: `audit verify` turned a line that is not a row into an I/O
/// style error (exit 1). It is a broken chain (exit 8) that names the line
/// and how many rows verified before it.
#[test]
fn audit_verify_names_the_first_damaged_line() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("audit.log");
    let (rows, hex) = audit_rows(dir.path(), &log, 5, "");
    let cases: [(&str, Vec<u8>, &str); 3] = [
        (
            "a line that is not JSON in the middle",
            [
                rows[0].as_str(),
                rows[1].as_str(),
                rows[2].as_str(),
                "garbage\n",
                rows[3].as_str(),
            ]
            .concat()
            .into_bytes(),
            "line 4: not an audit row",
        ),
        (
            "a torn last line",
            [
                rows[0].as_str(),
                rows[1].as_str(),
                rows[2].as_str(),
                &rows[3][..40],
            ]
            .concat()
            .into_bytes(),
            "line 4: not an audit row",
        ),
        (
            "a line that is not UTF-8",
            [
                rows[0].as_bytes(),
                rows[1].as_bytes(),
                rows[2].as_bytes(),
                b"\xc3\x28\n",
            ]
            .concat(),
            "line 4: not an audit row",
        ),
    ];
    for (what, bytes, want) in cases {
        let f = dir.path().join("damaged.log");
        fs::write(&f, bytes).unwrap();
        let r = nn_admin(
            dir.path(),
            &["audit", "verify", "--from", s(&f), "--agent-pubkey", &hex],
        );
        assert_eq!(r.code, 8, "{what}: stdout={} stderr={}", r.stdout, r.stderr);
        assert!(r.stderr.contains(want), "{what}: {}", r.stderr);
        assert!(
            r.stderr.contains("3 row(s) verified before it"),
            "{what}: {}",
            r.stderr
        );
    }
    // An empty file is an empty chain, not an error.
    let empty = dir.path().join("empty.log");
    File::create(&empty).unwrap();
    let r = nn_admin(
        dir.path(),
        &[
            "audit",
            "verify",
            "--from",
            s(&empty),
            "--agent-pubkey",
            &hex,
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stdout.contains("audit: 0 entries"), "{}", r.stdout);
}

/// A line of 96 MiB without a newline (an appended blob, a file that is
/// not a chain): every reader buffered it whole (`lines`, `read_until`).
/// Now a line is kept up to 16 MiB and a longer one is consumed, reported
/// and never stored.
#[test]
fn a_huge_line_is_reported_in_bounded_memory() {
    const HUGE: usize = 96 * 1024 * 1024;
    const BOUND_KIB: i64 = 48 * 1024;
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("audit.log");
    let (rows, hex) = audit_rows(dir.path(), &log, 3, "");
    {
        let mut f = File::create(&log).unwrap();
        f.write_all(rows[0].as_bytes()).unwrap();
        f.write_all(rows[1].as_bytes()).unwrap();
        let chunk = vec![b'x'; 1024 * 1024];
        for _ in 0..HUGE / chunk.len() {
            f.write_all(&chunk).unwrap();
        }
        f.write_all(b"\n").unwrap();
        f.write_all(rows[2].as_bytes()).unwrap();
    }
    let r = nn_admin_limited(
        dir.path(),
        &["audit", "verify", "--from", s(&log), "--agent-pubkey", &hex],
        Some(DATA_LIMIT),
    );
    assert_eq!(r.code, 8, "{}", r.stderr);
    assert!(
        r.stderr.contains("line 3: not an audit row"),
        "{}",
        r.stderr
    );
    assert!(
        r.max_rss_kib < BOUND_KIB,
        "audit verify peak RSS {} KiB",
        r.max_rss_kib
    );

    let r = nn_admin_limited(
        dir.path(),
        &["audit", "read", "--path", s(&log), "--json"],
        Some(DATA_LIMIT),
    );
    assert_eq!(r.code, 8, "{}", r.stderr);
    assert_eq!(
        r.stdout.lines().count(),
        3,
        "the row after the blob is read"
    );
    assert!(
        r.max_rss_kib < BOUND_KIB,
        "audit read peak RSS {} KiB",
        r.max_rss_kib
    );

    // The rotating logs' verifier (`chain verify`): the same line as the
    // detection log's active file.
    let state = dir.path().join("state");
    fs::create_dir_all(state.join("detections")).unwrap();
    {
        let mut f = File::create(state.join("detections").join("detections.jsonl")).unwrap();
        let chunk = vec![b'{'; 1024 * 1024];
        for _ in 0..HUGE / chunk.len() {
            f.write_all(&chunk).unwrap();
        }
    }
    let r = nn_admin_limited(
        dir.path(),
        &[
            "chain",
            "verify",
            "--log",
            "detections",
            "--state-dir",
            s(&state),
            "--audit-log",
            s(&dir.path().join("none.log")),
            "--heads",
            s(&dir.path().join("none.json")),
            "--agent-pubkey",
            &hex,
        ],
        Some(DATA_LIMIT),
    );
    assert_eq!(r.code, 8, "stdout={} stderr={}", r.stdout, r.stderr);
    assert!(r.stdout.contains("longer than"), "{}", r.stdout);
    assert!(
        r.max_rss_kib < BOUND_KIB,
        "chain verify peak RSS {} KiB",
        r.max_rss_kib
    );
}

/// A large genuine chain (128 MiB, 256 rows of 512 KiB) verifies with the
/// data segment capped at 64 MiB and a peak RSS under half the file: one
/// row in memory at a time. `audit verify --expect-head` kept every row,
/// then read the file a second time whole; `chain verify` read it whole and
/// kept every row too: both abort at the cap.
#[test]
fn a_large_chain_verifies_in_bounded_memory() {
    const ROWS: usize = 256;
    const BLOB: usize = 512 * 1024;
    const BOUND_KIB: i64 = 64 * 1024;
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("audit.log");
    let (k, hex) = key(dir.path());
    let blob = "b".repeat(BLOB);
    let mut audit = AuditLog::open(&log, k, [0x21; 16]).unwrap();
    let mut last: Option<AuditEntry> = None;
    for i in 0..ROWS {
        last = Some(audit.append(draft(i, &blob)).unwrap());
    }
    drop((audit, blob));
    let last = last.unwrap();
    let size = fs::metadata(&log).unwrap().len();
    assert!(size >= (ROWS * BLOB) as u64, "{size}");
    let min_seq = last.seq.unwrap().to_string();

    let r = nn_admin_limited(
        dir.path(),
        &[
            "audit",
            "verify",
            "--from",
            s(&log),
            "--agent-pubkey",
            &hex,
            "--expect-head",
            &last.entry_hash,
            "--min-seq",
            &min_seq,
        ],
        Some(DATA_LIMIT),
    );
    eprintln!(
        "audit verify: {size} bytes, exit {}, peak RSS {} KiB",
        r.code, r.max_rss_kib
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stdout.contains(&format!("audit: {ROWS} entries")),
        "{}",
        r.stdout
    );
    assert!(r.max_rss_kib < BOUND_KIB, "peak RSS {} KiB", r.max_rss_kib);

    let state = dir.path().join("state");
    let r = nn_admin_limited(
        dir.path(),
        &[
            "chain",
            "verify",
            "--log",
            "audit",
            "--state-dir",
            s(&state),
            "--audit-log",
            s(&log),
            "--heads",
            s(&dir.path().join("none.json")),
            "--agent-pubkey",
            &hex,
        ],
        Some(DATA_LIMIT),
    );
    eprintln!(
        "chain verify --log audit: {size} bytes, exit {}, peak RSS {} KiB",
        r.code, r.max_rss_kib
    );
    assert_eq!(r.code, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    assert!(r.max_rss_kib < BOUND_KIB, "peak RSS {} KiB", r.max_rss_kib);
}
