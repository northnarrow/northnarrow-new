//! R12c-2 (lab PR 270; report 06 INI-14): `nn-admin heartbeat export` and
//! the minimal external verifier, `nn-admin heartbeat watch`.
//!
//! `export` prints the newest lines of the agent's heartbeat chain as they
//! are on disk — what an SSH forced command on the agent's host gives the
//! verifier. `watch` runs on ANOTHER host, independent of any backend: it
//! fetches those lines (a command of the operator's — an SSH pull — or an
//! exported file), verifies them with the agent's public key
//! (`nn_evidence::heartbeat::check`: signatures, the chain's links, the
//! beats' numbers, freshness, replay, the chains' heads, loss, health)
//! against what it saw last (its state file), and prints one line per
//! check: `OK …`, or one `ALERT <KIND> …` per alert. Once (a systemd timer)
//! its exit code is the most severe alert's; with `--every` it runs until
//! stopped. `docs/operator/HEARTBEAT.md` says how to set it up and what
//! each alert means.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use ed25519_dalek::VerifyingKey;
use nn_evidence::heartbeat::{check, CheckResult, WatchConfig, WatchState};

/// Lines `export` prints by default.
pub const DEFAULT_EXPORT_LINES: usize = 64;
/// How long a fetch command may run.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(30);
/// Bytes a fetch may return at most.
const FETCH_MAX_BYTES: u64 = 4 * 1024 * 1024;

/// `heartbeat export`: the newest `count` lines of the chain at `path`.
pub fn export(path: &Path, count: usize) -> ExitCode {
    match nn_evidence::heartbeat::tail_lines(path, count.max(1)) {
        Ok(lines) => {
            for l in lines {
                println!("{l}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("heartbeat export: {}: {e}", path.display());
            ExitCode::from(1)
        }
    }
}

/// Where `watch` reads the beats.
#[derive(Debug, Clone)]
pub enum Source {
    /// A command run with `sh -c` (an SSH pull: `ssh -i key nn-hb@host`).
    Command(String),
    /// An exported file (its last [`DEFAULT_EXPORT_LINES`] lines).
    File(PathBuf),
}

/// `watch`'s options.
#[derive(Debug, Clone)]
pub struct Watch {
    pub pubkey: VerifyingKey,
    pub source: Source,
    pub state: PathBuf,
    pub every: Option<Duration>,
    pub cfg: WatchConfig,
    /// Start again from the newest beat when the state cannot be read
    /// (review of #478: never silently — an unreadable state would accept a
    /// rollback as the first beat).
    pub reanchor: bool,
}

/// The exit code of a verifier that cannot verify: its state unreadable
/// (and no `--reanchor`), or not written.
pub const EXIT_STATE: u8 = 3;

/// The default state file: `$HOME/.local/state/nn-heartbeat/<key>.json`.
pub fn default_state(pubkey: &VerifyingKey) -> PathBuf {
    let home = std::env::var_os("HOME").map_or_else(|| PathBuf::from("."), PathBuf::from);
    home.join(".local/state/nn-heartbeat")
        .join(format!("{}.json", &hex::encode(pubkey.to_bytes())[..16]))
}

/// The fetched lines, or why there are none.
fn fetch(source: &Source) -> Result<Vec<Vec<u8>>, String> {
    let bytes = match source {
        Source::File(p) => nn_evidence::heartbeat::tail_lines(p, DEFAULT_EXPORT_LINES)
            .map(|l| l.join("\n").into_bytes())
            .map_err(|e| format!("{}: {e}", p.display()))?,
        Source::Command(cmd) => run_with_timeout(cmd, FETCH_TIMEOUT)?,
    };
    Ok(bytes
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .map(<[u8]>::to_vec)
        .collect())
}

/// The longest wait for the source command's bytes between two looks at
/// whether it exited.
const POLL_STEP: Duration = Duration::from_millis(50);
/// Bytes of the source command's stderr kept for a failure's reason: its
/// end, where the last line is.
const STDERR_KEPT: usize = 4096;

/// One of the source command's pipes, read as its bytes come.
struct Pipe {
    fd: Option<std::fs::File>,
    buf: Vec<u8>,
    /// The bytes kept: the first `cap` (stdout: past them the pipe is
    /// closed, the answer cut), or the last `cap` (stderr: read to its end,
    /// so the command never waits on it).
    cap: usize,
    tail: bool,
}

impl Pipe {
    fn new(fd: Option<impl Into<std::os::fd::OwnedFd>>, cap: usize, tail: bool) -> Self {
        Self {
            fd: fd.map(|f| std::fs::File::from(f.into())),
            buf: Vec::new(),
            cap,
            tail,
        }
    }

    /// One read of what the pipe holds (it said it is readable, or closed).
    fn read_once(&mut self) {
        let Some(f) = self.fd.as_mut() else {
            return;
        };
        let mut chunk = [0u8; 16 * 1024];
        match f.read(&mut chunk) {
            Ok(0) => self.fd = None,
            Ok(n) if self.tail => {
                self.buf.extend_from_slice(&chunk[..n]);
                let over = self.buf.len().saturating_sub(self.cap);
                self.buf.drain(..over);
            }
            Ok(n) => {
                let room = self.cap.saturating_sub(self.buf.len());
                self.buf.extend_from_slice(&chunk[..n.min(room)]);
                if self.buf.len() >= self.cap {
                    self.fd = None;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => self.fd = None,
        }
    }
}

/// Wait at most `wait` for bytes on the open pipes, then read once from
/// each one that has some or closed. Whether one did.
fn read_ready(out: &mut Pipe, err: &mut Pipe, wait: Duration) -> bool {
    use rustix::event::{poll, PollFd, PollFlags, Timespec};
    let ready: Vec<bool> = {
        let open: Vec<&std::fs::File> = [&out.fd, &err.fd].into_iter().flatten().collect();
        if open.is_empty() {
            std::thread::sleep(wait);
            return false;
        }
        let mut fds: Vec<PollFd<'_>> = open
            .iter()
            .map(|f| PollFd::new(*f, PollFlags::IN))
            .collect();
        let timeout = Timespec::try_from(wait).unwrap_or_default();
        match poll(&mut fds, Some(&timeout)) {
            Ok(0) => return false,
            Ok(_) => fds.iter().map(|f| !f.revents().is_empty()).collect(),
            Err(_) => {
                std::thread::sleep(wait);
                return false;
            }
        }
    };
    // `ready` follows `[out, err]`, the closed ones left out
    let mut ready = ready.into_iter();
    let mut any = false;
    for p in [out, err] {
        if p.fd.is_some() && ready.next() == Some(true) {
            p.read_once();
            any = true;
        }
    }
    any
}

/// `sh -c cmd`, its stdout (bounded), killed past `timeout`.
///
/// Lot 299 (external bug hunt, editions 1.2/1.3: BUG-22, BUG-34, BUG-38):
/// its stdout and its stderr are one collection under the one bound, read
/// together as their bytes come, and the fetch ends when the command exits,
/// with what it left in the pipes:
/// - a command that writes more than a pipe holds on stderr before it
///   answers is not stopped by its pipe (it was, until the timeout);
/// - a process it started that keeps a pipe open (`cmd &`, a multiplexing
///   ssh master) holds neither its answer nor its failure — the fetch, and
///   `watch` with it, waited for it without a bound, with no OK and no
///   ALERT.
fn run_with_timeout(cmd: &str, timeout: Duration) -> Result<Vec<u8>, String> {
    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg(cmd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("the source command did not start: {e}"))?;
    let deadline = Instant::now() + timeout;
    let mut out = Pipe::new(child.stdout.take(), FETCH_MAX_BYTES as usize, false);
    let mut err = Pipe::new(child.stderr.take(), STDERR_KEPT, true);
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) => {}
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("the source command: {e}"));
            }
        }
        let now = Instant::now();
        if now >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "the source command did not answer within {} s",
                timeout.as_secs()
            ));
        }
        read_ready(&mut out, &mut err, (deadline - now).min(POLL_STEP));
    };
    // it exited: what it wrote is in the pipes now — read that, not what a
    // process it started may write later
    while Instant::now() < deadline && read_ready(&mut out, &mut err, Duration::ZERO) {}
    if !status.success() {
        let err = String::from_utf8_lossy(&err.buf);
        let err = err.lines().last().unwrap_or("").to_string();
        return Err(format!(
            "the source command failed ({status}){}",
            if err.is_empty() {
                String::new()
            } else {
                format!(": {err}")
            }
        ));
    }
    Ok(out.buf)
}

/// The state: `Ok(None)` when there is none yet (the first check anchors),
/// `Err` when it is there and cannot be read or decoded.
fn read_state(path: &Path) -> Result<Option<WatchState>, String> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| format!("{}: not a state ({e})", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// The state written whole or not at all (a temporary file renamed over).
fn write_state(path: &Path, s: &WatchState) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(
        &tmp,
        serde_json::to_vec_pretty(s).map_err(std::io::Error::other)?,
    )?;
    std::fs::rename(&tmp, path)
}

/// One check: fetch, verify, print, keep the state. Returns its result.
pub fn check_once(w: &Watch) -> Result<CheckResult, String> {
    let now = nn_evidence::audit::format_ts(chrono::Utc::now());
    let last = match read_state(&w.state) {
        Ok(s) => s,
        Err(why) if w.reanchor => {
            println!("{now} NOTE the state {why} — re-anchored (--reanchor)");
            None
        }
        Err(why) => {
            println!(
                "{now} ERROR the state {why} — not re-anchored: run once with --reanchor to start \
                 again from the newest beat"
            );
            return Err(why);
        }
    };
    let fetched = fetch(&w.source);
    let lines = fetched.as_deref().map_err(String::as_str);
    let r = check(lines, &w.pubkey, last.as_ref(), chrono::Utc::now(), &w.cfg);
    if r.alerts.is_empty() {
        let s = r.state.as_ref();
        println!(
            "{now} OK seq={} new={} age={}s{}",
            s.map_or(0, |s| s.seq),
            r.new_beats,
            r.age_secs.unwrap_or(-1),
            if r.anchored {
                " (anchored: first beat seen)"
            } else {
                ""
            }
        );
    }
    // R13 (the review of #479): an upgrade's contract change, said, no alert
    for n in &r.notices {
        println!("{now} NOTICE {n}");
    }
    for a in &r.alerts {
        println!("{now} ALERT {} {}", a.kind(), a.detail());
    }
    if let Some(s) = &r.state {
        if last.as_ref() != Some(s) {
            if let Err(e) = write_state(&w.state, s) {
                println!(
                    "{now} ERROR the state {} not written: {e}",
                    w.state.display()
                );
                return Err(format!("{}: {e}", w.state.display()));
            }
        }
    }
    Ok(r)
}

/// `heartbeat watch`: once (the exit code is the most severe alert's), or
/// every `w.every` until stopped.
pub fn watch(w: &Watch) -> ExitCode {
    match w.every {
        None => match check_once(w) {
            Ok(r) => ExitCode::from(u8::try_from(r.exit_code()).unwrap_or(1)),
            Err(_) => ExitCode::from(EXIT_STATE),
        },
        Some(every) => loop {
            let started = Instant::now();
            let _ = check_once(w);
            use std::io::Write;
            let _ = std::io::stdout().flush();
            std::thread::sleep(every.saturating_sub(started.elapsed()));
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The source command: its stdout; a failure or a hang is a fetch that
    /// failed, with why — the verifier's silence once past the bound.
    #[test]
    fn the_source_command_answers_fails_or_times_out() {
        let out = run_with_timeout("printf 'a\\nb\\n'", Duration::from_secs(5)).unwrap();
        assert_eq!(out, b"a\nb\n");
        let e = run_with_timeout("echo nope >&2; exit 3", Duration::from_secs(5)).unwrap_err();
        assert!(e.contains("failed") && e.contains("nope"), "{e}");
        let started = Instant::now();
        let e = run_with_timeout("sleep 30", Duration::from_millis(300)).unwrap_err();
        assert!(e.contains("did not answer"), "{e}");
        assert!(started.elapsed() < Duration::from_secs(10));
        let lines = fetch(&Source::Command("printf 'x\\n\\ny\\n'".into())).unwrap();
        assert_eq!(lines, [b"x".to_vec(), b"y".to_vec()]);
        assert!(fetch(&Source::File("/nonexistent/hb.jsonl".into())).is_err());
    }

    /// The state survives a restart of the verifier, written whole.
    #[test]
    fn the_state_is_kept_between_checks() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s/state.json");
        let s = WatchState {
            seq: 7,
            entry_hash: "ab".repeat(32),
            ts: "2026-11-01T10:00:00.000000Z".into(),
            run: "r".into(),
            boot_id: "b".into(),
            interval_secs: 30,
            loss: vec![Some(0); 7],
            actions: Default::default(),
            probe_gaps: None,
            degradations: Vec::new(),
            heads: Default::default(),
            heads_gone: Default::default(),
            stopped: false,
            seen_at: "2026-11-01T10:00:01.000000Z".into(),
            uptime_ms: 1,
            manifest_hash: Some("cd".repeat(32)),
            manifest_revision: Some(2),
            manifest_run: Some("r".into()),
            manifest_contract: Some("ef".repeat(32)),
            manifest_versions: Some(nn_evidence::heartbeat::ContractSeen {
                agent: "0.0.1".into(),
                contract_version: Some(1),
                kernel: Some("6.8.0-147-generic".into()),
            }),
        };
        write_state(&p, &s).unwrap();
        assert_eq!(read_state(&p), Ok(Some(s)));
        assert!(!p.with_extension("json.tmp").exists());
        assert_eq!(read_state(&dir.path().join("none.json")), Ok(None));
    }

    /// Review of #478: a state there and unreadable is an error (exit 3),
    /// never a silent re-anchor that would take a rollback for the first
    /// beat; `--reanchor` starts again on purpose.
    #[test]
    fn a_corrupt_state_is_an_error_unless_reanchored() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state.json");
        std::fs::write(&state, b"{ not json").unwrap();
        let file = dir.path().join("export.jsonl");
        std::fs::write(&file, b"").unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let mut w = Watch {
            pubkey: key.verifying_key(),
            source: Source::File(file),
            state: state.clone(),
            every: None,
            cfg: WatchConfig::default(),
            reanchor: false,
        };
        assert!(check_once(&w).is_err());
        assert_eq!(
            std::fs::read(&state).unwrap(),
            b"{ not json",
            "left as it was"
        );
        w.reanchor = true;
        assert!(check_once(&w).is_ok());
    }

    /// Lot 299 (external bug hunt, edition 1.2: BUG-22): a source command
    /// that writes more than a pipe holds on stderr before it answers still
    /// answers.
    #[test]
    fn noisy_stderr_source_still_answers() {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let started = Instant::now();
            let got = run_with_timeout(
                "head -c 100000 /dev/zero >&2; echo beat",
                Duration::from_secs(3),
            );
            let _ = tx.send((got, started.elapsed()));
        });
        let (got, took) = rx.recv_timeout(Duration::from_secs(10)).expect("returned");
        eprintln!("BUG22: {got:?} in {took:?}");
        assert_eq!(got, Ok(b"beat\n".to_vec()));
    }

    /// Lot 299 (external bug hunt, edition 1.2: BUG-34): a descendant of the
    /// source command that holds its stdout must not hold the fetch past its
    /// bound.
    #[test]
    fn descendant_holding_stdout_does_not_hang_fetch() {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(run_with_timeout(
                "sleep 15 & echo x",
                Duration::from_secs(1),
            ));
        });
        let r = rx.recv_timeout(Duration::from_secs(8));
        eprintln!("BUG34: {r:?}");
        assert!(
            r.is_ok(),
            "run_with_timeout(.., 1 s) did not return within 8 s"
        );
    }

    /// Lot 299 (external bug hunt, edition 1.2: BUG-38): a failed source
    /// command is a failed fetch at once, even when a descendant keeps its
    /// stderr open.
    #[test]
    fn failed_source_does_not_wait_for_stderr_holder() {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(run_with_timeout(
                "sleep 15 >/dev/null & exit 3",
                Duration::from_secs(1),
            ));
        });
        let r = rx.recv_timeout(Duration::from_secs(8));
        eprintln!("BUG38: {r:?}");
        let e = r.expect("blocked reading stderr").unwrap_err();
        assert!(e.contains("failed") && e.contains('3'), "{e}");
    }

    /// Lot 299 (BUG-22, BUG-34, BUG-38): `check_once` over each of those
    /// source commands answers well within the fetch's bound (30 s): an
    /// ALERT, never a hang.
    #[test]
    fn a_held_or_noisy_source_is_an_alert_not_a_hang() {
        for cmd in [
            "head -c 100000 /dev/zero >&2; echo beat",
            "sleep 15 & echo x",
            "sleep 15 >/dev/null & exit 3",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
            let w = Watch {
                pubkey: key.verifying_key(),
                source: Source::Command(cmd.into()),
                state: dir.path().join("state.json"),
                every: None,
                cfg: WatchConfig::default(),
                reanchor: false,
            };
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(check_once(&w));
            });
            let r = rx
                .recv_timeout(Duration::from_secs(10))
                .unwrap_or_else(|_| panic!("{cmd}: no answer within 10 s"))
                .unwrap_or_else(|e| panic!("{cmd}: {e}"));
            assert!(!r.alerts.is_empty(), "{cmd}: no alert");
        }
    }

    /// Lot 299: both pipes are read as their bytes come — stderr, stdout,
    /// stderr again, each more than a pipe holds — and the answer is the
    /// whole stdout.
    #[test]
    fn both_pipes_are_read_as_their_bytes_come() {
        let out = run_with_timeout(
            "head -c 200000 /dev/zero >&2; head -c 300000 /dev/zero; \
             head -c 200000 /dev/zero >&2",
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(out.len(), 300_000);
    }

    /// Lot 299: a failure's reason is the LAST line of its stderr, however
    /// much came before it (the first 4 KiB were read: a long stderr gave a
    /// line of its middle).
    #[test]
    fn a_failure_says_the_last_line_of_its_stderr() {
        let e = run_with_timeout(
            "printf 'first\\n' >&2; head -c 10000 /dev/zero | tr '\\0' x >&2; \
             printf '\\nthe-reason\\n' >&2; exit 4",
            Duration::from_secs(5),
        )
        .unwrap_err();
        assert!(e.ends_with(": the-reason") && e.contains('4'), "{e}");
    }

    /// Lot 299: the answer stays bounded — a source past
    /// [`FETCH_MAX_BYTES`] has its pipe closed at the bound, a failed fetch
    /// (it dies of the closed pipe), never an answer cut short or read to
    /// its end.
    #[test]
    fn a_source_past_the_bound_is_a_failed_fetch() {
        let e = run_with_timeout(
            &format!("head -c {} /dev/zero", FETCH_MAX_BYTES + 1_000_000),
            Duration::from_secs(10),
        )
        .unwrap_err();
        assert!(e.contains("failed"), "{e}");
        let out = run_with_timeout(
            &format!("head -c {FETCH_MAX_BYTES} /dev/zero"),
            Duration::from_secs(10),
        )
        .unwrap();
        assert_eq!(out.len() as u64, FETCH_MAX_BYTES);
    }
}
