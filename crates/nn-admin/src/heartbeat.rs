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
}

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

/// `sh -c cmd`, its stdout (bounded), killed past `timeout`.
fn run_with_timeout(cmd: &str, timeout: Duration) -> Result<Vec<u8>, String> {
    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg(cmd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("the source command did not start: {e}"))?;
    let mut out = child.stdout.take().expect("piped");
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = (&mut out).take(FETCH_MAX_BYTES).read_to_end(&mut buf);
        buf
    });
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if started.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "the source command did not answer within {} s",
                    timeout.as_secs()
                ));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => return Err(format!("the source command: {e}")),
        }
    };
    let buf = reader.join().unwrap_or_default();
    if !status.success() {
        let mut err = String::new();
        if let Some(mut e) = child.stderr.take() {
            let _ = (&mut e).take(4096).read_to_string(&mut err);
        }
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
    Ok(buf)
}

fn read_state(path: &Path) -> Option<WatchState> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
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
pub fn check_once(w: &Watch) -> CheckResult {
    let last = read_state(&w.state);
    let fetched = fetch(&w.source);
    let lines = fetched.as_deref().map_err(String::as_str);
    let r = check(lines, &w.pubkey, last.as_ref(), chrono::Utc::now(), &w.cfg);
    let now = nn_evidence::audit::format_ts(chrono::Utc::now());
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
    for a in &r.alerts {
        println!("{now} ALERT {} {}", a.kind(), a.detail());
    }
    if let Some(s) = &r.state {
        if last.as_ref() != Some(s) {
            if let Err(e) = write_state(&w.state, s) {
                eprintln!("heartbeat watch: the state {}: {e}", w.state.display());
            }
        }
    }
    r
}

/// `heartbeat watch`: once (the exit code is the most severe alert's), or
/// every `w.every` until stopped.
pub fn watch(w: &Watch) -> ExitCode {
    match w.every {
        None => {
            let r = check_once(w);
            ExitCode::from(u8::try_from(r.exit_code()).unwrap_or(1))
        }
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
            stopped: false,
        };
        write_state(&p, &s).unwrap();
        assert_eq!(read_state(&p), Some(s));
        assert!(!p.with_extension("json.tmp").exists());
    }
}
