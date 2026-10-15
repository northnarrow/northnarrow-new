//! Newest-first, bounded read of a chain log for the admin read verbs.
//!
//! External audit NN-AUD-080: `fim report`, `net flows` and `canary list`
//! scanned the active file from its start and stopped at the frame budget,
//! so they answered with the OLDEST rows, and no verb opened a rotated
//! archive. A flood of rows from any user pushed the rows that matter out
//! of every answer. [`read_chain_tail`] returns the newest rows first: it
//! reads the active file, then the sealed archives newest-first, only while
//! the budget is not full and, with `since`, only while no row older than
//! `since` has been met.
//!
//! Bounds (the read runs on the admin socket's task):
//! - memory: the rows kept never exceed `soft_cap` bytes, and a line longer
//!   than `soft_cap` is never buffered whole;
//! - I/O: a file is scanned over its last [`MAX_SCAN_BYTES_PER_FILE`] bytes
//!   at most, and one read scans at most [`MAX_SCAN_BYTES_TOTAL`] bytes over
//!   all its files. The per-file bound is above every rotation cap (netflow
//!   16 MiB, FIM drift 32 MiB by default), so a rotated file is read whole;
//!   a file that does not rotate (the listener log, the canary registry, or
//!   any log when rotation is off) is read over its tail only. Hitting a
//!   bound sets `truncated`.
//!
//! Files: the paths come from the agent's command line, never from the
//! request. The active path is resolved through the directory fd the
//! writers anchored ([`crate::anchored`]), so the verbs read the directory
//! the agent writes. Every file is opened `O_NOFOLLOW | O_NONBLOCK` and read
//! only if it is a regular file: a symlink at an archive name cannot make a
//! read verb serve another file, and a FIFO cannot stall the socket.
//!
//! The rows are not signature-verified here (`nn-admin chain verify` does
//! that; `detections` checks the rows it serves since lab PR 160).
//! Terminator lines of sealed archives are not rows and are skipped.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use tracing::warn;

/// Bytes scanned at most in one file (its tail).
pub(crate) const MAX_SCAN_BYTES_PER_FILE: u64 = 64 * 1024 * 1024;

/// Bytes scanned at most by one read, over all files.
pub(crate) const MAX_SCAN_BYTES_TOTAL: u64 = 128 * 1024 * 1024;

/// What one tail read keeps.
pub(crate) struct TailQuery<'a> {
    /// Lower bound on each row's `ts`, as an ISO-8601 prefix compared
    /// lexicographically (the chain logs write a fixed-width UTC form). A
    /// row without a `ts` field is kept.
    pub since: Option<&'a str>,
    /// Row predicate on the raw line; `None` keeps every row.
    pub keep: Option<&'a dyn Fn(&str) -> bool>,
    /// Byte budget of the returned body (rows plus newlines).
    pub soft_cap: usize,
    /// Row budget.
    pub max_rows: usize,
}

/// The rows a tail read returns.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ChainTail {
    /// Rows, newest first, one per line.
    pub jsonl: String,
    pub count: u32,
    /// Older matching rows may exist that are not in `jsonl`.
    pub truncated: bool,
}

/// The newest rows of the chain log whose active file is `active`, newest
/// first, within `query`'s budgets. See the module doc.
pub(crate) fn read_chain_tail(active: &Path, query: &TailQuery<'_>) -> ChainTail {
    read_chain_tail_bounded(active, query, MAX_SCAN_BYTES_PER_FILE, MAX_SCAN_BYTES_TOTAL)
}

fn read_chain_tail_bounded(
    active: &Path,
    query: &TailQuery<'_>,
    per_file: u64,
    total: u64,
) -> ChainTail {
    let active = crate::anchored::anchor(active);
    let mut files: Vec<PathBuf> = vec![active.clone()];
    files.extend(crate::chainlog::archives_newest_first(&active));

    let mut rows: Vec<String> = Vec::new();
    let mut used = 0usize;
    let mut scanned = 0u64;
    let mut truncated = false;
    for path in &files {
        let room_bytes = query.soft_cap.saturating_sub(used);
        let room_rows = query.max_rows.saturating_sub(rows.len());
        if room_bytes == 0 || room_rows == 0 || scanned >= total {
            // Older files are left unread: they may hold matching rows.
            truncated = true;
            break;
        }
        let Some(file) = open_regular(path) else {
            continue;
        };
        let budget = FileBudget {
            room_bytes,
            room_rows,
            max_scan: per_file.min(total - scanned),
        };
        let scan = match scan_file(file, query, &budget) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, path = %path.display(), "chain tail: read failed");
                truncated = true;
                break;
            }
        };
        scanned += scan.scanned;
        for row in scan.rows.into_iter().rev() {
            used += row.len() + 1;
            rows.push(row);
        }
        if scan.omitted || (scan.head_skipped && !scan.saw_older) {
            truncated = true;
        }
        if scan.omitted || scan.head_skipped || scan.saw_older {
            // Everything in older files is older still: either over the
            // budget, past a gap, or before `since`.
            break;
        }
    }

    let mut jsonl = String::with_capacity(used);
    for row in &rows {
        jsonl.push_str(row);
        jsonl.push('\n');
    }
    ChainTail {
        jsonl,
        count: u32::try_from(rows.len()).unwrap_or(u32::MAX),
        truncated,
    }
}

/// Open `path` for reading without following a final symlink and without
/// blocking; `None` unless it is a regular file. A missing file is not an
/// error (a log not written yet, an archive evicted meanwhile).
fn open_regular(path: &Path) -> Option<File> {
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            warn!(error = %e, path = %path.display(), "chain tail: file not opened");
            return None;
        }
    };
    match file.metadata() {
        Ok(m) if m.is_file() => Some(file),
        _ => {
            warn!(path = %path.display(), "chain tail: not a regular file, skipped");
            None
        }
    }
}

struct FileBudget {
    room_bytes: usize,
    room_rows: usize,
    max_scan: u64,
}

struct FileScan {
    /// Kept rows of this file, oldest first.
    rows: VecDeque<String>,
    /// A matching row was dropped for the budget (or could not fit).
    omitted: bool,
    /// The file's head, before the scanned window, was not read.
    head_skipped: bool,
    /// A row older than `since` was met.
    saw_older: bool,
    scanned: u64,
}

/// Scan the last `budget.max_scan` bytes of `file` forward, keeping the
/// newest matching rows that fit the budget.
fn scan_file(
    mut file: File,
    query: &TailQuery<'_>,
    budget: &FileBudget,
) -> std::io::Result<FileScan> {
    let len = file.metadata()?.len();
    let window = len.min(budget.max_scan);
    let start = len - window;
    file.seek(SeekFrom::Start(start))?;
    let mut reader = BufReader::with_capacity(64 * 1024, file.take(window));
    let max_line = query.soft_cap.min(budget.room_bytes.max(1));

    let mut out = FileScan {
        rows: VecDeque::new(),
        omitted: false,
        head_skipped: start > 0,
        saw_older: false,
        scanned: window,
    };
    let mut kept_bytes = 0usize;
    let mut buf = Vec::new();
    if start > 0 {
        // The window starts inside a line: drop that partial line.
        let _ = next_line(&mut reader, &mut buf, 0)?;
    }
    loop {
        let kind = next_line(&mut reader, &mut buf, max_line)?;
        let line = match kind {
            LineKind::Eof | LineKind::Unterminated => break,
            LineKind::Complete | LineKind::Oversized => match std::str::from_utf8(&buf) {
                Ok(s) => s.trim_end_matches('\r'),
                // Kept prefix of an oversized line may end mid-character.
                Err(e) if kind == LineKind::Oversized => {
                    std::str::from_utf8(&buf[..e.valid_up_to()]).unwrap_or("")
                }
                Err(_) => continue,
            },
        };
        if line.trim().is_empty() || crate::chainlog::is_terminator_line(line) {
            continue;
        }
        if let Some(since) = query.since {
            if let Some(ts) = ts_field(line) {
                if ts < since {
                    out.saw_older = true;
                    continue;
                }
            }
        }
        if kind == LineKind::Oversized {
            // Too long to ever fit the frame: a row the answer leaves out.
            out.omitted = true;
            continue;
        }
        if let Some(keep) = query.keep {
            if !keep(line) {
                continue;
            }
        }
        kept_bytes += line.len() + 1;
        out.rows.push_back(line.to_string());
        while kept_bytes > budget.room_bytes || out.rows.len() > budget.room_rows {
            match out.rows.pop_front() {
                Some(old) => kept_bytes -= old.len() + 1,
                None => break,
            }
            out.omitted = true;
        }
    }
    Ok(out)
}

/// The value of the first `"ts":"…"` field of a raw line (the chain logs
/// write `ts` first).
pub(crate) fn ts_field(line: &str) -> Option<&str> {
    let key = "\"ts\":\"";
    let start = line.find(key)? + key.len();
    let end = line[start..].find('"')?;
    Some(&line[start..start + end])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineKind {
    /// A whole line, newline excluded, in the buffer.
    Complete,
    /// A line longer than the limit: its first `max` bytes are in the
    /// buffer, the rest was consumed.
    Oversized,
    /// Bytes after the last newline (a write in progress or a torn tail).
    Unterminated,
    Eof,
}

/// Read one line into `buf` (newline excluded), keeping at most `max`
/// bytes of it.
fn next_line<R: BufRead>(r: &mut R, buf: &mut Vec<u8>, max: usize) -> std::io::Result<LineKind> {
    buf.clear();
    let mut over = false;
    let mut any = false;
    loop {
        let (used, done) = {
            let avail = match r.fill_buf() {
                Ok(b) => b,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            if avail.is_empty() {
                return Ok(if any {
                    LineKind::Unterminated
                } else {
                    LineKind::Eof
                });
            }
            any = true;
            let (chunk, used, done) = match avail.iter().position(|&b| b == b'\n') {
                Some(i) => (&avail[..i], i + 1, true),
                None => (avail, avail.len(), false),
            };
            if !over {
                let room = max.saturating_sub(buf.len());
                if chunk.len() > room {
                    buf.extend_from_slice(&chunk[..room]);
                    over = true;
                } else {
                    buf.extend_from_slice(chunk);
                }
            }
            (used, done)
        };
        r.consume(used);
        if done {
            return Ok(if over {
                LineKind::Oversized
            } else {
                LineKind::Complete
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn row(i: u64) -> String {
        format!(
            "{{\"ts\":\"2026-10-15T10:{:02}:{:02}.000000Z\",\"n\":{i}}}",
            i / 60,
            i % 60
        )
    }

    fn write_rows(path: &Path, range: std::ops::Range<u64>) {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        for i in range {
            writeln!(f, "{}", row(i)).unwrap();
        }
    }

    fn all(cap: usize) -> TailQuery<'static> {
        TailQuery {
            since: None,
            keep: None,
            soft_cap: cap,
            max_rows: usize::MAX,
        }
    }

    fn numbers(t: &ChainTail) -> Vec<u64> {
        t.jsonl
            .lines()
            .map(|l| {
                serde_json::from_str::<serde_json::Value>(l).unwrap()["n"]
                    .as_u64()
                    .unwrap()
            })
            .collect()
    }

    /// External audit NN-AUD-080: over the budget, the newest rows are
    /// kept, newest first, and the answer says older rows were left out.
    #[test]
    fn truncation_keeps_newest_rows_first() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("log.jsonl");
        write_rows(&active, 0..1000);
        let t = read_chain_tail(&active, &all(10 * (row(999).len() + 1)));
        assert_eq!(numbers(&t), (990..1000).rev().collect::<Vec<_>>());
        assert_eq!(t.count, 10);
        assert!(t.truncated);
    }

    #[test]
    fn whole_small_file_is_not_truncated() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("log.jsonl");
        write_rows(&active, 0..5);
        let t = read_chain_tail(&active, &all(1 << 20));
        assert_eq!(numbers(&t), vec![4, 3, 2, 1, 0]);
        assert!(!t.truncated);
        let missing = read_chain_tail(&dir.path().join("none.jsonl"), &all(1 << 20));
        assert_eq!(missing, ChainTail::default());
    }

    /// The active file, then the archives newest-first; the terminator of a
    /// sealed archive is not a row.
    #[test]
    fn reads_into_archives_newest_first_and_skips_terminators() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("log.jsonl");
        write_rows(&dir.path().join("log.jsonl.000001"), 0..3);
        write_rows(&dir.path().join("log.jsonl.000002"), 3..6);
        std::fs::OpenOptions::new()
            .append(true)
            .open(dir.path().join("log.jsonl.000002"))
            .unwrap()
            .write_all(b"{\"rotate\":{\"fmt_ver\":2},\"ts\":\"2026-10-15T11:00:00Z\"}\n")
            .unwrap();
        write_rows(&active, 6..8);
        std::fs::write(dir.path().join("log.jsonl.manifest.jsonl"), "{\"x\":1}\n").unwrap();
        let t = read_chain_tail(&active, &all(1 << 20));
        assert_eq!(numbers(&t), vec![7, 6, 5, 4, 3, 2, 1, 0]);
        assert!(!t.truncated);
    }

    /// `since` stops the descent at the first file holding an older row.
    #[test]
    fn since_stops_at_the_first_older_row() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("log.jsonl");
        write_rows(&dir.path().join("log.jsonl.000001"), 0..10);
        write_rows(&active, 10..12);
        let since = "2026-10-15T10:00:08";
        let q = TailQuery {
            since: Some(since),
            ..all(1 << 20)
        };
        let t = read_chain_tail(&active, &q);
        assert_eq!(numbers(&t), vec![11, 10, 9, 8]);
        assert!(!t.truncated);
    }

    #[test]
    fn keep_predicate_and_row_budget() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("log.jsonl");
        write_rows(&dir.path().join("log.jsonl.000001"), 0..50);
        write_rows(&active, 50..60);
        let even = |l: &str| {
            serde_json::from_str::<serde_json::Value>(l).unwrap()["n"]
                .as_u64()
                .unwrap()
                % 2
                == 0
        };
        let q = TailQuery {
            keep: Some(&even),
            max_rows: 8,
            ..all(1 << 20)
        };
        let t = read_chain_tail(&active, &q);
        assert_eq!(numbers(&t), vec![58, 56, 54, 52, 50, 48, 46, 44]);
        assert!(t.truncated);
    }

    /// A file larger than the scan bound is read over its tail only, and
    /// the answer says so; a partial first line of the window is dropped.
    #[test]
    fn scan_bounds_read_the_tail_and_flag_it() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("log.jsonl");
        write_rows(&dir.path().join("log.jsonl.000001"), 0..10);
        write_rows(&active, 10..100);
        let line = row(99).len() as u64 + 1;
        let t = read_chain_tail_bounded(&active, &all(1 << 20), 3 * line + 5, u64::MAX);
        assert_eq!(numbers(&t), vec![99, 98, 97]);
        assert!(t.truncated, "the head of the active file was not read");
        // The total bound stops the descent too.
        let t = read_chain_tail_bounded(&active, &all(1 << 20), u64::MAX, 90 * line);
        assert_eq!(t.count, 90);
        assert!(t.truncated);
    }

    #[test]
    fn oversized_and_unterminated_lines_are_not_returned() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("log.jsonl");
        let big = format!(
            "{{\"ts\":\"2026-10-15T10:00:00Z\",\"pad\":\"{}\"}}",
            "x".repeat(4096)
        );
        std::fs::write(
            &active,
            format!("{}\n{big}\n{}\n{{\"ts\":\"torn", row(1), row(2)),
        )
        .unwrap();
        let t = read_chain_tail(&active, &all(1024));
        assert_eq!(numbers(&t), vec![2, 1]);
        assert!(t.truncated, "the oversized row is a row left out");
    }

    /// A symlink or a FIFO at an archive name is not read.
    #[test]
    fn symlinked_and_special_files_are_not_read() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("log.jsonl");
        let secret = dir.path().join("secret");
        std::fs::write(&secret, "{\"ts\":\"2026-10-15T09:00:00Z\",\"n\":666}\n").unwrap();
        std::os::unix::fs::symlink(&secret, dir.path().join("log.jsonl.000002")).unwrap();
        let fifo = std::ffi::CString::new(
            dir.path()
                .join("log.jsonl.000001")
                .as_os_str()
                .to_str()
                .unwrap(),
        )
        .unwrap();
        // SAFETY: a NUL-terminated path that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        write_rows(&active, 0..2);
        let t = read_chain_tail(&active, &all(1 << 20));
        assert_eq!(numbers(&t), vec![1, 0]);
        // The active path itself as a symlink is refused too.
        let link = dir.path().join("link.jsonl");
        std::os::unix::fs::symlink(&secret, &link).unwrap();
        assert_eq!(read_chain_tail(&link, &all(1 << 20)).count, 0);
    }

    /// The terminator a real rotation writes is recognised.
    #[test]
    fn real_rotation_terminator_is_skipped() {
        use crate::chainlog::{NoProtection, RotatingChainLog, RotationConfig};
        #[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
        struct P {
            ts: String,
            n: u64,
        }
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("rot.jsonl");
        let key = crate::audit::AgentSigningKey::load_or_bootstrap(&dir.path().join("k")).unwrap();
        let cfg = RotationConfig {
            size_cap_bytes: 600,
            max_archives: 32,
            file_mode: 0o600,
        };
        let mut log =
            RotatingChainLog::<P>::open(&active, key, cfg, std::sync::Arc::new(NoProtection))
                .unwrap();
        for n in 0..12 {
            log.append(P {
                ts: format!("2026-10-15T10:00:{n:02}.000000Z"),
                n,
            })
            .unwrap();
        }
        assert!(!crate::chainlog::archives_newest_first(&active).is_empty());
        let t = read_chain_tail(&active, &all(1 << 20));
        assert_eq!(numbers(&t), (0..12).rev().collect::<Vec<_>>());
    }
}
