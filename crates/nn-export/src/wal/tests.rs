//! The chains as the log: rows read after a cursor across rotations, each
//! once, with their place and the terminator that links them; evictions
//! counted; a cursor that is gone or ahead handled; nothing past a line
//! still being written.

use super::*;
use crate::testing::{TestHost, TestKey};
use nn_evidence::chainlog::{ChainPayload, NoProtection, RotatingChainLog, RotationConfig};
use nn_proto::ipc::{MAX_EXPORT_BYTES, MAX_EXPORT_ROWS};
use std::io::Write;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Pay {
    n: u64,
    pad: String,
}

impl ChainPayload for Pay {
    const KIND: &'static str = "detections";
}

fn pk() -> VerifyingKey {
    use nn_evidence::chain_host::ChainSigner;
    TestKey::new(9).verifying_key()
}

fn log(active: &Path, cap: u64, archives: usize) -> RotatingChainLog<Pay, TestKey> {
    RotatingChainLog::open(
        active,
        TestKey::new(9),
        RotationConfig {
            size_cap_bytes: cap,
            max_archives: archives,
            file_mode: 0o600,
        },
        std::sync::Arc::new(NoProtection),
    )
    .unwrap()
}

fn write(active: &Path, from: u64, to: u64, cap: u64, archives: usize) {
    let mut l = log(active, cap, archives);
    for n in from..to {
        l.append_deferred(Pay {
            n,
            pad: "x".repeat(40),
        })
        .unwrap();
    }
    l.sync().unwrap();
}

fn src(active: &Path) -> Source {
    Source {
        chain: ExportChain::Detections,
        active: active.to_path_buf(),
    }
}

const ALL: Limits = Limits {
    rows: 10_000,
    bytes: 1 << 30,
};

fn ns(b: &Batch) -> Vec<u64> {
    b.rows
        .iter()
        .map(|r| {
            serde_json::from_slice::<serde_json::Value>(&r.raw).unwrap()["n"]
                .as_u64()
                .unwrap()
        })
        .collect()
}

#[test]
fn every_row_once_across_rotations_with_its_link() {
    let d = tempfile::tempdir().unwrap();
    let active = d.path().join("detections.jsonl");
    write(&active, 0, 30, 1000, 64);
    let s = src(&active);
    let b = read_after::<TestHost>(&s, &Cursor::start_of(1), false, ALL, &pk()).unwrap();
    assert_eq!(ns(&b), (0..30).collect::<Vec<_>>());
    assert_eq!(b.lost, 0);
    assert!(b.notes.is_empty(), "{:?}", b.notes);
    let files: std::collections::BTreeSet<u64> = b.rows.iter().map(|r| r.file).collect();
    assert!(files.len() >= 3, "rotated: {files:?}");
    let mut prev: Option<String> = None;
    for (r, h) in b.rows.iter().zip(&b.hashes) {
        let seal = nn_evidence::row_verify::verify_row(&r.raw, "detections", &pk()).unwrap();
        assert_eq!(&seal.entry_hash, h);
        assert!(r.line >= 1 && r.end > 0);
        // the first row of a later file carries the terminator its
        // prev_hash names
        if r.line == 1 && r.file > 1 {
            let t = r.rotate.as_ref().expect("the terminator");
            let ts = nn_evidence::row_verify::verify_row(t, "detections", &pk()).unwrap();
            assert!(ts.terminator);
            assert_eq!(ts.entry_hash, seal.prev_hash);
            assert_eq!(prev.as_ref(), Some(&ts.prev_hash));
        } else {
            assert!(r.rotate.is_none());
            if let Some(p) = &prev {
                assert_eq!(&seal.prev_hash, p);
            }
        }
        prev = Some(seal.entry_hash);
    }
    // the next cursor is the last row: nothing more until a row is written
    let next = b.next.clone().unwrap();
    assert_eq!(next.pos(), b.rows.last().unwrap().pos());
    let again = read_after::<TestHost>(&s, &next, true, ALL, &pk()).unwrap();
    assert!(again.rows.is_empty() && again.notes.is_empty());
    write(&active, 30, 33, 1000, 64);
    let more = read_after::<TestHost>(&s, &next, true, ALL, &pk()).unwrap();
    assert_eq!(ns(&more), vec![30, 31, 32]);
}

#[test]
fn reads_are_bounded_and_resume_where_they_stopped() {
    let d = tempfile::tempdir().unwrap();
    let active = d.path().join("detections.jsonl");
    write(&active, 0, 25, 1000, 64);
    let s = src(&active);
    let mut cur = Cursor::start_of(1);
    let mut got = Vec::new();
    for _ in 0..40 {
        let b = read_after::<TestHost>(
            &s,
            &cur,
            false,
            Limits {
                rows: 4,
                bytes: 1 << 20,
            },
            &pk(),
        )
        .unwrap();
        if b.rows.is_empty() {
            break;
        }
        assert!(b.rows.len() <= 4);
        got.extend(ns(&b));
        cur = b.next.unwrap();
    }
    assert_eq!(got, (0..25).collect::<Vec<_>>());
    // by bytes: at least one row a read
    let b = read_after::<TestHost>(
        &s,
        &Cursor::start_of(1),
        false,
        Limits {
            rows: 100,
            bytes: 1,
        },
        &pk(),
    )
    .unwrap();
    assert_eq!(b.rows.len(), 1);
}

/// A batch never passes its bytes (rows and terminators), unless it is
/// one row: the request built from it passes its check, whatever the
/// chain's backlog (lot 276's lab: a backlog of netflow rows made batches
/// a row past MAX_EXPORT_BYTES, each request refused).
#[test]
fn a_batch_never_passes_its_bytes() {
    let d = tempfile::tempdir().unwrap();
    let active = d.path().join("detections.jsonl");
    write(&active, 0, 60, 1500, 64);
    let s = src(&active);
    for limit in [1usize, 300, 700, 1000, 2500, 4096] {
        let mut cur = Cursor::start_of(1);
        let mut got = Vec::new();
        for _ in 0..200 {
            let b = read_after::<TestHost>(
                &s,
                &cur,
                false,
                Limits {
                    rows: MAX_EXPORT_ROWS,
                    bytes: limit,
                },
                &pk(),
            )
            .unwrap();
            if b.rows.is_empty() {
                break;
            }
            let bytes: usize = b
                .rows
                .iter()
                .map(|r| r.raw.len() + r.rotate.as_ref().map_or(0, Vec::len))
                .sum();
            assert!(
                bytes <= limit || b.rows.len() == 1,
                "{bytes} bytes in {} rows, limit {limit}",
                b.rows.len()
            );
            let req = nn_proto::ipc::ExportRows {
                sink: nn_proto::ipc::ExportSink::Syslog,
                chain: ExportChain::Detections,
                rows: b.rows.clone(),
                budget_ms: 1000,
            };
            assert_eq!(req.check(), Ok(()));
            got.extend(ns(&b));
            cur = b.next.unwrap();
        }
        assert_eq!(got, (0..60).collect::<Vec<_>>(), "limit {limit}");
    }
    // the export's own bound: a backlog of rows reads in batches its
    // requests carry
    let b = read_after::<TestHost>(
        &s,
        &Cursor::start_of(1),
        false,
        Limits {
            rows: MAX_EXPORT_ROWS,
            bytes: MAX_EXPORT_BYTES,
        },
        &pk(),
    )
    .unwrap();
    assert!(!b.rows.is_empty());
}

#[test]
fn a_cursor_at_the_end_reads_only_what_follows() {
    let d = tempfile::tempdir().unwrap();
    let active = d.path().join("detections.jsonl");
    write(&active, 0, 12, 1000, 64);
    let s = src(&active);
    let end = initial::<TestHost>(&s, false).unwrap();
    assert_eq!(end.file, chainlog::current_generation(&active));
    assert!(end.line > 0 && !end.hash.is_empty());
    assert!(read_after::<TestHost>(&s, &end, true, ALL, &pk())
        .unwrap()
        .rows
        .is_empty());
    write(&active, 12, 15, 1000, 64);
    assert_eq!(
        ns(&read_after::<TestHost>(&s, &end, true, ALL, &pk()).unwrap()),
        vec![12, 13, 14]
    );
    // the oldest: from the earliest archive
    let oldest = initial::<TestHost>(&s, true).unwrap();
    assert_eq!(oldest, Cursor::start_of(1));
    // no chain yet: the end is its first file's start
    let none = src(&d.path().join("none.jsonl"));
    assert_eq!(
        initial::<TestHost>(&none, false).unwrap(),
        Cursor::start_of(1)
    );
    assert!(
        read_after::<TestHost>(&none, &Cursor::start_of(1), false, ALL, &pk())
            .unwrap()
            .rows
            .is_empty()
    );
}

#[test]
fn evicted_files_are_counted_lost() {
    let d = tempfile::tempdir().unwrap();
    let active = d.path().join("detections.jsonl");
    write(&active, 0, 40, 600, 2);
    let s = src(&active);
    let earliest = chainlog::earliest_archive(&active).unwrap();
    assert!(earliest > 2, "evicted");
    let b = read_after::<TestHost>(&s, &Cursor::start_of(1), false, ALL, &pk()).unwrap();
    let first = ns(&b)[0];
    assert!(first > 0);
    assert_eq!(b.lost, first, "every row before the oldest file is counted");
    assert!(matches!(
        b.notes[0],
        Note::Evicted { files, rows: Some(r) } if files == earliest - 1 && r == first
    ));
    assert_eq!(*ns(&b).last().unwrap(), 39);
}

/// A cursor inside a file that was evicted since: only the rows after it
/// are lost, not the ones it had delivered. (One run of the log: a file
/// that spans a restart has a manifest count of its last run's rows only —
/// the count is a lower bound, `EXPORT.md` §3.)
#[test]
fn a_file_evicted_under_its_cursor_counts_only_the_rows_after_it() {
    let d = tempfile::tempdir().unwrap();
    let active = d.path().join("detections.jsonl");
    let mut l = log(&active, 1200, 2);
    let mut append = |from: u64, to: u64| {
        for n in from..to {
            l.append_deferred(Pay {
                n,
                pad: "x".repeat(40),
            })
            .unwrap();
        }
        l.sync().unwrap();
    };
    append(0, 6);
    let s = src(&active);
    let two = Limits {
        rows: 2,
        bytes: 1 << 30,
    };
    let b = read_after::<TestHost>(&s, &Cursor::start_of(1), true, two, &pk()).unwrap();
    assert_eq!(ns(&b), vec![0, 1]);
    let cur = b.next.unwrap();
    assert_eq!((cur.file, cur.line), (1, 2));
    // more rows: file 1 (and those after it) evicted
    append(6, 30);
    assert!(chainlog::earliest_archive(&active).unwrap() > 2);
    let b = read_after::<TestHost>(&s, &cur, true, ALL, &pk()).unwrap();
    let first = ns(&b)[0];
    assert_eq!(b.lost, first - 2, "rows 0 and 1 were delivered");
    assert!(matches!(
        b.notes[0],
        Note::Evicted { rows: Some(r), .. } if r == first - 2
    ));
    assert_eq!(*ns(&b).last().unwrap(), 29);
}

#[test]
fn a_cursor_gone_or_ahead_is_read_again_never_skipped() {
    let d = tempfile::tempdir().unwrap();
    let active = d.path().join("detections.jsonl");
    write(&active, 0, 6, 1 << 20, 4);
    let s = src(&active);
    let b = read_after::<TestHost>(&s, &Cursor::start_of(1), false, ALL, &pk()).unwrap();
    let mut gone = b.next.clone().unwrap();
    gone.hash = "f".repeat(64);
    // checked (a start): the file again from its start
    let again = read_after::<TestHost>(&s, &gone, true, ALL, &pk()).unwrap();
    assert_eq!(again.notes, vec![Note::CursorGone { file: 1, line: 6 }]);
    assert_eq!(ns(&again), (0..6).collect::<Vec<_>>());
    // a cursor of another installation, past the chain
    let ahead = read_after::<TestHost>(&s, &Cursor::start_of(99), false, ALL, &pk()).unwrap();
    assert_eq!(ahead.notes, vec![Note::CursorAhead { file: 99 }]);
    assert_eq!(ns(&ahead), (0..6).collect::<Vec<_>>());
}

#[test]
fn a_line_still_being_written_waits_and_a_long_one_is_lost() {
    let d = tempfile::tempdir().unwrap();
    let active = d.path().join("detections.jsonl");
    write(&active, 0, 2, 1 << 20, 4);
    let s = src(&active);
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&active)
        .unwrap();
    f.write_all(b"{\"n\":99").unwrap();
    let b = read_after::<TestHost>(&s, &Cursor::start_of(1), false, ALL, &pk()).unwrap();
    assert_eq!(ns(&b), vec![0, 1]);
    assert_eq!(b.next.unwrap().line, 2);
    // genuine rows longer than a request carries: lost to the export, the
    // rows after them read
    let d = tempfile::tempdir().unwrap();
    let active = d.path().join("detections.jsonl");
    {
        let mut l = log(&active, 1 << 30, 4);
        for (n, pad) in [
            (0, 10),
            (1, MAX_EXPORT_ROW + 10),
            (2, 10),
            (3, 5 * MAX_EXPORT_ROW),
            (4, 10),
        ] {
            l.append_deferred(Pay {
                n,
                pad: "y".repeat(pad),
            })
            .unwrap();
        }
        l.sync().unwrap();
    }
    let b = read_after::<TestHost>(&src(&active), &Cursor::start_of(1), false, ALL, &pk()).unwrap();
    assert_eq!(ns(&b), vec![0, 2, 4]);
    assert_eq!(b.lost, 2);
    assert!(matches!(
        b.notes[..],
        [
            Note::Oversize {
                file: 1,
                line: 2,
                ..
            },
            Note::Oversize {
                file: 1,
                line: 4,
                ..
            }
        ]
    ));
    // the rows keep their lines
    assert_eq!(
        b.rows.iter().map(|r| r.line).collect::<Vec<_>>(),
        vec![1, 3, 5]
    );
}

#[test]
fn the_flat_chain_is_one_file() {
    let d = tempfile::tempdir().unwrap();
    let active = d.path().join("canary_access.jsonl");
    std::fs::write(&active, b"{\"a\":1}\n{\"a\":2}\n").unwrap();
    let s = Source {
        chain: ExportChain::CanaryAccess,
        active,
    };
    assert_eq!(current_file(&s), 0);
    let b = read_after::<TestHost>(&s, &Cursor::start_of(0), false, ALL, &pk()).unwrap();
    assert_eq!(b.rows.len(), 2);
    assert!(b.rows.iter().all(|r| r.file == 0 && r.rotate.is_none()));
    assert_eq!(initial::<TestHost>(&s, false).unwrap().line, 2);
    assert_eq!(initial::<TestHost>(&s, true).unwrap(), Cursor::start_of(0));
}

#[test]
fn cursors_are_saved_atomically_and_read_back() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("cursors.json");
    let (c, why) = Cursors::load(&p);
    assert_eq!((c, why), (Cursors::default(), None));
    let mut c = Cursors::default();
    c.cursors.insert(
        key(ExportSink::Syslog, ExportChain::Netflow),
        Cursor {
            file: 3,
            line: 9,
            end: 1234,
            hash: "a".repeat(64),
        },
    );
    c.save(&p).unwrap();
    let (back, why) = Cursors::load(&p);
    assert_eq!(why, None);
    assert_eq!(back.cursors, c.cursors);
    assert_eq!(back.version, Cursors::VERSION);
    assert!(!d.path().join(".cursors.json.tmp").exists());
    std::fs::write(&p, b"{\"version\":7,\"cursors\":{}}").unwrap();
    assert!(Cursors::load(&p).1.unwrap().contains("version 7"));
    std::fs::write(&p, b"junk").unwrap();
    assert!(Cursors::load(&p).1.is_some());
}

/// The review of #499, X1: the writer appends a file's terminator, then
/// renames the file to its archive. A read in between finds the
/// terminator and no archive yet: it stops at the last row — no row from
/// the chain's oldest file, no note — and reads on once the rename is done,
/// the next file's first row carrying that terminator. The batch it sends
/// then passes the protocol's check of an honest worker's answer.
#[test]
fn a_read_inside_the_rotation_window_waits_for_the_rename() {
    use nn_proto::ipc::{check_rows_out, ExportRows, ExportRowsOut, ExportSink, SinkState};
    let d = tempfile::tempdir().unwrap();
    let active = d.path().join("detections.jsonl");
    write(&active, 0, 30, 1000, 64);
    let s = src(&active);
    let all = read_after::<TestHost>(&s, &Cursor::start_of(1), false, ALL, &pk()).unwrap();
    let last_file = all.rows.iter().map(|r| r.file).max().unwrap();
    let archived = last_file - 1;
    assert!(archived >= 2, "two archives at least");
    // the window: the last archive back as the active file, its terminator
    // its last line, the file after it not there yet
    let arch = chainlog::archive_path_for(&active, archived);
    let newest = d.path().join("newest");
    std::fs::rename(&active, &newest).unwrap();
    std::fs::rename(&arch, &active).unwrap();
    assert_eq!(current_file(&s), archived);
    let i = all.rows.iter().rposition(|r| r.file == archived).unwrap();
    let last = &all.rows[i];
    let cur = Cursor {
        file: last.file,
        line: last.line,
        end: last.end,
        hash: all.hashes[i].clone(),
    };
    for check in [false, true] {
        let b = read_after::<TestHost>(&s, &cur, check, ALL, &pk()).unwrap();
        assert!(
            b.rows.is_empty(),
            "{} rows from {:?}",
            b.rows.len(),
            b.rows.first().map(|r| r.pos())
        );
        assert!(b.notes.is_empty(), "{:?}", b.notes);
        assert_eq!(b.lost, 0);
        assert_eq!(b.next.as_ref().map(Cursor::pos), Some(cur.pos()));
    }
    // a sink a few rows behind reads up to the terminator, and stops
    let j = all.rows.iter().position(|r| r.file == archived).unwrap();
    let from = Cursor {
        file: all.rows[j].file,
        line: all.rows[j].line,
        end: all.rows[j].end,
        hash: all.hashes[j].clone(),
    };
    let b = read_after::<TestHost>(&s, &from, false, ALL, &pk()).unwrap();
    assert!(b
        .rows
        .iter()
        .all(|r| r.file == archived && r.line > from.line));
    assert_eq!(b.rows.last().map(|r| r.pos()), Some(last.pos()));
    assert!(b.notes.is_empty());
    // the rename done: the next file's first row, with its terminator
    std::fs::rename(&active, &arch).unwrap();
    std::fs::rename(&newest, &active).unwrap();
    let b = read_after::<TestHost>(&s, &cur, true, ALL, &pk()).unwrap();
    assert!(b.notes.is_empty(), "{:?}", b.notes);
    let first = &b.rows[0];
    assert_eq!((first.file, first.line), (archived + 1, 1));
    let t = std::fs::read(&arch).unwrap();
    let t_line = t[..t.len() - 1].rsplit(|c| *c == b'\n').next().unwrap();
    assert_eq!(first.rotate.as_deref(), Some(t_line));
    // what the core sends then, and an honest worker's answer: accepted
    let req = ExportRows {
        sink: ExportSink::File,
        chain: ExportChain::Detections,
        rows: b.rows.clone(),
        budget_ms: 1000,
    };
    assert_eq!(req.check(), Ok(()));
    let end = req.rows.last().unwrap().pos();
    let out = ExportRowsOut {
        acked: Some(end),
        committed: Some(end),
        records: req.rows.len() as u32,
        unverified: 0,
        state: SinkState::Up,
        fault: None,
        retry_ms: 0,
    };
    assert_eq!(check_rows_out(&req, &out), Ok(()));
}

/// The review of #499, D3: a blank line in a chain is no row any request
/// carries — it is lost here, counted and noted; the rows around it go,
/// and a cursor left on it holds at a start.
#[test]
fn a_blank_line_is_lost_counted_and_never_sent() {
    use nn_proto::ipc::{ExportRows, ExportSink};
    use std::io::Write as _;
    let d = tempfile::tempdir().unwrap();
    let active = d.path().join("detections.jsonl");
    write(&active, 0, 3, 1 << 20, 4);
    std::fs::OpenOptions::new()
        .append(true)
        .open(&active)
        .unwrap()
        .write_all(b"\n")
        .unwrap();
    let s = src(&active);
    let lim = Limits {
        rows: MAX_EXPORT_ROWS,
        bytes: MAX_EXPORT_BYTES,
    };
    let b = read_after::<TestHost>(&s, &Cursor::start_of(1), false, lim, &pk()).unwrap();
    assert_eq!(ns(&b), vec![0, 1, 2]);
    assert_eq!(b.lost, 1);
    assert_eq!(b.notes, vec![Note::Blank { file: 1, line: 4 }]);
    let req = ExportRows {
        sink: ExportSink::File,
        chain: ExportChain::Detections,
        rows: b.rows.clone(),
        budget_ms: 1000,
    };
    assert_eq!(req.check(), Ok(()));
    // the cursor on the blank line holds at a start: nothing read again
    let next = b.next.unwrap();
    assert_eq!((next.line, next.hash.as_str()), (4, ""));
    let again = read_after::<TestHost>(&s, &next, true, lim, &pk()).unwrap();
    assert!(
        again.rows.is_empty() && again.notes.is_empty(),
        "{:?}",
        again.notes
    );
}
