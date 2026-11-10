//! Lot 296 (external bug hunt BUG31): the JSONL sink after a write stopped
//! part-way. A binary of its own: each test lowers the file size limit
//! (`RLIMIT_FSIZE`) of the whole process for an instant — the kernel's own
//! short write, as a full disk makes it (the first `write` takes what fits,
//! the next fails) — so no other test of the crate may run beside them; the
//! tests here take turns.

use std::sync::Mutex;

use nn_export::jsonl::{JsonlSink, ACTIVE};

static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// `write` with the files of the process bounded to `limit` bytes.
fn write_bounded(s: &mut JsonlSink, lines: &[Vec<u8>], limit: u64) -> Result<(), i32> {
    let mut old = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: signal/getrlimit/setrlimit with valid arguments; the limit is
    // put back at once, before any assertion.
    unsafe {
        libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
        assert_eq!(libc::getrlimit(libc::RLIMIT_FSIZE, &mut old), 0);
        let low = libc::rlimit {
            rlim_cur: limit,
            rlim_max: old.rlim_max,
        };
        assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &low), 0);
    }
    let r = s.write(lines);
    // SAFETY: as above.
    unsafe {
        assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &old), 0);
    }
    r
}

fn lines_of(body: &[u8]) -> Vec<&[u8]> {
    let mut v: Vec<&[u8]> = body.split(|b| *b == b'\n').collect();
    assert_eq!(v.pop(), Some(&b""[..]), "the file ends in a newline");
    v
}

/// The triage's test: a batch retried after a write that stopped at 10
/// bytes is still one record per line — its first record was glued to
/// the 10 bytes (`{"rec":1,"{"rec":1,"x":"aaaaaaaa"}`), acknowledged and
/// no longer a line of its own.
#[test]
fn retry_after_partial_write_keeps_whole_lines() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let d = tempfile::tempdir().unwrap();
    let rec = br#"{"rec":1,"x":"aaaaaaaa"}"#.to_vec();
    let mut s = JsonlSink::open(d.path(), 1 << 20, 3).unwrap();
    assert_eq!(
        write_bounded(&mut s, std::slice::from_ref(&rec), 10),
        Err(libc::EFBIG)
    );
    assert_eq!(std::fs::read(d.path().join(ACTIVE)).unwrap(), &rec[..10]);
    s.write(std::slice::from_ref(&rec)).unwrap();
    let body = std::fs::read(d.path().join(ACTIVE)).unwrap();
    assert!(
        body.split(|b| *b == b'\n').any(|l| l == rec.as_slice()),
        "the acknowledged record is not a line of the file: {:?}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(lines_of(&body), [&rec[..10], &rec[..]]);
    assert_eq!(s.size(), body.len() as u64);
    // a later batch: no newline of its own before it
    s.write(&[b"{\"rec\":2}".to_vec()]).unwrap();
    let body = std::fs::read(d.path().join(ACTIVE)).unwrap();
    assert_eq!(lines_of(&body), [&rec[..10], &rec[..], b"{\"rec\":2}"]);
}

/// A write that stopped right after a newline left whole lines: the batch
/// written again gets no empty line before it.
#[test]
fn a_write_stopped_at_a_line_s_end_adds_no_empty_line() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let d = tempfile::tempdir().unwrap();
    let (a, b) = (b"{\"n\":1}".to_vec(), b"{\"n\":2}".to_vec());
    let mut s = JsonlSink::open(d.path(), 1 << 20, 3).unwrap();
    s.write(std::slice::from_ref(&a)).unwrap();
    // the file may grow to the end of the next line, not past it
    let limit = 2 * (a.len() as u64 + 1);
    assert_eq!(
        write_bounded(&mut s, &[a.clone(), b.clone()], limit),
        Err(libc::EFBIG)
    );
    s.write(std::slice::from_ref(&b)).unwrap();
    let body = std::fs::read(d.path().join(ACTIVE)).unwrap();
    assert_eq!(lines_of(&body), [&a[..], &a[..], &b[..]]);
}

/// The start of a line left in a file that a rotation then archives is
/// closed in that file; the new active file has whole lines only.
#[test]
fn a_rotation_after_a_partial_write_closes_the_line_in_its_file() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let d = tempfile::tempdir().unwrap();
    let rec = br#"{"rec":1,"x":"bbbbbbbbbbbbbbbbbbbb"}"#.to_vec();
    let mut s = JsonlSink::open(d.path(), 40, 3).unwrap();
    assert_eq!(
        write_bounded(&mut s, std::slice::from_ref(&rec), 12),
        Err(libc::EFBIG)
    );
    // the batch again, and one more: each passes the 40 bytes of the file
    // before it, so each rotates — the start of the line first closed
    s.write(&[rec.clone(), b"{\"rec\":2}".to_vec()]).unwrap();
    let file = |n: u8| std::fs::read(d.path().join(format!("{ACTIVE}.{n}"))).unwrap();
    assert_eq!(lines_of(&file(2)), [&rec[..12]]);
    assert_eq!(lines_of(&file(1)), [&rec[..]]);
    let active = std::fs::read(d.path().join(ACTIVE)).unwrap();
    assert_eq!(lines_of(&active), [b"{\"rec\":2}"]);
    // the new file is whole: nothing to close before the next line
    s.write(&[b"{\"rec\":3}".to_vec()]).unwrap();
    let active = std::fs::read(d.path().join(ACTIVE)).unwrap();
    assert_eq!(lines_of(&active), [b"{\"rec\":2}", b"{\"rec\":3}"]);
}

/// The active file gone after a write stopped part-way (a new one opened):
/// nothing to close in it — no empty line first.
#[test]
fn a_new_active_file_after_a_partial_write_has_no_empty_line() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let d = tempfile::tempdir().unwrap();
    let rec = br#"{"rec":1,"x":"cccccccc"}"#.to_vec();
    let mut s = JsonlSink::open(d.path(), 1 << 20, 3).unwrap();
    assert_eq!(
        write_bounded(&mut s, std::slice::from_ref(&rec), 10),
        Err(libc::EFBIG)
    );
    std::fs::remove_file(d.path().join(ACTIVE)).unwrap();
    s.write(std::slice::from_ref(&rec)).unwrap();
    let body = std::fs::read(d.path().join(ACTIVE)).unwrap();
    assert_eq!(lines_of(&body), [&rec[..]]);
}
