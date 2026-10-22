//! The line reader of the full verifiers and of the forensic reader:
//! external audit EVD-017 / MAIN-014 (NN-AUD-280, NN-AUD-256; Wave 3, lab
//! PR 190).
//!
//! `nn-admin chain verify` (the rotating logs, their manifests, the audit
//! chain), `nn-admin audit verify` and `nn-admin audit read` read files an
//! operator copies around and an intruder may have damaged. `BufRead::lines`
//! and `read_until` keep a whole line however long it is (a file without a
//! newline is a single line, read into memory whole) and `lines` fails on a
//! line that is not UTF-8. Here a line is kept up to
//! [`MAX_VERIFY_LINE_BYTES`]; a longer one is consumed to its newline
//! through the reader's own buffer, reported with its length and never
//! stored. Every line comes back with its 1-based number and the offset past
//! it, empty lines included, so a caller can name the line it could not use
//! and go on with the next one. The memory a file costs is one line,
//! whatever the file's size.

use std::io::{BufRead, ErrorKind};

/// Longest line the verifiers keep: 16 MiB. Far above any row the agent
/// writes: an admin row's operator strings come from one signed frame of at
/// most `MAX_FRAME_BODY` (64 KiB, at most six bytes of JSON escape each),
/// the rows the agent writes for itself and the rotating logs' records are
/// built from bounded kernel records and rule texts. A longer line cannot
/// be a row the agent wrote, and it is reported, not buffered.
pub const MAX_VERIFY_LINE_BYTES: usize = 16 * 1024 * 1024;

const _: () = assert!(
    MAX_VERIFY_LINE_BYTES >= 6 * (nn_proto::admin_protocol::MAX_FRAME_BODY + 4096) + 64 * 1024,
    "a row the agent can write must fit the verifiers' line cap"
);

/// What a line holds.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LineBody<'a> {
    /// The line's bytes, without its newline.
    Bytes(&'a [u8]),
    /// Longer than the cap: `len` bytes (newline excluded), consumed, not
    /// kept.
    Oversized { len: u64 },
}

/// One line of a file.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Line<'a> {
    /// 1-based, empty lines counted.
    pub number: u64,
    /// Offset past the line and its newline.
    pub end: u64,
    /// Ends in a newline; `false` for bytes after the file's last newline
    /// (a write cut short, or one in progress).
    pub newline: bool,
    pub body: LineBody<'a>,
}

impl Line<'_> {
    /// The line as text, or why it is not: over the cap, not UTF-8.
    pub fn text(&self) -> Result<&str, String> {
        match self.body {
            LineBody::Bytes(b) => std::str::from_utf8(b).map_err(|e| format!("not UTF-8 ({e})")),
            LineBody::Oversized { len } => Err(format!(
                "{len} bytes, longer than {MAX_VERIFY_LINE_BYTES} bytes: not read"
            )),
        }
    }

    /// Empty (a lone newline): the readers skip it.
    pub fn is_empty(&self) -> bool {
        matches!(self.body, LineBody::Bytes(b) if b.is_empty())
    }
}

/// Bounded line reader (see the module doc).
pub(crate) struct VerifyLines<R> {
    reader: R,
    buf: Vec<u8>,
    max: usize,
    number: u64,
    offset: u64,
}

impl<R: BufRead> VerifyLines<R> {
    pub fn new(reader: R) -> Self {
        Self::with_max(reader, MAX_VERIFY_LINE_BYTES)
    }

    pub(crate) fn with_max(reader: R, max: usize) -> Self {
        Self {
            reader,
            buf: Vec::new(),
            max,
            number: 0,
            offset: 0,
        }
    }

    /// The next line, `None` at the end of the file. An I/O error is the
    /// caller's: the file itself could not be read.
    pub fn next_line(&mut self) -> std::io::Result<Option<Line<'_>>> {
        self.buf.clear();
        let mut len = 0u64;
        let mut oversized = false;
        let mut newline = false;
        let mut read_any = false;
        loop {
            let avail = match self.reader.fill_buf() {
                Ok(b) => b,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            if avail.is_empty() {
                break;
            }
            read_any = true;
            let nl = avail.iter().position(|&b| b == b'\n');
            let part = &avail[..nl.unwrap_or(avail.len())];
            len += part.len() as u64;
            if !oversized {
                if self.buf.len() + part.len() > self.max {
                    oversized = true;
                    self.buf.clear();
                } else {
                    self.buf.extend_from_slice(part);
                }
            }
            let used = nl.map_or(avail.len(), |i| i + 1);
            self.reader.consume(used);
            self.offset += used as u64;
            if nl.is_some() {
                newline = true;
                break;
            }
        }
        if !read_any {
            return Ok(None);
        }
        self.number += 1;
        Ok(Some(Line {
            number: self.number,
            end: self.offset,
            newline,
            body: if oversized {
                LineBody::Oversized { len }
            } else {
                LineBody::Bytes(&self.buf)
            },
        }))
    }

    /// Bytes consumed so far.
    pub fn offset(&self) -> u64 {
        self.offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;

    type Seen = (u64, u64, bool, Result<String, u64>);

    fn collect(bytes: &[u8], max: usize) -> Vec<Seen> {
        let mut r = VerifyLines::with_max(BufReader::with_capacity(16, bytes), max);
        let mut out = Vec::new();
        while let Some(l) = r.next_line().unwrap() {
            let body = match l.body {
                LineBody::Bytes(b) => Ok(String::from_utf8_lossy(b).into_owned()),
                LineBody::Oversized { len } => Err(len),
            };
            out.push((l.number, l.end, l.newline, body));
        }
        assert_eq!(r.offset(), bytes.len() as u64);
        out
    }

    #[test]
    fn every_line_comes_back_numbered_with_its_end_empty_ones_included() {
        let got = collect(b"a\n\nbb\nccc", 8);
        assert_eq!(
            got,
            vec![
                (1, 2, true, Ok("a".into())),
                (2, 3, true, Ok(String::new())),
                (3, 6, true, Ok("bb".into())),
                (4, 9, false, Ok("ccc".into())),
            ]
        );
        assert!(collect(b"", 8).is_empty());
    }

    #[test]
    fn a_line_at_the_cap_is_kept_one_byte_more_is_reported_with_its_length() {
        let body = format!(
            "{}\n{}\nz\n{}",
            "x".repeat(8),
            "y".repeat(9),
            "w".repeat(20)
        );
        let got = collect(body.as_bytes(), 8);
        assert_eq!(
            got,
            vec![
                (1, 9, true, Ok("x".repeat(8))),
                (2, 19, true, Err(9)),
                (3, 21, true, Ok("z".into())),
                (4, 41, false, Err(20)),
            ]
        );
    }

    /// The over-cap line is consumed, never stored: the buffer stays within
    /// the cap however long the line is.
    #[test]
    fn an_oversized_line_is_consumed_without_being_stored() {
        let mut body = b"first\n".to_vec();
        body.extend_from_slice(&vec![b'q'; 4 * 1024 * 1024]);
        body.extend_from_slice(b"\nlast\n");
        let mut r = VerifyLines::with_max(BufReader::new(&body[..]), 1024);
        assert_eq!(r.next_line().unwrap().unwrap().text(), Ok("first"));
        let l = r.next_line().unwrap().unwrap();
        assert_eq!(
            l.body,
            LineBody::Oversized {
                len: 4 * 1024 * 1024
            }
        );
        assert!(l.text().unwrap_err().contains("longer than"));
        assert!(r.buf.capacity() <= 2 * 1024, "{}", r.buf.capacity());
        assert_eq!(r.next_line().unwrap().unwrap().text(), Ok("last"));
        assert!(r.next_line().unwrap().is_none());
    }

    #[test]
    fn a_line_that_is_not_utf8_is_named_not_an_error() {
        let mut r = VerifyLines::new(BufReader::new(&b"ok\n\xff\xfe{}\nok2\n"[..]));
        assert_eq!(r.next_line().unwrap().unwrap().text(), Ok("ok"));
        let bad = r.next_line().unwrap().unwrap();
        assert_eq!(bad.number, 2);
        assert!(bad.text().unwrap_err().starts_with("not UTF-8"));
        assert_eq!(r.next_line().unwrap().unwrap().text(), Ok("ok2"));
    }
}
