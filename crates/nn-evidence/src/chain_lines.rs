//! The one line reader of the canary chains (`canaries.jsonl`,
//! `canary_access.jsonl`): external audit DEC-012 (NN-AUD-337, Wave 3,
//! lab PR 178).
//!
//! `BufRead::lines` had no cap — a line of any length was materialised at
//! boot — and returned an error on a line that is not UTF-8, which the
//! readers' `?` turned into a failed open: the agent logged "canary
//! registry open failed" and ran the boot without deception. The DEC-006
//! skip (lab PR 90) covered only a line that did not parse. Here a line is
//! at most [`MAX_CHAIN_LINE_BYTES`]: a longer one is consumed to its
//! newline through the reader's own buffer and never stored, and a line
//! that is too long or not UTF-8 comes back [`ChainLine::Unreadable`],
//! which the callers skip and count like a line that does not parse (the
//! signed `chain_lines_unreadable` at boot). The memory a file costs is one
//! line, whatever its size; the file is still read to its end, so every row
//! after a bad line is applied.

use std::io::{BufRead, ErrorKind};

/// Longest line of a canary chain: 1 MiB. Every row the agent writes is
/// far below it: the operator's strings in a row (name, path, family,
/// `fake_arg0`, address) all come from one signed admin frame of at most
/// `MAX_FRAME_BODY` (64 KiB), a JSON escape is at most six bytes for one,
/// an access row adds a `/proc/<pid>/exe` of at most `PATH_MAX`, and the
/// rest is fixed-size (hashes, signature, ids). The writers refuse a row
/// over the cap, so no row they write is skipped at the next boot. The agent
/// holds this cap to the admin protocol's frame bound at build time
/// (`admin_socket`, R04a, lab PR 241).
pub const MAX_CHAIN_LINE_BYTES: usize = 1024 * 1024;

/// One line of a chain file.
#[derive(Debug, PartialEq, Eq)]
pub enum ChainLine<'a> {
    /// A complete, non-empty line without its newline: UTF-8, within the cap.
    Text(&'a str),
    /// Over the cap, or not UTF-8: skip it and count it.
    Unreadable,
}

/// What [`ChainLines::fill`] found.
enum Fill {
    Eof,
    Line,
    Oversized,
}

/// Bounded line reader over a chain file (see the module doc).
pub struct ChainLines<R> {
    reader: R,
    buf: Vec<u8>,
    max: usize,
}

impl<R: BufRead> ChainLines<R> {
    pub fn new(reader: R) -> Self {
        Self::with_max(reader, MAX_CHAIN_LINE_BYTES)
    }

    fn with_max(reader: R, max: usize) -> Self {
        Self {
            reader,
            buf: Vec::new(),
            max,
        }
    }

    /// The next non-empty line, `None` at the end of the file. An I/O
    /// error is the caller's: the file itself could not be read.
    pub fn next_line(&mut self) -> std::io::Result<Option<ChainLine<'_>>> {
        loop {
            match self.fill()? {
                Fill::Eof => return Ok(None),
                Fill::Oversized => return Ok(Some(ChainLine::Unreadable)),
                Fill::Line if self.buf.is_empty() => continue,
                Fill::Line => break,
            }
        }
        Ok(Some(match std::str::from_utf8(&self.buf) {
            Ok(s) => ChainLine::Text(s),
            Err(_) => ChainLine::Unreadable,
        }))
    }

    /// Read up to and including the next newline (or the end of the file)
    /// into `buf`, keeping at most `max` bytes: past that the line is only
    /// consumed.
    fn fill(&mut self) -> std::io::Result<Fill> {
        self.buf.clear();
        let mut oversized = false;
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
            if nl.is_some() {
                break;
            }
        }
        Ok(if !read_any {
            Fill::Eof
        } else if oversized {
            Fill::Oversized
        } else {
            Fill::Line
        })
    }
}

/// The writers' side of the cap: a row the reader would skip is refused
/// instead of written.
pub fn check_row_len(line_with_newline: &str) -> anyhow::Result<()> {
    let len = line_with_newline.len().saturating_sub(1);
    if len > MAX_CHAIN_LINE_BYTES {
        anyhow::bail!(
            "chain row of {len} bytes is over the {MAX_CHAIN_LINE_BYTES}-byte line cap — not \
             written"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;

    fn collect(bytes: &[u8], max: usize) -> Vec<Option<String>> {
        let mut r = ChainLines::with_max(BufReader::with_capacity(16, bytes), max);
        let mut out = Vec::new();
        while let Some(l) = r.next_line().unwrap() {
            out.push(match l {
                ChainLine::Text(s) => Some(s.to_string()),
                ChainLine::Unreadable => None,
            });
        }
        out
    }

    #[test]
    fn lines_within_the_cap_come_back_and_blank_lines_are_skipped() {
        let got = collect(b"a\n\nbb\nccc", 8);
        assert_eq!(
            got,
            vec![Some("a".into()), Some("bb".into()), Some("ccc".into())]
        );
        assert!(collect(b"", 8).is_empty());
        assert!(collect(b"\n\n", 8).is_empty());
    }

    #[test]
    fn a_line_at_the_cap_is_kept_one_byte_more_is_unreadable() {
        let exact = format!("{}\n{}\nz\n", "x".repeat(8), "y".repeat(9));
        let got = collect(exact.as_bytes(), 8);
        assert_eq!(got, vec![Some("x".repeat(8)), None, Some("z".into())]);
    }

    /// The over-cap line is consumed, never stored: the buffer stays
    /// within the cap however long the line is.
    #[test]
    fn an_oversized_line_is_consumed_without_being_stored() {
        let mut body = b"first\n".to_vec();
        body.extend_from_slice(&vec![b'q'; 4 * 1024 * 1024]);
        body.extend_from_slice(b"\nlast\n");
        let mut r = ChainLines::with_max(BufReader::new(&body[..]), 1024);
        assert_eq!(r.next_line().unwrap(), Some(ChainLine::Text("first")));
        assert_eq!(r.next_line().unwrap(), Some(ChainLine::Unreadable));
        assert!(r.buf.capacity() <= 2 * 1024, "{}", r.buf.capacity());
        assert_eq!(r.next_line().unwrap(), Some(ChainLine::Text("last")));
        assert_eq!(r.next_line().unwrap(), None);
    }

    #[test]
    fn a_line_that_is_not_utf8_is_unreadable_not_an_error() {
        let got = collect(b"ok\n\xff\xfe{\"x\":1}\nok2\n", 64);
        assert_eq!(got, vec![Some("ok".into()), None, Some("ok2".into())]);
    }

    #[test]
    fn the_writers_refuse_a_row_over_the_cap() {
        let mut row = "r".repeat(MAX_CHAIN_LINE_BYTES);
        row.push('\n');
        assert!(check_row_len(&row).is_ok());
        row.insert(0, 'r');
        assert!(check_row_len(&row).is_err());
    }
}
