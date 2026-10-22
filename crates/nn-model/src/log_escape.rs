//! Journal-safe log lines (external audit, Wave 3: journal line injection,
//! NN-AUD-413, lab PR 167).
//!
//! The agent and the watchdog log through `tracing-subscriber`'s fmt layer
//! to stdout, and journald makes one journal entry of every line it reads
//! there (it also breaks at a NUL byte and at `LineMax`, 48 KiB by
//! default). tracing-subscriber 0.3 escapes ANSI and C1 controls in the
//! message only, and neither `\n` nor `\r` anywhere: a value logged with
//! `%` (Display) as it came — a file name, a `comm`, a DNS name — could hold
//! `\n` followed by a whole line of the attacker's choosing, and the journal
//! showed a forged `ANTI-TAMPER DENIAL` or `VERDICT` entry that the agent
//! never wrote. Any local user can name a file in `/tmp` that way and run it.
//!
//! Two layers, both here so the agent and the watchdog share them:
//!
//! - [`Escaped`] renders one value another user can name (file names and
//!   paths of the files they touch, `comm`, argv, DNS names, canary names,
//!   the rule text that quotes them). A plain value prints as it is
//!   (`comm=bash`, `path=/etc/passwd`, what the lab checks grep for); one
//!   with a space, `"`, `=`, `\`, a control or a line/bidi separator is
//!   quoted, logfmt style, with those characters escaped
//!   (`target_filename="/tmp/x\nANTI-TAMPER DENIAL op=signal"`), so a value
//!   can neither end the line nor pass for another field. Every such field
//!   goes through it (`comm = %Escaped(&comm)`); the agent's test
//!   `journal_fields` refuses a `%` on those field names without it.
//! - [`OneLine`] is the writer the fmt layer writes through: whatever an
//!   event holds (an error that quotes a path, a message built with
//!   `format!`), it reaches journald as one line. Every control byte but the
//!   event's final newline is written escaped (`\n`, `\r`, `\t`, `\xNN`),
//!   ESC included unless the log goes to a terminal with colours, and a
//!   line longer than [`MAX_LINE_BYTES`] is cut there, under journald's
//!   `LineMax`, so its tail cannot become an entry of its own.

use core::fmt;
use std::io::{self, IsTerminal as _, Write};
use std::sync::OnceLock;

/// A log field value another user can name, rendered so it stays inside its
/// field and its line (module docs). `T` is anything with `Display`: a
/// `&str`, a `String`, `path.display()`.
#[derive(Clone, Copy)]
pub struct Escaped<T>(pub T);

/// A character written as an escape inside a quoted value: the controls
/// (C0, DEL, C1) and the Unicode line and bidi separators that can make a
/// terminal show text in another place or order than it was written.
fn is_special(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{2028}' | '\u{2029}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

/// A value that needs quotes: empty, or holding a space, `"`, `=`, `\` or a
/// special character.
fn needs_quotes(s: &str) -> bool {
    s.is_empty()
        || s.chars()
            .any(|c| c.is_whitespace() || c == '"' || c == '=' || c == '\\' || is_special(c))
}

/// Write `s` as one field value: as it is, or quoted and escaped.
pub fn write_escaped(f: &mut dyn fmt::Write, s: &str) -> fmt::Result {
    if !needs_quotes(s) {
        return f.write_str(s);
    }
    f.write_char('"')?;
    for c in s.chars() {
        match c {
            '"' => f.write_str("\\\"")?,
            '\\' => f.write_str("\\\\")?,
            '\n' => f.write_str("\\n")?,
            '\r' => f.write_str("\\r")?,
            '\t' => f.write_str("\\t")?,
            c if is_special(c) => write!(f, "\\u{{{:x}}}", c as u32)?,
            c => f.write_char(c)?,
        }
    }
    f.write_char('"')
}

impl<T: fmt::Display> fmt::Display for Escaped<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.0.to_string();
        write_escaped(f, &s)
    }
}

/// The same rendering under `?`, so `?Escaped(..)` is safe as well.
impl<T: fmt::Display> fmt::Debug for Escaped<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// The longest line [`OneLine`] writes, its newline included. Under
/// journald's default `LineMax` (48 KiB), which splits a longer line into
/// entries of which the next begins with whatever the cut fell on.
pub const MAX_LINE_BYTES: usize = 16 * 1024;

/// One formatted event as one line: `buf` with every control byte escaped
/// but a final `\n` (added when missing), ESC kept only when `keep_esc`
/// (the fmt layer's own colours on a terminal), and cut to
/// [`MAX_LINE_BYTES`]. Bytes ≥ 0x80 are kept: they never encode a control
/// below 0x80 in UTF-8, and tracing-subscriber writes UTF-8.
pub fn one_line(buf: &[u8], keep_esc: bool) -> Vec<u8> {
    let body = buf.strip_suffix(b"\n").unwrap_or(buf);
    let mut out = Vec::with_capacity(body.len().min(MAX_LINE_BYTES) + 1);
    let limit = MAX_LINE_BYTES - 1;
    let mut cut_at = None;
    for (i, &b) in body.iter().enumerate() {
        let before = out.len();
        match b {
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x1b if keep_esc => out.push(b),
            0x00..=0x1f | 0x7f => {
                let _ = write!(out, "\\x{b:02x}");
            }
            _ => out.push(b),
        }
        if out.len() > limit {
            out.truncate(before);
            cut_at = Some(i);
            break;
        }
    }
    if let Some(i) = cut_at {
        // Back to a character boundary: never half a UTF-8 sequence.
        while out.last().is_some_and(|&b| (0x80..0xc0).contains(&b)) {
            out.pop();
        }
        if out.last().is_some_and(|&b| b >= 0xc0) {
            out.pop();
        }
        let marker = format!(" [cut: {} more bytes]", body.len() - i);
        let room = limit.saturating_sub(marker.len());
        if out.len() > room {
            out.truncate(room);
            while out.last().is_some_and(|&b| (0x80..0xc0).contains(&b)) {
                out.pop();
            }
            if out.last().is_some_and(|&b| b >= 0xc0) {
                out.pop();
            }
        }
        out.extend_from_slice(marker.as_bytes());
    }
    out.push(b'\n');
    out
}

/// The writer of the fmt layer (`.with_writer(stdout_one_line)`): each
/// `write` is one formatted event (tracing-subscriber writes an event with
/// a single `write_all` on a fresh writer), written whole through
/// [`one_line`].
pub struct OneLine<W: Write> {
    inner: W,
    keep_esc: bool,
}

impl<W: Write> OneLine<W> {
    pub fn new(inner: W, keep_esc: bool) -> Self {
        Self { inner, keep_esc }
    }
}

impl<W: Write> Write for OneLine<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.inner.write_all(&one_line(buf, self.keep_esc))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Colours only on a terminal (a developer's run), never in the journal,
/// and never with `NO_COLOR` set: under journald the fmt layer writes no
/// ESC, and [`OneLine`] escapes every one a value brings.
pub fn stdout_ansi() -> bool {
    static ANSI: OnceLock<bool> = OnceLock::new();
    *ANSI.get_or_init(|| {
        io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty())
    })
}

/// The fmt layer's writer for the agent and the watchdog: stdout through
/// [`OneLine`].
pub fn stdout_one_line() -> OneLine<io::Stdout> {
    OneLine::new(io::stdout(), stdout_ansi())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn esc(s: &str) -> String {
        Escaped(s).to_string()
    }

    #[test]
    fn a_plain_value_prints_as_it_is() {
        for s in [
            "bash",
            "/etc/passwd",
            "/home/u/.aws/credentials",
            "NN-L-AT-001_AntiTamperDenial",
            "café",
        ] {
            assert_eq!(esc(s), s);
        }
    }

    #[test]
    fn a_newline_never_leaves_the_value() {
        let name = "/tmp/x\nANTI-TAMPER DENIAL pid=1 uid=0 comm=bash op=signal";
        let out = esc(name);
        assert!(!out.contains('\n') && !out.contains('\r'), "{out}");
        assert_eq!(
            out,
            "\"/tmp/x\\nANTI-TAMPER DENIAL pid=1 uid=0 comm=bash op=signal\""
        );
    }

    #[test]
    fn quotes_spaces_equals_and_escapes() {
        assert_eq!(esc(""), "\"\"");
        assert_eq!(esc("x op=signal"), "\"x op=signal\"");
        assert_eq!(esc("a\"b"), "\"a\\\"b\"");
        assert_eq!(esc("a\\nb"), "\"a\\\\nb\"");
        assert_eq!(esc("a\tb\rc"), "\"a\\tb\\rc\"");
        assert_eq!(esc("a\u{1b}[2Kb"), "\"a\\u{1b}[2Kb\"");
        assert_eq!(esc("a\u{85}b"), "\"a\\u{85}b\"");
        assert_eq!(esc("a\u{2028}b"), "\"a\\u{2028}b\"");
        assert_eq!(esc("a\u{202e}b"), "\"a\\u{202e}b\"");
        assert_eq!(esc("a\0b"), "\"a\\u{0}b\"");
        // Debug renders the same
        assert_eq!(format!("{:?}", Escaped("x\ny")), "\"x\\ny\"");
        // anything Display
        assert_eq!(
            Escaped(std::path::Path::new("/tmp/a b").display()).to_string(),
            "\"/tmp/a b\""
        );
    }

    #[test]
    fn one_line_keeps_one_line() {
        let ev = b"2026-10-16T00:00:00Z  WARN VERDICT (rule) target_filename=/tmp/x\nANTI-TAMPER DENIAL op=signal\r\n";
        let out = one_line(ev, false);
        assert_eq!(out.iter().filter(|&&b| b == b'\n').count(), 1);
        assert_eq!(out.last(), Some(&b'\n'));
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "2026-10-16T00:00:00Z  WARN VERDICT (rule) target_filename=/tmp/x\\nANTI-TAMPER DENIAL op=signal\\r\n"
        );
        // a missing final newline is added; NUL, ESC and DEL are escaped
        assert_eq!(one_line(b"a\0b\x1bc\x7f", false), b"a\\x00b\\x1bc\\x7f\n");
        // on a terminal with colours, ESC stays
        assert_eq!(
            one_line(b"\x1b[33mWARN\x1b[0m\n", true),
            b"\x1b[33mWARN\x1b[0m\n"
        );
        // UTF-8 untouched
        assert_eq!(one_line("é ✓\n".as_bytes(), false), "é ✓\n".as_bytes());
    }

    #[test]
    fn a_long_line_is_cut_under_line_max() {
        let mut ev = "é".repeat(MAX_LINE_BYTES).into_bytes();
        ev.extend_from_slice(b"\nANTI-TAMPER DENIAL op=signal\n");
        let out = one_line(&ev, false);
        assert!(out.len() <= MAX_LINE_BYTES);
        assert_eq!(out.iter().filter(|&&b| b == b'\n').count(), 1);
        let s = String::from_utf8(out).expect("cut on a character boundary");
        assert!(s.ends_with(" more bytes]\n"), "{}", &s[s.len() - 40..]);
        assert!(!s.contains("ANTI-TAMPER"));
    }

    #[test]
    fn the_writer_writes_each_event_whole() {
        let mut sink = Vec::new();
        {
            let mut w = OneLine::new(&mut sink, false);
            let ev = b"x\ny\n";
            assert_eq!(w.write(ev).unwrap(), ev.len());
            w.write_all(b"z\n").unwrap();
        }
        assert_eq!(sink, b"x\\ny\nz\n");
    }
}
