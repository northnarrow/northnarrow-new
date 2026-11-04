//! The signed chains as the export's write-ahead log (lot 276): what the
//! core runs (as root, on its `nn-export` thread — never the decision
//! thread). It reads a chain's rows after a cursor, verbatim, with their
//! place: the file (a rotating chain's archive number, the active file's
//! being the number it will take; 0 for the flat canary chain), the line,
//! the byte offset the line ends at. It parses nothing of a row but its
//! seal's hashes (`row_verify::links`): the mapping is the worker's.
//!
//! A cursor is the last row a sink has: `(file, line, end, entry_hash)`.
//! Read again at a start, it is checked against the chain (the line ending
//! at `end` still has that hash: `holds_line_ending_at`); a chain cut or
//! rewritten under it (a torn tail repaired at the agent's start) sends
//! the sink back to the start of that file — rows given twice, never
//! skipped. A file evicted before the sink read it is lost to the export:
//! its rows (the manifest's count) go to stage 8.
//!
//! Cursors live in `/var/lib/northnarrow/detections/export-cursors.json`,
//! written atomically by the core, never by the worker.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use ed25519_dalek::VerifyingKey;
use nn_evidence::chain_host::ChainHost;
use nn_evidence::chainlog::{self, ManifestEvent};
use nn_proto::ipc::{ExportChain, ExportRow, ExportSink, RowPos, MAX_EXPORT_ROW};
use serde::{Deserialize, Serialize};

/// The core's cursors' file's name, beside the detection log (the state
/// directory's `detections/`: root's, 0700, the agent's to write).
pub const CURSORS_FILE: &str = "export-cursors.json";

/// Its default path.
pub const CURSORS: &str = "/var/lib/northnarrow/detections/export-cursors.json";

/// A chain to read.
#[derive(Debug, Clone)]
pub struct Source {
    pub chain: ExportChain,
    /// Its active file.
    pub active: PathBuf,
}

/// A sink's place in a chain: the last row it has.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor {
    pub file: u64,
    pub line: u64,
    pub end: u64,
    /// The row's `entry_hash`; empty at the start of a file.
    pub hash: String,
}

impl Cursor {
    pub fn start_of(file: u64) -> Self {
        Self {
            file,
            line: 0,
            end: 0,
            hash: String::new(),
        }
    }

    pub fn pos(&self) -> RowPos {
        RowPos {
            file: self.file,
            line: self.line,
        }
    }
}

/// What a read found besides rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Note {
    /// Files evicted before the sink read them: `rows` lost to the export
    /// (`None`: their count is not in the manifest's tail). A lower bound:
    /// the manifest counts a file's rows of the log's last run (its open
    /// does not recount the file), so a file that spans a restart says
    /// fewer.
    Evicted { files: u64, rows: Option<u64> },
    /// The cursor's row is not in the chain any more (cut or rewritten):
    /// the file is read again from its start.
    CursorGone { file: u64, line: u64 },
    /// The cursor names a file past the chain's (another installation's
    /// cursor): read from the chain's oldest file.
    CursorAhead { file: u64 },
    /// A row longer than a request carries: lost to the export.
    Oversize { file: u64, line: u64, bytes: usize },
    /// A line no request can carry (empty: no row of a chain is): lost
    /// to the export, never asked of the worker (the review of #499, D3).
    Blank { file: u64, line: u64 },
}

/// One read's result.
#[derive(Debug, Clone, Default)]
pub struct Batch {
    pub rows: Vec<ExportRow>,
    /// Each row's `entry_hash` (the cursor's, once the row is acked).
    pub hashes: Vec<String>,
    /// Where the next read starts (past the last row read, or skipped).
    pub next: Option<Cursor>,
    /// Rows lost to the export by this read (stage 8).
    pub lost: u64,
    pub notes: Vec<Note>,
}

/// Why a chain could not be read now (retried at the next round).
#[derive(Debug)]
pub struct WalError(pub String);

impl std::fmt::Display for WalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn io(what: &Path) -> impl Fn(std::io::Error) -> WalError + '_ {
    move |e| WalError(format!("{}: {e}", what.display()))
}

enum Located {
    File(File),
    /// Evicted, or never there.
    Gone,
    /// After the chain's current file.
    Ahead,
}

/// The current generation of a chain: the active file's number (0 for a
/// flat chain).
pub fn current_file(src: &Source) -> u64 {
    if src.chain.rotates() {
        chainlog::current_generation(&src.active)
    } else {
        0
    }
}

fn locate<H: ChainHost>(src: &Source, file: u64) -> Result<Located, WalError> {
    if !src.chain.rotates() {
        return match H::open_read_nofollow(&src.active) {
            Ok(f) => Ok(Located::File(f)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Located::Gone),
            Err(e) => Err(io(&src.active)(e)),
        };
    }
    let archive = chainlog::archive_path_for(&src.active, file);
    if let Ok(f) = H::open_read_nofollow(&archive) {
        return Ok(Located::File(f));
    }
    let current = chainlog::current_generation(&src.active);
    if file > current {
        return Ok(Located::Ahead);
    }
    if file < current {
        return Ok(Located::Gone);
    }
    let f = match H::open_read_nofollow(&src.active) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Located::Gone),
        Err(e) => return Err(io(&src.active)(e)),
    };
    // a rotation between the generation's read and the open: the file
    // opened may be the next one — the archive's name says
    if let Ok(f) = H::open_read_nofollow(&archive) {
        return Ok(Located::File(f));
    }
    Ok(Located::File(f))
}

/// The rows the manifest says archive `file` held.
fn archived_rows<H: ChainHost>(src: &Source, file: u64, pk: &VerifyingKey) -> Option<u64> {
    chainlog::manifest_tail_events::<H>(&src.active, src.chain.name(), pk)
        .into_iter()
        .find_map(|e| match e {
            ManifestEvent::Rotated { seq, records, .. } if seq == file => Some(records),
            _ => None,
        })
}

/// Whether archive `file` of a rotating chain is on disk.
fn archived<H: ChainHost>(src: &Source, file: u64) -> bool {
    H::open_read_nofollow(&chainlog::archive_path_for(&src.active, file)).is_ok()
}

/// Whether the byte before `end` in `path` ends a line.
fn ends_a_line(path: &Path, end: u64) -> bool {
    let Ok(mut f) = File::open(path) else {
        return false;
    };
    let mut b = [0u8; 1];
    end > 0
        && f.seek(SeekFrom::Start(end - 1)).is_ok()
        && f.read_exact(&mut b).is_ok()
        && b[0] == b'\n'
}

/// The terminator that sealed archive `file` (its last line), verbatim.
fn terminator_of<H: ChainHost>(src: &Source, file: u64) -> Option<Vec<u8>> {
    let mut f = H::open_read_nofollow(&chainlog::archive_path_for(&src.active, file)).ok()?;
    let len = f.metadata().ok()?.len();
    let from = len.saturating_sub(4096);
    f.seek(SeekFrom::Start(from)).ok()?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).ok()?;
    let body = buf.strip_suffix(b"\n")?;
    let line = match body.iter().rposition(|b| *b == b'\n') {
        Some(i) => &body[i + 1..],
        None if from == 0 => body,
        None => return None,
    };
    chainlog::is_terminator_line(std::str::from_utf8(line).ok()?).then(|| line.to_vec())
}

/// Where a sink starts in a chain it has no cursor for: the chain's end
/// (the rows written from now) or its oldest row.
pub fn initial<H: ChainHost>(src: &Source, oldest: bool) -> Result<Cursor, WalError> {
    let current = current_file(src);
    if oldest {
        let first = if src.chain.rotates() {
            chainlog::earliest_archive(&src.active).unwrap_or(current)
        } else {
            0
        };
        return Ok(Cursor::start_of(first));
    }
    let f = match H::open_read_nofollow(&src.active) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Cursor::start_of(current)),
        Err(e) => return Err(io(&src.active)(e)),
    };
    let mut r = BufReader::new(f);
    let mut cur = Cursor::start_of(current);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let n = r.read_until(b'\n', &mut buf).map_err(io(&src.active))?;
        if n == 0 || buf.last() != Some(&b'\n') {
            break;
        }
        let line = &buf[..buf.len() - 1];
        cur.line += 1;
        cur.end += n as u64;
        cur.hash = nn_evidence::row_verify::links(line)
            .map(|(_, h)| h)
            .unwrap_or_default();
    }
    Ok(cur)
}

/// The limits of one read.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub rows: usize,
    pub bytes: usize,
}

/// Read the rows of `src` after `from`. `check`: the cursor comes from
/// disk (a start) and is checked against the chain; a position this core
/// read itself in this run is not checked again (the chain's tail is cut
/// only at a start).
pub fn read_after<H: ChainHost>(
    src: &Source,
    from: &Cursor,
    check: bool,
    lim: Limits,
    pk: &VerifyingKey,
) -> Result<Batch, WalError> {
    let mut out = Batch::default();
    let mut cur = from.clone();
    let mut check = check && cur.end > 0;
    let mut bytes = 0usize;
    // the terminator this read saw sealing a file: (that file, its bytes)
    let mut carried: Option<(u64, Vec<u8>)> = None;
    // every file this read crosses, at most this many (an evicted run of
    // files counts as one step)
    for _ in 0..64 {
        let f = match locate::<H>(src, cur.file)? {
            Located::File(f) => f,
            Located::Gone => {
                if !src.chain.rotates() {
                    break; // the flat chain not created yet
                }
                // evicted: count the rows of every file before the oldest
                let resume = chainlog::earliest_archive(&src.active)
                    .unwrap_or_else(|| chainlog::current_generation(&src.active))
                    .max(cur.file + 1);
                let mut rows = Some(0u64);
                for g in cur.file..resume {
                    rows = match (rows, archived_rows::<H>(src, g, pk)) {
                        (Some(r), Some(n)) => {
                            Some(r + n.saturating_sub(if g == cur.file { cur.line } else { 0 }))
                        }
                        _ => None,
                    };
                }
                out.lost += rows.unwrap_or(0);
                out.notes.push(Note::Evicted {
                    files: resume - cur.file,
                    rows,
                });
                cur = Cursor::start_of(resume);
                check = false;
                continue;
            }
            Located::Ahead => {
                let first = chainlog::earliest_archive(&src.active)
                    .unwrap_or_else(|| chainlog::current_generation(&src.active));
                out.notes.push(Note::CursorAhead { file: cur.file });
                cur = Cursor::start_of(first);
                check = false;
                continue;
            }
        };
        if check {
            check = false;
            let path = if src.chain.rotates()
                && chainlog::archive_path_for(&src.active, cur.file).exists()
            {
                chainlog::archive_path_for(&src.active, cur.file)
            } else {
                src.active.clone()
            };
            let holds = if cur.hash.is_empty() {
                // a line skipped (blank, oversize): its end, a line's end
                ends_a_line(&path, cur.end)
            } else {
                chainlog::holds_line_ending_at(&path, cur.end, &cur.hash).unwrap_or(false)
            };
            if !holds {
                out.notes.push(Note::CursorGone {
                    file: cur.file,
                    line: cur.line,
                });
                cur = Cursor::start_of(cur.file);
                continue;
            }
        }
        let mut r = BufReader::new(f);
        r.seek(SeekFrom::Start(cur.end))
            .map_err(|e| WalError(format!("{}: seek: {e}", src.chain.name())))?;
        let mut buf = Vec::new();
        let mut sealed: Option<Vec<u8>> = None;
        loop {
            if out.rows.len() >= lim.rows || bytes >= lim.bytes {
                out.next = Some(cur);
                return Ok(out);
            }
            buf.clear();
            let n = (&mut r)
                .take(4 * MAX_EXPORT_ROW as u64)
                .read_until(b'\n', &mut buf)
                .map_err(|e| WalError(format!("{}: read: {e}", src.chain.name())))?;
            if n == 0 {
                break;
            }
            if buf.last() != Some(&b'\n') {
                if n as u64 >= 4 * MAX_EXPORT_ROW as u64 {
                    // a line past any row's size: skip to its end
                    let mut rest = Vec::new();
                    let m = r
                        .read_until(b'\n', &mut rest)
                        .map_err(|e| WalError(format!("{}: read: {e}", src.chain.name())))?;
                    if rest.last() != Some(&b'\n') {
                        break; // still being written
                    }
                    cur.line += 1;
                    cur.end += (n + m) as u64;
                    out.lost += 1;
                    out.notes.push(Note::Oversize {
                        file: cur.file,
                        line: cur.line,
                        bytes: n + m,
                    });
                    continue;
                }
                break; // a line still being written: the next round
            }
            let line = &buf[..buf.len() - 1];
            if src.chain.rotates() && line.starts_with(b"{\"rotate\":") {
                sealed = Some(line.to_vec());
                break;
            }
            if line.is_empty() {
                // no row of a chain is empty: no request carries one (the
                // core's check refuses it), so it is lost here, counted
                cur.line += 1;
                cur.end += n as u64;
                cur.hash = String::new();
                out.lost += 1;
                out.notes.push(Note::Blank {
                    file: cur.file,
                    line: cur.line,
                });
                continue;
            }
            // the first row of a file after a rotation carries the
            // terminator that sealed the one before
            let rotate = (src.chain.rotates()
                && cur.line == 0
                && cur.file > 1
                && line.len() <= MAX_EXPORT_ROW)
                .then(|| {
                    // the one this read saw sealing the file before, else
                    // the archive's (the review of #499, D2)
                    carried
                        .take()
                        .filter(|(f, _)| *f + 1 == cur.file)
                        .map(|(_, t)| t)
                        .or_else(|| terminator_of::<H>(src, cur.file - 1))
                })
                .flatten();
            let size = line.len() + rotate.as_ref().map_or(0, Vec::len);
            // a row that would take the request past its bytes waits for the
            // next one: the request's check refuses one over them (lot 276's
            // lab: such a request refused, the worker set up again and again)
            if line.len() <= MAX_EXPORT_ROW && !out.rows.is_empty() && bytes + size > lim.bytes {
                out.next = Some(cur);
                return Ok(out);
            }
            cur.line += 1;
            cur.end += n as u64;
            cur.hash = nn_evidence::row_verify::links(line)
                .map(|(_, h)| h)
                .unwrap_or_default();
            if line.len() > MAX_EXPORT_ROW {
                out.lost += 1;
                out.notes.push(Note::Oversize {
                    file: cur.file,
                    line: cur.line,
                    bytes: line.len(),
                });
                continue;
            }
            bytes += size;
            out.rows.push(ExportRow {
                file: cur.file,
                line: cur.line,
                end: cur.end,
                raw: line.to_vec(),
                rotate,
            });
            out.hashes.push(cur.hash.clone());
        }
        if let Some(t) = sealed {
            // the writer appends the terminator to the active file, then
            // renames it to its archive: read inside that window, the next
            // file is not there yet — stop at the last row, read on at the
            // next round (the review of #499, X1: the read went "ahead" of
            // the chain and back to its oldest file)
            if !archived::<H>(src, cur.file) {
                out.next = Some(cur);
                return Ok(out);
            }
            carried = Some((cur.file, t));
            cur = Cursor::start_of(cur.file + 1);
            continue;
        }
        break;
    }
    out.next = Some(cur);
    Ok(out)
}

/// The cursors of every sink and chain, as the core keeps them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursors {
    pub version: u32,
    /// `<sink>/<chain>` → its cursor.
    pub cursors: BTreeMap<String, Cursor>,
}

pub fn key(sink: ExportSink, chain: ExportChain) -> String {
    format!("{}/{}", sink.name(), chain.name())
}

impl Cursors {
    pub const VERSION: u32 = 1;

    /// The file's cursors; none (a first start, or a file that does not
    /// parse: the sinks start as configured) and why.
    pub fn load(path: &Path) -> (Self, Option<String>) {
        match std::fs::read(path) {
            Ok(b) => match serde_json::from_slice::<Cursors>(&b) {
                Ok(c) if c.version == Self::VERSION => (c, None),
                Ok(c) => (
                    Self::default(),
                    Some(format!("version {} (want {})", c.version, Self::VERSION)),
                ),
                Err(e) => (Self::default(), Some(e.to_string())),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (Self::default(), None),
            Err(e) => (Self::default(), Some(e.to_string())),
        }
    }

    /// Write them atomically (a temporary file in the same directory,
    /// synced, renamed over the file).
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        use std::io::Write;
        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        let tmp = dir.join(".cursors.json.tmp");
        let mut c = self.clone();
        c.version = Self::VERSION;
        let bytes = serde_json::to_vec_pretty(&c).map_err(std::io::Error::other)?;
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
