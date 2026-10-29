//! The one reader of a `mountinfo` table (`proc(5)`): the start's mount
//! check (`boot::continuity`) and the self-integrity watcher read the same
//! parse (lab PR 265, the independent review of #468: R1, R3).
//!
//! The kernel writes each line as fields separated by one ASCII space, and
//! escapes only four bytes in a path — space `\040`, tab `\011`, newline
//! `\012`, backslash `\134` (`mangle()`, fs/proc_namespace.c); every other
//! byte of a path comes out as it is, valid UTF-8 or not. So the table is
//! read as bytes, split on `b'\n'` and `b' '` only (never on the other
//! Unicode spaces — a U+00A0 in a directory's name shifted every field
//! after it when `str::split_whitespace` did the split, and a bind over the
//! agent's directory went unseen), each `\ooo` turned back into its byte,
//! and the paths kept as `OsString`s: no byte is lost, and no byte that is
//! not UTF-8 makes the table unreadable (it did with `read_to_string`, and
//! an unprivileged FUSE mount on such a name could keep the agent from
//! starting).
//!
//! A line whose shape is not the kernel's (an id that is not a number, a
//! device that is not `major:minor`, a path that is not absolute, no single
//! `-` separator followed by the filesystem type, the source and the super
//! options) is kept apart ([`Malformed`]), with its mount point when that
//! field can still be read: the caller decides whether it concerns what it
//! checks.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

/// One mount of the table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry {
    pub id: u64,
    pub parent: u64,
    /// The filesystem's device, `major:minor`.
    pub major: u32,
    pub minor: u32,
    /// The directory of that filesystem mounted here (`/` for its root).
    pub root: PathBuf,
    pub mount_point: PathBuf,
    pub fstype: OsString,
    pub source: OsString,
}

impl MountEntry {
    /// `major:minor`, as the table spells it.
    pub fn dev(&self) -> String {
        format!("{}:{}", self.major, self.minor)
    }

    /// The same filesystem (superblock) as `other`.
    pub fn same_dev(&self, other: &MountEntry) -> bool {
        self.major == other.major && self.minor == other.minor
    }
}

/// A line that is not in the kernel's shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Malformed {
    /// Its number, from 1.
    pub line: usize,
    /// Its fifth field as a mount point, when that field is there and is an
    /// absolute path.
    pub mount_point: Option<PathBuf>,
    pub why: &'static str,
}

/// A parsed `mountinfo` table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MountTable {
    /// The well-formed lines, in order.
    pub entries: Vec<MountEntry>,
    /// The others.
    pub malformed: Vec<Malformed>,
}

impl MountTable {
    /// The mount `m` sits on (its parent, by id), when the table has it.
    pub fn parent_of(&self, m: &MountEntry) -> Option<&MountEntry> {
        self.entries
            .iter()
            .find(|p| p.id == m.parent && p.id != m.id)
    }
}

/// The table at `path`, read as bytes (`std::fs::read`).
pub fn read(path: &Path) -> std::io::Result<MountTable> {
    std::fs::read(path).map(|b| parse(&b))
}

/// Every line of `text` ([`MountTable`]); a last line without its newline
/// is read as well, an empty one is not a line.
pub fn parse(text: &[u8]) -> MountTable {
    let mut table = MountTable::default();
    for (i, line) in text.split(|b| *b == b'\n').enumerate() {
        if line.is_empty() {
            continue;
        }
        match parse_line(line) {
            Ok(m) => table.entries.push(m),
            Err(why) => table.malformed.push(Malformed {
                line: i + 1,
                mount_point: line
                    .split(|b| *b == b' ')
                    .nth(4)
                    .map(unescape)
                    .filter(|p| p.is_absolute()),
                why,
            }),
        }
    }
    table
}

fn parse_line(line: &[u8]) -> Result<MountEntry, &'static str> {
    // id parent major:minor root mount_point opts [optional…] - fstype source superopts
    let fields: Vec<&[u8]> = line.split(|b| *b == b' ').collect();
    if fields.iter().any(|f| f.is_empty()) {
        return Err("an empty field (two spaces in a row)");
    }
    let seps: Vec<usize> = fields
        .iter()
        .enumerate()
        .filter(|(i, f)| *i >= 6 && **f == b"-")
        .map(|(i, _)| i)
        .collect();
    let [sep] = seps[..] else {
        return Err("not exactly one `-` separator after the mount options");
    };
    if fields.len() != sep + 4 {
        return Err("not the filesystem type, the source and the super options after `-`");
    }
    let id = number(fields[0]).ok_or("the mount id is not a number")?;
    let parent = number(fields[1]).ok_or("the parent id is not a number")?;
    let (major, minor) = device(fields[2]).ok_or("the device is not major:minor")?;
    let root = unescape(fields[3]);
    let mount_point = unescape(fields[4]);
    if !root.is_absolute() || !mount_point.is_absolute() {
        return Err("a path that is not absolute");
    }
    Ok(MountEntry {
        id,
        parent,
        major,
        minor,
        root,
        mount_point,
        fstype: OsString::from_vec(unescape_bytes(fields[sep + 1])),
        source: OsString::from_vec(unescape_bytes(fields[sep + 2])),
    })
}

fn number<T: std::str::FromStr>(b: &[u8]) -> Option<T> {
    if b.is_empty() || !b.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(b).ok()?.parse().ok()
}

fn device(b: &[u8]) -> Option<(u32, u32)> {
    let colon = b.iter().position(|c| *c == b':')?;
    Some((number(&b[..colon])?, number(&b[colon + 1..])?))
}

/// `field` with every `\ooo` (three octal digits, a byte) turned back into
/// its byte; a backslash not followed by three octal digits is kept.
fn unescape_bytes(field: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(field.len());
    let mut i = 0;
    while i < field.len() {
        if field[i] == b'\\' && i + 4 <= field.len() {
            let oct = &field[i + 1..i + 4];
            if oct.iter().all(|d| (b'0'..=b'7').contains(d)) {
                let v = oct.iter().fold(0u32, |a, d| a * 8 + u32::from(d - b'0'));
                if let Ok(byte) = u8::try_from(v) {
                    out.push(byte);
                    i += 4;
                    continue;
                }
            }
        }
        out.push(field[i]);
        i += 1;
    }
    out
}

fn unescape(field: &[u8]) -> PathBuf {
    PathBuf::from(OsStr::from_bytes(&unescape_bytes(field)))
}

/// Whether `m` is a bind of a directory onto itself (lab PR 265): the mount
/// it sits on (`parent`) is of the same filesystem and shows, at `m`'s
/// mount point, the directory `m` mounts — `m`'s root is the parent's root
/// joined with the path from the parent's mount point to `m`'s, compared by
/// component. What the unit's `ReadWritePaths=` and `RuntimeDirectory=`
/// make in the agent's namespace, on any layout.
pub fn is_self_bind(m: &MountEntry, parent: &MountEntry) -> bool {
    let Ok(rel) = m.mount_point.strip_prefix(&parent.mount_point) else {
        return false;
    };
    m.same_dev(parent) && m.root == parent.root.join(rel)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(s: &str) -> MountTable {
        parse(s.as_bytes())
    }

    #[test]
    fn a_kernel_line_is_read_field_by_field() {
        let t = line("566 539 252:1 /etc/northnarrow /etc/northnarrow rw,nosuid,relatime shared:276 master:1 - ext4 /dev/vda1 rw,discard\n");
        assert!(t.malformed.is_empty(), "{:?}", t.malformed);
        let m = &t.entries[0];
        assert_eq!((m.id, m.parent, m.major, m.minor), (566, 539, 252, 1));
        assert_eq!(m.root, Path::new("/etc/northnarrow"));
        assert_eq!(m.mount_point, Path::new("/etc/northnarrow"));
        assert_eq!(
            (m.fstype.as_os_str(), m.source.as_os_str()),
            (OsStr::new("ext4"), OsStr::new("/dev/vda1"))
        );
        assert_eq!(m.dev(), "252:1");
        // no optional field, no final newline
        let t = line("29 1 252:1 / / rw - ext4 /dev/vda1 rw");
        assert_eq!(t.entries.len(), 1);
    }

    /// Review of #468 R1: the kernel escapes only space, tab, newline and
    /// backslash; every other byte — U+00A0, U+2028, a byte that is not
    /// UTF-8 — is a byte of the path, never a field separator, and nothing
    /// is lost.
    #[test]
    fn only_the_ascii_space_separates_and_every_byte_is_kept() {
        let mut text = Vec::new();
        text.extend_from_slice(
            b"413 235 8:48 /tmp/fake\xc2\xa0/x /tmp/state rw - ext4 /dev/sdd rw\n",
        );
        text.extend_from_slice(
            b"414 235 8:48 /a\xe2\x80\xa8b /c\\011d\\012e\\134f\\040g rw - ext4 /dev/sdd rw\n",
        );
        text.extend_from_slice(b"415 235 0:90 / /tmp/other\xff rw - tmpfs t\xff rw\n");
        let t = parse(&text);
        assert!(t.malformed.is_empty(), "{:?}", t.malformed);
        assert_eq!(
            t.entries[0].root.as_os_str().as_bytes(),
            b"/tmp/fake\xc2\xa0/x"
        );
        assert_eq!(t.entries[0].mount_point, Path::new("/tmp/state"));
        assert_eq!(t.entries[1].root.as_os_str().as_bytes(), b"/a\xe2\x80\xa8b");
        assert_eq!(
            t.entries[1].mount_point.as_os_str().as_bytes(),
            b"/c\td\ne\\f g"
        );
        assert_eq!(
            t.entries[2].mount_point.as_os_str().as_bytes(),
            b"/tmp/other\xff"
        );
        assert_eq!(t.entries[2].source.as_bytes(), b"t\xff");
    }

    /// A line not in the kernel's shape is kept apart, with its mount point
    /// when that field reads as an absolute path.
    #[test]
    fn a_line_not_in_the_kernels_shape_is_kept_apart() {
        for (text, mp) in [
            ("x 1 252:1 / /etc/northnarrow rw - ext4 /dev/vda1 rw", true),
            ("29 1 2521 / /etc/northnarrow rw - ext4 /dev/vda1 rw", true),
            ("29 1 252:1 / /etc/northnarrow rw ext4 /dev/vda1 rw", true),
            (
                "29 1 252:1 / /etc/northnarrow rw - - ext4 /dev/vda1 rw",
                true,
            ),
            ("29 1 252:1 / /etc/northnarrow rw - ext4 /dev/vda1", true),
            (
                "29 1 252:1 /  /etc/northnarrow rw - ext4 /dev/vda1 rw",
                false,
            ),
            (
                "29 1 252:1 relative /etc/northnarrow rw - ext4 /dev/vda1 rw",
                true,
            ),
            ("29 1", false),
        ] {
            let t = line(text);
            assert!(t.entries.is_empty(), "{text}");
            assert_eq!(t.malformed.len(), 1, "{text}");
            assert_eq!(
                t.malformed[0].mount_point.as_deref() == Some(Path::new("/etc/northnarrow")),
                mp,
                "{text}: {:?}",
                t.malformed[0]
            );
        }
    }

    #[test]
    fn octal_escapes_are_bytes_and_a_lone_backslash_stays() {
        assert_eq!(unescape_bytes(b"\\040\\011\\012\\134\\377"), b" \t\n\\\xff");
        assert_eq!(unescape_bytes(b"a\\b\\08\\"), b"a\\b\\08\\");
    }

    #[test]
    fn a_self_bind_is_the_same_directory_of_the_same_filesystem() {
        let t = line(
            "29 1 252:1 / / rw - ext4 /dev/vda1 rw
701 29 252:1 /etc/northnarrow /etc/northnarrow rw - ext4 /dev/vda1 rw
702 29 252:1 /srv/copy/northnarrow /etc/northnarrow rw - ext4 /dev/vda1 rw
703 29 7:0 /etc/northnarrow /etc/northnarrow rw - ext4 /dev/loop0 rw
",
        );
        let root = &t.entries[0];
        assert!(is_self_bind(&t.entries[1], root));
        assert!(
            !is_self_bind(&t.entries[2], root),
            "the same basename, another directory"
        );
        assert!(
            !is_self_bind(&t.entries[3], root),
            "the same path, another filesystem"
        );
        assert_eq!(t.parent_of(&t.entries[1]), Some(root));
    }
}
