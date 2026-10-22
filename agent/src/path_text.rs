//! The text of the paths the open sensor renders, shared by the sensor that
//! writes them and the posture code that reads them (external audit
//! SNS-005/SNS-006, lab PR 175): the marks of a cut or unread component, the
//! test of an exact host path, the device of an unplaced path, and the
//! octal escapes of `/proc/<pid>/mountinfo`.
//!
//! Wave 4 restructure, R04b (lab PR 241): from `crate::sensors::open_sensor`
//! (plan R04b: "gli helper di testo dei path vanno fuori da sensors"),
//! unchanged; `open_sensor` re-exports them. Text only: no I/O, no kernel
//! record.

/// The octal escapes of `/proc/<pid>/mountinfo` (`\040` for a space)
/// undone; anything else kept.
pub fn unescape_octal(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 4 <= b.len()
            && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c))
        {
            let v = u32::from(b[i + 1] - b'0') * 64
                + u32::from(b[i + 2] - b'0') * 8
                + u32::from(b[i + 3] - b'0');
            if let Ok(byte) = u8::try_from(v) {
                out.push(byte);
                i += 4;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Marks a component the kernel may have cut (a slot holds at most
/// `OPEN_PATH_SLOT_LEN - 1` bytes), and a path that is not placed on a
/// mount point.
pub const CUT_MARK: char = '…';
/// A component the kernel could not read (an empty slot).
pub const UNREAD_COMPONENT: &str = "?";

/// External audit SNS-005/SNS-006: whether `path`, as the open sensor renders
/// it, names one host file exactly: absolute (placed on a mount point),
/// with no cut and no unread component. Anything else is not comparable
/// for equality with a host path, and the consumers fall back on the
/// kernel's class (`Event::FileOpen::kernel_class`). A file whose own name
/// holds the marks only turns that fallback on.
pub fn path_is_exact(path: &str) -> bool {
    path.starts_with('/')
        && !path.contains(CUT_MARK)
        && !path.split('/').any(|c| c == UNREAD_COMPONENT)
}

/// Lab PR 175: the `(major, minor)` of the filesystem an unplaced path
/// (`mnt[<major>:<minor>:<ino>]<rel>`, the open sensor's) names, as field 3 of `/proc/<pid>/mountinfo` shows it; `None` for any
/// other path.
pub fn unplaced_root_dev(path: &str) -> Option<(u32, u32)> {
    let inner = path.strip_prefix("mnt[")?.split_once(']')?.0;
    let mut it = inner.splitn(3, ':');
    let major = it.next()?.parse().ok()?;
    let minor = it.next()?.parse().ok()?;
    it.next()?.parse::<u64>().ok()?;
    Some((major, minor))
}
