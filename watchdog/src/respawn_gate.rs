//! The review of #582 (F2 d): what the host would give the agent's
//! successor before its `main`, judged by the watchdog before each start of
//! the agent it makes — a respawn after a vacancy, a hold's retry.
//!
//! A change made while the role is vacated is seen by no live agent: a
//! drop-in that reaches our units and changes the code they run (their
//! environment, their commands, their memory's protection), systemd's copy
//! of the agent's unit (the re-check of #582, N3: a drop-in it loaded and
//! that was deleted since stays in force until the next reload), or
//! `/etc/ld.so.preload` and each library it names. The watchdog's reference
//! is what it read at its own start, while the agent ran, signed in its
//! witness chain's first row of the life ([`Baseline::describe`]). Before a
//! start it reads them again: what is as it was then is recorded (a
//! vendor's own `ld.so.preload`, a host's drop-in the agent signed), what is
//! new or changed since holds the start — recorded in the witness chain and
//! the agent's hold records, and the agent stays down until an operator
//! acts or the hold's retry finds the host as it was.
//!
//! The re-check of #582 (N2): inside a signed trusted-installer window
//! nothing is held — the operator's documented `systemctl edit` and restart
//! — and what the host is then becomes the reference, signed in a witness
//! row ([`adopt_now`]); never otherwise.
//!
//! Only names, paths, sizes and digests are recorded, never a file's
//! contents.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::Mutex;

use antitamper_bpf::host_dropins::{Harm, Kind};
use antitamper_bpf::unit_props::LoadedView;

/// The dynamic loader's preload list, read by every dynamically linked
/// start.
pub const PRELOAD_PATH: &str = "/etc/ld.so.preload";
/// The most of it read (far above any real list).
pub const PRELOAD_MAX: u64 = 64 << 10;

/// The drop-in directives that change the code a start of our units runs
/// or what protects it: its environment, its commands, its memory's
/// protection, its root. A harm of another directive (a limit below a
/// floor) is the agent's to sign and the floors' to restore: it never holds
/// a start. A drop-in the judge cannot read (no directive) is one.
pub const CODE_DIRECTIVES: &[&str] = &[
    "",
    "Environment",
    "EnvironmentFile",
    "UnsetEnvironment",
    "PassEnvironment",
    "ExecStart",
    "ExecStartPre",
    "ExecStartPost",
    "ExecCondition",
    "MemoryDenyWriteExecute",
    "RootDirectory",
    "RootImage",
    "MountImages",
    "ExtensionImages",
    "ExtensionDirectories",
    "BindPaths",
    "BindReadOnlyPaths",
    "TemporaryFileSystem",
];

/// What `/etc/ld.so.preload` holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Preload {
    /// No such file.
    Absent,
    /// Nothing but white space: nothing preloaded.
    Empty,
    /// Names to preload: the file's size and digest.
    Names { len: usize, sha256: String },
    /// Not a file the judge can read (a FIFO, a device, a read error).
    Unreadable(String),
}

impl Preload {
    /// One phrase for a record.
    pub fn describe(&self) -> String {
        match self {
            Preload::Absent => format!("no {PRELOAD_PATH}"),
            Preload::Empty => format!("{PRELOAD_PATH} empty"),
            Preload::Names { len, sha256 } => format!(
                "{PRELOAD_PATH} names libraries ({len} bytes, sha256 {})",
                sha256.get(..16).unwrap_or(sha256)
            ),
            Preload::Unreadable(why) => format!("{PRELOAD_PATH} not readable: {why}"),
        }
    }

    /// Something is preloaded, or may be.
    fn loads(&self) -> bool {
        matches!(self, Preload::Names { .. } | Preload::Unreadable(_))
    }
}

/// [`Preload`] of the bytes `read` gave.
pub fn preload_of(read: std::io::Result<Vec<u8>>) -> Preload {
    match read {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Preload::Absent,
        Err(e) => Preload::Unreadable(e.to_string()),
        Ok(b) if b.iter().all(u8::is_ascii_whitespace) => Preload::Empty,
        Ok(b) => Preload::Names {
            len: b.len(),
            sha256: nn_proto::witness::bytes_hash(&b),
        },
    }
}

/// The file at `path` as the loader reads it (symbolic links followed),
/// never blocking on a FIFO, a regular file only, at most [`PRELOAD_MAX`].
pub fn read_preload(path: &Path) -> Preload {
    read_preload_bytes(path).0
}

/// [`read_preload`], and the bytes read (`None` when none were).
pub fn read_preload_bytes(path: &Path) -> (Preload, Option<Vec<u8>>) {
    let read = || -> std::io::Result<Vec<u8>> {
        let f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOCTTY)
            .open(path)?;
        let t = f.metadata()?.file_type();
        if !t.is_file() {
            let what = if t.is_fifo() {
                "a FIFO"
            } else if t.is_socket() {
                "a socket"
            } else if t.is_char_device() || t.is_block_device() {
                "a device"
            } else {
                "not a regular file"
            };
            return Err(std::io::Error::other(what));
        }
        let mut b = Vec::new();
        f.take(PRELOAD_MAX + 1).read_to_end(&mut b)?;
        if b.len() as u64 > PRELOAD_MAX {
            return Err(std::io::Error::other(format!(
                "larger than {PRELOAD_MAX} bytes"
            )));
        }
        Ok(b)
    };
    match read() {
        Ok(b) => (preload_of(Ok(b.clone())), Some(b)),
        Err(e) => (preload_of(Err(e)), None),
    }
}

/// The re-check of #582 (N3): the names a preload list holds, as the
/// loader splits it (white space and `:`; `#` starts a comment to the end
/// of its line).
pub fn preload_names(text: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(text);
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("");
        for n in line.split(|c: char| c.is_ascii_whitespace() || c == ':') {
            if !n.is_empty() && !out.iter().any(|o| o == n) {
                out.push(n.to_string());
            }
        }
    }
    out
}

/// The directories the loader searches for a name without a `/` (the
/// default paths of the supported layouts: Debian's multiarch, Fedora's
/// `lib64`, merged `/usr` or not).
pub const SEARCH_DIRS: &[&str] = &[
    "/lib/x86_64-linux-gnu",
    "/usr/lib/x86_64-linux-gnu",
    "/lib64",
    "/usr/lib64",
    "/lib",
    "/usr/lib",
];

/// The re-check of #582 (N3): every path the loader may load for preload
/// entry `name` — the path itself, its `$LIB` and `$PLATFORM` expansions
/// (each a supported layout's), or `name` in each of [`SEARCH_DIRS`].
pub fn candidates(name: &str) -> Vec<String> {
    let mut out = vec![name.to_string()];
    for (token, values) in [
        ("$LIB", &["lib", "lib64", "lib/x86_64-linux-gnu", "usr/lib", "usr/lib64"][..]),
        ("${LIB}", &["lib", "lib64", "lib/x86_64-linux-gnu", "usr/lib", "usr/lib64"][..]),
        ("$PLATFORM", &["x86_64", "haswell", "xeon_phi"][..]),
        ("${PLATFORM}", &["x86_64", "haswell", "xeon_phi"][..]),
    ] {
        out = out
            .into_iter()
            .flat_map(|p| {
                if p.contains(token) {
                    values.iter().map(|v| p.replace(token, v)).collect()
                } else {
                    vec![p]
                }
            })
            .collect();
    }
    if !name.contains('/') {
        out = SEARCH_DIRS.iter().map(|d| format!("{d}/{name}")).collect();
    }
    out.dedup();
    out
}

/// The most of a named library read for its digest.
pub const ENTRY_MAX: u64 = 64 << 20;

/// The re-check of #582 (N3): what the loader would find at one candidate
/// path of a preload entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryId {
    /// Nothing there: nothing loads.
    Missing,
    /// A file: its identity (device, inode, size and digest).
    File {
        dev: u64,
        ino: u64,
        len: u64,
        sha256: String,
    },
    /// Something that cannot be judged (not a regular file, unreadable,
    /// too large).
    Unjudged(String),
}

/// [`EntryId`] of the file at `path` (symbolic links followed, as the
/// loader opens it), never blocking on a FIFO.
pub fn entry_id(path: &Path) -> EntryId {
    let f = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOCTTY)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return EntryId::Missing,
        Err(e) if e.raw_os_error() == Some(libc::ENOTDIR) => return EntryId::Missing,
        Err(e) => return EntryId::Unjudged(e.to_string()),
    };
    let m = match f.metadata() {
        Ok(m) => m,
        Err(e) => return EntryId::Unjudged(e.to_string()),
    };
    if !m.file_type().is_file() {
        return EntryId::Unjudged("not a regular file".into());
    }
    if m.len() > ENTRY_MAX {
        return EntryId::Unjudged(format!("larger than {ENTRY_MAX} bytes"));
    }
    let mut b = Vec::new();
    if let Err(e) = f.take(ENTRY_MAX + 1).read_to_end(&mut b) {
        return EntryId::Unjudged(e.to_string());
    }
    EntryId::File {
        dev: m.dev(),
        ino: m.ino(),
        len: b.len() as u64,
        sha256: nn_proto::witness::bytes_hash(&b),
    }
}

/// [`EntryId`] of every candidate path of every name the list `text` holds.
pub fn entries_of(text: Option<&[u8]>) -> BTreeMap<String, EntryId> {
    let mut out = BTreeMap::new();
    for name in text.map(preload_names).unwrap_or_default() {
        for c in candidates(&name) {
            let id = entry_id(Path::new(&c));
            out.insert(c, id);
        }
    }
    out
}

/// A harm's identity: where, which directive, what value.
pub fn harm_key(h: &Harm) -> String {
    format!("{}|{}|{}", h.path.display(), h.directive, h.value)
}

/// `h` changes the code a start of our units runs ([`CODE_DIRECTIVES`]).
pub fn reaches_code(h: &Harm) -> bool {
    h.kind == Kind::Harmful && CODE_DIRECTIVES.contains(&h.directive.as_str())
}

/// The host as one reading finds it: what a start of the agent would get.
#[derive(Debug, Clone)]
pub struct Host {
    pub preload: Preload,
    /// The re-check of #582 (N3): each library the list names, at each
    /// path the loader may load it from.
    pub entries: BTreeMap<String, EntryId>,
    pub harms: Vec<Harm>,
    /// The re-check of #582 (N3): systemd's copy of the agent's unit, or
    /// why it was not read.
    pub loaded: Result<LoadedView, String>,
}

impl Host {
    /// The host now. Blocking: call off the runtime.
    pub fn read() -> Host {
        let (preload, bytes) = read_preload_bytes(Path::new(PRELOAD_PATH));
        Host {
            entries: entries_of(bytes.as_deref()),
            preload,
            harms: antitamper_bpf::host_dropins::harmful_here(),
            loaded: loaded_now(),
        }
    }
}

/// systemd's copy of the agent's unit, through its private socket (5 s at
/// most each exchange); why not when it cannot be read.
fn loaded_now() -> Result<LoadedView, String> {
    let socket = Path::new(antitamper_bpf::systemd_bus::PRIVATE_SOCKET);
    if !socket.exists() {
        return Err("no systemd private socket".to_string());
    }
    antitamper_bpf::unit_props::loaded_view(
        socket,
        std::time::Duration::from_secs(5),
        antitamper_bpf::start_check::AGENT_UNIT,
    )
    .map_err(|e| e.to_string())
}

/// What the watchdog read at its start, or adopted since inside a signed
/// window: what a later reading is judged against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Baseline {
    pub preload: Preload,
    /// The re-check of #582 (N3): each library the list named then.
    pub entries: BTreeMap<String, EntryId>,
    /// [`harm_key`] of every drop-in harm that reaches code then.
    pub harms: BTreeSet<String>,
    /// The re-check of #582 (N3): systemd's copy of the agent's unit then
    /// (`None`: not read).
    pub loaded: Option<LoadedView>,
}

impl Baseline {
    pub fn of(preload: Preload, harms: &[Harm]) -> Baseline {
        Baseline {
            preload,
            entries: BTreeMap::new(),
            harms: harms
                .iter()
                .filter(|h| reaches_code(h))
                .map(harm_key)
                .collect(),
            loaded: None,
        }
    }

    /// The reference a reading of the host gives.
    pub fn of_host(h: &Host) -> Baseline {
        Baseline {
            entries: h.entries.clone(),
            loaded: h.loaded.as_ref().ok().cloned(),
            ..Baseline::of(h.preload.clone(), &h.harms)
        }
    }

    /// The host now.
    pub fn now() -> Baseline {
        Baseline::of_host(&Host::read())
    }

    /// One phrase for the witness chain's first row of the life.
    pub fn describe(&self) -> String {
        let loadable = self
            .entries
            .values()
            .filter(|e| !matches!(e, EntryId::Missing))
            .count();
        format!(
            "the host before any start it makes: {}{}; {} drop-in directive(s) that change our \
             units' code; {}",
            self.preload.describe(),
            if self.entries.is_empty() {
                String::new()
            } else {
                format!(" ({loadable} of {} named paths present)", self.entries.len())
            },
            self.harms.len(),
            match &self.loaded {
                Some(l) => format!(
                    "systemd's copy of the agent's unit: {} drop-in(s), MemoryDenyWriteExecute {}{}",
                    l.dropins.len(),
                    if l.mdwe { "on" } else { "OFF" },
                    if l.need_reload {
                        ", its files changed since it loaded them"
                    } else {
                        ""
                    }
                ),
                None => "systemd's copy of the agent's unit not read".to_string(),
            }
        )
    }
}

/// What a judgement before a start found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// Why the start is held; `None`: it goes on.
    pub hold: Option<String>,
    /// What was found, held or not (for the vacancy's or the successor's
    /// row): "the host before the start: …".
    pub detail: String,
    /// The same without its "before the start" (the re-check of #582, N3:
    /// a successor that started before the judgement is not given it as
    /// read before its start).
    pub found: String,
}

/// The re-check of #582 (N3): what systemd's copy `now` holds that the
/// reference `base` did not — `(held, seen)`.
fn judge_loaded(
    base: Option<&LoadedView>,
    now: &Result<LoadedView, String>,
    on_disk: impl Fn(&str) -> bool,
) -> (Vec<String>, Vec<String>) {
    let (mut held, mut seen) = (Vec::new(), Vec::new());
    let now = match now {
        Ok(n) => n,
        Err(why) => {
            seen.push(format!("systemd's copy of the agent's unit not read ({why})"));
            return (held, seen);
        }
    };
    for d in &now.dropins {
        if !on_disk(d) {
            held.push(format!(
                "a drop-in systemd loaded for the agent's unit is no longer on disk: {d} (its \
                 copy still applies it)"
            ));
        } else if base.is_some_and(|b| !b.dropins.contains(d)) {
            held.push(format!(
                "a drop-in systemd loaded for the agent's unit since the watchdog's start: {d}"
            ));
        }
    }
    let Some(base) = base else {
        seen.push("systemd's copy of the agent's unit not read at the watchdog's start".into());
        if !now.mdwe {
            held.push("MemoryDenyWriteExecute off in systemd's copy of the agent's unit".into());
        }
        return (held, seen);
    };
    if now.env != base.env {
        held.push(format!(
            "the environment systemd's copy gives the agent changed since the watchdog's start \
             (variables now: {})",
            now.env_names().join(",")
        ));
    }
    if now.unset != base.unset {
        held.push(
            "the variables systemd's copy unsets for the agent changed since the watchdog's start"
                .into(),
        );
    }
    if now.exec != base.exec {
        held.push(
            "the commands systemd's copy runs for the agent changed since the watchdog's start"
                .into(),
        );
    }
    if !now.mdwe {
        if base.mdwe {
            held.push(
                "MemoryDenyWriteExecute turned off in systemd's copy of the agent's unit since the \
                 watchdog's start"
                    .into(),
            );
        } else {
            seen.push(
                "MemoryDenyWriteExecute off in systemd's copy of the agent's unit, as at the \
                 watchdog's start (recorded, not held)"
                    .into(),
            );
        }
    }
    if now.need_reload {
        seen.push("systemd's copy of the agent's unit is not what is on disk (NeedDaemonReload)".into());
    }
    (held, seen)
}

/// The host now (`host`) against `base`: a preload, a library it names, a
/// code-reaching drop-in harm or systemd's copy of the agent's unit that is
/// new or changed since holds; one as it was is recorded only. The re-check
/// of #582 (N2): `in_window` (a signed trusted-installer window open)
/// holds nothing — the operator's change, recorded.
pub fn judge(base: &Baseline, host: &Host, in_window: bool) -> Verdict {
    judge_with(base, host, in_window, |p| Path::new(p).exists())
}

/// [`judge`], `on_disk` telling whether a drop-in path is there.
pub fn judge_with(
    base: &Baseline,
    host: &Host,
    in_window: bool,
    on_disk: impl Fn(&str) -> bool,
) -> Verdict {
    let preload = &host.preload;
    let mut held = Vec::new();
    let mut seen = Vec::new();
    if preload.loads() {
        if *preload == base.preload {
            // the re-check of #582 (N3): the same list — each library it
            // names judged; one that became loadable, or changed, holds
            let changed: Vec<&String> = host
                .entries
                .iter()
                .filter(|(_, id)| !matches!(id, EntryId::Missing))
                .filter(|(p, id)| base.entries.get(*p) != Some(*id))
                .map(|(p, _)| p)
                .collect();
            if changed.is_empty() {
                seen.push(format!(
                    "{}, as at the watchdog's start (recorded, not held)",
                    preload.describe()
                ));
            } else {
                held.push(format!(
                    "{}, as at the watchdog's start, but a library it names became loadable or \
                     changed since: {}",
                    preload.describe(),
                    changed
                        .iter()
                        .take(8)
                        .map(|p| p.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        } else {
            held.push(format!(
                "{}, written or changed since the watchdog's start ({})",
                preload.describe(),
                base.preload.describe()
            ));
        }
    }
    let mut old = 0usize;
    for h in host.harms.iter().filter(|h| reaches_code(h)) {
        if base.harms.contains(&harm_key(h)) {
            old += 1;
        } else {
            held.push(format!(
                "a drop-in new since the watchdog's start: {}",
                h.detail()
            ));
        }
    }
    if old > 0 {
        seen.push(format!(
            "{old} drop-in directive(s) that change our units' code, as at the watchdog's \
             start (recorded, not held)"
        ));
    }
    let (lh, ls) = judge_loaded(base.loaded.as_ref(), &host.loaded, on_disk);
    held.extend(lh);
    seen.extend(ls);
    let found = if held.is_empty() && seen.is_empty() {
        format!(
            "{}, no drop-in that changes our units' code, systemd's copy as at the watchdog's \
             start",
            preload.describe()
        )
    } else {
        held.iter()
            .chain(seen.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join("; ")
    };
    let (hold, found) = if in_window {
        (
            None,
            format!(
                "inside a signed trusted-installer window, nothing held (the operator's change): \
                 {found}"
            ),
        )
    } else {
        ((!held.is_empty()).then(|| held.join("; ")), found)
    };
    let found: String = found.chars().take(1150).collect();
    Verdict {
        hold,
        detail: format!("the host before the start: {found}"),
        found,
    }
}

static BASELINE: Mutex<Option<Baseline>> = Mutex::new(None);

/// The watchdog's start keeps its reference.
pub fn set_baseline(b: Baseline) {
    *BASELINE.lock().unwrap_or_else(|e| e.into_inner()) = Some(b);
}

/// The reference kept (an empty one when none was: then anything
/// preloaded, any code-reaching drop-in holds).
fn baseline() -> Baseline {
    BASELINE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .unwrap_or_else(|| Baseline::of(Preload::Absent, &[]))
}

/// The re-check of #582 (N2): the reference moved to `host` when it differs
/// — the caller does so only inside a signed trusted-installer window, and
/// signs the returned description in a witness row; `None` when nothing
/// changed.
pub fn adopt(host: &Host) -> Option<String> {
    let next = Baseline::of_host(host);
    let mut g = BASELINE.lock().unwrap_or_else(|e| e.into_inner());
    if g.as_ref() == Some(&next) {
        return None;
    }
    let what = next.describe().replacen(
        "the host before any start it makes",
        "the respawn gate's reference is now the host as a signed trusted-installer window left it",
        1,
    );
    *g = Some(next);
    Some(what)
}

/// [`adopt`] of the host read now. Blocking: call off the runtime.
pub fn adopt_now() -> Option<String> {
    adopt(&Host::read())
}

/// [`judge`] of the host now against the reference kept; inside a window
/// (`in_window`) the host is adopted too ([`adopt`]), its description the
/// second value. Blocking: call off the runtime.
pub fn judge_now(in_window: bool) -> (Verdict, Option<String>) {
    let host = Host::read();
    let v = judge(&baseline(), &host, in_window);
    let adopted = if in_window { adopt(&host) } else { None };
    (v, adopted)
}

/// [`judge`] of the host now against the reference kept, the reference
/// left as it is (a caller with no witness to sign a move). Blocking.
pub fn judge_now_keeping(in_window: bool) -> Verdict {
    judge(&baseline(), &Host::read(), in_window)
}

#[cfg(test)]
mod tests {
    use super::*;
    use antitamper_bpf::host_dropins::Reach;
    use std::path::PathBuf;

    fn harm(path: &str, directive: &str, value: &str, kind: Kind) -> Harm {
        Harm {
            path: PathBuf::from(path),
            directive: directive.to_string(),
            value: value.to_string(),
            why: "w".to_string(),
            reach: Reach::Agent,
            kind,
        }
    }

    fn names(b: &[u8]) -> Preload {
        preload_of(Ok(b.to_vec()))
    }

    /// A reading of the host with `preload` and `harms`, systemd's copy not
    /// read, every drop-in on disk.
    fn host(preload: &Preload, harms: &[Harm]) -> Host {
        Host {
            preload: preload.clone(),
            entries: BTreeMap::new(),
            harms: harms.to_vec(),
            loaded: Err("not read in this test".into()),
        }
    }

    fn j(base: &Baseline, preload: &Preload, harms: &[Harm]) -> Verdict {
        judge_with(base, &host(preload, harms), false, |_| true)
    }

    /// The review of #582 (F2 d): `/etc/ld.so.preload` written during the
    /// vacancy holds the start; the same list as at the watchdog's start (a
    /// vendor's own, signed then) is recorded, not held (F11); none, or an
    /// empty one, is nothing.
    #[test]
    fn a_preload_new_since_the_watchdog_s_start_holds_and_an_old_one_is_recorded() {
        let vendor = names(b"/opt/vendor/lib/libhook.so\n");
        let none = Baseline::of(Preload::Absent, &[]);
        let v = j(&none, &names(b"/tmp/x.so\n"), &[]);
        let why = v.hold.expect("held");
        assert!(
            why.contains("written or changed since the watchdog's start"),
            "{why}"
        );
        let base = Baseline::of(vendor.clone(), &[]);
        let v = j(&base, &vendor, &[]);
        assert_eq!(v.hold, None, "{}", v.detail);
        assert!(v.detail.contains("recorded, not held"), "{}", v.detail);
        // the vendor's list changed during the vacancy
        let v = j(
            &base,
            &names(b"/opt/vendor/lib/libhook.so /tmp/x.so\n"),
            &[],
        );
        assert!(v.hold.is_some(), "{}", v.detail);
        for p in [Preload::Absent, names(b" \n\t")] {
            let v = j(&none, &p, &[]);
            assert_eq!(v.hold, None, "{p:?}");
            let v = j(&base, &p, &[]);
            assert_eq!(v.hold, None, "removed is no harm: {p:?}");
        }
        // a FIFO or a device in its place: new since the start, held
        let v = j(&none, &Preload::Unreadable("a FIFO".into()), &[]);
        assert!(v.hold.unwrap().contains("a FIFO"));
    }

    /// The review of #582 (F2 d): a drop-in that changes our units' code
    /// (their environment, their commands, their memory's protection, one
    /// the judge cannot read) and appeared since the watchdog's start holds
    /// the start; the same as at its start is recorded; a harm to a limit,
    /// or a warning, never holds.
    #[test]
    fn a_code_drop_in_new_since_the_watchdog_s_start_holds() {
        let env = harm(
            "/usr/lib/systemd/system/service.d/x.conf",
            "UnsetEnvironment",
            "",
            Kind::Harmful,
        );
        let limit = harm(
            "/etc/systemd/system/northnarrow.slice.d/x.conf",
            "CPUQuota",
            "1%",
            Kind::Harmful,
        );
        let warn = harm(
            "/etc/systemd/system/service.d/y.conf",
            "Environment",
            "A=1",
            Kind::BreaksAgent,
        );
        let unread = harm(
            "/run/systemd/system/service.d/z.conf",
            "",
            "",
            Kind::Harmful,
        );
        let base = Baseline::of(Preload::Absent, &[]);
        for h in [&env, &unread] {
            let v = j(&base, &Preload::Absent, std::slice::from_ref(h));
            let why = v.hold.unwrap_or_else(|| panic!("{h:?} not held"));
            assert!(
                why.contains("a drop-in new since the watchdog's start"),
                "{why}"
            );
        }
        for h in [&limit, &warn] {
            let v = j(&base, &Preload::Absent, std::slice::from_ref(h));
            assert_eq!(v.hold, None, "{h:?}");
        }
        let base = Baseline::of(Preload::Absent, std::slice::from_ref(&env));
        assert_eq!(base.harms.len(), 1);
        let v = j(&base, &Preload::Absent, std::slice::from_ref(&env));
        assert_eq!(v.hold, None, "{}", v.detail);
        assert!(
            v.detail.contains("as at the watchdog's start"),
            "{}",
            v.detail
        );
        // the same file, another value: new
        let other = harm(
            &env.path.display().to_string(),
            "UnsetEnvironment",
            "",
            Kind::Harmful,
        );
        assert!(
            j(&base, &Preload::Absent, &[other.clone(), unread.clone()])
                .hold
                .is_some()
        );
        let changed = Harm {
            value: "x".into(),
            ..other
        };
        assert!(j(&base, &Preload::Absent, &[changed]).hold.is_some());
    }

    #[test]
    fn the_preload_file_is_read_as_the_loader_reads_it_and_never_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("ld.so.preload");
        assert_eq!(read_preload(&p), Preload::Absent);
        std::fs::write(&p, b"\n").unwrap();
        assert_eq!(read_preload(&p), Preload::Empty);
        std::fs::write(&p, b"/tmp/x.so\n").unwrap();
        assert!(matches!(read_preload(&p), Preload::Names { len: 10, .. }));
        // a symbolic link is followed, as the loader follows it
        let l = dir.path().join("link");
        std::os::unix::fs::symlink(&p, &l).unwrap();
        assert_eq!(read_preload(&l), read_preload(&p));
        // a FIFO is not read (the loader would wait on its writer)
        let f = dir.path().join("fifo");
        let c = std::ffi::CString::new(f.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert_eq!(read_preload(&f), Preload::Unreadable("a FIFO".into()));
        // never the contents, only the size and digest
        assert!(!read_preload(&p).describe().contains("/tmp/x.so"));
    }

    /// The re-check of #582 (N2): inside a signed trusted-installer window a
    /// start is never held — the guide's `systemctl edit` of the agent's
    /// environment and its restart are the operator's — and the host then
    /// becomes the reference (signed by the caller), so a later start
    /// outside a window is judged against the host as the operator left it,
    /// not held again; outside a window the same change holds.
    #[test]
    fn the_gate_holds_nothing_inside_a_signed_window_and_adopts_the_host() {
        let diag = harm(
            "/etc/systemd/system/northnarrow-agent.service.d/override.conf",
            "Environment",
            "NN_BPF_DEFENSE_OBSERVE=1",
            Kind::Harmful,
        );
        let base = Baseline::of(Preload::Absent, &[]);
        let h = host(&Preload::Absent, std::slice::from_ref(&diag));
        let out = judge_with(&base, &h, false, |_| true);
        assert!(out.hold.is_some(), "outside a window: {}", out.detail);
        let inside = judge_with(&base, &h, true, |_| true);
        assert_eq!(inside.hold, None, "{}", inside.detail);
        assert!(
            inside
                .detail
                .contains("inside a signed trusted-installer window, nothing held"),
            "{}",
            inside.detail
        );
        set_baseline(base.clone());
        let moved = adopt(&h).expect("the reference moves");
        assert!(moved.contains("as a signed trusted-installer window left it"), "{moved}");
        assert_eq!(adopt(&h), None, "nothing new: no second row");
        let later = judge_with(&baseline(), &h, false, |_| true);
        assert_eq!(later.hold, None, "{}", later.detail);
        assert!(later.detail.contains("as at the watchdog's start"), "{}", later.detail);
        set_baseline(base);
    }

    fn view(dropins: &[&str], env: &[&str], mdwe: bool) -> LoadedView {
        LoadedView {
            dropins: dropins.iter().map(|d| d.to_string()).collect(),
            need_reload: false,
            env: env.iter().map(|e| e.to_string()).collect(),
            unset: vec!["LD_PRELOAD".into()],
            mdwe,
            exec: "ExecStart\0/usr/bin/northnarrow-agent\0".into(),
        }
    }

    /// The re-check of #582 (N3): systemd's copy of the agent's unit, which
    /// its next start applies, judged before it — a drop-in it loaded that
    /// is no longer on disk (loaded, then deleted: the disk looks clean), a
    /// drop-in it loaded since the watchdog's start, its environment, the
    /// variables it unsets or its commands changed, `MemoryDenyWriteExecute`
    /// turned off: each holds. Files changed since it loaded them are
    /// recorded; a copy that cannot be read is recorded, never silent.
    #[test]
    fn systemd_s_copy_of_the_agent_s_unit_is_judged_before_a_start() {
        let a = "/usr/lib/systemd/system/service.d/10-timeout-abort.conf";
        let b = "/etc/systemd/system/service.d/zz.conf";
        let base = Baseline {
            loaded: Some(view(&[a], &["RUST_LOG=info"], true)),
            ..Baseline::of(Preload::Absent, &[])
        };
        let with = |v: LoadedView| Host {
            loaded: Ok(v),
            ..host(&Preload::Absent, &[])
        };
        let same = judge_with(&base, &with(view(&[a], &["RUST_LOG=info"], true)), false, |_| true);
        assert_eq!(same.hold, None, "{}", same.detail);
        let cases = [
            (view(&[a, b], &["RUST_LOG=info"], true), "since the watchdog's start: /etc"),
            (view(&[a], &["RUST_LOG=info", "NN_BPF_DEFENSE_OBSERVE=1"], true), "NN_BPF_DEFENSE_OBSERVE"),
            (view(&[a], &["RUST_LOG=info"], false), "MemoryDenyWriteExecute turned off"),
            (
                LoadedView {
                    unset: vec![],
                    ..view(&[a], &["RUST_LOG=info"], true)
                },
                "unsets",
            ),
            (
                LoadedView {
                    exec: "ExecStartPre\0/tmp/x\0".into(),
                    ..view(&[a], &["RUST_LOG=info"], true)
                },
                "commands",
            ),
        ];
        for (v, why) in cases {
            let out = judge_with(&base, &with(v), false, |_| true);
            let held = out.hold.unwrap_or_else(|| panic!("not held: {}", out.detail));
            assert!(held.contains(why), "{why}: {held}");
            assert!(!held.contains("debug"), "never a value");
        }
        // loaded, then deleted from disk: the copy still applies it
        let gone = judge_with(&base, &with(view(&[a, b], &["RUST_LOG=info"], true)), false, |p| p != b);
        assert!(gone.hold.unwrap().contains("no longer on disk: /etc/systemd/system/service.d/zz.conf"));
        let gone_old = judge_with(&base, &with(view(&[a], &["RUST_LOG=info"], true)), false, |p| p != a);
        assert!(gone_old.hold.unwrap().contains("no longer on disk"));
        // recorded only
        let stale = judge_with(
            &base,
            &with(LoadedView {
                need_reload: true,
                ..view(&[a], &["RUST_LOG=info"], true)
            }),
            false,
            |_| true,
        );
        assert_eq!(stale.hold, None);
        assert!(stale.detail.contains("NeedDaemonReload"), "{}", stale.detail);
        let unread = judge_with(&base, &host(&Preload::Absent, &[]), false, |_| true);
        assert_eq!(unread.hold, None);
        assert!(unread.detail.contains("not read"), "{}", unread.detail);
        // no reference copy: what is off now holds all the same
        let none = Baseline::of(Preload::Absent, &[]);
        let off = judge_with(&none, &with(view(&[a], &[], false)), false, |_| true);
        assert!(off.hold.unwrap().contains("MemoryDenyWriteExecute off"));
    }

    /// The re-check of #582 (N3): the preload list as the watchdog's start
    /// read it can only name files that do not load (a loadable one makes
    /// every start refuse itself); each name is judged — one that became
    /// loadable since (a file created during the vacancy), or changed,
    /// holds; the list's own text is split as the loader splits it.
    #[test]
    fn a_library_the_preload_list_names_that_became_loadable_holds() {
        let dir = tempfile::tempdir().unwrap();
        let lib = dir.path().join("k374-vendor.so");
        let text = format!("# vendor\n{}:/nonexistent/x.so  # comment\n", lib.display());
        assert_eq!(
            preload_names(text.as_bytes()),
            [lib.display().to_string(), "/nonexistent/x.so".to_string()]
        );
        let list = names(text.as_bytes());
        let read = || Host {
            entries: entries_of(Some(text.as_bytes())),
            ..host(&list, &[])
        };
        let before = read();
        assert!(before.entries.values().all(|e| *e == EntryId::Missing));
        let base = Baseline::of_host(&before);
        let v = judge_with(&base, &read(), false, |_| true);
        assert_eq!(v.hold, None, "{}", v.detail);
        std::fs::write(&lib, b"\x7fELF not really").unwrap();
        let v = judge_with(&base, &read(), false, |_| true);
        let why = v.hold.expect("a named library became loadable");
        assert!(why.contains("became loadable or changed since") && why.contains("k374-vendor.so"), "{why}");
        // as at the start, now with the file: recorded
        let base = Baseline::of_host(&read());
        assert_eq!(judge_with(&base, &read(), false, |_| true).hold, None);
        std::fs::write(&lib, b"\x7fELF changed").unwrap();
        assert!(judge_with(&base, &read(), false, |_| true).hold.is_some());
        // a bare name is searched where the loader searches; $LIB expands
        assert!(candidates("libx.so").contains(&"/usr/lib/x86_64-linux-gnu/libx.so".to_string()));
        assert!(candidates("/$LIB/liby.so").contains(&"/lib64/liby.so".to_string()));
        assert!(!candidates("/$LIB/liby.so").iter().any(|c| c.contains('$')));
    }
}
