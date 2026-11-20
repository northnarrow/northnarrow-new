//! The review of #582 (F2 d): what the host would give the agent's
//! successor before its `main`, judged by the watchdog before each start of
//! the agent it makes — a respawn after a vacancy, a hold's retry.
//!
//! A change made while the role is vacated is seen by no live agent: a
//! drop-in that reaches our units and changes the code they run (their
//! environment, their commands, their memory's protection), or
//! `/etc/ld.so.preload`. The watchdog's reference is what it read at its own
//! start, while the agent ran, signed in its witness chain's first row of
//! the life ([`Baseline::describe`]). Before a start it reads both again:
//! what is as it was then is recorded (a vendor's own `ld.so.preload`, a
//! host's drop-in the agent signed), what is new or changed since holds the
//! start — recorded in the witness chain and the agent's hold records, and
//! the agent stays down until an operator acts or the hold's retry finds
//! the host as it was.
//!
//! Only names, paths, sizes and digests are recorded, never a file's
//! contents.

use std::collections::BTreeSet;
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::Path;
use std::sync::OnceLock;

use antitamper_bpf::host_dropins::{Harm, Kind};

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
    preload_of(read())
}

/// A harm's identity: where, which directive, what value.
pub fn harm_key(h: &Harm) -> String {
    format!("{}|{}|{}", h.path.display(), h.directive, h.value)
}

/// `h` changes the code a start of our units runs ([`CODE_DIRECTIVES`]).
pub fn reaches_code(h: &Harm) -> bool {
    h.kind == Kind::Harmful && CODE_DIRECTIVES.contains(&h.directive.as_str())
}

/// What the watchdog read at its start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Baseline {
    pub preload: Preload,
    /// [`harm_key`] of every drop-in harm that reaches code then.
    pub harms: BTreeSet<String>,
}

impl Baseline {
    pub fn of(preload: Preload, harms: &[Harm]) -> Baseline {
        Baseline {
            preload,
            harms: harms
                .iter()
                .filter(|h| reaches_code(h))
                .map(harm_key)
                .collect(),
        }
    }

    /// The host now.
    pub fn now() -> Baseline {
        Baseline::of(
            read_preload(Path::new(PRELOAD_PATH)),
            &antitamper_bpf::host_dropins::harmful_here(),
        )
    }

    /// One phrase for the witness chain's first row of the life.
    pub fn describe(&self) -> String {
        format!(
            "the host before any start it makes: {}; {} drop-in directive(s) that change our \
             units' code",
            self.preload.describe(),
            self.harms.len()
        )
    }
}

/// What a judgement before a start found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// Why the start is held; `None`: it goes on.
    pub hold: Option<String>,
    /// What was found, held or not (for the vacancy's or the successor's
    /// row).
    pub detail: String,
}

/// The host now (`preload`, `harms`) against `base`: a preload or a
/// code-reaching drop-in harm that is new or changed since holds; one as it
/// was is recorded only.
pub fn judge(base: &Baseline, preload: &Preload, harms: &[Harm]) -> Verdict {
    let mut held = Vec::new();
    let mut seen = Vec::new();
    if preload.loads() {
        if *preload == base.preload {
            seen.push(format!(
                "{}, as at the watchdog's start (recorded, not held)",
                preload.describe()
            ));
        } else {
            held.push(format!(
                "{}, written or changed since the watchdog's start ({})",
                preload.describe(),
                base.preload.describe()
            ));
        }
    }
    let mut old = 0usize;
    for h in harms.iter().filter(|h| reaches_code(h)) {
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
    let detail = if held.is_empty() && seen.is_empty() {
        format!(
            "the host before the start: {}, no drop-in that changes our units' code",
            preload.describe()
        )
    } else {
        format!(
            "the host before the start: {}",
            held.iter().chain(seen.iter()).cloned().collect::<Vec<_>>().join("; ")
        )
    };
    Verdict {
        hold: (!held.is_empty()).then(|| held.join("; ")),
        detail: detail.chars().take(1200).collect(),
    }
}

static BASELINE: OnceLock<Baseline> = OnceLock::new();

/// The watchdog's start keeps its reference (once).
pub fn set_baseline(b: Baseline) {
    let _ = BASELINE.set(b);
}

/// [`judge`] of the host now against the reference the start kept (an
/// empty reference when it kept none: then anything preloaded, any
/// code-reaching drop-in holds). Blocking: call off the runtime.
pub fn judge_now() -> Verdict {
    let empty = Baseline {
        preload: Preload::Absent,
        harms: BTreeSet::new(),
    };
    let base = BASELINE.get().unwrap_or(&empty);
    judge(
        base,
        &read_preload(Path::new(PRELOAD_PATH)),
        &antitamper_bpf::host_dropins::harmful_here(),
    )
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

    /// The review of #582 (F2 d): `/etc/ld.so.preload` written during the
    /// vacancy holds the start; the same list as at the watchdog's start (a
    /// vendor's own, signed then) is recorded, not held (F11); none, or an
    /// empty one, is nothing.
    #[test]
    fn a_preload_new_since_the_watchdog_s_start_holds_and_an_old_one_is_recorded() {
        let vendor = names(b"/opt/vendor/lib/libhook.so\n");
        let none = Baseline::of(Preload::Absent, &[]);
        let v = judge(&none, &names(b"/tmp/x.so\n"), &[]);
        let why = v.hold.expect("held");
        assert!(why.contains("written or changed since the watchdog's start"), "{why}");
        let base = Baseline::of(vendor.clone(), &[]);
        let v = judge(&base, &vendor, &[]);
        assert_eq!(v.hold, None, "{}", v.detail);
        assert!(v.detail.contains("recorded, not held"), "{}", v.detail);
        // the vendor's list changed during the vacancy
        let v = judge(&base, &names(b"/opt/vendor/lib/libhook.so /tmp/x.so\n"), &[]);
        assert!(v.hold.is_some(), "{}", v.detail);
        for p in [Preload::Absent, names(b" \n\t")] {
            let v = judge(&none, &p, &[]);
            assert_eq!(v.hold, None, "{p:?}");
            let v = judge(&base, &p, &[]);
            assert_eq!(v.hold, None, "removed is no harm: {p:?}");
        }
        // a FIFO or a device in its place: new since the start, held
        let v = judge(&none, &Preload::Unreadable("a FIFO".into()), &[]);
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
        let unread = harm("/run/systemd/system/service.d/z.conf", "", "", Kind::Harmful);
        let base = Baseline::of(Preload::Absent, &[]);
        for h in [&env, &unread] {
            let v = judge(&base, &Preload::Absent, std::slice::from_ref(h));
            let why = v.hold.unwrap_or_else(|| panic!("{h:?} not held"));
            assert!(why.contains("a drop-in new since the watchdog's start"), "{why}");
        }
        for h in [&limit, &warn] {
            let v = judge(&base, &Preload::Absent, std::slice::from_ref(h));
            assert_eq!(v.hold, None, "{h:?}");
        }
        let base = Baseline::of(Preload::Absent, std::slice::from_ref(&env));
        assert_eq!(base.harms.len(), 1);
        let v = judge(&base, &Preload::Absent, std::slice::from_ref(&env));
        assert_eq!(v.hold, None, "{}", v.detail);
        assert!(v.detail.contains("as at the watchdog's start"), "{}", v.detail);
        // the same file, another value: new
        let other = harm(&env.path.display().to_string(), "UnsetEnvironment", "", Kind::Harmful);
        assert!(judge(&base, &Preload::Absent, &[other.clone(), unread.clone()])
            .hold
            .is_some());
        let changed = Harm {
            value: "x".into(),
            ..other
        };
        assert!(judge(&base, &Preload::Absent, &[changed]).hold.is_some());
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
}
