//! Lot 374: the agent's side of the witness — the surviving role's record
//! of the other role's vacancy and successor.
//!
//! * The watchdog's witness key: read from the verified watchdog's own
//!   descriptor table (its sealed memory file, `nn_proto::witness`), never
//!   from a path, and certified in the agent's signed audit chain
//!   ([`WITNESS_KEY`]) — once per key.
//! * The watchdog's witness chain: each row the agent can verify — signed
//!   by a key it certified, linked to the row before it — imported into its
//!   own chain ([`WITNESS_ROW`]); a row of a key it never certified is
//!   recorded as such ([`WITNESS_UNCERTIFIED`]), a broken chain too
//!   ([`WITNESS_BROKEN`]). Where it stopped is kept in the witness directory
//!   ([`nn_proto::witness::IMPORTED_FILE`]), which only the family writes.
//! * The watchdog's successor, when the watchdog's role was vacated: given
//!   the agent's registration only when it is its unit's restart, with clean
//!   lot 277/281 marks and nothing foreign in its environment or mappings
//!   ([`judge_watchdog_successor`]); recorded either way
//!   ([`WATCHDOG_SUCCESSION`], [`WATCHDOG_SUCCESSOR_REFUSED`]).
//! * Both roles found vacated at the agent's start: [`ROLES_VACATED_GAP`].

use std::path::{Path, PathBuf};

use nn_proto::witness::{
    parse_key_record, to_import, Imported, CHAIN_FILE, CHAIN_MAX_BYTES, IMPORTED_FILE,
    KEY_MEMFD_NAME, KIND_OPENED,
};

use crate::self_integrity::Finding;

/// The watchdog's witness key, certified (read from its own descriptor
/// table).
pub const WITNESS_KEY: &str = "witness_key_certified";
/// A row of the watchdog's witness chain, verified: the agent's role
/// vacated, its successor, the role found vacated (High).
pub const WITNESS_ROW: &str = "witness_row";
/// A witness row of a watchdog life's start (informational).
pub const WITNESS_OPENED: &str = "witness_opened";
/// A witness row signed by a key the agent never certified (High: what it
/// says is the watchdog's claim alone).
pub const WITNESS_UNCERTIFIED: &str = "witness_row_uncertified";
/// The witness chain broken: a row changed, removed or not one (High).
pub const WITNESS_BROKEN: &str = "witness_chain_broken";
/// The watchdog's vacated role taken by its unit's clean restart (High:
/// the watchdog died).
pub const WATCHDOG_SUCCESSION: &str = "watchdog_succession";
/// A process that took the watchdog's vacated role refused the agent's
/// registration: not its unit's restart, marks not clean, or something
/// foreign in it (High).
pub const WATCHDOG_SUCCESSOR_REFUSED: &str = "watchdog_successor_refused";
/// Both roles found vacated at the agent's start (High).
pub const ROLES_VACATED_GAP: &str = "roles_vacated_gap";

/// The public half the watchdog `pid` published: its sealed memory file
/// ([`KEY_MEMFD_NAME`]) in its own descriptor table, sealed against any
/// write, naming `pid` and its start. `Err` says why there is none.
pub fn published_key(pid: u32) -> Result<String, String> {
    let dir = format!("/proc/{pid}/fd");
    let names = antitamper_bpf::kernel_roots::read_dir_max(&dir, 256)
        .map_err(|e| format!("{dir}: {e}"))?;
    let want = format!("/memfd:{KEY_MEMFD_NAME}");
    let start = antitamper_bpf::start_check::start_ticks(pid)
        .ok_or_else(|| format!("the start of {pid} cannot be read"))?;
    for n in names {
        let entry = format!("{dir}/{}", n.to_string_lossy());
        let Ok(link) = antitamper_bpf::kernel_roots::read_link(&entry) else {
            continue;
        };
        if !link.to_string_lossy().starts_with(&want) {
            continue;
        }
        let f = antitamper_bpf::kernel_roots::open(&entry, libc::O_RDONLY | libc::O_CLOEXEC)
            .map_err(|e| format!("{entry}: {e}"))?;
        let need = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
        // SAFETY: fcntl on a descriptor we hold.
        let seals = unsafe { libc::fcntl(std::os::fd::AsRawFd::as_raw_fd(&f), libc::F_GET_SEALS) };
        if seals < 0 || seals & need != need {
            return Err(format!("the watchdog's key file is not sealed (seals {seals:#x})"));
        }
        let body = antitamper_bpf::kernel_roots::read_file_bounded(&f, 256)
            .map_err(|e| format!("{entry}: {e}"))?;
        let (tgid, at, key) = parse_key_record(&String::from_utf8_lossy(&body))
            .ok_or("the watchdog's key file holds no key record")?;
        if tgid != pid || at != start {
            return Err(format!(
                "the key record names pid {tgid} started at {at}, not the watchdog {pid} ({start})"
            ));
        }
        return Ok(key);
    }
    Err(format!("the watchdog {pid} published no witness key"))
}

/// The agent's reader of the watchdog's witness chain in `dir`.
#[derive(Debug)]
pub struct WitnessReader {
    dir: PathBuf,
    imported: Option<Imported>,
}

impl WitnessReader {
    pub fn new(dir: &Path) -> Self {
        WitnessReader {
            dir: dir.to_path_buf(),
            imported: None,
        }
    }

    fn position(&mut self) -> &mut Imported {
        let path = self.dir.join(IMPORTED_FILE);
        self.imported.get_or_insert_with(|| {
            crate::state_read::read_state(&path)
                .ok()
                .and_then(|t| serde_json::from_str(&t).ok())
                .unwrap_or_default()
        })
    }

    /// Kept in place (the file's inode is the one the deny hooks protect).
    fn save(&self) {
        let Some(imp) = &self.imported else {
            return;
        };
        let path = self.dir.join(IMPORTED_FILE);
        let body = serde_json::to_vec(imp).unwrap_or_default();
        let r = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .and_then(|mut f| std::io::Write::write_all(&mut f, &body).and_then(|()| f.sync_all()));
        if let Err(e) = r {
            tracing::warn!(path = %path.display(), error = %e, "witness: import position not kept");
        }
    }

    /// The watchdog `pid`'s published key certified: a finding the first
    /// time this key is seen (`None` after, or when it publishes none — that
    /// is in the debug log: a watchdog without a witness says so itself).
    pub fn certify(&mut self, pid: u32) -> Option<Finding> {
        let key = match published_key(pid) {
            Ok(k) => k,
            Err(why) => {
                tracing::debug!(watchdog_pid = pid, why = %why, "witness: no key certified");
                return None;
            }
        };
        if !self.position().certify(&key) {
            return None;
        }
        self.save();
        Some(Finding {
            kind: WITNESS_KEY,
            detail: format!(
                "the watchdog (pid {pid}) witness key {key}, read from its own sealed memory file: \
                 its witness rows are verified against it"
            ),
        })
    }

    /// The witness rows after the last one imported, as findings, and the
    /// position they move it to. The caller signs them, then
    /// [`WitnessReader::commit`]s the position (a row is never skipped
    /// unsigned).
    pub fn pending(&mut self) -> (Vec<Finding>, Option<String>) {
        let path = self.dir.join(CHAIN_FILE);
        let text = match crate::state_read::read_bounded(&path, CHAIN_MAX_BYTES) {
            Ok(b) => String::from_utf8_lossy(&b).into_owned(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (Vec::new(), None),
            Err(e) => {
                return (
                    vec![Finding {
                        kind: WITNESS_BROKEN,
                        detail: format!("the witness chain {}: {e}", path.display()),
                    }],
                    None,
                )
            }
        };
        let t = to_import(&text, self.position());
        let mut out = Vec::new();
        if t.position_lost {
            out.push(Finding {
                kind: WITNESS_BROKEN,
                detail: "the witness chain no longer holds the last row the agent imported \
                         (replaced or cut): its rows are imported again"
                    .to_string(),
            });
        }
        let mut last = None;
        for (row, hash, certified) in &t.rows {
            let kind = match (*certified, row.kind == KIND_OPENED) {
                (false, _) => WITNESS_UNCERTIFIED,
                (true, true) => WITNESS_OPENED,
                (true, false) => WITNESS_ROW,
            };
            out.push(Finding {
                kind,
                detail: format!("{} (row hash {})", row.describe(), &hash[..16]),
            });
            last = Some(hash.clone());
        }
        if let Some(why) = t.broken {
            out.push(Finding {
                kind: WITNESS_BROKEN,
                detail: format!("the witness chain is broken at {why}: what follows is not imported"),
            });
        }
        (out, last)
    }

    /// The position after the rows [`WitnessReader::pending`] gave, signed.
    pub fn commit(&mut self, last: Option<String>) {
        if let Some(h) = last {
            self.position().last = h;
            self.save();
        }
    }
}

/// What the agent found of a process that took the watchdog's vacated role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuccessorVerdict {
    /// Its unit's restart, clean marks, nothing foreign: registered.
    pub given: bool,
    pub detail: String,
}

/// The process `pid` that took the watchdog's vacated role: `id` where it
/// was started, `marks_clean` its lot 277/281 marks (`None`: not known),
/// `found` its environment and mappings. Given the agent's registration
/// only when all hold.
pub fn judge_watchdog_successor(
    pid: u32,
    id: &antitamper_bpf::start_check::Identity,
    marks_clean: Option<bool>,
    found: &antitamper_bpf::start_check::Findings,
) -> SuccessorVerdict {
    let in_unit = id.in_unit(antitamper_bpf::start_check::WATCHDOG_UNIT);
    let marks = match marks_clean {
        Some(true) => "marks clean",
        Some(false) => "marked (moved into its cgroup, born there by another, or injected)",
        None => "marks not known",
    };
    let given = in_unit && marks_clean == Some(true) && found.clean();
    SuccessorVerdict {
        given,
        detail: format!(
            "the watchdog's role, vacated, taken by pid {pid}: {}; {}; {marks}; {}",
            if in_unit {
                "its unit's restart"
            } else {
                "NOT its unit's restart (not PID 1's child in the watchdog's own cgroup)"
            },
            id.describe(),
            found.describe()
        ),
    }
}

/// Lot 277/281 marks of process `pid` read now: `Some(true)` it runs where
/// it started and nothing was injected into it.
pub fn marks_clean(pid: u32) -> Option<bool> {
    use nn_core::decision::rule_policy::Injected;
    let proc_root = Path::new("/proc");
    let started = crate::cgroup_join::started_in_cgroup(proc_root, pid)?;
    let injected = crate::cgroup_join::injected(proc_root, pid)?;
    Some(started && injected == Injected::No)
}

/// Both roles vacated at the agent's start (`agent` and `watchdog`, the
/// two `ROLE_TGIDS` slots it read before it claimed its own): the gap's
/// finding.
pub fn roles_gap(agent: u32, watchdog: u32) -> Option<Finding> {
    use antitamper_bpf::ROLE_VACATED;
    (agent == ROLE_VACATED && watchdog == ROLE_VACATED).then(|| Finding {
        kind: ROLES_VACATED_GAP,
        detail: "the agent's start found both roles vacated this boot: the agent and the \
                 watchdog had exited, no role held the other's record of it until now"
            .to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use antitamper_bpf::start_check::{Findings, Identity};
    use nn_proto::witness::{line_hash, Row, WitnessKey, KIND_SUCCEEDED, KIND_VACATED, ROW_VERSION};

    fn unit() -> Identity {
        Identity {
            ppid: Some(1),
            cgroup: Some("/northnarrow.slice/northnarrow-watchdog.service".into()),
        }
    }

    #[test]
    fn a_watchdog_successor_is_registered_only_as_its_unit_s_clean_restart() {
        let v = judge_watchdog_successor(9, &unit(), Some(true), &Findings::default());
        assert!(v.given, "{}", v.detail);
        for (id, marks, found) in [
            (
                Identity {
                    ppid: Some(1),
                    cgroup: Some("/system.slice/run-u7.service".into()),
                },
                Some(true),
                Findings::default(),
            ),
            (
                Identity {
                    ppid: Some(3000),
                    cgroup: Some("/northnarrow.slice/northnarrow-watchdog.service".into()),
                },
                Some(true),
                Findings::default(),
            ),
            (unit(), Some(false), Findings::default()),
            (unit(), None, Findings::default()),
            (
                unit(),
                Some(true),
                Findings {
                    loader_vars: vec!["LD_PRELOAD".into()],
                    ..Findings::default()
                },
            ),
        ] {
            let v = judge_watchdog_successor(9, &id, marks, &found);
            assert!(!v.given, "{}", v.detail);
        }
        let v = judge_watchdog_successor(9, &unit(), Some(true), &Findings::default());
        assert!(v.detail.contains("taken by pid 9") && v.detail.contains("marks clean"));
    }

    #[test]
    fn both_roles_vacated_is_the_gap_and_nothing_else_is() {
        use antitamper_bpf::ROLE_VACATED as V;
        assert_eq!(roles_gap(V, V).map(|f| f.kind), Some(ROLES_VACATED_GAP));
        for (a, w) in [(V, 0), (0, V), (V, 42), (42, V), (0, 0)] {
            assert!(roles_gap(a, w).is_none(), "{a} {w}");
        }
    }

    /// A memory file named as the watchdog's key file, holding `body`,
    /// sealed or not, in this process's descriptor table.
    fn key_file(body: &str, sealed: bool) -> std::os::fd::OwnedFd {
        use std::io::Write;
        use std::os::fd::{AsRawFd, FromRawFd};
        let name = std::ffi::CString::new(KEY_MEMFD_NAME).unwrap();
        // SAFETY: a NUL-terminated name.
        let fd = unsafe {
            libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
        };
        assert!(fd >= 0);
        // SAFETY: a new descriptor this test owns.
        let mut f = std::fs::File::from(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) });
        f.write_all(body.as_bytes()).unwrap();
        if sealed {
            let s = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
            // SAFETY: fcntl on a descriptor we hold.
            assert_eq!(unsafe { libc::fcntl(f.as_raw_fd(), libc::F_ADD_SEALS, s) }, 0);
        }
        f.into()
    }

    /// Lot 374: the watchdog's key is taken only from a sealed memory file
    /// in the watchdog's own descriptor table that names that process and
    /// its start — never from a file another process could write — and
    /// certified once.
    #[test]
    fn the_witness_key_is_read_only_from_the_watchdog_s_own_sealed_file() {
        let me = std::process::id();
        let start = antitamper_bpf::start_check::start_ticks(me).unwrap();
        let key = WitnessKey::from_seed([6; 32]).public_hex();
        let err = published_key(me).unwrap_err();
        assert!(err.contains("published no witness key"), "{err}");
        let record = nn_proto::witness::key_record(me, start, &key);
        for (body, sealed, why) in [
            (record.clone(), false, "not sealed"),
            (nn_proto::witness::key_record(me + 1, start, &key), true, "names pid"),
            (nn_proto::witness::key_record(me, start + 1, &key), true, "names pid"),
            ("nothing\n".to_string(), true, "holds no key record"),
        ] {
            let fd = key_file(&body, sealed);
            let err = published_key(me).unwrap_err();
            assert!(err.contains(why), "{why}: {err}");
            drop(fd);
        }
        let fd = key_file(&record, true);
        assert_eq!(published_key(me), Ok(key.clone()));
        // certified once, kept for the next reader
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(IMPORTED_FILE), b"").unwrap();
        let mut r = WitnessReader::new(dir.path());
        let f = r.certify(me).expect("certified");
        assert_eq!(f.kind, WITNESS_KEY);
        assert!(f.detail.contains(&key), "{}", f.detail);
        assert!(r.certify(me).is_none(), "once");
        assert!(WitnessReader::new(dir.path()).position().certified(&key));
        drop(fd);
    }

    fn write_chain(dir: &Path, k: &WitnessKey, kinds: &[&str]) -> Vec<String> {
        let mut prev = String::new();
        let mut lines = Vec::new();
        for (i, kind) in kinds.iter().enumerate() {
            let r = k.sign(Row {
                v: ROW_VERSION,
                seq: i as u64,
                prev: prev.clone(),
                at: 1,
                tgid: 50,
                key: String::new(),
                kind: kind.to_string(),
                detail: format!("row {i}"),
                sig: String::new(),
            });
            let l = serde_json::to_string(&r).unwrap();
            prev = line_hash(&l);
            lines.push(l);
        }
        std::fs::write(dir.join(CHAIN_FILE), lines.join("\n") + "\n").unwrap();
        lines
    }

    #[test]
    fn witness_rows_are_imported_once_after_their_key_is_certified() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(IMPORTED_FILE), b"").unwrap();
        let k = WitnessKey::from_seed([4; 32]);
        write_chain(dir.path(), &k, &[KIND_OPENED, KIND_VACATED, KIND_SUCCEEDED]);
        let mut r = WitnessReader::new(dir.path());
        // not certified: recorded as the watchdog's claim alone
        let (f, last) = r.pending();
        assert_eq!(f.len(), 3);
        assert!(f.iter().all(|x| x.kind == WITNESS_UNCERTIFIED));
        assert!(last.is_some());
        // certified (as `certify` does from the memory file), from scratch
        let mut r = WitnessReader::new(dir.path());
        r.position().certify(&k.public_hex());
        let (f, last) = r.pending();
        assert_eq!(
            f.iter().map(|x| x.kind).collect::<Vec<_>>(),
            vec![WITNESS_OPENED, WITNESS_ROW, WITNESS_ROW]
        );
        assert!(f[1].detail.contains("role_vacated"), "{}", f[1].detail);
        r.commit(last);
        // nothing again, and kept across a new reader (the agent's restart)
        assert!(r.pending().0.is_empty());
        let mut again = WitnessReader::new(dir.path());
        assert!(again.pending().0.is_empty());
        // a row changed: broken, said
        let text = std::fs::read_to_string(dir.path().join(CHAIN_FILE)).unwrap();
        std::fs::write(dir.path().join(CHAIN_FILE), text.replace("row 1", "row X")).unwrap();
        let mut after = WitnessReader::new(dir.path());
        let (f, _) = after.pending();
        assert!(f.iter().any(|x| x.kind == WITNESS_BROKEN), "{f:?}");
    }
}
