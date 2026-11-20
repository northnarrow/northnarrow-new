//! Lot 374: the agent's side of the witness — the surviving role's record
//! of the other role's vacancy and successor.
//!
//! * The watchdog's witness key: read from the verified watchdog's own
//!   descriptor table (its sealed memory file, `nn_proto::witness`), never
//!   from a path, and certified in the agent's signed audit chain
//!   ([`WITNESS_KEY`]) — once per key.
//! * The watchdog's witness chain: each row the agent can verify — signed
//!   by a key it certified, linked to the row before it — imported into its
//!   own chain ([`WITNESS_ROW`], High: the role vacated, taken by a process
//!   that is not its unit's clean restart; [`WITNESS_NOTE`]: the
//!   bookkeeping); a row of a key it never certified is
//!   recorded as such ([`WITNESS_UNCERTIFIED`]), a broken chain too
//!   ([`WITNESS_BROKEN`]). Where it stopped is kept in the witness directory
//!   ([`nn_proto::witness::IMPORTED_FILE`]), which only the family writes.
//! * The watchdog's successor, when the watchdog's role was vacated: given
//!   the agent's registration only when it is its unit's restart, with clean
//!   lot 277/281 marks and nothing foreign in its environment or mappings
//!   ([`judge_watchdog_successor`]); recorded either way — a successor that
//!   is not is observed, never refused here (the kernel gave it the role)
//!   ([`WATCHDOG_SUCCESSION`], [`WATCHDOG_SUCCESSOR_FOREIGN`]).
//! * Both roles found vacated at the agent's start: [`ROLES_VACATED_GAP`].

use std::path::{Path, PathBuf};

use nn_proto::witness::{
    parse_key_record, to_import, Imported, CHAIN_FILE, CHAIN_MAX_BYTES, IMPORTED_FILE,
    KEY_MEMFD_NAME, KIND_CHAIN_TORN, KIND_GATE_REFERENCE, KIND_OPENED, KIND_RELEASED,
    KIND_RELEASED_IN_WINDOW, KIND_SUCCEEDED,
};

/// A finding of this module signed as a note ([`WITNESS_OP`]): the
/// bookkeeping of the witness, never a drift of the host.
pub fn is_note(kind: &str) -> bool {
    matches!(
        kind,
        WITNESS_KEY | WITNESS_NOTE | WATCHDOG_SUCCESSION | ROLES_RELEASED
    )
}

/// A verified row's finding: the watchdog's bookkeeping a note, its record
/// of the role's vacancy or of a successor not its unit's clean restart a
/// [`WITNESS_ROW`] (High).
pub fn row_kind(row_kind: &str) -> &'static str {
    if matches!(
        row_kind,
        KIND_OPENED
            | KIND_RELEASED
            | KIND_RELEASED_IN_WINDOW
            | KIND_SUCCEEDED
            | KIND_GATE_REFERENCE
            | KIND_CHAIN_TORN
    ) {
        WITNESS_NOTE
    } else {
        WITNESS_ROW
    }
}

use crate::self_integrity::Finding;

/// The watchdog's witness key, certified (read from its own descriptor
/// table).
pub const WITNESS_KEY: &str = "witness_key_certified";
/// A row of the watchdog's witness chain, verified: the agent's role
/// vacated, its successor, the role found vacated (High).
pub const WITNESS_ROW: &str = "witness_row";
/// A witness row of the watchdog's bookkeeping, verified: a life's first
/// row, the role released by a signed shutdown, the unit's clean restart
/// taking it (signed as a note, [`WITNESS_OP`], not as a drift).
pub const WITNESS_NOTE: &str = "witness_note";
/// The audit op of the witness's notes and of a key's certification.
pub const WITNESS_OP: &str = "witness";
/// A witness row signed by a key the agent never certified (High: what it
/// says is the watchdog's claim alone).
pub const WITNESS_UNCERTIFIED: &str = "witness_row_uncertified";
/// The witness chain broken: a row changed, removed or not one (High).
pub const WITNESS_BROKEN: &str = "witness_chain_broken";
/// The watchdog's vacated role taken by its unit's clean restart (a note:
/// its death is `watchdog_gone`).
pub const WATCHDOG_SUCCESSION: &str = "watchdog_succession";
/// The re-check of #582 (N4): the watchdog's vacated role taken by its
/// unit's clean restart, but a library it maps was replaced on disk since
/// and is not the agent's own copy — its identity not confirmed (High). The
/// agent registers it: never withheld for that alone.
pub const WATCHDOG_SUCCESSOR_UNCONFIRMED: &str = "watchdog_successor_unconfirmed";
/// The review of #582 (F3): the process that took the watchdog's vacated
/// role is not its unit's clean restart — not its unit's restart, marks not
/// clean, or something foreign in it (High). Observed, not refused: the
/// kernel gave it the role and it registers itself; the agent withholds its
/// own registration of it and its posture exemption.
pub const WATCHDOG_SUCCESSOR_FOREIGN: &str = "watchdog_successor_foreign";
/// Both roles found vacated at the agent's start (High).
pub const ROLES_VACATED_GAP: &str = "roles_vacated_gap";

/// The public half the watchdog `pid` published: its sealed memory file
/// ([`KEY_MEMFD_NAME`]) in its own descriptor table, sealed against any
/// write, naming `pid` and its start. `Err` says why there is none.
pub fn published_key(pid: u32) -> Result<String, String> {
    let fds = format!("/proc/{pid}/fd");
    let names =
        antitamper_bpf::kernel_roots::read_dir_max(&fds, 256).map_err(|e| format!("{fds}: {e}"))?;
    let want = format!("/memfd:{KEY_MEMFD_NAME}");
    let start = antitamper_bpf::start_check::start_ticks(pid)
        .ok_or_else(|| format!("the start of {pid} cannot be read"))?;
    for n in names {
        let entry = format!("{fds}/{}", n.to_string_lossy());
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
            return Err(format!(
                "the watchdog's key file is not sealed (seals {seals:#x})"
            ));
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
        // in place (the inode the deny hooks protect); lost at a crash, the
        // position only makes rows imported again, never skipped
        if let Err(e) = antitamper_bpf::kernel_roots::write(&path, &body) {
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
        let mut t = to_import(&text, self.position());
        let mut out = Vec::new();
        // The re-check of #582 (N6): the chain rotated (full, at a watchdog's
        // open or within its life) — the import continues in the rotated
        // chain (`witness.chain.1`) where it stopped, then the new chain
        // from its first row: no row is lost, and a rotation is not a cut.
        if t.position_lost {
            if let Some(rest) = self.rotated_rest() {
                let from_start = Imported {
                    keys: self.position().keys.clone(),
                    last: String::new(),
                };
                let mut whole = to_import(&text, &from_start);
                if !whole.position_lost {
                    let mut rows = rest.rows;
                    rows.append(&mut whole.rows);
                    whole.rows = rows;
                    whole.broken = rest.broken.or(whole.broken);
                    t = whole;
                }
            }
        }
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
            let kind = if *certified {
                row_kind(&row.kind)
            } else {
                WITNESS_UNCERTIFIED
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
                detail: format!(
                    "the witness chain is broken at {why}: what follows is not imported"
                ),
            });
        }
        (out, last)
    }

    /// The re-check of #582 (N6): the rows of the rotated chain
    /// (`witness.chain.1`) after the last one imported — `None` when that
    /// chain does not hold it either.
    fn rotated_rest(&mut self) -> Option<nn_proto::witness::ToImport> {
        let path = self.dir.join(format!("{CHAIN_FILE}.1"));
        let b = crate::state_read::read_bounded(&path, CHAIN_MAX_BYTES).ok()?;
        let t = to_import(&String::from_utf8_lossy(&b), self.position());
        (!t.position_lost).then_some(t)
    }

    /// The review of #582 (F4 b): the chain's last valid row is the agent's
    /// role released by a shutdown the admin quorum signed
    /// ([`KIND_RELEASED`]: the watchdog stands down after it), signed by a
    /// key this agent's position certified — a later life of a watchdog
    /// would have opened a row after it.
    /// The re-check of #582 (N8): signed this boot — a release a previous
    /// boot's chain ends with (its certified key kept) is not this boot's
    /// stop.
    pub fn ends_with_signed_release(&mut self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let up = antitamper_bpf::start_check::boot_ns_now() / 1_000_000_000;
        self.ends_with_signed_release_since(now.saturating_sub(up))
    }

    /// [`WitnessReader::ends_with_signed_release`], the row written at
    /// `boot_at` (unix seconds) or after.
    pub fn ends_with_signed_release_since(&mut self, boot_at: u64) -> bool {
        let path = self.dir.join(CHAIN_FILE);
        let Ok(b) = crate::state_read::read_bounded(&path, CHAIN_MAX_BYTES) else {
            return false;
        };
        let text = String::from_utf8_lossy(&b).into_owned();
        let last = nn_proto::witness::judge_chain(&text)
            .into_iter()
            .rev()
            .find_map(|j| match j {
                nn_proto::witness::Judged::Valid { row, .. } => Some(row),
                nn_proto::witness::Judged::Broken { .. } => None,
            });
        last.is_some_and(|row| {
            row.kind == KIND_RELEASED && row.at >= boot_at && self.position().certified(&row.key)
        })
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
    /// The re-check of #582 (N4): and no library of it replaced on disk
    /// that is not the agent's own copy (`Findings::replaced`); a given
    /// successor that is not confirmed is registered, and signed High
    /// ([`WATCHDOG_SUCCESSOR_UNCONFIRMED`]).
    pub confirmed: bool,
}

impl SuccessorVerdict {
    /// The finding's kind: [`WATCHDOG_SUCCESSION`] (a note) for a given,
    /// confirmed successor, [`WATCHDOG_SUCCESSOR_UNCONFIRMED`] for a given
    /// one whose libraries' identity is not confirmed, and
    /// [`WATCHDOG_SUCCESSOR_FOREIGN`] otherwise.
    pub fn kind(&self) -> &'static str {
        match (self.given, self.confirmed) {
            (true, true) => WATCHDOG_SUCCESSION,
            (true, false) => WATCHDOG_SUCCESSOR_UNCONFIRMED,
            (false, _) => WATCHDOG_SUCCESSOR_FOREIGN,
        }
    }
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
    // the review of #582 (F3): observed, not refused
    let taken = if given {
        ""
    } else {
        " — it holds the role the kernel gave it and registers itself; the agent does not \
         register it nor exempt it"
    };
    SuccessorVerdict {
        given,
        confirmed: given && found.confirmed(),
        detail: format!(
            "the watchdog's role taken by pid {pid}: {}{taken}; {}; {marks}; {}",
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

/// The re-check 3 of #582 (R2-1): one step of the agent's watch over the
/// watchdog it verified ([`successor_step`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuccessorStep {
    /// Not judged: no succession pending, and not the watchdog this
    /// agent's start found first — registered as before.
    NotJudged,
    /// Not given: not registered nor exempted; the verdict to sign (High).
    Foreign(SuccessorVerdict),
    /// Given, a successor nobody judged: registered; the verdict to sign
    /// ([`SuccessorVerdict::kind`]).
    Succession(SuccessorVerdict),
    /// Given, the watchdog this start found first, which took its role
    /// while an agent ran: registered, nothing signed (no High for a
    /// library a package upgrade replaced on disk since, N4).
    Held(SuccessorVerdict),
}

/// The re-check 3 of #582 (R2-1): whether the agent judges the watchdog it
/// verified now, and what it does with the verdict (`judge`, called only
/// when it judges). `pending`: a succession nobody judged yet — a watchdog
/// death this agent saw, the timing rule at its start
/// ([`antitamper_bpf::succession_to_judge`]), or a watchdog refused before;
/// `vacated`: the watchdog's slot vacated now; `found_first`: the watchdog
/// this agent's start found first, judged whatever the timing rule says (an
/// earlier agent's refusal was in its memory only, and a successor it never
/// saw was judged by nobody). A watchdog not given leaves `pending` set:
/// the next round judges it (or whatever process holds the role then)
/// again, never registers it because its slot is no longer vacated.
pub fn successor_step(
    pending: &mut bool,
    vacated: bool,
    found_first: bool,
    judge: impl FnOnce() -> SuccessorVerdict,
) -> SuccessorStep {
    let succession = *pending || vacated;
    if !succession && !found_first {
        return SuccessorStep::NotJudged;
    }
    let mut v = judge();
    v.detail = if succession {
        format!(
            "the watchdog's role vacated, its successor not judged before: {}",
            v.detail
        )
    } else {
        format!(
            "the watchdog found at this agent's start, judged again whatever an earlier agent \
             concluded: {}",
            v.detail
        )
    };
    match antitamper_bpf::at_start(succession, v.given) {
        antitamper_bpf::AtStart::Foreign => {
            *pending = true;
            SuccessorStep::Foreign(v)
        }
        antitamper_bpf::AtStart::Succession => {
            *pending = false;
            SuccessorStep::Succession(v)
        }
        antitamper_bpf::AtStart::Held => SuccessorStep::Held(v),
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

/// What the agent's start read of both roles before it claimed its own:
/// the two `ROLE_TGIDS` slots and (the review of #582, F4 b, F6) the
/// kernel's marks of their holders' exits (`ROLE_MARKS`; `None` unread, or
/// not frozen), and (the re-check, N4) when the agent's role was last left
/// (`ROLE_EXITS`, `CLOCK_BOOTTIME` ns).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RolesAtStart {
    pub agent: u32,
    pub watchdog: u32,
    pub agent_mark: Option<u32>,
    pub watchdog_mark: Option<u32>,
    pub agent_exit_ns: Option<u64>,
}

impl RolesAtStart {
    /// Both roles' holders had exited (neither held now).
    pub fn both_vacated(&self) -> bool {
        use antitamper_bpf::ROLE_VACATED;
        self.agent == ROLE_VACATED && self.watchdog == ROLE_VACATED
    }

    /// Both last exits were inside a signed trusted-installer window (the
    /// operator's maintenance stop), as the kernel marked them.
    pub fn both_left_in_a_window(&self) -> bool {
        let w = |m: Option<u32>| m.is_some_and(|m| m & antitamper_bpf::ROLE_MARK_IN_WINDOW != 0);
        w(self.agent_mark) && w(self.watchdog_mark)
    }
}

static ROLES_AT_START: std::sync::OnceLock<RolesAtStart> = std::sync::OnceLock::new();

/// Kept once, by the start that read it (the eBPF load).
pub fn note_roles_at_start(r: RolesAtStart) {
    let _ = ROLES_AT_START.set(r);
}

/// What [`note_roles_at_start`] kept.
pub fn roles_at_start() -> Option<RolesAtStart> {
    ROLES_AT_START.get().copied()
}

/// Both roles released by the operator (a note): inside a signed window,
/// or after a shutdown the admin quorum signed.
pub const ROLES_RELEASED: &str = "roles_released";

/// Both roles vacated at the agent's start: the gap's finding — High
/// ([`ROLES_VACATED_GAP`]) unless the operator released both (the review of
/// #582, F4 b): their last exits inside a signed trusted-installer window
/// (the kernel's marks), or the watchdog's chain ending with the agent's
/// role released by a signed shutdown, the watchdog standing down after it
/// (`signed_stop`, [`WitnessReader::ends_with_signed_release`]) — then a
/// note ([`ROLES_RELEASED`]). `None` when not both were vacated.
pub fn roles_gap(r: &RolesAtStart, signed_stop: bool) -> Option<Finding> {
    if !r.both_vacated() {
        return None;
    }
    let why = if r.both_left_in_a_window() {
        Some("both last exits inside a signed trusted-installer window (the operator's stop)")
    } else if signed_stop {
        Some(
            "the watchdog's chain ends with the agent's role released by a shutdown the admin \
             quorum signed, the watchdog standing down after it",
        )
    } else {
        None
    };
    Some(match why {
        Some(why) => Finding {
            kind: ROLES_RELEASED,
            detail: format!("the agent's start found both roles released this boot: {why}"),
        },
        None => Finding {
            kind: ROLES_VACATED_GAP,
            detail: "the agent's start found both roles vacated this boot: the agent and the \
                     watchdog had exited, no role held the other's record of it until now"
                .to_string(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use antitamper_bpf::start_check::{Findings, Identity};
    use nn_proto::witness::{
        line_hash, Row, WitnessKey, KIND_SUCCEEDED, KIND_VACATED, ROW_VERSION,
    };

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
            assert_eq!(v.kind(), WATCHDOG_SUCCESSOR_FOREIGN);
        }
        let v = judge_watchdog_successor(9, &unit(), Some(true), &Findings::default());
        assert!(v.detail.contains("taken by pid 9") && v.detail.contains("marks clean"));
    }

    /// The review of #582 (F3): a watchdog successor that is not its unit's
    /// clean restart is observed, not refused — it holds the role the kernel
    /// gave it and registers itself — and the finding says so
    /// (`watchdog_successor_foreign`).
    #[test]
    fn a_foreign_watchdog_successor_is_recorded_as_holding_the_role_never_as_refused() {
        let v = judge_watchdog_successor(9, &unit(), Some(false), &Findings::default());
        assert!(!v.given);
        assert!(
            v.detail
                .contains("holds the role the kernel gave it and registers itself")
                && v.detail.contains("the agent does not register it"),
            "{}",
            v.detail
        );
        assert!(!v.detail.to_lowercase().contains("refus"), "{}", v.detail);
        assert_eq!(WATCHDOG_SUCCESSOR_FOREIGN, "watchdog_successor_foreign");
        let v = judge_watchdog_successor(9, &unit(), Some(true), &Findings::default());
        assert!(
            v.given && !v.detail.contains("holds the role"),
            "{}",
            v.detail
        );
    }

    /// Lot 374: the watchdog's record of a vacancy, or of a successor that
    /// is not its unit's clean restart, is a row (High); its bookkeeping —
    /// a life's first row, a signed shutdown's release, the unit's clean
    /// restart — a note, as the key's certification and the watchdog's
    /// clean succession.
    #[test]
    fn a_vacancy_or_a_foreign_successor_is_a_row_and_the_bookkeeping_a_note() {
        use nn_proto::witness::{
            KIND_CHAIN_CUT, KIND_FOUND_VACANT, KIND_RESPAWN_HELD, KIND_SUCCESSOR_FOREIGN,
            KIND_SUCCESSOR_UNCONFIRMED, KIND_UNMADE_START,
        };
        for k in [
            KIND_VACATED,
            KIND_FOUND_VACANT,
            KIND_SUCCESSOR_FOREIGN,
            // the review of #582 (F2 c, d): a held respawn, a cut chain
            KIND_RESPAWN_HELD,
            KIND_CHAIN_CUT,
            // the re-check of #582 (N3, N4)
            KIND_UNMADE_START,
            KIND_SUCCESSOR_UNCONFIRMED,
            "a kind of later",
        ] {
            assert_eq!(row_kind(k), WITNESS_ROW, "{k}");
        }
        for k in [
            KIND_OPENED,
            KIND_RELEASED,
            // the review of #582 (F4 a)
            KIND_RELEASED_IN_WINDOW,
            KIND_SUCCEEDED,
            // the re-check of #582 (N2, N6): the gate's reference moved
            // inside a window, the watchdog's own torn append repaired
            KIND_GATE_REFERENCE,
            KIND_CHAIN_TORN,
        ] {
            assert_eq!(row_kind(k), WITNESS_NOTE, "{k}");
        }
        for k in [WITNESS_KEY, WITNESS_NOTE, WATCHDOG_SUCCESSION] {
            assert!(is_note(k), "{k}");
        }
        for k in [
            WITNESS_ROW,
            WITNESS_UNCERTIFIED,
            WITNESS_BROKEN,
            WATCHDOG_SUCCESSOR_FOREIGN,
            ROLES_VACATED_GAP,
        ] {
            assert!(!is_note(k), "{k}");
        }
    }

    fn at_start(agent: u32, watchdog: u32, marks: (Option<u32>, Option<u32>)) -> RolesAtStart {
        RolesAtStart {
            agent,
            watchdog,
            agent_mark: marks.0,
            watchdog_mark: marks.1,
            agent_exit_ns: None,
        }
    }

    #[test]
    fn both_roles_vacated_is_the_gap_and_nothing_else_is() {
        use antitamper_bpf::ROLE_VACATED as V;
        let out = Some(antitamper_bpf::ROLE_MARK_VACATED);
        let gap = roles_gap(&at_start(V, V, (out, out)), false);
        assert_eq!(gap.map(|f| f.kind), Some(ROLES_VACATED_GAP));
        for (a, w) in [(V, 0), (0, V), (V, 42), (42, V), (0, 0)] {
            assert!(
                roles_gap(&at_start(a, w, (out, out)), false).is_none(),
                "{a} {w}"
            );
            assert!(
                roles_gap(&at_start(a, w, (out, out)), true).is_none(),
                "{a} {w}"
            );
        }
    }

    /// The review of #582 (F4 b): both roles released by the operator — the
    /// guide's maintenance stop inside a signed window (both last exits
    /// marked so by the kernel), or a shutdown the admin quorum signed (the
    /// watchdog's chain ends with the agent's role released) — is a note at
    /// the next start in the same boot, never the High gap. One exit
    /// outside a window, or a mark not read, is still the gap.
    #[test]
    fn both_roles_released_by_the_operator_is_a_note_not_the_gap() {
        use antitamper_bpf::{ROLE_MARK_IN_WINDOW as W, ROLE_MARK_VACATED as M, ROLE_VACATED as V};
        let win = Some(M | W);
        let f = roles_gap(&at_start(V, V, (win, win)), false).unwrap();
        assert_eq!(f.kind, ROLES_RELEASED);
        assert!(
            f.detail.contains("signed trusted-installer window"),
            "{}",
            f.detail
        );
        assert!(is_note(f.kind));
        let f = roles_gap(&at_start(V, V, (Some(M), Some(M))), true).unwrap();
        assert_eq!(f.kind, ROLES_RELEASED);
        assert!(f.detail.contains("admin quorum signed"), "{}", f.detail);
        for marks in [(win, Some(M)), (Some(M), win), (win, None), (None, None)] {
            let f = roles_gap(&at_start(V, V, marks), false).unwrap();
            assert_eq!(f.kind, ROLES_VACATED_GAP, "{marks:?}");
            assert!(!is_note(f.kind));
        }
    }

    /// The review of #582 (F4 b): the chain "ends with a signed release" only
    /// when its last valid row is `role_released` signed by a key the agent
    /// certified — a later watchdog life's row after it, a key never
    /// certified, or another kind is not.
    #[test]
    fn only_a_certified_release_as_the_chain_s_last_row_is_a_signed_stop() {
        use nn_proto::witness::{KIND_OPENED, KIND_RELEASED, KIND_VACATED};
        let dir = tempfile::tempdir().unwrap();
        let k = WitnessKey::from_seed([3; 32]);
        // written now (the re-check of #582, N8: this boot's)
        let at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let write = |kinds: &[&str]| {
            let mut text = String::new();
            let mut prev = String::new();
            for (i, kind) in kinds.iter().enumerate() {
                let r = k.sign(Row {
                    v: ROW_VERSION,
                    seq: i as u64,
                    prev: prev.clone(),
                    at,
                    tgid: 7,
                    key: String::new(),
                    kind: kind.to_string(),
                    detail: String::new(),
                    sig: String::new(),
                });
                let line = serde_json::to_string(&r).unwrap();
                prev = line_hash(&line);
                text += &line;
                text.push('\n');
            }
            std::fs::write(dir.path().join(CHAIN_FILE), text).unwrap();
        };
        let reader = |certified: bool| {
            let mut r = WitnessReader::new(dir.path());
            if certified {
                r.position().certify(&k.public_hex());
            }
            r
        };
        write(&[KIND_OPENED, KIND_RELEASED]);
        assert!(reader(true).ends_with_signed_release());
        assert!(!reader(false).ends_with_signed_release());
        // the re-check of #582 (N8): a release written before this boot (a
        // chain the watchdog did not continue this boot) is not this boot's
        assert!(reader(true).ends_with_signed_release_since(at));
        assert!(!reader(true).ends_with_signed_release_since(at + 1));
        write(&[KIND_OPENED, KIND_RELEASED, KIND_OPENED]);
        assert!(!reader(true).ends_with_signed_release());
        write(&[KIND_OPENED, KIND_VACATED]);
        assert!(!reader(true).ends_with_signed_release());
        std::fs::remove_file(dir.path().join(CHAIN_FILE)).unwrap();
        assert!(!reader(true).ends_with_signed_release());
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
            let s =
                libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
            // SAFETY: fcntl on a descriptor we hold.
            assert_eq!(
                unsafe { libc::fcntl(f.as_raw_fd(), libc::F_ADD_SEALS, s) },
                0
            );
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
            (
                nn_proto::witness::key_record(me + 1, start, &key),
                true,
                "names pid",
            ),
            (
                nn_proto::witness::key_record(me, start + 1, &key),
                true,
                "names pid",
            ),
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

    /// Lot 374: a line that breaks the chain after the last row imported
    /// is said on its own (the position still found: nothing is imported
    /// again).
    #[test]
    fn a_break_after_the_imported_rows_is_said() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(IMPORTED_FILE), b"").unwrap();
        let k = WitnessKey::from_seed([5; 32]);
        write_chain(dir.path(), &k, &[KIND_OPENED, KIND_VACATED]);
        let mut r = WitnessReader::new(dir.path());
        r.position().certify(&k.public_hex());
        let (f, last) = r.pending();
        assert_eq!(f.len(), 2, "{f:?}");
        r.commit(last);
        let mut text = std::fs::read_to_string(dir.path().join(CHAIN_FILE)).unwrap();
        text.push_str("not a row\n");
        std::fs::write(dir.path().join(CHAIN_FILE), text).unwrap();
        let (f, last) = r.pending();
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].kind, WITNESS_BROKEN);
        assert!(f[0].detail.contains("line 3"), "{}", f[0].detail);
        assert!(last.is_none());
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
            vec![WITNESS_NOTE, WITNESS_ROW, WITNESS_NOTE]
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

    /// The re-check of #582 (N6): the chain rotated (the watchdog moved it
    /// to `witness.chain.1` when full, at its start or within its life):
    /// the import goes on in the moved chain after the last row imported,
    /// then the new chain from its first row — every row once, and a
    /// rotation is not a broken chain. A chain cut (no rotated chain holds
    /// the position) still is.
    #[test]
    fn an_import_continues_through_a_rotated_chain() {
        use nn_proto::witness::{KIND_OPENED, KIND_SUCCEEDED, KIND_VACATED};
        let dir = tempfile::tempdir().unwrap();
        let k = WitnessKey::from_seed([5; 32]);
        write_chain(dir.path(), &k, &[KIND_OPENED, KIND_VACATED]);
        let mut r = WitnessReader::new(dir.path());
        r.position().certify(&k.public_hex());
        let (f, last) = r.pending();
        assert_eq!(f.len(), 2);
        r.commit(last);
        // a row more, then rotated: the old chain moved aside whole
        write_chain(dir.path(), &k, &[KIND_OPENED, KIND_VACATED, KIND_SUCCEEDED]);
        std::fs::rename(
            dir.path().join(CHAIN_FILE),
            dir.path().join(format!("{CHAIN_FILE}.1")),
        )
        .unwrap();
        write_chain(dir.path(), &k, &[KIND_SUCCEEDED, KIND_VACATED]);
        let (f, last) = r.pending();
        assert!(!f.iter().any(|x| x.kind == WITNESS_BROKEN), "{f:?}");
        assert_eq!(
            f.iter().map(|x| x.kind).collect::<Vec<_>>(),
            vec![WITNESS_NOTE, WITNESS_NOTE, WITNESS_ROW],
            "the moved chain's last row, then the new chain's two"
        );
        r.commit(last);
        assert!(r.pending().0.is_empty());
        // no rotated chain holds the position: broken, as before
        let other = WitnessKey::from_seed([6; 32]);
        write_chain(dir.path(), &other, &[KIND_OPENED]);
        std::fs::remove_file(dir.path().join(format!("{CHAIN_FILE}.1"))).unwrap();
        let (f, _) = r.pending();
        assert!(f.iter().any(|x| x.kind == WITNESS_BROKEN), "{f:?}");
    }

    /// The re-check of #582 (N4): the watchdog's clean successor whose
    /// library was replaced on disk since it mapped it, and is not the
    /// agent's own copy, is registered (never withheld for that alone) and
    /// signed High; a foreign one is still foreign.
    #[test]
    fn a_watchdog_successor_with_an_unconfirmed_library_is_registered_and_high() {
        let replaced = Findings {
            replaced: vec!["/usr/lib/x86_64-linux-gnu/libc.so.6".into()],
            ..Findings::default()
        };
        let v = judge_watchdog_successor(9, &unit(), Some(true), &replaced);
        assert!(v.given, "{}", v.detail);
        assert!(!v.confirmed);
        assert_eq!(v.kind(), WATCHDOG_SUCCESSOR_UNCONFIRMED);
        assert!(!is_note(v.kind()));
        assert!(v.detail.contains("identity not confirmed"), "{}", v.detail);
        let v = judge_watchdog_successor(9, &unit(), Some(true), &Findings::default());
        assert_eq!(
            (v.given, v.confirmed, v.kind()),
            (true, true, WATCHDOG_SUCCESSION)
        );
        let v = judge_watchdog_successor(9, &unit(), Some(false), &replaced);
        assert_eq!((v.given, v.kind()), (false, WATCHDOG_SUCCESSOR_FOREIGN));
    }
    fn foreign() -> SuccessorVerdict {
        judge_watchdog_successor(9, &unit(), Some(false), &Findings::default())
    }

    /// The re-check 3 of #582 (R2-1, scenario A; the reviewer's probe): a
    /// watchdog that took its role at 100 s, judged foreign by agent A1 and
    /// not registered for A1's whole life; A1 exits at 1000 s. The timing
    /// rule says an agent was there when it took its role — A2's start
    /// judges it all the same: refused and signed, and refused again at
    /// every later round, never registered on A1's word.
    #[test]
    fn a_watchdog_an_earlier_agent_refused_is_refused_again_at_the_next_agent_start() {
        const S: u64 = 1_000_000_000;
        let v = Some(antitamper_bpf::ROLE_MARK_VACATED);
        let timing = antitamper_bpf::succession_to_judge(v, v, Some(1_000 * S), Some(100 * S));
        assert_eq!(timing, None, "the probe: no succession by timing");
        let mut pending = timing.is_some();
        match successor_step(&mut pending, false, true, foreign) {
            SuccessorStep::Foreign(v) => {
                assert_eq!(v.kind(), WATCHDOG_SUCCESSOR_FOREIGN);
                assert!(
                    v.detail
                        .contains("judged again whatever an earlier agent concluded")
                        && !v.detail.contains("vacated"),
                    "{}",
                    v.detail
                );
            }
            s => panic!("A2's start registers the refused watchdog: {s:?}"),
        }
        assert!(pending);
        for _ in 0..3 {
            assert!(matches!(
                successor_step(&mut pending, false, false, foreign),
                SuccessorStep::Foreign(_)
            ));
        }
    }

    /// The re-check 3 of #582 (R2-1, scenario B): a successor that took the
    /// watchdog's role while agent A1 ran but that A1 never judged (no
    /// pidfile until A1 exited, or a stalled round): nothing pending, the
    /// slot held — the next agent's start judges it, and does not register
    /// it when it is not its unit's clean restart.
    #[test]
    fn a_watchdog_successor_no_agent_judged_is_judged_at_the_next_agent_start() {
        for found in [
            Findings {
                loader_vars: vec!["LD_PRELOAD".into()],
                ..Findings::default()
            },
            Findings {
                unreadable: vec!["environ: gone".into()],
                ..Findings::default()
            },
        ] {
            let judged = std::cell::Cell::new(0);
            let mut pending = false;
            let step = successor_step(&mut pending, false, true, || {
                judged.set(judged.get() + 1);
                judge_watchdog_successor(9, &unit(), Some(true), &found)
            });
            assert_eq!(judged.get(), 1);
            assert!(matches!(step, SuccessorStep::Foreign(_)), "{step:?}");
            assert!(pending);
        }
        // outside a start, nothing pending, the slot held: not judged
        let mut pending = false;
        assert_eq!(
            successor_step(&mut pending, false, false, || unreachable!()),
            SuccessorStep::NotJudged
        );
    }

    /// The re-check 3 of #582 (R2-1, N4 kept): the watchdog an agent's
    /// start finds, long-running and given — its library replaced on disk
    /// since it mapped it, not the agent's copy — is registered with
    /// nothing signed (no false High), and not judged again; a successor
    /// nobody judged with the same verdict is still signed High.
    #[test]
    fn a_long_running_watchdog_given_at_an_agent_start_is_registered_with_nothing_signed() {
        let replaced = Findings {
            replaced: vec!["/usr/lib/x86_64-linux-gnu/libgcc_s.so.1".into()],
            ..Findings::default()
        };
        let unconfirmed = || judge_watchdog_successor(9, &unit(), Some(true), &replaced);
        let mut pending = false;
        match successor_step(&mut pending, false, true, unconfirmed) {
            SuccessorStep::Held(v) => assert!(v.given && !v.confirmed, "{}", v.detail),
            s => panic!("{s:?}"),
        }
        assert!(!pending);
        assert_eq!(
            successor_step(&mut pending, false, false, || unreachable!()),
            SuccessorStep::NotJudged
        );
        let mut pending = false;
        assert!(matches!(
            successor_step(&mut pending, false, true, || judge_watchdog_successor(
                9,
                &unit(),
                Some(true),
                &Findings::default()
            )),
            SuccessorStep::Held(_)
        ));
        // a succession nobody judged (the timing rule, a death seen, the
        // slot vacated): the verdict signed, High when not confirmed
        for (mut pending, vacated) in [(true, false), (false, true), (true, true)] {
            match successor_step(&mut pending, vacated, false, unconfirmed) {
                SuccessorStep::Succession(v) => {
                    assert_eq!(v.kind(), WATCHDOG_SUCCESSOR_UNCONFIRMED);
                    assert!(v.detail.contains("vacated"), "{}", v.detail);
                }
                s => panic!("{s:?}"),
            }
            assert!(!pending);
        }
    }

    /// The re-check 3 of #582 (R2-1, the mini-hunt): a watchdog refused
    /// while its slot was vacated (before it claimed its role) is judged
    /// again at the next round, when its slot holds its tgid — never
    /// registered because the slot is no longer vacated; once a given
    /// process holds the role, it is signed as a succession.
    #[test]
    fn a_watchdog_refused_while_its_slot_was_vacated_is_judged_again_once_it_holds_the_slot() {
        let mut pending = false;
        assert!(matches!(
            successor_step(&mut pending, true, false, foreign),
            SuccessorStep::Foreign(_)
        ));
        assert!(matches!(
            successor_step(&mut pending, false, false, foreign),
            SuccessorStep::Foreign(_)
        ));
        let given = || judge_watchdog_successor(9, &unit(), Some(true), &Findings::default());
        match successor_step(&mut pending, false, false, given) {
            SuccessorStep::Succession(v) => assert_eq!(v.kind(), WATCHDOG_SUCCESSION),
            s => panic!("{s:?}"),
        }
        assert!(!pending);
    }
}
