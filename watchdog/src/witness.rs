//! Lot 374: the watchdog as the agent's witness.
//!
//! When the agent dies and a process takes its role, the record must not be
//! the successor's own: a successor running injected code writes what it
//! likes. The watchdog, the surviving role, signs it in a chain of its own
//! ([`nn_proto::witness`]): the vacancy and its cause, as systemd or the
//! wait on the agent reports it, then the successor — its pid, its parent,
//! its cgroup, whether it is its unit's restart, and what its environment
//! and executable mappings show (`antitamper_bpf::start_check`).
//!
//! The key is the watchdog's for its life: made from the kernel's random
//! bytes at its start, kept in its memory (the process is not dumpable and
//! its `ptrace` is refused), its public half in a sealed memory file of its
//! own that the agent certifies. The chain is in the agent's state
//! directory, which the deny hooks keep from every process outside the
//! family. Each row is also a journal line.

use std::os::fd::{FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use nn_proto::witness::{
    judge_chain, key_record, line_hash, Judged, Row, WitnessKey, CHAIN_FILE, CHAIN_MAX_BYTES,
    KEY_MEMFD_NAME, KIND_OPENED, ROW_VERSION,
};
use tracing::{error, info, warn};

/// The chain is moved aside (`witness.chain.1`) and a new one opened past
/// this size; the new one's first row names the old one's head.
pub const ROTATE_BYTES: u64 = CHAIN_MAX_BYTES / 2;

/// The watchdog's witness: its key, its chain and where it is in it.
pub struct Witness {
    key: WitnessKey,
    path: PathBuf,
    seq: u64,
    prev: String,
    tgid: u32,
    /// The sealed memory file with the key's public half, held for the
    /// watchdog's life (the agent reads it from this descriptor table).
    _published: Option<OwnedFd>,
}

/// 32 bytes from the kernel's random source (`getrandom(2)`, blocking
/// until it is seeded).
fn seed() -> Result<[u8; 32]> {
    let mut b = [0u8; 32];
    let mut got = 0usize;
    while got < b.len() {
        // SAFETY: writes at most the rest of `b`, which we own.
        let n = unsafe { libc::getrandom(b[got..].as_mut_ptr().cast(), b.len() - got, 0) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(anyhow!("getrandom: {e}"));
        }
        got += n as usize;
    }
    Ok(b)
}

/// The key's public half in a sealed memory file ([`KEY_MEMFD_NAME`]):
/// written once, then sealed against any write, resize or new seal.
fn publish(record: &str) -> Result<OwnedFd> {
    use std::io::Write;
    let name = std::ffi::CString::new(KEY_MEMFD_NAME).expect("no NUL");
    // SAFETY: a NUL-terminated name; the flags are memfd_create's.
    let fd =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    if fd < 0 {
        return Err(anyhow!("memfd_create: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: a new descriptor this call alone owns.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut f = std::fs::File::from(owned);
    f.write_all(record.as_bytes())
        .context("writing the key record")?;
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    // SAFETY: fcntl on a descriptor we hold.
    if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } < 0 {
        return Err(anyhow!(
            "sealing the key record: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(OwnedFd::from(f))
}

/// Where an existing chain at `path` ends: `(next seq, its last line's
/// hash)`, or why it cannot be continued.
fn chain_end(text: &str) -> std::result::Result<(u64, String), String> {
    let mut end = (0u64, String::new());
    for j in judge_chain(text) {
        match j {
            Judged::Valid { row, hash } => end = (row.seq + 1, hash),
            Judged::Broken { line, why } => return Err(format!("line {line}: {why}")),
        }
    }
    Ok(end)
}

impl Witness {
    /// The witness of this watchdog (`tgid`) in `dir`: a new key, published,
    /// and the chain continued (or moved aside and opened anew when it is
    /// broken or full) with a [`KIND_OPENED`] row. `Err` when no row can be
    /// written there: the caller records that for the agent to sign.
    pub fn open(dir: &Path, tgid: u32) -> Result<Witness> {
        let key = WitnessKey::from_seed(seed()?);
        let start = antitamper_bpf::start_check::start_ticks(tgid).unwrap_or(0);
        let published = match publish(&key_record(tgid, start, &key.public_hex())) {
            Ok(fd) => Some(fd),
            Err(e) => {
                warn!(target: "watchdog.witness", error = %e, "the witness key is not published: the agent cannot certify it");
                None
            }
        };
        let path = dir.join(CHAIN_FILE);
        let mut notes = Vec::new();
        let (seq, prev) = match std::fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (0, String::new()),
            Err(e) => return Err(anyhow!("{}: {e}", path.display())),
            Ok(m) if !m.is_file() => {
                return Err(anyhow!("{} is not a regular file", path.display()));
            }
            Ok(m) => {
                let text = antitamper_bpf::kernel_roots::read(&path, CHAIN_MAX_BYTES)
                    .map(|b| String::from_utf8_lossy(&b).into_owned());
                let end = match &text {
                    Ok(t) => chain_end(t),
                    Err(e) => Err(format!("unreadable: {e}")),
                };
                match end {
                    Ok((seq, prev)) if m.len() < ROTATE_BYTES => {
                        if seq > 0 {
                            notes.push(format!(
                                "continues row {} ({})",
                                seq - 1,
                                prev.get(..16).unwrap_or("")
                            ));
                        }
                        (seq, prev)
                    }
                    other => {
                        let aside = dir.join(format!("{CHAIN_FILE}.1"));
                        std::fs::rename(&path, &aside)
                            .with_context(|| format!("moving {} aside", path.display()))?;
                        match other {
                            Ok((seq, prev)) => notes.push(format!(
                                "the previous chain, full, ends at row {} ({}), kept as {}",
                                seq.saturating_sub(1),
                                prev.get(..16).unwrap_or(""),
                                aside.display()
                            )),
                            Err(why) => notes.push(format!(
                                "the previous chain is broken ({why}), kept as {}",
                                aside.display()
                            )),
                        }
                        (0, String::new())
                    }
                }
            }
        };
        let mut w = Witness {
            key,
            path,
            seq,
            prev,
            tgid,
            _published: published,
        };
        let detail = if notes.is_empty() {
            "a new chain".to_string()
        } else {
            notes.join("; ")
        };
        w.record(
            KIND_OPENED,
            &format!("watchdog {tgid} (start {start}) opened its witness: {detail}"),
        )?;
        Ok(w)
    }

    /// The key's public half (hex).
    pub fn key_hex(&self) -> String {
        self.key.public_hex()
    }

    /// One signed row of `kind` with `detail`, appended and logged.
    pub fn record(&mut self, kind: &str, detail: &str) -> Result<()> {
        let row = self.key.sign(Row {
            v: ROW_VERSION,
            seq: self.seq,
            prev: self.prev.clone(),
            at: crate::unix_now(),
            tgid: self.tgid,
            key: String::new(),
            kind: kind.to_string(),
            detail: detail.chars().take(1500).collect(),
            sig: String::new(),
        });
        let line = serde_json::to_string(&row).context("serialising the witness row")?;
        crate::append_line(&self.path, &format!("{line}\n"))
            .with_context(|| format!("appending to {}", self.path.display()))?;
        info!(target: "watchdog.witness", row = %line, "witness row signed");
        self.prev = line_hash(&line);
        self.seq += 1;
        Ok(())
    }

    /// [`Witness::record`], its failure an ERROR (and `false`): the row is
    /// then only the journal's.
    pub fn record_or_log(&mut self, kind: &str, detail: &str) -> bool {
        match self.record(kind, detail) {
            Ok(()) => true,
            Err(e) => {
                error!(
                    target: "watchdog.witness",
                    error = format!("{e:#}"),
                    kind,
                    detail,
                    "witness row NOT written"
                );
                false
            }
        }
    }
}

/// Why the agent exited, from `systemctl show`'s `Result=`, `ExecMainCode=`
/// and `ExecMainStatus=` (`None` when it says nothing yet).
pub fn cause_from_show(show: &str) -> Option<String> {
    let get = |k: &str| {
        show.lines()
            .find_map(|l| l.trim().strip_prefix(k).and_then(|v| v.strip_prefix('=')))
    };
    let result = get("Result")?;
    let code = get("ExecMainCode").unwrap_or("");
    let status = get("ExecMainStatus").unwrap_or("");
    let how = match code {
        "1" => format!("exit status {status}"),
        "2" => format!("signal {status}"),
        "3" => format!("signal {status}, core dumped"),
        _ => format!("exit code {code}, status {status}"),
    };
    Some(match result {
        "oom-kill" => format!("the OOM killer (systemd Result=oom-kill; {how})"),
        r => format!("{how} (systemd Result={r})"),
    })
}

/// How long [`unit_exit_cause`] waits for systemd to have recorded the
/// agent's exit (the watchdog's pidfd can see it first).
pub const EXIT_CAUSE_WAIT: std::time::Duration = std::time::Duration::from_secs(3);

/// What `systemctl show` says of the agent `pid`'s exit: `Some` once its
/// unit recorded that process's exit (`ExecMainPID=` is `pid`,
/// `ExecMainCode=` set) and left the active states — the cause
/// ([`cause_from_show`]) — or once its unit has started another process
/// since (then the cause is not known); `None` while neither holds yet.
pub fn exit_from_show(show: &str, pid: u32) -> Option<String> {
    let get = |k: &str| {
        show.lines()
            .find_map(|l| l.trim().strip_prefix(k).and_then(|v| v.strip_prefix('=')))
    };
    let main: u32 = get("ExecMainPID").and_then(|v| v.parse().ok()).unwrap_or(0);
    if main != 0 && main != pid {
        return Some(format!(
            "not known (systemd started another process of the unit since, pid {main})"
        ));
    }
    let code = get("ExecMainCode").unwrap_or("0");
    let settled = matches!(get("ActiveState"), Some("failed" | "inactive"));
    if main != pid || code == "0" || !settled {
        return None;
    }
    cause_from_show(show)
}

/// Why the agent `pid` of unit `unit` ended, as systemd recorded it
/// ([`exit_from_show`]), asked until it did or [`EXIT_CAUSE_WAIT`]
/// passed. Blocking: call off the runtime.
pub fn unit_exit_cause(unit: &str, pid: u32) -> Option<String> {
    let systemctl = crate::find_systemctl()?;
    let deadline = std::time::Instant::now() + EXIT_CAUSE_WAIT;
    loop {
        let out = std::process::Command::new(&systemctl)
            .arg("show")
            .arg("--property=ActiveState,ExecMainPID,Result,ExecMainCode,ExecMainStatus")
            .arg(unit)
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        if let Some(c) = exit_from_show(&text, pid) {
            return Some(c);
        }
        if std::time::Instant::now() >= deadline {
            return Some(format!(
                "not known (systemd had not recorded the exit of pid {pid} within {} s)",
                EXIT_CAUSE_WAIT.as_secs()
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// The vacancy row's detail: the agent `pid` gone, `cause` (the wait's or
/// systemd's), and what its shutdown marker said — an authorised stop is
/// one too, and says so.
pub fn vacancy_detail(pid: u32, cause: &str, verdict: &crate::ShutdownVerdict) -> String {
    let marker = match verdict {
        crate::ShutdownVerdict::Absent => "no shutdown marker",
        crate::ShutdownVerdict::Authorised => {
            "a shutdown the admin quorum signed: no successor follows"
        }
        crate::ShutdownVerdict::Refused(_) => {
            "a shutdown marker refused (not signed by the admin quorum for this agent)"
        }
    };
    format!("the agent (pid {pid}) exited, its role vacated: {cause}; {marker}")
}

/// Why the agent exited, from the wait on the exec backend's child
/// (`si_code`: `CLD_EXITED`, `CLD_KILLED`, `CLD_DUMPED`).
pub fn cause_from_wait(si_code: i32, code: i32) -> String {
    match si_code {
        libc::CLD_EXITED => format!("exit status {code}"),
        libc::CLD_KILLED => format!("signal {code}"),
        libc::CLD_DUMPED => format!("signal {code}, core dumped"),
        other => format!("si_code {other}, status {code}"),
    }
}

/// The successor's record: where it was started and what it shows, and
/// whether it is the restart of the agent's unit with nothing foreign
/// (the watchdog gives the role's rights only to that one).
pub fn successor_detail(
    old: u32,
    new: u32,
    id: &antitamper_bpf::start_check::Identity,
    found: &antitamper_bpf::start_check::Findings,
) -> (bool, String) {
    let in_unit = id.in_unit(antitamper_bpf::start_check::AGENT_UNIT);
    let ok = in_unit && found.clean();
    let verdict = match (in_unit, found.clean()) {
        (true, true) => "its unit's restart, nothing foreign in it",
        (false, _) => "NOT its unit's restart (not PID 1's child in the agent's own cgroup)",
        (true, false) => "its unit's restart, with something foreign in it",
    };
    (
        ok,
        format!(
            "the agent's role, vacated by pid {old}, taken by pid {new}: {verdict}; {}; {}",
            id.describe(),
            found.describe()
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use antitamper_bpf::start_check::{Findings, Foreign, Identity};

    fn show(state: &str, main: u32, result: &str, code: u8, status: i32) -> String {
        format!(
            "ActiveState={state}\nExecMainPID={main}\nResult={result}\nExecMainCode={code}\nExecMainStatus={status}\n"
        )
    }

    #[test]
    fn the_cause_names_the_oom_killer_a_signal_or_an_exit() {
        let c = cause_from_show(&show("failed", 7, "oom-kill", 2, 9)).unwrap();
        assert!(
            c.starts_with("the OOM killer") && c.contains("signal 9"),
            "{c}"
        );
        assert_eq!(
            cause_from_show(&show("failed", 7, "signal", 2, 11)).unwrap(),
            "signal 11 (systemd Result=signal)"
        );
        assert_eq!(
            cause_from_show(&show("failed", 7, "exit-code", 1, 78)).unwrap(),
            "exit status 78 (systemd Result=exit-code)"
        );
        assert_eq!(cause_from_show("ActiveState=active\n"), None);
        assert_eq!(cause_from_wait(libc::CLD_KILLED, 9), "signal 9");
        assert_eq!(cause_from_wait(libc::CLD_EXITED, 0), "exit status 0");
        assert_eq!(
            cause_from_wait(libc::CLD_DUMPED, 6),
            "signal 6, core dumped"
        );
    }

    /// Lot 374: systemd's record is the dead agent's only once it names
    /// that process and the unit left the active states; a record of
    /// another process is never given as its cause.
    #[test]
    fn the_exit_is_read_only_from_systemd_s_record_of_that_process() {
        // not recorded yet: the unit still active, or the exit not seen
        assert_eq!(exit_from_show(&show("active", 7, "success", 0, 0), 7), None);
        assert_eq!(
            exit_from_show(&show("deactivating", 7, "signal", 2, 9), 7),
            None
        );
        assert_eq!(exit_from_show(&show("failed", 7, "success", 0, 0), 7), None);
        assert_eq!(exit_from_show(&show("failed", 0, "success", 0, 0), 7), None);
        // recorded
        let c = exit_from_show(&show("failed", 7, "oom-kill", 2, 9), 7).unwrap();
        assert!(c.starts_with("the OOM killer"), "{c}");
        let c = exit_from_show(&show("inactive", 7, "success", 1, 0), 7).unwrap();
        assert_eq!(c, "exit status 0 (systemd Result=success)");
        // another process of the unit since: its status is not the cause
        let c = exit_from_show(&show("active", 8, "success", 0, 0), 7).unwrap();
        assert!(c.starts_with("not known") && c.contains("pid 8"), "{c}");
        let c = exit_from_show(&show("failed", 8, "signal", 2, 9), 7).unwrap();
        assert!(!c.contains("signal 9"), "{c}");
    }

    #[test]
    fn the_vacancy_names_the_agent_its_cause_and_the_marker() {
        let d = vacancy_detail(
            41,
            "signal 9 (systemd Result=signal)",
            &crate::ShutdownVerdict::Absent,
        );
        assert_eq!(
            d,
            "the agent (pid 41) exited, its role vacated: signal 9 (systemd Result=signal); no shutdown marker"
        );
        let d = vacancy_detail(41, "exit status 0", &crate::ShutdownVerdict::Authorised);
        assert!(
            d.ends_with("a shutdown the admin quorum signed: no successor follows"),
            "{d}"
        );
        let d = vacancy_detail(
            41,
            "exit status 0",
            &crate::ShutdownVerdict::Refused("x".into()),
        );
        assert!(d.contains("a shutdown marker refused"), "{d}");
    }

    fn chain_text(dir: &Path) -> String {
        std::fs::read_to_string(dir.join(CHAIN_FILE)).unwrap()
    }

    /// Lot 374 (the witness record when the agent dies): the watchdog's
    /// own rows — the vacancy, then its successor — signed by its key and
    /// linked, so the agent imports them as the watchdog's, whatever the
    /// successor writes or leaves out.
    #[test]
    fn the_witness_signs_the_vacancy_and_the_successor_in_one_chain() {
        use nn_proto::witness::{to_import, Imported, KIND_SUCCEEDED, KIND_VACATED};
        let dir = tempfile::tempdir().unwrap();
        let me = std::process::id();
        let mut w = Witness::open(dir.path(), me).unwrap();
        w.record(
            KIND_VACATED,
            "the agent (pid 10) exited, its role vacated: signal 9",
        )
        .unwrap();
        w.record(
            KIND_SUCCEEDED,
            "the agent's role, vacated by pid 10, taken by pid 11",
        )
        .unwrap();
        let text = chain_text(dir.path());
        let mut imp = Imported::default();
        imp.certify(&w.key_hex());
        let t = to_import(&text, &imp);
        assert!(t.broken.is_none() && !t.position_lost, "{t:?}");
        let kinds: Vec<&str> = t.rows.iter().map(|(r, _, _)| r.kind.as_str()).collect();
        assert_eq!(kinds, [KIND_OPENED, KIND_VACATED, KIND_SUCCEEDED]);
        assert!(t
            .rows
            .iter()
            .all(|(r, _, ok)| *ok && r.tgid == me && r.key == w.key_hex()));
        assert!(t.rows[1].0.detail.contains("signal 9"));
        // another key's rows are the claim of a key no agent certified
        let other = Imported::default();
        assert!(to_import(&text, &other).rows.iter().all(|(_, _, ok)| !ok));
    }

    /// Lot 374: a watchdog's next life continues the chain with a key of
    /// its own (never the last one's: it was never on disk).
    #[test]
    fn a_new_life_continues_the_chain_with_a_new_key() {
        let dir = tempfile::tempdir().unwrap();
        let me = std::process::id();
        let first = Witness::open(dir.path(), me).unwrap().key_hex();
        let mut second = Witness::open(dir.path(), me).unwrap();
        second.record(nn_proto::witness::KIND_VACATED, "d").unwrap();
        assert_ne!(first, second.key_hex());
        let j = judge_chain(&chain_text(dir.path()));
        assert_eq!(j.len(), 3, "{j:?}");
        let Judged::Valid { row, .. } = &j[1] else {
            panic!("{j:?}")
        };
        assert_eq!((row.seq, row.kind.as_str()), (1, KIND_OPENED));
        assert!(row.detail.contains("continues row 0"), "{}", row.detail);
        assert!(j.iter().all(|x| matches!(x, Judged::Valid { .. })));
    }

    /// Lot 374: a chain changed under the watchdog is not continued (its
    /// next row would vouch for it): kept aside, said in the new chain's
    /// first row.
    #[test]
    fn a_broken_chain_is_kept_aside_and_a_new_one_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let me = std::process::id();
        let mut w = Witness::open(dir.path(), me).unwrap();
        w.record(nn_proto::witness::KIND_VACATED, "row 1").unwrap();
        let text = chain_text(dir.path()).replace("row 1", "row X");
        std::fs::write(dir.path().join(CHAIN_FILE), &text).unwrap();
        Witness::open(dir.path(), me).unwrap();
        let aside = dir.path().join(format!("{CHAIN_FILE}.1"));
        assert_eq!(std::fs::read_to_string(aside).unwrap(), text);
        let j = judge_chain(&chain_text(dir.path()));
        assert_eq!(j.len(), 1, "{j:?}");
        let Judged::Valid { row, .. } = &j[0] else {
            panic!("{j:?}")
        };
        assert_eq!(row.seq, 0);
        assert!(
            row.detail.contains("the previous chain is broken (line 2"),
            "{}",
            row.detail
        );
        // a chain that is not a file is not written over
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(CHAIN_FILE)).unwrap();
        assert!(Witness::open(dir.path(), me).is_err());
    }

    /// Lot 374: the key's public half is published in a sealed memory file
    /// of this process's, naming this process and its start — what the
    /// agent reads from the watchdog's descriptor table.
    #[test]
    fn the_key_is_published_in_a_sealed_memory_file_of_its_own() {
        let dir = tempfile::tempdir().unwrap();
        let me = std::process::id();
        let w = Witness::open(dir.path(), me).unwrap();
        let want = format!("/memfd:{KEY_MEMFD_NAME}");
        let mut found = 0;
        for e in std::fs::read_dir("/proc/self/fd").unwrap() {
            let p = e.unwrap().path();
            let Ok(link) = std::fs::read_link(&p) else {
                continue;
            };
            if !link.to_string_lossy().starts_with(&want) {
                continue;
            }
            let f = std::fs::File::open(&p).unwrap();
            let seals =
                unsafe { libc::fcntl(std::os::fd::AsRawFd::as_raw_fd(&f), libc::F_GET_SEALS) };
            let need =
                libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
            if seals & need != need {
                continue; // another test's witness, not sealed yet
            }
            let body = std::fs::read_to_string(&p).unwrap();
            let (tgid, start, key) = nn_proto::witness::parse_key_record(&body).unwrap();
            if key == w.key_hex() {
                assert_eq!(tgid, me);
                assert_eq!(Some(start), antitamper_bpf::start_check::start_ticks(me));
                found += 1;
            }
        }
        assert_eq!(found, 1);
    }

    #[test]
    fn only_the_unit_s_restart_with_nothing_foreign_is_given_the_role() {
        let unit = Identity {
            ppid: Some(1),
            cgroup: Some("/northnarrow.slice/northnarrow-agent.service".into()),
        };
        let (ok, d) = successor_detail(10, 11, &unit, &Findings::default());
        assert!(ok, "{d}");
        assert!(d.contains("vacated by pid 10, taken by pid 11"), "{d}");
        let shell = Identity {
            ppid: Some(4242),
            cgroup: Some("/user.slice/session-1.scope".into()),
        };
        let (ok, d) = successor_detail(10, 11, &shell, &Findings::default());
        assert!(!ok && d.contains("NOT its unit's restart"), "{d}");
        let preloaded = Findings {
            loader_vars: vec!["LD_PRELOAD".into()],
            foreign: vec![Foreign {
                path: "/tmp/x.so".into(),
                why: "not in a system library directory",
            }],
            unreadable: vec![],
        };
        let (ok, d) = successor_detail(10, 11, &unit, &preloaded);
        assert!(
            !ok && d.contains("something foreign") && d.contains("/tmp/x.so"),
            "{d}"
        );
        let unread = Findings {
            unreadable: vec!["maps: denied".into()],
            ..Findings::default()
        };
        assert!(
            !successor_detail(10, 11, &unit, &unread).0,
            "unread is never clean"
        );
    }

    #[test]
    fn a_chain_is_continued_where_it_ends_or_refused_where_it_breaks() {
        let k = WitnessKey::from_seed([9; 32]);
        let mut text = String::new();
        let mut prev = String::new();
        for seq in 0..3 {
            let r = k.sign(Row {
                v: ROW_VERSION,
                seq,
                prev: prev.clone(),
                at: 1,
                tgid: 5,
                key: String::new(),
                kind: KIND_OPENED.into(),
                detail: "d".into(),
                sig: String::new(),
            });
            let l = serde_json::to_string(&r).unwrap();
            prev = line_hash(&l);
            text.push_str(&l);
            text.push('\n');
        }
        assert_eq!(chain_end(&text), Ok((3, prev)));
        assert_eq!(chain_end(""), Ok((0, String::new())));
        assert!(chain_end(&format!("{text}garbage\n"))
            .unwrap_err()
            .contains("line 4"));
    }
}
