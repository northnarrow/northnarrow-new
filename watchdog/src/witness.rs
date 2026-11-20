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
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use nn_proto::witness::{
    judge_chain, key_record, line_hash, Judged, Row, WitnessKey, CHAIN_FILE, CHAIN_MAX_BYTES,
    KEY_MEMFD_NAME, KIND_CHAIN_CUT, KIND_CHAIN_TORN, KIND_OPENED, ROW_VERSION,
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
    /// The re-check of #582 (N6): the chain's length after this life's last
    /// whole row (where a torn append is cut back to).
    len: u64,
    /// The re-check of #582 (N6): the text of an append that failed, and
    /// why — its partial row, if one was left, is this watchdog's own.
    tried: Option<(String, String)>,
    /// The re-check of #582 (N6): rows not written when they were due (a
    /// chain cut's, with the disk full), written before the next one.
    pending: Vec<(String, String)>,
    /// The re-check of #582 (N5): why the chain this life writes is not
    /// registered as the watchdog role's alone, said once in a row.
    unprotected: Option<String>,
    tgid: u32,
    /// The review of #582 (F2 c): the pin root each chain this life opens
    /// is registered under (the watchdog role's alone), once known.
    bpffs_root: Option<PathBuf>,
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
        Self::open_noting(dir, tgid, "")
    }

    /// [`Witness::open`], `note` added to its first row (the review of #582,
    /// F2 d: the host the watchdog's later judgements compare with, signed
    /// before any vacancy it sees).
    pub fn open_noting(dir: &Path, tgid: u32, note: &str) -> Result<Witness> {
        let key = WitnessKey::from_seed(seed()?);
        // this process's own start (`tgid` is this process)
        let start = antitamper_bpf::start_check::own_start_ticks().unwrap_or(0);
        let published = match publish(&key_record(tgid, start, &key.public_hex())) {
            Ok(fd) => Some(fd),
            Err(e) => {
                warn!(target: "watchdog.witness", error = %e, "the witness key is not published: the agent cannot certify it");
                None
            }
        };
        let path = dir.join(CHAIN_FILE);
        let mut notes = Vec::new();
        let mut len = 0u64;
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
                        len = text.as_ref().map_or(m.len(), |t| t.len() as u64);
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
            len,
            tried: None,
            pending: Vec::new(),
            unprotected: None,
            tgid,
            bpffs_root: None,
            _published: published,
        };
        let mut detail = if notes.is_empty() {
            "a new chain".to_string()
        } else {
            notes.join("; ")
        };
        if !note.is_empty() {
            detail.push_str("; ");
            detail.push_str(note);
        }
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

    /// The review of #582 (F2 c): the chain this life writes registered as
    /// the watchdog role's alone under `bpffs_root` (`ROLE_WRITE_INODES`:
    /// the agent and every other caller refused its write), now and for
    /// each chain opened after a cut. The re-check of #582 (N5): a failure
    /// is returned (the caller records it for the agent to sign) and said in
    /// the next row this life writes — the chain is then the family's, as
    /// before.
    pub fn protect_with(&mut self, bpffs_root: &Path) -> std::result::Result<(), String> {
        self.bpffs_root = Some(bpffs_root.to_path_buf());
        self.protect()
    }

    fn protect(&mut self) -> std::result::Result<(), String> {
        let Some(root) = &self.bpffs_root else {
            return Ok(());
        };
        match antitamper_bpf::protect_for_role(root, &self.path, antitamper_bpf::WATCHDOG_EXE_ROLE)
        {
            Ok(k) => {
                info!(target: "watchdog.witness", dev = k.dev, ino = k.ino, "witness chain registered as the watchdog role's alone");
                Ok(())
            }
            Err(e) => {
                let e = format!("{e:#}");
                warn!(target: "watchdog.witness", error = %e, "the witness chain is NOT registered as the watchdog role's alone");
                self.unprotected = Some(e.clone());
                Err(e)
            }
        }
    }

    /// The re-check of #582 (N6): what this watchdog's own failed append
    /// left at the chain's end. The bytes past its last whole row are the
    /// start of the text it tried to write: a partial row is cut back to
    /// that row (`Torn`, said in a row); the whole row (a write that went
    /// through, its sync failed) is taken as written (`Whole`). Anything
    /// else past that row is not this watchdog's (a cut,
    /// [`Witness::check_head`]).
    fn repair_torn(&mut self) -> Tail {
        let Some((text, why)) = self.tried.clone() else {
            return Tail::Clean;
        };
        let Ok(b) = antitamper_bpf::kernel_roots::read(&self.path, CHAIN_MAX_BYTES + 4096) else {
            return Tail::Foreign;
        };
        let Some(tail) = b.get(self.len as usize..) else {
            return Tail::Foreign;
        };
        let tail = tail.strip_prefix(b"\n").unwrap_or(tail);
        if tail.is_empty() {
            self.tried = None;
            return Tail::Clean;
        }
        if tail == text.as_bytes() {
            self.prev = line_hash(text.trim_end_matches('\n'));
            self.seq += 1;
            self.len = b.len() as u64;
            self.tried = None;
            return Tail::Whole;
        }
        if !text.as_bytes().starts_with(tail) {
            return Tail::Foreign;
        }
        let cut = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&self.path)
            .and_then(|f| f.set_len(self.len));
        match cut {
            Ok(()) => {
                let what = format!(
                    "an append of watchdog {} failed part-way ({why}): its partial row ({} bytes) \
                     removed, the chain ends at row {} ({}) again",
                    self.tgid,
                    b.len() as u64 - self.len,
                    self.seq.saturating_sub(1),
                    self.prev.get(..16).unwrap_or("")
                );
                warn!(target: "watchdog.witness", what = %what, "witness chain torn and repaired");
                self.tried = None;
                self.pending.push((KIND_CHAIN_TORN.to_string(), what));
                Tail::Torn
            }
            Err(e) => {
                warn!(target: "watchdog.witness", error = %e, "the torn witness row could not be removed yet");
                Tail::Foreign
            }
        }
    }

    /// The review of #582 (F2 c): what the chain's file shows of its end
    /// when it no longer ends at this life's last row (`None`: it does).
    fn cut_since_last_row(&self) -> Option<String> {
        if self.seq == 0 {
            return None;
        }
        let text = match antitamper_bpf::kernel_roots::read(&self.path, CHAIN_MAX_BYTES) {
            Ok(b) => String::from_utf8_lossy(&b).into_owned(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Some("the file is gone".to_string())
            }
            Err(e) => return Some(format!("the file cannot be read: {e}")),
        };
        match chain_end(&text) {
            Ok((seq, prev)) if seq == self.seq && prev == self.prev => None,
            Ok((0, _)) => Some("the file holds no row".to_string()),
            Ok((seq, prev)) => Some(format!(
                "the file ends at row {} ({})",
                seq - 1,
                prev.get(..16).unwrap_or("")
            )),
            Err(why) => Some(format!("the file is broken ({why})")),
        }
    }

    /// The review of #582 (F2 c): the chain checked against this life's last
    /// row (the watchdog's memory, which nothing else writes); a chain cut,
    /// changed or replaced since is set aside and a new chain begins with a
    /// signed [`KIND_CHAIN_CUT`] row saying what was expected and found.
    /// `true` when it was.
    pub fn check_head(&mut self) -> bool {
        // the re-check of #582 (N6): this watchdog's own torn append, cut
        // back and said so — torn, not cut
        self.repair_torn();
        let Some(found) = self.cut_since_last_row() else {
            return false;
        };
        let expected = format!(
            "row {} ({})",
            self.seq - 1,
            self.prev.get(..16).unwrap_or("")
        );
        // the re-check of #582 (N6): a name of its own for each cut, so a
        // later cut never replaces an earlier one's evidence
        let aside = aside_name(&self.path, &format!("cut.{}", crate::unix_now()));
        let moved = match std::fs::rename(&self.path, &aside) {
            Ok(()) => format!("set aside as {}", aside.display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                "nothing to set aside".to_string()
            }
            Err(e) => format!("not set aside ({e})"),
        };
        error!(
            target: "watchdog.witness",
            expected = %expected,
            found = %found,
            "the witness chain no longer ends at this watchdog's last row: a new chain begins"
        );
        self.seq = 0;
        self.prev = String::new();
        self.len = 0;
        self.tried = None;
        let detail = format!(
            "the chain watchdog {} writes no longer ended at its last row, {expected}: {found}; \
             {moved}; a new chain begins here",
            self.tgid
        );
        // the re-check of #582 (N6): a cut row not written now (a full
        // disk) is written before the next row, never lost
        self.pending.insert(0, (KIND_CHAIN_CUT.to_string(), detail));
        // not written now: kept, and written before the next row
        let _ = self.flush_pending();
        let _ = self.protect();
        true
    }

    /// The rows due and not written yet, in order; stops at the first that
    /// fails (kept for the next).
    fn flush_pending(&mut self) -> Result<()> {
        while let Some((kind, detail)) = self.pending.first().cloned() {
            self.append(&kind, &detail)?;
            self.pending.remove(0);
        }
        Ok(())
    }

    /// The re-check of #582 (N6): the chain moved aside within this life once
    /// it passes [`ROTATE_BYTES`] (as `open` does), so it never grows past
    /// what the agent and this watchdog read ([`CHAIN_MAX_BYTES`]): a new
    /// chain begins with a [`KIND_OPENED`] row naming the old one's last
    /// row, the old one kept as `witness.chain.1` (the agent continues its
    /// import there).
    fn rotate_if_full(&mut self) -> Result<()> {
        if self.len < ROTATE_BYTES || self.seq == 0 {
            return Ok(());
        }
        let aside = aside_name(&self.path, "1");
        let _ = std::fs::remove_file(&aside);
        std::fs::rename(&self.path, &aside)
            .with_context(|| format!("moving {} aside", self.path.display()))?;
        let detail = format!(
            "watchdog {} rotated its witness within its life: the previous chain, full, ends at \
             row {} ({}), kept as {}",
            self.tgid,
            self.seq - 1,
            self.prev.get(..16).unwrap_or(""),
            aside.display()
        );
        self.seq = 0;
        self.prev = String::new();
        self.len = 0;
        self.tried = None;
        self.append(KIND_OPENED, &detail)?;
        let _ = self.protect();
        Ok(())
    }

    /// One signed row of `kind` with `detail`, appended and logged — the
    /// chain checked first ([`Witness::check_head`]), rotated when full,
    /// the rows due before it written first.
    pub fn record(&mut self, kind: &str, detail: &str) -> Result<()> {
        self.check_head();
        self.rotate_if_full()?;
        self.flush_pending()?;
        match self.unprotected.take() {
            Some(why) => self.append(
                kind,
                &format!(
                    "{detail}; (this chain is not registered as the watchdog role's alone: {why})"
                ),
            ),
            None => self.append(kind, detail),
        }
    }

    fn append(&mut self, kind: &str, detail: &str) -> Result<()> {
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
        let text = format!("{line}\n");
        if let Err(e) = crate::append_line(&self.path, &text) {
            // the re-check of #582 (N6): what a partial write left is this
            // watchdog's own — cut back now, or at the next check
            self.tried = Some((text, e.to_string()));
            if self.repair_torn() == Tail::Whole {
                info!(target: "watchdog.witness", row = %line, "witness row signed (its sync failed, the row is whole)");
                return Ok(());
            }
            return Err(e).with_context(|| format!("appending to {}", self.path.display()));
        }
        info!(target: "watchdog.witness", row = %line, "witness row signed");
        self.prev = line_hash(&line);
        self.seq += 1;
        self.len += text.len() as u64;
        self.tried = None;
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

/// The re-check of #582 (N6): what the bytes past the last whole row of a
/// life are ([`Witness::repair_torn`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tail {
    /// Nothing past it, or no failed append to judge.
    Clean,
    /// The row a failed append tried to write, whole: written.
    Whole,
    /// Its partial row, removed.
    Torn,
    /// Not this watchdog's own (or not removable yet).
    Foreign,
}

/// The re-check of #582 (N6): `path` with `.{suffix}` added, and `.{n}`
/// after it when that name is taken (a cut never replaces another's
/// evidence; a rotation's `.1` is removed by its caller first).
fn aside_name(path: &Path, suffix: &str) -> PathBuf {
    let base = path.with_file_name(format!("{CHAIN_FILE}.{suffix}"));
    if suffix == "1" || std::fs::symlink_metadata(&base).is_err() {
        return base;
    }
    (2..1000)
        .map(|n| path.with_file_name(format!("{CHAIN_FILE}.{suffix}.{n}")))
        .find(|p| std::fs::symlink_metadata(p).is_err())
        .unwrap_or(base)
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

/// The vacancy row's kind: the role released by a shutdown the admin
/// quorum signed, or inside a signed trusted-installer window (the review of
/// #582, F4: the operator's documented restart and stop — a note, as the
/// successor's NN-L-BPF-002 is Low inside one), vacated otherwise. The
/// re-check of #582 (N8): inside a window only a clean stop (`clean`,
/// [`clean_stop`]) is the operator's — an OOM kill or a crash during an
/// upgrade's window stays a vacancy (High).
pub fn vacancy_kind(
    verdict: &crate::ShutdownVerdict,
    in_window: bool,
    clean: bool,
) -> &'static str {
    match verdict {
        crate::ShutdownVerdict::Authorised => nn_proto::witness::KIND_RELEASED,
        _ if in_window && clean => nn_proto::witness::KIND_RELEASED_IN_WINDOW,
        _ => nn_proto::witness::KIND_VACATED,
    }
}

/// The re-check of #582 (N8): the exit `cause` ([`cause_from_show`],
/// [`cause_from_wait`]) is a clean stop — exit status 0 (the agent's
/// answer to `SIGTERM`) or the `SIGTERM` itself.
pub fn clean_stop(cause: &str) -> bool {
    ["exit status 0", "signal 15"]
        .iter()
        .any(|c| cause == *c || cause.starts_with(&format!("{c} ")))
}

/// The review of #582 (F4, the mini-hunt): the row of the agent's role
/// found vacated at this watchdog's start — `role_found_vacant` (High),
/// or a note (`role_released_in_window`) when the kernel marked its
/// holder's last exit inside a signed trusted-installer window (`marks`,
/// `ROLE_MARKS`' agent word; `None` unread: not known to be a window's).
pub fn found_vacant(marks: Option<u32>) -> (&'static str, &'static str) {
    if marks.is_some_and(|m| m & antitamper_bpf::ROLE_MARK_IN_WINDOW != 0) {
        (
            nn_proto::witness::KIND_RELEASED_IN_WINDOW,
            "the agent's role was found vacated at this watchdog's start: its holder's last \
             exit was inside a signed trusted-installer window (the operator's stop)",
        )
    } else {
        (
            nn_proto::witness::KIND_FOUND_VACANT,
            "the agent's role was found vacated at this watchdog's start: its holder exited \
             with no watchdog to see it",
        )
    }
}

/// The successor row's kind: the agent's unit's clean restart, or not
/// (`given`: [`successor_detail`]'s verdict) — and (the re-check of #582,
/// N4) a given one whose libraries' identity is not all confirmed
/// (`confirmed`: `Findings::confirmed`) is
/// [`nn_proto::witness::KIND_SUCCESSOR_UNCONFIRMED`] (High, still given).
pub fn successor_kind(given: bool, confirmed: bool) -> &'static str {
    match (given, confirmed) {
        (true, true) => nn_proto::witness::KIND_SUCCEEDED,
        (true, false) => nn_proto::witness::KIND_SUCCESSOR_UNCONFIRMED,
        (false, _) => nn_proto::witness::KIND_SUCCESSOR_FOREIGN,
    }
}

/// The vacancy row's detail: the agent `pid` gone, `cause` (the wait's or
/// systemd's), and what its shutdown marker said — an authorised stop is
/// one too, and says so.
pub fn vacancy_detail(
    pid: u32,
    cause: &str,
    verdict: &crate::ShutdownVerdict,
    in_window: bool,
) -> String {
    let clean = clean_stop(cause);
    let marker = match verdict {
        crate::ShutdownVerdict::Absent => "no shutdown marker",
        crate::ShutdownVerdict::Authorised => {
            "a shutdown the admin quorum signed: no successor follows"
        }
        crate::ShutdownVerdict::Refused(_) => {
            "a shutdown marker refused (not signed by the admin quorum for this agent)"
        }
    };
    let window = match (in_window, clean) {
        (true, true) => {
            "; inside a signed trusted-installer window (the operator's restart or stop)"
        }
        (true, false) => {
            "; inside a signed trusted-installer window, but not a clean stop (exit status 0 or \
             SIGTERM): not taken as the operator's"
        }
        (false, _) => "",
    };
    format!("the agent (pid {pid}) exited, its role vacated: {cause}; {marker}{window}")
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
/// (the watchdog re-registers only that one). The review of #582 (F3): a
/// successor that is not is observed, never refused here — it holds the
/// role the kernel gave it, and the record says so.
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
    let taken = if ok {
        ""
    } else {
        " — it holds the role the kernel gave it; the watchdog does not re-register it"
    };
    // old 0: the vacancy is the kernel's mark, its holder not known here
    let by = if old == 0 {
        "earlier this boot".to_string()
    } else {
        format!("by pid {old}")
    };
    (
        ok,
        format!(
            "the agent's role, vacated {by}, taken by pid {new}: {verdict}{taken}; {}; {}",
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
            false,
        );
        assert_eq!(
            d,
            "the agent (pid 41) exited, its role vacated: signal 9 (systemd Result=signal); no shutdown marker"
        );
        let d = vacancy_detail(
            41,
            "exit status 0",
            &crate::ShutdownVerdict::Authorised,
            false,
        );
        assert!(
            d.ends_with("a shutdown the admin quorum signed: no successor follows"),
            "{d}"
        );
        let d = vacancy_detail(
            41,
            "exit status 0",
            &crate::ShutdownVerdict::Refused("x".into()),
            false,
        );
        assert!(d.contains("a shutdown marker refused"), "{d}");
        // only a signed shutdown releases the role; a refused marker vacates it
        use nn_proto::witness::{
            KIND_RELEASED, KIND_SUCCEEDED, KIND_SUCCESSOR_FOREIGN, KIND_VACATED,
        };
        assert_eq!(
            vacancy_kind(&crate::ShutdownVerdict::Authorised, false, true),
            KIND_RELEASED
        );
        assert_eq!(
            vacancy_kind(&crate::ShutdownVerdict::Absent, false, true),
            KIND_VACATED
        );
        assert_eq!(
            vacancy_kind(&crate::ShutdownVerdict::Refused("x".into()), false, true),
            KIND_VACATED
        );
        assert_eq!(successor_kind(true, true), KIND_SUCCEEDED);
        assert_eq!(successor_kind(false, true), KIND_SUCCESSOR_FOREIGN);
    }

    /// The review of #582 (F4, the mini-hunt): a watchdog start that finds
    /// the agent's role vacated by the operator's stop inside a signed
    /// window (the maintenance stop, the watchdog started first) writes a
    /// note; any other vacancy, or marks not read, stays `role_found_vacant`.
    #[test]
    fn a_role_found_vacated_by_a_window_s_stop_is_a_note() {
        use antitamper_bpf::{ROLE_MARK_IN_WINDOW as W, ROLE_MARK_VACATED as M};
        use nn_proto::witness::{KIND_FOUND_VACANT, KIND_RELEASED_IN_WINDOW};
        assert_eq!(found_vacant(Some(M | W)).0, KIND_RELEASED_IN_WINDOW);
        for m in [Some(M), Some(0), None] {
            assert_eq!(found_vacant(m).0, KIND_FOUND_VACANT, "{m:?}");
        }
    }

    /// The review of #582 (F4 a): the guide's restart — a window granted,
    /// the agent stopped, the watchdog starting it again — is the
    /// operator's: its vacancy is `role_released_in_window` (a note), never
    /// the High `role_vacated`; a signed shutdown stays `role_released`.
    #[test]
    fn a_vacancy_inside_a_signed_window_is_released_not_vacated() {
        use nn_proto::witness::{KIND_RELEASED, KIND_RELEASED_IN_WINDOW, KIND_VACATED};
        assert_eq!(
            vacancy_kind(&crate::ShutdownVerdict::Absent, true, true),
            KIND_RELEASED_IN_WINDOW
        );
        assert_eq!(
            vacancy_kind(&crate::ShutdownVerdict::Refused("x".into()), true, true),
            KIND_RELEASED_IN_WINDOW
        );
        assert_eq!(
            vacancy_kind(&crate::ShutdownVerdict::Authorised, true, true),
            KIND_RELEASED
        );
        assert_ne!(
            vacancy_kind(&crate::ShutdownVerdict::Absent, true, true),
            KIND_VACATED
        );
        let d = vacancy_detail(41, "exit status 0", &crate::ShutdownVerdict::Absent, true);
        assert!(
            d.ends_with(
                "inside a signed trusted-installer window (the operator's restart or stop)"
            ),
            "{d}"
        );
    }

    /// The re-check of #582 (N8): inside a window only a clean stop — exit
    /// status 0 (the agent's answer to SIGTERM) or the SIGTERM itself — is
    /// the operator's; an OOM kill, a crash or a SIGKILL during an upgrade's
    /// window stays the High vacancy, and its row says it was inside one
    /// without claiming the operator.
    #[test]
    fn inside_a_window_only_a_clean_stop_is_the_operator_s() {
        use nn_proto::witness::{KIND_RELEASED_IN_WINDOW, KIND_VACATED};
        for c in [
            "exit status 0",
            "exit status 0 (systemd Result=success)",
            "signal 15",
            "signal 15 (systemd Result=signal)",
        ] {
            assert!(clean_stop(c), "{c}");
        }
        for c in [
            "the OOM killer (systemd Result=oom-kill; signal 9)",
            "signal 9 (systemd Result=signal)",
            "signal 11, core dumped (systemd Result=core-dump)",
            "exit status 1 (systemd Result=exit-code)",
            "exit status 01",
            "signal 150",
            "not known (systemd reported none)",
        ] {
            assert!(!clean_stop(c), "{c}");
            assert_eq!(
                vacancy_kind(&crate::ShutdownVerdict::Absent, true, clean_stop(c)),
                KIND_VACATED,
                "{c}"
            );
            let d = vacancy_detail(41, c, &crate::ShutdownVerdict::Absent, true);
            assert!(
                d.contains("not taken as the operator's") && !d.contains("(the operator's restart"),
                "{d}"
            );
        }
        assert_eq!(
            vacancy_kind(&crate::ShutdownVerdict::Absent, true, true),
            KIND_RELEASED_IN_WINDOW
        );
        assert_eq!(
            vacancy_kind(&crate::ShutdownVerdict::Absent, false, true),
            KIND_VACATED
        );
    }

    /// The re-check of #582 (N4): a given successor whose libraries'
    /// identity is not all confirmed is its own High kind — never foreign
    /// on that alone, and still given.
    #[test]
    fn a_successor_with_an_unconfirmed_library_is_given_and_high() {
        use nn_proto::witness::{
            KIND_SUCCEEDED, KIND_SUCCESSOR_FOREIGN, KIND_SUCCESSOR_UNCONFIRMED,
        };
        assert_eq!(successor_kind(true, true), KIND_SUCCEEDED);
        assert_eq!(successor_kind(true, false), KIND_SUCCESSOR_UNCONFIRMED);
        assert_eq!(successor_kind(false, false), KIND_SUCCESSOR_FOREIGN);
        let unit = Identity {
            ppid: Some(1),
            cgroup: Some("/northnarrow.slice/northnarrow-agent.service".into()),
        };
        let found = Findings {
            replaced: vec!["/usr/lib/x86_64-linux-gnu/libc.so.6".into()],
            ..Findings::default()
        };
        let (given, d) = successor_detail(10, 11, &unit, &found);
        assert!(given, "{d}");
        assert!(d.contains("identity not confirmed"), "{d}");
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

    /// The review of #582 (F2 c): a tail cut of rows not yet imported, made
    /// while this watchdog lives, is detected — the chain no longer ends at
    /// the last row in the watchdog's memory: set aside, and a new chain
    /// begins with a signed `witness_chain_cut` row naming what it expected
    /// and found (the agent imports it High), before the next row. A chain
    /// left as written is never cut.
    #[test]
    fn a_tail_cut_while_the_watchdog_lives_is_detected_and_signed() {
        use nn_proto::witness::{to_import, Imported, KIND_SUCCEEDED, KIND_VACATED};
        let dir = tempfile::tempdir().unwrap();
        let me = std::process::id();
        let mut w = Witness::open(dir.path(), me).unwrap();
        w.record(KIND_VACATED, "the vacancy").unwrap();
        w.record(KIND_SUCCEEDED, "the successor").unwrap();
        assert!(!w.check_head(), "a chain as written is not cut");
        let text = chain_text(dir.path());
        // the successor's row and the vacancy's cut: a valid prefix is left
        let prefix: String = text.lines().take(1).map(|l| format!("{l}\n")).collect();
        std::fs::write(dir.path().join(CHAIN_FILE), &prefix).unwrap();
        assert!(w.check_head(), "the cut is detected");
        let aside = cut_files(dir.path());
        assert_eq!(aside.len(), 1, "{aside:?}");
        assert_eq!(std::fs::read_to_string(&aside[0]).unwrap(), prefix);
        w.record(KIND_SUCCEEDED, "after").unwrap();
        let mut imp = Imported::default();
        imp.certify(&w.key_hex());
        let t = to_import(&chain_text(dir.path()), &imp);
        assert!(t.broken.is_none(), "{t:?}");
        let kinds: Vec<&str> = t.rows.iter().map(|(r, _, _)| r.kind.as_str()).collect();
        assert_eq!(kinds, [KIND_CHAIN_CUT, KIND_SUCCEEDED]);
        let cut = &t.rows[0].0.detail;
        assert!(
            cut.contains("no longer ended at its last row, row 2")
                && cut.contains("the file ends at row 0"),
            "{cut}"
        );
        // a row appended by another writer, the file emptied or removed, or
        // replaced by another valid chain of as many rows (only its last
        // row's hash tells it): the same, at the next row the watchdog signs
        for damage in ["append", "empty", "remove", "replace"] {
            let dir = tempfile::tempdir().unwrap();
            let mut w = Witness::open(dir.path(), me).unwrap();
            w.record(KIND_VACATED, "v").unwrap();
            let p = dir.path().join(CHAIN_FILE);
            match damage {
                "append" => {
                    let t = chain_text(dir.path()) + "{\"not\":\"a row\"}\n";
                    std::fs::write(&p, t).unwrap();
                }
                "empty" => std::fs::write(&p, "").unwrap(),
                "replace" => {
                    let other = tempfile::tempdir().unwrap();
                    let mut o = Witness::open(other.path(), me).unwrap();
                    o.record(KIND_VACATED, "v").unwrap();
                    std::fs::copy(other.path().join(CHAIN_FILE), &p).unwrap();
                }
                _ => std::fs::remove_file(&p).unwrap(),
            }
            w.record(KIND_SUCCEEDED, "s").unwrap();
            let j = judge_chain(&chain_text(dir.path()));
            let Judged::Valid { row, .. } = &j[0] else {
                panic!("{damage}: {j:?}")
            };
            assert_eq!(row.kind, KIND_CHAIN_CUT, "{damage}");
            assert_eq!(j.len(), 2, "{damage}: {j:?}");
        }
    }

    /// The chain files set aside by cuts (`witness.chain.cut.*`), sorted.
    fn cut_files(dir: &Path) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.file_name().is_some_and(|n| {
                    n.to_string_lossy()
                        .starts_with(&format!("{CHAIN_FILE}.cut."))
                })
            })
            .collect();
        v.sort();
        v
    }

    /// The re-check of #582 (N6): an append of this watchdog's that failed
    /// part-way (a full disk, an I/O error) leaves the start of its own row
    /// past the chain's last whole row: cut back to that row and said in a
    /// `witness_chain_torn` row (a note) — never a `witness_chain_cut`. A
    /// row written whole whose sync failed is taken as written. Anything
    /// else past the last row is still a cut.
    #[test]
    fn a_torn_append_of_the_watchdog_s_own_is_repaired_and_said_torn() {
        use nn_proto::witness::{KIND_SUCCEEDED, KIND_VACATED};
        let dir = tempfile::tempdir().unwrap();
        let me = std::process::id();
        let p = dir.path().join(CHAIN_FILE);
        let mut w = Witness::open(dir.path(), me).unwrap();
        w.record(KIND_VACATED, "the vacancy").unwrap();
        let good = chain_text(dir.path());
        // the row it tried, a third of it on disk
        let tried =
            "{\"v\":1,\"seq\":2,\"kind\":\"role_succeeded\",\"detail\":\"x\"}\n".to_string();
        std::fs::write(&p, format!("{good}{}", &tried[..tried.len() / 3])).unwrap();
        w.tried = Some((
            tried.clone(),
            "No space left on device (os error 28)".into(),
        ));
        assert!(!w.check_head(), "torn is not cut");
        assert_eq!(chain_text(dir.path()), good, "the partial row removed");
        w.record(KIND_SUCCEEDED, "the successor").unwrap();
        let j = judge_chain(&chain_text(dir.path()));
        let kinds: Vec<String> = j
            .iter()
            .map(|x| match x {
                Judged::Valid { row, .. } => row.kind.clone(),
                Judged::Broken { why, .. } => format!("broken: {why}"),
            })
            .collect();
        assert_eq!(
            kinds,
            [KIND_OPENED, KIND_VACATED, KIND_CHAIN_TORN, KIND_SUCCEEDED]
        );
        let Judged::Valid { row, .. } = &j[2] else {
            panic!("{j:?}")
        };
        assert!(
            row.detail.contains("failed part-way (No space left"),
            "{}",
            row.detail
        );
        assert!(cut_files(dir.path()).is_empty());
        // a whole row whose sync failed: written, the chain continues
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(CHAIN_FILE);
        let mut w = Witness::open(dir.path(), me).unwrap();
        let row = w.key.sign(Row {
            v: ROW_VERSION,
            seq: w.seq,
            prev: w.prev.clone(),
            at: 1,
            tgid: me,
            key: String::new(),
            kind: KIND_VACATED.to_string(),
            detail: "whole".into(),
            sig: String::new(),
        });
        let whole = format!("{}\n", serde_json::to_string(&row).unwrap());
        std::fs::write(&p, format!("{}{whole}", chain_text(dir.path()))).unwrap();
        w.tried = Some((whole, "EIO at sync".into()));
        assert!(!w.check_head());
        w.record(KIND_SUCCEEDED, "next").unwrap();
        let j = judge_chain(&chain_text(dir.path()));
        let kinds: Vec<&str> = j
            .iter()
            .map(|x| match x {
                Judged::Valid { row, .. } => row.kind.as_str(),
                Judged::Broken { .. } => "broken",
            })
            .collect();
        assert_eq!(
            kinds,
            [KIND_OPENED, KIND_VACATED, KIND_SUCCEEDED],
            "the whole row kept"
        );
        // what is past the last row and not the row it tried: a cut
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(CHAIN_FILE);
        let mut w = Witness::open(dir.path(), me).unwrap();
        w.record(KIND_VACATED, "v").unwrap();
        std::fs::write(&p, chain_text(dir.path()) + "{\"not\":").unwrap();
        w.tried = Some(("{\"v\":1,\"seq\":2}\n".into(), "EIO".into()));
        assert!(w.check_head(), "another's bytes are a cut");
    }

    /// The re-check of #582 (N6): the chain rotated within a life once it
    /// passes `ROTATE_BYTES` (never grown past what is read: no false cut at
    /// 1 MiB) — the old one kept as `witness.chain.1`, the new one opened
    /// with a row naming the old one's last row; and a second cut never
    /// replaces the first one's evidence.
    #[test]
    fn a_full_chain_rotates_within_a_life_and_cuts_keep_their_own_names() {
        use nn_proto::witness::{KIND_SUCCEEDED, KIND_VACATED};
        let dir = tempfile::tempdir().unwrap();
        let me = std::process::id();
        let mut w = Witness::open(dir.path(), me).unwrap();
        w.record(KIND_VACATED, "before").unwrap();
        let before = chain_text(dir.path());
        w.len = ROTATE_BYTES;
        w.record(KIND_SUCCEEDED, "after").unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join(format!("{CHAIN_FILE}.1"))).unwrap(),
            before
        );
        let j = judge_chain(&chain_text(dir.path()));
        assert_eq!(j.len(), 2, "{j:?}");
        let Judged::Valid { row, .. } = &j[0] else {
            panic!("{j:?}")
        };
        assert_eq!((row.seq, row.kind.as_str()), (0, KIND_OPENED));
        assert!(
            row.detail.contains("rotated its witness within its life")
                && row.detail.contains("ends at row 1"),
            "{}",
            row.detail
        );
        assert!(!w.check_head(), "a rotation is not a cut");
        // two cuts, two files
        for _ in 0..2 {
            std::fs::write(dir.path().join(CHAIN_FILE), "").unwrap();
            assert!(w.check_head());
            w.record(KIND_SUCCEEDED, "s").unwrap();
        }
        assert_eq!(cut_files(dir.path()).len(), 2);
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
            replaced: vec![],
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

    /// The review of #582 (F3): a successor that is not its unit's clean
    /// restart is observed — it holds the role the kernel gave it — and its
    /// record says that, never that it was refused; the row's kind is
    /// `role_successor_foreign`.
    #[test]
    fn a_foreign_successor_is_recorded_as_holding_the_role_never_as_refused() {
        let unit = Identity {
            ppid: Some(1),
            cgroup: Some("/northnarrow.slice/northnarrow-agent.service".into()),
        };
        let preloaded = Findings {
            loader_vars: vec!["LD_PRELOAD".into()],
            ..Findings::default()
        };
        let (ok, d) = successor_detail(10, 11, &unit, &preloaded);
        assert!(!ok);
        assert!(
            d.contains("holds the role the kernel gave it")
                && d.contains("does not re-register it"),
            "{d}"
        );
        assert!(!d.to_lowercase().contains("refus"), "{d}");
        assert_eq!(successor_kind(false, true), "role_successor_foreign");
        assert_eq!(successor_kind(true, true), "role_succeeded");
        let (ok, d) = successor_detail(10, 11, &unit, &Findings::default());
        assert!(ok && !d.contains("holds the role"), "{d}");
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
