//! A refused start (Wave 4 restructure, R11b, lab PR 262; lab PR 218's
//! `record_refused_boot`, for every gate now).
//!
//! A boot gate that refuses the start leaves the refusal in a signed chain
//! before the process exits, so the trace is signed by the agent's key, not
//! only a journal line (lab PR 21): the rows lab PR 218 wrote — the rollback
//! floor, the identity, a `subsystem_degraded` when the gate has one, then
//! the `agent_boot` with `result: refused` and `refused_by` naming the gate.
//! They go
//!
//! 1. into the audit log — the one the integrity phase opened before the
//!    load, once it did, otherwise opened here;
//! 2. when the audit log cannot take them (it is the gate: not writable,
//!    its chain broken, its write failed), into a chain of the same format,
//!    signed with the same key, in a file of its own: created with
//!    `O_CREAT | O_EXCL` under a fresh random name in [`FALLBACK_DIR_NAME`]
//!    beside `--pid-file` (`/run/northnarrow/boot-refusals` in the unit), a
//!    directory the agent creates and checks ([`FallbackDir`]: no symbolic
//!    link is followed, owned by the agent's user, closed to group and
//!    others, not another filesystem mounted there). No name another
//!    process put there is ever opened for writing (review #466 F1). Its
//!    first row ([`FALLBACK_OPENED_OP`]) names the audit log's head at the
//!    refusal, which binds the chain to the log it stands in for. The next
//!    start that opens the audit log reads each such file once, bounded,
//!    verifies it and records it there from those same bytes
//!    ([`record_fallback`], review #466 F2);
//! 3. nowhere but the journal when neither can be written (no key, no
//!    absolute `--pid-file`, a fallback directory that is not the agent's):
//!    the line says why, never with the content of a file.
//!
//! The fallback directory is on the runtime directory's tmpfs: a reboot
//! empties it, and root can remove a file there before the next start
//! records it — the journal line, with the chain's hash, is then the trace
//! (`docs/operator/BOOT_INTEGRITY.md` §7).
//!
//! Then the start's registration in the pinned `PROTECTED_PIDS` — the
//! previous agent's map, written before the bootstraps (EBPF-015), or this
//! boot's once the attach registered it — is withdrawn, so a refused start
//! leaves no protected pid behind for a recycled pid to inherit, and the
//! process exits 78 (`EX_CONFIG`: the unit lands `failed`).
//!
//! Lab PR 265 (review #466 F4-bis): the two gates nothing can sign — the
//! agent's directories mounted over (`agent_mounts`), its key absent where
//! an earlier identity is on record (`signing_identity`) — refuse through
//! [`refuse_unsigned`], first thing in the preflight: the journal holds
//! them, the same withdrawal and exit follow.
//!
//! Every other gate before the load refuses through [`Context::refuse`] — the
//! eBPF object, the state directory, the BTF offsets (the preflight's three,
//! found before the identity is read, refuse at the start of the integrity
//! phase), the demo rules, the capabilities, the install manifest, the
//! audit log, the BPF LSM, the deny hooks' pin root and BTF — and so do
//! those that need the loaded object: the sensors' load and attach, the deny
//! hooks, the deny self-test, the boot's own `agent_boot` row.

use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use northnarrow_agent::agent_id::AgentIdentity;
use northnarrow_agent::audit::{
    AuditEntry, AuditEntryDraft, AuditLog, AuditVerifyError, GENESIS_PREV_HASH,
};
use northnarrow_agent::chain_host_linux::LinuxHost;
use northnarrow_agent::config::overlay_auth::OverlayGate;
use northnarrow_agent::keys::BootKey;
use serde_json::{json, Value};
use tracing::{debug, error, info, warn};

use super::cli::Cli;

/// The exit status of a refused start (sysexits.h `EX_CONFIG`): a non-zero
/// status systemd shows as a `failed` unit (`Restart=no`).
pub(crate) const EX_CONFIG: i32 = 78;

/// The directory beside `--pid-file` that holds the refusals the audit log
/// could not take: one chain per refusal, each its own file.
pub(crate) const FALLBACK_DIR_NAME: &str = "boot-refusals";

/// The audit `op` of a fallback chain's first row: the audit log it stands
/// in for and that log's head at the refusal (review #466 F2).
pub(crate) const FALLBACK_OPENED_OP: &str = "boot_refusal_fallback";

/// The audit `op` of the row that records a fallback chain in the audit
/// log ([`record_fallback`]).
pub(crate) const RECOVERED_OP: &str = "boot_refusals_recovered";

/// A fallback chain larger than this is not read: recorded as refused.
pub(crate) const MAX_FALLBACK_BYTES: u64 = 1 << 20;

/// The fallback chains one start records; the others wait for the next.
pub(crate) const MAX_FALLBACK_FILES: usize = 16;

/// The refused boots one [`RECOVERED_OP`] row lists (its count is the
/// chain's, all of them).
pub(crate) const MAX_LISTED: usize = 32;

/// The `binary_integrity` and `install_provenance` of a refusal before the
/// install manifest was checked.
pub(crate) const UNCHECKED: (&str, &str) = ("unchecked", "none");

/// A boot gate's refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Refusal {
    /// The gate (`refused_by`).
    pub(crate) gate: &'static str,
    /// What it found (the row's `detail`).
    pub(crate) detail: String,
    /// A `subsystem_degraded` signed before the refusal: its source.
    pub(crate) degraded: Option<&'static str>,
}

impl Refusal {
    pub(crate) fn new(gate: &'static str, detail: impl Into<String>) -> Self {
        Refusal {
            gate,
            detail: detail.into(),
            degraded: None,
        }
    }

    /// The refusal with a signed `subsystem_degraded` of `source` (its
    /// detail the refusal's), as lab PR 218's gates wrote it.
    pub(crate) fn degraded(mut self, source: &'static str) -> Self {
        self.degraded = Some(source);
        self
    }
}

/// What the start has to sign a refusal with when it refuses.
pub(crate) struct Context<'a> {
    pub(crate) cli: &'a Cli,
    pub(crate) identity: &'a AgentIdentity,
    pub(crate) overlay_gate: &'a OverlayGate,
    /// The install manifest's verdict and provenance ([`UNCHECKED`] before
    /// it ran).
    pub(crate) integrity: (&'a str, &'a str),
    /// The review of #468, R4: the start's one key, which signs the refusal
    /// as it signs every other row of the start (loaded at this first use
    /// when the preflight refused the start: no state file was bootstrapped).
    pub(crate) key: &'a BootKey,
}

impl Context<'_> {
    /// Refuse the start: sign the refusal ([`sign`]) — in `audit`, the audit
    /// log the integrity phase opened, once it did —, withdraw the start's
    /// registration in the pinned `PROTECTED_PIDS`, exit [`EX_CONFIG`]
    /// ([`Self::conclude`]). The gate has logged what it found.
    pub(crate) fn refuse(&self, audit: Option<&mut AuditLog>, refusal: Refusal) -> ! {
        exit_refused(self.conclude(audit, refusal, withdraw_registration))
    }

    /// What [`Self::refuse`] does before it exits (review #466 F7: the tail
    /// a test can run): the refusal signed and said in the journal, then
    /// `withdraw` of the start's registration under the bpffs root
    /// ([`withdraw_registration`] for the start) — always, signed or not —,
    /// then the status to exit with, [`EX_CONFIG`].
    pub(crate) fn conclude(
        &self,
        audit: Option<&mut AuditLog>,
        refusal: Refusal,
        withdraw: impl FnOnce(&Path),
    ) -> i32 {
        let signed = sign(self, audit, &refusal);
        finish(refusal.gate, signed, withdraw)
    }
}

/// Lab PR 265 (review #466 F4-bis): refuse a start that nothing can sign —
/// the agent's own directories mounted over (a chain opened now would be
/// in the view the gate refuses), or its key absent where an earlier
/// identity is on record (signing would mean minting the key the gate
/// refuses to mint). The gate has logged what it found; the journal holds
/// the refusal (`why`: why it is not signed), the start's registration in
/// the pinned `PROTECTED_PIDS` is withdrawn — the preflight refuses these
/// before the start registers, so there is none to withdraw then, as
/// [`withdraw_registration`] says —, and the process exits [`EX_CONFIG`],
/// as every refusal ([`Context::refuse`]).
pub(crate) fn refuse_unsigned(refusal: Refusal, why: &str) -> ! {
    exit_refused(conclude_unsigned(refusal, why, withdraw_registration))
}

/// What [`refuse_unsigned`] does before it exits (the tail a test can run):
/// the journal's lines, `withdraw`, [`EX_CONFIG`].
pub(crate) fn conclude_unsigned(refusal: Refusal, why: &str, withdraw: impl FnOnce(&Path)) -> i32 {
    finish(refusal.gate, Signed::Unsigned(why.to_string()), withdraw)
}

/// The one exit of a refused start (review #466 F7).
fn exit_refused(status: i32) -> ! {
    std::process::exit(status)
}

/// The tail of every refusal: where it was signed, said in the journal; the
/// registration withdrawn — always, signed or not —; the status to exit
/// with, [`EX_CONFIG`].
fn finish(gate: &'static str, signed: Signed, withdraw: impl FnOnce(&Path)) -> i32 {
    match signed {
        Signed::AuditLog { entry_hash } => {
            info!(entry_hash = %entry_hash, gate, "refused boot recorded in the audit chain")
        }
        Signed::Fallback {
            path,
            entry_hash,
            audit_log,
        } => error!(
            path = %path.display(),
            entry_hash = %entry_hash,
            gate,
            audit_log = %audit_log,
            "refused boot recorded in the fallback chain: the audit log cannot take it \
             (nn-admin audit verify --from <path>)"
        ),
        Signed::Unsigned(why) => error!(
            gate,
            why = %why,
            "could not record the refused boot in a signed chain — the journal holds it alone"
        ),
    }
    withdraw(Path::new(
        northnarrow_agent::anti_tamper::DEFAULT_BPFFS_ROOT,
    ));
    error!(gate, exit = EX_CONFIG, "start refused");
    EX_CONFIG
}

/// Where a refusal was signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Signed {
    /// In the audit log: the `agent_boot` row's hash.
    AuditLog { entry_hash: String },
    /// In a fallback chain, the file at `path` (the audit log could not
    /// take it: why).
    Fallback {
        path: PathBuf,
        entry_hash: String,
        audit_log: String,
    },
    /// Nowhere: why.
    Unsigned(String),
}

/// Sign `refusal`: in the audit log (`audit`, the one opened before the
/// load, or the file opened now), else in a fallback chain of its own in
/// the directory beside `--pid-file` ([`FallbackDir`]), else nowhere (why).
pub(crate) fn sign(ctx: &Context<'_>, audit: Option<&mut AuditLog>, refusal: &Refusal) -> Signed {
    let Context {
        cli,
        identity,
        overlay_gate,
        integrity,
        key,
    } = *ctx;
    // 1. the audit log: the one opened before the load, or opened now. When
    // an open log cannot take the rows, its head is what the fallback chain
    // names (review #466 F2).
    let mut head: Option<(u64, String)> = None;
    let mut take = |log: &mut AuditLog| {
        let r = write_refusal(log, identity, Some(overlay_gate), integrity, refusal);
        if r.is_err() {
            head = Some((log.rows(), log.last_hash().to_string()));
        }
        r
    };
    let audit_log = match audit {
        Some(log) => take(log),
        None => match key.signer() {
            Ok(key) => match AuditLog::open(&cli.audit_log_file, key, identity.id) {
                Ok(mut log) => take(&mut log),
                Err(e) => Err(format!("{e:#}")),
            },
            Err(e) => {
                return Signed::Unsigned(format!("the agent's signing key cannot be loaded: {e}"))
            }
        },
    };
    let audit_log = match audit_log {
        Ok(entry_hash) => return Signed::AuditLog { entry_hash },
        Err(why) => why,
    };
    // 2. a fallback chain, in a file of its own
    let Some(dir) = fallback_dir(cli) else {
        return Signed::Unsigned(format!(
            "the audit log cannot take it ({audit_log}), and without --pid-file (an absolute \
             path) there is no fallback chain"
        ));
    };
    let key = match key.signer() {
        Ok(key) => key,
        Err(e) => {
            return Signed::Unsigned(format!(
                "the audit log cannot take it ({audit_log}); the agent's signing key cannot be \
                 loaded: {e}"
            ))
        }
    };
    // the head the chain names: the open log's, else the file's, read
    // without writing (a chain that cannot be read names none, and why)
    let head = match head {
        Some(h) => Ok(h),
        None => northnarrow_agent::audit::read_head::<LinuxHost>(&cli.audit_log_file)
            .map_err(|e| format!("{e:#}")),
    };
    let mut chain = AuditLog::in_memory(key, identity.id);
    let entry_hash = match open_fallback(&mut chain, cli, &head, &audit_log)
        .and_then(|()| write_refusal(&mut chain, identity, None, integrity, refusal))
    {
        Ok(h) => h,
        Err(why) => {
            return Signed::Unsigned(format!(
                "the audit log cannot take it ({audit_log}); the fallback chain could not be \
                 signed: {why}"
            ))
        }
    };
    match FallbackDir::open(&dir, true).and_then(|d| d.create(&chain.into_bytes())) {
        Ok(path) => Signed::Fallback {
            path,
            entry_hash,
            audit_log,
        },
        Err(why) => Signed::Unsigned(format!(
            "the audit log cannot take it ({audit_log}); nor can the fallback directory {}: {why}",
            dir.display()
        )),
    }
}

/// A fallback chain's first row ([`FALLBACK_OPENED_OP`]): the audit log it
/// stands in for, that log's head at the refusal (`head`: its rows and last
/// hash, or why it could not be read), why the log could not take the
/// refusal, and a nonce of its own.
fn open_fallback(
    chain: &mut AuditLog,
    cli: &Cli,
    head: &Result<(u64, String), String>,
    audit_log: &str,
) -> Result<(), String> {
    let mut extra = json!({
        "audit_log": cli.audit_log_file.display().to_string(),
        "audit_head": match head {
            Ok((rows, hash)) => json!({ "rows": rows, "entry_hash": hash }),
            Err(_) => Value::Null,
        },
        "why": audit_log,
        "nonce": uuid::Uuid::new_v4().simple().to_string(),
    });
    if let Err(why) = head {
        extra["audit_head_unreadable"] = Value::String(why.clone());
    }
    chain
        .append(AuditEntryDraft {
            op: FALLBACK_OPENED_OP.to_string(),
            extra,
            key_fp: "agent-self".to_string(),
            cosigner_fps: Vec::new(),
            result: "opened".to_string(),
            client_pid: chain.self_pid(),
            client_uid: 0,
            client_comm: "northnarrow-agent".to_string(),
            client_exe: None,
        })
        .map(drop)
        .map_err(|e| format!("{e:#}"))
}

/// The refusal's rows in `log`: the rollback floor (the audit log only:
/// `floor`), the identity (EVD-020), the `subsystem_degraded`, the
/// `agent_boot` `refused` — its hash, or why it could not be written.
fn write_refusal(
    log: &mut AuditLog,
    identity: &AgentIdentity,
    floor: Option<&OverlayGate>,
    (integrity, provenance): (&str, &str),
    refusal: &Refusal,
) -> Result<String, String> {
    if let Some(gate) = floor {
        gate.attest_floor(log);
    }
    // External audit EVD-020: a refused boot records its identity too.
    if let Err(e) = log.attest_identity(identity) {
        warn!(error = format!("{e:#}"), "agent identity not recorded");
    }
    if let Some(source) = refusal.degraded {
        northnarrow_agent::boot::degradation::sign_into(log, source, &refusal.detail, true);
    }
    log.boot_refused_by(
        refusal.gate,
        integrity,
        provenance,
        &refusal.detail,
        &northnarrow_agent::build_info::agent_build(),
    )
    .map(|e| e.entry_hash)
    .map_err(|e| format!("{e:#}"))
}

/// The fallback directory: [`FALLBACK_DIR_NAME`] beside `--pid-file` (the
/// unit's `/run/northnarrow`, its `RuntimeDirectory`); none without
/// `--pid-file`, as for the BPF program-id list (DEP-006), nor with a
/// relative one (its directory would be the current one).
pub(crate) fn fallback_dir(cli: &Cli) -> Option<PathBuf> {
    let pid_file = cli.pid_file.as_deref()?;
    if !pid_file.is_absolute() {
        return None;
    }
    Some(pid_file.parent()?.join(FALLBACK_DIR_NAME))
}

/// This process's effective uid: the only owner of the fallback directory
/// and of its files it accepts (root under the unit).
fn euid() -> u32 {
    // SAFETY: geteuid has no precondition and cannot fail.
    unsafe { libc::geteuid() }
}

/// `path` opened as a directory, a symbolic link not followed, a FIFO not
/// waited on.
fn open_dir(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
}

/// The name `name` in the directory `dir` is open on, resolved through the
/// descriptor (`/proc/self/fd/<fd>/<name>`): a rename or a mount of the
/// directory's path after the open does not move it.
fn in_dir(dir: &File, name: &OsStr) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd())).join(name)
}

/// What sits at `path`, named without following it or reading it.
fn what_is(path: &Path) -> &'static str {
    match std::fs::symlink_metadata(path).map(|m| m.file_type()) {
        Ok(t) if t.is_symlink() => "a symbolic link",
        Ok(t) if t.is_dir() => "a directory",
        Ok(t) if t.is_file() => "a regular file",
        Ok(t) if t.is_fifo() => "a FIFO",
        Ok(t) if t.is_socket() => "a socket",
        Ok(t) if t.is_char_device() || t.is_block_device() => "a device",
        Ok(_) => "a special file",
        Err(_) => "nothing that can be named",
    }
}

/// The directory of the fallback chains, checked (R11b, lab PR 262, review
/// #466 F1). The directory of `--pid-file` is opened first, without
/// following a symbolic link: owned by this process's user, writable by
/// nobody else, and not a mount of another filesystem over that name (its
/// `..` on the same device) — a protected directory bind-mounted there
/// would take the agent's new entry. [`FALLBACK_DIR_NAME`] in it is created
/// (0700) by the first refusal that needs it, then opened the same way:
/// owned by this process's user, closed to its group and others, on the
/// same device. Every name below is resolved through these descriptors.
pub(crate) struct FallbackDir {
    /// `<pid dir>/boot-refusals`, as named (in the journal and the rows).
    path: PathBuf,
    /// The directory itself.
    dir: File,
    /// This process's effective uid.
    uid: u32,
}

impl FallbackDir {
    /// The directory `path` (`<pid dir>/boot-refusals`), checked; `create`:
    /// made when missing (a refusal), else `None` when missing (the next
    /// start's look).
    pub(crate) fn open(path: &Path, create: bool) -> Result<Self, String> {
        Self::open_in(path, create)?.ok_or_else(|| format!("{}: missing", path.display()))
    }

    fn open_in(path: &Path, create: bool) -> Result<Option<Self>, String> {
        let uid = euid();
        let (Some(pid_dir), Some(name)) = (path.parent(), path.file_name()) else {
            return Err(format!("{}: not a directory's entry", path.display()));
        };
        let parent = open_dir(pid_dir).map_err(|e| match e.raw_os_error() {
            Some(libc::ELOOP) | Some(libc::ENOTDIR) => format!(
                "the directory of --pid-file {} is {}, not followed",
                pid_dir.display(),
                what_is(pid_dir)
            ),
            _ => format!("the directory of --pid-file {}: {e}", pid_dir.display()),
        })?;
        let pmeta = parent
            .metadata()
            .map_err(|e| format!("fstat {}: {e}", pid_dir.display()))?;
        if pmeta.uid() != uid {
            return Err(format!(
                "the directory of --pid-file {} is owned by uid {}, not by this process's {uid}",
                pid_dir.display(),
                pmeta.uid()
            ));
        }
        if pmeta.mode() & 0o022 != 0 {
            return Err(format!(
                "the directory of --pid-file {} is writable by its group or others (mode {:o})",
                pid_dir.display(),
                pmeta.mode() & 0o7777
            ));
        }
        let up = std::fs::symlink_metadata(in_dir(&parent, OsStr::new("..")))
            .map_err(|e| format!("lstat {}/..: {e}", pid_dir.display()))?;
        if up.dev() != pmeta.dev() {
            return Err(format!(
                "the directory of --pid-file {} is another filesystem mounted over its name",
                pid_dir.display()
            ));
        }
        let at = in_dir(&parent, name);
        if create {
            match std::fs::DirBuilder::new().mode(0o700).create(&at) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(format!("creating {}: {e}", path.display())),
            }
        }
        let dir = match open_dir(&at) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !create => return Ok(None),
            Err(e) => {
                return Err(match e.raw_os_error() {
                    Some(libc::ELOOP) | Some(libc::ENOTDIR) => {
                        format!("{} is {}, not followed", path.display(), what_is(&at))
                    }
                    _ => format!("{}: {e}", path.display()),
                })
            }
        };
        let meta = dir
            .metadata()
            .map_err(|e| format!("fstat {}: {e}", path.display()))?;
        if meta.uid() != uid {
            return Err(format!(
                "{} is owned by uid {}, not by this process's {uid}",
                path.display(),
                meta.uid()
            ));
        }
        if meta.mode() & 0o077 != 0 {
            return Err(format!(
                "{} is open to its group or others (mode {:o})",
                path.display(),
                meta.mode() & 0o7777
            ));
        }
        if meta.dev() != pmeta.dev() {
            return Err(format!(
                "{} is another filesystem mounted there",
                path.display()
            ));
        }
        Ok(Some(FallbackDir {
            path: path.to_path_buf(),
            dir,
            uid,
        }))
    }

    /// A new file under a fresh random name (`refusal-<hex>.jsonl`, `0600`,
    /// `O_CREAT | O_EXCL | O_NOFOLLOW`: a name already there — a planted
    /// one, a link — is never opened) holding `bytes`, on the disk before
    /// this returns; its path. A write that fails removes the file.
    pub(crate) fn create(&self, bytes: &[u8]) -> Result<PathBuf, String> {
        for _ in 0..3 {
            let name = format!("refusal-{}.jsonl", uuid::Uuid::new_v4().simple());
            let at = in_dir(&self.dir, OsStr::new(&name));
            let mut f = match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(&at)
            {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(format!("creating a file in {}: {e}", self.path.display())),
            };
            if let Err(e) = f.write_all(bytes).and_then(|()| f.sync_all()) {
                let _ = std::fs::remove_file(&at);
                return Err(format!("writing {}/{name}: {e}", self.path.display()));
            }
            // the new name (tmpfs: already there)
            let _ = self.dir.sync_all();
            return Ok(self.path.join(name));
        }
        Err(format!(
            "{}: three fresh names were taken already",
            self.path.display()
        ))
    }

    /// The names in the directory, at most `max` of them.
    fn names(&self, max: usize) -> Result<Vec<OsString>, String> {
        let mut names: Vec<OsString> = std::fs::read_dir(in_dir(&self.dir, OsStr::new("")))
            .map_err(|e| format!("listing {}: {e}", self.path.display()))?
            .filter_map(|e| e.ok().map(|e| e.file_name()))
            .take(max)
            .collect();
        names.sort();
        Ok(names)
    }

    /// The file `name`, read once (review #466 F2, `read_marker`'s way): a
    /// symbolic link not followed, a FIFO not waited on; then, on the
    /// descriptor, a regular file of this process's user, closed to its
    /// group and others, of one link and at most [`MAX_FALLBACK_BYTES`],
    /// read to that bound. Why not, without any of its content.
    fn read(&self, name: &OsStr) -> Result<Vec<u8>, String> {
        let at = in_dir(&self.dir, name);
        let f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&at)
            .map_err(|e| match e.raw_os_error() {
                Some(libc::ELOOP) => "a symbolic link, not followed".to_string(),
                _ => format!("{}: {e}", what_is(&at)),
            })?;
        let meta = f.metadata().map_err(|e| format!("fstat: {e}"))?;
        if !meta.file_type().is_file() {
            return Err(format!("{}, not a regular file", what_is(&at)));
        }
        if meta.uid() != self.uid {
            return Err(format!("owned by uid {}", meta.uid()));
        }
        if meta.mode() & 0o077 != 0 {
            return Err(format!(
                "open to its group or others (mode {:o})",
                meta.mode() & 0o7777
            ));
        }
        if meta.nlink() != 1 {
            return Err(format!("{} hard links", meta.nlink()));
        }
        if meta.len() > MAX_FALLBACK_BYTES {
            return Err(format!("{} bytes, over {MAX_FALLBACK_BYTES}", meta.len()));
        }
        let mut bytes = Vec::new();
        f.take(MAX_FALLBACK_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| format!("unreadable: {e}"))?;
        if bytes.len() as u64 > MAX_FALLBACK_BYTES {
            return Err(format!("over {MAX_FALLBACK_BYTES} bytes"));
        }
        Ok(bytes)
    }

    /// Remove the entry `name` (an unlink: a link goes, not its target; an
    /// empty directory too).
    fn remove(&self, name: &OsStr) -> std::io::Result<()> {
        let at = in_dir(&self.dir, name);
        match std::fs::remove_file(&at) {
            Err(e) if std::fs::symlink_metadata(&at).is_ok_and(|m| m.is_dir()) => {
                std::fs::remove_dir(&at).map_err(|_| e)
            }
            r => r,
        }
    }
}

/// Withdraw this process from the pinned `PROTECTED_PIDS` under
/// `bpffs_root`: the previous agent's map it registered in before the
/// bootstraps (EBPF-015), or this boot's once the attach registered it. A
/// refused start must not leave a protected pid behind — a recycled pid
/// would inherit the immunity to kill and ptrace and the exemption from the
/// deny hooks until the next start's stale-pid scan. No pinned map: nothing
/// to withdraw.
pub(crate) fn withdraw_registration(bpffs_root: &Path) {
    if !bpffs_root
        .join(northnarrow_agent::anti_tamper::PROTECTED_PIDS_MAP_NAME)
        .exists()
    {
        debug!("anti-tamper: no pinned PROTECTED_PIDS, no registration to withdraw");
        return;
    }
    match northnarrow_agent::anti_tamper::evict_protected_pid(Some(bpffs_root), std::process::id())
    {
        Ok(()) => info!(
            pid = std::process::id(),
            "anti-tamper: the refused start's pid withdrawn from the pinned PROTECTED_PIDS"
        ),
        Err(e) => warn!(
            error = format!("{e:#}"),
            pid = std::process::id(),
            "anti-tamper: the refused start's pid NOT withdrawn from the pinned PROTECTED_PIDS — \
             the next start's stale-pid scan evicts it"
        ),
    }
}

/// The next start that opens the audit log: the refusals the fallback
/// chains in `dir` hold — the ones earlier starts could not sign there —,
/// each file read once and bounded ([`FallbackDir::read`]), verified with
/// the agent's key (`verifying_key`) from those bytes, and checked against
/// `log` (review #466 F2): its first row is a fallback chain's
/// ([`FALLBACK_OPENED_OP`]), every row is signed for this agent's id
/// (`agent_id`), the audit log's head it names is the row of `log` at that
/// place, and `log` has not recorded this chain before (a copy put back).
/// Each is recorded in `log` as one signed [`RECOVERED_OP`] row (the
/// chain's id — its first row's hash —, rows and head, each refused boot's
/// time, gate, detail, binary integrity and row hash, at most
/// [`MAX_LISTED`] of them), then the file removed. A chain that fails any
/// of that, a file that is not one of the agent's, is recorded too, with
/// why and none of its content, and removed all the same, so a bad file
/// cannot repeat at every start (lab PR 220's rule for the rollback
/// marker); a row that cannot be written leaves its file for the next
/// start. At most [`MAX_FALLBACK_FILES`] files per start. A directory that
/// is not the agent's is recorded and left. Each row's hash, or why it was
/// not written.
pub(crate) fn record_fallback(
    log: &mut AuditLog,
    dir: &Path,
    verifying_key: Option<&ed25519_dalek::VerifyingKey>,
    agent_id: [u8; 16],
) -> Vec<Result<String, String>> {
    let fallback = match FallbackDir::open_in(dir, false) {
        Ok(None) => return Vec::new(),
        Ok(Some(d)) => d,
        Err(why) => {
            return vec![write_recovered(
                log,
                dir,
                json!({ "verified": false, "why": why }),
            )]
        }
    };
    let names = match fallback.names(MAX_FALLBACK_FILES) {
        Ok(n) => n,
        Err(why) => {
            return vec![write_recovered(
                log,
                dir,
                json!({ "verified": false, "why": why }),
            )]
        }
    };
    let mut recorded = Vec::new();
    for name in names {
        let path = dir.join(&name);
        let extra = match fallback.read(&name) {
            Err(why) => json!({ "verified": false, "why": why }),
            Ok(bytes) => match verifying_key {
                None => json!({ "verified": false, "why": "no agent verifying key" }),
                Some(pk) => fallback_contents(log, &bytes, pk, agent_id),
            },
        };
        let result = write_recovered(log, &path, extra);
        if result.is_ok() {
            if let Err(e) = fallback.remove(&name) {
                warn!(
                    error = %e,
                    path = %path.display(),
                    "boot refusals recorded, their fallback chain NOT removed — recorded again at \
                     the next start"
                );
            }
        }
        recorded.push(result);
    }
    recorded
}

/// Why a fallback chain does not verify, without its content: the row and
/// the kind of break (review #466 F1).
fn describe_break(e: &AuditVerifyError) -> String {
    match e {
        AuditVerifyError::PrevHashMismatch { idx, .. } => {
            format!("row {idx}: not linked to the row before it")
        }
        AuditVerifyError::EntryHashMismatch { idx, .. } => {
            format!("row {idx}: its hash is not its content's")
        }
        AuditVerifyError::SignatureInvalid { idx } => {
            format!("row {idx}: its signature does not verify with the agent's key")
        }
        AuditVerifyError::MalformedField { idx, .. } => format!("row {idx}: a malformed field"),
        AuditVerifyError::Sequence { idx, reason } => format!("row {idx}: {reason}"),
        AuditVerifyError::NonCanonical { idx } => {
            format!("row {idx}: not in its canonical form")
        }
        AuditVerifyError::UnreadableLine { line, reason, .. } => {
            format!("line {line}: not an audit row ({reason})")
        }
    }
}

/// The head a fallback chain's first row names: its rows and last hash,
/// `None` when the audit log could not be read then; `Err` for a row that
/// names one in another shape.
fn named_head(first: &AuditEntry) -> Result<Option<(u64, String)>, String> {
    let head = &first.extra["audit_head"];
    if head.is_null() {
        return Ok(None);
    }
    match (head["rows"].as_u64(), head["entry_hash"].as_str()) {
        (Some(rows), Some(hash)) => Ok(Some((rows, hash.to_string()))),
        _ => Err("its first row names the audit log's head in another shape".to_string()),
    }
}

/// What a fallback chain's `bytes` say, once they verify with `pk` and the
/// chain is bound to `log` (see [`record_fallback`]).
fn fallback_contents(
    log: &AuditLog,
    bytes: &[u8],
    pk: &ed25519_dalek::VerifyingKey,
    agent_id: [u8; 16],
) -> Value {
    let refused = |why: String| json!({ "verified": false, "why": why });
    let report = northnarrow_agent::audit::verify_chain_bytes(bytes, pk, None);
    if let Some(broken) = &report.broken {
        return json!({
            "verified": false,
            "why": describe_break(broken),
            "rows_verified": report.rows,
        });
    }
    // the same bytes: every line verified, so every line is a row
    let rows: Vec<AuditEntry> = bytes
        .split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_slice(l).ok())
        .collect();
    let Some(first) = rows.first() else {
        return refused("no row".to_string());
    };
    if first.op != FALLBACK_OPENED_OP {
        return refused(
            "its first row is not a fallback chain's: the rows of another chain".to_string(),
        );
    }
    let ours = hex::encode(agent_id);
    if rows.iter().any(|e| e.agent_id != ours) {
        return refused("rows signed for another agent id".to_string());
    }
    let id = first.entry_hash.clone();
    let named = match named_head(first) {
        Ok(n) => n,
        Err(why) => return refused(why),
    };
    // one pass over the audit log: has it recorded this chain before, and is
    // the head the chain names this log's?
    let mut recorded_at = None;
    let mut head_found = matches!(&named, Some((0, h)) if h == GENESIS_PREV_HASH);
    let scanned = log.scan_rows(|i, e| {
        if e.op == RECOVERED_OP && e.extra["fallback"].as_str() == Some(id.as_str()) {
            recorded_at = Some(i);
            return std::ops::ControlFlow::Break(());
        }
        if let Some((n, h)) = &named {
            if *n > 0 && i == n - 1 && e.entry_hash == *h {
                head_found = true;
            }
        }
        std::ops::ControlFlow::Continue(())
    });
    if let Err(e) = scanned {
        return refused(format!(
            "the audit log could not be read to check it: {e:#}"
        ));
    }
    if let Some(i) = recorded_at {
        return json!({
            "verified": false,
            "fallback": id,
            "why": format!("recorded in the audit log already (row {i}): a copy put back"),
        });
    }
    if let (Some((n, _)), false) = (&named, head_found) {
        return json!({
            "verified": false,
            "fallback": id,
            "why": format!(
                "it names the audit log's head at row {n}, which this audit log does not hold: \
                 written against another log"
            ),
        });
    }
    let refused_boots: Vec<&AuditEntry> = rows
        .iter()
        .filter(|e| e.op == "agent_boot" && e.result == "refused")
        .collect();
    let listed: Vec<Value> = refused_boots
        .iter()
        .take(MAX_LISTED)
        .map(|e| {
            json!({
                "ts": e.ts,
                "refused_by": e.extra.get("refused_by"),
                "detail": e.extra.get("detail"),
                "binary_integrity": e.extra.get("binary_integrity"),
                "entry_hash": e.entry_hash,
            })
        })
        .collect();
    json!({
        "verified": true,
        "fallback": id,
        "audit_head": first.extra["audit_head"],
        "rows": rows.len(),
        "head": rows.last().map(|e| e.entry_hash.clone()),
        "refused_boots": refused_boots.len(),
        "listed": listed,
    })
}

/// The [`RECOVERED_OP`] row, `extra` with the file's path.
fn write_recovered(log: &mut AuditLog, path: &Path, mut extra: Value) -> Result<String, String> {
    extra["file"] = Value::String(path.display().to_string());
    let verified = extra["verified"].as_bool() == Some(true);
    if verified {
        error!(
            path = %path.display(),
            refused_boots = %extra["refused_boots"],
            "boot refusals the audit log could not take are recorded in it now (their fallback \
             chain verified)"
        );
    } else {
        error!(
            path = %path.display(),
            why = %extra["why"],
            "a fallback chain of boot refusals that does not verify, or a file that is not one — \
             recorded and removed"
        );
    }
    log.append(AuditEntryDraft {
        op: RECOVERED_OP.to_string(),
        extra,
        key_fp: "agent-self".to_string(),
        cosigner_fps: Vec::new(),
        result: if verified { "recorded" } else { "refused" }.to_string(),
        client_pid: log.self_pid(),
        client_uid: 0,
        client_comm: "northnarrow-agent".to_string(),
        client_exe: None,
    })
    .map(|e| e.entry_hash)
    .map_err(|e| format!("{e:#}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use northnarrow_agent::audit::AgentSigningKey;
    use std::os::unix::fs::PermissionsExt;

    fn cli(dir: &Path, audit_log: &Path) -> Cli {
        let _env = super::super::cli::TEST_ENV.lock();
        let arg = |p: &Path| p.to_string_lossy().into_owned();
        Cli::try_parse_from([
            "northnarrow-agent".to_string(),
            "--agent-id-file".to_string(),
            arg(&dir.join("agent_id")),
            "--admin-pub".to_string(),
            arg(&dir.join("admin.pub")),
            "--signing-key-file".to_string(),
            arg(&dir.join("agent.sig.key")),
            "--audit-log-file".to_string(),
            arg(audit_log),
            "--pid-file".to_string(),
            arg(&dir.join("run/agent.pid")),
        ])
        .expect("a command line with the test's paths")
    }

    fn identity(dir: &Path) -> AgentIdentity {
        northnarrow_agent::agent_id::resolve(&dir.join("agent_id"))
    }

    fn gate(dir: &Path, id: [u8; 16]) -> OverlayGate {
        OverlayGate::new(
            &dir.join("admin.pub"),
            id,
            northnarrow_agent::config::overlay_floor::RollbackFloor::scan(
                &dir.join("audit.log"),
                &dir.join("agent.sig.key"),
            ),
        )
    }

    fn rows(path: &Path) -> Vec<Value> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    /// The start's key in `dir`, decided as the preflight decides it there:
    /// there (in any form), or a first install.
    fn start_key(dir: &Path) -> BootKey {
        let path = dir.join("agent.sig.key");
        let decision = if std::fs::symlink_metadata(&path).is_ok() {
            northnarrow_agent::boot::checks::KeyDecision::present_for_tests(&path)
        } else {
            northnarrow_agent::boot::checks::KeyDecision::first_install_for_tests()
        };
        BootKey::decided(&path, decision)
    }

    fn pk(dir: &Path) -> ed25519_dalek::VerifyingKey {
        northnarrow_agent::keys::boot_verifying_key(&dir.join("agent.sig.key")).expect("the key")
    }

    fn verifies(path: &Path, dir: &Path) {
        let report = northnarrow_agent::audit::verify_chain_file(path, &pk(dir), None).unwrap();
        assert!(report.broken.is_none(), "{report:?}");
    }

    /// `dir/run`, the pid file's directory, as the unit's runtime directory
    /// is: the agent's user's, closed to others.
    fn run_dir(dir: &Path) -> PathBuf {
        let run = dir.join("run");
        std::fs::DirBuilder::new().mode(0o700).create(&run).unwrap();
        run
    }

    /// A start whose audit log cannot take a refusal (a directory where it
    /// goes): the fallback chain is the one to take it.
    struct Fixture {
        dir: tempfile::TempDir,
        cli: Cli,
        id: AgentIdentity,
        gate: OverlayGate,
        key: BootKey,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let audit = dir.path().join("audit.log");
            std::fs::create_dir(&audit).unwrap();
            run_dir(dir.path());
            AgentSigningKey::load_or_bootstrap(&dir.path().join("agent.sig.key")).unwrap();
            let cli = cli(dir.path(), &audit);
            let id = identity(dir.path());
            let gate = gate(dir.path(), id.id);
            let key = start_key(dir.path());
            Fixture {
                dir,
                cli,
                id,
                gate,
                key,
            }
        }

        fn path(&self, name: &str) -> PathBuf {
            self.dir.path().join(name)
        }

        fn fallback(&self) -> PathBuf {
            fallback_dir(&self.cli).unwrap()
        }

        fn refuse(&self) -> Signed {
            refuse_with(&self.cli, &self.id, &self.gate, &self.key)
        }

        /// The audit log back (the directory removed), opened as the next
        /// start opens it.
        fn next_start(&self) -> AuditLog {
            let audit = self.path("audit.log");
            if audit.is_dir() {
                std::fs::remove_dir(&audit).unwrap();
            }
            let key = AgentSigningKey::load_or_bootstrap(&self.path("agent.sig.key")).unwrap();
            AuditLog::open(&audit, key, self.id.id).unwrap()
        }

        fn record(&self, log: &mut AuditLog) -> Vec<Result<String, String>> {
            record_fallback(
                log,
                &self.fallback(),
                Some(&pk(self.dir.path())),
                self.id.id,
            )
        }

        /// The files in the fallback directory.
        fn files(&self) -> Vec<PathBuf> {
            let mut v: Vec<PathBuf> = std::fs::read_dir(self.fallback())
                .map(|d| d.flatten().map(|e| e.path()).collect())
                .unwrap_or_default();
            v.sort();
            v
        }
    }

    fn refuse_with(cli: &Cli, id: &AgentIdentity, gate: &OverlayGate, key: &BootKey) -> Signed {
        let ctx = Context {
            cli,
            identity: id,
            overlay_gate: gate,
            integrity: UNCHECKED,
            key,
        };
        sign(
            &ctx,
            None,
            &Refusal::new("audit_log", "audit.log: Is a directory"),
        )
    }

    /// `f` on its own thread, done within five seconds: a FIFO opened
    /// without `O_NONBLOCK` waits for its other end.
    fn within_5s<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .expect("blocked for 5 s")
    }

    fn mkfifo(p: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap();
        // SAFETY: a NUL-terminated path that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    }

    /// The refusal is signed in the audit log, its last row the
    /// `agent_boot` `refused` naming the gate, with the degradation before
    /// it; the chain verifies.
    #[test]
    fn a_refusal_is_signed_in_the_audit_log() {
        let dir = tempfile::tempdir().unwrap();
        let audit = dir.path().join("audit.log");
        let cli = cli(dir.path(), &audit);
        let id = identity(dir.path());
        let gate_ = gate(dir.path(), id.id);
        let key = start_key(dir.path());
        let ctx = Context {
            cli: &cli,
            identity: &id,
            overlay_gate: &gate_,
            integrity: UNCHECKED,
            key: &key,
        };
        let r = Refusal::new("capabilities", "CAP_KILL missing").degraded("capabilities");
        let signed = sign(&ctx, None, &r);
        let Signed::AuditLog { entry_hash } = signed else {
            panic!("{signed:?}")
        };
        let rows = rows(&audit);
        let last = rows.last().unwrap();
        assert_eq!(last["op"], "agent_boot");
        assert_eq!(last["result"], "refused");
        assert_eq!(last["extra"]["refused_by"], "capabilities");
        assert_eq!(last["extra"]["detail"], "CAP_KILL missing");
        assert_eq!(last["extra"]["binary_integrity"], "unchecked");
        assert_eq!(last["entry_hash"], entry_hash.as_str());
        let before = &rows[rows.len() - 2];
        assert_eq!(before["extra"]["kind"], "subsystem_degraded");
        assert_eq!(before["extra"]["source"], "capabilities");
        verifies(&audit, dir.path());
        assert!(!fallback_dir(&cli).unwrap().exists(), "no fallback");
    }

    /// The audit log open before the load takes the refusal: one writer,
    /// one chain.
    #[test]
    fn a_refusal_goes_into_the_log_already_open() {
        let dir = tempfile::tempdir().unwrap();
        let audit = dir.path().join("audit.log");
        let cli = cli(dir.path(), &audit);
        let id = identity(dir.path());
        let gate_ = gate(dir.path(), id.id);
        let key = AgentSigningKey::load_or_bootstrap(&dir.path().join("agent.sig.key")).unwrap();
        let mut log = AuditLog::open(&audit, key, id.id).unwrap();
        let key = start_key(dir.path());
        let ctx = Context {
            cli: &cli,
            identity: &id,
            overlay_gate: &gate_,
            integrity: ("verified", "source-tree"),
            key: &key,
        };
        let signed = sign(
            &ctx,
            Some(&mut log),
            &Refusal::new("bpf_lsm", "bpf not active").degraded("bpf_lsm"),
        );
        assert!(matches!(signed, Signed::AuditLog { .. }), "{signed:?}");
        // the same writer goes on: the chain is one
        log.boot_probe(
            None,
            "verified",
            "source-tree",
            &northnarrow_agent::build_info::agent_build(),
        )
        .unwrap();
        verifies(&audit, dir.path());
        let rows = rows(&audit);
        assert_eq!(rows[rows.len() - 2]["extra"]["refused_by"], "bpf_lsm");
        assert_eq!(
            rows[rows.len() - 2]["extra"]["binary_integrity"],
            "verified"
        );
    }

    /// An audit log that cannot take the refusal (a directory there): a
    /// fallback chain of its own holds it — a new file, `0600`, in the
    /// directory beside --pid-file the agent created `0700` —, signed with
    /// the same key, its first row naming the audit log it stands in for
    /// and that its head could not be read.
    #[test]
    fn an_unwritable_audit_log_sends_the_refusal_to_a_fallback_chain_of_its_own() {
        let f = Fixture::new();
        let Signed::Fallback {
            path, entry_hash, ..
        } = f.refuse()
        else {
            panic!("not in a fallback chain")
        };
        assert_eq!(path.parent().unwrap(), f.fallback());
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            name.starts_with("refusal-") && name.ends_with(".jsonl"),
            "{name}"
        );
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(&f.fallback()), 0o700);
        let fb = rows(&path);
        let first = &fb[0];
        assert_eq!(first["op"], FALLBACK_OPENED_OP);
        assert_eq!(first["prev_hash"], GENESIS_PREV_HASH);
        assert_eq!(
            first["extra"]["audit_log"],
            f.path("audit.log").display().to_string()
        );
        assert!(first["extra"]["audit_head"].is_null(), "{first}");
        assert!(
            first["extra"]["audit_head_unreadable"]
                .as_str()
                .is_some_and(|w| w.contains("a directory")),
            "{first}"
        );
        let last = fb.last().unwrap();
        assert_eq!(last["op"], "agent_boot");
        assert_eq!(last["result"], "refused");
        assert_eq!(last["extra"]["refused_by"], "audit_log");
        assert_eq!(last["entry_hash"], entry_hash.as_str());
        verifies(&path, f.dir.path());
        // a second refusal: a second file, never the first one again
        let Signed::Fallback { path: second, .. } = f.refuse() else {
            panic!("not in a fallback chain")
        };
        assert_ne!(second, path);
        assert_eq!(f.files().len(), 2);
    }

    /// A log that opened but cannot take the row (its write fails): the
    /// fallback chain, naming the head the open log had.
    #[test]
    fn a_failed_write_sends_the_refusal_to_the_fallback_chain_with_the_logs_head() {
        let dir = tempfile::tempdir().unwrap();
        let audit = dir.path().join("audit.log");
        run_dir(dir.path());
        let cli = cli(dir.path(), &audit);
        let id = identity(dir.path());
        let gate_ = gate(dir.path(), id.id);
        let key = AgentSigningKey::load_or_bootstrap(&dir.path().join("agent.sig.key")).unwrap();
        let mut log = AuditLog::open(&audit, key, id.id).unwrap();
        // a directory where the log goes, after the open (which creates no
        // file): every append fails
        std::fs::create_dir(&audit).unwrap();
        let key = start_key(dir.path());
        let ctx = Context {
            cli: &cli,
            identity: &id,
            overlay_gate: &gate_,
            integrity: UNCHECKED,
            key: &key,
        };
        let signed = sign(
            &ctx,
            Some(&mut log),
            &Refusal::new("audit_log", "write failed"),
        );
        let Signed::Fallback { path, .. } = signed else {
            panic!("{signed:?}")
        };
        let first = &rows(&path)[0];
        assert_eq!(first["extra"]["audit_head"]["rows"], 0);
        assert_eq!(
            first["extra"]["audit_head"]["entry_hash"],
            GENESIS_PREV_HASH
        );
    }

    /// Without --pid-file, or with a relative one, and with an audit log
    /// that cannot take it, the refusal is in the journal alone, and says
    /// why.
    #[test]
    fn without_a_fallback_the_refusal_is_unsigned_and_says_why() {
        let f = Fixture::new();
        for pid_file in [None, Some(PathBuf::from("agent.pid"))] {
            let mut cli = cli(f.dir.path(), &f.path("audit.log"));
            cli.pid_file = pid_file;
            assert_eq!(fallback_dir(&cli), None);
            let signed = refuse_with(&cli, &f.id, &f.gate, &f.key);
            assert!(
                matches!(&signed, Signed::Unsigned(why) if why.contains("--pid-file")),
                "{signed:?}"
            );
        }
    }

    /// The next start that opens the audit log records the fallback chain
    /// there, verified and bound — the chain's id, the head it named —, and
    /// removes the file; a second look finds nothing.
    #[test]
    fn the_next_start_records_the_fallback_chain_in_the_audit_log() {
        let f = Fixture::new();
        let Signed::Fallback {
            path, entry_hash, ..
        } = f.refuse()
        else {
            panic!("not in a fallback chain")
        };
        let id = rows(&path)[0]["entry_hash"].as_str().unwrap().to_string();
        let mut log = f.next_start();
        let recorded = f.record(&mut log);
        assert_eq!(recorded.len(), 1, "{recorded:?}");
        let hash = recorded[0].clone().expect("recorded");
        assert!(
            !path.exists(),
            "the fallback chain is removed once recorded"
        );
        let main = rows(&f.path("audit.log"));
        let row = main.last().unwrap();
        assert_eq!(row["op"], RECOVERED_OP);
        assert_eq!(row["result"], "recorded");
        assert_eq!(row["entry_hash"], hash.as_str());
        assert_eq!(row["extra"]["verified"], true, "{row}");
        assert_eq!(row["extra"]["fallback"], id.as_str());
        assert!(row["extra"]["audit_head"].is_null());
        assert_eq!(row["extra"]["refused_boots"], 1);
        assert_eq!(row["extra"]["head"], entry_hash.as_str());
        assert_eq!(row["extra"]["listed"][0]["refused_by"], "audit_log");
        assert_eq!(row["extra"]["listed"][0]["entry_hash"], entry_hash.as_str());
        assert_eq!(row["extra"]["file"], path.display().to_string());
        verifies(&f.path("audit.log"), f.dir.path());
        assert!(f.record(&mut log).is_empty());
    }

    /// The head a fallback chain names must be this log's: a chain written
    /// while the log had one row is recorded against that log, and refused
    /// against another chain at the same path.
    #[test]
    fn a_fallback_chain_is_bound_to_the_log_whose_head_it_names() {
        for same_log in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let audit = dir.path().join("audit.log");
            run_dir(dir.path());
            let cli = cli(dir.path(), &audit);
            let id = identity(dir.path());
            let gate_ = gate(dir.path(), id.id);
            let key = || AgentSigningKey::load_or_bootstrap(&dir.path().join("agent.sig.key"));
            let build = northnarrow_agent::build_info::agent_build();
            {
                let mut log = AuditLog::open(&audit, key().unwrap(), id.id).unwrap();
                log.boot_probe(None, "none", "none", &build).unwrap();
            }
            // the log opens (one row), then cannot take the refusal: the
            // fallback chain names its head, (1, that row's hash)
            let mut open = AuditLog::open(&audit, key().unwrap(), id.id).unwrap();
            let aside = dir.path().join("aside.log");
            std::fs::rename(&audit, &aside).unwrap();
            std::fs::create_dir(&audit).unwrap();
            let start = start_key(dir.path());
            let ctx = Context {
                cli: &cli,
                identity: &id,
                overlay_gate: &gate_,
                integrity: UNCHECKED,
                key: &start,
            };
            let signed = sign(&ctx, Some(&mut open), &Refusal::new("audit_log", "x"));
            let Signed::Fallback { path, .. } = signed else {
                panic!("{signed:?}")
            };
            let named = &rows(&path)[0]["extra"]["audit_head"];
            assert_eq!(named["rows"], 1, "{named}");
            assert_eq!(named["entry_hash"], rows(&aside)[0]["entry_hash"]);
            std::fs::remove_dir(&audit).unwrap();
            if same_log {
                std::fs::rename(&aside, &audit).unwrap();
            } else {
                // another chain at the same path: its row is another one
                let mut other = AuditLog::open(&audit, key().unwrap(), id.id).unwrap();
                other.boot_probe(Some("x"), "none", "none", &build).unwrap();
            }
            let mut log = AuditLog::open(&audit, key().unwrap(), id.id).unwrap();
            let r = record_fallback(
                &mut log,
                &fallback_dir(&cli).unwrap(),
                Some(&pk(dir.path())),
                id.id,
            );
            assert!(r[0].is_ok(), "{r:?}");
            let row = rows(&audit).last().unwrap().clone();
            assert_eq!(row["extra"]["verified"], same_log, "{row}");
            if !same_log {
                assert!(
                    row["extra"]["why"]
                        .as_str()
                        .is_some_and(|w| w.contains("written against another log")),
                    "{row}"
                );
            }
        }
    }

    /// Review #466 F2: what was recorded once is not recorded again — a
    /// copy of a recorded chain put back is refused as such; a prefix of
    /// the audit log (a chain signed by the same key, from the genesis) is
    /// not a fallback chain; rows signed for another agent id are not this
    /// agent's.
    #[test]
    fn no_copy_no_prefix_of_the_audit_log_no_other_agents_chain_is_recorded() {
        let f = Fixture::new();
        let Signed::Fallback { path, .. } = f.refuse() else {
            panic!("not in a fallback chain")
        };
        let copy = std::fs::read(&path).unwrap();
        let mut log = f.next_start();
        assert!(f.record(&mut log)[0].is_ok());
        let last_why = |f: &Fixture| {
            let row = rows(&f.path("audit.log")).last().unwrap().clone();
            assert_eq!(row["op"], RECOVERED_OP);
            assert_eq!(row["result"], "refused", "{row}");
            assert!(row["extra"].get("listed").is_none(), "{row}");
            row["extra"]["why"].as_str().unwrap_or_default().to_string()
        };
        let plant = |f: &Fixture, name: &str, bytes: &[u8]| {
            let p = f.fallback().join(name);
            std::fs::write(&p, bytes).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        };
        // the copy, put back
        plant(&f, "refusal-copy.jsonl", &copy);
        assert!(f.record(&mut log)[0].is_ok());
        assert!(last_why(&f).contains("a copy put back"), "{}", last_why(&f));
        // a prefix of the audit log
        let main = std::fs::read(f.path("audit.log")).unwrap();
        plant(&f, "refusal-prefix.jsonl", &main);
        assert!(f.record(&mut log)[0].is_ok());
        assert!(
            last_why(&f).contains("not a fallback chain's"),
            "{}",
            last_why(&f)
        );
        // the agent's key, another agent id
        let key = AgentSigningKey::load_or_bootstrap(&f.path("agent.sig.key")).unwrap();
        let mut other = AuditLog::in_memory(key, [9; 16]);
        open_fallback(&mut other, &f.cli, &Err("x".into()), "y").unwrap();
        plant(&f, "refusal-other.jsonl", &other.into_bytes());
        assert!(f.record(&mut log)[0].is_ok());
        assert!(
            last_why(&f).contains("another agent id"),
            "{}",
            last_why(&f)
        );
        assert!(f.files().is_empty(), "every one removed: {:?}", f.files());
        verifies(&f.path("audit.log"), f.dir.path());
    }

    /// A fallback chain that does not verify (here: another key's) is
    /// recorded as refused, with why and none of its contents, and removed.
    #[test]
    fn a_fallback_chain_that_does_not_verify_is_recorded_and_removed() {
        let f = Fixture::new();
        let other = tempfile::tempdir().unwrap();
        let key = AgentSigningKey::load_or_bootstrap(&other.path().join("k")).unwrap();
        let mut forged = AuditLog::in_memory(key, f.id.id);
        open_fallback(&mut forged, &f.cli, &Err("x".into()), "y").unwrap();
        forged
            .boot_refused_by(
                "install_manifest",
                "mismatch",
                "none",
                "forged",
                &northnarrow_agent::build_info::agent_build(),
            )
            .unwrap();
        let fallback = FallbackDir::open(&f.fallback(), true).unwrap();
        let path = fallback.create(&forged.into_bytes()).unwrap();
        let mut log = f.next_start();
        assert!(f.record(&mut log)[0].is_ok());
        assert!(!path.exists());
        let row = rows(&f.path("audit.log")).last().unwrap().clone();
        assert_eq!(row["result"], "refused");
        assert_eq!(row["extra"]["verified"], false);
        assert!(
            row["extra"]["why"]
                .as_str()
                .is_some_and(|w| w.contains("signature does not verify")),
            "{row}"
        );
        assert!(!row.to_string().contains("forged"), "{row}");
    }

    // ── review #466 F1: names planted where the fallback chain goes ──

    /// The reviewer's probe 1: a symbolic link to the agent's key where the
    /// fallback directory goes. Nothing is followed: the refusal is
    /// unsigned, says what it found, and the key is in no message and
    /// unchanged. Inside the directory, the same link is not read at the
    /// next start: recorded as refused, the link removed, the key intact.
    #[test]
    fn a_link_to_the_key_is_never_followed() {
        let f = Fixture::new();
        let key = f.path("agent.sig.key");
        // root opens a 0400 file for writing all the same (CAP_DAC_OVERRIDE):
        // the test user stands in for it with 0600
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let key_text = std::fs::read_to_string(&key).unwrap();
        std::os::unix::fs::symlink(&key, f.fallback()).unwrap();
        let signed = f.refuse();
        let Signed::Unsigned(why) = &signed else {
            panic!("{signed:?}")
        };
        assert!(why.contains("a symbolic link"), "{why}");
        assert!(!why.contains(key_text.trim()), "{why}");
        assert_eq!(std::fs::read_to_string(&key).unwrap(), key_text);
        // the next start records that the directory is not the agent's, and
        // leaves the key alone
        // a refusal with the directory the agent's: a new file of its own,
        // the name planted in it never opened
        std::fs::remove_file(f.fallback()).unwrap();
        FallbackDir::open(&f.fallback(), true).unwrap();
        std::os::unix::fs::symlink(&key, f.fallback().join("refusal-0.jsonl")).unwrap();
        assert!(matches!(f.refuse(), Signed::Fallback { .. }));
        assert_eq!(std::fs::read_to_string(&key).unwrap(), key_text);
        assert_eq!(f.files().len(), 2);
        // the next start: the link inside is not read, the chain is recorded
        let mut log = f.next_start();
        let r = f.record(&mut log);
        assert_eq!(r.len(), 2, "{r:?}");
        let main = rows(&f.path("audit.log"));
        assert!(
            main.iter().any(|r| r["extra"]["verified"] == true),
            "{main:?}"
        );
        assert!(!format!("{main:?}").contains(key_text.trim()));
        assert!(f.files().is_empty());
        assert_eq!(std::fs::read_to_string(&key).unwrap(), key_text);
        // a directory that is not the agent's: recorded, the key left alone
        std::fs::remove_dir(f.fallback()).unwrap();
        std::os::unix::fs::symlink(&key, f.fallback()).unwrap();
        let r = f.record(&mut log);
        assert!(r[0].is_ok(), "{r:?}");
        let row = rows(&f.path("audit.log")).last().unwrap().clone();
        assert_eq!(row["result"], "refused");
        assert!(!row.to_string().contains(key_text.trim()), "{row}");
        assert_eq!(std::fs::read_to_string(&key).unwrap(), key_text);
        // inside the directory
        std::fs::remove_file(f.fallback()).unwrap();
        FallbackDir::open(&f.fallback(), true).unwrap();
        std::os::unix::fs::symlink(&key, f.fallback().join("refusal-0.jsonl")).unwrap();
        assert!(f.record(&mut log)[0].is_ok());
        let row = rows(&f.path("audit.log")).last().unwrap().clone();
        assert_eq!(
            row["extra"]["why"], "a symbolic link, not followed",
            "{row}"
        );
        assert!(!row.to_string().contains(key_text.trim()), "{row}");
        assert!(f.files().is_empty(), "the link is removed");
        assert_eq!(std::fs::read_to_string(&key).unwrap(), key_text);
    }

    /// The reviewer's probe 2: a symbolic link to a file whose last line has
    /// no newline. It is neither truncated nor given a newline, and its
    /// lines are in no message — where the directory goes, and inside it.
    #[test]
    fn a_link_to_a_file_without_a_final_newline_changes_nothing() {
        let f = Fixture::new();
        let target = f.path("protected.json");
        let body = b"{\"first\":1}\n{\"second\": \"no newline\"";
        std::fs::write(&target, body).unwrap();
        std::os::unix::fs::symlink(&target, f.fallback()).unwrap();
        let signed = f.refuse();
        let Signed::Unsigned(why) = &signed else {
            panic!("{signed:?}")
        };
        assert!(!why.contains("first") && !why.contains("second"), "{why}");
        assert_eq!(std::fs::read(&target).unwrap(), body);
        std::fs::remove_file(f.fallback()).unwrap();
        FallbackDir::open(&f.fallback(), true).unwrap();
        std::os::unix::fs::symlink(&target, f.fallback().join("refusal-1.jsonl")).unwrap();
        let mut log = f.next_start();
        assert!(f.record(&mut log)[0].is_ok());
        let row = rows(&f.path("audit.log")).last().unwrap().clone();
        assert!(!row.to_string().contains("no newline"), "{row}");
        assert_eq!(std::fs::read(&target).unwrap(), body);
    }

    /// The reviewer's probe 3: a dangling symbolic link — where the
    /// directory goes, and as the pid file's directory itself. Its target
    /// is not created, nor anything in it.
    #[test]
    fn a_dangling_link_creates_nothing() {
        let f = Fixture::new();
        let elsewhere = f.path("nocreate-dir");
        std::fs::create_dir(&elsewhere).unwrap();
        std::os::unix::fs::symlink(elsewhere.join("planted"), f.fallback()).unwrap();
        let signed = f.refuse();
        assert!(
            matches!(&signed, Signed::Unsigned(why) if why.contains("a symbolic link")),
            "{signed:?}"
        );
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
        // a link to a directory the agent could write: not followed either
        std::fs::remove_file(f.fallback()).unwrap();
        std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&elsewhere, f.fallback()).unwrap();
        let signed = f.refuse();
        assert!(
            matches!(&signed, Signed::Unsigned(why) if why.contains("a symbolic link")),
            "{signed:?}"
        );
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
        // the pid file's directory a link to another directory: not followed
        std::fs::remove_file(f.fallback()).unwrap();
        std::fs::remove_dir(f.path("run")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, f.path("run")).unwrap();
        let signed = f.refuse();
        assert!(
            matches!(&signed, Signed::Unsigned(why) if why.contains("directory of --pid-file")),
            "{signed:?}"
        );
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
    }

    /// The reviewer's probe 4: a FIFO where the directory goes, and one in
    /// it. Nothing waits on it: the refusal returns at once, unsigned, and
    /// the next start records the FIFO as refused and removes it.
    #[test]
    fn a_fifo_blocks_nothing() {
        let f = Fixture::new();
        mkfifo(&f.fallback());
        let (f, signed) = within_5s(move || {
            let s = f.refuse();
            (f, s)
        });
        assert!(
            matches!(&signed, Signed::Unsigned(why) if why.contains("a FIFO")),
            "{signed:?}"
        );
        std::fs::remove_file(f.fallback()).unwrap();
        FallbackDir::open(&f.fallback(), true).unwrap();
        mkfifo(&f.fallback().join("refusal-2.jsonl"));
        let log = f.next_start();
        let (f, r) = within_5s(move || {
            let mut log = log;
            let r = f.record(&mut log);
            (f, r)
        });
        assert!(r[0].is_ok(), "{r:?}");
        let row = rows(&f.path("audit.log")).last().unwrap().clone();
        assert!(
            row["extra"]["why"]
                .as_str()
                .is_some_and(|w| w.contains("a FIFO")),
            "{row}"
        );
        assert!(f.files().is_empty());
    }

    /// The directory and its files are the agent's alone: a directory open
    /// to others refuses the fallback (and is recorded, left, at the next
    /// start); a file open to others, a hard link and a file over the bound
    /// are recorded as refused and removed — the hard link's other name
    /// untouched.
    #[test]
    fn the_fallback_directory_and_its_files_are_the_agents_alone() {
        let f = Fixture::new();
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(f.fallback())
            .unwrap();
        std::fs::set_permissions(f.fallback(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let signed = f.refuse();
        assert!(
            matches!(&signed, Signed::Unsigned(why) if why.contains("open to its group or others")),
            "{signed:?}"
        );
        let mut log = f.next_start();
        assert!(f.record(&mut log)[0].is_ok());
        assert!(
            f.fallback().is_dir(),
            "a directory that is not the agent's is left"
        );
        std::fs::set_permissions(f.fallback(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let open = f.fallback().join("refusal-open.jsonl");
        std::fs::write(&open, b"{}\n").unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o644)).unwrap();
        let other = f.path("other-name");
        std::fs::write(&other, b"kept\n").unwrap();
        std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&other, f.fallback().join("refusal-link.jsonl")).unwrap();
        let big = f.fallback().join("refusal-big.jsonl");
        std::fs::write(&big, vec![b'x'; MAX_FALLBACK_BYTES as usize + 1]).unwrap();
        std::fs::set_permissions(&big, std::fs::Permissions::from_mode(0o600)).unwrap();
        let r = f.record(&mut log);
        assert_eq!(r.len(), 3, "{r:?}");
        let main = rows(&f.path("audit.log"));
        let whys: Vec<String> = main[main.len() - 3..]
            .iter()
            .map(|r| r["extra"]["why"].as_str().unwrap_or_default().to_string())
            .collect();
        assert!(whys.iter().any(|w| w.contains("bytes, over")), "{whys:?}");
        assert!(whys.iter().any(|w| w.contains("2 hard links")), "{whys:?}");
        assert!(
            whys.iter()
                .any(|w| w.contains("open to its group or others")),
            "{whys:?}"
        );
        assert!(f.files().is_empty());
        assert_eq!(std::fs::read(&other).unwrap(), b"kept\n");
    }

    /// Review #466 F7: a refused start signs its refusal, then withdraws its
    /// registration under the pinned root — once, signed or not — and exits
    /// 78 (`EX_CONFIG`, a `failed` unit).
    #[test]
    fn a_refusal_signs_withdraws_the_registration_and_exits_78() {
        assert_eq!(EX_CONFIG, 78);
        let f = Fixture::new();
        let ctx = Context {
            cli: &f.cli,
            identity: &f.id,
            overlay_gate: &f.gate,
            integrity: UNCHECKED,
            key: &f.key,
        };
        let mut withdrawn = Vec::new();
        let code = ctx.conclude(None, Refusal::new("audit_log", "x"), |root| {
            withdrawn.push(root.to_path_buf());
        });
        assert_eq!(code, 78);
        assert_eq!(
            withdrawn,
            vec![PathBuf::from(
                northnarrow_agent::anti_tamper::DEFAULT_BPFFS_ROOT
            )]
        );
        assert_eq!(f.files().len(), 1, "signed before the withdrawal");
        // unsigned (no fallback either): withdrawn and 78 all the same
        let mut cli = cli(f.dir.path(), &f.path("audit.log"));
        cli.pid_file = None;
        let ctx = Context { cli: &cli, ..ctx };
        let mut withdrawn = 0;
        assert_eq!(
            ctx.conclude(None, Refusal::new("audit_log", "y"), |_| withdrawn += 1),
            78
        );
        assert_eq!(withdrawn, 1);
    }

    /// Lab PR 265 (review #466 F4-bis): a refusal nothing can sign — the
    /// agent's directories mounted over, its key absent beside an earlier
    /// identity — writes nothing (no chain, no fallback, no key), withdraws
    /// the registration under the pinned root once and exits 78, as every
    /// refusal.
    #[test]
    fn an_unsigned_refusal_writes_nothing_withdraws_and_exits_78() {
        let f = Fixture::new();
        let before: Vec<_> = std::fs::read_dir(f.dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        for gate in ["agent_mounts", "signing_identity"] {
            let mut withdrawn = Vec::new();
            let code = conclude_unsigned(Refusal::new(gate, "x"), "nothing can sign it", |root| {
                withdrawn.push(root.to_path_buf());
            });
            assert_eq!(code, EX_CONFIG);
            assert_eq!(
                withdrawn,
                vec![PathBuf::from(
                    northnarrow_agent::anti_tamper::DEFAULT_BPFFS_ROOT
                )],
                "{gate}"
            );
        }
        let after: Vec<_> = std::fs::read_dir(f.dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert_eq!(before, after, "an unsigned refusal wrote a file");
        assert!(f.files().is_empty(), "a fallback chain");
    }

    /// No pinned map: nothing to withdraw, nothing touched.
    #[test]
    fn no_pinned_map_no_withdrawal() {
        let dir = tempfile::tempdir().unwrap();
        withdraw_registration(dir.path());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}
