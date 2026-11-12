//! `Quarantine` — encrypt a target's executable into a vault and
//! remove the original file.
//!
//! Vault layout:
//! ```text
//! <quarantine_dir>/
//! ├── index.json          (mode 0600; atomic write via tmp+rename)
//! └── vault/
//!     ├── <uuid>.bin      (AES-256-GCM record, mode 0600)
//!     └── <uuid>.meta     (JSON metadata, mode 0600)
//! ```
//!
//! Crypto (R14c: the key store's, `crate::keys::vault` — this module seals
//! and opens records through [`ExecutorConfig::vault`] and never holds the
//! key):
//! - Master key: 32 random bytes at [`ExecutorConfig::master_key_file`],
//!   created mode 0600 on first use, then held by the key store in memory
//!   of its own (`mlock`, `MADV_DONTDUMP`, zeroed when dropped).
//! - Per-file derivation: HKDF-SHA256 with the format's salt and per-file
//!   info equal to the vault id. This means a leaked file-key can decrypt
//!   only its own ciphertext.
//! - Per-file nonce: 96 random bits, fresh per encryption.
//!
//! Record formats of the `.bin` (lab PR 238):
//! - **v2**, written since lab PR 238: `"NNQV" ‖ 0x02 ‖ nonce (12) ‖
//!   ciphertext ‖ tag (16)`, the key salted `"northnarrow-quarantine-v2"`,
//!   the header and the vault id authenticated with it (associated data
//!   `"NNQV" ‖ 0x02 ‖ vault id`): a record cannot be passed off as another
//!   format or another entry's. Its `.meta` says `"format": 2`.
//! - **v1**, written before: `nonce (12) ‖ ciphertext ‖ tag (16)`, no
//!   header (the format was only the salt's `"northnarrow-quarantine-v1"`),
//!   the vault id as associated data; its `.meta` names no format. Read,
//!   never written.
//!
//! A `.meta` naming a format this agent does not read, or a `.bin` whose
//! header disagrees with it, is refused before anything is decrypted.
//!
//! [`restore`] reverses the operation: decrypts the vault file and
//! writes it to a new file (never over an existing one, never through a
//! link), after checking it against the SHA-256 recorded at capture.
//! The vault entry stays.

use std::collections::{BTreeMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use rand::Rng;
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use super::{config::ExecutorConfig, ExecutionOutcome};
use crate::keys::vault::{bad_record, record_format, RECORD_V2};

/// R14c: the vault `cfg` seals and opens through — the key store's
/// ([`ExecutorConfig::vault`]). Review of #482 (R14c-5): a configuration
/// without it reads no master key of its own in the agent's builds — the
/// quarantine fails, said; the tests' builds make one for its path.
fn vault_of(
    cfg: &ExecutorConfig,
) -> std::io::Result<std::sync::Arc<dyn nn_core::response::config::VaultKey>> {
    if let Some(v) = &cfg.vault {
        return Ok(std::sync::Arc::clone(v));
    }
    #[cfg(any(test, feature = "test-util"))]
    {
        Ok(std::sync::Arc::new(crate::keys::vault::for_tests(
            &cfg.master_key_file,
        )))
    }
    #[cfg(not(any(test, feature = "test-util")))]
    {
        Err(std::io::Error::other(
            "no vault: the key store's is not in the executor's configuration (the master key \
             is read by the key store only)",
        ))
    }
}

/// Paths that are NEVER quarantined, whatever the verdict says.
///
/// `quarantine_file` unlinks the original after vaulting it. For a
/// system binary (`/usr/bin/bash` abused by `bash -c`, `systemd`,
/// `sshd`), a kernel image, a config tree, or NorthNarrow's own
/// binaries/state, that unlink makes the host unbootable, locks the
/// operator out, or disables the agent itself — a self-inflicted
/// denial of service that a malformed event, a wrong rule or an
/// upstream bug can trigger. Malware living under these prefixes is
/// still handled by KillProcess / KillProcessTree; it just cannot be
/// removed from disk by the executor. A prefix ending in `/` matches
/// a directory subtree; one without matches as a filename prefix
/// (`/usr/local/bin/northnarrow-` covers agent + watchdog).
const QUARANTINE_DENY_PREFIXES: &[&str] = &[
    "/bin/",
    "/sbin/",
    "/lib/",
    "/lib32/",
    "/lib64/",
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/lib/",
    "/usr/lib32/",
    "/usr/lib64/",
    "/usr/libexec/",
    "/etc/",
    "/boot/",
    "/proc/",
    "/sys/",
    "/dev/",
    "/usr/local/bin/northnarrow-",
    "/usr/local/bin/nn-admin",
    "/var/lib/northnarrow/",
    "/run/northnarrow/",
];

/// `true` when `path` must never be vaulted + unlinked under `cfg`. Lexical
/// check on the path of the inode itself ([`ExeHandle::current_path`]:
/// absolute and symlink-free at the moment it is read): the fixed
/// prefixes ([`is_quarantine_denied`]) and, external audit CMB-025, the
/// agent's own files where this host keeps them (`cfg.own_files`, made by
/// [`own_files`] at boot; R11c, lab PR 264: they were a process-wide
/// `RUNTIME_DENY`).
pub fn is_denied_by(cfg: &ExecutorConfig, path: &Path) -> bool {
    is_quarantine_denied(path) || cfg.own_files.denies(path)
}

/// The fixed prefixes alone ([`QUARANTINE_DENY_PREFIXES`]).
pub fn is_quarantine_denied(path: &Path) -> bool {
    let p = path.to_string_lossy();
    QUARANTINE_DENY_PREFIXES.iter().any(|d| p.starts_with(d))
}

/// External audit CMB-025: the agent's own files, wherever this host keeps
/// them (nn-core's [`OwnFiles`], the executor configuration's
/// `own_files`).
pub use nn_core::response::config::OwnFiles;

/// Each path as given and, where it differs, as it resolves now.
fn with_canonical(paths: impl IntoIterator<Item = PathBuf>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for p in paths {
        if let Ok(c) = p.canonicalize() {
            if c != p {
                out.push(c);
            }
        }
        out.push(p);
    }
    out
}

/// The agent's own files for this run: `own_exe` (`current_exe()`),
/// `watchdog_exe` (`--watchdog-exe`, or the sibling default) and `cfg`'s
/// master key, vault and containment record, each as given and as it
/// resolves now.
pub fn own_files(cfg: &ExecutorConfig, own_exe: Option<&Path>, watchdog_exe: &Path) -> OwnFiles {
    let own = own_exe.map(Path::to_path_buf);
    let files = with_canonical(own.iter().cloned().chain([
        watchdog_exe.to_path_buf(),
        cfg.master_key_file.clone(),
        cfg.containment_file.clone(),
    ]));
    let install_dirs = with_canonical(own.iter().filter_map(|p| p.parent().map(Path::to_path_buf)));
    OwnFiles {
        files,
        dirs: with_canonical([cfg.quarantine_dir.clone()]),
        install_dirs,
    }
}

/// External audit CMB-001: a binary to quarantine, held open — the inode a
/// process ran, not a name. The quarantine used to resolve
/// `/proc/<pid>/exe` once and then check the denylist, read, and unlink BY
/// NAME: a user who owns a directory of their own binary's path could swap
/// it for a symlink in between and have the agent (root, CAP_DAC_OVERRIDE)
/// vault and delete any file. Opened through `/proc/<pid>/exe`, the
/// kernel's link to the inode, the content read and the size checked are
/// the binary's whatever becomes of its path; the denylist is judged on the
/// inode's own path ([`Self::current_path`]) and the removal is verified
/// against it ([`remove_verified`]).
pub struct ExeHandle {
    file: fs::File,
    dev: u64,
    ino: u64,
    /// Lot 312 (review F1): the uid the offender acted as (its `fsuid`,
    /// read with the binary): a file it owns, with no other name, is the
    /// only one whose content a quarantine destroys. `None` when unknown:
    /// never destroyed.
    offender_uid: Option<u32>,
    /// Tests: no name of the inode verifies (as through another mount
    /// namespace's bind mount).
    #[cfg(test)]
    unverifiable: bool,
}

impl ExeHandle {
    /// The executable `pid` runs, opened through `/proc/<pid>/exe` — the
    /// kernel's link to the inode, whatever became of its names.
    /// `Ok(None)` once the process has exited (or for a kernel thread,
    /// which runs none). Lot 312 (external bug hunt 1.4, BUG-90): a binary
    /// whose name was removed while it ran is still opened, and whether it
    /// is gone is the inode's to say ([`Self::unlinked`]). The kernel's
    /// ` (deleted)` suffix decided it here: a payload on disk named
    /// `x (deleted)` was "nothing on disk to quarantine", and NEUTRALIZE
    /// left it runnable.
    pub fn of_pid(pid: u32) -> std::io::Result<Option<Self>> {
        match fs::File::open(format!("/proc/{pid}/exe")) {
            Ok(f) => {
                let uid = fsuid_of(pid);
                Self::from_file(f).map(|h| Some(h.with_offender_uid(uid)))
            }
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// The file at `path` (tests, tools), the caller standing for the
    /// offender (its effective uid).
    pub fn open(path: &Path) -> std::io::Result<Self> {
        // SAFETY: geteuid(2) takes no argument and cannot fail.
        let me = unsafe { libc::geteuid() };
        Self::from_file(fs::File::open(path)?).map(|h| h.with_offender_uid(Some(me)))
    }

    /// Lot 312 (review F1): the uid the offender acted as ([`Self::of_pid`]
    /// reads it; the exec quarantine knows it from the exec it held).
    pub fn with_offender_uid(mut self, uid: Option<u32>) -> Self {
        self.offender_uid = uid;
        self
    }

    /// A file already open (lab PR 223: the exec quarantine vaults the very
    /// inode its scanner judged, opened through `/proc/<pid>/exe` while the
    /// process was held).
    pub fn from_open_file(file: fs::File) -> std::io::Result<Self> {
        Self::from_file(file)
    }

    fn from_file(file: fs::File) -> std::io::Result<Self> {
        let m = file.metadata()?;
        Ok(Self {
            dev: m.dev(),
            ino: m.ino(),
            file,
            offender_uid: None,
            #[cfg(test)]
            unverifiable: false,
        })
    }

    /// Tests: a handle no name of which verifies.
    #[cfg(test)]
    fn unverifiable(mut self) -> Self {
        self.unverifiable = true;
        self
    }

    /// Lot 312 (BUG-90): the inode has no name left anywhere — `st_nlink`
    /// of the held descriptor ([`super::inode::exe_unlinked`]), never the
    /// name `/proc` shows for it.
    pub fn unlinked(&self) -> std::io::Result<bool> {
        super::inode::exe_unlinked(&self.file)
    }

    /// The name `/proc/self/fd/N` shows for the held inode, as the kernel
    /// shows it (a ` (deleted)` suffix kept): what the logs and the vault's
    /// record name when no name can be verified ([`Self::current_path`]).
    fn shown_path(&self) -> Option<PathBuf> {
        fs::read_link(format!("/proc/self/fd/{}", self.file.as_raw_fd())).ok()
    }

    /// Where the inode is now, verified: the name the agent's own
    /// descriptor shows (`/proc/self/fd/N`) while that name still leads to
    /// this inode — looked up through the host's view without following a
    /// last link, `(dev, ino)` compared. A rename or a swapped directory
    /// moves it, a string read earlier does not. `None` once the inode has
    /// no name, or when the name shown leads elsewhere: lot 312 (BUG-90),
    /// the name the process ran was removed while another hard link keeps
    /// the inode — the kernel then shows that name with ` (deleted)` after
    /// it, a suffix a file on disk may also carry in its own name.
    pub fn current_path(&self) -> Option<PathBuf> {
        #[cfg(test)]
        if self.unverifiable {
            return None;
        }
        if self.unlinked().unwrap_or(true) {
            return None;
        }
        let p = self.shown_path()?;
        let m = super::on_host_path(&p, |q| fs::symlink_metadata(q)).ok()?;
        self.is_inode(m.dev(), m.ino()).then_some(p)
    }

    /// [`Self::current_path`], tried up to [`VERIFY_TRIES`] times: a
    /// directory of the path exchanged with a link in a loop (CMB-001)
    /// fails a try, not all of them. `None` when no name led to the inode
    /// on any try — its name removed while another hard link keeps it.
    fn verified_name(&self) -> Option<PathBuf> {
        for _ in 0..VERIFY_TRIES {
            if self.unlinked().unwrap_or(true) {
                return None;
            }
            if let Some(p) = self.current_path() {
                return Some(p);
            }
        }
        None
    }

    /// The same inode as this handle's.
    pub fn is_inode(&self, dev: u64, ino: u64) -> bool {
        self.dev == dev && self.ino == ino
    }

    /// `(dev, ino)` of the inode.
    pub fn key(&self) -> (u64, u64) {
        (self.dev, self.ino)
    }
}
/// The filesystem uid `pid` acts as (`Uid:`'s fourth field of
/// `/proc/<pid>/status`, read as bytes).
fn fsuid_of(pid: u32) -> Option<u32> {
    fsuid_in(&crate::state_read::read_state(format!("/proc/{pid}/status")).ok()?)
}

/// The filesystem uid a `/proc/<pid>/status` text names (`Uid:` real,
/// effective, saved, filesystem): the one file access is judged with.
fn fsuid_in(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))?
        .split_whitespace()
        .nth(3)?
        .parse()
        .ok()
}

const NONCE_LEN: usize = 12;

/// Public entry point: encrypt the binary backing `target_pid` and
/// remove the original file.
/// R12c (lab PR 270): only for an action whose intent is signed (`intent`).
pub fn quarantine_process_binary(
    target_pid: u32,
    protected: &HashSet<u32>,
    cfg: &ExecutorConfig,
    intent: &super::journal::Intent,
) -> ExecutionOutcome {
    if target_pid == 0 {
        return ExecutionOutcome::Refused {
            pid: target_pid,
            reason: "PID 0 invalid",
        };
    }
    if protected.contains(&target_pid) {
        return ExecutionOutcome::Refused {
            pid: target_pid,
            reason: "PID is protected",
        };
    }

    let handle = match ExeHandle::of_pid(target_pid) {
        Ok(Some(h)) => h,
        Ok(None) => return ExecutionOutcome::AlreadyGone { pid: target_pid },
        Err(e) => {
            warn!(pid = target_pid, error = %e, "open /proc/<pid>/exe");
            return ExecutionOutcome::Failed {
                pid: target_pid,
                errno: e.raw_os_error().unwrap_or(0),
            };
        }
    };
    quarantine_handle(&handle, target_pid, cfg, intent)
}

/// Review 87: encrypt the binary `handle` holds into the vault and remove
/// it. `pid` is the process it backed, for the outcome. The combat
/// ladder's NEUTRALIZE opens the binary before it kills the process (after
/// the kill `/proc/<pid>/exe` is gone) and quarantines it here.
/// R12c (lab PR 270): only for an action whose intent is signed (`_intent`).
pub fn quarantine_handle(
    handle: &ExeHandle,
    pid: u32,
    cfg: &ExecutorConfig,
    _intent: &super::journal::Intent,
) -> ExecutionOutcome {
    let target_pid = pid;
    // Lot 312 (BUG-90): gone only once the inode has no name left — a name
    // the agent cannot see (another hard link) keeps the binary runnable.
    match handle.unlinked() {
        Ok(true) => {
            // Review F9: no name left, but the agent holds it — evidence.
            if !cfg.dry_run {
                if let Some(vault_id) = vault_nameless(handle, cfg) {
                    info!(pid = target_pid, vault_id = %vault_id, "quarantine: a binary with no name left (a memfd or an unlinked file) — vaulted as evidence");
                }
            }
            return ExecutionOutcome::AlreadyGone { pid: target_pid };
        }
        Ok(false) => {}
        Err(e) => {
            warn!(pid = target_pid, error = %e, "quarantine: fstat of the held binary failed");
            return ExecutionOutcome::Failed {
                pid: target_pid,
                errno: e.raw_os_error().unwrap_or(0),
            };
        }
    }
    let original_str = handle
        .verified_name()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| NAME_UNKNOWN.to_string());

    // External audit CMB-020: detect-only touches nothing and says so —
    // `Quarantined` with the vault id "dry-run" was a file never moved.
    if cfg.dry_run {
        info!(
            pid = target_pid,
            path = %nn_model::log_escape::Escaped(&original_str),
            "dry-run: would quarantine binary"
        );
        return ExecutionOutcome::WouldExecute { pid: target_pid };
    }

    match quarantine_file(handle, cfg) {
        Ok(Done::Removed { vault_id, name }) => {
            info!(
                pid = target_pid,
                vault_id = %vault_id,
                path = %nn_model::log_escape::Escaped(name.display()),
                "quarantined binary"
            );
            ExecutionOutcome::Quarantined {
                original_path: name.to_string_lossy().into_owned(),
                vault_id,
            }
        }
        Ok(Done::InPlace {
            vault_id,
            name,
            detail,
            effect,
        }) => {
            warn!(
                pid = target_pid,
                vault_id = %vault_id,
                path = %nn_model::log_escape::Escaped(&original_str),
                detail = %detail,
                "quarantine: vaulted, the binary neutralized in place"
            );
            ExecutionOutcome::QuarantinedInPlace {
                vault_id,
                original_path: name.map(|p| p.to_string_lossy().into_owned()),
                detail,
                effect,
            }
        }
        Err(QuarantineError::Gone) => ExecutionOutcome::AlreadyGone { pid: target_pid },
        // Review F4: a removal that failed is neutralized in place by
        // `quarantine_file`; this answer is left for nothing done at all.
        Err(QuarantineError::PathSwapped) => ExecutionOutcome::Refused {
            pid: target_pid,
            reason: "the binary's path changed under the quarantine — nothing done",
        },
        Err(QuarantineError::ProtectedFile) => {
            warn!(
                pid = target_pid,
                path = %nn_model::log_escape::Escaped(&original_str),
                "the binary is a protected system file (the dynamic loader, a shell, init, sshd \
                 or the agent's own), whatever its name; refusing to quarantine (kill-only)"
            );
            ExecutionOutcome::Refused {
                pid: target_pid,
                reason: "a protected system file (by identity: the loader, a shell, init, sshd, \
                         the agent's own)",
            }
        }
        Err(QuarantineError::Refused(detail)) => {
            warn!(pid = target_pid, detail = %detail, "quarantine refused: the file is not changed");
            ExecutionOutcome::QuarantineRefused {
                pid: target_pid,
                detail,
            }
        }
        Err(QuarantineError::ProtectedPath) => {
            warn!(
                pid = target_pid,
                path = %nn_model::log_escape::Escaped(&original_str),
                "binary lives under a protected system prefix; refusing to quarantine (kill-only)"
            );
            ExecutionOutcome::Refused {
                pid: target_pid,
                reason: "path is under a protected system prefix",
            }
        }
        Err(QuarantineError::TooLarge { size, max }) => {
            warn!(
                pid = target_pid,
                size, max, "binary exceeds quarantine_max_bytes; refusing"
            );
            ExecutionOutcome::Failed {
                pid: target_pid,
                // EFBIG is "file too large"; close enough.
                errno: libc::EFBIG,
            }
        }
        Err(QuarantineError::Io(e)) => {
            warn!(pid = target_pid, error = %e, "quarantine I/O failed");
            ExecutionOutcome::Failed {
                pid: target_pid,
                errno: e.raw_os_error().unwrap_or(0),
            }
        }
        Err(QuarantineError::Crypto(e)) => {
            warn!(pid = target_pid, error = %e, "quarantine crypto failed");
            ExecutionOutcome::Failed {
                pid: target_pid,
                errno: 0,
            }
        }
    }
}

/// External audit CMB-026: a vault id is the 32 hex digits the
/// quarantine mints (`Uuid::simple`). Anything else — a `/`, a `..` — would
/// name a file outside the vault.
pub fn is_valid_vault_id(vault_id: &str) -> bool {
    vault_id.len() == 32 && vault_id.bytes().all(|b| b.is_ascii_hexdigit())
}

fn invalid(msg: &str) -> std::io::Error {
    std::io::Error::new(ErrorKind::InvalidInput, msg.to_string())
}

/// External audit CMB-026: where a restore may write. An absolute path
/// with a file name, no `.` or `..` component, outside the prefixes the
/// quarantine never touches ([`is_quarantine_denied`]: system binaries and
/// libraries, `/etc`, the agent's binaries and state). A file the
/// quarantine took cannot come from there, so the default destination —
/// the original path — always passes.
pub fn check_restore_destination(cfg: &ExecutorConfig, path: &Path) -> std::io::Result<()> {
    use std::path::Component;
    if !path.is_absolute() {
        return Err(invalid("the destination must be an absolute path"));
    }
    if path
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(invalid("the destination must not contain `.` or `..`"));
    }
    if path.file_name().is_none() {
        return Err(invalid("the destination must name a file"));
    }
    if is_denied_by(cfg, path) {
        return Err(std::io::Error::new(
            ErrorKind::PermissionDenied,
            "the destination is under a protected prefix",
        ));
    }
    Ok(())
}

/// External audit CMB-016: restore a vault entry for `nn-admin response
/// restore` — to `to` when given, else to the path it was taken from (its
/// `.meta`). Returns the path written.
pub fn restore_entry(
    vault_id: &str,
    to: Option<&str>,
    cfg: &ExecutorConfig,
) -> std::io::Result<PathBuf> {
    if !is_valid_vault_id(vault_id) {
        return Err(invalid("a vault id is 32 hex digits"));
    }
    let meta = vault_meta(vault_id, cfg)
        .ok_or_else(|| std::io::Error::new(ErrorKind::NotFound, "no such vault entry"))?;
    // Lot 312 (review F1): a binary neutralized in place comes back in
    // place — its content and mode put back into the same inode, so that
    // every name of it runs again; no name is created.
    if meta.get("in_place").is_some_and(|v| !v.is_null()) {
        let path = to
            .map(PathBuf::from)
            .or_else(|| meta["original_path"].as_str().map(PathBuf::from))
            .ok_or_else(|| {
                invalid(
                    "no name of this file was verified when it was quarantined: give --to a \
                     current name of it (any of its hard links)",
                )
            })?;
        restore_in_place(vault_id, &path, &meta, cfg)?;
        return Ok(path);
    }
    let dest = match to {
        Some(t) => PathBuf::from(t),
        None => PathBuf::from(meta["original_path"].as_str().ok_or_else(|| {
            std::io::Error::new(ErrorKind::InvalidData, "the entry records no original path")
        })?),
    };
    restore(vault_id, &dest, cfg)?;
    Ok(dest)
}

/// Whether the vault entry `vault_id` was neutralized in place (its
/// restore puts content and mode back into the same file).
pub fn is_in_place(vault_id: &str, cfg: &ExecutorConfig) -> bool {
    vault_meta(vault_id, cfg).is_some_and(|m| m.get("in_place").is_some_and(|v| !v.is_null()))
}

/// Lot 312 (review F1): put a vault entry neutralized in place back into
/// its inode — `path` a current name of it, checked to be the very inode
/// the quarantine held (`(dev, ino)`, and the birth time where the
/// filesystem keeps one: a number freed and reused is another file). Its
/// mode first, then, if it was emptied and is still empty, its content;
/// both read back (the sha256 recorded at capture). Nothing is created,
/// nothing replaced by name: every hard link of the file comes back with
/// it.
fn restore_in_place(
    vault_id: &str,
    path: &Path,
    meta: &serde_json::Value,
    cfg: &ExecutorConfig,
) -> std::io::Result<()> {
    use std::path::Component;
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(invalid(
            "the name must be an absolute path without `.` or `..`",
        ));
    }
    let inode = &meta["inode"];
    let want = |k: &str| {
        inode[k].as_u64().ok_or_else(|| {
            std::io::Error::new(
                ErrorKind::InvalidData,
                format!("the entry records no inode {k}"),
            )
        })
    };
    let (dev, ino, mode) = (want("dev")?, want("ino")?, want("mode")? as u32);
    let held = super::on_host_path(path, |p| {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(p)
    })?;
    let m = held.metadata()?;
    let same_birth = match (inode["btime_ns"].as_i64(), btime_of(held.as_raw_fd())) {
        (Some(a), Some(b)) => a == b,
        _ => true,
    };
    if !m.is_file() || m.dev() != dev || m.ino() != ino || !same_birth {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            format!(
                "{} is not the file this entry was taken from (inode {dev}:{ino})",
                path.display()
            ),
        ));
    }
    let emptied = meta["in_place"]["emptied"].as_bool().unwrap_or(false);
    let plaintext = vault_plaintext(vault_id, meta, cfg)?;
    if emptied && m.len() != 0 {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            "the file was written since it was emptied — not overwritten",
        ));
    }
    let via = format!("/proc/self/fd/{}", held.as_raw_fd());
    if m.mode() & 0o7777 != mode {
        fs::set_permissions(&via, fs::Permissions::from_mode(mode))?;
    }
    if emptied {
        let mut w = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(&via)?;
        w.write_all(&plaintext)?;
        w.sync_all()?;
    }
    // read back: the inode holds what was taken, with its mode
    let now = fs::read(&via)?;
    let mode_now = held.metadata()?.mode() & 0o7777;
    let sha = hex::encode(Sha256::digest(&now));
    if Some(sha.as_str()) != meta["sha256"].as_str() || mode_now != mode {
        return Err(std::io::Error::other(format!(
            "read back: content sha256 {sha}, mode {mode_now:o} — not the file taken"
        )));
    }
    info!(
        vault_id,
        path = %nn_model::log_escape::Escaped(path.display()),
        mode = format!("{mode:o}"),
        emptied,
        "restored a quarantined file in place (every name of it)"
    );
    Ok(())
}

/// Decrypt a quarantined file to `out_path`.
///
/// External audit CMB-026: the vault id must be one the quarantine mints
/// ([`is_valid_vault_id`]), the destination must pass
/// [`check_restore_destination`], and the plaintext must match the
/// `sha256` its `.meta` recorded at capture. The file is created, never
/// replaced: `O_CREAT | O_EXCL | O_NOFOLLOW`, mode 0600, under its parent
/// directory opened once (through the host's view, as the quarantine
/// removes — review 87) and judged again by the denylist where it really
/// is, so a directory of the path swapped for a link cannot place it in
/// `/etc`. The directory must exist. The vault entry stays.
pub fn restore(vault_id: &str, out_path: &Path, cfg: &ExecutorConfig) -> std::io::Result<()> {
    if !is_valid_vault_id(vault_id) {
        return Err(invalid("a vault id is 32 hex digits"));
    }
    check_restore_destination(cfg, out_path)?;
    let meta = vault_meta(vault_id, cfg)
        .ok_or_else(|| std::io::Error::new(ErrorKind::NotFound, "no such vault entry"))?;
    let plaintext = vault_plaintext(vault_id, &meta, cfg)?;
    write_restored(&plaintext, out_path, cfg)?;
    info!(
        vault_id,
        out = %nn_model::log_escape::Escaped(out_path.display()),
        size = plaintext.len(),
        "restored quarantined file (mode 0600)"
    );
    Ok(())
}

/// The content of the vault entry `vault_id` (its `.meta` `meta`),
/// decrypted and checked against the sha256 recorded at capture.
fn vault_plaintext(
    vault_id: &str,
    meta: &serde_json::Value,
    cfg: &ExecutorConfig,
) -> std::io::Result<zeroize::Zeroizing<Vec<u8>>> {
    let vault_dir = cfg.quarantine_dir.join("vault");
    let bin_path = vault_dir.join(format!("{vault_id}.bin"));
    let want_sha = meta["sha256"]
        .as_str()
        .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidData, "the entry records no sha256"))?
        .to_ascii_lowercase();

    let bin = fs::read(&bin_path)?;
    if bin.len() < NONCE_LEN {
        return Err(std::io::Error::other("vault file too short"));
    }

    let vault = vault_of(cfg)?;
    let plaintext = match declared_format(meta)? {
        // Written before lab PR 238: a v1 record, read as one whatever its
        // first (random) bytes are.
        None => zeroize::Zeroizing::new(vault.open_v1(vault_id, &bin)?),
        Some(declared) => {
            let found = record_format(&bin)?;
            if found != declared {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "the entry's .meta declares vault record format {declared}, its .bin is \
                         format {found} — refused"
                    ),
                ));
            }
            zeroize::Zeroizing::new(vault.open(vault_id, &bin)?)
        }
    };
    drop(bin);
    let got_sha = hex::encode(Sha256::digest(&*plaintext));
    if got_sha != want_sha {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!("sha256 mismatch: the entry recorded {want_sha}, the content is {got_sha}"),
        ));
    }
    Ok(plaintext)
}

/// [`restore`]'s write: a new file at `out_path`, mode 0600, never
/// replacing one, never through a link, judged where it really is.
fn write_restored(plaintext: &[u8], out_path: &Path, cfg: &ExecutorConfig) -> std::io::Result<()> {
    let (Some(parent), Some(name)) = (out_path.parent(), out_path.file_name()) else {
        return Err(invalid("the destination must name a file"));
    };
    let dir = super::on_host_path(parent, |p| {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(p)
    })?;
    if let Ok(real) = fs::read_link(format!("/proc/self/fd/{}", dir.as_raw_fd())) {
        let real = match real.strip_prefix("/proc/1/root") {
            Ok(rel) => Path::new("/").join(rel),
            Err(_) => real,
        };
        if is_denied_by(cfg, &real.join(name)) || is_denied_by(cfg, &real) {
            return Err(std::io::Error::new(
                ErrorKind::PermissionDenied,
                format!(
                    "the destination directory is {} — under a protected prefix",
                    real.display()
                ),
            ));
        }
    }
    let cname = std::ffi::CString::new(name.as_bytes())
        .map_err(|_| invalid("the destination contains a NUL byte"))?;
    let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // SAFETY: a valid directory fd and a NUL-terminated name; the returned
    // fd is owned by the File below.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            cname.as_ptr(),
            flags,
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by openat and is owned by nobody else.
    let mut out = unsafe { fs::File::from_raw_fd(fd) };
    let written = out
        .set_permissions(fs::Permissions::from_mode(0o600))
        .and_then(|()| out.write_all(plaintext))
        .and_then(|()| out.sync_all());
    if let Err(e) = written {
        drop(out);
        // SAFETY: the same directory fd and name as the openat above.
        unsafe { libc::unlinkat(dir.as_raw_fd(), cname.as_ptr(), 0) };
        return Err(e);
    }
    Ok(())
}

#[derive(Debug)]
enum QuarantineError {
    /// Path is under [`QUARANTINE_DENY_PREFIXES`]; nothing was touched.
    ProtectedPath,
    /// Re-check of #543 (N1): the inode is a protected system file by
    /// identity ([`protected_identities`]); nothing was touched.
    ProtectedFile,
    /// Re-check of #543 (N1, N2): a file the offender could not change
    /// itself — not its own (and no root offender on a verified name), or
    /// root's without a verified name. Nothing was touched; the reason.
    Refused(String),
    /// The file was unlinked before the quarantine reached it.
    Gone,
    /// External audit CMB-001: the path no longer names the inode the
    /// process ran. Internal since lot 312 (review F4): the held inode is
    /// then neutralized in place.
    PathSwapped,
    TooLarge {
        size: u64,
        max: u64,
    },
    Io(std::io::Error),
    Crypto(String),
}

impl From<std::io::Error> for QuarantineError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// What a quarantine did to the binary on disk (lot 312).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Done {
    /// Vaulted, and its only name removed: no name of it is left.
    Removed { vault_id: String, name: PathBuf },
    /// Vaulted, and the inode itself neutralized where it is
    /// ([`neutralize_in_place`]): its other names, a name the agent could
    /// not verify, or a removal that failed keep it. `detail` says what
    /// was done, `effect` what holds.
    InPlace {
        vault_id: String,
        name: Option<PathBuf>,
        detail: String,
        effect: InPlaceEffect,
    },
}

#[cfg(test)]
impl Done {
    /// The vault entry's id.
    fn vault_id(&self) -> &str {
        match self {
            Done::Removed { vault_id, .. } | Done::InPlace { vault_id, .. } => vault_id,
        }
    }
}

fn quarantine_file(handle: &ExeHandle, cfg: &ExecutorConfig) -> Result<Done, QuarantineError> {
    quarantine_file_after_check(handle, cfg, || {})
}

/// [`quarantine_file`], running `after_check` between the size check and
/// the read (tests: a file that grows in between).
fn quarantine_file_after_check(
    handle: &ExeHandle,
    cfg: &ExecutorConfig,
    after_check: impl FnOnce(),
) -> Result<Done, QuarantineError> {
    quarantine_file_with(handle, cfg, after_check, &|| {})
}

/// [`quarantine_file_after_check`], running `before_unlink` between the
/// verification of the name and its unlink (tests: a swap in between).
fn quarantine_file_with(
    handle: &ExeHandle,
    cfg: &ExecutorConfig,
    after_check: impl FnOnce(),
    before_unlink: &dyn Fn(),
) -> Result<Done, QuarantineError> {
    // Lot 312 (BUG-90): gone only when no name is left.
    if handle.unlinked()? {
        return Err(QuarantineError::Gone);
    }
    // Re-check of #543 (N1): the identity of the system's own files wins
    // over any name — the dynamic loader, the shells, init, sshd, the
    // agent's own binaries are never touched, whatever name (another mount
    // namespace's bind of /usr/bin) leads to them.
    // The shells /etc/shells lists are among them: one that cannot be read
    // leaves them unknown, and nothing is changed (lot 311b's rule: a read
    // that fails never empties a protection).
    let list = shells_path();
    let shells = listed_shells(&list).map_err(|e| {
        QuarantineError::Refused(format!(
            "{} could not be read ({e}): the shells it lists are not all known, so no file is \
             changed",
            list.display()
        ))
    })?;
    if is_protected_identity(cfg, handle, &shells) {
        return Err(QuarantineError::ProtectedFile);
    }
    let named = handle.verified_name();
    // Review F5: the denylist judges a VERIFIED name; the name the kernel
    // shows when none verifies is not a location and decides nothing.
    if named.as_deref().is_some_and(|p| is_denied_by(cfg, p)) {
        return Err(QuarantineError::ProtectedPath);
    }
    let meta = handle.file.metadata()?;
    // Re-check of #543 (N1, N2): what the offender could do to this file
    // itself, the quarantine may do. A file it owns, under any name; a
    // root offender, a file of anyone's under a VERIFIED name (as before
    // the lot: the payload a user dropped and root ran). Never a
    // root-owned file without a verified name (a mount namespace's view of
    // the host's binaries), never another user's for a non-root offender.
    let owner = meta.uid();
    let owns = handle.offender_uid == Some(owner);
    let root_on_a_name = handle.offender_uid == Some(0) && named.is_some();
    if named.is_none() && owner == 0 {
        return Err(QuarantineError::Refused(format!(
            "a root-owned file (uid 0, {} link(s)) reached through a name that could not be \
             verified is never changed — not quarantined",
            meta.nlink()
        )));
    }
    if !(owns || root_on_a_name) {
        return Err(QuarantineError::Refused(match handle.offender_uid {
            Some(uid) => format!(
                "the offender (uid {uid}) does not own this file (owner uid {owner}{}): its \
                 quarantine never changes another user's file — not quarantined",
                if named.is_none() {
                    ", no name of it verified"
                } else {
                    ""
                }
            ),
            None => format!(
                "the offender's uid is unknown (owner uid {owner}): the file is not changed — not \
                 quarantined"
            ),
        }));
    }
    let size = meta.len();
    if size > cfg.quarantine_max_bytes {
        return Err(QuarantineError::TooLarge {
            size,
            max: cfg.quarantine_max_bytes,
        });
    }

    after_check();

    let content = read_bounded(handle, cfg.quarantine_max_bytes)?;
    let identity = Identity::of(handle, &meta);
    let vault_id = vault_content(cfg, &content, named.as_deref(), &identity, false)?;

    // Lot 312 (review F1): a name is removed — the content left to the
    // vault — only when it is the inode's only name: never a shared one (a
    // package store's, an environment's hard link).
    if let (Some(name), 1) = (&named, meta.nlink()) {
        match remove_held_with(handle, cfg, before_unlink) {
            Ok(Removal::Unlinked) | Ok(Removal::NoNameLeft) => {}
            Err(QuarantineError::ProtectedPath) => return Err(QuarantineError::ProtectedPath),
            // Review F4: a failed removal (a swap, EISDIR, EBUSY) leaves the
            // inode to be neutralized in place below.
            Err(e) => {
                warn!(error = ?e, "quarantine: the name could not be removed — neutralized in place")
            }
        }
        if handle.unlinked()? {
            return Ok(Done::Removed {
                vault_id,
                name: name.clone(),
            });
        }
    }
    let (detail, effect) = neutralize_in_place(handle, &identity, named.is_some());
    record_in_place(cfg, &vault_id, effect == InPlaceEffect::Emptied, handle)?;
    Ok(Done::InPlace {
        vault_id,
        name: named,
        detail,
        effect,
    })
}

/// The system's list of login shells.
const SHELLS: &str = "/etc/shells";

#[cfg(test)]
thread_local! {
    /// Tests: the shell list read in place of [`SHELLS`] on this thread.
    static SHELLS_AT: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}

/// Where the shell list is read: [`SHELLS`] (a test's own list under
/// `cfg(test)`, when it set one).
fn shells_path() -> PathBuf {
    #[cfg(test)]
    if let Some(p) = SHELLS_AT.with(|s| s.borrow().clone()) {
        return p;
    }
    PathBuf::from(SHELLS)
}

/// Re-check of #543 (N1): the shells a `/etc/shells` lists, its bytes made
/// text. A host with none lists none (the usual shells of
/// [`PROTECTED_FILES`] stay protected); one that exists and cannot be read
/// is an error, never an empty list.
fn listed_shells(path: &Path) -> std::io::Result<Vec<PathBuf>> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    Ok(String::from_utf8_lossy(&bytes)
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with('/'))
        .map(PathBuf::from)
        .collect())
}

/// Re-check of #543 (N1): the files whose identity — `(dev, ino)`, not a
/// name — the quarantine never touches: the dynamic loaders, the shells
/// (`shells`, from `/etc/shells`, and the usual ones), init and systemd,
/// the SSH daemon, and the agent's own files and binaries.
fn protected_identities(cfg: &ExecutorConfig, shells: &[PathBuf]) -> HashSet<(u64, u64)> {
    let mut paths: Vec<PathBuf> = PROTECTED_FILES.iter().map(PathBuf::from).collect();
    paths.extend(shells.iter().cloned());
    for dir in LOADER_DIRS {
        if let Ok(entries) = fs::read_dir(dir) {
            paths.extend(entries.flatten().filter_map(|e| {
                let n = e.file_name();
                let n = n.to_string_lossy();
                (n.starts_with("ld-linux") || n.starts_with("ld-musl") || n == "ld.so")
                    .then(|| e.path())
            }));
        }
    }
    paths.extend(cfg.own_files.files.iter().cloned());
    for dir in &cfg.own_files.install_dirs {
        if let Ok(entries) = fs::read_dir(dir) {
            paths.extend(entries.flatten().filter_map(|e| {
                let n = e.file_name();
                let n = n.to_string_lossy();
                (n.starts_with("northnarrow-") || n.starts_with("nn-admin")).then(|| e.path())
            }));
        }
    }
    paths
        .iter()
        .filter_map(|p| fs::metadata(p).ok())
        .map(|m| (m.dev(), m.ino()))
        .collect()
}

/// Re-check of #543 (N1): the held inode is one of [`protected_identities`].
fn is_protected_identity(cfg: &ExecutorConfig, handle: &ExeHandle, shells: &[PathBuf]) -> bool {
    protected_identities(cfg, shells).contains(&handle.key())
}

/// The system files [`protected_identities`] names besides the shells of
/// `/etc/shells` and the loaders found in [`LOADER_DIRS`].
const PROTECTED_FILES: &[&str] = &[
    "/bin/sh",
    "/bin/bash",
    "/bin/dash",
    "/bin/zsh",
    "/bin/busybox",
    "/usr/bin/sh",
    "/usr/bin/bash",
    "/usr/bin/dash",
    "/usr/bin/zsh",
    "/usr/bin/busybox",
    "/sbin/init",
    "/usr/sbin/init",
    "/lib/systemd/systemd",
    "/usr/lib/systemd/systemd",
    "/usr/sbin/sshd",
    "/usr/libexec/openssh/sshd",
    "/usr/local/bin/northnarrow-agent",
    "/usr/local/bin/northnarrow-watchdog",
    "/usr/local/bin/nn-admin",
];

/// Where the dynamic loaders live (`ld-linux*`, `ld-musl*`, `ld.so`).
const LOADER_DIRS: &[&str] = &[
    "/lib",
    "/lib64",
    "/usr/lib",
    "/usr/lib64",
    "/lib/x86_64-linux-gnu",
    "/usr/lib/x86_64-linux-gnu",
    "/lib/aarch64-linux-gnu",
    "/usr/lib/aarch64-linux-gnu",
];

/// The held inode's content, bounded as the size check (external audit
/// CMB-024: a file that grew since is refused, not read whole).
fn read_bounded(handle: &ExeHandle, max: u64) -> Result<Vec<u8>, QuarantineError> {
    let mut content = Vec::new();
    let mut reader = &handle.file;
    reader.seek(SeekFrom::Start(0))?;
    reader
        .take(max.saturating_add(1))
        .read_to_end(&mut content)?;
    let size = content.len() as u64;
    if size > max {
        return Err(QuarantineError::TooLarge { size, max });
    }
    Ok(content)
}

/// Lot 312: who the held inode is, as captured before the quarantine
/// touched it — recorded in the vault entry so that a restore finds the
/// same inode and puts back its mode and content.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Identity {
    dev: u64,
    ino: u64,
    mode: u32,
    uid: u32,
    nlink: u64,
    /// Birth time (ns) where the filesystem keeps it: an inode number
    /// freed and reused is another file.
    btime_ns: Option<i64>,
}

impl Identity {
    fn of(handle: &ExeHandle, m: &fs::Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            mode: m.mode() & 0o7777,
            uid: m.uid(),
            nlink: m.nlink(),
            btime_ns: btime_of(handle.file.as_raw_fd()),
        }
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "dev": self.dev,
            "ino": self.ino,
            "mode": self.mode,
            "uid": self.uid,
            "nlink": self.nlink,
            "btime_ns": self.btime_ns,
        })
    }
}

/// `statx` birth time of the descriptor `fd`, in ns.
fn btime_of(fd: i32) -> Option<i64> {
    // SAFETY: zeroed statx buffer filled by the kernel.
    let mut sx: libc::statx = unsafe { std::mem::zeroed() };
    // SAFETY: a valid descriptor, an empty NUL-terminated path, a buffer.
    let rc = unsafe {
        libc::statx(
            fd,
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            libc::STATX_BTIME,
            &mut sx,
        )
    };
    (rc == 0 && sx.stx_mask & libc::STATX_BTIME != 0)
        .then(|| sx.stx_btime.tv_sec * 1_000_000_000 + i64::from(sx.stx_btime.tv_nsec))
}

/// Seal `content` into a new vault entry: its `.bin`, its `.meta` (the
/// verified `name`, or none; the inode's [`Identity`]; `nameless` for the
/// content of an inode with no name left), the index. Returns its id.
fn vault_content(
    cfg: &ExecutorConfig,
    content: &[u8],
    name: Option<&Path>,
    identity: &Identity,
    nameless: bool,
) -> Result<String, QuarantineError> {
    let sha = Sha256::digest(content);
    let vault_id = uuid::Uuid::new_v4().simple().to_string();
    let mut nonce = [0u8; NONCE_LEN];
    crate::os_rng::OsRng.fill_bytes(&mut nonce);
    let record = vault_of(cfg)?
        .seal(&vault_id, &nonce, content)
        .map_err(|e| QuarantineError::Crypto(format!("{e}")))?;

    let vault_dir = cfg.quarantine_dir.join("vault");
    fs::create_dir_all(&vault_dir)?;
    set_dir_root_only(&cfg.quarantine_dir);
    set_dir_root_only(&vault_dir);

    let bin_path = vault_dir.join(format!("{vault_id}.bin"));
    let meta_path = vault_dir.join(format!("{vault_id}.meta"));
    let mut bin_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&bin_path)?;
    bin_file.write_all(&record)?;
    bin_file.sync_all()?;
    drop(bin_file);

    // Lot 312 (review F1): never a name the kernel shows (`… (deleted)`),
    // only one verified; none when there is none.
    let original_str = name.map(|p| p.to_string_lossy().into_owned());
    let meta_json = serde_json::json!({
        "vault_id": vault_id,
        "original_path": original_str,
        "size_bytes": content.len(),
        "sha256": hex::encode(sha),
        "captured_at": current_timestamp(),
        "format": RECORD_V2,
        "inode": identity.json(),
        "nameless": nameless,
    });
    let mut meta_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&meta_path)?;
    meta_file.write_all(meta_json.to_string().as_bytes())?;
    meta_file.sync_all()?;
    drop(meta_file);

    let shown = original_str.unwrap_or_else(|| {
        if nameless {
            NO_NAME_LEFT.to_string()
        } else {
            NAME_UNKNOWN.to_string()
        }
    });
    update_index(&cfg.quarantine_dir, &vault_id, &shown, content.len() as u64)?;
    Ok(vault_id)
}

/// What the index and the rows say for an inode no name of which could be
/// verified.
pub const NAME_UNKNOWN: &str = "(name not verified: neutralized in place)";

/// What they say for an inode with no name left (a memfd, an unlinked
/// file), vaulted as evidence.
pub const NO_NAME_LEFT: &str = "(no name left: a memfd or an unlinked file)";

/// Lot 312 (review F9): the largest nameless inode vaulted as evidence.
const NAMELESS_VAULT_MAX: u64 = 16 * 1024 * 1024;

/// Lot 312 (review F9): the content of a binary with no name left (a
/// memfd, an unlinked or `O_TMPFILE` file — still runnable by whoever holds
/// a descriptor to it), vaulted as evidence while the agent holds it. Its
/// vault id, or `None` (too large, or the vault failed: said in the log).
fn vault_nameless(handle: &ExeHandle, cfg: &ExecutorConfig) -> Option<String> {
    let m = handle.file.metadata().ok()?;
    let max = cfg.quarantine_max_bytes.min(NAMELESS_VAULT_MAX);
    if m.len() > max {
        return None;
    }
    let vaulted = read_bounded(handle, max)
        .and_then(|content| vault_content(cfg, &content, None, &Identity::of(handle, &m), true));
    match vaulted {
        Ok(id) => Some(id),
        Err(e) => {
            warn!(error = ?e, "quarantine: the nameless binary could not be vaulted");
            None
        }
    }
}

/// What an in-place neutralization left on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InPlaceEffect {
    /// The content is gone (the file emptied): a success.
    Emptied,
    /// Mode 000, the content kept: partial.
    MadeUnusable,
    /// Nothing changed on disk — the content is only vaulted: a failure.
    Unchanged,
}

/// Lot 312 (review F1, F4, F5; re-check N1, N2): neutralize the held inode
/// where it is — `named`: a name of it was verified. The caller has
/// checked the offender could change the file itself. Its content is
/// destroyed (the file emptied through the agent's own descriptor,
/// `/proc/self/fd/N` reopened for writing: `CAP_DAC_OVERRIDE`) only when it
/// has no other name. A shared inode (a package store's, an environment's
/// hard links) keeps its content: it is made unusable (mode 000 on the held
/// descriptor), and the detail names its owner and its link count — a
/// `fchmod` of a file the agent does not own fails in the unit (no
/// `CAP_FOWNER`): then nothing changed, and that is said. Read back either
/// way.
fn neutralize_in_place(handle: &ExeHandle, id: &Identity, named: bool) -> (String, InPlaceEffect) {
    let name = if named {
        "its name verified"
    } else {
        "no name of it verified"
    };
    if id.nlink == 1 {
        let emptied = OpenOptions::new()
            .write(true)
            .truncate(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(format!("/proc/self/fd/{}", handle.file.as_raw_fd()));
        if let Err(e) = &emptied {
            warn!(error = %e, "quarantine: emptying the held binary failed");
        }
        drop(emptied);
        let _ = handle
            .file
            .set_permissions(fs::Permissions::from_mode(0o000));
        if handle.file.metadata().is_ok_and(|m| m.len() == 0) {
            return (
                format!(
                    "emptied in place (owner uid {}, its only link; {name}): no name of it runs \
                     the binary; a restore puts content and mode back into that file",
                    id.uid
                ),
                InPlaceEffect::Emptied,
            );
        }
    }
    let why = if id.nlink > 1 {
        format!("shared: {} links", id.nlink)
    } else {
        "it could not be emptied".to_string()
    };
    let chmod = handle
        .file
        .set_permissions(fs::Permissions::from_mode(0o000));
    let now = handle.file.metadata().map(|m| m.mode() & 0o7777).ok();
    if now == Some(0) {
        (
            format!(
                "made unusable in place, content kept ({why}; owner uid {}; {name}): mode {:o} -> \
                 000 under every name; a restore puts the mode back",
                id.uid, id.mode
            ),
            InPlaceEffect::MadeUnusable,
        )
    } else {
        let err = chmod.err().map(|e| e.to_string()).unwrap_or_default();
        (
            format!(
                "vaulted only, the file NOT changed ({why}; owner uid {}; {name}): the mode change \
                 was refused ({err}) — still runnable",
                id.uid
            ),
            InPlaceEffect::Unchanged,
        )
    }
}

/// Lot 312: the vault entry of an in-place neutralization says what the
/// inode holds now (emptied, mode) — what a restore puts back.
fn record_in_place(
    cfg: &ExecutorConfig,
    vault_id: &str,
    emptied: bool,
    handle: &ExeHandle,
) -> std::io::Result<()> {
    let now = handle.file.metadata()?;
    let path = cfg
        .quarantine_dir
        .join("vault")
        .join(format!("{vault_id}.meta"));
    let mut meta: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)
        .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;
    meta["in_place"] = serde_json::json!({
        "emptied": emptied,
        "mode_now": now.mode() & 0o7777,
    });
    let tmp = path.with_extension("meta.tmp");
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(meta.to_string().as_bytes())?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, &path)
}

/// What [`remove_verified`] did to the name it verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Removal {
    /// The name is gone.
    Unlinked,
    /// No name of the inode was left to verify (removed meanwhile).
    NoNameLeft,
}

/// Lot 312: tries of [`ExeHandle::verified_name`] before the inode is taken
/// for one whose names the agent cannot verify. A swap racing it fails
/// about one try in two (the lab's CMB-001 loop): 2^-64 that all of them do.
const VERIFY_TRIES: usize = 64;

/// Tries of the verified removal. A swap racing it fails the `(dev, ino)`
/// comparison of that try only; the next one starts again from where the
/// inode is (lab, CMB-001: a directory exchanged with a symlink in a tight
/// loop failed about one try in two).
const REMOVE_TRIES: usize = 8;

/// Remove the binary `handle` holds by its current name, re-read from the
/// descriptor for each try ([`ExeHandle::verified_name`]) and judged by the
/// denylist each time. [`QuarantineError::PathSwapped`] once the tries are
/// spent. Lot 312: once no name of it is left to verify
/// ([`Removal::NoNameLeft`]), the caller reads the inode back — it is gone,
/// or another name holds it.
#[cfg(test)]
fn remove_held(handle: &ExeHandle, cfg: &ExecutorConfig) -> Result<Removal, QuarantineError> {
    remove_held_with(handle, cfg, &|| {})
}

/// [`remove_held`], running `before_unlink` between the verification of a
/// name and its unlink (tests: a swap in between).
fn remove_held_with(
    handle: &ExeHandle,
    cfg: &ExecutorConfig,
    before_unlink: &dyn Fn(),
) -> Result<Removal, QuarantineError> {
    for _ in 0..REMOVE_TRIES {
        let Some(path) = handle.verified_name() else {
            return Ok(Removal::NoNameLeft);
        };
        if is_denied_by(cfg, &path) {
            return Err(QuarantineError::ProtectedPath);
        }
        match remove_verified(&path, handle, before_unlink) {
            Err(QuarantineError::PathSwapped) => continue,
            r => return r,
        }
    }
    Err(QuarantineError::PathSwapped)
}

/// External audit CMB-001: remove `path` only while it names the inode
/// `handle` holds. The parent directory is opened once (through the host's
/// view of it — review 87: the agent's own mounts are read-only), the name
/// opened under it without following a link in the last component and
/// compared by `(dev, ino)`, then unlinked under that same directory: a
/// directory of the path swapped for a symlink makes the comparison fail
/// ([`QuarantineError::PathSwapped`]) instead of removing whatever the new
/// path leads to. Lot 312 (review F4): an unlink that fails (`EISDIR` once
/// the name was exchanged with a directory, `EBUSY`) is an error the
/// caller answers by neutralizing the held inode in place — the `fchmod
/// 000` of the name that ran here failed on another user's file.
fn remove_verified(
    path: &Path,
    handle: &ExeHandle,
    before_unlink: &dyn Fn(),
) -> Result<Removal, QuarantineError> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(QuarantineError::PathSwapped);
    };
    let dir = super::on_host_path(parent, |p| {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(p)
    })?;
    let cname =
        std::ffi::CString::new(name.as_bytes()).map_err(|_| QuarantineError::PathSwapped)?;
    let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
    // SAFETY: a valid directory fd and a NUL-terminated name; the returned
    // fd is owned by the File below.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), cname.as_ptr(), flags) };
    if fd < 0 {
        let e = std::io::Error::last_os_error();
        return Err(match e.raw_os_error() {
            Some(libc::ELOOP) | Some(libc::ENOENT) | Some(libc::ENOTDIR) => {
                QuarantineError::PathSwapped
            }
            _ => e.into(),
        });
    }
    // SAFETY: `fd` was just returned by openat and is owned by nobody else.
    let target = unsafe { fs::File::from_raw_fd(fd) };
    let m = target.metadata()?;
    if !handle.is_inode(m.dev(), m.ino()) {
        return Err(QuarantineError::PathSwapped);
    }
    before_unlink();
    // SAFETY: the same directory fd and name as the openat above.
    if unsafe { libc::unlinkat(dir.as_raw_fd(), cname.as_ptr(), 0) } != 0 {
        let e = std::io::Error::last_os_error();
        warn!(error = %e, path = %nn_model::log_escape::Escaped(path.display()), "remove original failed");
        return Err(e.into());
    }
    Ok(Removal::Unlinked)
}

/// External audit CMB-017: what happened to a quarantine index that did
/// not parse, waiting to be recorded in the signed audit log by the
/// executor ([`take_index_notes`]) — by vault, its directory the key (lab
/// PR 258). One list for the process let an executor take the repairs of
/// another vault: an executor's test took the note another test of the
/// crate was waiting for. The agent has one vault, which its executor and
/// the exec quarantine share: the same notes, recorded at the same
/// quarantine as before.
static INDEX_NOTES: parking_lot::Mutex<BTreeMap<PathBuf, Vec<String>>> =
    parking_lot::const_mutex(BTreeMap::new());

/// The repairs of the index of the vault `quarantine_dir` since the last
/// call (external audit CMB-017).
pub fn take_index_notes(quarantine_dir: &Path) -> Vec<String> {
    INDEX_NOTES
        .lock()
        .remove(quarantine_dir)
        .unwrap_or_default()
}

/// The `.meta` of a vault entry: what was quarantined (path, size,
/// sha256, time).
pub fn vault_meta(vault_id: &str, cfg: &ExecutorConfig) -> Option<serde_json::Value> {
    if !is_valid_vault_id(vault_id) {
        return None;
    }
    let s = fs::read_to_string(
        cfg.quarantine_dir
            .join("vault")
            .join(format!("{vault_id}.meta")),
    )
    .ok()?;
    serde_json::from_str(&s).ok()
}

/// One entry of the vault, as `index.json` lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultEntry {
    pub vault_id: String,
    pub original_path: String,
    pub size_bytes: u64,
    pub captured_at: u64,
}

/// External audit CMB-016: the vault's entries, oldest first — from
/// `index.json`, or rebuilt from the `.meta` files when the index is
/// missing or does not parse (read-only: the index is left as it is).
pub fn list_vault(cfg: &ExecutorConfig) -> Vec<VaultEntry> {
    // lot 311 (bug hunt 1.4, BUG-95): bytes, parsed — an index that is
    // not UTF-8 does not parse, and is rebuilt like any other
    let entries: Vec<serde_json::Value> = match fs::read(cfg.quarantine_dir.join("index.json")) {
        Ok(s) => {
            serde_json::from_slice(&s).unwrap_or_else(|_| index_from_meta(&cfg.quarantine_dir))
        }
        Err(_) => index_from_meta(&cfg.quarantine_dir),
    };
    entries
        .iter()
        .map(|e| VaultEntry {
            vault_id: e["vault_id"].as_str().unwrap_or_default().to_string(),
            original_path: e["original_path"].as_str().unwrap_or_default().to_string(),
            size_bytes: e["size_bytes"].as_u64().unwrap_or(0),
            captured_at: e["captured_at"].as_u64().unwrap_or(0),
        })
        .collect()
}

/// The index entries rebuilt from the vault's `.meta` files, oldest first.
fn index_from_meta(quarantine_dir: &Path) -> Vec<serde_json::Value> {
    let mut entries: Vec<serde_json::Value> = fs::read_dir(quarantine_dir.join("vault"))
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.path().extension().is_some_and(|x| x == "meta"))
                .filter_map(|e| fs::read(e.path()).ok())
                .filter_map(|s| serde_json::from_slice::<serde_json::Value>(&s).ok())
                .map(|m| {
                    serde_json::json!({
                        "vault_id": m["vault_id"],
                        "original_path": m["original_path"],
                        "size_bytes": m["size_bytes"],
                        "captured_at": m["captured_at"],
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    entries.sort_by_key(|e| e["captured_at"].as_u64().unwrap_or(0));
    entries
}

fn update_index(
    quarantine_dir: &Path,
    vault_id: &str,
    original_path: &str,
    size: u64,
) -> std::io::Result<()> {
    let index_path = quarantine_dir.join("index.json");
    let tmp_path = quarantine_dir.join("index.json.tmp");

    // lot 311 (bug hunt 1.4, BUG-95): read as bytes and parsed — an index
    // that is not UTF-8 (a disk's corruption) failed the read itself, and
    // every quarantine after it, its `.bin` and `.meta` left behind; it is
    // an index that does not parse, kept aside and rebuilt (CMB-017)
    let mut entries: Vec<serde_json::Value> = match fs::read(&index_path) {
        Ok(s) => match serde_json::from_slice(&s) {
            Ok(v) => v,
            Err(e) => {
                // External audit CMB-017: an index that does not parse was
                // replaced by an empty one — the record of every earlier
                // quarantine lost. Kept aside, rebuilt from the vault's
                // `.meta` files, and reported.
                let kept =
                    quarantine_dir.join(format!("index.json.corrupt-{}", current_timestamp()));
                fs::rename(&index_path, &kept)?;
                let rebuilt = index_from_meta(quarantine_dir);
                let note = format!(
                    "quarantine index did not parse ({e}); kept as {}; rebuilt from {} vault .meta file(s)",
                    kept.display(),
                    rebuilt.len()
                );
                warn!("{note}");
                INDEX_NOTES
                    .lock()
                    .entry(quarantine_dir.to_path_buf())
                    .or_default()
                    .push(note);
                rebuilt
            }
        },
        Err(e) if e.kind() == ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e),
    };
    // A rebuild from the vault already holds this entry (its `.meta` is
    // written first): listed once (found in lab PR 123).
    if !entries.iter().any(|e| e["vault_id"] == vault_id) {
        entries.push(serde_json::json!({
            "vault_id": vault_id,
            "original_path": original_path,
            "size_bytes": size,
            "captured_at": current_timestamp(),
        }));
    }

    let serialized = serde_json::to_string_pretty(&entries).map_err(std::io::Error::other)?;
    let mut tmp = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp_path)?;
    tmp.write_all(serialized.as_bytes())?;
    tmp.sync_all()?;
    drop(tmp);
    fs::rename(&tmp_path, &index_path)?;
    Ok(())
}

fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn set_dir_root_only(path: &Path) {
    if let Ok(meta) = fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o700);
        let _ = fs::set_permissions(path, perms);
    }
}

/// The record format a vault entry's `.meta` declares: `None` when it
/// declares none (an entry written before lab PR 238, a v1 record); a
/// format this agent does not read is refused.
fn declared_format(meta: &serde_json::Value) -> std::io::Result<Option<u8>> {
    match meta.get("format") {
        None => Ok(None),
        Some(f) => match f.as_u64() {
            Some(1) => Ok(Some(1)),
            Some(v) if v == u64::from(RECORD_V2) => Ok(Some(RECORD_V2)),
            _ => Err(bad_record(format!(
                "the entry's .meta declares vault record format {f}, not one this agent reads \
                 (1, {RECORD_V2}) — refused"
            ))),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The vault id of a quarantine (the pre-lot-312 shape these tests use).
    fn quarantine_file(h: &ExeHandle, cfg: &ExecutorConfig) -> Result<String, QuarantineError> {
        super::quarantine_file(h, cfg).map(|d| d.vault_id().to_owned())
    }

    fn quarantine_file_after_check(
        h: &ExeHandle,
        cfg: &ExecutorConfig,
        after_check: impl FnOnce(),
    ) -> Result<String, QuarantineError> {
        super::quarantine_file_after_check(h, cfg, after_check).map(|d| d.vault_id().to_owned())
    }
    // R14c: the record crypto is the key store's vault's (its pinned
    // vectors still checked here, against what the quarantine writes)
    use crate::keys::vault::{
        derive_file_key, derive_file_key_v2, open, open_v1, open_v2, seal, seal_v2, HEADER_LEN,
    };
    use tempfile::TempDir;
    use zeroize::Zeroizing;

    fn load_or_init_master_key(cfg: &ExecutorConfig) -> std::io::Result<Zeroizing<[u8; 32]>> {
        crate::keys::vault::load_or_init_master_key(&cfg.master_key_file)
    }

    fn cfg_for(tmp: &TempDir) -> ExecutorConfig {
        let mut c = ExecutorConfig::for_test(tmp.path());
        c.dry_run = false;
        c
    }

    #[test]
    fn round_trip_encrypts_and_decrypts() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);

        let payload_path = tmp.path().join("payload.bin");
        let payload = b"hello, this is the payload contents".to_vec();
        fs::write(&payload_path, &payload).unwrap();

        let vault_id =
            quarantine_file(&ExeHandle::open(&payload_path).unwrap(), &cfg).expect("quarantine");
        assert!(!payload_path.exists(), "original should be unlinked");

        let restored_path = tmp.path().join("restored.bin");
        restore(&vault_id, &restored_path, &cfg).expect("restore");
        assert_eq!(fs::read(&restored_path).unwrap(), payload);
    }

    #[test]
    fn denylist_covers_system_and_own_paths() {
        for p in [
            "/usr/bin/bash",
            "/bin/sh",
            "/usr/lib/systemd/systemd",
            "/usr/sbin/sshd",
            "/etc/northnarrow/admin.pub",
            "/boot/vmlinuz",
            "/usr/local/bin/northnarrow-agent",
            "/usr/local/bin/northnarrow-watchdog",
            "/usr/local/bin/nn-admin",
            "/var/lib/northnarrow/quarantine/key",
        ] {
            assert!(is_quarantine_denied(Path::new(p)), "{p} must be denied");
        }
        for p in [
            "/tmp/payload",
            "/home/user/.cache/x",
            "/usr/local/bin/evil",
            "/opt/app/bin/tool",
            "/var/tmp/dropper",
        ] {
            assert!(!is_quarantine_denied(Path::new(p)), "{p} must be allowed");
        }
    }

    #[test]
    fn refuses_to_quarantine_protected_path_without_touching_it() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        // A real system binary: the denylist must fire BEFORE any
        // metadata/read/unlink, so the file is untouched afterwards. (Lot
        // 312: not a shell — `/bin/sh` is refused by identity even before
        // the denylist, `n1_the_loader_and_the_shells_are_refused_by_identity`.)
        let target = ["/usr/bin/env", "/bin/ls", "/usr/bin/ls"]
            .into_iter()
            .map(Path::new)
            .find(|p| p.exists())
            .expect("a system binary on a Linux test host");
        let before = fs::metadata(target).expect("exists");
        match quarantine_file(&ExeHandle::open(target).unwrap(), &cfg) {
            Err(QuarantineError::ProtectedPath) => {}
            Ok(_) => panic!("expected ProtectedPath, got Ok"),
            Err(_) => panic!("expected ProtectedPath, got a different error"),
        }
        let after = fs::metadata(target).unwrap();
        assert_eq!(before.len(), after.len());
        assert!(
            !tmp.path().join("vault").exists(),
            "no vault must be created for a refused path"
        );
    }

    /// External audit CMB-001: a directory of the binary's path renamed and
    /// replaced by a symlink to a victim directory before the quarantine.
    /// The quarantine follows the inode it holds — the attacker's file,
    /// wherever it went — never the victim the old path now leads to.
    #[test]
    fn a_swapped_directory_does_not_redirect_the_quarantine() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        let dir = tmp.path().join("own");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("mal"), b"malware").unwrap();
        let victim_dir = tmp.path().join("victim");
        fs::create_dir(&victim_dir).unwrap();
        fs::write(victim_dir.join("mal"), b"victim").unwrap();
        let handle = ExeHandle::open(&dir.join("mal")).unwrap();
        // the swap: the directory moved away, a link to the victim's in place
        fs::rename(&dir, tmp.path().join("own.moved")).unwrap();
        std::os::unix::fs::symlink(&victim_dir, &dir).unwrap();

        let id = quarantine_file(&handle, &cfg).expect("quarantine");
        assert_eq!(fs::read(victim_dir.join("mal")).unwrap(), b"victim");
        assert!(
            !tmp.path().join("own.moved/mal").exists(),
            "the binary itself removed"
        );
        let restored = tmp.path().join("restored");
        restore(&id, &restored, &cfg).unwrap();
        assert_eq!(fs::read(&restored).unwrap(), b"malware");

        // the removal step on its own, handed the old path: it leads to
        // another inode now, and nothing is removed
        fs::write(tmp.path().join("own.moved/mal2"), b"malware2").unwrap();
        let h2 = ExeHandle::open(&tmp.path().join("own.moved/mal2")).unwrap();
        fs::write(victim_dir.join("mal2"), b"victim2").unwrap();
        assert!(matches!(
            remove_verified(&dir.join("mal2"), &h2, &|| {}),
            Err(QuarantineError::PathSwapped)
        ));
        assert_eq!(fs::read(victim_dir.join("mal2")).unwrap(), b"victim2");
    }

    /// External audit CMB-001, the lab's race: the binary's directory
    /// exchanged with a symlink to a victim directory in a tight loop while
    /// the quarantine runs. Whatever the timing, the victim survives and the
    /// binary is vaulted; it is removed, or left where it is and reported
    /// (`PathSwapped`) — never another file in its place.
    #[test]
    fn a_directory_flipped_in_a_loop_never_redirects_the_removal() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        for round in 0..20 {
            let tmp = TempDir::new().unwrap();
            let cfg = cfg_for(&tmp);
            let own = tmp.path().join("own");
            let alt = tmp.path().join("own.alt");
            let victim_dir = tmp.path().join("victim");
            fs::create_dir(&own).unwrap();
            fs::create_dir(&victim_dir).unwrap();
            fs::write(own.join("mal"), b"malware").unwrap();
            fs::write(victim_dir.join("mal"), b"victim").unwrap();
            std::os::unix::fs::symlink(&victim_dir, &alt).unwrap();
            let handle = ExeHandle::open(&own.join("mal")).unwrap();

            let stop = Arc::new(AtomicBool::new(false));
            let flipper = {
                let stop = stop.clone();
                let a = std::ffi::CString::new(own.as_os_str().as_bytes()).unwrap();
                let b = std::ffi::CString::new(alt.as_os_str().as_bytes()).unwrap();
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        // SAFETY: two NUL-terminated paths; renameat2 reads them only.
                        unsafe {
                            libc::syscall(
                                libc::SYS_renameat2,
                                libc::AT_FDCWD,
                                a.as_ptr(),
                                libc::AT_FDCWD,
                                b.as_ptr(),
                                libc::RENAME_EXCHANGE,
                            );
                        }
                    }
                })
            };
            let outcome = super::quarantine_file(&handle, &cfg);
            stop.store(true, Ordering::Relaxed);
            flipper.join().unwrap();

            assert_eq!(
                fs::read(victim_dir.join("mal")).unwrap(),
                b"victim",
                "round {round}: the victim must survive"
            );
            let real = if fs::symlink_metadata(&own).unwrap().is_dir() {
                own.join("mal")
            } else {
                alt.join("mal")
            };
            match outcome {
                Ok(Done::Removed { vault_id, .. }) => {
                    assert!(!real.exists(), "round {round}: quarantined, so removed");
                    let restored = tmp.path().join("restored");
                    restore(&vault_id, &restored, &cfg).unwrap();
                    assert_eq!(fs::read(&restored).unwrap(), b"malware");
                }
                // lot 312 (review F4): the removal lost every try to the
                // swap; the binary itself (never another file) is emptied
                // where it is, and comes back there
                Ok(Done::InPlace {
                    vault_id,
                    effect: InPlaceEffect::Emptied,
                    ..
                }) => {
                    assert_eq!(fs::metadata(&real).unwrap().len(), 0, "round {round}");
                    restore_entry(&vault_id, Some(real.to_str().unwrap()), &cfg).unwrap();
                    assert_eq!(fs::read(&real).unwrap(), b"malware");
                }
                other => panic!("round {round}: unexpected {other:?}"),
            }
        }
    }

    /// A binary replaced under its name (a rename over it) after it was
    /// opened: the inode held is gone from disk, nothing is vaulted or
    /// removed, and the new file is left alone.
    #[test]
    fn a_binary_replaced_under_its_name_is_gone_not_the_new_file() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        let p = tmp.path().join("tool");
        fs::write(&p, b"old").unwrap();
        let handle = ExeHandle::open(&p).unwrap();
        let fresh = tmp.path().join("tool.new");
        fs::write(&fresh, b"new").unwrap();
        fs::rename(&fresh, &p).unwrap();
        assert!(matches!(
            quarantine_file(&handle, &cfg),
            Err(QuarantineError::Gone)
        ));
        assert_eq!(fs::read(&p).unwrap(), b"new");
    }

    #[test]
    fn nonce_differs_per_call() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);

        let p1 = tmp.path().join("a.bin");
        let p2 = tmp.path().join("b.bin");
        fs::write(&p1, b"same content").unwrap();
        fs::write(&p2, b"same content").unwrap();

        let id1 = quarantine_file(&ExeHandle::open(&p1).unwrap(), &cfg).unwrap();
        let id2 = quarantine_file(&ExeHandle::open(&p2).unwrap(), &cfg).unwrap();
        assert_ne!(id1, id2);

        let bin1 = fs::read(cfg.quarantine_dir.join("vault").join(format!("{id1}.bin"))).unwrap();
        let bin2 = fs::read(cfg.quarantine_dir.join("vault").join(format!("{id2}.bin"))).unwrap();
        // Different nonces (first 12 bytes) and ciphertexts.
        assert_ne!(&bin1[..12], &bin2[..12]);
        assert_ne!(bin1, bin2);
    }

    #[test]
    fn refuses_files_above_max_size() {
        let tmp = TempDir::new().unwrap();
        let mut cfg = cfg_for(&tmp);
        cfg.quarantine_max_bytes = 8;

        let p = tmp.path().join("too-big.bin");
        fs::write(&p, vec![0u8; 32]).unwrap();
        let err = quarantine_file(&ExeHandle::open(&p).unwrap(), &cfg).unwrap_err();
        match err {
            QuarantineError::TooLarge { size, max } => {
                assert_eq!(size, 32);
                assert_eq!(max, 8);
            }
            _ => panic!("expected TooLarge"),
        }
        // Original file untouched on refusal.
        assert!(p.exists());
    }

    /// External audit CMB-024: the file grows past the maximum between the
    /// size check and the read — refused, nothing vaulted, the original
    /// intact.
    #[test]
    fn a_file_that_grows_after_the_check_is_refused() {
        let tmp = TempDir::new().unwrap();
        let mut cfg = cfg_for(&tmp);
        cfg.quarantine_max_bytes = 64;
        let p = tmp.path().join("growing.sh");
        fs::write(&p, vec![b'a'; 32]).unwrap();
        let handle = ExeHandle::open(&p).unwrap();
        let err = quarantine_file_after_check(&handle, &cfg, || {
            let mut f = OpenOptions::new().append(true).open(&p).unwrap();
            f.write_all(&[b'b'; 4096]).unwrap();
        })
        .unwrap_err();
        match err {
            QuarantineError::TooLarge { size, max } => {
                assert_eq!(max, 64);
                assert_eq!(size, 65, "the read stops one byte past the maximum");
            }
            e => panic!("expected TooLarge, got {e:?}"),
        }
        assert_eq!(
            fs::metadata(&p).unwrap().len(),
            32 + 4096,
            "original intact"
        );
        assert!(
            !cfg.quarantine_dir.join("vault").exists(),
            "nothing vaulted"
        );
        // Grown but still within the maximum: vaulted as read.
        cfg.quarantine_max_bytes = 8192;
        let id = quarantine_file_after_check(&ExeHandle::open(&p).unwrap(), &cfg, || {
            let mut f = OpenOptions::new().append(true).open(&p).unwrap();
            f.write_all(b"c").unwrap();
        })
        .unwrap();
        let meta = vault_meta(&id, &cfg).unwrap();
        assert_eq!(meta["size_bytes"], 32 + 4096 + 1);
    }

    /// External audit CMB-025: the agent's own files wherever this host
    /// keeps them — a watchdog under `/opt`, the running binary and its
    /// siblings, the executor's key, vault and containment record — and
    /// nothing else of `/opt`. R11c (lab PR 264): in the configuration it
    /// was made for, no longer the process's.
    #[test]
    fn denylist_covers_the_runtime_own_binaries() {
        let tmp = TempDir::new().unwrap();
        let mut cfg = cfg_for(&tmp);
        let own = std::env::current_exe().unwrap();
        let deny = own_files(
            &cfg,
            Some(&own),
            Path::new("/opt/nn/bin/northnarrow-watchdog"),
        );
        let dir = own.parent().unwrap();
        for p in [
            own.clone(),
            PathBuf::from("/opt/nn/bin/northnarrow-watchdog"),
            dir.join("northnarrow-watchdog"),
            dir.join("nn-admin"),
            cfg.master_key_file.clone(),
            cfg.containment_file.clone(),
            cfg.quarantine_dir.clone(),
            cfg.quarantine_dir.join("vault/0123.bin"),
        ] {
            assert!(deny.denies(&p), "{} must be denied", p.display());
        }
        for p in [
            PathBuf::from("/opt/nn/bin/tool"),
            PathBuf::from("/opt/app/bin/northnarrow-agent"),
            dir.join("evil"),
            tmp.path().join("quarantine-other/x"),
            PathBuf::from("/tmp/payload"),
        ] {
            assert!(!deny.denies(&p), "{} must be allowed", p.display());
        }
        // In the configuration: the quarantine's and the restore's check.
        let bare = cfg.clone();
        cfg.own_files = deny;
        assert!(is_denied_by(&cfg, &own));
        assert!(is_denied_by(
            &cfg,
            Path::new("/opt/nn/bin/northnarrow-watchdog")
        ));
        assert!(!is_denied_by(&cfg, Path::new("/opt/nn/bin/tool")));
        assert!(check_restore_destination(&cfg, &cfg.master_key_file).is_err());
        // Another configuration (another executor, another test) has its own.
        assert!(!is_denied_by(&bare, &own));
        assert!(check_restore_destination(&bare, &bare.master_key_file).is_ok());
    }

    #[test]
    fn index_json_is_appended_atomically() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);

        let pa = tmp.path().join("a.bin");
        let pb = tmp.path().join("b.bin");
        fs::write(&pa, b"a contents").unwrap();
        fs::write(&pb, b"b contents").unwrap();

        let _ida = quarantine_file(&ExeHandle::open(&pa).unwrap(), &cfg).unwrap();
        let _idb = quarantine_file(&ExeHandle::open(&pb).unwrap(), &cfg).unwrap();

        let index_path = cfg.quarantine_dir.join("index.json");
        let s = fs::read_to_string(&index_path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v.as_array().map(|a| a.len()), Some(2));
        // tmp file should not be left behind.
        assert!(!cfg.quarantine_dir.join("index.json.tmp").exists());
    }

    /// External audit CMB-017: an index that does not parse is kept
    /// aside and rebuilt from the vault's `.meta` files, and the repair is
    /// reported.
    #[test]
    fn a_corrupt_index_is_rebuilt_from_the_meta_files() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        let vault = cfg.quarantine_dir.join("vault");
        std::fs::create_dir_all(&vault).unwrap();
        for (id, t) in [
            ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 10u64),
            ("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 20),
            // the entry being added: its `.meta` is written before the index
            ("cccccccccccccccccccccccccccccccc", 30),
        ] {
            std::fs::write(
                vault.join(format!("{id}.meta")),
                serde_json::json!({"vault_id": id, "original_path": format!("/tmp/{id}"), "size_bytes": 3, "sha256": "x", "captured_at": t}).to_string(),
            )
            .unwrap();
        }
        std::fs::write(cfg.quarantine_dir.join("index.json"), b"{ not json").unwrap();
        assert!(take_index_notes(&cfg.quarantine_dir).is_empty());
        update_index(
            &cfg.quarantine_dir,
            "cccccccccccccccccccccccccccccccc",
            "/tmp/cccccccccccccccccccccccccccccccc",
            3,
        )
        .unwrap();
        let index: Vec<serde_json::Value> = serde_json::from_str(
            &std::fs::read_to_string(cfg.quarantine_dir.join("index.json")).unwrap(),
        )
        .unwrap();
        let ids: Vec<&str> = index
            .iter()
            .map(|e| e["vault_id"].as_str().unwrap())
            .collect();
        assert_eq!(
            ids,
            vec![
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "cccccccccccccccccccccccccccccccc"
            ],
            "the entry being added is listed once"
        );
        let kept: Vec<_> = std::fs::read_dir(&cfg.quarantine_dir)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("index.json.corrupt-")
            })
            .collect();
        assert_eq!(kept.len(), 1, "the corrupt index is kept aside");
        let notes = take_index_notes(&cfg.quarantine_dir);
        assert!(
            notes.len() == 1 && notes[0].contains("rebuilt from 3"),
            "{notes:?}"
        );
        assert!(
            take_index_notes(&cfg.quarantine_dir).is_empty(),
            "taken once"
        );
        assert_eq!(
            vault_meta("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &cfg).unwrap()["original_path"],
            "/tmp/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }

    /// Lab PR 258: a repair of the index waits for its own vault's
    /// executor. With one list for the process, any executor's quarantine
    /// took it, even one refused with no vault touched: the NEUTRALIZE
    /// tests of the COMBAT actuator (an executor and a vault of their own)
    /// took the note of the test above, which then found none (lab PR
    /// 256's flake).
    #[test]
    fn an_index_repair_is_taken_by_its_own_vaults_executor() {
        let (a, b) = (TempDir::new().unwrap(), TempDir::new().unwrap());
        let (cfg, other) = (cfg_for(&a), cfg_for(&b));
        std::fs::create_dir_all(cfg.quarantine_dir.join("vault")).unwrap();
        std::fs::write(cfg.quarantine_dir.join("index.json"), b"{ not json").unwrap();
        update_index(
            &cfg.quarantine_dir,
            "dddddddddddddddddddddddddddddddd",
            "/tmp/dddddddddddddddddddddddddddddddd",
            3,
        )
        .unwrap();
        // Another vault's executor quarantines (PID 0: refused, and
        // recorded with the repairs it takes).
        let report = super::super::Executor::with_config(other.clone()).execute(
            nn_model::ResponseAction::Quarantine,
            0,
            &super::super::journal::test_intent(),
        );
        assert!(
            matches!(report.primary, ExecutionOutcome::Refused { pid: 0, .. }),
            "{:?}",
            report.primary
        );
        assert!(take_index_notes(&other.quarantine_dir).is_empty());
        let notes = take_index_notes(&cfg.quarantine_dir);
        assert!(
            notes.len() == 1 && notes[0].contains("rebuilt from 0"),
            "{notes:?}"
        );
    }

    /// A vaulted file under `tmp` (the original removed), and its id.
    fn vaulted(tmp: &TempDir, cfg: &ExecutorConfig, content: &[u8]) -> (PathBuf, String) {
        let p = tmp.path().join("payload.bin");
        fs::write(&p, content).unwrap();
        let id = quarantine_file(&ExeHandle::open(&p).unwrap(), cfg).expect("quarantine");
        (p, id)
    }

    /// External audit CMB-026: a vault id that is not 32 hex digits is
    /// refused before any path is built from it.
    #[test]
    fn restore_rejects_a_traversing_vault_id() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        let out = tmp.path().join("out");
        for id in [
            "../../etc/shadow",
            "",
            "0123456789abcdef0123456789abcde/",
            "0123456789abcdef0123456789abcdefaa",
        ] {
            let e = restore(id, &out, &cfg).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::InvalidInput, "{id}");
            let e = restore_entry(id, None, &cfg).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::InvalidInput, "{id}");
        }
        assert!(vault_meta("../../etc/shadow", &cfg).is_none());
        assert!(!out.exists());
    }

    /// External audit CMB-026: the output is created, never opened through
    /// a link — a symlink at the destination (dangling or not) is refused
    /// and its target untouched.
    #[test]
    fn restore_refuses_to_follow_a_symlink_output() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        let (_, id) = vaulted(&tmp, &cfg, b"malware");
        let victim = tmp.path().join("victim");
        fs::write(&victim, b"precious").unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        assert!(restore(&id, &link, &cfg).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"precious");
        let dangling = tmp.path().join("dangling");
        let nowhere = tmp.path().join("nowhere");
        std::os::unix::fs::symlink(&nowhere, &dangling).unwrap();
        assert!(restore(&id, &dangling, &cfg).is_err());
        assert!(!nowhere.exists());
    }

    /// External audit CMB-026: an existing file is never overwritten, and a
    /// missing directory is not created.
    #[test]
    fn restore_refuses_an_existing_file() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        let (_, id) = vaulted(&tmp, &cfg, b"malware");
        let existing = tmp.path().join("existing");
        fs::write(&existing, b"keep me").unwrap();
        let e = restore(&id, &existing, &cfg).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&existing).unwrap(), b"keep me");
        let e = restore(&id, &tmp.path().join("no/such/dir/f"), &cfg).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::NotFound);
        assert!(!tmp.path().join("no").exists());
        // relative, `..`, protected: refused before anything is decrypted
        for bad in ["relative/f", "/tmp/../etc/cron.d/x", "/etc/cron.d/x"] {
            assert!(restore(&id, Path::new(bad), &cfg).is_err(), "{bad}");
        }
    }

    /// External audit CMB-026: a plaintext that does not match the
    /// `sha256` recorded at capture is not written.
    #[test]
    fn restore_checks_the_sha256() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        let (_, id) = vaulted(&tmp, &cfg, b"malware");
        let meta_path = cfg.quarantine_dir.join("vault").join(format!("{id}.meta"));
        let mut meta: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&meta_path).unwrap()).unwrap();
        meta["sha256"] = serde_json::json!(hex::encode(Sha256::digest(b"other")));
        fs::write(&meta_path, meta.to_string()).unwrap();
        let out = tmp.path().join("out");
        let e = restore(&id, &out, &cfg).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidData);
        assert!(!out.exists());
    }

    /// External audit CMB-016: quarantine, list, restore to the original
    /// path (mode 0600), and the entry stays in the vault.
    #[test]
    fn quarantine_then_restore_to_the_original_path() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        let (original, id) = vaulted(&tmp, &cfg, b"payload bytes");
        assert!(!original.exists());
        let listed = list_vault(&cfg);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].vault_id, id);
        assert_eq!(listed[0].original_path, original.to_string_lossy());
        assert_eq!(listed[0].size_bytes, 13);

        let written = restore_entry(&id, None, &cfg).unwrap();
        assert_eq!(written, original);
        assert_eq!(fs::read(&original).unwrap(), b"payload bytes");
        assert_eq!(
            fs::metadata(&original).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // a second restore to the same place is refused; the vault keeps it
        assert!(restore_entry(&id, None, &cfg).is_err());
        assert_eq!(list_vault(&cfg).len(), 1);
        let elsewhere = tmp.path().join("copy");
        let to = elsewhere.to_string_lossy().into_owned();
        assert_eq!(restore_entry(&id, Some(&to), &cfg).unwrap(), elsewhere);
        assert_eq!(fs::read(&elsewhere).unwrap(), b"payload bytes");
    }

    #[test]
    fn master_key_is_persisted_and_reused() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);

        let k1 = load_or_init_master_key(&cfg).unwrap();
        let k2 = load_or_init_master_key(&cfg).unwrap();
        assert_eq!(&*k1, &*k2);

        // Mode 0600 enforced.
        let mode = fs::metadata(&cfg.master_key_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    /// Lab PR 230 (D0 of the dependency plan): the vault's bytes as the
    /// crypto crates of today produce them, pinned before the RustCrypto
    /// bump (aes-gcm 0.11, hkdf 0.13, sha2 0.11). The bump must pass these
    /// unchanged. Values recomputed outside the repository (OpenSSL).
    mod crypto_vectors {
        use super::*;

        const VAULT_ID: &str = "00112233445566778899aabbccddeeff";
        const NONCE: [u8; NONCE_LEN] = [
            0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab,
        ];
        const MSG: &[u8] = b"NorthNarrow quarantine KAT v1\n";
        const FILE_KEY: &str = "fea604d8c1e07187f19e324a0171a9d8baef3a6f8ce8e5d0a01d58cf5296ea2f";
        /// nonce ‖ ciphertext (30) ‖ tag (16).
        const VAULT_BIN: &str = concat!(
            "a0a1a2a3a4a5a6a7a8a9aaab",
            "df7852d98195bb82f42e822715c7fc1b60fbcfabb758bfd48d03170636c6b114",
            "0f83e8fc3597da8b8ef04c1da52a",
        );
        const MSG_SHA256: &str = "c40f026076e81e6e596843a2720c1e41b979956ccd86188de96cfd725c4e1f0f";

        /// The master key 00 01 … 1f.
        fn master() -> Zeroizing<[u8; 32]> {
            let mut k = Zeroizing::new([0u8; 32]);
            for (i, b) in k.iter_mut().enumerate() {
                *b = i as u8;
            }
            k
        }

        fn unhex(s: &str) -> Vec<u8> {
            hex::decode(s.trim()).unwrap()
        }

        /// Protects: the per-entry key a vault written before the bump was sealed under.
        #[test]
        fn hkdf_file_key_is_pinned() {
            assert_eq!(hex::encode(*derive_file_key(&master(), VAULT_ID)), FILE_KEY);
        }

        /// Protects: a vault record sealed before the bump is the record sealed after it.
        #[test]
        fn vault_record_v1_is_pinned() {
            let mut bin = NONCE.to_vec();
            bin.extend(seal(&master(), VAULT_ID, &NONCE, MSG).unwrap());
            assert_eq!(bin.len(), NONCE_LEN + MSG.len() + 16);
            assert_eq!(hex::encode(&bin), VAULT_BIN);
            assert_eq!(&*open(&master(), VAULT_ID, &unhex(VAULT_BIN)).unwrap(), MSG);
        }

        /// Protects: a record with a wrong tag, nonce or vault id stays refused after the bump.
        #[test]
        fn a_vault_record_that_does_not_match_is_refused() {
            let good = unhex(VAULT_BIN);
            // a bit of the nonce, of the ciphertext, of the tag
            for at in [0, NONCE_LEN, good.len() - 1] {
                let mut bad = good.clone();
                bad[at] ^= 1;
                assert!(open(&master(), VAULT_ID, &bad).is_err(), "byte {at}");
            }
            assert!(open(&master(), "00112233445566778899aabbccddeefe", &good).is_err());
            assert!(open(&master(), VAULT_ID, &good[..NONCE_LEN + 15]).is_err());
            assert!(open(&master(), VAULT_ID, &good[..NONCE_LEN - 1]).is_err());
        }

        /// Protects: what the quarantine writes is the format a vector
        /// pins — v2 since lab PR 238 ([`VAULT_BIN_V2`]; it was the v1
        /// record above until then).
        #[test]
        fn the_quarantine_writes_the_pinned_format() {
            let tmp = TempDir::new().unwrap();
            let cfg = cfg_for(&tmp);
            fs::write(&cfg.master_key_file, *master()).unwrap();
            let src = tmp.path().join("kat-sample");
            fs::write(&src, MSG).unwrap();
            let id = quarantine_file(&ExeHandle::open(&src).unwrap(), &cfg).expect("quarantine");
            // `.bin` = seal_v2(…) (header, nonce, ciphertext, tag); `.meta`
            // = the SHA-256 in lowercase hex and the format.
            let bin = fs::read(cfg.quarantine_dir.join("vault").join(format!("{id}.bin"))).unwrap();
            assert_eq!(bin.len(), HEADER_LEN + NONCE_LEN + MSG.len() + 16);
            assert_eq!(bin[..HEADER_LEN], *b"NNQV\x02");
            let nonce: [u8; NONCE_LEN] =
                bin[HEADER_LEN..HEADER_LEN + NONCE_LEN].try_into().unwrap();
            assert_eq!(bin, seal_v2(&master(), &id, &nonce, MSG).unwrap());
            let meta = vault_meta(&id, &cfg).unwrap();
            assert_eq!(meta["sha256"], MSG_SHA256);
            assert_eq!(meta["size_bytes"], MSG.len() as u64);
            assert_eq!(meta["format"], 2);
        }

        /// Lab PR 238: the v2 record of [`MSG_V2`] under the master key
        /// 00 01 … 1f, vault id [`VAULT_ID`] and nonce [`NONCE`] —
        /// `"NNQV" ‖ 02 ‖ nonce ‖ ciphertext (30) ‖ tag (16)`. Recomputed
        /// outside the repository (Python `cryptography` 41 on OpenSSL),
        /// with the v1 record and key above as a check of the script.
        const MSG_V2: &[u8] = b"NorthNarrow quarantine KAT v2\n";
        const FILE_KEY_V2: &str =
            "b021499b6001b1be9e08ba5c05fc2804e6737d9597c6c4836a4ae95ebb8e7835";
        const VAULT_BIN_V2: &str = concat!(
            "4e4e515602",
            "a0a1a2a3a4a5a6a7a8a9aaab",
            "dce6f148d4e74442230dd0a7a8a947be6cf2514eec02784b728eec305000",
            "10d608cc0d4dcd9a9657992aacf72a7c",
        );
        const MSG_V2_SHA256: &str =
            "d0b9ea3f27483db1df593647f6222a6d9a698476c8d5ab6bdb6fd025422f389b";

        /// Protects: the per-entry key of a v2 record (its own salt).
        #[test]
        fn hkdf_file_key_v2_is_pinned() {
            assert_eq!(
                hex::encode(*derive_file_key_v2(&master(), VAULT_ID)),
                FILE_KEY_V2
            );
            assert_ne!(FILE_KEY_V2, FILE_KEY);
        }

        /// Protects: the v2 record's bytes, and that the reader opens them
        /// and the v1 record alike.
        #[test]
        fn vault_record_v2_is_pinned() {
            let bin = seal_v2(&master(), VAULT_ID, &NONCE, MSG_V2).unwrap();
            assert_eq!(bin.len(), HEADER_LEN + NONCE_LEN + MSG_V2.len() + 16);
            assert_eq!(hex::encode(&bin), VAULT_BIN_V2);
            assert_eq!(hex::encode(Sha256::digest(MSG_V2)), MSG_V2_SHA256);
            assert_eq!(record_format(&bin).unwrap(), 2);
            assert_eq!(
                &*open(&master(), VAULT_ID, &unhex(VAULT_BIN_V2)).unwrap(),
                MSG_V2
            );
            assert_eq!(record_format(&unhex(VAULT_BIN)).unwrap(), 1);
            assert_eq!(&*open(&master(), VAULT_ID, &unhex(VAULT_BIN)).unwrap(), MSG);
        }

        /// Protects: a v2 record with a changed header, nonce, ciphertext,
        /// tag or vault id is refused; so is one cut short, and one read as
        /// v1 (its header stripped, or as an older agent would).
        #[test]
        fn a_v2_record_that_does_not_match_is_refused() {
            let good = unhex(VAULT_BIN_V2);
            // a bit of the magic, of the version byte, of the nonce, of
            // the ciphertext, of the tag
            for at in [
                0,
                3,
                HEADER_LEN - 1,
                HEADER_LEN,
                HEADER_LEN + NONCE_LEN,
                good.len() - 1,
            ] {
                let mut bad = good.clone();
                bad[at] ^= 1;
                assert!(open(&master(), VAULT_ID, &bad).is_err(), "byte {at}");
            }
            assert!(open(&master(), "00112233445566778899aabbccddeefe", &good).is_err());
            assert!(open(&master(), VAULT_ID, &good[..HEADER_LEN + NONCE_LEN + 15]).is_err());
            assert!(open(&master(), VAULT_ID, &good[..HEADER_LEN + NONCE_LEN - 1]).is_err());
            assert!(open(&master(), VAULT_ID, &good[..HEADER_LEN - 1]).is_err());
            // no downgrade: the record without its header, and the record
            // read as v1, open nothing
            assert!(open(&master(), VAULT_ID, &good[HEADER_LEN..]).is_err());
            assert!(open_v1(&master(), VAULT_ID, &good).is_err());
            assert!(open_v1(&master(), VAULT_ID, &good[HEADER_LEN..]).is_err());
            // nor the v1 record read as v2
            assert!(open_v2(&master(), VAULT_ID, &unhex(VAULT_BIN)).is_err());
        }

        /// Protects: a format this agent does not read — in the `.bin`'s
        /// header or in the `.meta` — and a `.bin` that disagrees with its
        /// `.meta` are refused with what is wrong, nothing written.
        #[test]
        fn an_unknown_or_mismatched_record_format_is_refused_clearly() {
            let good = unhex(VAULT_BIN_V2);
            let mut v3 = good.clone();
            v3[HEADER_LEN - 1] = 3;
            let e = open(&master(), VAULT_ID, &v3).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::InvalidData);
            assert!(
                e.to_string()
                    .contains("format 3 is not one this agent reads"),
                "{e}"
            );
            let mut v1_header = good.clone();
            v1_header[HEADER_LEN - 1] = 1;
            let e = open(&master(), VAULT_ID, &v1_header).unwrap_err();
            assert!(
                e.to_string()
                    .contains("names format 1, which has no header"),
                "{e}"
            );
            let e = open(&master(), VAULT_ID, b"NNQV").unwrap_err();
            assert!(e.to_string().contains("cut before its version byte"), "{e}");

            // Through restore: a quarantined entry, then its `.meta` or its
            // `.bin` changed.
            let tmp = TempDir::new().unwrap();
            let cfg = cfg_for(&tmp);
            fs::write(&cfg.master_key_file, *master()).unwrap();
            let src = tmp.path().join("kat-sample");
            fs::write(&src, MSG_V2).unwrap();
            let id = quarantine_file(&ExeHandle::open(&src).unwrap(), &cfg).expect("quarantine");
            let vault = cfg.quarantine_dir.join("vault");
            let meta_path = vault.join(format!("{id}.meta"));
            let bin_path = vault.join(format!("{id}.bin"));
            let meta: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&meta_path).unwrap()).unwrap();
            let bin = fs::read(&bin_path).unwrap();
            let out = tmp.path().join("out");
            let refused = |why: &str| {
                let e = restore(&id, &out, &cfg).unwrap_err();
                assert_eq!(e.kind(), ErrorKind::InvalidData, "{e}");
                assert!(e.to_string().contains(why), "{e}");
                assert!(!out.exists());
            };
            // the `.meta` names a format this agent does not read
            for f in [
                serde_json::json!(3),
                serde_json::json!("2"),
                serde_json::json!(0),
            ] {
                let mut m = meta.clone();
                m["format"] = f;
                fs::write(&meta_path, m.to_string()).unwrap();
                refused("not one this agent reads");
            }
            fs::write(&meta_path, meta.to_string()).unwrap();
            // the `.bin`'s header names format 3
            let mut b = bin.clone();
            b[HEADER_LEN - 1] = 3;
            fs::write(&bin_path, &b).unwrap();
            refused("declares vault record format 2, its .bin is format 3");
            // the `.bin` lost its header (format 1 to the reader)
            fs::write(&bin_path, &bin[HEADER_LEN..]).unwrap();
            refused("declares vault record format 2, its .bin is format 1");
            // as written: restored
            fs::write(&bin_path, &bin).unwrap();
            restore(&id, &out, &cfg).unwrap();
            assert_eq!(fs::read(&out).unwrap(), MSG_V2);
        }

        /// The vault `quarantine_file` of `main` at 8180540 wrote for
        /// `/tmp/nn-vault-v1/kat-sample` (content [`MSG`]) under the master
        /// key 00 01 … 1f: `agent/tests/fixtures/vault-v1/`, binary files
        /// as hex.
        const FIXTURE_ID: &str = "1b3e9723638c4980bfe76816eafc1081";
        const FIXTURE_MASTER: &str = include_str!(concat!(
            env!("NN_REPO_ROOT"),
            "/agent/tests/fixtures/vault-v1/master.key.hex"
        ));
        const FIXTURE_BIN: &str = include_str!(concat!(
            env!("NN_REPO_ROOT"),
            "/agent/tests/fixtures/vault-v1/1b3e9723638c4980bfe76816eafc1081.bin.hex"
        ));
        const FIXTURE_META: &str = include_str!(concat!(
            env!("NN_REPO_ROOT"),
            "/agent/tests/fixtures/vault-v1/1b3e9723638c4980bfe76816eafc1081.meta"
        ));
        const FIXTURE_INDEX: &str = include_str!(concat!(
            env!("NN_REPO_ROOT"),
            "/agent/tests/fixtures/vault-v1/index.json"
        ));

        /// Protects: a vault written before the bump must restore after it.
        #[test]
        fn a_vault_written_before_the_bump_restores() {
            let tmp = TempDir::new().unwrap();
            let cfg = cfg_for(&tmp);
            let vault = cfg.quarantine_dir.join("vault");
            fs::create_dir_all(&vault).unwrap();
            fs::write(&cfg.master_key_file, unhex(FIXTURE_MASTER)).unwrap();
            fs::write(vault.join(format!("{FIXTURE_ID}.bin")), unhex(FIXTURE_BIN)).unwrap();
            fs::write(vault.join(format!("{FIXTURE_ID}.meta")), FIXTURE_META).unwrap();
            fs::write(cfg.quarantine_dir.join("index.json"), FIXTURE_INDEX).unwrap();
            assert_eq!(*load_or_init_master_key(&cfg).unwrap(), *master());

            // the index and the `.meta` as written, the `.bin` opens, restore writes it
            assert_eq!(
                list_vault(&cfg),
                vec![VaultEntry {
                    vault_id: FIXTURE_ID.to_string(),
                    original_path: "/tmp/nn-vault-v1/kat-sample".to_string(),
                    size_bytes: MSG.len() as u64,
                    captured_at: 1_792_620_126,
                }]
            );
            assert_eq!(vault_meta(FIXTURE_ID, &cfg).unwrap()["sha256"], MSG_SHA256);
            assert_eq!(
                &*open(&master(), FIXTURE_ID, &unhex(FIXTURE_BIN)).unwrap(),
                MSG
            );

            let out = tmp.path().join("restored");
            let to = out.to_string_lossy().into_owned();
            assert_eq!(restore_entry(FIXTURE_ID, Some(&to), &cfg).unwrap(), out);
            assert_eq!(fs::read(&out).unwrap(), MSG);
        }

        /// Lab PR 238: the vault of `main` (v1, [`FIXTURE_ID`]) gets a new
        /// entry, written as v2 beside it; both are listed and both
        /// restore, each by its own format, and the v1 entry's files are
        /// left as they were.
        #[test]
        fn a_v1_vault_takes_v2_entries_and_restores_both() {
            let tmp = TempDir::new().unwrap();
            let cfg = cfg_for(&tmp);
            let vault = cfg.quarantine_dir.join("vault");
            fs::create_dir_all(&vault).unwrap();
            fs::write(&cfg.master_key_file, unhex(FIXTURE_MASTER)).unwrap();
            fs::write(vault.join(format!("{FIXTURE_ID}.bin")), unhex(FIXTURE_BIN)).unwrap();
            fs::write(vault.join(format!("{FIXTURE_ID}.meta")), FIXTURE_META).unwrap();
            fs::write(cfg.quarantine_dir.join("index.json"), FIXTURE_INDEX).unwrap();

            let src = tmp.path().join("new-sample");
            fs::write(&src, MSG_V2).unwrap();
            let id = quarantine_file(&ExeHandle::open(&src).unwrap(), &cfg).expect("quarantine");
            let listed: Vec<String> = list_vault(&cfg).into_iter().map(|e| e.vault_id).collect();
            assert_eq!(listed, vec![FIXTURE_ID.to_string(), id.clone()]);
            let new_bin = fs::read(vault.join(format!("{id}.bin"))).unwrap();
            assert_eq!(record_format(&new_bin).unwrap(), 2);
            assert_eq!(vault_meta(&id, &cfg).unwrap()["format"], 2);
            assert!(vault_meta(FIXTURE_ID, &cfg)
                .unwrap()
                .get("format")
                .is_none());

            let old_out = tmp.path().join("old-restored");
            restore(FIXTURE_ID, &old_out, &cfg).unwrap();
            assert_eq!(fs::read(&old_out).unwrap(), MSG);
            assert_eq!(restore_entry(&id, None, &cfg).unwrap(), src);
            assert_eq!(fs::read(&src).unwrap(), MSG_V2);
            // the v1 entry untouched
            assert_eq!(
                fs::read(vault.join(format!("{FIXTURE_ID}.bin"))).unwrap(),
                unhex(FIXTURE_BIN)
            );
            assert_eq!(
                fs::read_to_string(vault.join(format!("{FIXTURE_ID}.meta"))).unwrap(),
                FIXTURE_META
            );
        }
    }
}

/// Lot 312 (external bug hunt 1.4, BUG-90): a file ON DISK whose name ends
/// in ` (deleted)` was taken for the kernel's suffix of an unlinked dentry,
/// and a name removed while a hard link keeps the inode for a binary gone.
#[cfg(test)]
mod bug90 {
    use super::*;
    use tempfile::TempDir;

    fn cfg_for(tmp: &TempDir) -> ExecutorConfig {
        let mut c = ExecutorConfig::for_test(tmp.path());
        c.dry_run = false;
        c
    }

    fn restored(cfg: &ExecutorConfig, tmp: &TempDir, out: &ExecutionOutcome) -> Vec<u8> {
        let ExecutionOutcome::Quarantined { vault_id, .. } = out else {
            panic!("not quarantined: {out:?}");
        };
        let to = tmp.path().join(format!("restored-{vault_id}"));
        restore(vault_id, &to, cfg).unwrap();
        fs::read(&to).unwrap()
    }

    /// Promise (`current_path`): `None` only once no name leads to the inode.
    #[test]
    fn bug90_current_path_of_a_file_on_disk_named_deleted() {
        let tmp = TempDir::new().unwrap();
        let f = tmp.path().join("evil (deleted)");
        fs::write(&f, b"malware").unwrap();
        let h = ExeHandle::open(&f).unwrap();
        assert_eq!(fs::metadata(&f).unwrap().nlink(), 1, "premise: on disk");
        assert_eq!(
            h.current_path(),
            Some(f.clone()),
            "BUG-90: current_path() of a file still on disk under that name"
        );
        assert!(!h.unlinked().unwrap());
    }

    /// The entry point the NEUTRALIZE and the exec quarantine use.
    #[test]
    fn bug90_quarantine_handle_of_a_file_on_disk_named_deleted() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        let f = tmp.path().join("evil (deleted)");
        fs::write(&f, b"malware").unwrap();
        let h = ExeHandle::open(&f).unwrap();
        let out = quarantine_handle(&h, 4242, &cfg, &super::super::journal::test_intent());
        let still = f.exists();
        assert!(
            matches!(out, ExecutionOutcome::Quarantined { .. }) && !still,
            "BUG-90: outcome {out:?}, file still on disk: {still}"
        );
        assert_eq!(restored(&cfg, &tmp, &out), b"malware");
    }

    /// `of_pid` (Executor's Quarantine, the ladder's `binary_of`): a real
    /// process running a copy of `sleep` named `evil (deleted)`.
    #[test]
    fn bug90_of_pid_of_a_running_binary_named_deleted() {
        let tmp = TempDir::new().unwrap();
        let f = tmp.path().join("evil (deleted)");
        let sleep = ["/usr/bin/sleep", "/bin/sleep"]
            .into_iter()
            .find(|p| Path::new(p).exists())
            .expect("a sleep binary");
        fs::copy(sleep, &f).unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o755)).unwrap();
        // ETXTBSY: another test thread's fork may hold the copy's write fd
        let mut child = None;
        for _ in 0..50 {
            match std::process::Command::new(&f).arg("30").spawn() {
                Ok(c) => {
                    child = Some(c);
                    break;
                }
                Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => {
                    std::thread::sleep(std::time::Duration::from_millis(20))
                }
                Err(e) => panic!("spawn: {e}"),
            }
        }
        let mut child = child.expect("spawned");
        let mut link = PathBuf::new();
        for _ in 0..100 {
            link = fs::read_link(format!("/proc/{}/exe", child.id())).unwrap_or_default();
            if link == f {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let h = ExeHandle::of_pid(child.id());
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(link, f, "premise: /proc/<pid>/exe is the name, no suffix");
        let h = h
            .expect("of_pid")
            .expect("BUG-90: a binary on disk (nlink 1)");
        assert_eq!(h.current_path(), Some(f));
    }

    /// Guard (must stay): an inode really unlinked is gone — and a memfd.
    #[test]
    fn bug90_guard_an_unlinked_file_is_gone() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        let f = tmp.path().join("payload");
        fs::write(&f, b"malware").unwrap();
        let h = ExeHandle::open(&f).unwrap();
        fs::remove_file(&f).unwrap();
        assert_eq!(h.current_path(), None);
        let out = quarantine_handle(&h, 4242, &cfg, &super::super::journal::test_intent());
        assert!(
            matches!(out, ExecutionOutcome::AlreadyGone { .. }),
            "{out:?}"
        );
        use std::os::fd::FromRawFd;
        // SAFETY: memfd_create with a NUL-terminated name; the fd is owned
        // by the File below.
        let fd = unsafe { libc::memfd_create(c"nn-test".as_ptr(), libc::MFD_CLOEXEC) };
        assert!(fd >= 0);
        // SAFETY: a fresh fd owned by nobody else.
        let memfd = unsafe { fs::File::from_raw_fd(fd) };
        (&memfd).write_all(b"malware").unwrap();
        let h = ExeHandle::from_open_file(memfd).unwrap();
        let out = quarantine_handle(&h, 4243, &cfg, &super::super::journal::test_intent());
        assert!(
            matches!(out, ExecutionOutcome::AlreadyGone { .. }),
            "{out:?}"
        );
    }

    /// Variant (the triage's): the name the process ran removed, the inode
    /// kept under a hard link. The kernel shows ` (deleted)`, yet the
    /// binary is on disk (nlink 1): `AlreadyGone` ("nothing on disk") was
    /// wrong. The offender's own file with no other name: vaulted and
    /// emptied through the held descriptor; the restore puts it back into
    /// that very file — never a name `payload (deleted)`.
    #[test]
    fn bug90_variant_an_inode_still_linked_elsewhere_is_not_already_gone() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        let f = tmp.path().join("payload");
        let keep = tmp.path().join(".keep");
        fs::write(&f, b"malware").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o750)).unwrap();
        fs::hard_link(&f, &keep).unwrap();
        let h = ExeHandle::open(&f).unwrap();
        fs::remove_file(&f).unwrap();
        let nlink = h.file.metadata().unwrap().nlink();
        assert_eq!(nlink, 1, "premise");
        assert_eq!(h.current_path(), None, "premise: no name the agent can see");
        let out = quarantine_handle(&h, 4242, &cfg, &super::super::journal::test_intent());
        assert!(
            !matches!(out, ExecutionOutcome::AlreadyGone { .. }),
            "BUG-90 variant: the inode is still on disk as .keep (nlink {nlink}), outcome {out:?}"
        );
        let ExecutionOutcome::QuarantinedInPlace {
            vault_id,
            original_path: None,
            effect: InPlaceEffect::Emptied,
            detail,
        } = &out
        else {
            panic!("{out:?}");
        };
        assert!(detail.starts_with("emptied in place"), "{detail}");
        assert_eq!(
            fs::metadata(&keep).unwrap().len(),
            0,
            "the other name runs nothing"
        );
        // the restore needs a name of it, and finds the same inode there
        assert!(
            restore_entry(vault_id, None, &cfg).is_err(),
            "no name was verified"
        );
        let back = restore_entry(vault_id, Some(keep.to_str().unwrap()), &cfg).unwrap();
        assert_eq!(back, keep);
        assert_eq!(
            fs::read(&keep).unwrap(),
            b"malware",
            "content back in the same file"
        );
        assert_eq!(
            fs::metadata(&keep).unwrap().mode() & 0o7777,
            0o750,
            "its own mode"
        );
        assert!(
            !tmp.path().join("payload (deleted)").exists(),
            "no name created"
        );
    }

    /// Review F1: a SHARED inode — a package store's, as conda, pnpm or uv
    /// hard-link one binary into many environments — is never emptied:
    /// the store and the other environments keep their content. It is made
    /// unusable (mode 000) in place, the row partial with the owner and the
    /// link count; the restore puts the mode back on every name.
    #[test]
    fn bug90_review_f1_a_shared_store_inode_is_made_unusable_not_emptied() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        let store = tmp.path().join("pkgs/python-3.11/bin");
        let env = tmp.path().join("envs/ds/bin");
        let env2 = tmp.path().join("envs/other/bin");
        for d in [&store, &env, &env2] {
            fs::create_dir_all(d).unwrap();
        }
        let c = store.join("python3.11");
        fs::write(&c, b"python-interpreter").unwrap();
        fs::set_permissions(&c, fs::Permissions::from_mode(0o755)).unwrap();
        fs::hard_link(&c, env.join("python3.11")).unwrap();
        fs::hard_link(&c, env2.join("python3.11")).unwrap();
        let h = ExeHandle::open(&env.join("python3.11")).unwrap();
        let out = quarantine_handle(&h, 4242, &cfg, &super::super::journal::test_intent());
        let ExecutionOutcome::QuarantinedInPlace {
            vault_id,
            original_path,
            effect: InPlaceEffect::MadeUnusable,
            detail,
        } = &out
        else {
            panic!("{out:?}");
        };
        assert_eq!(
            original_path.as_deref(),
            Some(env.join("python3.11").to_str().unwrap())
        );
        assert!(
            detail.contains("shared: 3 links") && detail.contains("mode 755 -> 000"),
            "{detail}"
        );
        for p in [&c, &env.join("python3.11"), &env2.join("python3.11")] {
            let m = fs::metadata(p).unwrap();
            assert_eq!(m.len(), 18, "{} keeps its content", p.display());
            assert_eq!(m.mode() & 0o7777, 0, "{} unusable", p.display());
        }
        let (result, _, reason) = super::super::journal_outcome(&super::super::ExecutionReport {
            action: nn_model::ResponseAction::Quarantine,
            primary: out.clone(),
            additional: Vec::new(),
            elapsed: std::time::Duration::from_micros(1),
        });
        assert_eq!(result, super::super::journal::ActionResult::Partial);
        assert!(reason.unwrap().contains("owner uid"));
        // the restore: every name runs again, no name created
        let back = restore_entry(vault_id, None, &cfg).unwrap();
        assert_eq!(back, env.join("python3.11"));
        for p in [&c, &env.join("python3.11"), &env2.join("python3.11")] {
            assert_eq!(
                fs::metadata(p).unwrap().mode() & 0o7777,
                0o755,
                "{}",
                p.display()
            );
            assert_eq!(fs::read(p).unwrap(), b"python-interpreter");
        }
    }

    /// Review F1: another user's inode — a shared install the offender did
    /// not own — keeps its content and its names; made unusable where the
    /// agent may (here the test owns it; the unit, without CAP_FOWNER, is
    /// refused and says so), the row partial and naming the owner.
    #[test]
    fn bug90_review_f1_another_users_inode_keeps_its_content() {
        use std::os::unix::fs::MetadataExt as _;
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        let f = tmp.path().join("tool");
        fs::write(&f, b"shared tool").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o755)).unwrap();
        let owner = fs::metadata(&f).unwrap().uid();
        let h = ExeHandle::open(&f)
            .unwrap()
            .with_offender_uid(Some(owner.wrapping_add(1)));
        let out = quarantine_handle(&h, 4242, &cfg, &super::super::journal::test_intent());
        // re-check of #543 (N1): refused before anything — not even a mode
        let ExecutionOutcome::QuarantineRefused { detail, .. } = &out else {
            panic!("{out:?}");
        };
        assert!(
            detail.contains(&format!("does not own this file (owner uid {owner}")),
            "{detail}"
        );
        assert!(f.exists(), "its name is not removed");
        let m = fs::metadata(&f).unwrap();
        assert_eq!((m.len(), m.mode() & 0o7777), (11, 0o755), "nothing changed");
        assert!(list_vault(&cfg).is_empty(), "nothing vaulted either");
        let (result, _, _) = super::super::journal_outcome(&super::super::ExecutionReport {
            action: nn_model::ResponseAction::Quarantine,
            primary: out.clone(),
            additional: Vec::new(),
            elapsed: std::time::Duration::from_micros(1),
        });
        assert_eq!(result, super::super::journal::ActionResult::Failure);
        // an unknown offender: refused too
        let g = tmp.path().join("tool2");
        fs::write(&g, b"x").unwrap();
        let h = ExeHandle::open(&g).unwrap().with_offender_uid(None);
        let out = quarantine_handle(&h, 4243, &cfg, &super::super::journal::test_intent());
        assert!(
            matches!(&out, ExecutionOutcome::QuarantineRefused { detail, .. } if detail.contains("uid is unknown")),
            "{out:?}"
        );
        assert!(g.exists());
    }

    /// Review F5: with no name verified, the name the kernel shows decides
    /// nothing (a mount namespace's `/usr/bin/…` is no system binary): the
    /// held inode's identity does. One of the agent's own files is
    /// refused; anything else is neutralized in place.
    #[test]
    fn bug90_review_f5_an_unverified_name_is_judged_by_the_held_inode() {
        let tmp = TempDir::new().unwrap();
        let mut cfg = cfg_for(&tmp);
        // an unverified name under a directory the prefixes protect
        let own = tmp.path().join("own");
        fs::create_dir_all(&own).unwrap();
        cfg.own_files.dirs.push(own.clone());
        let f = own.join("payload");
        let keep = tmp.path().join(".keep");
        fs::write(&f, b"malware").unwrap();
        fs::hard_link(&f, &keep).unwrap();
        let h = ExeHandle::open(&f).unwrap();
        fs::remove_file(&f).unwrap();
        let out = quarantine_handle(&h, 4242, &cfg, &super::super::journal::test_intent());
        assert!(
            matches!(
                out,
                ExecutionOutcome::QuarantinedInPlace {
                    effect: InPlaceEffect::Emptied,
                    ..
                }
            ),
            "not refused by the shown name: {out:?}"
        );
        // the agent's own file, held with no verified name: refused
        let mine = tmp.path().join("agent-bin");
        let other = tmp.path().join(".agent-bin-link");
        fs::write(&mine, b"agent").unwrap();
        fs::hard_link(&mine, &other).unwrap();
        cfg.own_files.files.push(other.clone());
        let h = ExeHandle::open(&mine).unwrap();
        fs::remove_file(&mine).unwrap();
        let out = quarantine_handle(&h, 4243, &cfg, &super::super::journal::test_intent());
        assert!(
            matches!(
                out,
                ExecutionOutcome::Refused { reason, .. } if reason.starts_with("a protected system file (by identity")
            ),
            "{out:?}"
        );
        assert_eq!(fs::read(&other).unwrap(), b"agent");
    }

    /// Variant: the name the process ran removed, a hard link keeping the
    /// inode, and a DECOY created at the very name the kernel shows (`…
    /// (deleted)`). The shown name leads to another inode: it is not the
    /// binary's (never removed for it), and the binary is still handled.
    #[test]
    fn bug90_variant_a_decoy_at_the_shown_name_is_not_the_binary() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        let f = tmp.path().join("payload");
        let keep = tmp.path().join(".keep");
        fs::write(&f, b"malware").unwrap();
        fs::hard_link(&f, &keep).unwrap();
        let h = ExeHandle::open(&f).unwrap();
        fs::remove_file(&f).unwrap();
        let decoy = tmp.path().join("payload (deleted)");
        fs::write(&decoy, b"decoy").unwrap();
        assert_eq!(h.current_path(), None, "the shown name leads to the decoy");
        let out = quarantine_handle(&h, 4242, &cfg, &super::super::journal::test_intent());
        assert!(
            matches!(
                out,
                ExecutionOutcome::QuarantinedInPlace {
                    effect: InPlaceEffect::Emptied,
                    ..
                }
            ),
            "{out:?}"
        );
        assert_eq!(
            fs::read(&decoy).unwrap(),
            b"decoy",
            "the decoy is untouched"
        );
        assert_eq!(fs::metadata(&keep).unwrap().len(), 0);
    }

    /// A hidden link the agent cannot empty (here read-only to its owner,
    /// as a read-only mount or a binary still run by another process is to
    /// the agent) keeps its content, is made unusable where it may be, and
    /// the row is partial — never `Quarantined`.
    #[test]
    fn bug90_a_hidden_link_that_cannot_be_emptied_is_partial() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        let f = tmp.path().join("payload");
        let keep = tmp.path().join(".keep");
        fs::write(&f, b"malware").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o444)).unwrap();
        fs::hard_link(&f, &keep).unwrap();
        let h = ExeHandle::open(&f).unwrap();
        fs::remove_file(&f).unwrap();
        let out = quarantine_handle(&h, 4242, &cfg, &super::super::journal::test_intent());
        let ExecutionOutcome::QuarantinedInPlace {
            effect: InPlaceEffect::MadeUnusable,
            detail,
            ..
        } = &out
        else {
            panic!("{out:?}");
        };
        assert!(detail.contains("it could not be emptied"), "{detail}");
        assert_eq!(
            fs::metadata(&keep).unwrap().len(),
            7,
            "still on disk, whole"
        );
    }

    /// Review F4: the name exchanged with a DIRECTORY between its check
    /// and its unlink (`EISDIR`): the removal fails, and the held inode is
    /// still neutralized in place — never "refused, binary intact". The
    /// directory now at that name is untouched.
    #[test]
    fn bug90_review_f4_a_name_swapped_for_a_directory_still_neutralizes() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        let a = tmp.path().join("a");
        let d = tmp.path().join("d");
        fs::write(&a, b"malware").unwrap();
        fs::create_dir(&d).unwrap();
        fs::write(d.join("inside"), b"x").unwrap();
        let h = ExeHandle::open(&a).unwrap();
        let (ca, cd) = (
            std::ffi::CString::new(a.as_os_str().as_bytes()).unwrap(),
            std::ffi::CString::new(d.as_os_str().as_bytes()).unwrap(),
        );
        let swapped = std::cell::Cell::new(false);
        let swap = || {
            if swapped.replace(true) {
                return;
            }
            // SAFETY: two NUL-terminated paths; renameat2 reads them only.
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    libc::AT_FDCWD,
                    ca.as_ptr(),
                    libc::AT_FDCWD,
                    cd.as_ptr(),
                    libc::RENAME_EXCHANGE,
                )
            };
            assert_eq!(rc, 0, "premise: the exchange");
        };
        let done = super::quarantine_file_with(&h, &cfg, || {}, &swap).unwrap();
        assert!(swapped.get(), "premise: the swap ran before the unlink");
        let Done::InPlace {
            effect: InPlaceEffect::Emptied,
            ..
        } = &done
        else {
            panic!("{done:?}");
        };
        assert_eq!(
            h.file.metadata().unwrap().len(),
            0,
            "the binary (now named d) emptied"
        );
        assert!(
            a.join("inside").exists(),
            "the directory now at `a` is untouched"
        );
    }

    /// Review F9: a binary with no name left that the agent holds is gone
    /// from disk (`AlreadyGone`), and its content is vaulted as evidence.
    #[test]
    fn bug90_review_f9_a_nameless_binary_is_vaulted_as_evidence() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        let f = tmp.path().join("payload");
        fs::write(&f, b"fileless").unwrap();
        let h = ExeHandle::open(&f).unwrap();
        fs::remove_file(&f).unwrap();
        let out = quarantine_handle(&h, 4242, &cfg, &super::super::journal::test_intent());
        assert_eq!(out, ExecutionOutcome::AlreadyGone { pid: 4242 });
        let entries = list_vault(&cfg);
        assert_eq!(entries.len(), 1, "{entries:?}");
        let meta = vault_meta(&entries[0].vault_id, &cfg).unwrap();
        assert_eq!(meta["nameless"], true);
        assert!(meta["original_path"].is_null(), "no name, none invented");
        let to = tmp.path().join("evidence");
        restore_entry(&entries[0].vault_id, Some(to.to_str().unwrap()), &cfg).unwrap();
        assert_eq!(fs::read(&to).unwrap(), b"fileless");
    }

    /// The restore in place puts content back only into the very inode
    /// taken (another file at the name is refused), and never over a file
    /// written since it was emptied.
    #[test]
    fn bug90_review_f1_a_restore_in_place_finds_the_same_inode_or_refuses() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        let f = tmp.path().join("payload");
        let keep = tmp.path().join(".keep");
        fs::write(&f, b"malware").unwrap();
        fs::hard_link(&f, &keep).unwrap();
        let h = ExeHandle::open(&f).unwrap();
        fs::remove_file(&f).unwrap();
        let ExecutionOutcome::QuarantinedInPlace { vault_id, .. } =
            quarantine_handle(&h, 4242, &cfg, &super::super::journal::test_intent())
        else {
            panic!();
        };
        let other = tmp.path().join("other");
        fs::write(&other, b"").unwrap();
        let e = restore_entry(&vault_id, Some(other.to_str().unwrap()), &cfg).unwrap_err();
        assert!(e.to_string().contains("is not the file"), "{e}");
        assert_eq!(fs::read(&other).unwrap(), b"");
        // written since: not overwritten
        fs::set_permissions(&keep, fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(&keep, b"new").unwrap();
        let e = restore_entry(&vault_id, Some(keep.to_str().unwrap()), &cfg).unwrap_err();
        assert!(e.to_string().contains("written since"), "{e}");
        assert_eq!(fs::read(&keep).unwrap(), b"new");
    }

    /// A binary with no name left is gone in detect-only too (nothing a
    /// quarantine would do), and the removal of a binary whose verified
    /// name went meanwhile says so instead of "the path changed".
    #[test]
    fn bug90_no_name_left_is_gone_and_said_so() {
        let tmp = TempDir::new().unwrap();
        let dry = ExecutorConfig::for_test(tmp.path());
        assert!(dry.dry_run, "premise: for_test is detect-only");
        let f = tmp.path().join("payload");
        fs::write(&f, b"malware").unwrap();
        let h = ExeHandle::open(&f).unwrap();
        let keep = tmp.path().join(".keep");
        fs::hard_link(&f, &keep).unwrap();
        fs::remove_file(&f).unwrap();
        // the name the agent knew went; another link holds the inode
        assert_eq!(remove_held(&h, &dry).unwrap(), Removal::NoNameLeft);
        assert_eq!(fs::metadata(&keep).unwrap().len(), 7, "nothing removed");
        fs::remove_file(&keep).unwrap();
        let out = quarantine_handle(&h, 4242, &dry, &super::super::journal::test_intent());
        assert_eq!(out, ExecutionOutcome::AlreadyGone { pid: 4242 });
        assert!(list_vault(&dry).is_empty(), "detect-only vaults nothing");
    }

    /// The offender's uid is the one file access is judged with (`Uid:`'s
    /// fourth field): a set-uid run's real uid is not the owner it writes
    /// as.
    #[test]
    fn review_f1_the_offenders_uid_is_its_filesystem_uid() {
        assert_eq!(
            fsuid_in("Name:\tx\nUid:\t1000\t0\t0\t0\nGid:\t1\t1\t1\t1\n"),
            Some(0)
        );
        assert_eq!(fsuid_in("Uid:\t1000\t1000\t1000\t1001\n"), Some(1001));
        assert_eq!(fsuid_in("Uid:\t1000\n"), None);
        // SAFETY: getuid(2) takes no argument and cannot fail.
        let me = unsafe { libc::getuid() };
        assert_eq!(fsuid_of(std::process::id()), Some(me));
    }

    /// Where the filesystem records no birth time, the inode number alone
    /// tells the taken file from another at the name given.
    #[test]
    fn review_f1_without_a_birth_time_the_inode_number_decides() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        let f = tmp.path().join("payload");
        let keep = tmp.path().join(".keep");
        fs::write(&f, b"malware").unwrap();
        fs::hard_link(&f, &keep).unwrap();
        let h = ExeHandle::open(&f).unwrap();
        fs::remove_file(&f).unwrap();
        let ExecutionOutcome::QuarantinedInPlace { vault_id, .. } =
            quarantine_handle(&h, 4242, &cfg, &super::super::journal::test_intent())
        else {
            panic!();
        };
        let meta_path = cfg
            .quarantine_dir
            .join("vault")
            .join(format!("{vault_id}.meta"));
        let mut meta: serde_json::Value =
            serde_json::from_slice(&fs::read(&meta_path).unwrap()).unwrap();
        meta["inode"]["btime_ns"] = serde_json::Value::Null;
        fs::write(&meta_path, meta.to_string()).unwrap();
        let other = tmp.path().join("other");
        fs::write(&other, b"").unwrap();
        let e = restore_entry(&vault_id, Some(other.to_str().unwrap()), &cfg).unwrap_err();
        assert!(e.to_string().contains("is not the file"), "{e}");
        assert_eq!(fs::read(&other).unwrap(), b"");
        restore_entry(&vault_id, Some(keep.to_str().unwrap()), &cfg).unwrap();
        assert_eq!(fs::read(&keep).unwrap(), b"malware");
    }

    /// The executor's signed row of an in-place quarantine: `partial` with
    /// what was done when the content is kept, `success` when it is gone.
    #[test]
    fn review_f1_the_signed_row_of_an_in_place_quarantine() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        let key = crate::audit::AgentSigningKey::load_or_bootstrap(&tmp.path().join("agent.sig"))
            .unwrap();
        let log = std::sync::Arc::new(parking_lot::Mutex::new(
            crate::audit::AuditLog::open(&tmp.path().join("audit.log"), key, [7u8; 16]).unwrap(),
        ));
        let exec = super::super::Executor::with_config(cfg.clone());
        exec.set_audit_log(log);
        let rows = || -> Vec<serde_json::Value> {
            fs::read_to_string(tmp.path().join("audit.log"))
                .unwrap_or_default()
                .lines()
                .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
                .filter(|r| r["op"] == "response_quarantine")
                .collect()
        };
        // shared: content kept
        let a = tmp.path().join("a");
        fs::write(&a, b"shared").unwrap();
        fs::hard_link(&a, tmp.path().join("a2")).unwrap();
        exec.quarantine_handle(
            &ExeHandle::open(&a).unwrap(),
            4242,
            &super::super::journal::test_intent(),
        );
        // hidden link of its own: emptied
        let b = tmp.path().join("b");
        fs::write(&b, b"own").unwrap();
        fs::hard_link(&b, tmp.path().join(".b")).unwrap();
        let hb = ExeHandle::open(&b).unwrap();
        fs::remove_file(&b).unwrap();
        exec.quarantine_handle(&hb, 4243, &super::super::journal::test_intent());
        let r = rows();
        assert_eq!(r.len(), 2, "{r:?}");
        assert_eq!(r[0]["result"], "partial");
        assert!(r[0]["extra"]["in_place"]
            .as_str()
            .unwrap()
            .contains("shared: 2 links"));
        assert_eq!(r[1]["result"], "success");
        assert!(r[1]["extra"]["in_place"]
            .as_str()
            .unwrap()
            .starts_with("emptied in place"));
        assert!(r[1]["extra"]["original_path"].is_null(), "no name invented");
    }

    fn not_root() -> bool {
        // SAFETY: geteuid(2) takes no argument and cannot fail.
        let root = unsafe { libc::geteuid() } == 0;
        if root {
            eprintln!("SKIP: this test reads system files and must not run as root");
        }
        !root
    }

    /// Re-check of #543 (N1): a root-owned file reached through a name that
    /// does not verify (a mount namespace's bind of the host's `/usr/bin`)
    /// is never changed, whoever the offender is — refused before any
    /// mode change, nothing vaulted, the row a failure.
    #[test]
    fn n1_a_root_owned_file_without_a_verified_name_is_never_changed() {
        if !not_root() {
            return;
        }
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        let sys = ["/usr/bin/sleep", "/bin/sleep", "/usr/bin/true"]
            .into_iter()
            .find(|p| fs::metadata(p).is_ok_and(|m| m.uid() == 0))
            .expect("a root-owned system binary");
        let before = fs::metadata(sys).unwrap().mode();
        for offender in [Some(1000), Some(0), None] {
            let h = ExeHandle::open(Path::new(sys))
                .unwrap()
                .unverifiable()
                .with_offender_uid(offender);
            let out = quarantine_handle(&h, 4242, &cfg, &super::super::journal::test_intent());
            let ok = match &out {
                ExecutionOutcome::QuarantineRefused { detail, .. } => {
                    detail.starts_with("a root-owned file (uid 0")
                }
                // a shell or the loader: refused by identity first
                ExecutionOutcome::Refused { reason, .. } => reason.contains("by identity"),
                _ => false,
            };
            assert!(ok, "offender {offender:?}: {out:?}");
        }
        assert_eq!(
            fs::metadata(sys).unwrap().mode(),
            before,
            "never a mode change"
        );
        assert!(list_vault(&cfg).is_empty());
    }

    /// Re-check of #543 (N1), with lot 311b's rule: the shells a
    /// `/etc/shells` lists, its bytes made text; none for a host without
    /// one; an error — never an empty list — for one that cannot be read.
    #[test]
    fn n1_an_unreadable_shell_list_is_an_error_not_an_empty_one() {
        let tmp = TempDir::new().unwrap();
        let list = tmp.path().join("shells");
        fs::write(
            &list,
            b"# comment\n/bin/sh\n  /usr/bin/fish \nnologin\n/opt/\xff/zsh\n",
        )
        .unwrap();
        assert_eq!(
            listed_shells(&list).unwrap(),
            [
                PathBuf::from("/bin/sh"),
                PathBuf::from("/usr/bin/fish"),
                PathBuf::from("/opt/\u{fffd}/zsh"),
            ]
        );
        assert!(listed_shells(&tmp.path().join("none")).unwrap().is_empty());
        // a directory in its place: EISDIR, not NotFound
        assert!(listed_shells(tmp.path()).is_err());
    }

    /// Re-check of #543 (N1), with lot 311b's rule: a shell list that
    /// cannot be read refuses the quarantine — even of the offender's own
    /// payload — before anything is changed or vaulted; the same payload is
    /// quarantined once the list reads.
    #[test]
    fn n1_an_unreadable_shell_list_refuses_the_quarantine() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        let payload = tmp.path().join("payload.bin");
        fs::write(&payload, b"the offender's own payload").unwrap();
        let before = fs::metadata(&payload).unwrap().mode();
        let h = ExeHandle::open(&payload).unwrap();
        SHELLS_AT.with(|s| *s.borrow_mut() = Some(tmp.path().to_path_buf()));
        let out = quarantine_file(&h, &cfg);
        SHELLS_AT.with(|s| *s.borrow_mut() = None);
        match &out {
            Err(QuarantineError::Refused(why)) => assert!(
                why.contains("could not be read") && why.contains("no file is changed"),
                "{why}"
            ),
            other => panic!("{other:?}"),
        }
        assert_eq!(fs::read(&payload).unwrap(), b"the offender's own payload");
        assert_eq!(fs::metadata(&payload).unwrap().mode(), before);
        assert!(list_vault(&cfg).is_empty(), "nothing vaulted");
        // premise: the refusal was the list's
        assert!(quarantine_file(&h, &cfg).is_ok());
        assert!(!payload.exists());
    }

    /// Re-check of #543 (N1): a shell the list names — here only there, by
    /// a name of the test's own — is refused by identity, the offender's
    /// own file too, and left as it was.
    #[test]
    fn n1_a_shell_the_list_names_is_refused_by_identity() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        let shell = tmp.path().join("myshell");
        fs::write(&shell, b"a login shell").unwrap();
        let list = tmp.path().join("shells");
        fs::write(&list, format!("# shells\n{}\n", shell.display())).unwrap();
        let h = ExeHandle::open(&shell).unwrap();
        SHELLS_AT.with(|s| *s.borrow_mut() = Some(list));
        let out = quarantine_file(&h, &cfg);
        SHELLS_AT.with(|s| *s.borrow_mut() = None);
        assert!(
            matches!(out, Err(QuarantineError::ProtectedFile)),
            "{out:?}"
        );
        assert_eq!(fs::read(&shell).unwrap(), b"a login shell");
        assert!(list_vault(&cfg).is_empty(), "nothing vaulted");
    }

    /// Re-check of #543 (N1): the system's own files are refused by
    /// IDENTITY, whatever name leads to them — the dynamic loader, the
    /// shells — the check winning over any name, verified or not.
    #[test]
    fn n1_the_loader_and_the_shells_are_refused_by_identity() {
        if !not_root() {
            return;
        }
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        let ids = protected_identities(&cfg, &listed_shells(Path::new(SHELLS)).unwrap());
        let loader = LOADER_DIRS
            .iter()
            .filter_map(|d| fs::read_dir(d).ok())
            .flat_map(|e| e.flatten())
            .map(|e| e.path())
            .find(|p| {
                p.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with("ld-linux"))
            })
            .expect("a dynamic loader on this host");
        let mut checked = 0;
        for p in [
            loader.as_path(),
            Path::new("/bin/sh"),
            Path::new("/usr/bin/bash"),
        ] {
            let Ok(m) = fs::metadata(p) else { continue };
            assert!(
                ids.contains(&(m.dev(), m.ino())),
                "{} not protected",
                p.display()
            );
            for h in [
                ExeHandle::open(p).unwrap().unverifiable(),
                ExeHandle::open(p).unwrap().with_offender_uid(Some(0)),
            ] {
                let out = quarantine_handle(&h, 4242, &cfg, &super::super::journal::test_intent());
                assert!(
                    matches!(&out, ExecutionOutcome::Refused { reason, .. } if reason.contains("by identity")),
                    "{}: {out:?}",
                    p.display()
                );
            }
            checked += 1;
        }
        assert!(checked >= 2, "{checked}");
    }

    /// Re-check of #543 (N1), the reviewer's case: an unprivileged user
    /// namespace binds the host's `/usr/bin` and runs its `sleep` (and its
    /// shell) from there. The agent sees a name of the namespace that does
    /// not verify: refused before any mode change. Needs `unshare -Urm`
    /// (unprivileged user namespaces); said and skipped where denied.
    #[test]
    fn n1_a_host_binary_through_a_user_namespace_bind_is_refused() {
        if !not_root() {
            return;
        }
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        let bin = tmp.path().join("ns/bin");
        fs::create_dir_all(&bin).unwrap();
        for prog in ["sleep", "bash"] {
            let host = Path::new("/usr/bin").join(prog);
            let Ok(before) = fs::metadata(&host).map(|m| m.mode()) else {
                continue;
            };
            let script = if prog == "sleep" {
                format!(
                    "mount --bind /usr/bin {b} && exec {b}/sleep 30",
                    b = bin.display()
                )
            } else {
                format!(
                    "mount --bind /usr/bin {b} && exec {b}/bash -c 'sleep 30; true'",
                    b = bin.display()
                )
            };
            let Ok(mut child) = std::process::Command::new("unshare")
                .args(["-Urm", "sh", "-c", &script])
                .spawn()
            else {
                eprintln!("SKIP: no unshare");
                return;
            };
            let pid = child.id();
            let mut link = PathBuf::new();
            for _ in 0..200 {
                link = fs::read_link(format!("/proc/{pid}/exe")).unwrap_or_default();
                if link.file_name().is_some_and(|n| n == prog) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            if link.file_name().is_none_or(|n| n != prog) {
                let _ = child.kill();
                let _ = child.wait();
                eprintln!("SKIP: unprivileged user namespaces denied here ({link:?})");
                return;
            }
            let out = quarantine_process_binary(
                pid,
                &HashSet::new(),
                &cfg,
                &super::super::journal::test_intent(),
            );
            let after = fs::metadata(&host).unwrap().mode();
            let _ = child.kill();
            let _ = child.wait();
            assert!(
                matches!(&out, ExecutionOutcome::QuarantineRefused { .. })
                    || matches!(&out, ExecutionOutcome::Refused { reason, .. } if reason.contains("by identity")),
                "{prog} through {link:?}: {out:?}"
            );
            assert_eq!(after, before, "{prog}: never a mode change");
        }
    }

    /// Re-check of #543 (N2): a root offender running another user's
    /// payload (dropped by `www-data`, run by root) by a VERIFIED name — the
    /// name is removed as before the lot, the content in the vault.
    #[test]
    fn n2_a_root_offender_quarantines_another_users_payload_by_its_name() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        let f = tmp.path().join("payload");
        fs::write(&f, b"dropped by www-data").unwrap();
        let h = ExeHandle::open(&f).unwrap().with_offender_uid(Some(0));
        let out = quarantine_handle(&h, 4242, &cfg, &super::super::journal::test_intent());
        assert!(
            matches!(&out, ExecutionOutcome::Quarantined { original_path, .. } if Path::new(original_path) == f),
            "{out:?}"
        );
        assert!(!f.exists());
        assert_eq!(restored(&cfg, &tmp, &out), b"dropped by www-data");
        // without a verified name, root has no more than the owner's say
        let g = tmp.path().join("payload2");
        let keep = tmp.path().join(".keep2");
        fs::write(&g, b"x").unwrap();
        fs::hard_link(&g, &keep).unwrap();
        // SAFETY: geteuid(2) takes no argument and cannot fail.
        let me = unsafe { libc::geteuid() };
        if me != 0 {
            let h = ExeHandle::open(&g).unwrap().with_offender_uid(Some(0));
            fs::remove_file(&g).unwrap();
            let out = quarantine_handle(&h, 4243, &cfg, &super::super::journal::test_intent());
            assert!(
                matches!(&out, ExecutionOutcome::QuarantineRefused { .. }),
                "{out:?}"
            );
            assert_eq!(fs::read(&keep).unwrap(), b"x");
        }
    }

    /// Re-check of #543 (N2): a quarantine whose only effect was the vault —
    /// the file could not be changed (another owner's mode, a write
    /// refused) — is `Unchanged`, signed a FAILURE, never partial.
    #[test]
    fn n2_a_quarantine_that_only_vaulted_is_a_failure() {
        if !not_root() {
            return;
        }
        let sys = ["/usr/bin/sleep", "/bin/sleep"]
            .into_iter()
            .find(|p| fs::metadata(p).is_ok_and(|m| m.uid() == 0))
            .expect("a root-owned file");
        let h = ExeHandle::open(Path::new(sys)).unwrap();
        let m = fs::metadata(sys).unwrap();
        let before = m.mode();
        let (detail, effect) = neutralize_in_place(&h, &Identity::of(&h, &m), true);
        assert_eq!(effect, InPlaceEffect::Unchanged, "{detail}");
        assert!(
            detail.starts_with("vaulted only, the file NOT changed"),
            "{detail}"
        );
        assert_eq!(fs::metadata(sys).unwrap().mode(), before);
        let (result, _, _) = super::super::journal_outcome(&super::super::ExecutionReport {
            action: nn_model::ResponseAction::Quarantine,
            primary: ExecutionOutcome::QuarantinedInPlace {
                vault_id: "v".into(),
                original_path: None,
                detail,
                effect,
            },
            additional: Vec::new(),
            elapsed: std::time::Duration::from_micros(1),
        });
        assert_eq!(result, super::super::journal::ActionResult::Failure);
    }
}

/// Lot 311 (bug hunt 1.4, BUG-95): an index that is not UTF-8.
#[cfg(test)]
mod bug95 {
    use super::*;
    use tempfile::TempDir;

    /// Promise (CMB-017): an index that does not parse is kept aside,
    /// rebuilt from the `.meta` files, and the quarantine goes on — one
    /// that is not UTF-8 too (on main: `Failed { errno: 0 }`, the original
    /// left on disk, every later quarantine failing the same way).
    #[test]
    fn a_non_utf8_index_is_kept_aside_and_rebuilt() {
        let tmp = TempDir::new().unwrap();
        let mut cfg = ExecutorConfig::for_test(tmp.path());
        cfg.dry_run = false;
        let intent = super::super::journal::test_intent();
        let a = tmp.path().join("first.bin");
        fs::write(&a, b"first").unwrap();
        let first = quarantine_handle(&ExeHandle::open(&a).unwrap(), 4241, &cfg, &intent);
        assert!(
            matches!(first, ExecutionOutcome::Quarantined { .. }),
            "premise: {first:?}"
        );
        let index = cfg.quarantine_dir.join("index.json");
        let mut bytes = fs::read(&index).unwrap();
        let at = bytes.len() / 2;
        bytes[at] = 0xFF;
        fs::write(&index, bytes).unwrap();
        assert_eq!(list_vault(&cfg).len(), 1, "listed from the .meta files");
        let b = tmp.path().join("payload.bin");
        fs::write(&b, b"payload").unwrap();
        let out = quarantine_handle(&ExeHandle::open(&b).unwrap(), 4242, &cfg, &intent);
        let kept_aside = fs::read_dir(&cfg.quarantine_dir)
            .unwrap()
            .flatten()
            .any(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("index.json.corrupt-")
            });
        let _ = take_index_notes(&cfg.quarantine_dir);
        let still = b.exists();
        assert!(
            matches!(out, ExecutionOutcome::Quarantined { .. }) && !still && kept_aside,
            "BUG-95: outcome {out:?}, original still on disk: {still}, index kept aside: {kept_aside}"
        );
        assert_eq!(list_vault(&cfg).len(), 2);
    }

    /// Guard (must stay): a UTF-8 index that does not parse is repaired.
    #[test]
    fn a_utf8_corrupt_index_is_repaired() {
        let tmp = TempDir::new().unwrap();
        let mut cfg = ExecutorConfig::for_test(tmp.path());
        cfg.dry_run = false;
        let intent = super::super::journal::test_intent();
        fs::create_dir_all(&cfg.quarantine_dir).unwrap();
        fs::write(cfg.quarantine_dir.join("index.json"), b"{ not json").unwrap();
        let b = tmp.path().join("payload.bin");
        fs::write(&b, b"payload").unwrap();
        let out = quarantine_handle(&ExeHandle::open(&b).unwrap(), 4242, &cfg, &intent);
        let _ = take_index_notes(&cfg.quarantine_dir);
        assert!(
            matches!(out, ExecutionOutcome::Quarantined { .. }) && !b.exists(),
            "{out:?}"
        );
    }
}
