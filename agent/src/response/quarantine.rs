//! `Quarantine` — encrypt a target's executable into a vault and
//! remove the original file.
//!
//! Vault layout:
//! ```text
//! <quarantine_dir>/
//! ├── index.json          (mode 0600; atomic write via tmp+rename)
//! └── vault/
//!     ├── <uuid>.bin      (AES-256-GCM ciphertext, mode 0600)
//!     └── <uuid>.meta     (JSON metadata, mode 0600)
//! ```
//!
//! Crypto:
//! - Master key: 32 random bytes at [`ExecutorConfig::master_key_file`],
//!   created mode 0600 on first use, kept in memory wrapped in
//!   `Zeroizing<[u8; 32]>` so it gets wiped on drop.
//! - Per-file derivation: HKDF-SHA256 with salt
//!   `"northnarrow-quarantine-v1"` and per-file info equal to the
//!   vault id. This means a leaked file-key can decrypt only its
//!   own ciphertext.
//! - Per-file nonce: 96 random bits, fresh per encryption.
//!
//! [`restore`] reverses the operation: decrypts the vault file and
//! writes it to a new file (never over an existing one, never through a
//! link), after checking it against the SHA-256 recorded at capture.
//! The vault entry stays.

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use zeroize::Zeroizing;

use super::{config::ExecutorConfig, ExecutionOutcome};

const KDF_SALT: &[u8] = b"northnarrow-quarantine-v1";

/// Paths that are NEVER quarantined, whatever the verdict says.
///
/// `quarantine_file` unlinks the original after vaulting it. For a
/// system binary (`/usr/bin/bash` abused by `bash -c`, `systemd`,
/// `sshd`), a kernel image, a config tree, or NorthNarrow's own
/// binaries/state, that unlink makes the host unbootable, locks the
/// operator out, or disables the agent itself — a self-inflicted
/// denial of service that a malformed event, an LLM verdict or an
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

/// `true` when `path` must never be vaulted + unlinked. Lexical check on
/// the path of the inode itself ([`ExeHandle::current_path`]: absolute and
/// symlink-free at the moment it is read).
pub fn is_quarantine_denied(path: &Path) -> bool {
    let p = path.to_string_lossy();
    QUARANTINE_DENY_PREFIXES.iter().any(|d| p.starts_with(d))
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
}

impl ExeHandle {
    /// The executable `pid` runs. `Ok(None)` once the process has exited,
    /// or when its binary was deleted while it ran (the kernel's
    /// ` (deleted)` suffix): nothing on disk to quarantine.
    pub fn of_pid(pid: u32) -> std::io::Result<Option<Self>> {
        let link = format!("/proc/{pid}/exe");
        match fs::read_link(&link) {
            Ok(p) if p.to_string_lossy().ends_with(" (deleted)") => return Ok(None),
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        }
        match fs::File::open(&link) {
            Ok(f) => Self::from_file(f).map(Some),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// The file at `path` (tests, tools).
    pub fn open(path: &Path) -> std::io::Result<Self> {
        Self::from_file(fs::File::open(path)?)
    }

    fn from_file(file: fs::File) -> std::io::Result<Self> {
        let m = file.metadata()?;
        Ok(Self {
            dev: m.dev(),
            ino: m.ino(),
            file,
        })
    }

    /// Where the inode is now, from the agent's own descriptor
    /// (`/proc/self/fd/N`): a rename or a swapped directory moves it, a
    /// string read earlier does not. `None` once it was unlinked.
    pub fn current_path(&self) -> Option<PathBuf> {
        let p = fs::read_link(format!("/proc/self/fd/{}", self.file.as_raw_fd())).ok()?;
        (!p.to_string_lossy().ends_with(" (deleted)")).then_some(p)
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
const NONCE_LEN: usize = 12;

/// Public entry point: encrypt the binary backing `target_pid` and
/// remove the original file.
pub fn quarantine_process_binary(
    target_pid: u32,
    protected: &HashSet<u32>,
    cfg: &ExecutorConfig,
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
    quarantine_handle(&handle, target_pid, cfg)
}

/// Review 87: encrypt the binary `handle` holds into the vault and remove
/// it. `pid` is the process it backed, for the outcome. The combat
/// ladder's NEUTRALIZE opens the binary before it kills the process (after
/// the kill `/proc/<pid>/exe` is gone) and quarantines it here.
pub fn quarantine_handle(handle: &ExeHandle, pid: u32, cfg: &ExecutorConfig) -> ExecutionOutcome {
    let target_pid = pid;
    let original_str = match handle.current_path() {
        Some(p) => p.to_string_lossy().into_owned(),
        None => return ExecutionOutcome::AlreadyGone { pid: target_pid },
    };

    if cfg.dry_run {
        info!(
            pid = target_pid,
            path = %original_str,
            "dry-run: would quarantine binary"
        );
        return ExecutionOutcome::Quarantined {
            original_path: original_str,
            vault_id: "dry-run".to_string(),
        };
    }

    match quarantine_file(handle, cfg) {
        Ok(vault_id) => {
            info!(
                pid = target_pid,
                vault_id = %vault_id,
                path = %original_str,
                "quarantined binary"
            );
            ExecutionOutcome::Quarantined {
                original_path: original_str,
                vault_id,
            }
        }
        Err(QuarantineError::Gone) => ExecutionOutcome::AlreadyGone { pid: target_pid },
        Err(QuarantineError::PathSwapped) => {
            warn!(
                pid = target_pid,
                path = %original_str,
                "the binary's path no longer names the file the process ran (a directory \
                 swapped for a link?) — vaulted, not removed"
            );
            ExecutionOutcome::Refused {
                pid: target_pid,
                reason: "the binary's path changed under the quarantine — vaulted, not removed",
            }
        }
        Err(QuarantineError::ProtectedPath) => {
            warn!(
                pid = target_pid,
                path = %original_str,
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
pub fn check_restore_destination(path: &Path) -> std::io::Result<()> {
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
    if is_quarantine_denied(path) {
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
    let dest = match to {
        Some(t) => PathBuf::from(t),
        None => {
            let meta = vault_meta(vault_id, cfg)
                .ok_or_else(|| std::io::Error::new(ErrorKind::NotFound, "no such vault entry"))?;
            PathBuf::from(meta["original_path"].as_str().ok_or_else(|| {
                std::io::Error::new(ErrorKind::InvalidData, "the entry records no original path")
            })?)
        }
    };
    restore(vault_id, &dest, cfg)?;
    Ok(dest)
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
    check_restore_destination(out_path)?;
    let vault_dir = cfg.quarantine_dir.join("vault");
    let bin_path = vault_dir.join(format!("{vault_id}.bin"));
    let meta = vault_meta(vault_id, cfg)
        .ok_or_else(|| std::io::Error::new(ErrorKind::NotFound, "no such vault entry"))?;
    let want_sha = meta["sha256"]
        .as_str()
        .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidData, "the entry records no sha256"))?
        .to_ascii_lowercase();

    let mut bin = fs::read(&bin_path)?;
    if bin.len() < NONCE_LEN {
        return Err(std::io::Error::other("vault file too short"));
    }
    let nonce_bytes: [u8; NONCE_LEN] = bin[..NONCE_LEN]
        .try_into()
        .map_err(|_| std::io::Error::other("nonce slice"))?;
    let ciphertext = bin.split_off(NONCE_LEN);
    drop(bin);

    let master = load_or_init_master_key(cfg)?;
    let key = derive_file_key(&master, vault_id);
    let cipher = Aes256Gcm::new((&*key).into());
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &ciphertext,
                    aad: vault_id.as_bytes(),
                },
            )
            .map_err(|e| std::io::Error::other(format!("decrypt: {e}")))?,
    );
    let got_sha = format!("{:x}", Sha256::digest(&*plaintext));
    if got_sha != want_sha {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!("sha256 mismatch: the entry recorded {want_sha}, the content is {got_sha}"),
        ));
    }

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
        if is_quarantine_denied(&real.join(name)) || is_quarantine_denied(&real) {
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
        .and_then(|()| out.write_all(&plaintext))
        .and_then(|()| out.sync_all());
    if let Err(e) = written {
        drop(out);
        // SAFETY: the same directory fd and name as the openat above.
        unsafe { libc::unlinkat(dir.as_raw_fd(), cname.as_ptr(), 0) };
        return Err(e);
    }

    info!(
        vault_id,
        out = %out_path.display(),
        size = plaintext.len(),
        "restored quarantined file (mode 0600)"
    );
    Ok(())
}

#[derive(Debug)]
enum QuarantineError {
    /// Path is under [`QUARANTINE_DENY_PREFIXES`]; nothing was touched.
    ProtectedPath,
    /// The file was unlinked before the quarantine reached it.
    Gone,
    /// External audit CMB-001: the path no longer names the inode the
    /// process ran; the content is vaulted, nothing is removed.
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

fn quarantine_file(handle: &ExeHandle, cfg: &ExecutorConfig) -> Result<String, QuarantineError> {
    let original_buf = handle.current_path().ok_or(QuarantineError::Gone)?;
    let original = original_buf.as_path();
    if is_quarantine_denied(original) {
        return Err(QuarantineError::ProtectedPath);
    }
    let meta = handle.file.metadata()?;
    let size = meta.len();
    if size > cfg.quarantine_max_bytes {
        return Err(QuarantineError::TooLarge {
            size,
            max: cfg.quarantine_max_bytes,
        });
    }

    // Read once, from the inode the handle holds.
    let mut content = Vec::with_capacity(size as usize + 16);
    let mut reader = &handle.file;
    reader.seek(SeekFrom::Start(0))?;
    reader.read_to_end(&mut content)?;
    let sha = Sha256::digest(&content);

    // Encrypt.
    let vault_id = uuid::Uuid::new_v4().simple().to_string();
    let master = load_or_init_master_key(cfg)?;
    let file_key = derive_file_key(&master, &vault_id);
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new((&*file_key).into());
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &content,
                aad: vault_id.as_bytes(),
            },
        )
        .map_err(|e| QuarantineError::Crypto(format!("encrypt: {e}")))?;

    // Lay out the vault.
    let vault_dir = cfg.quarantine_dir.join("vault");
    fs::create_dir_all(&vault_dir)?;
    set_dir_root_only(&cfg.quarantine_dir);
    set_dir_root_only(&vault_dir);

    let bin_path = vault_dir.join(format!("{vault_id}.bin"));
    let meta_path = vault_dir.join(format!("{vault_id}.meta"));

    // Write ciphertext (nonce prefix). Mode 0600.
    let mut bin_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&bin_path)?;
    bin_file.write_all(&nonce)?;
    bin_file.write_all(&ciphertext)?;
    bin_file.sync_all()?;
    drop(bin_file);

    // Write meta as JSON.
    let original_str = original.to_string_lossy().into_owned();
    let meta_json = serde_json::json!({
        "vault_id": vault_id,
        "original_path": original_str,
        "size_bytes": size,
        "sha256": format!("{:x}", sha),
        "captured_at": current_timestamp(),
    });
    let mut meta_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&meta_path)?;
    meta_file.write_all(meta_json.to_string().as_bytes())?;
    meta_file.sync_all()?;
    drop(meta_file);

    // Update index.json atomically (tmp + fsync + rename).
    update_index(&cfg.quarantine_dir, &vault_id, &original_str, size)?;

    remove_held(handle)?;
    Ok(vault_id)
}

/// Tries of the verified removal. A swap racing it fails the `(dev, ino)`
/// comparison of that try only; the next one starts again from where the
/// inode is (lab, CMB-001: a directory exchanged with a symlink in a tight
/// loop failed about one try in two).
const REMOVE_TRIES: usize = 8;

/// Remove the binary `handle` holds by its current name, re-read from the
/// descriptor for each try ([`ExeHandle::current_path`]) and judged by the
/// denylist each time. [`QuarantineError::PathSwapped`] once the tries are
/// spent, or once the name the agent knew is gone while the inode lives on
/// (another name may hold it): vaulted, not removed.
fn remove_held(handle: &ExeHandle) -> Result<(), QuarantineError> {
    for _ in 0..REMOVE_TRIES {
        let Some(path) = handle.current_path() else {
            break;
        };
        if is_quarantine_denied(&path) {
            return Err(QuarantineError::ProtectedPath);
        }
        match remove_verified(&path, handle) {
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
/// path leads to. If the unlink fails (EBUSY on an mmapped binary), the
/// verified file is made unusable (`fchmod 000`); if that fails too the
/// binary is still there, which is a failure, never a quarantine.
fn remove_verified(path: &Path, handle: &ExeHandle) -> Result<(), QuarantineError> {
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
    // SAFETY: the same directory fd and name as the openat above.
    if unsafe { libc::unlinkat(dir.as_raw_fd(), cname.as_ptr(), 0) } != 0 {
        let e = std::io::Error::last_os_error();
        warn!(error = %e, path = %path.display(), "remove original failed; chmod 000");
        target.set_permissions(fs::Permissions::from_mode(0o000))?;
    }
    Ok(())
}

/// External audit CMB-017: what happened to a quarantine index that did
/// not parse, waiting to be recorded in the signed audit log by the
/// executor ([`take_index_notes`]).
static INDEX_NOTES: parking_lot::Mutex<Vec<String>> = parking_lot::const_mutex(Vec::new());

/// The index repairs since the last call (external audit CMB-017).
pub fn take_index_notes() -> Vec<String> {
    std::mem::take(&mut *INDEX_NOTES.lock())
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
    let entries: Vec<serde_json::Value> =
        match fs::read_to_string(cfg.quarantine_dir.join("index.json")) {
            Ok(s) => {
                serde_json::from_str(&s).unwrap_or_else(|_| index_from_meta(&cfg.quarantine_dir))
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
                .filter_map(|e| fs::read_to_string(e.path()).ok())
                .filter_map(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
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

    let mut entries: Vec<serde_json::Value> = match fs::read_to_string(&index_path) {
        Ok(s) => match serde_json::from_str(&s) {
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
                INDEX_NOTES.lock().push(note);
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

/// Load the 32-byte master key. Generate + write mode 0600 on first
/// use.
pub(crate) fn load_or_init_master_key(
    cfg: &ExecutorConfig,
) -> std::io::Result<Zeroizing<[u8; 32]>> {
    if let Ok(bytes) = fs::read(&cfg.master_key_file) {
        if bytes.len() == 32 {
            let mut k = Zeroizing::new([0u8; 32]);
            k.copy_from_slice(&bytes);
            return Ok(k);
        }
        return Err(std::io::Error::other(format!(
            "master key at {} has wrong length {}",
            cfg.master_key_file.display(),
            bytes.len()
        )));
    }
    if let Some(parent) = cfg.master_key_file.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut k = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(&mut *k);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&cfg.master_key_file)?;
    f.write_all(&*k)?;
    f.sync_all()?;
    Ok(k)
}

fn derive_file_key(master: &Zeroizing<[u8; 32]>, vault_id: &str) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(KDF_SALT), &**master);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(vault_id.as_bytes(), &mut *out)
        .expect("HKDF 32-byte expand cannot fail");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

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
        // metadata/read/unlink, so the file is untouched afterwards.
        let target = Path::new("/bin/sh");
        let before = fs::metadata(target).expect("/bin/sh exists on a Linux test host");
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
            remove_verified(&dir.join("mal2"), &h2),
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
            let outcome = quarantine_file(&handle, &cfg);
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
                Ok(id) => {
                    assert!(!real.exists(), "round {round}: quarantined, so removed");
                    let restored = tmp.path().join("restored");
                    restore(&id, &restored, &cfg).unwrap();
                    assert_eq!(fs::read(&restored).unwrap(), b"malware");
                }
                Err(QuarantineError::PathSwapped) => {
                    assert_eq!(fs::read(&real).unwrap(), b"malware");
                }
                Err(e) => panic!("round {round}: unexpected {e:?}"),
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
        let _ = take_index_notes();
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
        let notes = take_index_notes();
        assert!(
            notes.len() == 1 && notes[0].contains("rebuilt from 3"),
            "{notes:?}"
        );
        assert_eq!(
            vault_meta("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &cfg).unwrap()["original_path"],
            "/tmp/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
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
        meta["sha256"] = serde_json::json!(format!("{:x}", Sha256::digest(b"other")));
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
}
