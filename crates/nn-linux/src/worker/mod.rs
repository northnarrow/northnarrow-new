//! The agent's workers (Wave 4 restructure, R14a — plan §3.1, §3.5;
//! `docs/architecture/PROCESS_MODEL.md`, `docs/operator/WORKERS.md`).
//!
//! The core — the agent's root process, which loads the eBPF object,
//! holds the keys, decides and acts — keeps nothing in itself that parses
//! hostile bytes once R14b moves the parsers out: a worker does, the same
//! binary started as `--worker <kind> --ipc-fd 3`, as the unprivileged
//! `northnarrow-worker` account, in its sandbox (`crate::sandbox`):
//!
//! - [`SelfImage`]: the agent's binary, opened at boot; a worker is started
//!   from that descriptor (`/proc/self/fd/N`), so an upgrade that replaced
//!   the file on disk does not start a worker of another version;
//! - [`spawn`]: the child's steps between `fork` and `exec`;
//! - [`transport`]: the channel's packets (`SOCK_SEQPACKET`, no
//!   descriptor);
//! - [`serve`]: the worker's side — the sandbox first, then the hello, then
//!   the requests;
//! - [`parse`]: the core's way to the parsers (R14b): the DNS pump's names
//!   in batches, a ClientHello, a DNS answer — or no decode;
//! - [`supervisor`]: the core's side — starting, checking the hello,
//!   requests with a deadline, killing a worker that breaks the protocol,
//!   hangs or dies, the backoff, the disabled state and its signed
//!   degradation. When a worker is down the core does without what it
//!   gives: it never parses in its own process instead (plan §5).
//!
//! In the kernel a worker is a protected pid but not an exempt one
//! (`common::wire::pid_role::WORKER`): its signals, its ptrace and the
//! deny hooks treat it as the agent's family for its own defence and as
//! anyone for the keys and the protected paths.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

pub mod parse;
pub mod serve;
pub mod spawn;
pub mod supervisor;
pub mod transport;

#[cfg(feature = "debug-trigger")]
pub mod hostile;

pub use supervisor::{Health, WorkerError, Workers};

/// The account the workers run as (install.sh, the packages' postinst).
pub const WORKER_USER: &str = "northnarrow-worker";

/// Lot 276, the review of #499 (D1): the export worker's own account — the
/// one that owns the export's directory; the parse worker's cannot write
/// it.
pub const EXPORT_USER: &str = "northnarrow-export";

/// The account a worker of `kind` runs as.
pub fn account_name(kind: nn_proto::ipc::WorkerKind) -> &'static str {
    match kind {
        nn_proto::ipc::WorkerKind::Parse => WORKER_USER,
        nn_proto::ipc::WorkerKind::Export => EXPORT_USER,
    }
}

/// The lowest descriptor number [`SelfImage`] keeps its binary on: far
/// from the channel's (3) and stdio, which a child rearranges.
const IMAGE_FD_MIN: libc::c_int = 64;

/// The agent's own binary, opened at boot (read-only, close-on-exec).
#[derive(Debug)]
pub struct SelfImage {
    fd: OwnedFd,
    dev: u64,
    ino: u64,
}

impl SelfImage {
    /// `/proc/self/exe`: the file this process runs, whatever happened to
    /// its path since.
    pub fn open_own() -> io::Result<Self> {
        Self::open(Path::new("/proc/self/exe"))
    }

    /// `path` (the lab harness: the agent's binary from a test).
    pub fn open(path: &Path) -> io::Result<Self> {
        let f = std::fs::File::open(path)?;
        // SAFETY: F_DUPFD_CLOEXEC on a descriptor we own.
        let fd = unsafe { libc::fcntl(f.as_raw_fd(), libc::F_DUPFD_CLOEXEC, IMAGE_FD_MIN) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the kernel just returned this descriptor to us.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        drop(f);
        // SAFETY: zeroed stat is a valid out-buffer.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: fstat into a local struct.
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if st.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the agent's image is not a regular file",
            ));
        }
        Ok(Self {
            fd,
            dev: st.st_dev,
            ino: st.st_ino,
        })
    }

    /// The path a child executes it by.
    pub fn exec_path(&self) -> String {
        format!("/proc/self/fd/{}", self.fd.as_raw_fd())
    }

    /// `(st_dev, st_ino)` of the binary.
    pub fn identity(&self) -> (u64, u64) {
        (self.dev, self.ino)
    }
}

/// The account a worker runs as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerAccount {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
}

impl WorkerAccount {
    /// `getpwnam_r(name)`; refused when it is root or in group 0.
    pub fn lookup(name: &str) -> Result<Self, String> {
        let cname = CString::new(name).map_err(|_| format!("bad user name `{name}`"))?;
        // SAFETY: zeroed passwd is a valid out-buffer.
        let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = vec![0 as libc::c_char; 16 * 1024];
        let mut out: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: all pointers are valid for the call.
        let rc = unsafe {
            libc::getpwnam_r(
                cname.as_ptr(),
                &mut pw,
                buf.as_mut_ptr(),
                buf.len(),
                &mut out,
            )
        };
        if rc != 0 {
            return Err(format!(
                "getpwnam_r({name}): {}",
                io::Error::from_raw_os_error(rc)
            ));
        }
        if out.is_null() {
            return Err(format!("no user `{name}`"));
        }
        if pw.pw_uid == 0 || pw.pw_gid == 0 {
            return Err(format!("user `{name}` is root or in group 0"));
        }
        Ok(Self {
            name: name.to_string(),
            uid: pw.pw_uid,
            gid: pw.pw_gid,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_image_is_kept_on_a_high_descriptor_by_its_identity() {
        let img = SelfImage::open_own().unwrap();
        let fd: i32 = img
            .exec_path()
            .strip_prefix("/proc/self/fd/")
            .unwrap()
            .parse()
            .unwrap();
        assert!(fd >= IMAGE_FD_MIN);
        let md = std::fs::metadata("/proc/self/exe").unwrap();
        use std::os::unix::fs::MetadataExt;
        assert_eq!(img.identity(), (md.dev(), md.ino()));
        // close-on-exec
        // SAFETY: F_GETFD on our descriptor.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert_eq!(flags & libc::FD_CLOEXEC, libc::FD_CLOEXEC);
        assert!(SelfImage::open(Path::new("/proc/self")).is_err());
    }

    #[test]
    fn root_and_absent_accounts_are_refused() {
        assert!(WorkerAccount::lookup("root").is_err());
        assert!(WorkerAccount::lookup("no-such-user-nn14").is_err());
        assert!(WorkerAccount::lookup("bad\0name").is_err());
    }
}
