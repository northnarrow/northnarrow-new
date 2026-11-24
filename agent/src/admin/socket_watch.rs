//! External audit WDG-007 (NN-AUD-358): the admin socket's own watch.
//!
//! `/run/northnarrow` is writable by root and outside the inode deny set,
//! so root could `rm /run/northnarrow/admin.sock` while the agent ran: the
//! listener stayed open on a name nobody could reach, `nn-admin` was dead
//! until the next agent start, and the watchdog read the missing socket as
//! "never came up" — no hang recovery any more, even for an agent then
//! frozen through its cgroup. The agent now records the socket's
//! `(st_dev, st_ino)` when it binds it and looks at the path every
//! [`SOCKET_CHECK_EVERY`]: a socket removed or replaced (a link, a file, a
//! directory, someone else's socket) is a signed `integrity_drift`
//! (`admin_socket_removed`) and is bound again at once, so a healthy agent
//! answers the watchdog's next ping and the removal cannot be turned into a
//! restart. A frozen agent cannot bind it again: the watchdog sees the
//! socket gone after the agent answered and recovers it.
//!
//! [`bind`] is also the boot-time bind: whatever sits at the path is
//! removed without following a link (a dangling link at the name made
//! `bind` fail with `EADDRINUSE`, ASK-014), a missing parent is created
//! 0700, and the mode is set to 0600 on the socket just bound — through an
//! `O_PATH | O_NOFOLLOW` descriptor, never on what a link put in its place.
//!
//! Lot 353 (re-check 2 of #563, R2-1): the whole check — the look at the
//! path, and for a socket taken away the clear, the parent's creation, the
//! bind and the mode — runs on a helper thread of its own ([`look_and_rebind`],
//! one in flight at most), never in the serve loop: the serve loop starts a
//! check ([`SocketWatch::start_check`]) and takes its answer when it comes
//! ([`SocketWatch::finish`]: the std listener made a tokio one there). Only
//! the look was bounded, on a helper with a deadline; the rebind ran in the
//! serve loop by path, and a FUSE over `/run/northnarrow` that answered the
//! look and held the next lookup of the same name held the serve loop and
//! its worker — on one worker, the whole runtime. A check that does not
//! answer holds its helper only: the serve loop goes on serving the
//! listener it has, and starts no other check until that one answers. The
//! socket's name is the one `nn-admin` and the watchdog walk to, so it is
//! bound by path; the mode is set beneath the anchored `/proc` root
//! (`kernel_roots::chmod_fd`). The start's bind is bounded the same way
//! ([`bind_within`]).

use std::fs::{self, OpenOptions, Permissions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use parking_lot::Mutex;
use tokio::net::UnixListener;
use tracing::{error, info, warn};

use crate::audit::AuditLog;
use crate::self_integrity::{self, Finding};

/// How often the agent looks at its socket's path: a lstat. The watchdog
/// reports a socket gone on two pings in a row (30 s apart) and recovers
/// the agent on three (`northnarrow_watchdog::STATUS_PING_VANISHED_*`), so
/// a healthy agent has bound it again long before either.
pub const SOCKET_CHECK_EVERY: Duration = Duration::from_secs(10);

/// The kind of the signed finding.
pub const KIND: &str = "admin_socket_removed";

/// Paths whose watch stops: the agent unlinks its socket on the way out
/// ([`retire`]) and must not bind it again in the moments before it exits.
static RETIRED: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

/// The agent is stopping: stop watching `path`.
pub fn retire(path: &Path) {
    let mut retired = RETIRED.lock();
    if !retired.iter().any(|p| p == path) {
        retired.push(path.to_path_buf());
    }
}

fn is_retired(path: &Path) -> bool {
    RETIRED.lock().iter().any(|p| p == path)
}

/// The socket file the agent bound, by device and inode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketId {
    dev: u64,
    ino: u64,
}

impl SocketId {
    fn of(m: &fs::Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
        }
    }
}

/// Bind the admin socket at `path` (see the module doc): the listener and
/// the identity of the socket file, on the caller's thread (the tests'; the
/// agent's start binds it through [`bind_within`]). Must run inside the
/// tokio runtime.
#[cfg(test)]
pub fn bind(path: &Path) -> Result<(UnixListener, SocketId)> {
    let (listener, id) = bind_std(path)?;
    Ok((UnixListener::from_std(listener)?, id))
}

/// Lot 353 (re-check 2 of #563, R2-1): how long the start's bind and a
/// check of the path wait for their helper.
pub const BIND_DEADLINE: Duration = Duration::from_secs(5);

/// Lot 353 (re-check 2 of #563, R2-1): [`bind_std`] on a helper thread,
/// awaited at most `deadline` (the start's bind, in the serve task: a mount
/// over `/run/northnarrow` that does not answer holds the helper, never a
/// worker of the runtime). Past it, an error: the serve loop does not
/// start (an ERROR and a signed record, as for any bind that fails).
pub async fn bind_within(path: &Path, deadline: Duration) -> Result<(UnixListener, SocketId)> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let p = path.to_path_buf();
    std::thread::Builder::new()
        .name("nn-sock-bind".into())
        .spawn(move || {
            let _ = tx.send(bind_std(&p));
        })
        .context("no helper thread for the admin socket's bind")?;
    let (listener, id) = tokio::time::timeout(deadline, rx)
        .await
        .map_err(|_| {
            anyhow!(
                "binding admin socket {}: no answer within {} s (a mount over its directory \
                 that does not answer?)",
                path.display(),
                deadline.as_secs()
            )
        })?
        .map_err(|_| anyhow!("the admin socket's bind helper ended without an answer"))??;
    Ok((UnixListener::from_std(listener)?, id))
}

/// The bind itself, by path, on the caller's thread: whatever sits at the
/// path cleared, the parent made, the socket bound (non-blocking, for the
/// runtime) and its mode set — a std listener the runtime takes
/// (`UnixListener::from_std`).
fn bind_std(path: &Path) -> Result<(std::os::unix::net::UnixListener, SocketId)> {
    clear(path)?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && fs::symlink_metadata(parent).is_err() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .with_context(|| format!("creating socket parent dir {}", parent.display()))?;
        }
    }
    let listener = std::os::unix::net::UnixListener::bind(path)
        .with_context(|| format!("binding admin socket {}", path.display()))?;
    listener
        .set_nonblocking(true)
        .with_context(|| format!("admin socket {} non-blocking", path.display()))?;
    // bind() honours the umask; root:root remains via ownership of the
    // bind() syscall. The mode is the first gate; the accept loop checks
    // each peer's uid as well (external audit ASK-012, NN-AUD-238), so a
    // mode widened later lets no other user in. V1.1's root:northnarrow
    // 0660 would widen both together.
    let id = restrict(path).with_context(|| format!("chmod 0600 {}", path.display()))?;
    Ok((listener, id))
}

/// Remove whatever sits at `path`: never through a link, never a
/// directory (a refusal, not a recursive delete). Also the agent's unlink
/// at shutdown (`admin_socket::unlink_socket`, external audit ASK-014).
pub(crate) fn clear(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => Err(anyhow!(
            "{} is a directory, not a socket the agent can replace",
            path.display()
        )),
        Ok(_) => fs::remove_file(path)
            .with_context(|| format!("unlinking stale socket {}", path.display())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("lstat {}", path.display())),
    }
}

/// Mode 0600 on the socket at `path`, through a descriptor that does not
/// follow a link: what a swap after `bind` put there is refused, not
/// chmod-ed. Returns the socket's identity.
fn restrict(path: &Path) -> io::Result<SocketId> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW)
        .open(path)?;
    let m = f.metadata()?;
    if !m.file_type().is_socket() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the path no longer holds the socket just bound",
        ));
    }
    // Lot 353 (the review of #563, F2): through the /proc root the start
    // anchored, never the /proc mounted now (a FUSE over it held the
    // re-bind of WDG-007).
    if antitamper_bpf::kernel_roots::chmod_fd(&f, 0o600).is_err() {
        // No anchored /proc: chmod by name, then check it is still that
        // socket.
        fs::set_permissions(path, Permissions::from_mode(0o600))?;
        let after = fs::symlink_metadata(path)?;
        if SocketId::of(&after) != SocketId::of(&m) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the path changed while its mode was set",
            ));
        }
    }
    Ok(SocketId::of(&m))
}

/// What the path holds now, against the socket the agent bound.
#[derive(Debug)]
pub enum PathState {
    /// The agent's socket.
    Ours,
    /// Nothing.
    Removed,
    /// Something else: what.
    Replaced(&'static str),
    /// The path could not be looked at.
    Unreadable(io::Error),
}

/// Lot 353 (re-check 1 of #563): how long a test's check waits for its
/// helper ([`SocketWatch::check`]; the serve loop never waits for one).
pub const LOOK_DEADLINE: Duration = Duration::from_secs(2);

/// Look at `path` (never through a link).
pub fn path_state(path: &Path, bound: SocketId) -> PathState {
    state_of(fs::symlink_metadata(path), bound)
}

/// Lot 353 (re-check 2 of #563, R2-1): what one check found — the path's
/// state, and for a socket removed or replaced the bind again (`None`: not
/// tried, the socket is the agent's, the path unreadable or retired).
#[derive(Debug)]
pub struct Looked {
    state: PathState,
    rebound: Option<Result<(std::os::unix::net::UnixListener, SocketId)>>,
}

/// Lot 353 (re-check 2 of #563, R2-1): one check, whole, on the caller's
/// thread (a helper's: [`SocketWatch::start_check`]) — the look, and for a
/// socket taken away its bind again (the clear, the parent, the bind, the
/// mode). Nothing of it runs in the serve loop.
pub fn look_and_rebind(path: &Path, bound: SocketId) -> Looked {
    let state = path_state(path, bound);
    let rebound = (matches!(state, PathState::Removed | PathState::Replaced(_))
        && !is_retired(path))
    .then(|| bind_std(path));
    Looked { state, rebound }
}

fn state_of(looked: io::Result<fs::Metadata>, bound: SocketId) -> PathState {
    match looked {
        Ok(m) => {
            let t = m.file_type();
            if t.is_socket() && SocketId::of(&m) == bound {
                PathState::Ours
            } else if t.is_socket() {
                PathState::Replaced("replaced by another socket")
            } else if t.is_symlink() {
                PathState::Replaced("replaced by a symbolic link")
            } else if t.is_dir() {
                PathState::Replaced("replaced by a directory")
            } else if t.is_file() {
                PathState::Replaced("replaced by a regular file")
            } else {
                PathState::Replaced("replaced by another kind of file")
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => PathState::Removed,
        Err(e) => PathState::Unreadable(e),
    }
}

/// The watch: one [`Self::check`] every [`SOCKET_CHECK_EVERY`].
pub struct SocketWatch {
    path: PathBuf,
    bound: SocketId,
    /// A removal seen and not bound again yet (reported once).
    pending: bool,
    /// When the last signed record was written, and the removals seen
    /// since without one (at most one record per
    /// [`self_integrity::REREPORT_SECS`], as for the round's findings).
    last_signed: Option<Instant>,
    unsigned: u32,
    /// The last "still not bound" warning.
    last_retry_log: Option<Instant>,
    /// Lot 353 (re-check 2 of #563, R2-1): a check on its helper that has
    /// not answered yet (one at a time), and since when.
    in_flight: Arc<std::sync::atomic::AtomicBool>,
    started: Option<Instant>,
    /// The last "the check does not answer" warning.
    last_held_log: Option<Instant>,
}

impl SocketWatch {
    pub fn new(path: PathBuf, bound: SocketId) -> Self {
        Self {
            path,
            bound,
            pending: false,
            last_signed: None,
            unsigned: 0,
            last_retry_log: None,
            in_flight: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            started: None,
            last_held_log: None,
        }
    }

    /// Lot 353 (re-check 2 of #563, R2-1): start one check on a helper
    /// thread ([`look_and_rebind`]); its answer comes on the receiver,
    /// handed to [`Self::finish`]. `None`: the path is retired, or the
    /// previous check has not answered (warned once a minute: its helper is
    /// held — the serve loop goes on serving the listener it has).
    pub fn start_check(&mut self) -> Option<tokio::sync::oneshot::Receiver<Looked>> {
        use std::sync::atomic::Ordering;
        if is_retired(&self.path) {
            return None;
        }
        if self.in_flight.swap(true, Ordering::AcqRel) {
            self.still_held();
            return None;
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        let (path, bound, in_flight) = (self.path.clone(), self.bound, Arc::clone(&self.in_flight));
        let spawned = std::thread::Builder::new()
            .name("nn-sock-watch".into())
            .spawn(move || {
                let looked = look_and_rebind(&path, bound);
                in_flight.store(false, Ordering::Release);
                let _ = tx.send(looked);
            });
        if let Err(e) = spawned {
            self.in_flight.store(false, Ordering::Release);
            warn!(error = %e, "admin socket path not checked: no helper thread");
            return None;
        }
        self.started = Some(Instant::now());
        Some(rx)
    }

    /// A check started and not answered: warned once a minute.
    pub fn still_held(&mut self) {
        let now = Instant::now();
        if self
            .last_held_log
            .is_some_and(|t| now.duration_since(t) < Duration::from_secs(60))
        {
            return;
        }
        self.last_held_log = Some(now);
        warn!(
            path = %self.path.display(),
            secs = self.started.map_or(0, |t| t.elapsed().as_secs()),
            "admin socket path: its check has not answered (a mount over its directory that \
             does not answer?) — the serve loop goes on, no other check until it does"
        );
    }

    /// One check, waited for at most `deadline` on the caller's thread (the
    /// tests'): `Some(listener)` when the socket was removed or replaced
    /// and has been bound again.
    #[cfg(test)]
    pub fn check(&mut self, audit_log: Option<&Arc<Mutex<AuditLog>>>) -> Option<UnixListener> {
        let mut rx = self.start_check()?;
        let started = Instant::now();
        loop {
            match rx.try_recv() {
                Ok(looked) => return self.finish(looked, audit_log),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty)
                    if started.elapsed() < LOOK_DEADLINE =>
                {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(_) => return None,
            }
        }
    }

    /// Lot 353 (re-check 2 of #563, R2-1): a check's answer, in the serve
    /// loop — reported (a signed finding for a socket taken away), and the
    /// socket bound again made the runtime's listener: `Some(listener)`, the
    /// caller serves on it from then on.
    pub fn finish(
        &mut self,
        looked: Looked,
        audit_log: Option<&Arc<Mutex<AuditLog>>>,
    ) -> Option<UnixListener> {
        self.started = None;
        if is_retired(&self.path) {
            return None;
        }
        let Looked { state, rebound } = looked;
        let what = match state {
            PathState::Ours => return None,
            PathState::Unreadable(e) => {
                if self.retry_log_due() {
                    warn!(
                        error = %e,
                        path = %self.path.display(),
                        "admin socket path cannot be checked"
                    );
                }
                return None;
            }
            PathState::Removed => "removed",
            PathState::Replaced(what) => what,
        };
        let first = !self.pending;
        let rebound = rebound
            .unwrap_or_else(|| Err(anyhow!("the path was retired")))
            .and_then(|(l, id)| Ok((UnixListener::from_std(l)?, id)));
        if first {
            self.report(what, rebound.as_ref().err(), audit_log);
        }
        match rebound {
            Ok((listener, id)) => {
                if !first {
                    info!(
                        path = %self.path.display(),
                        "admin socket bound again (mode 0600)"
                    );
                }
                self.bound = id;
                self.pending = false;
                Some(listener)
            }
            Err(e) => {
                self.pending = true;
                if !first && self.retry_log_due() {
                    warn!(
                        error = format!("{e:#}"),
                        path = %self.path.display(),
                        "admin socket still not bound again — nn-admin cannot reach the agent"
                    );
                }
                None
            }
        }
    }

    fn report(
        &mut self,
        what: &str,
        rebind_error: Option<&anyhow::Error>,
        audit_log: Option<&Arc<Mutex<AuditLog>>>,
    ) {
        let outcome = match rebind_error {
            None => "bound again (mode 0600)".to_string(),
            Some(e) => format!(
                "NOT bound again ({e:#}); retried every {} s",
                SOCKET_CHECK_EVERY.as_secs()
            ),
        };
        let mut detail = format!(
            "{}: {what} while the agent ran (nn-admin and the watchdog's STATUS ping reach \
             the agent through it); {outcome}",
            self.path.display()
        );
        let now = Instant::now();
        let due = self.last_signed.is_none_or(|t| {
            now.duration_since(t) >= Duration::from_secs(self_integrity::REREPORT_SECS)
        });
        if due {
            if self.unsigned > 0 {
                detail.push_str(&format!(
                    " ({} more time(s) since the last record)",
                    self.unsigned
                ));
            }
            self_integrity::report_event(audit_log, &Finding { kind: KIND, detail });
            self.last_signed = Some(now);
            self.unsigned = 0;
        } else {
            self.unsigned = self.unsigned.saturating_add(1);
            error!(
                kind = KIND,
                detail = %detail,
                "INTEGRITY DRIFT — admin socket taken away again (signed with the next record, \
                 at most one per {} s)",
                self_integrity::REREPORT_SECS
            );
        }
    }

    fn retry_log_due(&mut self) -> bool {
        let now = Instant::now();
        if self
            .last_retry_log
            .is_some_and(|t| now.duration_since(t) < Duration::from_secs(60))
        {
            return false;
        }
        self.last_retry_log = Some(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn audit_log(dir: &Path) -> (PathBuf, Arc<Mutex<AuditLog>>) {
        let key =
            crate::audit::AgentSigningKey::load_or_bootstrap(&dir.join("agent.sig.key")).unwrap();
        let path = dir.join("audit.log");
        let log = AuditLog::open(&path, key, [0u8; 16]).unwrap();
        (path, Arc::new(Mutex::new(log)))
    }

    fn findings(log: &Path) -> Vec<String> {
        fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
            .filter(|v| v["op"] == self_integrity::AUDIT_OP && v["extra"]["kind"] == KIND)
            .map(|v| v["extra"]["detail"].as_str().unwrap().to_string())
            .collect()
    }

    async fn answers(path: &Path, listener: &UnixListener) -> bool {
        let client = tokio::net::UnixStream::connect(path);
        let (c, a) = tokio::join!(client, listener.accept());
        c.is_ok() && a.is_ok()
    }

    #[tokio::test]
    async fn admin_socket_inode_change_is_a_finding() {
        let dir = TempDir::new().unwrap();
        let (log_path, log) = audit_log(dir.path());
        let sock = dir.path().join("admin.sock");
        let (listener, id) = bind(&sock).unwrap();
        assert_eq!(fs::metadata(&sock).unwrap().mode() & 0o777, 0o600);
        let mut watch = SocketWatch::new(sock.clone(), id);
        assert!(
            watch.check(Some(&log)).is_none(),
            "untouched: nothing to do"
        );
        assert!(findings(&log_path).is_empty());

        // Removed: one signed finding, bound again, and the new socket
        // answers where the old listener can no longer be reached.
        fs::remove_file(&sock).unwrap();
        let rebound = watch.check(Some(&log)).expect("bound again");
        drop(listener);
        assert!(answers(&sock, &rebound).await);
        let f = findings(&log_path);
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].contains("removed while the agent ran"), "{}", f[0]);
        assert!(f[0].contains("bound again (mode 0600)"), "{}", f[0]);
        assert_eq!(fs::metadata(&sock).unwrap().mode() & 0o777, 0o600);
        assert!(watch.check(Some(&log)).is_none(), "the new socket is ours");

        // Replaced by a regular file within the re-report window: bound
        // again, journal only; the next signed record carries the count.
        fs::remove_file(&sock).unwrap();
        fs::write(&sock, "x").unwrap();
        let rebound = watch.check(Some(&log)).expect("bound again");
        assert!(answers(&sock, &rebound).await);
        assert_eq!(findings(&log_path).len(), 1);
        // Past the window, the next removal is signed with that count.
        let window = Duration::from_secs(self_integrity::REREPORT_SECS);
        let Some(earlier) = Instant::now().checked_sub(window) else {
            return; // a clock younger than the window
        };
        watch.last_signed = Some(earlier);
        fs::remove_file(&sock).unwrap();
        let _rebound = watch.check(Some(&log)).expect("bound again");
        let f = findings(&log_path);
        assert_eq!(f.len(), 2, "{f:?}");
        assert!(
            f[1].contains("(1 more time(s) since the last record)"),
            "{}",
            f[1]
        );
    }

    #[tokio::test]
    async fn a_link_at_the_socket_path_is_removed_not_followed() {
        let dir = TempDir::new().unwrap();
        let victim = dir.path().join("audit.log.victim");
        fs::write(&victim, "CHAIN").unwrap();
        fs::set_permissions(&victim, Permissions::from_mode(0o644)).unwrap();
        let sock = dir.path().join("admin.sock");
        // At boot: a dangling link and a link to a file are both replaced.
        std::os::unix::fs::symlink(dir.path().join("nowhere"), &sock).unwrap();
        let (_l, id) = bind(&sock).unwrap();
        let mut watch = SocketWatch::new(sock.clone(), id);
        fs::remove_file(&sock).unwrap();
        std::os::unix::fs::symlink(&victim, &sock).unwrap();
        assert!(matches!(
            path_state(&sock, id),
            PathState::Replaced("replaced by a symbolic link")
        ));
        let _rebound = watch.check(None).expect("bound again");
        assert!(fs::symlink_metadata(&sock).unwrap().file_type().is_socket());
        assert_eq!(fs::read_to_string(&victim).unwrap(), "CHAIN");
        assert_eq!(fs::metadata(&victim).unwrap().mode() & 0o777, 0o644);
    }

    #[tokio::test]
    async fn a_path_that_cannot_be_rebound_is_reported_once() {
        let dir = TempDir::new().unwrap();
        let (log_path, log) = audit_log(dir.path());
        let sock = dir.path().join("admin.sock");
        let (_l, id) = bind(&sock).unwrap();
        let mut watch = SocketWatch::new(sock.clone(), id);
        fs::remove_file(&sock).unwrap();
        fs::create_dir(&sock).unwrap();
        for _ in 0..3 {
            assert!(watch.check(Some(&log)).is_none());
        }
        let f = findings(&log_path);
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].contains("replaced by a directory"), "{}", f[0]);
        assert!(f[0].contains("NOT bound again"), "{}", f[0]);
        // Once the path is free again the socket comes back, with no
        // second record for the same removal.
        fs::remove_dir(&sock).unwrap();
        assert!(watch.check(Some(&log)).is_some());
        assert_eq!(findings(&log_path).len(), 1);
    }

    #[tokio::test]
    async fn a_retired_socket_is_not_bound_again() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("admin.sock");
        let (_l, id) = bind(&sock).unwrap();
        let mut watch = SocketWatch::new(sock.clone(), id);
        retire(&sock);
        fs::remove_file(&sock).unwrap();
        assert!(watch.check(None).is_none());
        assert!(!sock.exists(), "the agent's own unlink at shutdown stays");
    }

    #[tokio::test]
    async fn bind_creates_a_missing_parent_closed_to_others() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("run/northnarrow/admin.sock");
        let (_l, _id) = bind(&sock).unwrap();
        let parent = fs::metadata(sock.parent().unwrap()).unwrap();
        assert_eq!(parent.mode() & 0o777, 0o700);
    }
}
