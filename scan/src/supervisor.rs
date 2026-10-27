//! The agent's end of the scanner (lab PR 223): start `northnarrow-scan`
//! as its own user, configure it, hand it descriptors, read its answers,
//! notice when it dies or hangs, and start it again under a backoff.
//!
//! Single-threaded and non-blocking: the agent's exec quarantine
//! controller polls [`Supervisor::fd`] with its other sources and calls
//! [`Supervisor::poll`] when it is readable.

use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use nn_proto::execq::{
    decode, encode, FromScanner, ScanRequest, ScanResult, ScannerHello, ToScanner, MAX_PACKET,
    PROTOCOL_VERSION,
};

use crate::ipc;

/// The account the scanner runs as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanUser {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
}

/// `getpwnam_r(name)`.
pub fn lookup_user(name: &str) -> Result<ScanUser, String> {
    let cname = std::ffi::CString::new(name).map_err(|_| format!("bad user name `{name}`"))?;
    // SAFETY: zeroed passwd is a valid out-buffer; buf is large and owned.
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
            std::io::Error::from_raw_os_error(rc)
        ));
    }
    if out.is_null() {
        return Err(format!("no user `{name}`"));
    }
    if pw.pw_uid == 0 || pw.pw_gid == 0 {
        return Err(format!("user `{name}` is root or in group 0"));
    }
    Ok(ScanUser {
        name: name.to_string(),
        uid: pw.pw_uid,
        gid: pw.pw_gid,
    })
}

/// What the scanner said or did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScannerEvent {
    Ready(ScannerHello),
    Result(ScanResult),
    Refused {
        id: u64,
        reason: String,
    },
    /// It exited, was killed, or broke the protocol: every request it held
    /// is lost. `why` names the exit status.
    Died {
        why: String,
    },
}

/// How long a started scanner has to say it is ready.
pub const READY_TIMEOUT: Duration = Duration::from_secs(5);
/// Longest wait between two starts.
pub const MAX_BACKOFF: Duration = Duration::from_secs(30);

pub struct Supervisor {
    exe: PathBuf,
    user: ScanUser,
    config: Vec<u8>,
    child: Option<Child>,
    sock: Option<OwnedFd>,
    started: Option<Instant>,
    ready: bool,
    hello: Option<ScannerHello>,
    /// Starts since the last `Ready`.
    failures: u32,
    next_start: Instant,
    starts: u64,
    deaths: u64,
    buf: Vec<u8>,
}

impl std::fmt::Debug for Supervisor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Supervisor")
            .field("exe", &self.exe)
            .field("ready", &self.ready)
            .field("starts", &self.starts)
            .finish_non_exhaustive()
    }
}

impl Supervisor {
    /// `config`: the encoded `ScanConfig` (`nn_proto::execq::encode_config`).
    pub fn new(exe: PathBuf, user: ScanUser, config: Vec<u8>) -> Self {
        Self {
            exe,
            user,
            config,
            child: None,
            sock: None,
            started: None,
            ready: false,
            hello: None,
            failures: 0,
            next_start: Instant::now(),
            starts: 0,
            deaths: 0,
            buf: vec![0u8; MAX_PACKET],
        }
    }

    pub fn is_ready(&self) -> bool {
        self.ready
    }

    pub fn is_running(&self) -> bool {
        self.child.is_some()
    }

    pub fn hello(&self) -> Option<&ScannerHello> {
        self.hello.as_ref()
    }

    pub fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(Child::id)
    }

    /// Starts so far, and deaths.
    pub fn counts(&self) -> (u64, u64) {
        (self.starts, self.deaths)
    }

    /// When a stopped scanner will be started again (`None` while one
    /// runs).
    pub fn next_start(&self) -> Option<Instant> {
        (self.child.is_none()).then_some(self.next_start)
    }

    /// The channel, to poll for readability.
    pub fn fd(&self) -> Option<RawFd> {
        self.sock.as_ref().map(AsRawFd::as_raw_fd)
    }

    /// Start the scanner when none runs and its backoff has passed.
    /// `Ok(true)`: started (it is ready once [`ScannerEvent::Ready`]).
    pub fn start_if_due(&mut self, now: Instant) -> Result<bool, String> {
        if self.child.is_some() || now < self.next_start {
            return Ok(false);
        }
        self.starts += 1;
        match self.spawn() {
            Ok(()) => {
                self.started = Some(now);
                Ok(true)
            }
            Err(e) if self.child.is_some() => Err(self.kill(&e)),
            Err(e) => {
                self.backoff(now);
                Err(e)
            }
        }
    }

    fn spawn(&mut self) -> Result<(), String> {
        let (ours, theirs) = ipc::socketpair().map_err(|e| format!("socketpair: {e}"))?;
        let raw = theirs.as_raw_fd();
        let mut cmd = Command::new(&self.exe);
        cmd.args(["--fd", "3"])
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .gid(self.user.gid)
            .uid(self.user.uid);
        // SAFETY: async-signal-safe calls only, in the child after std has
        // dropped to the scanner's uid and gid (and its groups).
        unsafe {
            cmd.pre_exec(move || {
                let rc = if raw == 3 {
                    libc::fcntl(3, libc::F_SETFD, 0)
                } else {
                    libc::dup2(raw, 3)
                };
                if rc < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // After the uid change (which clears it): die with the agent.
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd
            .spawn()
            .map_err(|e| format!("spawn {} as {}: {e}", self.exe.display(), self.user.name))?;
        drop(theirs);
        self.child = Some(child);
        self.sock = Some(ours);
        self.ready = false;
        let memfd = ipc::sealed_memfd("northnarrow-scan-config", &self.config)
            .map_err(|e| format!("config memfd: {e}"))?;
        let msg = encode(&ToScanner::Configure {
            version: PROTOCOL_VERSION,
            config_len: self.config.len() as u64,
        })?;
        let sock = self.fd().ok_or("no channel")?;
        ipc::send(sock, &msg, Some(memfd.as_raw_fd())).map_err(|e| format!("configure: {e}"))
    }

    /// Hand the scanner one file.
    pub fn send(&mut self, req: &ScanRequest, file: RawFd) -> Result<(), ScannerEvent> {
        let Some(sock) = self.fd().filter(|_| self.ready) else {
            return Err(ScannerEvent::Died {
                why: "not ready".into(),
            });
        };
        let msg =
            encode(&ToScanner::Scan(req.clone())).map_err(|why| ScannerEvent::Died { why })?;
        ipc::send(sock, &msg, Some(file)).map_err(|e| {
            let why = self.reap(&format!("send: {e}"));
            ScannerEvent::Died { why }
        })
    }

    /// Read everything queued on the channel (non-blocking), and check the
    /// readiness deadline.
    pub fn poll(&mut self, now: Instant) -> Vec<ScannerEvent> {
        let mut out = Vec::new();
        while let Some(sock) = self.fd() {
            match ipc::recv(sock, &mut self.buf, true) {
                Ok(p) if p.len == 0 => {
                    let why = self.reap("closed its channel");
                    out.push(ScannerEvent::Died { why });
                    break;
                }
                Ok(p) => match decode::<FromScanner>(&self.buf[..p.len]) {
                    Ok(FromScanner::Ready(h)) => match self.check_hello(&h) {
                        Ok(()) => {
                            self.ready = true;
                            self.failures = 0;
                            self.hello = Some(h.clone());
                            out.push(ScannerEvent::Ready(h));
                        }
                        Err(e) => {
                            let why = self.kill(&e);
                            out.push(ScannerEvent::Died { why });
                            break;
                        }
                    },
                    Ok(FromScanner::Result(r)) => out.push(ScannerEvent::Result(r)),
                    Ok(FromScanner::Refused { id, reason }) => {
                        out.push(ScannerEvent::Refused { id, reason })
                    }
                    Err(e) => {
                        let why = self.kill(&format!("undecodable message: {e}"));
                        out.push(ScannerEvent::Died { why });
                        break;
                    }
                },
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    let why = self.reap(&format!("recv: {e}"));
                    out.push(ScannerEvent::Died { why });
                    break;
                }
            }
        }
        if !self.ready && self.child.is_some() {
            if let Some(t) = self.started {
                if now.duration_since(t) >= READY_TIMEOUT {
                    let why = self.kill(&format!("not ready within {READY_TIMEOUT:?}"));
                    out.push(ScannerEvent::Died { why });
                }
            }
        }
        out
    }

    fn check_hello(&self, h: &ScannerHello) -> Result<(), String> {
        if h.version != PROTOCOL_VERSION {
            return Err(format!("protocol {} (want {PROTOCOL_VERSION})", h.version));
        }
        if !h.seccomp {
            return Err("ready without its seccomp filter".into());
        }
        if h.uid != self.user.uid {
            return Err(format!("runs as uid {} (want {})", h.uid, self.user.uid));
        }
        Ok(())
    }

    /// Kill the scanner (hung, or broke the protocol); its exit status.
    pub fn kill(&mut self, why: &str) -> String {
        if let Some(c) = self.child.as_mut() {
            let _ = c.kill();
        }
        self.reap(why)
    }

    /// Collect the child (killing it if it still runs), close the channel
    /// and schedule the next start.
    fn reap(&mut self, why: &str) -> String {
        self.sock = None;
        self.ready = false;
        let status = match self.child.take() {
            Some(mut c) => {
                let st = match c.try_wait() {
                    Ok(Some(st)) => Some(st),
                    _ => {
                        let _ = c.kill();
                        c.wait().ok()
                    }
                };
                match st {
                    Some(st) => match (st.code(), st.signal()) {
                        (Some(code), _) => format!("exit status {code}"),
                        (None, Some(sig)) => format!("killed by signal {sig}"),
                        _ => "ended".to_string(),
                    },
                    None => "status unknown".to_string(),
                }
            }
            None => "not running".to_string(),
        };
        self.deaths += 1;
        self.backoff(Instant::now());
        format!("{why} ({status})")
    }

    fn backoff(&mut self, now: Instant) {
        self.failures = self.failures.saturating_add(1);
        let secs = match self.failures {
            0 | 1 => 0,
            n => 1u64 << (n - 2).min(5),
        };
        self.next_start = now + Duration::from_secs(secs).min(MAX_BACKOFF);
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        if self.child.is_some() {
            let _ = self.kill("agent stopping");
        }
    }
}
