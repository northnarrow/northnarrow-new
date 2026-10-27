//! Lab PR 217 (capability C18): an external command the response layer
//! runs, waited for at most a deadline.
//!
//! COMBAT's isolation (`iptables-restore`, `iptables` and their v6 pair) and
//! the per-process egress block (`nft`) were waited for with `output()` /
//! `wait_with_output()`: a binary that hung — a stuck xtables lock, a
//! netlink call that never returned, a replaced binary that sleeps — held
//! the ladder's worker thread (and with it every later step, the stand-down
//! of an admin unlock included) for as long as it liked. [`run_bounded`]
//! kills the child at the deadline and reports the timeout as the step's
//! error, so the caller records an outcome instead of waiting forever.

use std::io::{self, Read, Write};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// How long one iptables / ip6tables / nft invocation may take. They
/// normally answer in milliseconds; a few seconds covers a loaded host and
/// a contended xtables lock.
pub const EXTERNAL_CMD_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the output pipes are read after the child exited (or was
/// killed): a grandchild that kept them open cannot hold the caller.
const DRAIN_GRACE: Duration = Duration::from_millis(500);

/// Run `cmd`, feed it `stdin` (when given), and wait at most `timeout` for
/// it to exit. Its stdout and stderr are captured. Past the deadline the
/// child is killed and the error is [`io::ErrorKind::TimedOut`], naming
/// `what`. The caller's stdio settings for the three streams are
/// replaced.
pub fn run_bounded(
    mut cmd: Command,
    stdin: Option<&[u8]>,
    timeout: Duration,
    what: &str,
) -> io::Result<Output> {
    cmd.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    // A group of its own: the kill at the deadline reaches what it forked.
    std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
    let mut child = cmd.spawn()?;
    // Written from a thread of its own: a child that does not read its
    // stdin would otherwise block the write past the deadline.
    let writer = match (stdin, child.stdin.take()) {
        (Some(data), Some(mut pipe)) => {
            let data = data.to_vec();
            Some(std::thread::spawn(move || pipe.write_all(&data)))
        }
        _ => None,
    };
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());
    let deadline = Instant::now() + timeout;
    let status: ExitStatus = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            // SAFETY: kill(2) on the process group the child leads.
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "{what} did not exit within {} s — killed",
                    timeout.as_secs_f32()
                ),
            ));
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    if let Some(w) = writer {
        // A child that exits without reading all of it closes the pipe
        // (EPIPE): its exit status says what happened.
        let _ = w.join();
    }
    Ok(Output {
        status,
        stdout: stdout.recv_timeout(DRAIN_GRACE).unwrap_or_default(),
        stderr: stderr.recv_timeout(DRAIN_GRACE).unwrap_or_default(),
    })
}

/// Read `pipe` to its end on a thread; the bytes arrive on the channel.
fn drain<R: Read + Send + 'static>(pipe: Option<R>) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    match pipe {
        Some(mut pipe) => {
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = pipe.read_to_end(&mut buf);
                let _ = tx.send(buf);
            });
        }
        None => {
            let _ = tx.send(Vec::new());
        }
    }
    rx
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(script: &str) -> Command {
        let mut c = Command::new("/bin/sh");
        c.args(["-c", script]);
        c
    }

    /// The output and the exit status of a command that finishes in time.
    #[test]
    fn a_prompt_command_is_captured() {
        let out = run_bounded(
            sh("cat; echo err >&2; exit 3"),
            Some(b"in\n"),
            Duration::from_secs(5),
            "sh",
        )
        .unwrap();
        assert_eq!(out.status.code(), Some(3));
        assert_eq!(out.stdout, b"in\n");
        assert_eq!(out.stderr, b"err\n");
    }

    /// Lab PR 217: a command that hangs is killed at the deadline and the
    /// caller gets a timeout, not a wait without end.
    #[test]
    fn a_hung_command_times_out() {
        let start = Instant::now();
        let err = run_bounded(
            sh("sleep 30"),
            None,
            Duration::from_millis(300),
            "iptables -S",
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(err.to_string().contains("iptables -S"), "{err}");
        assert!(start.elapsed() < Duration::from_secs(5));
        // one that never reads its stdin either
        let err = run_bounded(
            sh("sleep 30"),
            Some(&vec![b'x'; 1 << 20]),
            Duration::from_millis(300),
            "iptables-restore",
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(10));
    }
}
