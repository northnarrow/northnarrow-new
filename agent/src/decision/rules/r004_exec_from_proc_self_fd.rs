//! R004 — memfd-style exec via `/proc/self/fd/*` or `/proc/<pid>/fd/*`.

use common::{Event, ResponseAction, Severity, Verdict};

use crate::decision::{rules::build_verdict, Rule};

pub struct R004ExecFromProcSelfFd;

impl R004ExecFromProcSelfFd {
    /// True if the path looks like `/proc/self/fd/<n>` or
    /// `/proc/<pid>/fd/<n>`. Both forms are the canonical way to exec
    /// from a memfd or anonymous fd, which is a strong fileless-exec
    /// signal.
    fn is_proc_fd_path(path: &str) -> bool {
        let rest = match path.strip_prefix("/proc/") {
            Some(r) => r,
            None => return false,
        };
        // /proc/self/fd/N
        if let Some(after_self) = rest.strip_prefix("self/fd/") {
            return !after_self.is_empty();
        }
        // /proc/<pid>/fd/N — first segment must be all-digits.
        let mut parts = rest.splitn(3, '/');
        let pid = parts.next().unwrap_or("");
        let fd_lit = parts.next().unwrap_or("");
        let after = parts.next().unwrap_or("");
        if !pid.is_empty()
            && pid.bytes().all(|b| b.is_ascii_digit())
            && fd_lit == "fd"
            && !after.is_empty()
        {
            return true;
        }
        false
    }
}

impl Rule for R004ExecFromProcSelfFd {
    fn id(&self) -> &'static str {
        "R004_ExecFromProcSelfFd"
    }
    fn name(&self) -> &'static str {
        "Exec from /proc/<pid>/fd/* (memfd)"
    }
    fn category(&self) -> &'static str {
        "execution"
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn { filename, .. } = event else {
            return None;
        };
        if !Self::is_proc_fd_path(filename) {
            return None;
        }
        Some(build_verdict(
            self,
            event,
            ResponseAction::KillProcessTree,
            Severity::Critical,
            "memfd-style exec detected — fileless execution, highly suspicious",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::rules::testutil::spawn;

    #[test]
    fn fires_on_proc_self_fd() {
        let v = R004ExecFromProcSelfFd
            .evaluate(&spawn("memexec", "/proc/self/fd/3"))
            .expect("fires");
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(v.action, ResponseAction::KillProcessTree);
    }

    #[test]
    fn ignores_normal_paths() {
        assert!(R004ExecFromProcSelfFd
            .evaluate(&spawn("ls", "/usr/bin/ls"))
            .is_none());
        // /proc/<pid>/status is not an exec target.
        assert!(R004ExecFromProcSelfFd
            .evaluate(&spawn("x", "/proc/123/status"))
            .is_none());
    }

    #[test]
    fn matches_proc_pid_fd_form_too() {
        assert!(R004ExecFromProcSelfFd
            .evaluate(&spawn("x", "/proc/4242/fd/7"))
            .is_some());
        // Empty fd number does not count.
        assert!(R004ExecFromProcSelfFd
            .evaluate(&spawn("x", "/proc/self/fd/"))
            .is_none());
        // Non-numeric pid does not count.
        assert!(R004ExecFromProcSelfFd
            .evaluate(&spawn("x", "/proc/abc/fd/3"))
            .is_none());
    }
}
