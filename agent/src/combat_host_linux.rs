//! The Linux host of the COMBAT ladder: nn-core's [`CombatHost`] (Wave 4
//! restructure, R08c, lab PR 252) — the ladder's capture of a process is
//! [`ProcRef`], a pidfd and the start `/proc` gives the process (external
//! audit CMB-004), made and read with the calls the ladder made on it
//! before, the same arguments. The host is the chains', the posture's and
//! the engine's one ([`LinuxHost`], `chain_host_linux`): one type, the
//! agent's.

use nn_core::combat::host::{Capture, CombatHost};

use crate::chain_host_linux::LinuxHost;
use crate::response::proc_ref::ProcRef;

impl CombatHost for LinuxHost {
    type Proc = ProcRef;

    /// [`ProcRef::open_for_event`].
    fn open_for_event(pid: u32, start_ns: u64, seen_ns: u64) -> ProcRef {
        ProcRef::open_for_event(pid, start_ns, seen_ns)
    }
}

/// [`ProcRef`]'s own methods, by name.
impl Capture for ProcRef {
    fn pid(&self) -> u32 {
        ProcRef::pid(self)
    }

    fn start_ticks(&self) -> Option<u64> {
        ProcRef::start_ticks(self)
    }

    fn start_ns(&self) -> Option<u64> {
        ProcRef::start_ns(self)
    }

    fn seen_ns(&self) -> Option<u64> {
        ProcRef::seen_ns(self)
    }

    fn capture_errno(&self) -> Option<i32> {
        ProcRef::capture_errno(self)
    }

    fn matches_event(&self, start_ns: u64) -> bool {
        ProcRef::matches_event(self, start_ns)
    }

    fn is_live(&self) -> bool {
        ProcRef::is_live(self)
    }

    fn has_fd(&self) -> bool {
        ProcRef::has_fd(self)
    }

    fn without_fd(&self) -> ProcRef {
        ProcRef::without_fd(self)
    }
}

/// What is Linux about the ladder's host: the capture is a pidfd on the
/// process, with the start `/proc` gives it. The ladder's own tests
/// (nn-core's) run on a portable test host.
#[cfg(test)]
mod tests {
    use super::*;

    /// A running process captured through the host: its pid and the start
    /// `/proc` gives it, a descriptor held while it runs; an event with no
    /// start names it while it runs, and once it has exited, an event with
    /// its start still does; its descriptor dropped, it is the same
    /// process.
    #[test]
    fn the_host_captures_a_process_by_its_pidfd_and_start() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();
        let start = crate::response::proc_ref::proc_start_ns(pid).expect("its start");
        let p = <LinuxHost as CombatHost>::open_for_event(pid, start, 0);
        assert_eq!(Capture::pid(&p), pid);
        assert_eq!(
            Capture::start_ticks(&p),
            crate::response::proc_ref::proc_start_ticks(pid)
        );
        assert_eq!(Capture::start_ns(&p), Some(start));
        assert!(Capture::has_fd(&p) && Capture::is_live(&p));
        assert!(Capture::matches_event(&p, 0));
        assert_eq!(Capture::capture_errno(&p), None);
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(!Capture::is_live(&p));
        assert!(Capture::matches_event(&p, start), "its own start");
        assert!(!Capture::matches_event(&p, 0), "no start, not running");
        let q = Capture::without_fd(&p);
        assert!(!Capture::has_fd(&q));
        assert_eq!(
            (Capture::pid(&q), Capture::start_ticks(&q)),
            (pid, Capture::start_ticks(&p))
        );
    }
}
