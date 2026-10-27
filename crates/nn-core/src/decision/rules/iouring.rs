//! NN-L-IOU-001/002 — io_uring, the asynchronous I/O channel that
//! syscall-centric sensors miss (Tappa 10.8; external review 2026-10-10).
//!
//! The sensor emits one record when a process creates a ring and one
//! whenever it uses a NEW opcode class (file open, file read/write,
//! network connect, network send/recv, filesystem mutation). The rules
//! score the shape, not the mere use: io_uring is legitimate for
//! databases, QEMU, nginx, liburing programs and libuv-based runtimes
//! (Node ≥ 20), so both verdicts are **Log** — telemetry and an alert,
//! never a kill — and every program in the process allowlist is exempt,
//! judged on the executable the kernel ran (external audit NETR-003
//! class), not on the `comm` a process can name itself.
//!
//! * `NN-L-IOU-001_IoUringRingCreated` (Low): a ring created by a process
//!   outside the allowlist. One line per creation; the baseline of who
//!   uses io_uring on this host.
//! * `NN-L-IOU-002_IoUringFileAndNetwork` (High): the same process has
//!   driven BOTH file I/O (open or read/write) AND network I/O (connect
//!   or send/recv) through rings — the exfiltration / implant shape
//!   that leaves no `openat`/`connect`/`sendto` for the other sensors.
//!   Fires once per process (the first record carrying both classes).

use std::sync::Arc;

use common::wire::{
    IOURING_CLASS_FILE_OPEN, IOURING_CLASS_FILE_RW, IOURING_CLASS_NET_CONNECT,
    IOURING_CLASS_NET_SENDRECV,
};
use nn_model::{Event, ResponseAction, Severity, Verdict};

use crate::config::comm_allowlist::{CommAllowlist, Judgement};
use crate::decision::attack::{AttackRef, Tactic};
use crate::decision::{rules::build_verdict, Rule};
use crate::posture::host::PostureHost;

const FILE_CLASSES: u32 = IOURING_CLASS_FILE_OPEN | IOURING_CLASS_FILE_RW;
const NET_CLASSES: u32 = IOURING_CLASS_NET_CONNECT | IOURING_CLASS_NET_SENDRECV;

/// Known legitimate io_uring users on a server, matched on the executable
/// the kernel ran (a 15-character name also covers the longer names the
/// kernel truncates `comm` to it), and on `comm` only when that cannot be
/// read. Extended by the operator through `process-comm-allowlist.local`.
pub const KNOWN_IOURING_PROGRAMS: &[&str] = &[
    "qemu-system-x86",
    "qemu-kvm",
    "nginx",
    "postgres",
    "mariadbd",
    "mysqld",
    "redis-server",
    "node",
    "fio",
    "systemd-journal",
];

pub struct NnLIou001IoUringRingCreated<H: PostureHost> {
    allowlist: Arc<CommAllowlist<H>>,
}

impl<H: PostureHost> NnLIou001IoUringRingCreated<H> {
    pub fn new(allowlist: Arc<CommAllowlist<H>>) -> Self {
        Self { allowlist }
    }
}

impl<H: PostureHost> Rule for NnLIou001IoUringRingCreated<H> {
    fn id(&self) -> &'static str {
        "NN-L-IOU-001_IoUringRingCreated"
    }
    fn name(&self) -> &'static str {
        "io_uring ring created by an unlisted process"
    }
    fn category(&self) -> &'static str {
        "defense_evasion"
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[AttackRef::new(Tactic::Execution, "T1106")];
        ATTACK
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::IoUring {
            created: true,
            pid,
            comm,
            count,
            classes,
            ..
        } = event
        else {
            return None;
        };
        let judgement = judge(&self.allowlist, *pid, comm);
        if judgement == Judgement::Allowed {
            return None;
        }
        let reasoning = format!(
            "io_uring ring set up by `{comm}` (sq_entries={count}, flags={classes:#x}): the process \
             can now perform file and network I/O without the syscalls the other sensors hook \
             (a sensor-evasion shape). Logged as baseline; NN-L-IOU-002 scores the usage."
        );
        Some(judgement.apply(
            build_verdict(self, event, ResponseAction::Log, Severity::Low, &reasoning),
            comm,
        ))
    }
}

pub struct NnLIou002IoUringFileAndNetwork<H: PostureHost> {
    allowlist: Arc<CommAllowlist<H>>,
}

impl<H: PostureHost> NnLIou002IoUringFileAndNetwork<H> {
    pub fn new(allowlist: Arc<CommAllowlist<H>>) -> Self {
        Self { allowlist }
    }
}

impl<H: PostureHost> Rule for NnLIou002IoUringFileAndNetwork<H> {
    fn id(&self) -> &'static str {
        "NN-L-IOU-002_IoUringFileAndNetwork"
    }
    fn name(&self) -> &'static str {
        "io_uring file and network I/O from the same unlisted process"
    }
    fn category(&self) -> &'static str {
        "defense_evasion"
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[AttackRef::new(Tactic::Execution, "T1106")];
        ATTACK
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::IoUring {
            created: false,
            pid,
            comm,
            classes,
            last_opcode,
            sq_thread,
            ..
        } = event
        else {
            return None;
        };
        if classes & FILE_CLASSES == 0 || classes & NET_CLASSES == 0 {
            return None;
        }
        // Fire once: on the record that COMPLETES the pair. The sensor emits
        // a record on every new class, so the completing record is the one
        // whose last opcode belongs to the class that was still missing.
        let last_class = common::wire::io_uring_opcode_class(*last_opcode);
        if last_class & (FILE_CLASSES | NET_CLASSES) == 0 {
            return None;
        }
        let judgement = judge(&self.allowlist, *pid, comm);
        if judgement == Judgement::Allowed {
            return None;
        }
        let names = nn_model::io_uring_class_names(*classes);
        let reasoning = format!(
            "`{comm}` drives both file I/O and network I/O through io_uring rings ({}){}: \
             reads, writes and connections that never pass through openat/connect/sendto — \
             the blind-channel exfiltration/implant shape (RingReaper class). \
             Alert only: legitimate io_uring servers are exempted by executable.",
            names.join(", "),
            if *sq_thread {
                " with SQPOLL kernel-thread submission"
            } else {
                ""
            }
        );
        Some(judgement.apply(
            build_verdict(self, event, ResponseAction::Log, Severity::High, &reasoning),
            comm,
        ))
    }
}

/// External audit NETR-003 class: the known servers and the operator
/// allowlist judged on what the kernel ran, not on the `comm` a process
/// names itself.
fn judge<H: PostureHost>(allowlist: &CommAllowlist<H>, pid: u32, comm: &str) -> Judgement {
    allowlist.judge_with(pid, comm, KNOWN_IOURING_PROGRAMS)
}

/// The two io_uring rules, sharing the process comm allowlist.
pub fn iouring_rules<H: PostureHost>(allowlist: Arc<CommAllowlist<H>>) -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(NnLIou001IoUringRingCreated::new(Arc::clone(&allowlist))),
        Box::new(NnLIou002IoUringFileAndNetwork::new(allowlist)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    // R08b (lab PR 251): on the portable test host.
    use crate::posture::host::testing::TestHost as H;
    type CommAllowlist = crate::config::comm_allowlist::CommAllowlist<H>;
    type NnLIou001IoUringRingCreated = super::NnLIou001IoUringRingCreated<H>;
    type NnLIou002IoUringFileAndNetwork = super::NnLIou002IoUringFileAndNetwork<H>;

    fn ev(created: bool, comm: &str, classes: u32, last_opcode: u8) -> Event {
        Event::IoUring {
            created,
            pid: 4242,
            uid: 1000,
            comm: comm.to_string(),
            classes,
            count: 32,
            last_opcode,
            sq_thread: false,
            timestamp_ns: 1,
        }
    }

    fn rules() -> (NnLIou001IoUringRingCreated, NnLIou002IoUringFileAndNetwork) {
        let al = Arc::new(CommAllowlist::from_iter_owned(["myapp".to_string()]));
        (
            NnLIou001IoUringRingCreated::new(Arc::clone(&al)),
            NnLIou002IoUringFileAndNetwork::new(al),
        )
    }

    #[test]
    fn ring_creation_logs_unlisted_and_exempts_known_and_allowlisted() {
        let (r1, _) = rules();
        let v = r1.evaluate(&ev(true, "evil", 0, 0)).expect("fires");
        assert_eq!(v.rule_id, "NN-L-IOU-001_IoUringRingCreated");
        assert_eq!(v.severity, Severity::Low);
        assert_eq!(v.action, ResponseAction::Log);
        assert!(r1.evaluate(&ev(true, "nginx", 0, 0)).is_none());
        assert!(r1.evaluate(&ev(true, "myapp", 0, 0)).is_none());
        // activity records are not creations
        assert!(r1.evaluate(&ev(false, "evil", FILE_CLASSES, 22)).is_none());
    }

    #[test]
    fn file_and_network_fires_once_on_the_completing_record() {
        let (_, r2) = rules();
        // file only: no
        assert!(r2
            .evaluate(&ev(false, "evil", IOURING_CLASS_FILE_RW, 22))
            .is_none());
        // file + net, completed by CONNECT (16): yes, High, Log
        let both = IOURING_CLASS_FILE_RW | IOURING_CLASS_NET_CONNECT;
        let v = r2.evaluate(&ev(false, "evil", both, 16)).expect("fires");
        assert_eq!(v.rule_id, "NN-L-IOU-002_IoUringFileAndNetwork");
        assert_eq!(v.severity, Severity::High);
        assert_eq!(v.action, ResponseAction::Log);
        assert!(v.reasoning.contains("file_rw, net_connect"));
        // a later record whose last opcode is OTHER (NOP=0) does not re-fire
        assert!(r2.evaluate(&ev(false, "evil", both, 0)).is_none());
        // known servers and the allowlist are exempt
        assert!(r2.evaluate(&ev(false, "postgres", both, 16)).is_none());
        assert!(r2.evaluate(&ev(false, "myapp", both, 16)).is_none());
    }

    /// External audit LLMR-012 (NN-AUD-055): a process that calls itself
    /// `nginx` (`prctl(PR_SET_NAME)`) no longer borrows nginx's exemption;
    /// the servers are recognised by the executable the kernel ran.
    #[test]
    fn a_process_named_like_a_known_server_is_no_longer_exempt() {
        let tmp = tempfile::TempDir::new().unwrap();
        let t = crate::posture::lineage::AuthSessionTracker::<H>::new(tmp.path());
        for (pid, exe, argv) in [
            (800, "/dev/shm/.k", &["/dev/shm/.k"][..]),
            (801, "/usr/sbin/nginx", &["nginx"][..]),
            (
                802,
                "/usr/bin/qemu-system-x86_64",
                &["qemu-system-x86_64"][..],
            ),
            (
                803,
                "/usr/lib/systemd/systemd-journald",
                &["systemd-journald"][..],
            ),
            (804, "/usr/bin/node", &["node", "/srv/app/server.js"][..]),
        ] {
            let argv: Vec<String> = argv.iter().map(|a| a.to_string()).collect();
            t.ingest_spawn_with_argv(pid, 1, exe, &argv, 1);
        }
        let al = Arc::new(CommAllowlist::from_iter_owned(["myapp".to_string()]).with_identity(t));
        let r1 = NnLIou001IoUringRingCreated::new(Arc::clone(&al));
        let r2 = NnLIou002IoUringFileAndNetwork::new(al);
        let by = |pid: u32, created: bool, comm: &str, classes: u32, op: u8| {
            let mut e = ev(created, comm, classes, op);
            if let Event::IoUring { pid: p, .. } = &mut e {
                *p = pid;
            }
            e
        };
        let both = IOURING_CLASS_FILE_RW | IOURING_CLASS_NET_CONNECT;
        let v = r2
            .evaluate(&by(800, false, "nginx", both, 16))
            .expect("an implant named nginx fires");
        assert!(v.reasoning.contains("named 'nginx'"), "{}", v.reasoning);
        assert!(r1.evaluate(&by(800, true, "nginx", 0, 0)).is_some());
        assert!(r2.evaluate(&by(801, false, "nginx", both, 16)).is_none());
        // the 15-character comm the kernel shows for the longer names
        assert!(r1
            .evaluate(&by(802, true, "qemu-system-x86", 0, 0))
            .is_none());
        assert!(r1
            .evaluate(&by(803, true, "systemd-journal", 0, 0))
            .is_none());
        // a known runtime is known whatever script it runs
        assert!(r2.evaluate(&by(804, false, "node", both, 16)).is_none());
    }
}
