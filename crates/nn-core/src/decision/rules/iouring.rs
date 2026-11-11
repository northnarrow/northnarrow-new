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
//!   Lot 314 (the third bug hunt, BUG-83): "once" is a memory, keyed by
//!   the process's pid and start ([`OncePerProcess`], capped). The rule
//!   had none and took the record whose last opcode belonged to a file or
//!   network class for the completing one; the sensor sends the cumulative
//!   bitmap with every new class and again at most once a second with the
//!   opcode of that moment, so it fired on most of them. A pid the kernel
//!   gives to a new process is a new key (the sensor's own per-pid state is
//!   cleared at exit on the kernel side, N9).

use std::sync::Arc;

use common::wire::{
    IOURING_CLASS_FILE_OPEN, IOURING_CLASS_FILE_RW, IOURING_CLASS_NET_CONNECT,
    IOURING_CLASS_NET_SENDRECV,
};
use nn_model::{Event, ResponseAction, Severity, Verdict};
use parking_lot::Mutex;

use crate::config::comm_allowlist::{CommAllowlist, Judgement};
use crate::decision::attack::{AttackRef, Tactic};
use crate::decision::bounded::OncePerProcess;
use crate::decision::{rules::build_verdict, Rule};
use crate::posture::host::PostureHost;

const FILE_CLASSES: u32 = IOURING_CLASS_FILE_OPEN | IOURING_CLASS_FILE_RW;
const NET_CLASSES: u32 = IOURING_CLASS_NET_CONNECT | IOURING_CLASS_NET_SENDRECV;

/// Lot 314 (BUG-83): the processes NN-L-IOU-002 remembers firing for; past
/// it the one it fired for least recently is forgotten (one more verdict,
/// which the per-rule budget bounds).
pub const IOU002_FIRED_CAP: usize = 4096;

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
        let judgement = judge(
            &self.allowlist,
            *pid,
            comm,
            crate::posture::lineage::AsOf::of_event(event),
        );
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
    /// Lot 314 (BUG-83): the processes it fired for, by pid and start.
    fired: Mutex<OncePerProcess>,
}

impl<H: PostureHost> NnLIou002IoUringFileAndNetwork<H> {
    pub fn new(allowlist: Arc<CommAllowlist<H>>) -> Self {
        Self {
            allowlist,
            fired: Mutex::new(OncePerProcess::new(IOU002_FIRED_CAP)),
        }
    }

    /// The processes it holds a fired-for record of (tests: the cap).
    #[cfg(test)]
    fn fired_len(&self) -> usize {
        self.fired.lock().len()
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
            sq_thread,
            ..
        } = event
        else {
            return None;
        };
        if classes & FILE_CLASSES == 0 || classes & NET_CLASSES == 0 {
            return None;
        }
        let judgement = judge(
            &self.allowlist,
            *pid,
            comm,
            crate::posture::lineage::AsOf::of_event(event),
        );
        if judgement == Judgement::Allowed {
            return None;
        }
        // Fire once per process: the first record carrying both classes.
        // Lot 314 (BUG-83): remembered by pid and start — the stateless
        // test it replaced (the record's last opcode in a file or network
        // class) held for most of the records the sensor sends after it.
        if !self
            .fired
            .lock()
            .first(*pid, self.allowlist.process_start(*pid))
        {
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
fn judge<H: PostureHost>(
    allowlist: &CommAllowlist<H>,
    pid: u32,
    comm: &str,
    as_of: crate::posture::lineage::AsOf,
) -> Judgement {
    allowlist.judge_with(pid, comm, KNOWN_IOURING_PROGRAMS, as_of)
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

/// Triage bug hunt 3, BUG-83: NN-L-IOU-002 promises one verdict per
/// process, on the record that completes the file+network pair
/// (module doc line 21, comment at `evaluate`). The sensor
/// (agent-ebpf/src/io_uring.rs:145-153) re-emits the full cumulative
/// bitmap on every new class and at most once a second afterwards, with
/// the opcode of that moment as `last_opcode`.
#[cfg(test)]
mod bug83 {
    use super::*;
    use crate::posture::host::testing::TestHost as H;
    use common::wire::{
        IOURING_CLASS_FILE_OPEN as FO, IOURING_CLASS_FILE_RW as FRW,
        IOURING_CLASS_NET_CONNECT as NC, IOURING_CLASS_NET_SENDRECV as NS,
    };

    fn ev(classes: u32, last_opcode: u8) -> Event {
        Event::IoUring {
            created: false,
            pid: 4242,
            uid: 1000,
            comm: "evil".to_string(),
            classes,
            count: 32,
            last_opcode,
            sq_thread: false,
            timestamp_ns: 1,
        }
    }

    fn fired_on(records: &[Event]) -> Vec<usize> {
        let al = Arc::new(CommAllowlist::<H>::from_iter_owned(Vec::<String>::new()));
        let r = NnLIou002IoUringFileAndNetwork::new(al);
        records
            .iter()
            .enumerate()
            .filter(|(_, e)| r.evaluate(e).is_some())
            .map(|(i, _)| i)
            .collect()
    }

    #[test]
    fn bug83_new_classes_and_periodic_records_do_not_refire() {
        let records = [
            ev(FO, 18),                 // OPENAT: file only
            ev(FO | NC, 16),            // CONNECT: completes the pair
            ev(FO | FRW | NC, 22),      // READ: new class
            ev(FO | FRW | NC | NS, 26), // SEND: new class
            ev(FO | FRW | NC | NS, 22), // periodic (1 s)
            ev(FO | FRW | NC | NS, 26), // periodic (1 s)
        ];
        assert_eq!(
            fired_on(&records),
            vec![1],
            "NN-L-IOU-002 must fire once per process, on the completing record"
        );
    }

    #[test]
    fn bug83_two_class_server_periodic_records_do_not_refire() {
        let records = [
            ev(NC, 13),       // ACCEPT
            ev(NC | FRW, 22), // READ: completes the pair
            ev(NC | FRW, 23), // periodic WRITE
            ev(NC | FRW, 22), // periodic READ
        ];
        assert_eq!(fired_on(&records), vec![1], "periodic records re-fire");
    }
}

/// Lot 314 (F3, [`crate::model_check`]): NN-L-IOU-002 as a "once" machine.
/// A seeded generator draws, for a few pids, processes that start (a
/// `stat` with their start in the rule's `/proc`) and exit, the records the
/// sensor sends for them (a new class, a periodic one) and the reader that
/// takes them later — some after their process exited. After every record
/// read: at most one verdict per (pid, start); a record read while its
/// process runs fires exactly when its process has none yet; one read
/// after its process exited fires only for a pid never fired for.
#[cfg(test)]
mod model {
    use super::*;
    use crate::model_check::{check, Rng, SEQUENCES};
    use crate::posture::host::testing::TestHost as H;
    use common::wire::{
        IOURING_CLASS_FILE_OPEN as FO, IOURING_CLASS_FILE_RW as FRW,
        IOURING_CLASS_NET_CONNECT as NC, IOURING_CLASS_NET_SENDRECV as NS,
    };
    use std::collections::{BTreeMap, BTreeSet, VecDeque};
    use std::path::Path;

    const PIDS: [u32; 4] = [100, 101, 102, 103];
    /// An opcode of each class (OPENAT, READ, CONNECT, SEND) and of none (NOP).
    const OPS: [(u32, u8); 5] = [(FO, 18), (FRW, 22), (NC, 16), (NS, 26), (0, 0)];

    fn stat(proc: &Path, pid: u32) -> std::path::PathBuf {
        proc.join(pid.to_string()).join("stat")
    }

    fn write_stat(proc: &Path, pid: u32, start: u64) {
        std::fs::write(
            stat(proc, pid),
            format!("{pid} (evil) S 1 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 {start} 0 0\n"),
        )
        .unwrap();
    }

    fn record(pid: u32, classes: u32, last_opcode: u8, ts: u64) -> Event {
        Event::IoUring {
            created: false,
            pid,
            uid: 1000,
            comm: "evil".to_string(),
            classes,
            count: 1,
            last_opcode,
            sq_thread: false,
            timestamp_ns: ts,
        }
    }

    fn run(rng: &mut Rng, proc: &Path, next_start: &mut u64) -> Result<(), String> {
        for pid in PIDS {
            let _ = std::fs::remove_file(stat(proc, pid));
        }
        let tracker = crate::posture::lineage::AuthSessionTracker::<H>::new(proc);
        let al = Arc::new(CommAllowlist::<H>::from_iter_owned(Vec::<String>::new()).with_identity(tracker));
        let rule = NnLIou002IoUringFileAndNetwork::new(al);
        // pid -> (start, classes) of the process running now
        let mut live: BTreeMap<u32, (u64, u32)> = BTreeMap::new();
        // records written, not read yet: (pid, start of their process, the event)
        let mut queue: VecDeque<(u32, u64, Event)> = VecDeque::new();
        let mut verdicts: BTreeSet<(u32, u64)> = BTreeSet::new();
        let mut fired_pids: BTreeSet<u32> = BTreeSet::new();
        let mut ts = 1u64;
        for step in 0..40 {
            ts += 1;
            let pid = *rng.pick(&PIDS);
            match rng.below(10) {
                0 => {
                    // A new process takes the pid once the records of the
                    // last one are read: the start is read when the record
                    // is, so a record read after its pid went to another
                    // process is taken for that one's (the limit of a start
                    // the record does not carry; the reader runs
                    // milliseconds behind, a pid comes back after the whole
                    // pid space).
                    if !live.contains_key(&pid) && queue.iter().all(|(p, _, _)| *p != pid) {
                        *next_start += 1;
                        write_stat(proc, pid, *next_start);
                        live.insert(pid, (*next_start, 0));
                    }
                }
                1 => {
                    if live.remove(&pid).is_some() {
                        std::fs::remove_file(stat(proc, pid)).unwrap();
                    }
                }
                2..=5 => {
                    if let Some((start, classes)) = live.get_mut(&pid) {
                        let (class, op) = *rng.pick(&OPS);
                        let new = *classes | class != *classes;
                        *classes |= class;
                        // a new class is sent at once; the same ones at most
                        // once a second (here: one draw in three)
                        if *classes != 0 && (new || rng.one_in(3)) {
                            queue.push_back((pid, *start, record(pid, *classes, op, ts)));
                        }
                    }
                }
                _ => {
                    let Some((pid, start, e)) = queue.pop_front() else {
                        continue;
                    };
                    let Event::IoUring { classes, .. } = e else {
                        unreachable!()
                    };
                    let both = classes & FILE_CLASSES != 0 && classes & NET_CLASSES != 0;
                    let running = live.get(&pid).is_some_and(|(s, _)| *s == start);
                    let fired = rule.evaluate(&e).is_some();
                    let want = both
                        && if running {
                            !verdicts.contains(&(pid, start))
                        } else {
                            !fired_pids.contains(&pid)
                        };
                    if fired && !verdicts.insert((pid, start)) {
                        return Err(format!("step {step}: a second verdict for ({pid}, {start})"));
                    }
                    if fired != want {
                        return Err(format!(
                            "step {step}: ({pid}, {start}) classes {classes:#x} running \
                             {running}: fired {fired}, the oracle says {want}"
                        ));
                    }
                    if fired {
                        fired_pids.insert(pid);
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn nn_l_iou_002_fires_at_most_once_per_process() {
        let tmp = tempfile::TempDir::new().unwrap();
        for pid in PIDS {
            std::fs::create_dir_all(tmp.path().join(pid.to_string())).unwrap();
        }
        let mut next_start = 1_000;
        check("NN-L-IOU-002 once", 0x3142_0000, SEQUENCES, |rng| {
            run(rng, tmp.path(), &mut next_start)
        });
    }

    /// The rule's memory has a cap: a flood of distinct pids keeps
    /// [`IOU002_FIRED_CAP`] of them.
    #[test]
    fn nn_l_iou_002_s_memory_is_capped() {
        let al = Arc::new(CommAllowlist::<H>::from_iter_owned(Vec::<String>::new()));
        let rule = NnLIou002IoUringFileAndNetwork::new(al);
        for pid in 1..=(IOU002_FIRED_CAP as u32 * 2) {
            assert!(rule.evaluate(&record(pid, FO | NC, 16, 1)).is_some());
        }
        assert_eq!(rule.fired_len(), IOU002_FIRED_CAP);
    }
}
