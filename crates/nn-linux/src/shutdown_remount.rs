//! Lot 389 (pre-alpha Phase 2h, F2h-2): Ubuntu's `finalrd` at the host's
//! shutdown.
//!
//! Ubuntu's packaged `finalrd.service` (`Conflicts=shutdown.target`) is
//! stopped as the host's shutdown begins, and its `ExecStop=`, the packaged
//! script `/usr/bin/finalrd`, makes `/run` executable first (`mount -o
//! remount,exec /run`) to build the shutdown's final runtime directory. The
//! agent is stopped by systemd-shutdown seconds later, and a round of the
//! integrity check that landed in between signed `/run` losing `noexec` as
//! `mount_attrs_changed` (High): the stop beat carried it, and the off-host
//! verifier said `DEGRADED` after one normal reboot in six (rc14's lab).
//!
//! The change is the shutdown's own — a note ([`RUN_EXEC_KIND`], signed
//! `recorded`, never held), not a degradation — when every fact below holds
//! ([`RunExecFacts::shutdown_not_drift`]); otherwise it is judged as before:
//!
//! - the change is exactly finalrd's: `/run` in PID 1's table lost `noexec`
//!   and nothing else (`mount_attrs::AttrChange::is_run_made_exec`);
//! - the host goes down: systemd (PID 1, over its private socket — the
//!   source of lot 388's rule and of the active response's stand-down,
//!   EBPF-001) says `stopping`, and a job of `reboot.target`,
//!   `poweroff.target`, `halt.target` or `kexec.target` is pending (its id;
//!   its type is not read). `shutdown.target` alone can be pulled into a
//!   transaction that ends nothing, and a soft-reboot (the review of #597,
//!   P3-4) does not take the host down — the agent survives it;
//! - the unit is the packaged one, as systemd holds it: its fragment in the
//!   vendor directory, no drop-in, its one `ExecStop=` the packaged
//!   `/usr/bin/finalrd` — "packaged" meaning both files root's and
//!   writable by no one else (their owner and mode, links followed; not
//!   their content);
//! - that `ExecStop=` ran — systemd's record of it, with its pid — since
//!   the start of the last round that read `/run` unchanged (about one
//!   round interval before), on the monotonic clock (the wall clock is
//!   root's to set);
//! - the change was not signed as a degradation earlier in the run (a later
//!   shutdown never ends it), and less than [`NOTE_MAX_SECS`] passed since
//!   the run's first such note — one budget a run, on the monotonic clock:
//!   past it, or once the host no longer goes down, the round signs the
//!   change as before.
//!
//! The review of #597 (P2-1): root can make those facts true without the
//! host going down — a reboot held or cancelled, finalrd stopped in it or
//! by hand — and put `noexec` back before the next round: the note would
//! then be the only trace. A note therefore awaits its shutdown: at each
//! later round of the run, systemd answering a state other than `stopping`
//! (the shutdown ended, the host runs on), or the agent still running past
//! [`NOTE_MAX_SECS`] after the run's first note, is the High
//! [`NO_SHUTDOWN_KIND`] — a remount noted as the host's shutdown, but the
//! host did not shut down ([`shutdown_not_come`]) — whatever `/run` looks
//! like then, and the run notes no more. A real shutdown ends the agent
//! within seconds of finalrd's stop.
//!
//! The note says what the facts show — the change finalrd makes, made while
//! finalrd's stop ran in the host's shutdown — not that finalrd's process
//! made it: the kernel's mount table names no actor, and a root process's
//! identical remount within that window reads the same. In the last stage
//! (PID 1 is `systemd-shutdown`) systemd no longer answers: a change seen
//! then is judged as before.

use std::path::Path;
use std::time::Duration;

use antitamper_bpf::systemd_bus::{self, Value};

/// The note's kind (an `integrity_drift` row signed `recorded`).
pub const RUN_EXEC_KIND: &str = "run_exec_at_shutdown";

/// The review of #597 (P2-1): the High a round signs when the shutdown a
/// note was signed for did not come ([`shutdown_not_come`]).
pub const NO_SHUTDOWN_KIND: &str = "run_exec_without_shutdown";

/// The packaged unit, its script and where the package puts the unit.
pub const UNIT: &str = "finalrd.service";
pub const BINARY: &str = "/usr/bin/finalrd";
pub const FRAGMENTS: &[&str] = &[
    "/lib/systemd/system/finalrd.service",
    "/usr/lib/systemd/system/finalrd.service",
];

/// The targets whose pending job is the host going down (not
/// `soft-reboot.target`: the review of #597, P3-4 — a soft-reboot keeps the
/// kernel and the agent).
pub const GOING_DOWN_TARGETS: &[&str] = &[
    "reboot.target",
    "poweroff.target",
    "halt.target",
    "kexec.target",
];

/// How long after the run's first note the change may still be noted, and
/// the agent may still run before the note's shutdown is one that did not
/// come (a real shutdown ends the agent within seconds of finalrd's stop).
pub const NOTE_MAX_SECS: u64 = 120;

/// How long each question to systemd may take.
const ASK_TIMEOUT: Duration = Duration::from_millis(800);

/// systemd's record of one `ExecStop=` command (`a(sasbttttuii)`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecRecord {
    pub path: String,
    pub argv: Vec<String>,
    /// When it started: the wall clock and `CLOCK_MONOTONIC` (µs; 0: never
    /// in this boot).
    pub start_realtime_us: u64,
    pub start_monotonic_us: u64,
    pub pid: u32,
}

/// `finalrd.service` as systemd holds it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FinalrdUnit {
    pub fragment: String,
    pub dropins: Vec<String>,
    pub exec_stop: Vec<ExecRecord>,
}

/// What a round knows when `/run` lost `noexec` (see the module).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RunExecFacts {
    /// systemd says `stopping` (PID 1, its private socket).
    pub host_stopping: bool,
    /// The target with a pending job ([`GOING_DOWN_TARGETS`]); `None`: none.
    pub going_down: Option<String>,
    /// The unit as systemd holds it (`None`: not asked, or no answer).
    pub unit: Option<FinalrdUnit>,
    /// The unit's fragment and its script are root's files no one else may
    /// write.
    pub files_packaged: bool,
    /// The last round that read `/run` unchanged (`CLOCK_MONOTONIC`, µs).
    pub unchanged_at_us: u64,
    /// The change was signed as a degradation earlier in this run.
    pub already_signed: bool,
    /// Seconds since the run's first note (`CLOCK_MONOTONIC`); `None`: none
    /// yet.
    pub noted_for: Option<u64>,
}

impl RunExecFacts {
    /// Why `/run` losing `noexec` is the host's shutdown's (a note), or
    /// `None`: a drift, judged as before.
    pub fn shutdown_not_drift(&self) -> Option<String> {
        if !self.host_stopping
            || !self.files_packaged
            || self.already_signed
            || self.noted_for.is_some_and(|s| s > NOTE_MAX_SECS)
        {
            return None;
        }
        let target = self.going_down.as_deref()?;
        let u = self.unit.as_ref()?;
        if !FRAGMENTS.contains(&u.fragment.as_str()) || !u.dropins.is_empty() {
            return None;
        }
        let [e] = u.exec_stop.as_slice() else {
            return None;
        };
        if e.path != BINARY || e.argv != [BINARY] || e.pid == 0 || e.start_monotonic_us == 0 {
            return None;
        }
        // it ran since the last round that read /run unchanged (a second's
        // slack for the round's read within it)
        if e.start_monotonic_us.saturating_add(1_000_000) < self.unchanged_at_us {
            return None;
        }
        Some(format!(
            "made while the host goes down (systemd: stopping, {target} pending) and the stop of \
             {UNIT} ran ({}, no drop-in, root's; systemd's record: {BINARY}, pid {}, started at \
             unix {}), whose first step is this very change (mount -o remount,exec /run) for the \
             shutdown's final runtime directory — the shutdown's own change, not a drift (if the \
             host does not shut down — systemd running again, or the agent still running \
             {NOTE_MAX_SECS} s after the run's first note — the High {NO_SHUTDOWN_KIND} follows)",
            u.fragment,
            e.pid,
            e.start_realtime_us / 1_000_000
        ))
    }
}

/// The review of #597 (P2-1): why the shutdown a note was signed for did
/// not come, `noted_for` seconds after the run's first note — the agent
/// still running past [`NOTE_MAX_SECS`], or systemd's `state` (asked only
/// within it) other than `stopping`: the shutdown ended, the host runs on —
/// or `None`: it may still come (systemd says `stopping`, or no longer
/// answers, as in the last stage).
pub fn shutdown_not_come(noted_for: u64, state: impl FnOnce() -> Option<String>) -> Option<String> {
    if noted_for > NOTE_MAX_SECS {
        return Some(format!(
            "the agent still runs {noted_for} s after the note, past the {NOTE_MAX_SECS} s a \
             shutdown takes to end it"
        ));
    }
    match state() {
        Some(s) if s != "stopping" => Some(format!(
            "systemd says {s} {noted_for} s after the note: the shutdown ended without the host \
             going down"
        )),
        _ => None,
    }
}

/// systemd's state now (PID 1, its private socket); `None`: no answer.
pub fn system_state() -> Option<String> {
    systemd_bus::system_state(Path::new(systemd_bus::PRIVATE_SOCKET), ASK_TIMEOUT).ok()
}

/// The `ExecStop=` records of a property value (`a(sasbttttuii)`); `None`
/// for any other shape.
pub fn exec_records(v: &Value) -> Option<Vec<ExecRecord>> {
    let Value::Array(cmds) = v else {
        return None;
    };
    cmds.iter()
        .map(|c| match c {
            Value::Struct(f) => match f.as_slice() {
                [
                    Value::Str(path),
                    argv,
                    Value::Bool(_),
                    Value::U64(start_rt),
                    Value::U64(start_mono),
                    _,
                    _,
                    Value::U32(pid),
                    ..,
                ] => Some(ExecRecord {
                    path: path.clone(),
                    argv: argv.strings()?,
                    start_realtime_us: *start_rt,
                    start_monotonic_us: *start_mono,
                    pid: *pid,
                }),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

/// A unit's `Job` property (`(uo)`): a job is pending when its id is not 0.
pub fn job_pending(v: &Value) -> bool {
    matches!(v, Value::Struct(f) if matches!(f.first(), Some(Value::U32(id)) if *id != 0))
}

/// The unit as systemd holds it, over its private socket.
fn ask_unit(socket: &Path) -> Option<FinalrdUnit> {
    let v = systemd_bus::unit_properties(
        socket,
        ASK_TIMEOUT,
        UNIT,
        &[
            (antitamper_bpf::unit_props::UNIT, "FragmentPath"),
            (antitamper_bpf::unit_props::UNIT, "DropInPaths"),
            (antitamper_bpf::unit_props::SERVICE, "ExecStop"),
        ],
    )
    .ok()?;
    let [fragment, dropins, exec_stop] = v.as_slice() else {
        return None;
    };
    Some(FinalrdUnit {
        fragment: fragment.as_str()?.to_string(),
        dropins: dropins.strings()?,
        exec_stop: exec_records(exec_stop)?,
    })
}

/// The first of [`GOING_DOWN_TARGETS`] with a pending job.
fn ask_going_down(socket: &Path) -> Option<String> {
    GOING_DOWN_TARGETS
        .iter()
        .find(|t| {
            systemd_bus::unit_property(
                socket,
                ASK_TIMEOUT,
                t,
                antitamper_bpf::unit_props::UNIT,
                "Job",
            )
            .is_ok_and(|v| job_pending(&v))
        })
        .map(|t| t.to_string())
}

/// The facts of this host now (the unit and the jobs asked only while
/// systemd says `stopping`).
pub fn read_facts(
    unchanged_at_us: u64,
    already_signed: bool,
    noted_for: Option<u64>,
) -> RunExecFacts {
    let socket = Path::new(systemd_bus::PRIVATE_SOCKET);
    let root = Path::new("/");
    facts_from(
        systemd_bus::system_state(socket, ASK_TIMEOUT).ok(),
        || ask_going_down(socket),
        || ask_unit(socket),
        |p| crate::known_system_prog::packaged(root, p, 0).is_some(),
        (unchanged_at_us, already_signed, noted_for),
    )
}

/// [`read_facts`] from systemd's state, the questions asked of it only
/// while it says `stopping` (the jobs, then the unit while one is pending)
/// and the files' check (`packaged`); `(unchanged_at_us, already_signed,
/// noted_for)` the round's own.
pub fn facts_from(
    state: Option<String>,
    going_down: impl FnOnce() -> Option<String>,
    unit: impl FnOnce() -> Option<FinalrdUnit>,
    packaged: impl Fn(&str) -> bool,
    (unchanged_at_us, already_signed, noted_for): (u64, bool, Option<u64>),
) -> RunExecFacts {
    let host_stopping = state.as_deref() == Some("stopping");
    let going_down = host_stopping.then(going_down).flatten();
    let unit = going_down.as_ref().and_then(|_| unit());
    let files_packaged = unit
        .as_ref()
        .is_some_and(|u| packaged(&u.fragment) && packaged(BINARY));
    RunExecFacts {
        host_stopping,
        going_down,
        unit,
        files_packaged,
        unchanged_at_us,
        already_signed,
        noted_for,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// rc14's reboot 4 on ubuntu2204: finalrd's stop at 14:19:52.225 (the
    /// boot's 380.2 s), the round at 14:19:52.606, the last round before it
    /// ~25 s earlier.
    fn shutdown() -> RunExecFacts {
        RunExecFacts {
            host_stopping: true,
            going_down: Some("reboot.target".into()),
            unit: Some(FinalrdUnit {
                fragment: FRAGMENTS[0].into(),
                dropins: Vec::new(),
                exec_stop: vec![ExecRecord {
                    path: BINARY.into(),
                    argv: vec![BINARY.into()],
                    start_realtime_us: 1_795_357_192_225_043,
                    start_monotonic_us: 380_200_000,
                    pid: 3637,
                }],
            }),
            files_packaged: true,
            unchanged_at_us: 355_000_000,
            already_signed: false,
            noted_for: None,
        }
    }

    /// Lot 389 (F2h-2): finalrd's remount at the host's shutdown is a note —
    /// and each fact alone missing makes it a drift again: the host running,
    /// "stopping" with no reboot or power-off pending (shutdown.target pulled
    /// in alone), another unit file or a drop-in, another or a second
    /// ExecStop, a script not root's, a stop that did not run or ran before
    /// the last round that read /run unchanged, a change already signed, the
    /// run's budget spent.
    #[test]
    fn finalrds_remount_is_the_shutdowns_only_with_every_fact() {
        let why = shutdown().shutdown_not_drift().expect("the shutdown's own");
        assert!(
            why.contains("pid 3637") && why.contains("reboot.target pending"),
            "{why}"
        );
        assert!(
            RunExecFacts {
                noted_for: Some(NOTE_MAX_SECS),
                ..shutdown()
            }
            .shutdown_not_drift()
            .is_some()
        );
        let unit = |f: &dyn Fn(&mut FinalrdUnit)| {
            let mut s = shutdown();
            f(s.unit.as_mut().unwrap());
            s
        };
        let exec = |f: &dyn Fn(&mut ExecRecord)| unit(&|u| f(&mut u.exec_stop[0]));
        let cases: Vec<(&str, RunExecFacts)> = vec![
            (
                "the host runs",
                RunExecFacts {
                    host_stopping: false,
                    ..shutdown()
                },
            ),
            (
                "nothing goes down",
                RunExecFacts {
                    going_down: None,
                    ..shutdown()
                },
            ),
            (
                "systemd did not answer",
                RunExecFacts {
                    unit: None,
                    ..shutdown()
                },
            ),
            (
                "not root's",
                RunExecFacts {
                    files_packaged: false,
                    ..shutdown()
                },
            ),
            (
                "already signed",
                RunExecFacts {
                    already_signed: true,
                    ..shutdown()
                },
            ),
            (
                "the run's budget spent",
                RunExecFacts {
                    noted_for: Some(NOTE_MAX_SECS + 1),
                    ..shutdown()
                },
            ),
            (
                "an /etc unit",
                unit(&|u| u.fragment = "/etc/systemd/system/finalrd.service".into()),
            ),
            (
                "a drop-in",
                unit(&|u| u.dropins = vec!["/etc/systemd/system/finalrd.service.d/x.conf".into()]),
            ),
            ("no ExecStop", unit(&|u| u.exec_stop.clear())),
            (
                "two ExecStop",
                unit(&|u| {
                    let e = u.exec_stop[0].clone();
                    u.exec_stop.push(e)
                }),
            ),
            (
                "another script",
                exec(&|e| e.path = "/usr/local/bin/finalrd".into()),
            ),
            ("an argument", exec(&|e| e.argv.push("--x".into()))),
            ("never ran", exec(&|e| e.start_monotonic_us = 0)),
            ("no pid", exec(&|e| e.pid = 0)),
            (
                "ran before the last round",
                exec(&|e| e.start_monotonic_us = 353_900_000),
            ),
        ];
        for (what, f) in cases {
            assert_eq!(f.shutdown_not_drift(), None, "{what}");
        }
        // a stop that never ran is none of the shutdown's, whatever the
        // round read before it
        let never = RunExecFacts {
            unchanged_at_us: 0,
            ..exec(&|e| e.start_monotonic_us = 0)
        };
        assert_eq!(never.shutdown_not_drift(), None);
        // a stop started within the second before the round's read
        assert!(
            exec(&|e| e.start_monotonic_us = 354_100_000)
                .shutdown_not_drift()
                .is_some()
        );
        // the wall clock set anywhere: the monotonic one decides
        assert!(
            exec(&|e| e.start_realtime_us = 1)
                .shutdown_not_drift()
                .is_some()
        );
    }

    /// The review of #597 (P2-1): the shutdown a note was signed for did not
    /// come — systemd answers a state other than `stopping` (a reboot
    /// cancelled: the host runs on), or the agent still runs past the bound
    /// (a reboot held, systemd silent or not); while systemd says
    /// `stopping`, or does not answer (the last stage), within the bound it
    /// may still come. Past the bound systemd is not asked.
    #[test]
    fn a_noted_shutdown_that_does_not_come_is_told() {
        for s in ["running", "degraded", "starting", "maintenance"] {
            let why = shutdown_not_come(30, || Some(s.into())).expect(s);
            assert!(why.contains(s) && why.contains("30 s"), "{why}");
        }
        assert_eq!(shutdown_not_come(30, || Some("stopping".into())), None);
        assert_eq!(shutdown_not_come(30, || None), None);
        assert_eq!(
            shutdown_not_come(NOTE_MAX_SECS, || Some("stopping".into())),
            None
        );
        for state in [Some("stopping".to_string()), None] {
            let why = shutdown_not_come(NOTE_MAX_SECS + 1, || -> Option<String> {
                panic!("not asked past the bound: {state:?}")
            })
            .expect("past the bound");
            assert!(why.contains(&format!("{} s", NOTE_MAX_SECS + 1)), "{why}");
        }
        // the note itself names the High that follows
        let why = shutdown().shutdown_not_drift().unwrap();
        assert!(why.contains(NO_SHUTDOWN_KIND), "{why}");
        assert!(
            !why.contains("PID 1's child"),
            "systemd records a pid, no more"
        );
        let code = include_str!("shutdown_remount.rs");
        let ask = &code[code.find("pub fn system_state(").unwrap()..];
        assert!(
            ask[..ask.find('}').unwrap()]
                .contains("systemd_bus::system_state(Path::new(systemd_bus::PRIVATE_SOCKET)"),
            "PID 1's private socket"
        );
    }

    /// The review of #597 (P3-4): a soft-reboot keeps the kernel and the
    /// agent — no shutdown of the host: its pending job is none of the
    /// facts, so finalrd's remount in it stays the High.
    #[test]
    fn a_soft_reboot_is_no_shutdown_of_the_host() {
        assert!(!GOING_DOWN_TARGETS.contains(&"soft-reboot.target"));
        assert_eq!(
            GOING_DOWN_TARGETS,
            [
                "reboot.target",
                "poweroff.target",
                "halt.target",
                "kexec.target"
            ]
        );
    }

    /// The facts as read: systemd asked about the jobs only while it says
    /// `stopping`, about the unit only while a job is pending; both files
    /// checked, the fragment systemd names and the script.
    #[test]
    fn the_facts_are_asked_of_systemd_only_while_the_host_goes_down() {
        let unit = || shutdown().unit;
        let round = (7, false, None);
        let f = facts_from(
            Some("running".into()),
            || panic!("no job asked"),
            || panic!("no unit asked"),
            |_| true,
            round,
        );
        assert!(
            !f.host_stopping && f.going_down.is_none() && f.unit.is_none() && !f.files_packaged
        );
        let f = facts_from(
            None,
            || panic!("no job asked"),
            || panic!("no unit asked"),
            |_| true,
            round,
        );
        assert!(!f.host_stopping);
        let f = facts_from(
            Some("stopping".into()),
            || None,
            || panic!("no unit asked"),
            |_| true,
            round,
        );
        assert!(f.host_stopping && f.going_down.is_none() && f.shutdown_not_drift().is_none());
        let f = facts_from(
            Some("stopping".into()),
            || Some("reboot.target".into()),
            unit,
            |_| true,
            (355_000_000, false, None),
        );
        assert_eq!(f, shutdown());
        for bad in [FRAGMENTS[0], BINARY] {
            let f = facts_from(
                Some("stopping".into()),
                || Some("reboot.target".into()),
                unit,
                |p| p != bad,
                round,
            );
            assert!(!f.files_packaged, "{bad}");
        }
        let f = facts_from(
            Some("stopping".into()),
            || Some("reboot.target".into()),
            unit,
            |_| true,
            (1, true, Some(9)),
        );
        assert_eq!(
            (f.unchanged_at_us, f.already_signed, f.noted_for),
            (1, true, Some(9))
        );
    }

    /// systemd's `ExecStop` property as the private socket gives it (the
    /// guest's: one command, `/usr/bin/finalrd`, never run yet in that
    /// boot) is read; any other shape is not. A unit's `Job` is pending only
    /// with a job id.
    #[test]
    fn the_exec_stop_records_and_jobs_are_read_from_systemds_properties() {
        let cmd = |start: u64, pid: u32| {
            Value::Struct(vec![
                Value::Str(BINARY.into()),
                Value::Array(vec![Value::Str(BINARY.into())]),
                Value::Bool(false),
                Value::U64(start),
                Value::U64(start / 1000),
                Value::U64(0),
                Value::U64(0),
                Value::U32(pid),
                Value::I32(0),
                Value::I32(0),
            ])
        };
        assert_eq!(
            exec_records(&Value::Array(vec![cmd(0, 0)])),
            Some(vec![ExecRecord {
                path: BINARY.into(),
                argv: vec![BINARY.into()],
                start_realtime_us: 0,
                start_monotonic_us: 0,
                pid: 0,
            }])
        );
        let r = exec_records(&Value::Array(vec![cmd(7_000, 3637)])).unwrap();
        assert_eq!((r[0].pid, r[0].start_monotonic_us), (3637, 7));
        assert_eq!(exec_records(&Value::Array(Vec::new())), Some(Vec::new()));
        assert_eq!(exec_records(&Value::Str(BINARY.into())), None);
        assert_eq!(
            exec_records(&Value::Array(vec![Value::Struct(vec![Value::Str(
                BINARY.into()
            )])])),
            None
        );
        let job = |id: u32| Value::Struct(vec![Value::U32(id), Value::Str("/".into())]);
        assert!(job_pending(&job(212)));
        assert!(!job_pending(&job(0)));
        assert!(!job_pending(&Value::U32(212)));
    }
}
