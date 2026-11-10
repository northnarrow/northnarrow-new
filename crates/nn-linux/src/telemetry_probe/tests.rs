use super::*;

use crate::audit::AgentSigningKey;
use crate::boot::degradation;

const AGENT: u32 = 4_000;
const CHILD: u32 = 4_242;
const EXE: &str = "/usr/local/bin/northnarrow-agent";
const DENY: (u64, u64) = (0x0080_0001, 77);
const FROM: u64 = 1_000_000;
const UNTIL: u64 = 2_000_000;
const TS: u64 = 1_500_000;

fn window() -> Window {
    Window {
        pid: CHILD,
        from_ns: FROM,
        until_ns: UNTIL,
    }
}

fn probe_with_round(nonce: &str) -> TelemetryProbe {
    let p = TelemetryProbe::for_tests(Duration::from_secs(60));
    p.open_round_for_tests(nonce, AGENT, EXE, window(), Some(DENY));
    p
}

/// The child's report of a round whose every step ran.
fn full_report_text() -> String {
    "file=ok\ndns=ok\ntcp=ok\nio_uring=ok\nbpf=ok\nfim=ok\ndeny_signal=refused\ndeny_create=refused\n"
        .to_string()
}

fn full_report() -> ChildReport {
    ChildReport::parse(&full_report_text())
}

/// The attach checks of a healthy host.
fn checks_ok() -> Vec<(Sensor, Outcome)> {
    Sensor::ALL
        .into_iter()
        .filter(|s| !s.live())
        .map(|s| (s, Outcome::Seen))
        .collect()
}

/// R13 (lab PR 271), lot 280c: the self-test's word for the manifest —
/// pending until a round ends, then each sensor's own; stale for all when
/// no round ends.
#[test]
fn the_probe_s_word_on_each_sensor() {
    let every = Duration::from_secs(60);
    let probe = TelemetryProbe::for_tests(every);
    let words = |p: &TelemetryProbe| -> Vec<ProbeState> {
        p.states().into_iter().map(|(_, s)| s).collect()
    };
    assert_eq!(words(&probe), [ProbeState::Pending; SENSORS]);
    let names: Vec<String> = probe.states().into_iter().map(|(n, _)| n).collect();
    assert_eq!(
        names,
        [
            "exec",
            "file_open",
            "dns",
            "exec_check",
            "tcp_connect",
            "net_listen",
            "net_inbound",
            "tls_hello",
            "io_uring",
            "bpf",
            "fim",
            "deny",
            "module_load",
            "exploit_guard",
            "dns_answer"
        ]
    );
    assert_eq!(probe.rounds(), 0);
    let now = Instant::now();
    {
        let mut st = probe.tracker.lock();
        st.rounds = 1;
        st.word = [Some(ProbeState::Seen); SENSORS];
        st.word[Sensor::Dns as usize] = Some(ProbeState::Gap);
        st.word[Sensor::IoUring as usize] = Some(ProbeState::NotExercised);
        st.last_round = Some(now);
    }
    let w = words(&probe);
    assert_eq!(w[Sensor::Exec as usize], ProbeState::Seen);
    assert_eq!(w[Sensor::Dns as usize], ProbeState::Gap);
    assert_eq!(w[Sensor::IoUring as usize], ProbeState::NotExercised);
    assert_eq!(probe.rounds(), 1);
    // the review of #479, X2: no round ended for two of its longest
    // intervals and the deadline — stale, whatever it said last
    assert_eq!(stale_after(every), Duration::from_secs(149));
    let at = |d: Duration| -> Vec<ProbeState> {
        probe
            .states_at(now + d)
            .into_iter()
            .map(|(_, s)| s)
            .collect()
    };
    assert_eq!(at(stale_after(every))[0], ProbeState::Seen, "at the bound");
    assert_eq!(
        at(stale_after(every) + Duration::from_secs(1)),
        [ProbeState::Stale; SENSORS]
    );
    // a probe whose first round never ends goes stale past its first
    // round's time and the bound
    let never = TelemetryProbe::for_tests(every);
    let first = Duration::from_secs(FIRST_ROUND_SECS);
    let started = never.started;
    assert_eq!(
        never.states_at(started + first + stale_after(every))[0].1,
        ProbeState::Pending
    );
    assert_eq!(
        never.states_at(started + first + stale_after(every) + Duration::from_secs(1))[0].1,
        ProbeState::Stale
    );
}

/// Lot 280c (the brief's first named test): each live sensor's self-test
/// sees its event — the events one round's child makes, as the pipeline
/// decodes them, are each taken by the tap (never judged) and each live
/// sensor is seen; the round ends with every sensor seen, nothing signed.
#[test]
fn each_sensor_s_self_test_sees_its_event() {
    let nonce = &make_nonce().unwrap();
    let probe = probe_with_round(nonce);
    for (sensor, e) in round_events_for_tests(nonce, AGENT, EXE, CHILD, TS, DENY) {
        assert!(probe.observe(&e), "{sensor:?} not taken: {e:?}");
    }
    let live: Vec<Sensor> = Sensor::ALL.into_iter().filter(|s| s.live()).collect();
    assert_eq!(probe.seen_for_tests(), live, "every live sensor, each once");
    let notes = probe.end_round_for_tests(&full_report(), &checks_ok(), Duration::ZERO, None);
    assert!(notes.is_empty(), "{notes:?}");
    assert!(probe.states().iter().all(|(_, w)| *w == ProbeState::Seen));
    // the deny is seen only with both of its refusals
    let probe = probe_with_round(nonce);
    let events = round_events_for_tests(nonce, AGENT, EXE, CHILD, TS, DENY);
    let signal = events
        .iter()
        .find(|(_, e)| {
            matches!(
                e,
                Event::FsProtectDenial {
                    operation: FsProtectOperation::Signal,
                    ..
                }
            )
        })
        .unwrap();
    assert!(probe.observe(&signal.1));
    assert!(
        !probe.seen_for_tests().contains(&Sensor::Deny),
        "half of it"
    );
}

/// Lot 280c: what is taken is the child's own, of its steps' shape, within
/// its lifetime, at most as many as its steps make — anything else is
/// judged as any process's (a process the child's pid named after it, a
/// connect off the host, an event of the deny's kind on another target).
#[test]
fn only_the_child_s_own_events_of_its_steps_are_taken() {
    let nonce = &make_nonce().unwrap();
    let events = round_events_for_tests(nonce, AGENT, EXE, CHILD, TS, DENY);
    let of = |s: Sensor| {
        events
            .iter()
            .find(|(x, _)| *x == Some(s))
            .unwrap()
            .1
            .clone()
    };
    // another pid, the same time
    let other = round_events_for_tests(nonce, AGENT, EXE, CHILD + 1, TS, DENY);
    let probe = probe_with_round(nonce);
    for (s, e) in &other {
        let by_content = matches!(
            s,
            Some(Sensor::Exec) | Some(Sensor::FileOpen) | Some(Sensor::Dns)
        ) || matches!(e, Event::FileOpen { .. } | Event::ExecCheck { .. });
        if !by_content {
            assert!(!probe.observe(e), "another pid's {s:?} taken");
        }
    }
    // outside the child's lifetime: after its reap the pid may be anyone's
    let late = round_events_for_tests(nonce, AGENT, EXE, CHILD, UNTIL + 1, DENY);
    let probe = probe_with_round(nonce);
    for (s, e) in &late {
        if !matches!(
            e,
            Event::ProcessSpawn { .. } | Event::FileOpen { .. } | Event::DnsQuery { .. }
        ) {
            assert!(!probe.observe(e), "an event after the reap taken: {s:?}");
        }
    }
    // a connect off the host, by the child: judged
    let probe = probe_with_round(nonce);
    let mut off = of(Sensor::TcpConnect);
    if let Event::TcpConnect { dst_addr, .. } = &mut off {
        dst_addr[..4].copy_from_slice(&[203, 0, 113, 9]);
    }
    assert!(!probe.observe(&off));
    // a denial on another target: judged
    let mut other_target = of(Sensor::Deny);
    if let Event::FsProtectDenial { target_ino, .. } = &mut other_target {
        *target_ino = 1;
    }
    assert!(!probe.observe(&other_target));
    let mut create = events
        .iter()
        .find(|(_, e)| {
            matches!(
                e,
                Event::FsProtectDenial {
                    operation: FsProtectOperation::Create,
                    ..
                }
            )
        })
        .unwrap()
        .1
        .clone();
    if let Event::FsProtectDenial { target_ino, .. } = &mut create {
        *target_ino += 1;
    }
    assert!(
        !probe.observe(&create),
        "a create refused in another directory"
    );
    // another round's nonce, another parent
    let other = make_nonce().unwrap();
    assert_ne!(other, *nonce);
    let wrong = round_events_for_tests(&other, AGENT + 1, EXE, CHILD, TS, DENY);
    let probe = probe_with_round(nonce);
    for (s, e) in &wrong {
        if matches!(
            e,
            Event::ProcessSpawn { .. } | Event::ExecCheck { .. } | Event::DnsQuery { .. }
        ) {
            assert!(!probe.observe(e), "another round's {s:?} taken");
        }
    }
    // the round's nonce from another parent, the agent's path exec'd by
    // another process: judged
    let probe = probe_with_round(nonce);
    let mut spawn = of(Sensor::Exec);
    if let Event::ProcessSpawn { ppid, .. } = &mut spawn {
        *ppid = AGENT + 1;
    }
    assert!(!probe.observe(&spawn), "the nonce from another parent");
    let mut check = of(Sensor::ExecCheck);
    if let Event::ExecCheck { filename, .. } = &mut check {
        *filename = "/tmp/northnarrow-agent".into();
    }
    assert!(!probe.observe(&check), "another path");
    let mut check = of(Sensor::ExecCheck);
    if let Event::ExecCheck { pid, .. } = &mut check {
        *pid = CHILD + 1;
    }
    assert!(!probe.observe(&check), "another child of the agent");
    let mut bpf = of(Sensor::Bpf);
    if let Event::BpfSyscall { cmd, .. } = &mut bpf {
        *cmd = common::bpf_cmd::BPF_PROG_LOAD;
    }
    assert!(!probe.observe(&bpf), "a program load by the child");
    let mut signal = of(Sensor::Deny);
    if let Event::FsProtectDenial { target_dev, .. } = &mut signal {
        *target_dev = libc::SIGTERM as u64;
    }
    assert!(!probe.observe(&signal), "another signal");
    // at most what the step makes: a second connect is judged
    let probe = probe_with_round(nonce);
    assert!(probe.observe(&of(Sensor::TcpConnect)));
    assert!(!probe.observe(&of(Sensor::TcpConnect)), "one connect only");
    assert!(probe.observe(&of(Sensor::Exec)));
    assert!(!probe.observe(&of(Sensor::Exec)), "one exec only");
    // no round open: nothing taken
    let idle = TelemetryProbe::for_tests(Duration::from_secs(60));
    for (_, e) in &events {
        assert!(!idle.observe(e));
    }
    // a late event of the round just ended: taken, not counted (the round
    // missed everything: its degradations go to the registry, one per
    // process — held for the test)
    let _g = degradation::TEST_LOCK.lock();
    let probe = probe_with_round(nonce);
    probe.end_round_for_tests(&full_report(), &checks_ok(), Duration::ZERO, None);
    assert!(probe.observe(&of(Sensor::Bpf)), "late, still the child's");
    assert_eq!(probe.tracker.lock().late_taken, 1);
    assert!(probe.states()[Sensor::Bpf as usize].1 == ProbeState::Missed);
    degradation::reset_for_tests();
}

/// Lot 280c: a sensor whose source does not run is not exercised — the
/// start's list of the pumps and drains; the file-open word speaks for the
/// LSM sensor or the tracepoint that carries its events.
#[test]
fn a_sensor_whose_source_does_not_run_is_not_exercised() {
    let p = TelemetryProbe::for_tests(Duration::from_secs(60));
    assert!(p.source_runs(Sensor::TlsHello), "not known yet: expected");
    p.set_running(&["process_spawn", "file_open", "tcp_connect"]);
    assert!(p.source_runs(Sensor::Exec));
    assert!(p.source_runs(Sensor::FileOpen), "the tracepoint carries it");
    assert!(!p.source_runs(Sensor::TlsHello));
    assert!(!p.source_runs(Sensor::Deny));
    p.set_running(&["open_sensor"]);
    assert!(p.source_runs(Sensor::FileOpen));
    assert!(!p.source_runs(Sensor::TcpConnect));
}

/// Lot 280c: the drains' tag — a row of the child within its lifetime is
/// the self-test's (not written to the signed logs, counted); the round
/// before stays tagged for its late rows.
#[test]
fn the_drains_skip_the_child_s_rows() {
    let tag = SelfTestTag::default();
    assert!(!tag.is_self_test(CHILD, TS));
    assert!(!tag.is_self_test(0, 0), "no child yet: no pid is one");
    tag.open(Window {
        pid: 0,
        from_ns: FROM,
        until_ns: u64::MAX,
    });
    assert!(!tag.is_self_test(0, TS), "a round before its spawn");
    tag.open(Window {
        pid: CHILD,
        from_ns: FROM,
        until_ns: u64::MAX,
    });
    assert!(tag.is_self_test(CHILD, TS), "while it runs");
    tag.close(UNTIL);
    assert!(tag.skip(CHILD, TS));
    assert!(!tag.skip(CHILD, UNTIL + 1), "after its reap");
    assert!(!tag.skip(CHILD + 1, TS), "another pid");
    assert!(!tag.skip(0, TS), "no pid");
    assert_eq!(tag.skipped(), 1);
    tag.open(Window {
        pid: CHILD + 7,
        from_ns: UNTIL + 10,
        until_ns: UNTIL + 20,
    });
    assert!(tag.is_self_test(CHILD, TS), "the round before");
    assert!(tag.is_self_test(CHILD + 7, UNTIL + 15));
    tag.open(Window::default());
    assert!(!tag.is_self_test(CHILD, TS), "two rounds back");
}

fn open_log(dir: &Path) -> Arc<Mutex<AuditLog>> {
    let key = AgentSigningKey::load_or_bootstrap(&dir.join("agent.sig")).unwrap();
    Arc::new(Mutex::new(
        AuditLog::open(&dir.join("audit.log"), key, [7u8; 16]).unwrap(),
    ))
}

fn rows(dir: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(dir.join("audit.log"))
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .collect()
}

/// Lot 280c (the brief's second named test): a sensor whose events are
/// dropped (its ring's events never reach the tap, as the debug-trigger
/// build's `debug-ring-drop` does) gives the signed degradation in the
/// first round — `sensor_selftest`, the sensor and the step named, the
/// word `missed` —, the alert in the second (`sensor_selftest_alert`, the
/// word `gap`), nothing more in the third; seen again, the degradation is
/// withdrawn and the return signed.
#[test]
fn a_sensor_whose_events_are_dropped_gives_the_signed_degradation_then_the_alert() {
    let _g = degradation::TEST_LOCK.lock();
    degradation::reset_for_tests();
    let dir = tempfile::tempdir().unwrap();
    let log = open_log(dir.path());
    let probe = TelemetryProbe::for_tests(Duration::from_secs(60));
    let word = |p: &TelemetryProbe| {
        p.states()
            .into_iter()
            .find(|(n, _)| n == "tcp_connect")
            .unwrap()
            .1
    };
    let round = |dropped: bool| {
        let nonce = make_nonce().unwrap();
        probe.open_round_for_tests(&nonce, AGENT, EXE, window(), Some(DENY));
        for (s, e) in round_events_for_tests(&nonce, AGENT, EXE, CHILD, TS, DENY) {
            if dropped && s == Some(Sensor::TcpConnect) {
                continue; // the tcp_connect ring's events dropped
            }
            assert!(probe.observe(&e));
        }
        probe.end_round_for_tests(&full_report(), &checks_ok(), Duration::ZERO, Some(&log))
    };
    // round 1: the signed degradation
    let notes = round(true);
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(matches!(
        &notes[0],
        Note::Degraded {
            sensor: Sensor::TcpConnect,
            ..
        }
    ));
    assert_eq!(word(&probe), ProbeState::Missed);
    let degraded: Vec<serde_json::Value> = rows(dir.path())
        .into_iter()
        .filter(|r| r["extra"]["kind"] == "subsystem_degraded")
        .collect();
    assert_eq!(degraded.len(), 1);
    let extra = &degraded[0]["extra"];
    assert_eq!(extra["source"], DEGRADATION_SOURCE);
    let detail = extra["detail"].as_str().unwrap();
    assert!(
        detail.starts_with("tcp_connect (tcp_connect): self-test step `a connect to the child's loopback listener` missed"),
        "{detail}"
    );
    assert!(degradation::snapshot()
        .iter()
        .any(|l| l.starts_with("sensor_selftest: tcp_connect")));
    // round 2: the alert
    let notes = round(true);
    assert!(
        matches!(
            &notes[..],
            [Note::Alert {
                sensor: Sensor::TcpConnect,
                ..
            }]
        ),
        "{notes:?}"
    );
    assert_eq!(word(&probe), ProbeState::Gap);
    let alerts: Vec<serde_json::Value> = rows(dir.path())
        .into_iter()
        .filter(|r| r["op"] == AUDIT_OP_ALERT)
        .collect();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0]["extra"]["sensor"], "tcp_connect");
    assert_eq!(alerts[0]["extra"]["rounds_missed"], 2);
    assert_eq!(alerts[0]["result"], "detected");
    // round 3: still silent, nothing new signed
    let before = rows(dir.path()).len();
    let notes = round(true);
    assert!(
        matches!(&notes[..], [Note::StillSilent { rounds: 3, .. }]),
        "{notes:?}"
    );
    assert_eq!(rows(dir.path()).len(), before);
    // round 4: seen again — the return signed, the degradation withdrawn
    let notes = round(false);
    assert!(
        matches!(
            &notes[..],
            [Note::Restored {
                sensor: Sensor::TcpConnect,
                rounds: 3
            }]
        ),
        "{notes:?}"
    );
    assert_eq!(word(&probe), ProbeState::Seen);
    assert!(rows(dir.path())
        .iter()
        .any(|r| r["op"] == AUDIT_OP_RESTORED && r["extra"]["rounds_missed"] == 3));
    assert!(
        !degradation::snapshot()
            .iter()
            .any(|l| l.starts_with("sensor_selftest")),
        "{:?}",
        degradation::snapshot()
    );
    degradation::reset_for_tests();
}

/// Lot 280c: a step that could not run says nothing of its sensor (not
/// exercised: a window open for the deny, io_uring off, a source that does
/// not run); a deny step not refused is a miss by itself; an attach check's
/// verdict is its sensor's; the round's cost over its budget is signed
/// until a round is back under it.
#[test]
fn a_step_that_cannot_run_is_not_exercised_and_a_deny_let_through_is_missed() {
    let all_seen = [true; SENSORS];
    let runs = |_: Sensor| true;
    let o = outcomes(&all_seen, &full_report(), false, &checks_ok(), &runs);
    assert!(o.iter().all(|x| *x == Outcome::Seen), "{o:?}");
    // a window open: the deny is not exercised
    let o = outcomes(&all_seen, &full_report(), true, &checks_ok(), &runs);
    assert!(matches!(&o[Sensor::Deny as usize], Outcome::NotExercised(w) if w.contains("window")));
    // io_uring switched off
    let r = ChildReport::parse("file=ok\ndns=ok\ntcp=ok\nio_uring=skipped: errno 1 (EPERM)\nbpf=ok\nfim=ok\ndeny_signal=refused\ndeny_create=refused\n");
    let o = outcomes(&all_seen, &r, false, &checks_ok(), &runs);
    assert!(
        matches!(&o[Sensor::IoUring as usize], Outcome::NotExercised(w) if w.contains("errno 1"))
    );
    // each step that could not be made: its sensor (or sensors) not exercised
    for (key, sensors) in [
        ("file", &[Sensor::FileOpen][..]),
        ("dns", &[Sensor::Dns]),
        (
            "tcp",
            &[
                Sensor::TcpConnect,
                Sensor::NetListen,
                Sensor::NetInbound,
                Sensor::TlsHello,
            ],
        ),
        ("bpf", &[Sensor::Bpf]),
        ("fim", &[Sensor::Fim]),
        ("deny_signal", &[Sensor::Deny]),
        ("deny_create", &[Sensor::Deny]),
    ] {
        let text =
            full_report_text().replace(&format!("{key}=ok"), &format!("{key}=skipped: errno 30"));
        let text = text.replace(
            &format!("{key}=refused"),
            &format!("{key}=skipped: errno 30"),
        );
        let o = outcomes(
            &all_seen,
            &ChildReport::parse(&text),
            false,
            &checks_ok(),
            &runs,
        );
        for s in Sensor::ALL {
            assert_eq!(
                matches!(&o[s as usize], Outcome::NotExercised(w) if w.contains("errno 30")),
                sensors.contains(&s),
                "{key}: {s:?}"
            );
        }
    }
    // a deny step let through: missed, whatever was seen
    let r = ChildReport::parse(
        "file=ok\ndns=ok\ntcp=ok\nio_uring=ok\nbpf=ok\nfim=ok\ndeny_signal=refused\ndeny_create=done\n",
    );
    let o = outcomes(&all_seen, &r, false, &checks_ok(), &runs);
    assert!(
        matches!(&o[Sensor::Deny as usize], Outcome::Missed(w) if w.contains("deny_create step was not refused"))
    );
    // a step the child did not report (it died): not exercised
    let o = outcomes(
        &all_seen,
        &ChildReport::default(),
        false,
        &checks_ok(),
        &runs,
    );
    for s in [
        Sensor::TcpConnect,
        Sensor::FileOpen,
        Sensor::Dns,
        Sensor::Deny,
    ] {
        assert!(matches!(&o[s as usize], Outcome::NotExercised(_)), "{s:?}");
    }
    assert_eq!(o[Sensor::Exec as usize], Outcome::Seen, "its exec was seen");
    // a source that does not run on this host
    let o = outcomes(&all_seen, &full_report(), false, &checks_ok(), &|s| {
        s != Sensor::TlsHello
    });
    assert!(
        matches!(&o[Sensor::TlsHello as usize], Outcome::NotExercised(w) if w.contains("tls_hello"))
    );
    // nothing seen: every live step that ran is missed
    let o = outcomes(
        &[false; SENSORS],
        &full_report(),
        false,
        &checks_ok(),
        &runs,
    );
    for s in Sensor::ALL {
        assert_eq!(
            matches!(o[s as usize], Outcome::Missed(_)),
            s.live(),
            "{s:?}"
        );
    }
    // an attach check's verdict
    let mut checks = checks_ok();
    checks[0].1 = Outcome::Missed("detached".into());
    let o = outcomes(&all_seen, &full_report(), false, &checks, &runs);
    assert_eq!(
        o[Sensor::ModuleLoad as usize],
        Outcome::Missed("detached".into())
    );
    // the cost: over its budget once signed, back under withdrawn
    let mut st = State::default();
    let seen: [Outcome; SENSORS] = std::array::from_fn(|_| Outcome::Seen);
    let notes = apply(&mut st, &seen, ROUND_CPU_BUDGET + Duration::from_millis(1));
    assert!(matches!(&notes[..], [Note::OverBudget { .. }]), "{notes:?}");
    assert!(
        apply(&mut st, &seen, ROUND_CPU_BUDGET * 2).is_empty(),
        "once"
    );
    assert_eq!(open_details(&st).len(), 1);
    assert_eq!(
        apply(&mut st, &seen, ROUND_CPU_BUDGET),
        [Note::BackUnderBudget]
    );
    assert!(open_details(&st).is_empty());
    // one round missed, then seen: the return signed, the degradation's
    // detail no longer open
    let mut st = State::default();
    let mut once: [Outcome; SENSORS] = std::array::from_fn(|_| Outcome::Seen);
    once[Sensor::Fim as usize] = Outcome::Missed("x".into());
    assert!(matches!(
        &apply(&mut st, &once, Duration::ZERO)[..],
        [Note::Degraded {
            sensor: Sensor::Fim,
            ..
        }]
    ));
    assert_eq!(open_details(&st).len(), 1);
    assert_eq!(
        apply(&mut st, &seen, Duration::ZERO),
        [Note::Restored {
            sensor: Sensor::Fim,
            rounds: 1
        }]
    );
    assert!(open_details(&st).is_empty());
    assert_eq!(st.word[Sensor::Fim as usize], Some(ProbeState::Seen));
    // a step not exercised after a miss keeps the miss open
    let mut st = State::default();
    let mut miss: [Outcome; SENSORS] = std::array::from_fn(|_| Outcome::Seen);
    miss[Sensor::Bpf as usize] = Outcome::Missed("x".into());
    apply(&mut st, &miss, Duration::ZERO);
    miss[Sensor::Bpf as usize] = Outcome::NotExercised("y".into());
    let notes = apply(&mut st, &miss, Duration::ZERO);
    assert!(matches!(
        &notes[..],
        [Note::NotExercised {
            sensor: Sensor::Bpf,
            ..
        }]
    ));
    assert_eq!(st.word[Sensor::Bpf as usize], Some(ProbeState::Missed));
    assert_eq!(open_details(&st).len(), 1);
}

/// Lot 300: since lot 285 the module_load attach check found
/// `module_write_observe` "detached" in every round, on every host (an
/// alert at the second round; seen on 5.15 and 6.12): the check reads the
/// links the agent holds and the `link_*` pins of the pin root
/// (`bpf_defense::live_links`), and the write history's link was pinned in
/// its own directory beside the root and dropped. The programs the check
/// names are the module-load programs the agent attaches, both ways; each
/// is linked where the check reads — a `link_<hook>` pin in the root, or,
/// pinned in a directory of its own, a link the agent holds.
#[test]
fn the_module_load_check_reads_each_of_its_programs_where_it_is_linked() {
    use crate::anti_tamper::bpf_defense::LINK_PIN_PREFIX;
    use crate::anti_tamper::filesystem::{MODULE_LOAD_PROGRAMS, MODULE_WRITE_PROGRAM};
    let root = Path::new("/sys/fs/bpf/northnarrow");
    let mut attached: Vec<&str> = MODULE_LOAD_PROGRAMS
        .iter()
        .map(|(p, _)| *p)
        .chain([MODULE_WRITE_PROGRAM.0])
        .collect();
    let mut named = Sensor::ModuleLoad.programs().to_vec();
    attached.sort_unstable();
    named.sort_unstable();
    assert_eq!(
        named, attached,
        "the module_load attach check and the module-load programs the agent attaches differ"
    );
    // the two load hooks: `link_<hook>` in the root, which the check walks
    for (program, hook) in MODULE_LOAD_PROGRAMS {
        let link = antitamper_bpf::lsm_pin_paths(root, hook).1;
        assert_eq!(link.parent(), Some(root), "{program}");
        let name = link.file_name().and_then(|n| n.to_str()).unwrap_or("");
        assert!(name.starts_with(LINK_PIN_PREFIX), "{program}: {name}");
    }
    // the write history's: beside the root — the agent holds it (the
    // pinned link handed back, kept open), and since lot 301 the check
    // walks that directory too (every pin directory beside the root)
    let link = crate::module_writes::link_pin(&crate::module_writes::pin_dir(root));
    assert_ne!(link.parent(), Some(root));
    let mw = include_str!(concat!(
        env!("NN_REPO_ROOT"),
        "/crates/nn-linux/src/module_writes.rs"
    ));
    let mw = &mw[..mw.find("#[cfg(test)]").expect("module_writes' tests")];
    let at = mw
        .find("reattach_fresh_held(ebpf, PROGRAM, HOOK, btf, Some(&dir))")
        .expect("the write history's link is attached and handed back");
    let held = &mw[at..at + 200];
    assert!(held.contains("LINK.set(FdLink::from(link))"), "{held}");
    assert!(
        !mw.contains("reattach_fresh(ebpf, PROGRAM"),
        "a link dropped once pinned"
    );
    // and the check's view takes what the agent holds, and (lot 301) every
    // link pinned in the pin directories, the write history's among them
    let bd = include_str!(concat!(
        env!("NN_REPO_ROOT"),
        "/crates/nn-linux/src/anti_tamper/bpf_defense.rs"
    ));
    let at = bd.find("fn live_links(").expect("live_links");
    let view = &bd[at..at + 700];
    assert!(view.contains("held_objects()"), "{view}");
    assert!(view.contains("pinned_objects(root)"), "{view}");
    let at = bd.find("fn held_objects(").expect("held_objects");
    assert!(bd[at..at + 400].contains("read_dir(\"/proc/self/fd\")"));
}

/// Lot 280c: the attach checks — each loaded program of the sensor has a
/// live link; none loaded is not exercised; and the module count: more
/// modules new in the kernel's list than loads reported is a miss.
#[test]
fn the_attach_checks_and_the_module_count() {
    let own = "# northnarrow-agent pid 1: loaded BPF programs (id name [kept])\n\
               10 module_read_file_observe\n11 module_load_data_observe\n\
               20 epg_lite_capable\n21 epg_lite_commit_creds\n30 dns_answer_v4_ret6\n40 task_kill_deny\n";
    let live: HashSet<u32> = [10, 11, 20, 21, 30].into_iter().collect();
    for s in [Sensor::ModuleLoad, Sensor::ExploitGuard, Sensor::DnsAnswer] {
        assert_eq!(attach_check(s, own, &live), Outcome::Seen, "{s:?}");
    }
    let mut detached = live.clone();
    detached.remove(&21);
    assert!(matches!(
        attach_check(Sensor::ExploitGuard, own, &detached),
        Outcome::Missed(w) if w.contains("epg_lite_commit_creds (id 21)")
    ));
    assert_eq!(
        attach_check(Sensor::ModuleLoad, own, &detached),
        Outcome::Seen
    );
    assert!(matches!(
        attach_check(Sensor::DnsAnswer, "40 task_kill_deny\n", &live),
        Outcome::NotExercised(_)
    ));
    let before = module_names("ext4 1 0 - Live 0x0\nvfat 2 0 - Live 0x0\n");
    let now = module_names("ext4 1 0 - Live 0x0\nnn_test 2 0 - Live 0x0\nzram 3 0 - Live 0x0\n");
    assert_eq!(module_count_check(&before, &now, 2), None);
    let why = module_count_check(&before, &now, 1).unwrap();
    assert!(why.starts_with("2 module(s) new in /proc/modules"), "{why}");
    assert!(
        why.contains("nn_test, zram") && why.contains("1 load(s)"),
        "{why}"
    );
    let after = module_names("ext4 1 0 - Live 0x0\n");
    assert_eq!(
        module_count_check(&now, &after, 0),
        None,
        "modules that left"
    );
}

/// Lot 280c: the TCP steps on loopback (no privilege needed), and the
/// ClientHello's shape the tls_hello sensor reads.
#[test]
fn the_tcp_steps_run_on_loopback_and_the_hello_has_the_sensor_s_shape() {
    let nonce = make_nonce().unwrap();
    assert_eq!(tcp_steps(&nonce), "ok");
    let h = client_hello(&dns_name(&nonce));
    assert_eq!(&h[..3], &[0x16, 0x03, 0x01], "a handshake record");
    assert_eq!(h[5], 0x01, "a ClientHello");
    assert_eq!(u16::from_be_bytes([h[3], h[4]]) as usize, h.len() - 5);
    let hs_len = u32::from_be_bytes([0, h[6], h[7], h[8]]) as usize;
    assert_eq!(hs_len, h.len() - 9);
    let name = dns_name(&nonce);
    assert!(
        h.windows(name.len()).any(|w| w == name.as_bytes()),
        "the SNI"
    );
    assert!(loopback_raw(
        2,
        &[127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    ));
    let mut v6 = [0u8; 16];
    v6[15] = 1;
    assert!(loopback_raw(10, &v6));
    let mut mapped = [0u8; 16];
    mapped[10] = 0xff;
    mapped[11] = 0xff;
    mapped[12] = 127;
    assert!(loopback_raw(10, &mapped));
    assert!(!loopback_raw(
        2,
        &[10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    ));
    assert!(!loopback_raw(10, &[0u8; 16]));
}

#[test]
fn probe_name_stays_below_the_dns_tunnel_rule() {
    let n = make_nonce().unwrap();
    assert!(n.len() <= 16, "{n}");
    let name = dns_name(&n);
    assert!(
        name.split('.').next().unwrap().len() < 20,
        "below NN-L-NET-014's label length"
    );
    assert!(name.len() <= 60, "NN-L-NET-004 length");
}

/// External audit EVD-015 (NN-AUD-278): the nonce is random — no pid,
/// no clock in a name a resolver may see.
#[test]
fn nonce_is_random_not_pid_or_clock() {
    let a = make_nonce().unwrap();
    let b = make_nonce().unwrap();
    assert_ne!(a, b);
    for n in [&a, &b] {
        assert_eq!(n.len(), 2 * NONCE_BYTES, "{n}");
        assert!(n
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }
    // 64 random bits: two nonces sharing the pid's hex tail is a
    // 1-in-2^24 accident at most, a clock-and-pid nonce always does it
    let pid = format!("{:x}", std::process::id() & 0xFF_FFFF);
    assert!(
        !(a.ends_with(&pid) && b.ends_with(&pid)),
        "nonce carries the pid: {a} {b}"
    );
}

#[test]
fn dns_packet_is_well_formed() {
    let p = dns_probe_packet("ab.probe.northnarrow.invalid");
    assert_eq!(&p[..12], &[0x4e, 0x4e, 0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    assert_eq!(p[12], 2);
    assert_eq!(&p[13..15], b"ab");
    assert_eq!(p[15], 5);
    assert_eq!(&p[p.len() - 5..], &[0, 0, 1, 0, 1]);
}

/// External audit EVD-015 (NN-AUD-278): a name server must discard the
/// probe, not answer or forward it — a response (`QR`), no recursion
/// asked (`RD` clear), no answer records.
#[test]
fn probe_packet_is_a_response_no_resolver_forwards() {
    let p = dns_probe_packet(&dns_name(&make_nonce().unwrap()));
    assert_eq!(p[2] & DNS_FLAG_QR, DNS_FLAG_QR, "QR set");
    assert_eq!(p[2] & DNS_FLAG_RD, 0, "RD clear");
    assert_eq!(p[2] & 0x78, 0, "opcode QUERY");
    assert_eq!(
        &p[4..12],
        &[0, 1, 0, 0, 0, 0, 0, 0],
        "one question, no records"
    );
}

/// External audit EVD-015 (NN-AUD-278): the datagram goes from loopback
/// to loopback port 53 and carries the probed name after the header,
/// where the sensors read it.
#[test]
fn probe_datagram_stays_on_loopback_and_carries_the_name() {
    assert!(PROBE_DNS_DEST.ip().is_loopback());
    assert_eq!(PROBE_DNS_DEST.port(), 53, "the sensors' filter");
    assert!(PROBE_DNS_SOURCE.ip().is_loopback());
    let listener = UdpSocket::bind("127.0.0.1:0").unwrap();
    listener
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let nonce = make_nonce().unwrap();
    let name = dns_name(&nonce);
    let sent = send_dns_probe(&name, listener.local_addr().unwrap()).unwrap();
    let mut buf = [0u8; 512];
    let (n, from) = listener.recv_from(&mut buf).unwrap();
    assert_eq!(n, sent);
    assert!(from.ip().is_loopback(), "{from}");
    assert_eq!(&buf[..n], &dns_probe_packet(&name)[..]);
    assert_eq!(buf[2] & DNS_FLAG_QR, DNS_FLAG_QR);
    assert_eq!(&buf[13..29], nonce.as_bytes());
}

#[test]
fn interval_env_zero_disables() {
    std::env::set_var(INTERVAL_ENV, "0");
    assert!(interval_from_env().is_none());
    std::env::set_var(INTERVAL_ENV, "3");
    assert_eq!(
        interval_from_env(),
        Some(Duration::from_secs(DEADLINE_SECS + 1))
    );
    std::env::remove_var(INTERVAL_ENV);
    assert_eq!(
        interval_from_env(),
        Some(Duration::from_secs(DEFAULT_INTERVAL_SECS))
    );
}

/// Lot 280c: every source of the contract has the self-test's word, a
/// sensor's own; the attach checks are the three sources no live event
/// exercises.
#[test]
fn every_source_of_the_contract_has_a_self_test_word() {
    use crate::sensors::contract::SOURCES;
    for c in &SOURCES {
        let word = c.probe.unwrap_or_else(|| panic!("{}: no word", c.source));
        let s = Sensor::ALL
            .into_iter()
            .find(|s| s.name() == word)
            .unwrap_or_else(|| panic!("{}: {word} is no sensor's", c.source));
        assert_eq!(c.attach_check, !s.live(), "{}", c.source);
        assert!(
            s.source() == c.source || c.standby_for == Some(s.source()),
            "{}: {word} speaks for {}",
            c.source,
            s.source()
        );
    }
    for s in Sensor::ALL {
        assert!(
            SOURCES.iter().any(|c| c.probe == Some(s.name())),
            "{s:?} has no source"
        );
        assert_eq!(s.live(), s.programs().is_empty(), "{s:?}");
    }
}
