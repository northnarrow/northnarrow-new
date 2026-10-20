//! Live integration test for the exec sensor.
//!
//! This test loads the real eBPF program, attaches it to the
//! `sched/sched_process_exec` tracepoint (`ExecSensor`, with this kernel's
//! BTF offsets armed, lab PR 187), then spawns `/bin/echo
//! northnarrow-canary` and asserts that within 3 s an event arrives for
//! THAT exec: its pid, its parent (this test process) and the canary
//! argument. It needs:
//!
//! - the eBPF artifact present in `agent-ebpf/target/.../release/`
//!   (run `cargo xtask build-ebpf` first), and
//! - root or `CAP_BPF` + `CAP_PERFMON` capabilities.
//!
//! It is `#[ignore]` by default so `cargo test --workspace` stays
//! green in CI/IDE without privileges. Run it manually:
//!
//! ```sh
//! cargo xtask build-ebpf
//! sudo -E env "PATH=$PATH" \
//!   cargo test -p northnarrow-agent --test exec_sensor_live -- \
//!   --ignored --nocapture
//! ```

use std::time::Duration;

use common::Event;
use northnarrow_agent::sensors::ExecSensor;

/// The argument the canary exec carries.
const CANARY_ARG: &str = "northnarrow-canary";

/// External audit NN-AUD-422 (TST-016): the test matched `comm == "echo"`
/// alone, so any `echo` on the host passed it, the canary's own exec or
/// not. The record must be the canary's: its pid, this process as its
/// parent (`real_parent->tgid`, read through the BTF offsets) and the
/// canary argument in its argv; every `echo` seen is listed on failure.
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires root and a Linux kernel with eBPF"]
async fn the_canary_exec_is_observed_with_its_pid_parent_and_argv() {
    let mut sensor = ExecSensor::start()
        .await
        .expect("ExecSensor::start (need root + built eBPF artifact)");

    // Spawn the canary AFTER the sensor is attached so we know the
    // event is captured live, not from before the test.
    let mut child = std::process::Command::new("/bin/echo")
        .arg(CANARY_ARG)
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("spawn /bin/echo");
    let pid = child.id();
    let me = std::process::id();
    let _ = child.wait();

    // Every `echo` exec seen, for the failure message.
    let mut seen: Vec<String> = Vec::new();
    let found = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let evt = sensor.next_event().await.expect("sensor closed");
            let Event::ProcessSpawn {
                pid: p,
                ppid,
                comm,
                argv,
                ..
            } = &evt
            else {
                continue;
            };
            if comm == "echo" {
                seen.push(format!("pid={p} ppid={ppid} argv={argv:?}"));
            }
            if *p == pid && *ppid == me && argv.iter().any(|a| a == CANARY_ARG) {
                return;
            }
        }
    })
    .await;

    assert!(
        found.is_ok(),
        "no exec record for the canary (pid {pid}, ppid {me}, argv with {CANARY_ARG:?}) \
         within 3s; `echo` execs seen: {seen:#?}"
    );
}

/// External audit EBPF-021: the kernel marks what it cuts. `/bin/true`
/// run with 2.5 KiB of filler arguments before a last one: the record's
/// argv is cut at 511 bytes, the last argument is not in it, and
/// `argv_truncated` says so. The same program with one short argument is
/// whole. A caller's path longer than 256 bytes (`/bin/` and a run of
/// `./`) is cut too, and `filename_truncated` says so.
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires root and a Linux kernel with eBPF"]
async fn long_argv_and_filename_are_marked_cut() {
    let mut sensor = ExecSensor::start()
        .await
        .expect("ExecSensor::start (need root + built eBPF artifact)");

    let filler: Vec<&str> = std::iter::repeat_n("--padding", 256).collect();
    let run = |prog: &str, args: &[&str]| {
        let _ = std::process::Command::new(prog)
            .args(args)
            .spawn()
            .expect("spawn")
            .wait();
    };
    let mut padded: Vec<&str> = filler.clone();
    padded.push("nn-kernfid-tail");
    run("/bin/true", &padded);
    run("/bin/true", &["nn-kernfid-short"]);
    let long_path = format!("/bin/{}true", "./".repeat(140));
    run(&long_path, &["nn-kernfid-path"]);

    let mut cut_argv = None;
    let mut short = None;
    let mut cut_path = None;
    // Every `true` exec seen, for the failure message.
    let mut seen: Vec<String> = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), async {
        while cut_argv.is_none() || short.is_none() || cut_path.is_none() {
            let evt = sensor.next_event().await.expect("sensor closed");
            let Event::ProcessSpawn {
                comm,
                argv,
                filename,
                argv_truncated,
                filename_truncated,
                ..
            } = evt
            else {
                continue;
            };
            if comm != "true" {
                continue;
            }
            seen.push(format!(
                "argc={} argv1={:?} last={:?} argv_cut={} file={:?} file_cut={}",
                argv.len(),
                argv.get(1),
                argv.last(),
                argv_truncated,
                filename,
                filename_truncated
            ));
            if argv.get(1).map(String::as_str) == Some("--padding") {
                cut_argv = Some((argv, argv_truncated));
            } else if argv.iter().any(|a| a == "nn-kernfid-short") {
                short = Some(argv_truncated);
            } else if argv.iter().any(|a| a == "nn-kernfid-path") {
                cut_path = Some((filename, filename_truncated, argv_truncated));
            }
        }
    })
    .await;

    let (argv, truncated) = cut_argv
        .unwrap_or_else(|| panic!("the padded exec was observed; `true` execs seen: {seen:#?}"));
    assert!(truncated, "argv_truncated for a 2.5 KiB command line");
    assert!(
        !argv.iter().any(|a| a == "nn-kernfid-tail"),
        "the last argument is past the cut: {argv:?}"
    );
    assert_eq!(short, Some(false), "a short command line is whole");
    let (filename, f_cut, a_cut) = cut_path
        .unwrap_or_else(|| panic!("the long-path exec was observed; `true` execs seen: {seen:#?}"));
    assert!(
        f_cut,
        "filename_truncated for a {}-byte path",
        long_path.len()
    );
    assert!(
        filename.len() <= 256 && long_path.starts_with(&filename),
        "{filename}"
    );
    assert!(!a_cut, "its argv fits");
}
