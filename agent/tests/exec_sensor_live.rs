//! Live integration test for the exec sensor.
//!
//! This test loads the real eBPF program, attaches it to the kernel
//! tracepoint, then spawns `/bin/echo test` and asserts that within
//! 1s an event arrives whose `comm` is `"echo"`. It needs:
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

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires root and a Linux kernel with eBPF"]
async fn echo_is_observed_within_one_second() {
    let mut sensor = ExecSensor::start()
        .await
        .expect("ExecSensor::start (need root + built eBPF artifact)");

    // Spawn the canary AFTER the sensor is attached so we know the
    // event is captured live, not from before the test.
    let mut child = std::process::Command::new("/bin/echo")
        .arg("northnarrow-canary")
        .spawn()
        .expect("spawn /bin/echo");
    let _ = child.wait();

    let saw_echo = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let evt = sensor.next_event().await.expect("sensor closed");
            if let Event::ProcessSpawn { comm, .. } = &evt {
                if comm == "echo" {
                    return true;
                }
            }
        }
    })
    .await;

    assert!(
        matches!(saw_echo, Ok(true)),
        "did not observe an `echo` exec within 1s"
    );
}
