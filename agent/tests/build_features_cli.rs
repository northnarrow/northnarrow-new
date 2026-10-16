//! External audit NN-AUD-211: `northnarrow-agent --build-features` is the
//! positive marker the range bootstrap (`deploy/adversarial/
//! bootstrap-target-prod.sh`) checks before it installs a binary. It must
//! name exactly the test and debug features this build carries, and print
//! `none` for a release build. Runs unprivileged: the flag exits before
//! any eBPF or root work.

use std::process::Command;

fn expected() -> String {
    let mut features = Vec::new();
    if cfg!(feature = "debug-trigger") {
        features.push("debug-trigger");
    }
    if cfg!(feature = "demo-tappa5") {
        features.push("demo-tappa5");
    }
    if cfg!(feature = "test-privileged") {
        features.push("test-privileged");
    }
    if features.is_empty() {
        "none".to_string()
    } else {
        features.join(",")
    }
}

#[test]
fn build_features_flag_names_the_compiled_lab_features() {
    let out = Command::new(env!("CARGO_BIN_EXE_northnarrow-agent"))
        .arg("--build-features")
        .output()
        .expect("run northnarrow-agent --build-features");
    assert!(out.status.success(), "exit status {:?}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    // One line, nothing else: the bootstrap compares it verbatim.
    assert_eq!(stdout, format!("{}\n", expected()));
}
