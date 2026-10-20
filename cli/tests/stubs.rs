//! External audit WDG-016 (NN-AUD-365): the `northnarrow` stubs printed
//! "Not implemented yet" on stdout and exited 0, so a caller took the
//! command for done. Each one must fail (69, `EX_UNAVAILABLE`), print
//! nothing on stdout, and say on stderr that nothing was done.

use std::process::Command;

#[test]
fn every_stub_fails_and_says_so() {
    for name in ["status", "alerts", "isolate", "recover"] {
        let out = Command::new(env!("CARGO_BIN_EXE_northnarrow"))
            .arg(name)
            .output()
            .expect("run northnarrow");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(69), "{name}: {stderr}");
        assert!(out.stdout.is_empty(), "{name}: stdout {:?}", out.stdout);
        assert!(
            stderr.contains(name) && stderr.contains("not implemented"),
            "{name}: {stderr}"
        );
        assert!(stderr.contains("nn-admin"), "{name}: {stderr}");
    }
}
