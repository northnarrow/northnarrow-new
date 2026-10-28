//! The network isolator with the agent's signed-overlay gate (external
//! audit ATP-001 / DEP-003, NN-AUD-095). Wave 4 restructure, R09a (lab PR
//! 253): cut verbatim from the isolator's tests, which leave for nn-linux
//! with it (`anti_tamper::network_isolate`); these build the agent's gate
//! (`OverlayGate`, `overlay_floor::RollbackFloor`), which stays here. Their
//! fixtures are copies of the isolator's.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use crate::anti_tamper::network_isolate::{
    validate_ruleset, NetworkIsolator, BUILTIN_ALLOW, BUILTIN_RULES_V4, BUILTIN_RULES_V6,
};

/// Absolute path to `configs/combat-rules.v4` in the repo. Tests
/// run with `CARGO_MANIFEST_DIR` set to the agent crate root.
fn combat_rules_path() -> PathBuf {
    PathBuf::from(env!("NN_REPO_ROOT"))
        .join("configs")
        .join("combat-rules.v4")
}

/// Convenience: build a NetworkIsolator with `/usr/bin/cat` for
/// the restore side and `/bin/true` for the iptables side — the
/// "success path" mock used by most tests.
/// A mock `iptables-restore`: a tiny script that drains stdin to EOF
/// and exits 0, IGNORING its args — so it tolerates the `--noflush`
/// flag (BUG-041) that `cat` rejects as an unknown option, while
/// still avoiding the EPIPE a non-reading mock (`/bin/true`) hits.
fn mock_restore_bin() -> Option<PathBuf> {
    mock_script("#!/bin/sh\ncat >/dev/null 2>&1\nexit 0\n")
}

/// A mock binary running the shell `body` (see [`mock_restore_bin`]).
fn mock_script(body: &str) -> Option<PathBuf> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU32, Ordering};
    // UNIQUE per call: tests run in parallel; a shared path would let
    // one test's File::create (truncate) collide with another test
    // exec'ing it (ETXTBSY / a truncated script → EPIPE on the write).
    static N: AtomicU32 = AtomicU32::new(0);
    let path = std::env::temp_dir().join(format!(
        "nn-test-mock-restore-{}-{}.sh",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let mut f = std::fs::File::create(&path).ok()?;
    f.write_all(body.as_bytes()).ok()?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).ok()?;
    drop(f);
    // ETXTBSY guard: the test harness runs tests on parallel threads.
    // If ANOTHER thread fork()s (Command::spawn) while our write fd
    // above is still open, the child inherits that fd until it
    // exec()s — and the kernel refuses to exec a file that anyone
    // holds open for writing ("Text file busy"). Probe-exec the
    // (harmless) script until that transient window has closed so
    // the real test spawn never trips over it.
    for _ in 0..200 {
        match Command::new(&path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        {
            Ok(_) => break,
            Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Err(_) => return None,
        }
    }
    Some(path)
}

/// External audit ATP-001 / DEP-003: with the overlay gate, a ruleset
/// rewritten to isolate nothing and a carve-out adding a network,
/// neither signed, are not applied — the built-in content is; the
/// shipped content is applied as it is; a deleted ruleset no longer
/// fails the engage.
#[test]
fn unsigned_combat_files_give_way_to_the_builtin_content() {
    let Some(restore) = mock_restore_bin() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let admin_pub = dir.path().join("admin.pub");
    std::fs::write(&admin_pub, format!("{} config-manage\n", "00".repeat(32))).unwrap();
    let gate = std::sync::Arc::new(crate::config::overlay_auth::OverlayGate::new(
        &admin_pub,
        [1; 16],
        crate::config::overlay_floor::RollbackFloor::default(),
    ));
    let v4 = dir.path().join("combat-rules.v4");
    let allow = dir.path().join("combat-allow.cidrs");
    std::fs::write(
        &v4,
        "*filter\n:NORTHNARROW_COMBAT - [0:0]\n-A NORTHNARROW_COMBAT -j ACCEPT\nCOMMIT\n",
    )
    .unwrap();
    std::fs::write(&allow, "203.0.113.0/24\n").unwrap();
    let iso = NetworkIsolator::new_with_bin(v4.clone(), restore, PathBuf::from("/bin/true"))
        .unwrap()
        .with_allow_cidrs_path(allow.clone())
        .with_overlay_gate(gate);
    let (ruleset, carved) = iso.build_engaged_ruleset().expect("build");
    assert!(
        ruleset.contains("-A NORTHNARROW_COMBAT -j DROP"),
        "{ruleset}"
    );
    assert!(
        !ruleset.contains("-A NORTHNARROW_COMBAT -j ACCEPT\n"),
        "{ruleset}"
    );
    assert!(
        carved.is_empty(),
        "an unsigned carve-out spares nothing: {carved:?}"
    );
    // the shipped content is applied as it is
    std::fs::write(&v4, BUILTIN_RULES_V4).unwrap();
    std::fs::write(&allow, BUILTIN_ALLOW).unwrap();
    let (ruleset, _) = iso.build_engaged_ruleset().expect("build");
    assert!(ruleset.contains("-A NORTHNARROW_COMBAT -j DROP"));
    // deleted: the built-in ruleset, not a failed engage
    std::fs::remove_file(&v4).unwrap();
    let (ruleset, _) = iso.build_engaged_ruleset().expect("built-in when deleted");
    assert!(ruleset.contains("-A NORTHNARROW_COMBAT -j DROP"));
    assert!(validate_ruleset(BUILTIN_RULES_V4).is_ok());
    assert!(validate_ruleset(BUILTIN_RULES_V6).is_ok());
    assert!(validate_ruleset("*filter\n:NORTHNARROW_COMBAT - [0:0]\nCOMMIT\n").is_err());
}

/// External audit NN-AUD-095: with a gate, a carve-out file that is
/// missing is answered by the gate (the built-in, empty list), not by
/// the ungated loader — whose read would apply a file created after
/// the old `exists()` check without a signature. The ungated loader's
/// mark is its `read_error` for the missing file.
#[test]
fn missing_allow_file_is_never_read_ungated() {
    let dir = tempfile::tempdir().unwrap();
    let admin_pub = dir.path().join("admin.pub");
    std::fs::write(&admin_pub, format!("{} config-manage\n", "00".repeat(32))).unwrap();
    let gate = std::sync::Arc::new(crate::config::overlay_auth::OverlayGate::new(
        &admin_pub,
        [1; 16],
        crate::config::overlay_floor::RollbackFloor::default(),
    ));
    let allow = dir.path().join("combat-allow.cidrs");
    let ungated = NetworkIsolator::new_with_bin(
        combat_rules_path(),
        PathBuf::from("/usr/bin/cat"),
        PathBuf::from("/bin/true"),
    )
    .unwrap()
    .with_allow_cidrs_path(allow.clone());
    assert!(
        ungated.trusted_allow().read_error.is_some(),
        "without a gate the file is read directly"
    );
    let gated = ungated.with_overlay_gate(gate);
    let load = gated.trusted_allow();
    assert!(
        load.read_error.is_none(),
        "read outside the gate: {:?}",
        load.read_error
    );
    assert!(load.entries.is_empty() && load.warnings.is_empty());
    // and once the file appears, unsigned, it spares nothing either
    std::fs::write(&allow, "203.0.113.0/24\n").unwrap();
    assert!(gated.trusted_allow().entries.is_empty());
}
