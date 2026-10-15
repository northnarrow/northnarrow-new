//! Self-tests of the shared fixture helpers (`common/mod.rs`), in ONE test
//! binary.
//!
//! External audit NN-AUD-232 (TST-011): the iptables guard's self-tests
//! lived in a `#[cfg(test)]` module of `common/mod.rs`, so each of the
//! eight binaries with `mod common;` ran them (and the lab's test counts
//! carried two extra tests per binary), and the clean-state test deleted
//! the production `NORTHNARROW_COMBAT` chain and its INPUT jump without
//! asking whose they were. They are here now, and they refuse to start
//! while a NorthNarrow agent or watchdog runs or when the chain exists.
//!
//! The helper tests need no privilege and run in `cargo test --workspace`.
//! The two iptables tests need root, iptables and the `test-privileged`
//! feature, and are `#[ignore]`d (the lab's `test-ignored` run):
//!   sudo -E env "PATH=$PATH" cargo test --release -p northnarrow-agent \
//!     --features "test-privileged debug-trigger" --test fixture_selftest \
//!     -- --include-ignored --test-threads=1

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::{Duration, SystemTime};

mod common;
use common::PathState;

// ── host guards (NN-AUD-232/233) ──────────────────────────────────────

#[test]
fn a_disposable_host_is_an_nn_lab_guest_or_an_explicit_opt_in() {
    assert!(common::disposable_host_verdict(true, None).is_ok());
    assert!(common::disposable_host_verdict(false, Some("1")).is_ok());
    for opt_in in [None, Some(""), Some("0"), Some("yes"), Some("true")] {
        let err =
            common::disposable_host_verdict(false, opt_in).expect_err("neither the marker nor `1`");
        assert!(
            err.contains(common::LAB_GUEST_MARKER) && err.contains(common::DISPOSABLE_HOST_ENV),
            "{err}"
        );
    }
}

#[test]
fn installed_agents_watchdogs_and_fixture_copies_are_northnarrow_daemons() {
    for (exe, comm) in [
        (Some("northnarrow-agent"), "northnarrow-age\n"),
        (Some("northnarrow-watchdog"), "northnarrow-wat\n"),
        (
            Some("northnarrow-agent-e2etest-17-42 (deleted)"),
            "northnarrow-age",
        ),
        (
            Some("northnarrow-watchdog-e2etest-17-42"),
            "northnarrow-wat",
        ),
        // exe unreadable (not root): comm alone.
        (None, "northnarrow-age\n"),
        (None, "northnarrow-wat\n"),
        // A renamed copy still has the agent's comm.
        (Some("nn"), "northnarrow-age"),
    ] {
        assert!(common::is_northnarrow_daemon(exe, comm), "{exe:?} {comm:?}");
    }
    for (exe, comm) in [
        // The agent crate's own unit-test binary and this one.
        (Some("northnarrow_agent-0123abcd"), "northnarrow_age"),
        (Some("fixture_selftest-0123abcd"), "fixture_selfte"),
        (Some("nn-admin"), "nn-admin"),
        (None, "kworker/0:1"),
    ] {
        assert!(
            !common::is_northnarrow_daemon(exe, comm),
            "{exe:?} {comm:?}"
        );
    }
}

#[test]
fn this_test_process_is_not_listed_as_a_northnarrow_daemon() {
    let me = format!("{} ", std::process::id());
    assert!(
        !common::northnarrow_daemons()
            .iter()
            .any(|d| d.starts_with(&me)),
        "the runner itself must not make the guard refuse"
    );
}

#[test]
fn the_combat_chain_is_absent_only_when_iptables_says_so() {
    assert_eq!(common::combat_chain_verdict(Some(0), ""), Ok(true));
    assert_eq!(
        common::combat_chain_verdict(Some(1), "iptables: No chain/target/match by that name.\n"),
        Ok(false)
    );
    // Not root, iptables broken, killed: unknown, never "absent".
    for (status, stderr) in [
        (
            Some(4),
            "iptables v1.8.10 (nf_tables): Could not fetch rule set generation id: \
             Permission denied (you must be root)",
        ),
        (
            Some(3),
            "iptables v1.8.7 (legacy): can't initialize iptables table `filter'",
        ),
        (Some(1), ""),
        (None, ""),
    ] {
        assert!(
            common::combat_chain_verdict(status, stderr).is_err(),
            "{status:?} {stderr:?}"
        );
    }
}

#[test]
fn strip_ansi_leaves_the_fields_a_log_check_reads() {
    let coloured = "\u{1b}[32m INFO\u{1b}[0m anti-tamper: all LSM hooks attached \
                    \u{1b}[3mdeny_attached\u{1b}[0m\u{1b}[2m=\u{1b}[0m9";
    assert_eq!(
        common::strip_ansi(coloured),
        " INFO anti-tamper: all LSM hooks attached deny_attached=9"
    );
}

// ── PathState / restore_path (NN-AUD-233) ─────────────────────────────

/// A file with known content, mode 0640 and an mtime in the past.
fn seed(path: &Path, content: &[u8]) -> PathState {
    std::fs::write(path, content).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640)).unwrap();
    let f = std::fs::File::options().write(true).open(path).unwrap();
    f.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000))
        .unwrap();
    PathState::read(path).unwrap()
}

#[test]
fn an_overwritten_file_gets_its_content_mode_and_mtime_back() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("kill_switch.conf");
    let before = seed(&p, b"operator's own content\n");
    assert!(matches!(before, PathState::File { mode: 0o640, .. }));

    std::fs::write(&p, b"canonical bait\n").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_ne!(PathState::read(&p).unwrap(), before);

    common::restore_path(&p, &before).unwrap();
    assert_eq!(PathState::read(&p).unwrap(), before);
    assert_eq!(std::fs::read(&p).unwrap(), b"operator's own content\n");
}

#[test]
fn a_deleted_file_is_recreated() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("pause.flag");
    let before = seed(&p, b"paused=false\n");
    std::fs::remove_file(&p).unwrap();
    assert_eq!(PathState::read(&p).unwrap(), PathState::Absent);

    common::restore_path(&p, &before).unwrap();
    assert_eq!(PathState::read(&p).unwrap(), before);
}

#[test]
fn a_file_the_run_created_is_removed() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("unload.signal");
    let before = PathState::read(&p).unwrap();
    assert_eq!(before, PathState::Absent);
    std::fs::write(&p, b"created by the run\n").unwrap();

    common::restore_path(&p, &before).unwrap();
    assert!(!p.exists());
}

#[test]
fn an_unchanged_file_is_not_written() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("maintenance.mode");
    let before = seed(&p, b"enabled=false\n");
    let m = std::fs::metadata(&p).unwrap();
    std::thread::sleep(Duration::from_millis(20));

    common::restore_path(&p, &before).unwrap();
    let after = std::fs::metadata(&p).unwrap();
    assert_eq!(
        (after.ino(), after.ctime(), after.ctime_nsec()),
        (m.ino(), m.ctime(), m.ctime_nsec())
    );
}

#[test]
fn a_symlink_in_place_of_the_file_is_replaced_not_written_through() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("debug_disable.flag");
    let victim = dir.path().join("victim");
    std::fs::write(&victim, b"not a bait\n").unwrap();
    let before = seed(&p, b"debug=false\n");
    std::fs::remove_file(&p).unwrap();
    std::os::unix::fs::symlink(&victim, &p).unwrap();
    assert_eq!(PathState::read(&p).unwrap(), PathState::Other("symlink"));

    common::restore_path(&p, &before).unwrap();
    assert_eq!(PathState::read(&p).unwrap(), before);
    assert_eq!(std::fs::read(&victim).unwrap(), b"not a bait\n");
}

#[test]
fn what_is_not_a_regular_file_is_named_and_never_restored_or_removed() {
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("agent.dev.lock");
    std::fs::create_dir(&sub).unwrap();
    assert_eq!(
        PathState::read(&sub).unwrap(),
        PathState::Other("directory")
    );

    // A directory where a file or nothing was: left alone, with an error.
    let file = PathState::File {
        bytes: b"x".to_vec(),
        mode: 0o644,
        uid: unsafe { libc::geteuid() },
        gid: unsafe { libc::getegid() },
        mtime: SystemTime::UNIX_EPOCH,
    };
    assert!(common::restore_path(&sub, &file).is_err());
    assert!(common::restore_path(&sub, &PathState::Absent).is_err());
    assert!(sub.is_dir());

    // A state that was not a file is never recreated.
    let gone = dir.path().join("override.config");
    assert!(common::restore_path(&gone, &PathState::Other("symlink")).is_err());
    assert!(!gone.exists());
}

// ── EniIptablesGuard (moved from common/mod.rs) ───────────────────────

#[cfg(feature = "test-privileged")]
mod iptables {
    use std::process::Command;

    use super::common::{self, EniIptablesGuard};

    /// The guard is exercised on a chain of its own: the production
    /// `NORTHNARROW_COMBAT` (an agent's isolation, or an earlier test's) is
    /// never created, read or deleted here (external audit NN-AUD-232).
    const SELFTEST_CHAIN: &str = "NN_GUARD_SELFTEST";

    /// Root, and the self-test chain absent: one an aborted run left is
    /// this test's own, removed first.
    fn require_selftest_chain_absent() {
        common::require_root("exercise the iptables guard");
        if common::chain_present(SELFTEST_CHAIN) == Ok(true) {
            drop(EniIptablesGuard::install_for(SELFTEST_CHAIN));
        }
        assert_eq!(
            common::chain_present(SELFTEST_CHAIN),
            Ok(false),
            "test precondition: {SELFTEST_CHAIN} absent"
        );
    }

    /// Install the self-test chain and its INPUT jump, then drop
    /// the guard inside `catch_unwind` to prove the cleanup runs on the
    /// unwind path. The chain must be gone after the drop.
    #[test]
    #[ignore = "requires sudo + iptables (run via integration runbook)"]
    fn iptables_guard_drops_cleans_chain_even_on_panic() {
        require_selftest_chain_absent();
        let new_chain = Command::new("iptables")
            .args(["-N", SELFTEST_CHAIN])
            .status()
            .expect("spawn iptables -N");
        assert!(
            new_chain.success(),
            "iptables -N {SELFTEST_CHAIN} failed (test precondition)"
        );
        let jump = Command::new("iptables")
            .args(["-I", "INPUT", "-j", SELFTEST_CHAIN])
            .status()
            .expect("spawn iptables -I INPUT");
        assert!(jump.success(), "iptables -I INPUT failed (precondition)");
        assert_eq!(
            common::chain_present(SELFTEST_CHAIN),
            Ok(true),
            "test precondition: chain should be present before guard drop"
        );

        let result = std::panic::catch_unwind(|| {
            let _guard = EniIptablesGuard::install_for(SELFTEST_CHAIN);
            panic!("simulated test failure to exercise unwind-path Drop");
        });
        assert!(result.is_err(), "the inner closure should have panicked");

        assert_eq!(
            common::chain_present(SELFTEST_CHAIN),
            Ok(false),
            "EniIptablesGuard::drop failed to clean {SELFTEST_CHAIN} after panic"
        );
    }

    /// Drop the guard with no chain: its `-D` / `-F` / `-X` each fail and
    /// Drop must swallow that, and create nothing. The chain's absence is
    /// a precondition checked, never made: the test used to delete it.
    #[test]
    #[ignore = "requires sudo + iptables (run via integration runbook)"]
    fn iptables_guard_idempotent_on_clean_state() {
        require_selftest_chain_absent();
        {
            let _guard = EniIptablesGuard::install_for(SELFTEST_CHAIN);
        }
        assert_eq!(
            common::chain_present(SELFTEST_CHAIN),
            Ok(false),
            "guard's idempotent drop should not have created a chain"
        );
    }
}
