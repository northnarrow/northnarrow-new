//! Lot 365 (an external tester's run of the alpha on Debian 12): `nn-admin
//! status` without sudo, with the agent running, exited 5 with
//! `connecting to /run/northnarrow/admin.sock: Permission denied`, and the
//! tester's guide reads exit 5 as "the agent is not running". A permission
//! the host refused is now exit 17 with what to do (run it with sudo); an
//! agent that cannot be reached is still exit 5.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::process::{Command, Output};

const NN_ADMIN: &str = env!("CARGO_BIN_EXE_nn-admin");

/// `nn-admin status --socket <socket>`, as a user without root: under root
/// (the lab) the child runs as `nobody`, which a socket of mode 0 refuses.
fn status(socket: &std::path::Path) -> Output {
    let mut cmd = Command::new(NN_ADMIN);
    cmd.arg("status").arg("--socket").arg(socket).env_clear();
    // SAFETY: geteuid(2) has no preconditions and cannot fail.
    if unsafe { libc::geteuid() } == 0 {
        use std::os::unix::process::CommandExt;
        cmd.uid(65534).gid(65534);
    }
    cmd.output().expect("nn-admin runs")
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn status_without_root_on_a_running_agent_says_sudo_not_stopped() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let socket = dir.path().join("admin.sock");
    // The agent runs: its socket listens, and only root may open it.
    let _agent = UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o0)).unwrap();

    let out = status(&socket);
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(17), "{err}");
    assert!(err.contains("Permission denied"), "{err}");
    assert!(
        err.contains("Run it with sudo: `sudo nn-admin status …`"),
        "the message says what to do: {err}"
    );
    assert!(
        err.contains("This does not mean the agent is stopped"),
        "the message tells it from an agent that is down: {err}"
    );
    assert!(out.stdout.is_empty());
}

#[test]
fn status_with_no_agent_is_still_exit_5() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    // No agent: nothing at the socket's path, then a socket nobody listens on.
    let socket = dir.path().join("admin.sock");
    for case in ["no socket", "nobody listens"] {
        if case == "nobody listens" {
            drop(UnixListener::bind(&socket).unwrap());
            // writable by anyone: the refusal is the connection's, not the file's
            std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o777)).unwrap();
        }
        let out = status(&socket);
        let err = stderr(&out);
        assert_eq!(out.status.code(), Some(5), "{case}: {err}");
        assert!(!err.contains("sudo"), "{case}: no permission advice: {err}");
    }
}

/// Review F3: a key that is another user's (root's, mode 0600) in a
/// directory this user can traverse: the stat succeeds, so the refusal is
/// the ownership rule's, and it is exit 17 too, not 5.
#[test]
fn a_key_owned_by_another_user_in_a_readable_directory_is_exit_17_not_5() {
    // SAFETY: geteuid(2) has no preconditions and cannot fail.
    let as_root = unsafe { libc::geteuid() } == 0;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let key = if as_root {
        // root's own file, run as `nobody` below
        let k = dir.path().join("admin.key");
        std::fs::write(&k, "00".repeat(32)).unwrap();
        std::fs::set_permissions(&k, std::fs::Permissions::from_mode(0o600)).unwrap();
        k
    } else {
        // a file this user cannot have created: root's, mode 0600, in /etc
        use std::os::unix::fs::MetadataExt;
        let k = std::path::PathBuf::from("/etc/.pwd.lock");
        match std::fs::metadata(&k) {
            Ok(m) if m.uid() == 0 && m.mode() & 0o7777 == 0o600 => k,
            _ => {
                eprintln!("skipped: no root-owned 0600 file at /etc/.pwd.lock");
                return;
            }
        }
    };
    let socket = dir.path().join("admin.sock");
    let _agent = UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o777)).unwrap();
    let mut cmd = Command::new(NN_ADMIN);
    cmd.arg("status")
        .arg("--socket")
        .arg(&socket)
        .arg("--key")
        .arg(&key)
        .env_clear();
    if as_root {
        use std::os::unix::process::CommandExt;
        cmd.uid(65534).gid(65534);
    }
    let out = cmd.output().expect("nn-admin runs");
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(17), "{err}");
    assert!(err.contains("belongs to uid 0, not to this user"), "{err}");
    assert!(
        err.contains("Run it with sudo: `sudo nn-admin status …`"),
        "{err}"
    );
}

/// The mini-hunt's variant: `status --key` with a key this user may not
/// read (the install key is root's, in /root) was exit 5 too.
#[test]
fn a_key_this_user_may_not_read_is_exit_17_not_5() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let socket = dir.path().join("admin.sock");
    let _agent = UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o777)).unwrap();
    let locked = dir.path().join("root-only");
    std::fs::create_dir(&locked).unwrap();
    std::fs::write(locked.join("admin.key"), "00".repeat(32)).unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o0)).unwrap();

    let mut cmd = Command::new(NN_ADMIN);
    cmd.arg("status")
        .arg("--socket")
        .arg(&socket)
        .arg("--key")
        .arg(locked.join("admin.key"))
        .env_clear();
    // SAFETY: geteuid(2) has no preconditions and cannot fail.
    if unsafe { libc::geteuid() } == 0 {
        use std::os::unix::process::CommandExt;
        cmd.uid(65534).gid(65534);
    }
    let out = cmd.output().expect("nn-admin runs");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(17), "{err}");
    assert!(err.contains("reading private key"), "{err}");
    assert!(
        err.contains("Run it with sudo: `sudo nn-admin status …`"),
        "{err}"
    );
}
