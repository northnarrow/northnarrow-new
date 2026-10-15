//! External audit NN-AUD-077: a transient `accept()` error must not end
//! the admin plane.
//!
//! The test lowers this process's `RLIMIT_NOFILE`, fills the fd table so
//! the admin socket's `accept()` fails with EMFILE, frees the table, and
//! expects `status` to answer. The serve loop used to return on the first
//! accept error: the listener was gone and every later connect was refused
//! until the agent restarted. The limit is process-wide, hence a binary of
//! its own with a single test. Unprivileged.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use northnarrow_agent::admin_cli::run_status;
use northnarrow_agent::admin_socket::serve;
use northnarrow_agent::anti_tamper::admin_auth::AdminAuth;
use northnarrow_agent::anti_tamper::network_isolate::NetworkIsolator;
use northnarrow_agent::posture::PostureMachine;

fn lower_nofile_soft_limit(soft: libc::rlim_t) {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit/setrlimit only read/write the struct we pass.
    unsafe {
        assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim), 0);
        lim.rlim_cur = soft.min(lim.rlim_max);
        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &lim), 0);
    }
}

/// `status` round trip, retried for up to `within`.
async fn status_answers(socket: PathBuf, within: Duration) -> bool {
    tokio::task::spawn_blocking(move || {
        let deadline = std::time::Instant::now() + within;
        while std::time::Instant::now() < deadline {
            if run_status(&socket).is_ok() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_socket_survives_emfile() {
    let dir = tempfile::TempDir::new().unwrap();
    let socket = dir.path().join("admin.sock");
    let pub_path = dir.path().join("admin.pub");
    let key = SigningKey::from_bytes(&[7u8; 32]);
    std::fs::write(
        &pub_path,
        format!("{}\n", hex::encode(key.verifying_key().to_bytes())),
    )
    .unwrap();
    let auth = Arc::new(AdminAuth::load(&pub_path).unwrap());
    let rules = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../configs/combat-rules.v4");
    let isolator = Arc::new(NetworkIsolator::new(rules).unwrap());
    let posture = Arc::new(PostureMachine::new());
    let server = tokio::spawn(serve(socket.clone(), auth, posture, isolator));
    assert!(
        status_answers(socket.clone(), Duration::from_secs(5)).await,
        "the admin socket never answered"
    );

    // Fill the fd table, leaving one fd for the client's connect: the
    // server's accept() then has none and fails with EMFILE.
    lower_nofile_soft_limit(256);
    let mut hogs = Vec::new();
    loop {
        match std::fs::File::open("/dev/null") {
            Ok(f) => hogs.push(f),
            Err(e) if e.raw_os_error() == Some(libc::EMFILE) => break,
            Err(e) => panic!("opening /dev/null: {e}"),
        }
    }
    hogs.pop();
    let pending = std::os::unix::net::UnixStream::connect(&socket)
        .expect("the connect lands in the listen backlog");
    tokio::time::sleep(Duration::from_millis(500)).await;
    drop(hogs);
    drop(pending);

    assert!(
        !server.is_finished(),
        "the serve loop ended on a transient EMFILE: {:?}",
        server.await
    );
    assert!(
        status_answers(socket, Duration::from_secs(5)).await,
        "status must answer once fds are free again"
    );
}
