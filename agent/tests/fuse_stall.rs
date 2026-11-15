//! Lot 353 (re-check 2 of #563): the harness the three reviews of #563
//! would have needed. Each found, one at a time, a by-path walk of `/proc`
//! (or of `/run/northnarrow`) on a thread the agent cannot lose: the signed
//! appends' `/proc/self/fd` path (the first review), the open sensor's rule
//! refresh on a runtime worker (the first re-check), the decision's
//! `trusted_exe`, the admin socket's rebind in the serve loop and the
//! entropy sampler (the second). This test runs those loops together, in a
//! user and mount namespace of its own, under a FUSE over `/proc` — and a
//! second over the admin socket's directory — whose daemon answers the
//! first lookup and holds every request after it: the agent's runtime on
//! ONE worker (a 1-vCPU host), the admin socket's real serve loop on it,
//! and on their own threads the decision's per-process facts, the signed
//! audit appends, the open sensor's rule refresh and the entropy sampler.
//! Each must keep making progress for the whole run; a loop held on the
//! FUSE stops its count, and the test names it.
//!
//! Fix round 5 (the KVM suites of #563): the decision's loop runs as the
//! decision thread runs — in its role, under its seccomp filter, which
//! refuses `openat2` — and a third FUSE, mounted below `/proc` over the
//! directory of the process whose `exe … sha256` facts it reads, holds
//! what crosses into it. On 92de8ac5 that loop read nothing at all (every
//! read beneath the anchored roots failed with the filter's `EPERM`); a
//! walk from the root that crossed mounts would be held on the FUSE below.
//!
//! Re-check 4 of #563 (R4-1): a fourth FUSE over this process's own
//! `/proc/<pid>/fd`. The decision thread's walk opened its last file again
//! by name through `self/fd/N`, crossing it: on 8c1c5d12 that loop made no
//! round at all; it reopens through its own `thread-self/fd` now, each
//! name of the way checked.
//!
//! A test binary of its own, with this one test: the run forks (the user
//! namespace), and a fork while other tests' threads hold a lock (the
//! allocator's, a registry's) left the child waiting on it for ever.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long the loops run under the mounts: past the admin socket's first
/// check of its path (`SOCKET_CHECK_EVERY`, 10 s), whose rebind the second
/// FUSE holds.
const RUN: Duration = Duration::from_secs(14);

/// The longest a loop may go without progress at the end of the run.
const STALL: Duration = Duration::from_secs(4);

/// One loop's progress: its count and when it last moved.
struct Progress {
    name: &'static str,
    count: AtomicU64,
    last_ms: AtomicU64,
}

impl Progress {
    fn new(name: &'static str) -> Arc<Self> {
        Arc::new(Self {
            name,
            count: AtomicU64::new(0),
            last_ms: AtomicU64::new(0),
        })
    }

    fn moved(&self, t0: Instant) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.last_ms
            .store(t0.elapsed().as_millis() as u64, Ordering::Relaxed);
    }
}

/// `body` again and again on a thread named `name` until `stop`, each
/// round that returns counted in `p`.
fn looping(
    name: &str,
    p: &Arc<Progress>,
    t0: Instant,
    stop: &Arc<AtomicBool>,
    every: Duration,
    mut body: impl FnMut() -> bool + Send + 'static,
) {
    let (p, stop) = (Arc::clone(p), Arc::clone(stop));
    std::thread::Builder::new()
        .name(name.to_string())
        .spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if body() {
                    p.moved(t0);
                }
                std::thread::sleep(every);
            }
        })
        .expect("a loop's thread");
}

/// A file of `n` random bytes (high entropy) at `p`.
fn random_file(p: &Path, n: usize, seed: u64) {
    let mut x = seed | 1;
    let bytes: Vec<u8> = (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect();
    std::fs::write(p, bytes).unwrap();
}

/// The child's run (in its namespaces): 0 when every loop kept going, else
/// a bit per loop that stalled (printed by name).
fn run_loops(dir: &Path) -> i32 {
    use std::os::unix::fs::FileTypeExt;
    let _ = antitamper_bpf::kernel_roots::init();
    if antitamper_bpf::kernel_roots::symlink_metadata("/proc/self").is_err() {
        eprintln!("missing here: /proc not anchored");
        return 99;
    }
    // the admin socket, its directory and a second name of it (a hard link
    // reaches the same socket: the client's way in once the FUSE hides the
    // first)
    let run = dir.join("run");
    let alt = dir.join("alt");
    std::fs::create_dir_all(&run).unwrap();
    std::fs::create_dir_all(&alt).unwrap();
    let socket = run.join("admin.sock");
    let socket_alt = alt.join("admin.sock");
    let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let pub_path = dir.join("admin.pub");
    std::fs::write(
        &pub_path,
        format!("{}\n", hex::encode(signing.verifying_key().to_bytes())),
    )
    .unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    {
        let auth = Arc::new(
            northnarrow_agent::anti_tamper::admin_auth::AdminAuth::load(&pub_path).unwrap(),
        );
        let isolator = Arc::new(
            northnarrow_agent::anti_tamper::network_isolate::NetworkIsolator::new(
                PathBuf::from(env!("NN_REPO_ROOT")).join("configs/combat-rules.v4"),
            )
            .unwrap(),
        );
        let posture = Arc::new(northnarrow_agent::posture::PostureMachine::new());
        let s = socket.clone();
        rt.spawn(async move {
            let _ = northnarrow_agent::admin::serve(s, auth, posture, isolator).await;
        });
    }
    let started = Instant::now();
    while !std::fs::symlink_metadata(&socket).is_ok_and(|m| m.file_type().is_socket()) {
        if started.elapsed() > Duration::from_secs(10) {
            eprintln!("the admin socket was not bound");
            return 120;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    std::fs::hard_link(&socket, &socket_alt).unwrap();
    // the entropy sampler's burst: high-entropy files of the host's view
    let burst = dir.join("burst");
    std::fs::create_dir_all(&burst).unwrap();
    for i in 0..4u64 {
        random_file(&burst.join(format!("f{i}.locked")), 8192, i + 1);
    }
    // a process of the system tree for the decision's `exe … sha256` facts
    let Ok(mut sleeper) = std::process::Command::new("/usr/bin/sleep")
        .arg("60")
        .spawn()
    else {
        eprintln!("missing here: no /usr/bin/sleep");
        return 99;
    };
    let sleeper_pid = sleeper.id();
    // the audit log the signing loop appends to (its directory anchored)
    let key =
        northnarrow_agent::audit::AgentSigningKey::load_or_bootstrap(&dir.join("agent.sig.key"))
            .unwrap();
    let audit =
        northnarrow_agent::audit::AuditLog::open(&dir.join("audit.log"), key, [0u8; 16]).unwrap();

    // the mounts: a FUSE over `/proc` and one over the socket's directory,
    // each answering the first lookup and holding the rest — and, first,
    // one below `/proc` over the sleeper's directory (fix round 5) and one
    // over this process's own descriptors (re-check 4, R4-1)
    let own_fd = PathBuf::from(format!("/proc/{}/fd", std::process::id()));
    let below = PathBuf::from(format!("/proc/{sleeper_pid}"));
    let (Some(own_fd_fuse), Some(below_fuse), Some(proc_fuse), Some(run_fuse)) = (
        nn_linux::fuse_testing::smart_fuse_over(&own_fd, 1),
        nn_linux::fuse_testing::smart_fuse_over(&below, 1),
        nn_linux::fuse_testing::smart_fuse_over(Path::new("/proc"), 1),
        nn_linux::fuse_testing::smart_fuse_over(&run, 1),
    ) else {
        eprintln!("missing here: FUSE refused in this namespace");
        let _ = sleeper.kill();
        return 99;
    };

    let t0 = Instant::now();
    let stop = Arc::new(AtomicBool::new(false));
    let runtime = Progress::new("the runtime's one worker (a task's ticks)");
    let status = Progress::new("the admin socket's serve loop (STATUS answered)");
    let decision =
        Progress::new("the decision's process facts (uid, cgroup, exe … sha256), under its filter");
    let signing = Progress::new("the signed audit appends");
    let refresh = Progress::new("the open sensor's rule refresh (answered or unjudged)");
    let entropy = Progress::new("the entropy sampler (nn-slow-work)");
    let all = [&runtime, &status, &decision, &signing, &refresh, &entropy];
    {
        let p = Arc::clone(&runtime);
        let stop = Arc::clone(&stop);
        rt.spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_millis(20)).await;
                p.moved(t0);
            }
        });
    }
    let s = socket_alt.clone();
    looping(
        "nn-test-status",
        &status,
        t0,
        &stop,
        Duration::from_millis(250),
        move || northnarrow_agent::admin_cli::run_status(&s).is_ok(),
    );
    looping(
        "nn-decision",
        &decision,
        t0,
        &stop,
        Duration::from_millis(50),
        {
            let mut entered = false;
            move || {
                use nn_core::decision::rule_policy::ActorFacts;
                // fix round 5: the decision thread's role and filter (no
                // `openat2`), taken on the loop's thread at its first round
                if !std::mem::replace(&mut entered, true) {
                    let e = nn_linux::caps::enter(nn_linux::caps::Role::Decision);
                    assert!(
                        e.as_ref().is_ok_and(|e| e.filter == Some(Ok(()))),
                        "the decision's filter: {e:?}"
                    );
                }
                let facts = northnarrow_agent::decision_host_linux::ProcFacts::default();
                let me = std::process::id();
                let uid = facts.uid(me);
                let _ = facts.cgroup(me);
                // the open of `/proc/<pid>/exe` (re-check 2's R2-2): an
                // image of the system tree, its owner not root in this
                // namespace — its directory now under the FUSE below `/proc`
                let _ = facts.trusted_exe(sleeper_pid);
                let _ = facts.started_in_cgroup(me);
                uid.is_some()
            }
        },
    );
    let audit = std::sync::Mutex::new(audit);
    looping(
        "nn-test-signing",
        &signing,
        t0,
        &stop,
        Duration::from_millis(100),
        move || {
            let draft = northnarrow_agent::audit::AuditEntryDraft {
                op: "fuse_stall_harness".to_string(),
                extra: serde_json::json!({}),
                key_fp: String::new(),
                cosigner_fps: Vec::new(),
                result: "ok".to_string(),
                client_pid: 0,
                client_uid: 0,
                client_comm: String::new(),
                client_exe: None,
            };
            audit.lock().unwrap().append(draft).is_ok()
        },
    );
    let mut rules = nn_linux::sensors::open_sensor::RuleRefresh::new(Default::default());
    looping(
        "nn-test-refresh",
        &refresh,
        t0,
        &stop,
        Duration::from_millis(500),
        move || {
            let _ = rules.next(&nn_linux::sensors::open_sensor::BUILD_READER);
            true
        },
    );
    let file = burst.join("f0.locked");
    looping(
        "nn-slow-work",
        &entropy,
        t0,
        &stop,
        Duration::from_millis(100),
        move || {
            // the sampler's walk of the host's view, here this process's own
            // root (`/proc/self/root`: PID 1's is out of this namespace's reach)
            let host =
                |p: &Path| Path::new("/proc/self/root").join(p.strip_prefix("/").unwrap_or(p));
            let s = nn_linux::impact::entropy::sample_dir(&file, Duration::from_secs(600), &host);
            s.examined > 0
        },
    );

    std::thread::sleep(RUN);
    let end = t0.elapsed().as_millis() as u64;
    let mut rc = 0;
    for (i, p) in all.iter().enumerate() {
        let (n, last) = (
            p.count.load(Ordering::Relaxed),
            p.last_ms.load(Ordering::Relaxed),
        );
        let stalled = n == 0 || end.saturating_sub(last) > STALL.as_millis() as u64;
        eprintln!(
            "{}: {n} rounds, last {} ms before the end{}",
            p.name,
            end.saturating_sub(last),
            if stalled { " — STALLED" } else { "" }
        );
        if stalled {
            rc |= 1 << i;
        }
    }
    stop.store(true, Ordering::Relaxed);
    // the connections aborted: what they held fails and ends
    drop(run_fuse);
    drop(proc_fuse);
    drop(below_fuse);
    drop(own_fd_fuse);
    let _ = sleeper.kill();
    rt.shutdown_timeout(Duration::from_secs(2));
    rc
}

/// Lot 353 (re-check 2 of #563): the critical loops keep going under a FUSE
/// over `/proc` (and one over the admin socket's directory) that answers
/// the first lookup and holds every other request, with the runtime on one
/// worker. On main (65bf765b) the decision's facts (`trusted_exe`'s open of
/// `/proc/<pid>/exe` by path), the entropy sampler (`read_dir` of the
/// host's view by path) and the serve loop (the admin socket's rebind by
/// path, past its first check) stall; in the first review's tree the signed
/// appends did, in the first re-check's the rule refresh; on 8c1c5d12 the
/// decision's, under the FUSE over this process's own `/proc/<pid>/fd`.
#[test]
fn the_critical_loops_keep_going_under_a_fuse_that_answers_one_lookup() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().to_path_buf();
    // under CI a run that cannot happen here fails (`fuse_testing::ran`)
    let rc = nn_linux::fuse_testing::in_userns(move || run_loops(&path));
    if let Some(rc) = nn_linux::fuse_testing::ran(rc) {
        assert_eq!(rc, 0, "loops stalled (bits, in order: runtime, status, decision, signing, refresh, entropy): {rc:#b}");
    }
}
