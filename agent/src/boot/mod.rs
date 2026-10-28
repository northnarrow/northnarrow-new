//! Boot integrity (lab PR 218; external review G-09, G-11, G-12, AR-09,
//! P0 C-13, P0 C-14; `docs/operator/BOOT_INTEGRITY.md`).
//!
//! The agent's start as typed phases, in an order the code enforces
//! instead of comments in `main()`:
//!
//! 1. [`BootPhase::Preflight`] — checks only, nothing is loaded into the
//!    kernel: the embedded eBPF object, the BTF offsets, the capabilities,
//!    the install manifest, the audit log's writability, the active LSMs
//!    ([`lsm`]). A refusal here leaves the host as it was.
//! 2. [`BootPhase::Attach`] — the eBPF object, the sensors and the deny
//!    hooks. Only an [`AttachPermit`] opens it, and only
//!    [`BootSequence::enter_attach`] gives one, once every preflight check
//!    has run: the sensor and anti-tamper attach take it as an argument.
//! 3. [`BootPhase::SelfTest`] — one deny hook exercised against the agent
//!    itself ([`deny_selftest`]): "attached but never run" is measured, not
//!    assumed.
//! 4. [`BootPhase::Attest`] — the signed audit log opens (`agent_boot`),
//!    then every degradation found so far is signed ([`degradation`]).
//! 5. [`BootPhase::Subsystems`] — what needs the audit log: the FIM
//!    observers, the file-open sensor, the drains, the admin socket.
//! 6. [`BootPhase::Run`] — the capability manifest and the trust level are
//!    signed ([`manifest`], [`trust`]); then the event loop.
//!
//! A step recorded in the wrong phase, a phase skipped or left with a
//! required step missing is a [`BootOrderError`]: the start stops there.
//!
//! Wave 4 restructure, R11a (lab PR 261): the start's code, `main.rs`'s
//! `run` until then, is in the modules below, and `main`'s `run` calls
//! them in the order the code always ran — `logging`, `preflight`, `state`,
//! `identity`, `integrity` (the preflight phase, which ends in the attach
//! permit), `attach` (the attach and the self-test), `evidence` (the
//! attest phase; later the audit log's late binding and the stores), the
//! subsystems `policy`, `response`, `posture`, `fim`, `canary`, `net`,
//! `admin` and `tasks`, then `ready` (the run phase); the event loop and
//! the stop are the crate's `run_loop` and `shutdown`. Each phase takes
//! what the ones before it produced and returns what the ones after it
//! read: the attach takes the permit only the integrity phase holds, the
//! event loop the proof of READY only `ready` makes.

use anyhow::{Context, Result};
use clap::Parser;

use cli::Cli;

pub mod deny_selftest;
pub mod manifest;
pub mod trust;

// Wave 4 restructure, R11a (lab PR 261): `main.rs`'s start, cut into its
// phases and called by `main` in the order the code always ran.
pub(crate) mod admin;
pub(crate) mod attach;
pub(crate) mod canary;
pub(crate) mod cli;
pub(crate) mod evidence;
pub(crate) mod fim;
pub(crate) mod identity;
pub(crate) mod integrity;
pub(crate) mod logging;
pub(crate) mod net;
pub(crate) mod policy;
pub(crate) mod posture;
pub(crate) mod preflight;
pub(crate) mod ready;
pub(crate) mod response;
pub(crate) mod state;
pub(crate) mod tasks;

/// R09b shim (lab PR 254; plan §4.1 rule 2, removed in R17): the phases,
/// the attach permit and the degradations of a run are nn-linux's, with
/// the eBPF loader and the sensors that take and report them.
pub use nn_linux::boot::{
    degradation, lsm, AttachPermit, BootOrderError, BootPhase, BootSequence, BootStep,
};

/// The agent daemon (R11a, lab PR 261: `main.rs`'s `main`): the command
/// line and its one-shot modes, then the runtime and `run`.
pub fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.build_features {
        let features = northnarrow_agent::build_info::build_features();
        if features.is_empty() {
            println!("none");
        } else {
            println!("{}", features.join(","));
        }
        std::process::exit(0);
    }
    if let Some(nonce) = cli.telemetry_probe.as_deref() {
        std::process::exit(northnarrow_agent::telemetry_probe::run_child(nonce));
    }
    if cli.deny_self_test {
        std::process::exit(northnarrow_agent::boot::deny_selftest::run_child());
    }
    if let Some(path) = &cli.btf_check {
        std::process::exit(preflight::btf_check(path));
    }
    if cli.sensor_feasibility {
        #[cfg(feature = "test-privileged")]
        {
            std::process::exit(northnarrow_agent::sensor_feasibility::run());
        }
        #[cfg(not(feature = "test-privileged"))]
        {
            eprintln!("--sensor-feasibility exists only in lab builds (feature test-privileged)");
            std::process::exit(2);
        }
    }
    if cli.verifier_check {
        #[cfg(feature = "debug-trigger")]
        {
            std::process::exit(northnarrow_agent::verifier_check::run());
        }
        #[cfg(not(feature = "debug-trigger"))]
        {
            eprintln!("--verifier-check exists only in lab builds (feature debug-trigger)");
            std::process::exit(2);
        }
    }

    // Lab PR 216 (static review C-43 / G-06): from here on the process is
    // the daemon, and it will hold its signing key — no core dump, no
    // `/proc/<agent>/mem` for a reader without CAP_SYS_PTRACE. Before the
    // runtime and before any key is read; reported once logging is up.
    let undumpable = northnarrow_agent::process_hardening::forbid_core_dumps();
    northnarrow_agent::loop_progress::start();

    // The runtime is the one `#[tokio::main]` built: multi-thread, every
    // driver. (External audit LLMR-009 built it by hand to pin the LLM
    // advisor's worker count first; the advisor was removed in lab PR 214.)
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building the tokio runtime")?
        .block_on(run(cli, undumpable))
}

/// The start: its phases in their order, the event loop, the stop (R11a,
/// lab PR 261: `main.rs`'s `run`).
async fn run(cli: Cli, undumpable: std::io::Result<()>) -> Result<()> {
    // Wave 4 restructure, R11a (lab PR 261): the start in typed phases,
    // called in the order their code always ran. Each takes what the phases
    // before it produced and returns what the ones after it read; what the
    // agent keeps until it stops is this function's, as it was.
    logging::init(&cli, undumpable);
    let preflight::Preflight {
        mut boot,
        tracepoint_degraded,
        hook_args_degraded,
        heads_file,
        chain_targets,
        boot_chains,
        rollback_floor,
    } = preflight::check(&cli)?;
    let state::StateReady {
        early_registration_failed,
    } = state::bootstrap(&cli, &heads_file);
    let identity::Identity {
        identity,
        agent_id,
        overlay_gate,
        ..
    } = identity::resolve(&cli, &mut boot, rollback_floor)?;
    let integrity::Integrity {
        exec_cfg,
        detect_only,
        detect_only_source,
        caps_degraded,
        integrity,
        host_checks,
        allow_degraded,
        bpf_lsm_state,
        attach_permit,
    } = integrity::check(
        &cli,
        &mut boot,
        &identity,
        &overlay_gate,
        early_registration_failed,
    )?;
    let attach::Attached {
        lineage,
        flow_tracker,
        dns_cache,
        execq_mode,
        execpol_mode,
        own_prog_ids_file,
        mut sensor,
        net_bufs,
        exploit_guard_degraded,
    } = attach::load(&cli, &mut boot, attach_permit, &overlay_gate).await?;
    let attach::SelfTested { self_test } = attach::self_test(
        &cli,
        &mut boot,
        &identity,
        &overlay_gate,
        &integrity,
        allow_degraded,
        &bpf_lsm_state,
        detect_only,
    )?;
    let evidence::Attested {
        chain_anchor,
        audit_log,
    } = evidence::attest(
        &cli,
        &mut boot,
        heads_file,
        &chain_targets,
        boot_chains,
        agent_id,
        &overlay_gate,
        identity,
        &detect_only_source,
        integrity,
        tracepoint_degraded,
        hook_args_degraded,
        exploit_guard_degraded,
        caps_degraded,
    )?;
    let policy::Policy {
        netflow_blocklist,
        installer_override,
        chain_store,
        ransom_tracker,
        defense_detector,
        engine,
    } = policy::load(
        &cli,
        &overlay_gate,
        &mut sensor,
        detect_only,
        &audit_log,
        &dns_cache,
        &lineage,
    );
    let response::Response {
        legacy_isolation_removed,
        execq_exec_cfg,
        executor,
        correlation,
        isolator,
    } = response::build(&cli, exec_cfg, detect_only, &audit_log, &overlay_gate)?;
    let posture::Posture {
        ladder_slot,
        exempt,
        open_sensor_carveout,
        posture,
        watchdog_audit,
        stale_combat,
    } = posture::machine(
        &cli,
        &overlay_gate,
        &lineage,
        &isolator,
        &installer_override,
        &ransom_tracker,
        &defense_detector,
    );
    evidence::wire(
        &cli,
        &audit_log,
        &watchdog_audit,
        &overlay_gate,
        &executor,
        &chain_anchor,
        chain_targets,
        &posture,
        &installer_override,
    );
    let combat = posture::ladder(
        &cli,
        &executor,
        &isolator,
        detect_only,
        &audit_log,
        &exempt,
        &posture,
        &ladder_slot,
        &overlay_gate,
        &lineage,
    );
    let fim::FimPaths {
        watched_paths_load,
        paths_summary,
    } = fim::paths(
        &cli,
        &overlay_gate,
        &audit_log,
        legacy_isolation_removed,
        &stale_combat,
    );
    let evidence::Stores {
        state_protection,
        rotation_protection,
        fim_drift_rotation,
        netflow_rotation,
        detection_sink,
        detection_admin_state,
    } = evidence::stores(&cli, &mut sensor, &stale_combat, &chain_anchor, &audit_log);
    let fim_admin_state = fim::start(
        &cli,
        agent_id,
        &audit_log,
        &mut sensor,
        open_sensor_carveout,
        &posture,
        &own_prog_ids_file,
        watched_paths_load,
        &defense_detector,
        &overlay_gate,
        &rotation_protection,
        fim_drift_rotation,
        &lineage,
        paths_summary,
        &state_protection,
    );
    let canary::Canary {
        canary_admin_state,
        canary_detector,
    } = canary::start(&cli, agent_id, &audit_log, &fim_admin_state);
    net::start(
        &cli,
        agent_id,
        rotation_protection,
        netflow_rotation,
        &audit_log,
        flow_tracker,
        dns_cache,
        &lineage,
        &mut sensor,
        net_bufs,
        netflow_blocklist,
        chain_store,
    );
    admin::start(
        &cli,
        &isolator,
        agent_id,
        &audit_log,
        &chain_anchor,
        &posture,
        &combat.shutdown_signal,
        &fim_admin_state,
        &canary_admin_state,
        &installer_override,
        &detection_admin_state,
        &executor,
        &combat.ladder,
        &detect_only_source,
        &exempt,
    );
    let tasks::Tasks {
        execq_handle,
        execpol_handle,
        mut signals,
    } = tasks::start(
        &posture,
        &installer_override,
        execq_mode,
        &overlay_gate,
        &detection_sink,
        &audit_log,
        execq_exec_cfg,
        execpol_mode,
    )?;
    let armed = ready::arm(
        &mut boot,
        bpf_lsm_state,
        self_test,
        host_checks,
        detect_only,
        &audit_log,
    )?;
    let stopped = crate::run_loop::run(
        armed,
        &cli,
        &mut sensor,
        &engine,
        &executor,
        &correlation,
        &posture,
        &combat,
        &canary_detector,
        &installer_override,
        &detection_sink,
        &audit_log,
        &mut signals,
    )
    .await;
    crate::shutdown::stop(
        &cli,
        execq_handle,
        execpol_handle,
        &audit_log,
        &chain_anchor,
        stopped,
    )
}

/// Lab PR 231: give the kernel back the heap the boot freed, once, after
/// READY. The attach parses the vmlinux BTF several times (aya's loader, the
/// LSM, fentry and FIM attaches), each a transient of about 15 MB; from aya
/// 0.14 (aya-obj 0.3, whose `BtfType` grew from 48 to 72 bytes) glibc keeps
/// those pages after the free, and the idle agent's RSS rose by about 17 MB
/// (perf gate: `agent_rss_idle_kib` +47 %, `agent_rss_load_kib` +38 %
/// against the same guest's `main`). `malloc_trim(0)` releases only free
/// memory. Returns whether glibc released any; `false` off glibc.
pub fn release_boot_heap() -> bool {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        // SAFETY: malloc_trim takes glibc's own arena locks and touches only
        // free chunks; no Rust allocation or invariant is involved.
        unsafe { libc::malloc_trim(0) == 1 }
    }
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    {
        false
    }
}

/// The start's sources (R11a, lab PR 261: the code `main.rs` held), their
/// test modules left out: `main.rs`, every file of `boot/` and of
/// `pipeline/`, `run_loop.rs`, `shutdown.rs`. A file added there is read
/// too. What the start's order tests and the identity's read-once test
/// scan, as they scanned `main.rs`.
#[cfg(test)]
pub(crate) fn start_sources() -> String {
    let src = std::path::Path::new(concat!(env!("NN_REPO_ROOT"), "/agent/src"));
    let mut files = vec![src.join("main.rs")];
    for dir in ["boot", "pipeline"] {
        let mut in_dir: Vec<_> = std::fs::read_dir(src.join(dir))
            .unwrap_or_else(|e| panic!("agent/src/{dir}: {e}"))
            .map(|e| e.expect("a directory entry").path())
            .filter(|p| p.extension().is_some_and(|x| x == "rs"))
            .collect();
        in_dir.sort();
        files.extend(in_dir);
    }
    files.push(src.join("run_loop.rs"));
    files.push(src.join("shutdown.rs"));
    let mut out = String::new();
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap_or_else(|e| panic!("{}: {e}", f.display()));
        let code = text
            .find("\n#[cfg(test)]\nmod tests {")
            .map_or(text.as_str(), |end| &text[..end]);
        out.push_str(code);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The phases [`run`] calls, in its order: the call in `run`, the
    /// phase's source and its function's head (R11a, lab PR 261: they were
    /// `main.rs`'s `run`, in this order).
    const PHASES: &[(&str, &str, &str)] = &[
        (
            "logging::init(",
            include_str!(concat!(env!("NN_REPO_ROOT"), "/agent/src/boot/logging.rs")),
            "pub(crate) fn init(",
        ),
        (
            "preflight::check(",
            include_str!(concat!(
                env!("NN_REPO_ROOT"),
                "/agent/src/boot/preflight.rs"
            )),
            "pub(crate) fn check(",
        ),
        (
            "state::bootstrap(",
            include_str!(concat!(env!("NN_REPO_ROOT"), "/agent/src/boot/state.rs")),
            "pub(crate) fn bootstrap(",
        ),
        (
            "identity::resolve(",
            include_str!(concat!(env!("NN_REPO_ROOT"), "/agent/src/boot/identity.rs")),
            "pub(crate) fn resolve(",
        ),
        (
            "integrity::check(",
            include_str!(concat!(
                env!("NN_REPO_ROOT"),
                "/agent/src/boot/integrity.rs"
            )),
            "pub(crate) fn check(",
        ),
        (
            "attach::load(",
            include_str!(concat!(env!("NN_REPO_ROOT"), "/agent/src/boot/attach.rs")),
            "pub(crate) async fn load(",
        ),
        (
            "attach::self_test(",
            include_str!(concat!(env!("NN_REPO_ROOT"), "/agent/src/boot/attach.rs")),
            "pub(crate) fn self_test(",
        ),
        (
            "evidence::attest(",
            include_str!(concat!(env!("NN_REPO_ROOT"), "/agent/src/boot/evidence.rs")),
            "pub(crate) fn attest(",
        ),
        (
            "policy::load(",
            include_str!(concat!(env!("NN_REPO_ROOT"), "/agent/src/boot/policy.rs")),
            "pub(crate) fn load(",
        ),
        (
            "response::build(",
            include_str!(concat!(env!("NN_REPO_ROOT"), "/agent/src/boot/response.rs")),
            "pub(crate) fn build(",
        ),
        (
            "posture::machine(",
            include_str!(concat!(env!("NN_REPO_ROOT"), "/agent/src/boot/posture.rs")),
            "pub(crate) fn machine(",
        ),
        (
            "evidence::wire(",
            include_str!(concat!(env!("NN_REPO_ROOT"), "/agent/src/boot/evidence.rs")),
            "pub(crate) fn wire(",
        ),
        (
            "posture::ladder(",
            include_str!(concat!(env!("NN_REPO_ROOT"), "/agent/src/boot/posture.rs")),
            "pub(crate) fn ladder(",
        ),
        (
            "fim::paths(",
            include_str!(concat!(env!("NN_REPO_ROOT"), "/agent/src/boot/fim.rs")),
            "pub(crate) fn paths(",
        ),
        (
            "evidence::stores(",
            include_str!(concat!(env!("NN_REPO_ROOT"), "/agent/src/boot/evidence.rs")),
            "pub(crate) fn stores(",
        ),
        (
            "fim::start(",
            include_str!(concat!(env!("NN_REPO_ROOT"), "/agent/src/boot/fim.rs")),
            "pub(crate) fn start(",
        ),
        (
            "canary::start(",
            include_str!(concat!(env!("NN_REPO_ROOT"), "/agent/src/boot/canary.rs")),
            "pub(crate) fn start(",
        ),
        (
            "net::start(",
            include_str!(concat!(env!("NN_REPO_ROOT"), "/agent/src/boot/net.rs")),
            "pub(crate) fn start(",
        ),
        (
            "admin::start(",
            include_str!(concat!(env!("NN_REPO_ROOT"), "/agent/src/boot/admin.rs")),
            "pub(crate) fn start(",
        ),
        (
            "tasks::start(",
            include_str!(concat!(env!("NN_REPO_ROOT"), "/agent/src/boot/tasks.rs")),
            "pub(crate) fn start(",
        ),
        (
            "ready::arm(",
            include_str!(concat!(env!("NN_REPO_ROOT"), "/agent/src/boot/ready.rs")),
            "pub(crate) fn arm(",
        ),
        (
            "crate::run_loop::run(",
            include_str!(concat!(env!("NN_REPO_ROOT"), "/agent/src/run_loop.rs")),
            "pub(crate) async fn run(",
        ),
        (
            "crate::shutdown::stop(",
            include_str!(concat!(env!("NN_REPO_ROOT"), "/agent/src/shutdown.rs")),
            "pub(crate) fn stop(",
        ),
    ];

    /// The function whose head is `head` in `src`: from the head to the
    /// first line that closes an item (rustfmt's `}` in column 0).
    fn function<'a>(src: &'a str, head: &str) -> &'a str {
        let start = src
            .find(head)
            .unwrap_or_else(|| panic!("`{head}` not found"));
        let end = src[start..]
            .find("\n}\n")
            .unwrap_or_else(|| panic!("`{head}`: no end"));
        &src[start..start + end + 3]
    }

    /// The start's code in the order it runs: [`run`], then each phase in
    /// the order `run` calls it — each call once, after the one before it
    /// (R11a, lab PR 261: `main.rs`'s `run` held this code in this order).
    fn start_in_order() -> String {
        let mut out = function(
            include_str!(concat!(env!("NN_REPO_ROOT"), "/agent/src/boot/mod.rs")),
            "async fn run(",
        )
        .to_string();
        let run = out.clone();
        let mut at = 0;
        for (call, src, head) in PHASES {
            assert_eq!(run.matches(call).count(), 1, "run calls `{call}` once");
            let i = run[at..]
                .find(call)
                .unwrap_or_else(|| panic!("run calls `{call}` before the phase it follows"));
            at += i + call.len();
            out.push_str(function(src, head));
        }
        out
    }

    /// The order of the start's code (R11a, lab PR 261: of `main.rs` until
    /// it was cut into the phases): every preflight check and the permit
    /// come before the first attach, the self-test right after the deny
    /// hooks, the audit log before the subsystems, the manifest before the
    /// event loop.
    #[test]
    fn main_runs_the_phases_in_order() {
        let main = start_in_order();
        let at = |needle: &str| {
            main.find(needle)
                .unwrap_or_else(|| panic!("the start: `{needle}` not found"))
        };
        let attach = at("SensorMultiplexer::start_with_net(");
        assert!(at(".attach_anti_tamper(") > attach);
        for check in [
            "caps::boot_gate(",
            "install_manifest::check(",
            "audit_preflight::preflight_writable(",
            "boot::lsm::gate(",
            "boot.done(BootStep::Capabilities)",
            "boot.done(BootStep::InstallManifest)",
            "boot.done(BootStep::AuditWritable)",
            "boot.done(BootStep::BpfLsm)",
            "boot.enter_attach()",
        ] {
            assert!(at(check) < attach, "`{check}` after the attach");
        }
        let selftest = at("boot::deny_selftest::run(");
        assert!(selftest > at(".attach_anti_tamper("));
        let audit_open = at("AuditLog::open(&cli.audit_log_file, key, agent_id) {");
        assert!(audit_open > selftest);
        assert!(at("boot.enter(BootPhase::Attest)") < audit_open);
        assert!(at("boot.enter(BootPhase::Subsystems)") > audit_open);
        assert!(
            at("RuleEngine::with_default_rules_and_net(") > at("boot.enter(BootPhase::Subsystems)"),
            "the rule engine in the subsystems phase, after the audit log"
        );
        let manifest = at("boot::manifest::sign(");
        assert!(manifest > at("boot.enter(BootPhase::Run)"));
        assert!(manifest < at("sd_notify::ready()"));
        assert!(at("boot.done(BootStep::CapabilityManifest)") > manifest);
        // the permit is given once, in the integrity phase, which the
        // attach follows
        let sources = start_sources();
        assert_eq!(sources.matches("boot.enter_attach()").count(), 1);
        assert!(function(PHASES[4].1, PHASES[4].2).contains("boot.enter_attach()"));
    }

    /// Lab PR 231: the boot's heap is released once, after READY — after
    /// every attach (the BTF parses whose pages glibc kept) and only once.
    #[test]
    fn main_releases_the_boot_heap_after_ready() {
        let main = start_in_order();
        let release = main
            .find("boot::release_boot_heap()")
            .expect("the start releases the boot heap");
        assert_eq!(
            start_sources().matches("boot::release_boot_heap()").count(),
            1
        );
        assert!(release > main.find("sd_notify::ready()").expect("READY"));
        assert!(release > main.find("boot::manifest::sign(").expect("manifest"));
    }

    /// Lab PR 231: only free memory goes back: what is still allocated is
    /// intact after the release.
    #[test]
    fn releasing_the_boot_heap_keeps_live_allocations() {
        let live: Vec<u64> = (0..200_000).collect();
        let freed: Vec<Vec<u8>> = (0..64).map(|i| vec![i as u8; 64 * 1024]).collect();
        drop(freed);
        let released = release_boot_heap();
        if cfg!(not(all(target_os = "linux", target_env = "gnu"))) {
            assert!(!released);
        }
        assert!(live.iter().enumerate().all(|(i, v)| *v == i as u64));
    }

    /// External review P0 C-14: the network drain is spawned whatever the
    /// netflow log — without it the flows reach the rules unpersisted, and
    /// the gap is signed (`net::drain` tests the record path without a log).
    #[test]
    fn main_runs_the_net_drain_without_its_log() {
        let main = start_in_order();
        assert!(
            !start_sources().contains("if let Some(netflow_db) = netflow_db_opt"),
            "the drain waits for the netflow log again"
        );
        let open = main.find("NetFlowDb::open(").expect("the netflow log");
        let spawn = main[open..]
            .find("drain_loop(")
            .map(|i| open + i)
            .expect("the drain");
        assert!(
            main[open..spawn].contains("\"net_drain\""),
            "a netflow log that cannot be opened is a signed degradation"
        );
    }
}
