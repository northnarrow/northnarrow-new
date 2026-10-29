//! `BootPhase::Attach` and `BootPhase::SelfTest` (R11a, lab PR 261: from
//! `main.rs`): the eBPF object, the sensors and the deny hooks attach on
//! the proof the integrity checks gave (R11b, lab PR 262:
//! `IntegrityVerified`, and the state files bootstrapped before), then one
//! deny hook is exercised against the agent itself.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use nn_proto::admin_signed_payload::OverlayKind;
use northnarrow_agent::boot::{checks, BootPhase, BootSequence, BootStep};
use northnarrow_agent::net::dns_cache::DnsCache;
use northnarrow_agent::net::flow_tracker::FlowTracker;
use northnarrow_agent::posture::AuthSessionTracker;
use northnarrow_agent::sensors::SensorMultiplexer;
use tracing::{debug, error, info, warn};

use super::cli::{Cli, DnsSensor, ExecSensor, ExploitGuard, FileOpenSensor};
use super::refusal::{self, Refusal};
use super::state::StateReady;

/// What [`load`] attached.
pub(crate) struct Attached {
    /// The process lineage the posture, the rules and the pumps share.
    pub(crate) lineage: AuthSessionTracker,
    pub(crate) flow_tracker: Arc<parking_lot::Mutex<FlowTracker>>,
    pub(crate) dns_cache: Arc<DnsCache>,
    pub(crate) execq_mode: northnarrow_agent::execq::Mode,
    pub(crate) execpol_mode: northnarrow_agent::execpol::Mode,
    /// R11c (lab PR 264): the exec guards the load installed, with their
    /// configuration and the kernel objects their controllers start on.
    pub(crate) exec_guards: northnarrow_agent::exec_guards::AgentExecGuards,
    /// Where the ids of the agent's BPF programs go (DEP-006).
    pub(crate) own_prog_ids_file: Option<PathBuf>,
    pub(crate) sensor: SensorMultiplexer,
    /// The network drain's rings.
    pub(crate) net_bufs: northnarrow_agent::sensors::multiplexer::NetRingBufs,
    /// The exploit guard off or unavailable, signed once the audit log is
    /// open.
    pub(crate) exploit_guard_degraded: Option<String>,
    /// R11c (lab PR 264): the running exploit guard (`None`: off or
    /// unavailable) — its sampler's audit log, which the attest phase
    /// binds, and its response, which the response phase sets.
    pub(crate) exploit_guard: Option<northnarrow_agent::sensors::epg::ExploitGuard>,
    /// R11c (lab PR 264): what the deny hooks' attach found — the deny
    /// side, for the trust level and the manifest, and the degraded states,
    /// signed by the attest phase (process-wide statics until then).
    pub(crate) anti_tamper: northnarrow_agent::anti_tamper::AttachReport,
}

/// `BootPhase::Attach`: the eBPF object loads and the sensors attach
/// (`SensorMultiplexer::start_with_net`), the deny hooks attach and the
/// agent registers in them (`attach_anti_tamper`), the exploit guard
/// attaches. The load, the pins and every attach take `verified`, which
/// only [`crate::boot::integrity::check`] holds (R11b, lab PR 262: the
/// plan's `attach(&IntegrityVerified, &StateReady)`): nothing reaches the
/// kernel before every integrity check has passed, and the state files the
/// deny hooks protect were bootstrapped before (`_state`, which only
/// [`crate::boot::state::bootstrap`] builds). A load or an attach that
/// fails refuses the start, signed (`refusals`, into `audit`, the log the
/// integrity phase opened); what attached before it stays pinned — the deny
/// hooks that did attach keep protecting the agent's files.
pub(crate) async fn load(
    cli: &Cli,
    boot: &mut BootSequence,
    verified: &northnarrow_agent::boot::IntegrityVerified,
    _state: &StateReady,
    overlay_gate: &Arc<northnarrow_agent::config::overlay_auth::OverlayGate>,
    refusals: &refusal::Context<'_>,
    audit: &mut checks::AuditOpen,
) -> Result<Attached> {
    // Process-lineage cache shared by the posture triggers and the FIM
    // rules' package-manager carve-out (review 49): "does this writer
    // descend from dpkg/rpm/dnf?". Fed from Event::ProcessSpawn by the
    // posture trigger detector; reads /proc on a cache miss.
    // External audit POS-003: every cached exec checked against the
    // process its pid names now. External audit NETR-008: built before
    // the sensors so the network pumps name each flow's image with it.
    let lineage = AuthSessionTracker::for_host();

    // Tappa 10 N9 — build the shared net state BEFORE starting the
    // sensor multiplexer so the TcpConnect + DnsQuery pumps can
    // feed the FlowTracker / DnsCache the instant they start
    // pumping. NetWiring is Arc-shared with the net drain task
    // spawned further down.
    let flow_tracker = Arc::new(parking_lot::Mutex::new(FlowTracker::default()));
    let dns_cache = Arc::new(DnsCache::default());
    let net_wiring = northnarrow_agent::sensors::multiplexer::NetWiring {
        flow_tracker: Arc::clone(&flow_tracker),
        dns_cache: Arc::clone(&dns_cache),
        lineage: lineage.clone(),
    };
    // R11c (lab PR 264): what the load is told — it was set in process-wide
    // switches before the multiplexer started.
    let mut plan = northnarrow_agent::sensors::multiplexer::LoadPlan {
        // Tappa 10.9 step 2: which exec sensor the multiplexer attaches.
        exec_lsm: cli.exec_sensor == ExecSensor::Lsm,
        // Review 69: `sys_enter_openat` emits from the start only in
        // tracepoint mode; otherwise `start_open_sensor` decides.
        open_tracepoint: cli.file_open_sensor == FileOpenSensor::Tracepoint,
        // Tappa 10.9 step 3: which DNS sensor the multiplexer attaches.
        dns_skb: cli.dns_sensor == DnsSensor::Skb,
        ..Default::default()
    };
    // Lab PR 223 (EXPERIMENTAL): the exec quarantine's mode, before the
    // multiplexer writes it into the kernel (the same detect-only inputs
    // the executor reads further down: a detect-only agent observes).
    let execq_cfg = cli.execq_config(
        cli.detect_only || northnarrow_agent::response::config::detect_only_env().is_some(),
    );
    let execq_mode = execq_cfg.mode;
    // Lab PR 226 (EXPERIMENTAL): the exec policy, its signed table read
    // now (the kernel configuration is written and frozen when the
    // multiplexer starts); a detect-only agent audits.
    let execpol_cfg = {
        use northnarrow_agent::execpol::{self as ep, Mode};
        let detect_only =
            cli.detect_only || northnarrow_agent::response::config::detect_only_env().is_some();
        let mode = match cli.exec_policy {
            Mode::Enforce if detect_only => Mode::Audit,
            m => m,
        };
        let boot = if mode == Mode::Off {
            ep::boot_table(None, cli.exec_policy_profile)
        } else {
            match overlay_gate.verified(OverlayKind::ExecPolicy, &cli.exec_policy_local) {
                northnarrow_agent::config::overlay_auth::Verified::Content { path, text } => {
                    ep::boot_table(Some((&path, &text)), cli.exec_policy_profile)
                }
                _ => ep::boot_table(None, cli.exec_policy_profile),
            }
        };
        if let Some(detail) = &boot.degraded {
            error!(detail = %detail, "exec policy unreadable — the built-in profile applies");
            // A signed file `overlay set` would refuse (a bad line) found at
            // boot: the operator's table is not in force — a signed
            // degradation, listed by `status --key`, not only a log line.
            northnarrow_agent::boot::degradation::report("exec_policy", detail);
        }
        let ep::BootTable { table, source, .. } = boot;
        ep::Config {
            mode,
            table,
            source,
            env: !cli.exec_policy_no_env,
            map: !cli.exec_policy_no_map,
        }
    };
    let execpol_mode = execpol_cfg.mode;
    // R11c (lab PR 264): the guards, with their configuration, given to the
    // load, which installs them and leaves them their kernel objects (they
    // were process-wide statics the start configured).
    let mut exec_guards =
        northnarrow_agent::exec_guards::AgentExecGuards::new(execq_cfg, execpol_cfg);
    // External audit DEP-006: the previous boot's program-id list goes before
    // this boot loads anything — its programs are replaced now, and a list
    // that cannot be rewritten must not outlive them (the scripts then fall
    // back to their host-wide wait).
    let own_prog_ids_file = own_prog_ids_file(cli);
    if let Some(path) = own_prog_ids_file.as_deref() {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                warn!(error = %e, path = %path.display(), "stale BPF program-id list not removed")
            }
        }
    }
    // Lab PR 219: the exploit guard's task maps, sized at load.
    plan.epg_task_maps = northnarrow_agent::sensors::epg::TaskMaps::for_variant(
        cli.exploit_guard_tasks,
        cli.exploit_guard.variant(),
    );
    let (mut sensor, net_bufs) = match SensorMultiplexer::start_with_net(
        net_wiring,
        &plan,
        &mut exec_guards,
        verified,
    )
    .await
    .context("starting the sensor multiplexer (with net observation)")
    {
        Ok(started) => started,
        // R11b (lab PR 262): a load or a mandatory sensor's attach that
        // fails refuses the start, signed; it needs the loaded object
        Err(e) => {
            let why = format!("{e:#}");
            error!(error = %why, "refusing to start: the eBPF object's load or a sensor's attach failed");
            refusals.refuse(audit.log_mut(), Refusal::new("sensors", why))
        }
    };
    boot.done(BootStep::Sensors)?;
    info!(
        sensors =
            "process_spawn, file_open, exec_check, tcp_connect_v4, tcp_connect_v6, dns_query, \
                   inet_csk_listen_start, tcp_close, udp_sendmsg_outbound",
        "sensor multiplexer attached (including Tappa 10 N2 net observation programs)"
    );

    // Tappa 7: turn ourselves opaque to kill(2) and ptrace(2) before
    // anything spawns child tasks or holds resources we'd hate to
    // leak. Per-hook failures are logged WARN inside the call and
    // tolerated so the agent still runs on kernels without BPF-LSM.
    //
    // Watchdog W6: the watchdog is protected too. External audit
    // MAIN-001: never on the word of `/run/northnarrow/watchdog.pid` —
    // membership also lets a pid signal the agent and pass every inode
    // deny hook. The watchdog's own entry (it registers itself) is kept
    // below while it runs the installed watchdog binary, and the refresh
    // task (`spawn_watchdog_exempt_refresh`, first round right after
    // boot) registers a pid it has verified by `/proc/<pid>/exe`.
    // External audit ATP-002: entries a previous agent left in the pinned
    // map are kept only while they run the agent's or the watchdog's
    // executable, no longer while they merely call themselves so.
    let agent_pid = std::process::id();
    let keep: Vec<northnarrow_agent::anti_tamper::ExeIdentity> = [
        northnarrow_agent::anti_tamper::ExeIdentity::of_file(std::path::Path::new(
            "/proc/self/exe",
        )),
        northnarrow_agent::anti_tamper::ExeIdentity::of_file(&cli.resolved_watchdog_exe()),
    ]
    .into_iter()
    .flatten()
    .collect();
    let pids = vec![agent_pid];
    // Audit `ebpf-lsm-1`: a deny-hook shortfall is fail-closed (the
    // escape hatch is NN_ANTI_TAMPER_ALLOW_DEGRADED=1, handled inside
    // anti_tamper::attach). A kernel without `bpf` in its active LSMs was
    // refused by the preflight above (lab PR 218), or runs under that same
    // opt-in; hooks that attach and never run are the self-test's below.
    let anti_tamper = match sensor
        .attach_anti_tamper(verified, &pids, &keep)
        .with_context(|| {
            format!(
                "anti-tamper setup failed (agent_pid={agent_pid}) — \
                 refusing to start with a silently-absent protection"
            )
        }) {
        Ok(report) => report,
        Err(e) => {
            // R11b (lab PR 262): the deny hooks' shortfall refuses the start,
            // signed; it is the attach's own result. The hooks that attached
            // stay pinned: they protect the agent's files until the next
            // start.
            let why = format!("{e:#}");
            error!(error = %why, "refusing to start: the deny hooks did not attach");
            refusals.refuse(audit.log_mut(), Refusal::new("deny_hooks", why));
        }
    };
    boot.done(BootStep::AntiTamper)?;
    // Lab PR 219: the exploit post-condition guard, attached before the
    // agent's programs are recorded as its own (DEP-006), in detect mode
    // until the no-enforcement gate is resolved below. Off or unavailable
    // is attested once the audit log is open.
    let (exploit_guard, exploit_guard_degraded) =
        match sensor.attach_exploit_guard(verified, cli.exploit_guard.variant()) {
            Ok(guard) => (Some(guard), None),
            Err(_) if cli.exploit_guard == ExploitGuard::Off => (
                None,
                Some(
                    "exploit post-condition guard off (--exploit-guard off / \
                     NN_EXPLOIT_GUARD=off): kernel exploit post-conditions are not watched"
                        .to_string(),
                ),
            ),
            Err(e) => (
                None,
                Some(format!(
                    "exploit post-condition guard unavailable on this kernel: {e} — kernel \
                     exploit post-conditions are not watched"
                )),
            ),
        };
    // External audit DEP-006: the ids install.sh / uninstall.sh wait for.
    record_own_prog_ids(own_prog_ids_file.as_deref(), sensor.ebpf_mut());
    Ok(Attached {
        lineage,
        flow_tracker,
        dns_cache,
        execq_mode,
        execpol_mode,
        exec_guards,
        own_prog_ids_file,
        sensor,
        net_bufs,
        exploit_guard_degraded,
        exploit_guard,
        anti_tamper,
    })
}

/// What [`self_test`] measured.
pub(crate) struct SelfTested {
    pub(crate) self_test: northnarrow_agent::boot::deny_selftest::SelfTestOutcome,
    /// R11c (lab PR 264): the self-test's own denial, which the event loop
    /// takes (a process-wide slot until then).
    pub(crate) expected_denial: northnarrow_agent::boot::deny_selftest::ExpectedDenial,
    /// R11c (lab PR 264): the boot's measurements the trust level is
    /// computed from (the manifest's, the admin socket's status); they were
    /// a process-wide static this phase set.
    pub(crate) trust_inputs: northnarrow_agent::boot::trust::TrustInputs,
}

/// `BootPhase::SelfTest` (lab PR 218, external review AR-09 / G-12): one
/// deny hook exercised against the agent itself; hooks attached but never
/// run refuse the start (signed, `refusals`: into `audit`, the log the
/// integrity phase opened) unless the degraded mode is asked for. It needs
/// the attached hooks: after the attach, by its nature.
#[allow(clippy::too_many_arguments)]
pub(crate) fn self_test(
    boot: &mut BootSequence,
    refusals: &refusal::Context<'_>,
    audit: &mut checks::AuditOpen,
    allow_degraded: bool,
    bpf_lsm_state: &northnarrow_agent::boot::lsm::BpfLsm,
    detect_only: bool,
    anti_tamper: &northnarrow_agent::anti_tamper::AttachReport,
) -> Result<SelfTested> {
    // Lab PR 218 (external review AR-09 / G-12): one deny hook exercised
    // against the agent itself — an unprotected child signals it and must
    // be refused. Hooks attached but not run (`bpf` missing from the active
    // LSMs, Ubuntu) refuse the start unless NN_ANTI_TAMPER_ALLOW_DEGRADED=1;
    // an unmeasured test is signed and lowers the trust level to L1.
    boot.enter(BootPhase::SelfTest)?;
    let (self_test, expected_denial) =
        northnarrow_agent::boot::deny_selftest::run(std::path::Path::new("/proc/self/exe"));
    let self_test_detail = northnarrow_agent::boot::deny_selftest::report(&self_test);
    if self_test == northnarrow_agent::boot::deny_selftest::SelfTestOutcome::NotDenied
        && !allow_degraded
    {
        let detail = self_test_detail.clone().unwrap_or_default();
        error!(
            "refusing to start: {detail}; set {}=1 to start without enforcement. Exiting 78.",
            northnarrow_agent::anti_tamper::ALLOW_DEGRADED_ENV
        );
        refusals.refuse(
            audit.log_mut(),
            Refusal::new("deny_self_test", detail).degraded("deny_self_test"),
        );
    }
    if let Some(detail) = &self_test_detail {
        northnarrow_agent::boot::degradation::report("deny_self_test", detail);
    }
    let trust_inputs = {
        let deny = anti_tamper.deny.clone().unwrap_or_default();
        northnarrow_agent::boot::trust::TrustInputs {
            bpf_lsm: bpf_lsm_state.clone(),
            deny_expected: deny.expected,
            deny_attached: deny.attached,
            self_test: self_test.clone(),
            detect_only,
        }
    };
    boot.done(BootStep::DenySelfTest)?;
    Ok(SelfTested {
        self_test,
        expected_denial,
        trust_inputs,
    })
}

/// External audit DEP-006: where the ids of the agent's loaded BPF programs
/// go — next to `--pid-file` (the unit: `/run/northnarrow/bpf-own-ids`).
/// Without `--pid-file` (the e2e fixtures, a manual run) nothing is
/// written, so the installed agent's list is never overwritten by another.
fn own_prog_ids_file(cli: &Cli) -> Option<PathBuf> {
    cli.pid_file
        .as_deref()
        .and_then(std::path::Path::parent)
        .map(|dir| dir.join(northnarrow_agent::anti_tamper::bpf_defense::OWN_IDS_FILE_NAME))
}

/// Write the program-id list (see [`own_prog_ids_file`]); a failure is a
/// WARN: the scripts then fall back to their older, host-wide wait.
pub(crate) fn record_own_prog_ids(path: Option<&std::path::Path>, ebpf: &aya::Ebpf) {
    let Some(path) = path else {
        return;
    };
    match northnarrow_agent::anti_tamper::bpf_defense::write_own_prog_ids(ebpf, path) {
        Ok(n) => debug!(
            path = %path.display(),
            programs = n,
            "own BPF program ids recorded (install.sh / uninstall.sh wait for them)"
        ),
        Err(e) => warn!(
            error = format!("{e:#}"),
            path = %path.display(),
            "own BPF program ids NOT recorded — install.sh --upgrade and uninstall.sh wait on the \
             list written earlier this boot, or fall back to waiting for no LSM program on the host"
        ),
    }
}
