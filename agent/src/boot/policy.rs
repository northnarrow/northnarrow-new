
/// What [`boot_policy`] loaded.
struct Policy {
    netflow_blocklist: Arc<NetBlocklist>,
    installer_override:
        Arc<northnarrow_agent::anti_tamper::trusted_installer::TrustedInstallerOverride>,
    chain_store:
        Arc<parking_lot::Mutex<northnarrow_agent::decision::correlation::CorrelationStore>>,
    ransom_tracker: Arc<northnarrow_agent::impact::RansomTracker>,
    defense_detector: Arc<northnarrow_agent::impair::DefenseDetector>,
    engine: RuleEngine,
}

/// The signed content and the decision engine: the network blocklists and
/// the optional kernel deny of a connect to them, the comm allowlists, the
/// trusted-installer window, the chain rules' store, the network rules'
/// thresholds, the ransomware tracker and the security-tool detector, the
/// signed per-rule response policy, the rule engine.
fn boot_policy(
    cli: &Cli,
    overlay_gate: &Arc<northnarrow_agent::config::overlay_auth::OverlayGate>,
    sensor: &mut SensorMultiplexer,
    detect_only: bool,
    audit_log: &AuditHandle,
    dns_cache: &Arc<DnsCache>,
    lineage: &AuthSessionTracker,
) -> Policy {
    // Tappa 10 N9 — load operator-curated netflow blocklists from
    // disk + thread them into the decision engine. Load failures
    // degrade gracefully (empty list, like N6 net_rules_empty),
    // so a missing/broken file never blocks agent boot. The
    // production deploy bootstrap (N8 install.sh) ships the v1
    // defaults; missing .local overlay is the normal case for a
    // host without operator-specific block additions.
    // External audit LLMR-013: every loader gets the overlay's text as the
    // gate verified it (one read), never a path to read again; LLMR-016: a
    // `.v1` that cannot be read gives way to the copy built into the agent,
    // recorded.
    let netflow_blocklist = Arc::new(
        NetBlocklist::load::<LinuxHost>(
            &cli.netflow_blocklist_v1,
            &overlay_gate.verified(OverlayKind::NetflowBlocklist, &cli.netflow_blocklist_local),
        )
        .unwrap_or_else(|e| {
            warn!(
                error = %e,
                v1 = %cli.netflow_blocklist_v1.display(),
                local = %cli.netflow_blocklist_local.display(),
                "netflow blocklist load failed — booting with empty blocklist"
            );
            NetBlocklist::empty()
        }),
    );
    report_builtin_defaults(
        overlay_gate,
        "netflow-blocklist",
        &cli.netflow_blocklist_v1,
        netflow_blocklist.defaults(),
    );
    // Lab PR 224 (CM-02 c): the optional kernel deny of a connect to a
    // blocklisted destination, before the late programs are registered as
    // the agent's own (below). A failure leaves it off: NN-L-NET-001 still
    // kills at the connect. Detect-only never arms it (review A.1).
    use northnarrow_agent::sensors::connect_deny::{arming, Arming};
    let connect_deny = arming(cli.net_connect_deny, detect_only);
    if connect_deny == Arming::DetectOnly {
        warn!(
            "connect deny NOT armed: --net-connect-deny is ignored in detect-only, which never \
             refuses a connect (NN-L-NET-001 records the flow at the connect, nothing is killed)"
        );
    }
    if connect_deny == Arming::Arm {
        match northnarrow_agent::sensors::connect_deny::arm(sensor.ebpf_mut(), &netflow_blocklist) {
            Ok(report) => {
                for (entry, why) in &report.skipped {
                    warn!(
                        entry = %entry,
                        why,
                        "connect deny: blocklist entry kept out of the kernel deny \
                         (NN-L-NET-001 still judges it at the connect)"
                    );
                }
                info!(
                    ipv4 = report.v4,
                    ipv6 = report.v6,
                    skipped = report.skipped.len(),
                    "connect deny armed on LSM socket_connect: a connect to a blocklisted \
                     destination is refused in the kernel (--net-connect-deny)"
                );
            }
            Err(e) => {
                error!(
                    error = format!("{e:#}"),
                    "connect deny NOT armed (--net-connect-deny): NN-L-NET-001 kills at the \
                     connect, after the connection is made"
                );
                // Lab PR 218: a requested protection that did not arm is a
                // signed degradation, listed by `status --key`.
                northnarrow_agent::boot::degradation::report_signed(
                    audit_log.as_ref(),
                    "net_connect_deny",
                    &format!(
                        "connect deny not armed (--net-connect-deny): {e:#} — NN-L-NET-001 \
                         kills at the connect, after the connection is made"
                    ),
                    true,
                );
            }
        }
    }
    let ja3_blocklist = Arc::new(
        Ja3Blocklist::load::<LinuxHost>(
            &cli.netflow_ja3_blocklist_v1,
            &overlay_gate.verified(
                OverlayKind::NetflowJa3Blocklist,
                &cli.netflow_ja3_blocklist_local,
            ),
        )
        .unwrap_or_else(|e| {
            warn!(
                error = %e,
                v1 = %cli.netflow_ja3_blocklist_v1.display(),
                local = %cli.netflow_ja3_blocklist_local.display(),
                "netflow ja3 blocklist load failed — booting with empty blocklist"
            );
            Ja3Blocklist::empty()
        }),
    );
    report_builtin_defaults(
        overlay_gate,
        "netflow-ja3-blocklist",
        &cli.netflow_ja3_blocklist_v1,
        ja3_blocklist.defaults(),
    );
    // External audit NET-009 (BUG-025): no sensor produces TLS
    // fingerprints, so a JA3 list with entries protects nothing. Said at
    // boot, and in the signed chain once the audit log is open (below).
    northnarrow_agent::net::blocklist::note_ja3_entries(ja3_blocklist.len());
    let ja3_gap = northnarrow_agent::net::blocklist::ja3_coverage_gap(
        ja3_blocklist.len(),
        northnarrow_agent::net::blocklist::TLS_FINGERPRINT_PRODUCER,
    );
    if let Some(gap) = &ja3_gap {
        error!(
            v1 = %cli.netflow_ja3_blocklist_v1.display(),
            local = %cli.netflow_ja3_blocklist_local.display(),
            "{gap}"
        );
        // External audit NET-009: the JA3 list with no producer.
        attest_degraded(audit_log.as_ref(), gap);
    }
    // External audit NET-017 (lab PR 207): systemd-resolved on DNS over TLS
    // hides its upstream queries from the DNS rules. Said at boot; `nn-admin
    // net status` reads the setting again at each request.
    if let Some(dot) = northnarrow_agent::net::blind_spots::resolver_dns_over_tls() {
        warn!(
            "{}",
            northnarrow_agent::net::blind_spots::dns_blind_rule(&dot)
        );
    }
    let burst_window = Arc::new(parking_lot::Mutex::new(
        northnarrow_agent::decision::rules::net::DnsBurstWindow::new(),
    ));

    // Tappa 10.5 D4: per-family netflow comm allowlist (the comm-gated
    // net rules NN-L-NET-006/007/009/010/011/013/018/019 consult it)
    // + the NN-L-NET-013 beacon-timing window. Same fail-soft contract
    // as the netflow blocklists — a missing/broken file boots with an
    // empty allowlist.
    let netflow_comm_allowlist = Arc::new(
        northnarrow_agent::config::comm_allowlist::load_comm_allowlist(
            "netflow-comm-allowlist",
            &cli.netflow_comm_allowlist_v1,
            northnarrow_agent::config::comm_allowlist::NETFLOW_COMM_ALLOWLIST_SHIPPED,
            &overlay_gate.verified(
                OverlayKind::NetflowCommAllowlist,
                &cli.netflow_comm_allowlist_local,
            ),
        )
        .unwrap_or_else(|e| {
            warn!(
                error = %e,
                v1 = %cli.netflow_comm_allowlist_v1.display(),
                local = %cli.netflow_comm_allowlist_local.display(),
                "netflow-comm allowlist load failed — booting with empty allowlist"
            );
            northnarrow_agent::config::comm_allowlist::CommAllowlist::default()
        }),
    );
    report_builtin_defaults(
        overlay_gate,
        "netflow-comm-allowlist",
        &cli.netflow_comm_allowlist_v1,
        netflow_comm_allowlist.defaults(),
    );
    let beacon_window = Arc::new(parking_lot::Mutex::new(
        northnarrow_agent::decision::rules::net::BeaconWindow::new(),
    ));

    // Tappa 10.5 D2: load the process-comm allowlist for the
    // R011..R017 process rules. Same fail-soft contract as the
    // netflow blocklists — a missing/broken file boots with an empty
    // allowlist (the rules then fire purely on their predicates).
    let process_allowlist = Arc::new(
        northnarrow_agent::config::comm_allowlist::load_comm_allowlist(
            "process-comm-allowlist",
            &cli.process_comm_allowlist_v1,
            northnarrow_agent::config::comm_allowlist::PROCESS_COMM_ALLOWLIST_SHIPPED,
            &overlay_gate.verified(
                OverlayKind::ProcessCommAllowlist,
                &cli.process_comm_allowlist_local,
            ),
        )
        .unwrap_or_else(|e| {
            warn!(
                error = %e,
                v1 = %cli.process_comm_allowlist_v1.display(),
                local = %cli.process_comm_allowlist_local.display(),
                "process-comm allowlist load failed — booting with empty allowlist"
            );
            northnarrow_agent::config::comm_allowlist::CommAllowlist::default()
        }),
    );
    report_builtin_defaults(
        overlay_gate,
        "process-comm-allowlist",
        &cli.process_comm_allowlist_v1,
        process_allowlist.defaults(),
    );

    // FIM-009 self-upgrade (§15.1): construct the trusted-installer
    // override BEFORE the engine so the NN-L-FIM-009 rule can hold a read
    // handle (wired next commit). The bpffs maps were pinned +
    // boot-zeroed by the sensor multiplexer's anti_tamper::attach above;
    // the audit-chain writer is late-bound below once the AuditLog opens.
    let installer_override =
        northnarrow_agent::anti_tamper::trusted_installer::TrustedInstallerOverride::boot(
            northnarrow_agent::anti_tamper::prepare_pin_root().map(|p| p.to_path_buf()),
            None,
        );

    // External audit NET-019: the chain rules' correlation store, shared
    // with the netflow limiter (a process with a chain precursor always
    // has its flows evaluated).
    let chain_store = Arc::new(parking_lot::Mutex::new(
        northnarrow_agent::decision::correlation::CorrelationStore::new(),
    ));
    // Lab PR 224: the host's configured resolvers (the port-53 exemption of
    // NN-L-NET-008 and NN-L-CHAIN-002/005) and the fan-out thresholds
    // (NN-L-NET-026/027).
    let net_rule_config = northnarrow_agent::decision::rules::net::NetRuleConfig {
        resolvers: northnarrow_agent::net::resolvers::HostResolvers::for_host(),
        fanout: Arc::new(
            northnarrow_agent::decision::rules::net_fanout::FanoutConfig {
                scan_window_ns: cli.net_scan_window_secs * 1_000_000_000,
                scan_hosts: cli.net_scan_hosts,
                scan_pairs: cli.net_scan_pairs,
                scan_kill_hosts: cli.net_scan_kill_hosts,
                brute_window_ns: cli.net_brute_window_secs * 1_000_000_000,
                brute_connects: cli.net_brute_connects,
                brute_kill_connects: cli.net_brute_kill_connects,
                exempt: cli.net_fanout_exempt.clone(),
                // Held behind the per-rule policy (off by default).
                ..Default::default()
            },
        ),
    };
    info!(
        resolvers = ?net_rule_config.resolvers.snapshot(),
        scan_hosts = cli.net_scan_hosts,
        scan_pairs = cli.net_scan_pairs,
        scan_kill_hosts = cli.net_scan_kill_hosts,
        scan_window_secs = cli.net_scan_window_secs,
        brute_connects = cli.net_brute_connects,
        brute_kill_connects = cli.net_brute_kill_connects,
        brute_window_secs = cli.net_brute_window_secs,
        fanout_exempt_extra = ?cli.net_fanout_exempt,
        "network rules: configured resolvers (port-53 exemption) and fan-out thresholds"
    );
    // Lab PR 225: the ransomware tracker (NN-L-IMP-001/002) and the
    // security-tool detector (NN-L-EVA-001..004) the rules and the posture
    // share; the list of security tools is the shipped content
    // `security-tools.v1`.
    let ransom_tracker = Arc::new(northnarrow_agent::impact::RansomTracker::new(
        lineage.clone(),
    ));
    let security_tools_v1 = std::path::Path::new(northnarrow_agent::impair::SECURITY_TOOLS_V1);
    let (security_tools, security_tools_defaults) =
        northnarrow_agent::impair::SecurityTools::load::<LinuxHost>(security_tools_v1);
    report_builtin_defaults(
        overlay_gate,
        "security-tools",
        security_tools_v1,
        &security_tools_defaults,
    );
    let defense_detector = Arc::new(northnarrow_agent::impair::DefenseDetector::new(
        Arc::new(security_tools),
        lineage.clone(),
        Some(Arc::new(
            process_allowlist
                .as_ref()
                .clone()
                .with_identity(lineage.clone()),
        )),
    ));
    // Lab PR 236: the signed per-rule response policy, read once through the
    // overlay gate (absent or refused: the built-in defaults — every held
    // kill held). A signed file that does not parse leaves the defaults in
    // force, a signed degradation.
    {
        use northnarrow_agent::config::overlay_auth::Verified;
        use northnarrow_agent::decision::rule_policy as rp;
        let boot = match overlay_gate.verified(OverlayKind::RulePolicy, &cli.rule_policy_local) {
            Verified::Content { path, text } => rp::boot_policy(Some((&path, &text))),
            _ => rp::boot_policy(None),
        };
        if let Some(detail) = &boot.degraded {
            error!(detail = %detail, "per-rule policy unreadable — the built-in defaults apply");
            northnarrow_agent::boot::degradation::report("rule_policy", detail);
        }
        let policy = boot.policy;
        if !policy.is_builtin() {
            warn!(
                source = %policy.source,
                summary = %policy.summary(),
                "per-rule response policy in force"
            );
            overlay_gate.record_note(
                rp::AUDIT_OP_LOADED,
                "success",
                serde_json::json!({
                    "source": policy.source,
                    "summary": policy.summary(),
                    "at_boot": true,
                }),
            );
        } else {
            info!("per-rule response policy: built-in defaults (every held kill held)");
        }
        rp::install_global(policy);
    }
    let engine = RuleEngine::with_default_rules_and_net(
        Arc::clone(&netflow_blocklist),
        Arc::clone(&ja3_blocklist),
        Arc::clone(&burst_window),
        Arc::clone(&process_allowlist),
        Arc::clone(&netflow_comm_allowlist),
        Arc::clone(&beacon_window),
        // FP-3: the SAME DnsCache the DnsQuery pump feeds — NN-L-NET-004/
        // -014 read its reverse index to back-correlate a forwarded leg
        // to the originating process instead of the stub resolver.
        Arc::clone(dns_cache),
        // FIM-009 self-upgrade (§15.1): the NN-L-FIM-009 rule reads this
        // override; the admin dispatcher arms it on a signed grant.
        Arc::clone(&installer_override),
        lineage.clone(),
        // External audit DEC-005: the built-in readers of whole trees plus
        // the operator's signed canary-readers.local.
        northnarrow_agent::canary::readers::CanaryReaders::load(
            &overlay_gate.verified(
                OverlayKind::CanaryReaders,
                std::path::Path::new(northnarrow_agent::canary::readers::CANARY_READERS_LOCAL),
            ),
            lineage.clone(),
        ),
        Arc::clone(&chain_store),
        net_rule_config,
        Arc::clone(&ransom_tracker),
        Arc::clone(&defense_detector),
    )
    .with_policy(northnarrow_agent::decision::rule_policy::global().clone());
    // External audit PROC-015 / PROC-014: a demo build runs R901..R904
    // ahead of the production engine (operator state included), and
    // enforces only under the demo-rules gate below.
    #[cfg(feature = "demo-tappa5")]
    let engine = engine.with_demo_tappa5_first();
    info!(
        rules = engine.rule_count(),
        demo_tappa5 = cfg!(feature = "demo-tappa5"),
        netflow_blocklist_entries = netflow_blocklist.len(),
        ja3_blocklist_entries = ja3_blocklist.len(),
        process_comm_allowlist_entries = process_allowlist.len(),
        netflow_comm_allowlist_entries = netflow_comm_allowlist.len(),
        "decision engine ready"
    );
    Policy {
        netflow_blocklist,
        installer_override,
        chain_store,
        ransom_tracker,
        defense_detector,
        engine,
    }
}

/// External audit LLMR-016: a default list that could not be read, and
/// gave way to the copy built into the agent, is recorded in the signed
/// chain through the overlay gate (queued until the audit log is open);
/// LLMR-015 (NN-AUD-327): so is one edited by hand, which is not applied.
/// An earlier release's list, superseded by the built-in copy, is a WARN
/// only: what is in force is what shipped.
fn report_builtin_defaults(
    gate: &northnarrow_agent::config::overlay_auth::OverlayGate,
    list: &str,
    v1: &std::path::Path,
    source: &northnarrow_agent::config::overlay::DefaultsSource,
) {
    use northnarrow_agent::config::overlay::DefaultsSource;
    match source {
        DefaultsSource::BuiltIn(why) => gate.report_default_unavailable(list, v1, why),
        DefaultsSource::Modified {
            sha256,
            builtin_sha256,
            loaded_anyway,
        } => gate.report_default_modified(list, v1, sha256, builtin_sha256, *loaded_anyway),
        DefaultsSource::Disk | DefaultsSource::Superseded { .. } => {}
    }
}

/// Lab PR 160: the head anchor of this run, written once now with the heads
/// this boot found (before this boot appends anything). Reports a removed
/// anchor first ([`northnarrow_agent::chain_anchor::BootCheck::heads_missing`]).
fn start_chain_anchor(
    cli: &Cli,
    heads_file: &std::path::Path,
    targets: &[northnarrow_agent::chain_anchor::ChainTarget],
    boot: &mut northnarrow_agent::chain_anchor::BootCheck,
    agent_id: [u8; 16],
    log: &northnarrow_agent::audit::AuditLog,
) -> Option<Arc<parking_lot::Mutex<northnarrow_agent::chain_anchor::Anchor>>> {
    boot.heads_missing(heads_file, log.anchoring_started());
    let key =
        match northnarrow_agent::audit::AgentSigningKey::load_or_bootstrap(&cli.signing_key_file) {
            Ok(k) => k,
            Err(e) => {
                warn!(
                    error = format!("{e:#}"),
                    "chain heads: no signing key — heads not anchored"
                );
                return None;
            }
        };
    let mut anchor = northnarrow_agent::chain_anchor::Anchor::new(
        heads_file.to_path_buf(),
        key,
        agent_id,
        targets.to_vec(),
        boot.previous.clone(),
        log.anchoring_started(),
    );
    let second = log.second_key_added() || boot.second_key_added();
    match anchor.refresh(true, second) {
        Ok(_) => info!(path = %heads_file.display(), "chain heads anchored at start"),
        Err(e) => warn!(
            error = format!("{e:#}"),
            path = %heads_file.display(),
            "chain heads: not anchored at start (retried every few minutes)"
        ),
    }
    Some(Arc::new(parking_lot::Mutex::new(anchor)))
}

/// Lab PR 160: what a chain's open verification found (external audit
/// NN-AUD-174), in the signed audit chain.
fn attest_chain_findings(
    audit_log: Option<&Arc<parking_lot::Mutex<northnarrow_agent::audit::AuditLog>>>,
    findings: Vec<northnarrow_agent::chain_anchor::ChainFinding>,
) {
    if findings.is_empty() {
        return;
    }
    let mut guard = audit_log.map(|l| l.lock());
    for f in &findings {
        f.attest(guard.as_deref_mut());
    }
}

/// External audit DEC-006 / NET-003: what a chain log's open repaired or
/// skipped is recorded in the signed audit chain.
fn attest_open_findings(
    audit_log: Option<&Arc<parking_lot::Mutex<northnarrow_agent::audit::AuditLog>>>,
    file: &std::path::Path,
    (repair, skipped): (Option<northnarrow_agent::chainlog::TailRepair>, usize),
) {
    let Some(log) = audit_log else {
        return;
    };
    let mut log = log.lock();
    if let Some(r) = repair {
        if let Err(e) = log.attest_tail_repair(file, &r) {
            warn!(error = %e, file = %file.display(), "attesting a chain repair failed");
        }
    }
    if skipped > 0 {
        if let Err(e) = log.attest_skipped_lines(file, skipped) {
            warn!(error = %e, file = %file.display(), "attesting skipped chain lines failed");
        }
    }
}

/// Beta Step 3: background task that keeps the watchdog PID slot of
/// `exempt` in sync with the live, exe-verified watchdog.
///
/// Re-resolves every 30 s (the first tick fires immediately so the
/// exemption activates as soon as the watchdog publishes its pidfile).
/// Logs only on a *change* of verified PID so a steady state doesn't
/// flood the journal; any non-`Verified` outcome clears the exemption
/// (fail toward over-triggering).
/// External audit EBPF-001: systemd (PID 1 itself, `SO_PEERCRED`) reported
/// the host as stopping — no posture escalation and no ladder until the
/// process ends at systemd-shutdown's final stage.
static HOST_STOPPING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// External audit CMB-012: how long the COMBAT release waits for the
/// ladder's queued steps (a NEUTRALIZE of a large tree takes seconds)
/// before it lifts the isolation anyway.
const LADDER_RELEASE_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// The host is shutting down: stand the ladder down once and stop
/// escalating (see [`HOST_STOPPING`]).
fn host_stopping(ladder: &northnarrow_agent::combat::CombatLadder) {
    if !HOST_STOPPING.swap(true, std::sync::atomic::Ordering::SeqCst) {
        warn!("host shutting down — active response stood down, detection continues");
        ladder.stand_down(Instant::now());
    }
}

/// What systemd reports the host as (`SystemState`: `running`,
/// `degraded`, `stopping`, …), asked over its private socket from this
/// process ([`northnarrow_agent::systemd_state`]) — only for a signal PID 1
/// relayed and the kernel refused, and every 2 s by the shutdown watch;
/// at most once a second. `None` when
/// systemd does not answer within 1 s, or the socket is not served by
/// PID 1.
async fn systemd_state() -> Option<String> {
    static LAST: parking_lot::Mutex<Option<(Instant, Option<String>)>> =
        parking_lot::Mutex::new(None);
    if let Some((at, state)) = LAST.lock().clone() {
        if at.elapsed() < Duration::from_secs(1) {
            return state;
        }
    }
    let ask = tokio::task::spawn_blocking(|| {
        northnarrow_agent::systemd_state::system_state(
            std::path::Path::new(northnarrow_agent::systemd_state::PRIVATE_SOCKET),
            Duration::from_millis(800),
        )
    });
    let state = match tokio::time::timeout(Duration::from_secs(1), ask).await {
        Ok(Ok(Ok(state))) => Some(state),
        Ok(Ok(Err(e))) => {
            debug!(error = %e, "systemd's state could not be read");
            None
        }
        _ => None,
    };
    *LAST.lock() = Some((Instant::now(), state.clone()));
    state
}

/// PID 1 is `systemd-shutdown` (its comm, truncated to 15 bytes): the
/// machine is in the last stage of a shutdown.
fn pid1_is_systemd_shutdown() -> bool {
    std::fs::read_to_string("/proc/1/comm").is_ok_and(|c| c.trim_end() == "systemd-shutdow")
}

/// External audit EBPF-001: re-record `systemd-shutdown`'s identity every
/// minute (a package upgrade gives it a new inode).
fn spawn_shutdown_exe_refresh() {
    let Some(root) = northnarrow_agent::anti_tamper::prepare_pin_root() else {
        return;
    };
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            match northnarrow_agent::anti_tamper::refresh_shutdown_exe(root) {
                Ok(Some(k)) => info!(
                    dev = k.dev,
                    ino = k.ino,
                    "anti-tamper: systemd-shutdown changed on disk — final-stage identity updated"
                ),
                Ok(None) => {}
                Err(e) => warn!(
                    error = format!("{e:#}"),
                    "anti-tamper: SHUTDOWN_EXE refresh failed"
                ),
            }
        }
    });
}

/// The signed audit log, as the watchdog refresh gets it once it is open.
type WatchdogAudit = Option<Arc<parking_lot::Mutex<northnarrow_agent::audit::AuditLog>>>;

fn spawn_watchdog_exempt_refresh(
    exempt: ExemptPids,
    pidfile: PathBuf,
    expected_exe: PathBuf,
    audit: Arc<std::sync::OnceLock<WatchdogAudit>>,
) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        // Last verified PID we stored (`None` == exemption cleared).
        let mut last: Option<u32> = None;
        // A pid the pidfile named while the registered watchdog ran (logged once).
        let mut refused: Option<u32> = None;
        // BUG-011 (PHASE 15.1): resolve the bpffs root once. None ⇒
        // no bpffs ⇒ register_protected_observer is a no-op (it
        // logs the degraded mode internally).
        let bpffs_root = northnarrow_agent::anti_tamper::prepare_pin_root();
        loop {
            tick.tick().await;
            let resolution = resolve_verified_watchdog_pid(&pidfile, &expected_exe);
            let new_pid = match &resolution {
                WatchdogResolution::Verified { pid, .. } => Some(*pid),
                _ => None,
            };
            if new_pid == last {
                // External audit POS-009: the posture exemption follows the
                // start of the process verified now (a restart that drew the
                // same PID).
                if let WatchdogResolution::Verified { pid, start_ticks } = &resolution {
                    exempt.set_watchdog(*pid, *start_ticks);
                }
                continue; // no change — stay quiet on the hot path
            }
            // External audit EBPF-002: one watchdog at a time. While the
            // registered watchdog still runs, a pidfile naming another
            // process — even one running the watchdog binary, possibly with
            // LD_PRELOAD — is not protected: rewritten or mounted over, it
            // would hand a root shell's process the agent's maps.
            if let (Some(prev), Some(p)) = (last, new_pid) {
                if runs_watchdog_binary(prev, &expected_exe) {
                    if refused != Some(p) {
                        warn!(
                            registered = prev,
                            named = p,
                            "the watchdog pidfile names another process while the registered \
                             watchdog runs — not protected"
                        );
                        refused = Some(p);
                    }
                    continue;
                }
            }
            // External audit MAIN-001: PROTECTED_PIDS follows the verified
            // watchdog. The previous pid leaves it once it no longer runs
            // the watchdog binary (dead, or recycled by another program);
            // a deleted or rewritten pidfile alone does not unprotect the
            // watchdog that still runs.
            if let Some(prev) = last {
                // Lab PR 216: a watchdog gone is signed, once per pid.
                if !runs_watchdog_binary(prev, &expected_exe) {
                    let f = northnarrow_agent::self_integrity::watchdog_gone(prev, &resolution);
                    let log = audit.get().and_then(|l| l.as_ref());
                    northnarrow_agent::self_integrity::report_event(log, &f);
                }
                withdraw_watchdog_pid(bpffs_root, prev, &expected_exe);
            }
            if let Some(p) = new_pid {
                if let Err(e) =
                    northnarrow_agent::anti_tamper::register_protected_pid(bpffs_root, p)
                {
                    warn!(watchdog_pid = p, error = %e, "PROTECTED_PIDS register of the verified watchdog failed");
                }
                // External audit EBPF-002: the verified watchdog is the
                // live one — no second watchdog binary may load beside it.
                if let Err(e) = northnarrow_agent::anti_tamper::claim_watchdog_role(bpffs_root, p) {
                    debug!(watchdog_pid = p, error = %e, "watchdog role not recorded");
                }
            }
            match &resolution {
                WatchdogResolution::Verified {
                    pid: p,
                    start_ticks,
                } => {
                    // External audit POS-009: with its start time — the
                    // exemption ends with that process, not with its PID.
                    exempt.set_watchdog(*p, *start_ticks);
                    // BUG-011: register the verified watchdog PID
                    // in PROTECTED_OBSERVERS so the kernel
                    // ptrace_access_check hook allows it to read
                    // /proc/<agent>/exe (the watchdog's argv
                    // reconstruction path). Eviction of the prior
                    // verified PID (if any) happens first to keep
                    // the map's set semantics tight — a watchdog
                    // restart with a new PID otherwise leaves the
                    // old PID lingering for whatever else might
                    // recycle it.
                    if let Some(prev) = last {
                        if let Err(e) = northnarrow_agent::anti_tamper::evict_protected_observer(
                            bpffs_root, prev,
                        ) {
                            warn!(
                                pid = prev,
                                error = %e,
                                "BUG-011: failed to evict prior watchdog PID from \
                                 PROTECTED_OBSERVERS (continuing; new PID will still register)"
                            );
                        }
                    }
                    match northnarrow_agent::anti_tamper::register_protected_observer(
                        bpffs_root, *p,
                    ) {
                        Ok(()) => info!(
                            watchdog_pid = *p,
                            start_ticks = *start_ticks,
                            exe = %expected_exe.display(),
                            "watchdog PID verified; exempting it from posture triggers + \
                             registering in PROTECTED_OBSERVERS (BUG-011)"
                        ),
                        Err(e) => warn!(
                            watchdog_pid = *p,
                            error = %e,
                            "BUG-011: PROTECTED_OBSERVERS register failed; watchdog \
                             will still be posture-exempt but ptrace_access_check will deny"
                        ),
                    }
                }
                WatchdogResolution::NotPresent => {
                    exempt.clear_watchdog();
                    // BUG-011: withdraw observer rights on watchdog
                    // teardown so a recycled PID can't inherit them.
                    if let Some(prev) = last {
                        let _ = northnarrow_agent::anti_tamper::evict_protected_observer(
                            bpffs_root, prev,
                        );
                    }
                    info!(
                        pidfile = %pidfile.display(),
                        "watchdog pidfile absent; no watchdog exemption active"
                    );
                }
                WatchdogResolution::InvalidPidfile { reason } => {
                    exempt.clear_watchdog();
                    if let Some(prev) = last {
                        let _ = northnarrow_agent::anti_tamper::evict_protected_observer(
                            bpffs_root, prev,
                        );
                    }
                    warn!(%reason, "watchdog pidfile unparseable; watchdog exemption cleared");
                }
                WatchdogResolution::Unverifiable { pid, reason } => {
                    exempt.clear_watchdog();
                    if let Some(prev) = last {
                        let _ = northnarrow_agent::anti_tamper::evict_protected_observer(
                            bpffs_root, prev,
                        );
                    }
                    warn!(pid, %reason, "watchdog exe verification failed; exemption cleared");
                }
                WatchdogResolution::ExeMismatch { pid, resolved } => {
                    exempt.clear_watchdog();
                    if let Some(prev) = last {
                        let _ = northnarrow_agent::anti_tamper::evict_protected_observer(
                            bpffs_root, prev,
                        );
                    }
                    warn!(
                        pid,
                        resolved = %resolved.display(),
                        expected = %expected_exe.display(),
                        "watchdog PID maps to an unexpected binary (PID reuse or \
                         substitution); exemption refused"
                    );
                }
            }
            last = new_pid;
        }
    });
}

/// Best-effort compatibility record for a Beta Step 4a stale-COMBAT
/// reconcile: one JSONL line in
/// [`northnarrow_agent::combat::reconcile::LOG_PATH`]; a write failure is
/// logged but never fatal — the teardown it records has already happened,
/// and the signed `integrity_drift` (`combat_reconcile`) is the evidence
/// (external audit MAIN-013). Lab follow-up (lab PR 188): written once the
/// state directory's protection exists, a missing file created inside
/// `protection`'s dance ([`northnarrow_agent::combat::reconcile::record_line`]).
fn audit_combat_reconcile(
    protection: &dyn northnarrow_agent::chainlog::ProtectionManager,
    rules_removed: usize,
) {
    use northnarrow_agent::combat::reconcile::{record_line, CAP_BYTES, LOG_PATH};
    // BUG-026 B-cap: combat-audit is the lone UNSIGNED / unchained
    // best-effort log (BUG-028). `/var/lib/northnarrow` is `chattr +i`, so
    // a rename-based rotate is a blocked dir-entry op — capped by
    // TRUNCATE-IN-PLACE (a content op, allowed under `+i`).
    if let Err(e) = record_line(
        std::path::Path::new(LOG_PATH),
        rules_removed,
        CAP_BYTES,
        protection,
    ) {
        warn!(
            error = format!("{e:#}"),
            path = LOG_PATH,
            "could not write COMBAT reconcile audit line (non-fatal)"
        );
    }
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
fn record_own_prog_ids(path: Option<&std::path::Path>, ebpf: &aya::Ebpf) {
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

/// Atomically publish the current PID to `path` (Tappa 7 task 6
/// #2b-verify). A sibling tempfile is written then `rename(2)`d over
/// the target, so the rename is a same-filesystem atomic swap and a
/// concurrent reader observes either the old file or the complete new
/// one — never a truncated or empty file. The tempfile name carries
/// the PID so two agents misconfigured onto one path cannot corrupt
/// each other's tempfile mid-write. Every error is contextualised and
/// propagated (never swallowed) so the caller can make it fatal and a
/// failing harness can pinpoint which syscall failed.
fn write_pid_file(path: &std::path::Path) -> Result<()> {
    let pid = std::process::id();
    if path.file_name().is_none() {
        anyhow::bail!(
            "--pid-file path has no file-name component: {}",
            path.display()
        );
    }
    // External audit WDG-015 (NN-AUD-364): `/run/northnarrow` is writable
    // by root and outside the inode deny set, and the agent is a process
    // the hooks trust: its temporary file (`agent.pid.tmp.<pid>`, written
    // with `fs::write`) followed a link planted at that predictable name.
    // The AUT-003 writer removes whatever sits at the temporary name and
    // creates it exclusively, then renames it into place. A missing parent
    // directory still fails here, at startup, loudly.
    northnarrow_agent::atomic_file::write_pidfile(path, pid)
        .with_context(|| format!("writing PID file {} (atomic replace)", path.display()))?;

    info!(
        target: "anti-tamper",
        path = %path.display(),
        pid,
        "pid_file written (atomic tempfile+rename; existence == post-attach readiness gate)"
    );
    Ok(())
}

/// Raise the soft `RLIMIT_NOFILE` to the hard limit (at most 65 536).
/// Returns the new soft limit.
fn raise_nofile_rlimit() -> std::io::Result<u64> {
    let mut rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: a valid `rlimit` to fill.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let want = rlim.rlim_max.min(65_536);
    if rlim.rlim_cur >= want {
        return Ok(rlim.rlim_cur);
    }
    rlim.rlim_cur = want;
    // SAFETY: a valid `rlimit` passed by reference; the kernel only reads it.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(want)
}

/// Raise `RLIMIT_MEMLOCK` to infinity so older kernels accept large
/// eBPF map allocations. Best-effort: failure is logged and ignored.
fn bump_memlock_rlimit() -> std::io::Result<()> {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: a valid `rlimit` is passed by reference; the kernel only
    // reads from it. Failure is reported via the return code.
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// `--btf-check`: resolve the runtime offset table against a BTF file and
/// print a one-line verdict plus every drifted or missing entry.
fn btf_check(path: &std::path::Path) -> i32 {
    use northnarrow_agent::anti_tamper::btf_revalidate::resolve_offsets_from;
    match resolve_offsets_from(path) {
        ResolveOutcome::Resolved(r) => {
            println!(
                "btf-check {}: {} — {} slots resolved, {} differ from the build kernel, {} absent, {} hook arguments checked",
                path.display(),
                if r.absent.is_empty() {
                    "SUPPORTED"
                } else {
                    "SUPPORTED (degraded)"
                },
                r.values.len(),
                r.drifted.len(),
                r.absent.len(),
                r.hook_args_checked
            );
            for m in &r.absent {
                let effect = if m.struct_name.starts_with("bpf_lsm_") {
                    format!(
                        "not attached: {} (the agent starts only with NN_ANTI_TAMPER_ALLOW_DEGRADED=1)",
                        northnarrow_agent::anti_tamper::btf_revalidate::hook_arg_effect(m.struct_name)
                    )
                } else {
                    "dependent sensor path disabled".to_string()
                };
                println!(
                    "  absent  {:<34} {:<12} {} — {effect}",
                    m.name, m.struct_name, m.detail
                );
            }
            // Lab PR 174: the deny hooks only some kernels have, counted
            // as expected where the BTF has them.
            for (hook, present) in &r.optional_deny_hooks {
                let verdict = if *present {
                    format!(
                        "present — bpf_lsm_{hook} in the BTF: its deny program attaches and counts as an expected deny hook"
                    )
                } else {
                    format!("absent  — no bpf_lsm_{hook} in the BTF: no deny program on it, not expected")
                };
                println!("  optional {hook:<33} {verdict}");
            }
            for module in &r.modules_not_loaded {
                println!(
                    "  module  {module:<34} no BTF next to the vmlinux file — its types' offsets stay unset (not a degradation)"
                );
            }
            for m in &r.drifted {
                println!(
                    "  drift   {:<34} {:<12} compiled={:<6} runtime={}",
                    m.name,
                    m.struct_name,
                    m.expected,
                    m.actual
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "?".into())
                );
            }
            0
        }
        ResolveOutcome::SkippedNoBtf { reason } => {
            println!("btf-check {}: UNREADABLE — {reason}", path.display());
            3
        }
        ResolveOutcome::Refuse(RefuseReason::Drift(missing)) => {
            println!(
                "btf-check {}: NOT SUPPORTED — {} field(s)/enumerator(s)/hook argument(s) missing (the agent would refuse to start)",
                path.display(),
                missing.len()
            );
            for m in &missing {
                println!(
                    "  missing {:<34} {:<12} {}",
                    m.name, m.struct_name, m.detail
                );
            }
            2
        }
        ResolveOutcome::Refuse(RefuseReason::ParseError(e)) => {
            println!("btf-check {}: UNPARSEABLE — {e}", path.display());
            3
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wave 4 (lab PR 214): a unit written for an agent with the LLM
    /// advisor still parses — its flags are accepted, ignored and named.
    #[test]
    fn the_removed_advisor_flags_still_parse_and_are_named() {
        let cli = Cli::try_parse_from([
            "northnarrow-agent",
            "--no-ade",
            "--ade-model",
            "/var/lib/northnarrow/models/m.gguf",
            "--ade-timeout",
            "15",
            "--ade-prompt",
            "dataset/system_prompt_v1.md",
            "--ade-threads",
            "3",
            "--detect-only",
        ])
        .expect("an old unit's command line parses");
        assert_eq!(
            cli.removed_flags(),
            northnarrow_agent::removed_settings::REMOVED_FLAGS
        );
        assert!(cli.detect_only, "the other flags keep their meaning");

        let cli = Cli::try_parse_from(["northnarrow-agent", "--ade-timeout", "not-a-number"])
            .expect("a removed flag's value is not parsed");
        assert_eq!(cli.removed_flags(), ["--ade-timeout"]);

        let cli = Cli::try_parse_from(["northnarrow-agent"]).unwrap();
        assert!(cli.removed_flags().is_empty());
    }

    /// Lab (21/10, debian12): an agent unit with `NN_NET_CONNECT_DENY=1`,
    /// the value the help and the CHANGELOG give, did not start — exit 2,
    /// "invalid value '1' for '--net-connect-deny'" (clap's plain bool
    /// parser takes only `true` / `false` from the environment) — and the
    /// watchdog held. An environment switch reads 1/0, true/false, yes/no,
    /// on/off; anything else is refused, never read as on.
    #[test]
    fn env_switches_read_1_and_0() {
        const SWITCHES: &[(&str, &str)] = &[
            ("NN_NET_CONNECT_DENY", "--net-connect-deny"),
            ("NN_EXEC_POLICY_NO_ENV", "--exec-policy-no-env"),
            ("NN_EXEC_POLICY_NO_MAP", "--exec-policy-no-map"),
        ];
        fn get(cli: &Cli, flag: &str) -> bool {
            match flag {
                "--net-connect-deny" => cli.net_connect_deny,
                "--exec-policy-no-env" => cli.exec_policy_no_env,
                "--exec-policy-no-map" => cli.exec_policy_no_map,
                _ => unreachable!("{flag}"),
            }
        }
        let clear = || {
            for (env, _) in SWITCHES {
                std::env::remove_var(env);
            }
        };
        clear();
        let cli = Cli::try_parse_from(["northnarrow-agent"]).unwrap();
        for (_, flag) in SWITCHES {
            assert!(!get(&cli, flag), "{flag} off by default");
            let cli = Cli::try_parse_from(["northnarrow-agent", flag]).unwrap();
            assert!(get(&cli, flag), "{flag} on the command line");
        }
        for (value, on) in [
            ("1", true),
            ("true", true),
            ("yes", true),
            ("on", true),
            ("0", false),
            ("false", false),
            ("no", false),
            ("off", false),
        ] {
            for (env, flag) in SWITCHES {
                std::env::set_var(env, value);
                let cli = Cli::try_parse_from(["northnarrow-agent"]);
                std::env::remove_var(env);
                let cli = cli.unwrap_or_else(|e| panic!("{env}={value}: {e}"));
                assert_eq!(get(&cli, flag), on, "{env}={value}");
            }
        }
        for (env, _) in SWITCHES {
            std::env::set_var(env, "maybe");
            let r = Cli::try_parse_from(["northnarrow-agent"]);
            std::env::remove_var(env);
            assert!(r.is_err(), "{env}=maybe is refused, not read as on");
        }
        clear();
    }

    /// The removed flags are hidden: `--help` no longer offers them.
    #[test]
    fn the_removed_advisor_flags_are_not_in_the_help() {
        use clap::CommandFactory;
        let help = Cli::command().render_long_help().to_string();
        for flag in northnarrow_agent::removed_settings::REMOVED_FLAGS {
            assert!(!help.contains(flag), "{flag} in:\n{help}");
        }
    }
}
