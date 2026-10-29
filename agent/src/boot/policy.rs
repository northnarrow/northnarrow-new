//! The signed content and the decision engine (R11a, lab PR 261: from
//! `main.rs`'s `run`).

use std::sync::Arc;

use nn_proto::admin_signed_payload::OverlayKind;
use northnarrow_agent::chain_host_linux::LinuxHost;
use northnarrow_agent::decision::RuleEngine;
use northnarrow_agent::net::blocklist::{Ja3Blocklist, NetBlocklist};
use northnarrow_agent::net::dns_cache::DnsCache;
use northnarrow_agent::posture::AuthSessionTracker;
use northnarrow_agent::sensors::SensorMultiplexer;
use tracing::{error, info, warn};

use super::cli::Cli;
use super::evidence::{attest_degraded, AuditHandle};

/// What [`load`] loaded.
pub(crate) struct Policy {
    pub(crate) netflow_blocklist: Arc<NetBlocklist>,
    pub(crate) installer_override:
        Arc<northnarrow_agent::anti_tamper::trusted_installer::TrustedInstallerOverride>,
    pub(crate) chain_store:
        Arc<parking_lot::Mutex<northnarrow_agent::decision::correlation::CorrelationStore>>,
    pub(crate) ransom_tracker: Arc<northnarrow_agent::impact::RansomTracker>,
    pub(crate) defense_detector: Arc<northnarrow_agent::impair::DefenseDetector>,
    /// R11c (lab PR 264): the signed per-rule response policy in force —
    /// the handle the engine reads, and the one the posture and the admin
    /// socket get (`nn-admin policy set` installs the next policy through
    /// it). It was a process-wide handle the start set.
    pub(crate) rule_policy: northnarrow_agent::decision::rule_policy::PolicyHandle,
    /// The JA3 list's size, for `net status`'s inactive rules (R11c, lab
    /// PR 264: it was a process-wide value this phase noted).
    pub(crate) ja3_entries: usize,
    pub(crate) engine: RuleEngine,
}

/// The signed content and the decision engine: the network blocklists and
/// the optional kernel deny of a connect to them, the comm allowlists, the
/// trusted-installer window, the chain rules' store, the network rules'
/// thresholds, the ransomware tracker and the security-tool detector, the
/// signed per-rule response policy, the rule engine.
pub(crate) fn load(
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
    // boot, and in the signed chain once the audit log is open (below);
    // the list's size goes to the admin socket's `net status` (R11c, lab PR
    // 264: in `Policy`, no longer a process-wide note).
    let ja3_entries = ja3_blocklist.len();
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
    // force, a signed degradation. R11c (lab PR 264): in force in the handle
    // made here, which the engine, the posture and the admin socket share.
    let rule_policy = {
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
        rp::PolicyHandle::new(policy)
    };
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
    .with_policy(rule_policy.clone());
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
        rule_policy,
        ja3_entries,
        engine,
    }
}

/// External audit LLMR-016: a default list that could not be read, and
/// gave way to the copy built into the agent, is recorded in the signed
/// chain through the overlay gate (queued until the audit log is open);
/// LLMR-015 (NN-AUD-327): so is one edited by hand, which is not applied.
/// An earlier release's list, superseded by the built-in copy, is a WARN
/// only: what is in force is what shipped.
pub(crate) fn report_builtin_defaults(
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
