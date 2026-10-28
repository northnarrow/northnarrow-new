
/// What [`boot_attach`] attached.
struct Attached {
    /// The process lineage the posture, the rules and the pumps share.
    lineage: AuthSessionTracker,
    flow_tracker: Arc<parking_lot::Mutex<FlowTracker>>,
    dns_cache: Arc<DnsCache>,
    execq_mode: northnarrow_agent::execq::Mode,
    execpol_mode: northnarrow_agent::execpol::Mode,
    /// Where the ids of the agent's BPF programs go (DEP-006).
    own_prog_ids_file: Option<PathBuf>,
    sensor: SensorMultiplexer,
    /// The network drain's rings.
    net_bufs: northnarrow_agent::sensors::multiplexer::NetRingBufs,
    /// The exploit guard off or unavailable, signed once the audit log is
    /// open.
    exploit_guard_degraded: Option<String>,
}

/// `BootPhase::Attach`: the eBPF object loads and the sensors attach
/// (`SensorMultiplexer::start_with_net`), the deny hooks attach and the
/// agent registers in them (`attach_anti_tamper`), the exploit guard
/// attaches. Both attaches take `attach_permit`, which only
/// [`boot_integrity`] hands out: nothing reaches the kernel before every
/// preflight check has run.
async fn boot_attach(
    cli: &Cli,
    boot: &mut BootSequence,
    attach_permit: northnarrow_agent::boot::AttachPermit,
    overlay_gate: &Arc<northnarrow_agent::config::overlay_auth::OverlayGate>,
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
    // Tappa 10.9 step 2: which exec sensor the multiplexer attaches.
    northnarrow_agent::sensors::exe_identity::want_lsm(cli.exec_sensor == ExecSensor::Lsm);
    // Review 69: `sys_enter_openat` emits from the start only in tracepoint
    // mode; otherwise `start_open_sensor` decides.
    northnarrow_agent::sensors::open_sensor::want_tracepoint(
        cli.file_open_sensor == FileOpenSensor::Tracepoint,
    );
    // Tappa 10.9 step 3: which DNS sensor the multiplexer attaches.
    northnarrow_agent::sensors::dns_sensor::want_skb(cli.dns_sensor == DnsSensor::Skb);
    // Lab PR 223 (EXPERIMENTAL): the exec quarantine's mode, before the
    // multiplexer writes it into the kernel (the same detect-only inputs
    // the executor reads further down: a detect-only agent observes).
    let execq_cfg = cli.execq_config(
        cli.detect_only || northnarrow_agent::response::config::detect_only_env().is_some(),
    );
    let execq_mode = execq_cfg.mode;
    northnarrow_agent::execq::configure(execq_cfg);
    // Lab PR 226 (EXPERIMENTAL): the exec policy, its signed table read
    // now (the kernel configuration is written and frozen when the
    // multiplexer starts); a detect-only agent audits.
    let execpol_mode = {
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
        ep::configure(ep::Config {
            mode,
            table,
            source,
            env: !cli.exec_policy_no_env,
            map: !cli.exec_policy_no_map,
        });
        mode
    };
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
    northnarrow_agent::sensors::epg::set_task_map_entries(
        cli.exploit_guard_tasks,
        cli.exploit_guard.variant(),
    );
    let (mut sensor, net_bufs) = SensorMultiplexer::start_with_net(net_wiring, &attach_permit)
        .await
        .context("starting the sensor multiplexer (with net observation)")?;
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
    sensor
        .attach_anti_tamper(&attach_permit, &pids, &keep)
        .with_context(|| {
            format!(
                "anti-tamper setup failed (agent_pid={agent_pid}) — \
                 refusing to start with a silently-absent protection"
            )
        })?;
    boot.done(BootStep::AntiTamper)?;
    // Lab PR 219: the exploit post-condition guard, attached before the
    // agent's programs are recorded as its own (DEP-006), in detect mode
    // until the no-enforcement gate is resolved below. Off or unavailable
    // is attested once the audit log is open.
    let exploit_guard_degraded: Option<String> =
        match sensor.attach_exploit_guard(cli.exploit_guard.variant()) {
            Ok(()) => None,
            Err(_) if cli.exploit_guard == ExploitGuard::Off => Some(
                "exploit post-condition guard off (--exploit-guard off / NN_EXPLOIT_GUARD=off): \
                 kernel exploit post-conditions are not watched"
                    .to_string(),
            ),
            Err(e) => Some(format!(
                "exploit post-condition guard unavailable on this kernel: {e} — kernel exploit \
                 post-conditions are not watched"
            )),
        };
    // External audit DEP-006: the ids install.sh / uninstall.sh wait for.
    record_own_prog_ids(own_prog_ids_file.as_deref(), sensor.ebpf_mut());
    Ok(Attached {
        lineage,
        flow_tracker,
        dns_cache,
        execq_mode,
        execpol_mode,
        own_prog_ids_file,
        sensor,
        net_bufs,
        exploit_guard_degraded,
    })
}

/// What [`boot_self_test`] measured.
struct SelfTested {
    self_test: northnarrow_agent::boot::deny_selftest::SelfTestOutcome,
}

/// `BootPhase::SelfTest` (lab PR 218, external review AR-09 / G-12): one
/// deny hook exercised against the agent itself; hooks attached but never
/// run refuse the start (signed) unless the degraded mode is asked for.
#[allow(clippy::too_many_arguments)]
fn boot_self_test(
    cli: &Cli,
    boot: &mut BootSequence,
    identity: &agent_id::AgentIdentity,
    overlay_gate: &Arc<northnarrow_agent::config::overlay_auth::OverlayGate>,
    integrity: &northnarrow_agent::install_manifest::IntegrityOutcome,
    allow_degraded: bool,
    bpf_lsm_state: &northnarrow_agent::boot::lsm::BpfLsm,
    detect_only: bool,
) -> Result<SelfTested> {
    // Lab PR 218 (external review AR-09 / G-12): one deny hook exercised
    // against the agent itself — an unprotected child signals it and must
    // be refused. Hooks attached but not run (`bpf` missing from the active
    // LSMs, Ubuntu) refuse the start unless NN_ANTI_TAMPER_ALLOW_DEGRADED=1;
    // an unmeasured test is signed and lowers the trust level to L1.
    boot.enter(BootPhase::SelfTest)?;
    let self_test =
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
        record_refused_boot(
            cli,
            identity,
            overlay_gate,
            "deny_self_test",
            (integrity.label(), integrity.provenance()),
            Some(("deny_self_test", detail.as_str())),
            &detail,
        );
        std::process::exit(78);
    }
    if let Some(detail) = &self_test_detail {
        northnarrow_agent::boot::degradation::report("deny_self_test", detail);
    }
    {
        let deny = northnarrow_agent::anti_tamper::deny_report().unwrap_or_default();
        northnarrow_agent::boot::trust::set_boot_inputs(
            northnarrow_agent::boot::trust::TrustInputs {
                bpf_lsm: bpf_lsm_state.clone(),
                deny_expected: deny.expected,
                deny_attached: deny.attached,
                self_test: self_test.clone(),
                detect_only,
            },
        );
    }
    boot.done(BootStep::DenySelfTest)?;
    Ok(SelfTested { self_test })
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
