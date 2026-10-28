
/// What [`boot_response`] built.
struct Response {
    legacy_isolation_removed: bool,
    /// The exec quarantine's copy of the executor's configuration.
    execq_exec_cfg: ExecutorConfig,
    executor: Executor,
    correlation: CorrelationBuffer,
    isolator: Option<Arc<NetworkIsolator>>,
}

/// The response side: the optional pid file (the hooks attached, the engine
/// loaded), the exploit guard's response, an older agent's host-wide
/// isolation removed, the quarantine's deny of the agent's own files, the
/// executor and what an earlier run left (kill cgroups, contained
/// processes), the correlation buffer, the network isolator.
fn boot_response(
    cli: &Cli,
    exec_cfg: ExecutorConfig,
    detect_only: bool,
    audit_log: &AuditHandle,
    overlay_gate: &Arc<northnarrow_agent::config::overlay_auth::OverlayGate>,
) -> Result<Response> {
    // Tappa 7 task 6 #2b-verify: optional PID file. `attach_anti_tamper`
    // above is fully synchronous (anti_tamper::attach attempts AND pins
    // every LSM hook before it returns — crates/nn-linux/src/anti_tamper/mod.rs),
    // and the "decision engine ready" line has now flushed, so the
    // file's *existence* is a sound readiness gate: anything that sees
    // it knows every hook is attached and self-protection is live.
    //
    // The agent writing its OWN pid is immune to the failure class that
    // sank three external-resolution strategies in the retired #2b
    // harness, docs/verify-2b.sh (989c292 pgrep -P / -x, 6e746c6
    // /proc/*/exe diff): the sudo+exec
    // process-tree race, TASK_COMM_LEN comm truncation, and pgrep
    // quirks. A write failure here is FATAL by design — a harness or
    // supervisor that asked for a PID file cannot proceed without it,
    // and silently degrading would resurrect exactly the "agent is
    // alive but the watcher can't find it" bug this flag exists to
    // kill. Production never passes --pid-file, so this is inert there.
    if let Some(pid_file) = cli.pid_file.as_deref() {
        write_pid_file(pid_file)
            .with_context(|| format!("writing --pid-file {}", pid_file.display()))?;
    } else {
        debug!("no --pid-file provided; PID file write skipped (production default)");
    }

    // Lab PR 219: the exploit guard enforces only when asked to and outside
    // detect-only (the one no-enforcement switch wins).
    if cli.exploit_guard != ExploitGuard::Off {
        use northnarrow_agent::sensors::epg::{effective_response, set_response, Response};
        let requested = cli.exploit_guard_response.response();
        match effective_response(requested, detect_only) {
            Response::Enforce => match set_response(Response::Enforce) {
                Ok(()) => warn!(
                    "exploit post-condition guard ENFORCING: a task found holding what no \
                     legitimate transition gave it is sent SIGKILL in the kernel (lite: and \
                     the use is refused)"
                ),
                Err(e) => warn!(reason = %e, "exploit guard: enforce requested, not applied"),
            },
            Response::Detect if requested == Response::Enforce => {
                info!("exploit guard: enforce requested, detect-only in force — detect mode")
            }
            Response::Detect => {}
        }
    }
    // External audit CMB-006: an older agent's host-wide nftables blackout
    // (no carve-out, no release, no status) is removed before anything
    // else; host-wide isolation is the COMBAT ladder's alone.
    let legacy_isolation_removed =
        match northnarrow_agent::response::network_isolation::retire_legacy(&exec_cfg) {
            Ok(removed) => {
                if removed {
                    warn!(
                        "removed the host-wide nftables isolation an older agent left \
                         (external audit CMB-006): host-wide isolation is the COMBAT ladder's"
                    );
                }
                removed
            }
            Err(e) => {
                error!(
                    error = %e,
                    "an older agent's host-wide nftables isolation could not be removed — \
                     `nft delete chain inet northnarrow isolation_output` (and isolation_input) \
                     from the console"
                );
                false
            }
        };
    // External audit CMB-025: the quarantine never takes the agent's own
    // files, wherever this host keeps them (`--watchdog-exe`, the running
    // binary, the executor's key, vault and containment record).
    {
        let own_exe = std::env::current_exe().ok();
        let deny = northnarrow_agent::response::quarantine::RuntimeDeny::new(
            &exec_cfg,
            own_exe.as_deref(),
            &cli.resolved_watchdog_exe(),
        );
        info!(
            paths = %deny.describe(),
            "quarantine: the agent's own files are never quarantined"
        );
        northnarrow_agent::response::quarantine::set_runtime_deny(deny);
    }
    // Lab PR 223: the exec quarantine vaults block-listed files.
    let execq_exec_cfg = exec_cfg.clone();
    let executor = Executor::with_config(exec_cfg);
    // External audit CMB-019: a kill cgroup an earlier agent left in the
    // middle of a kill (its tree frozen) is finished and removed.
    if !detect_only {
        let removed = northnarrow_agent::response::kill::reap_stale_kill_cgroups(
            &executor.config().blocked_cgroup_dir(),
        );
        if removed > 0 {
            warn!(
                removed,
                "kill cgroups left by an earlier agent were finished and removed"
            );
        }
    }
    // External audit CMB-010: the processes an earlier run moved into the
    // blocked / throttled scopes — the gone ones dropped from the record,
    // the still-contained ones reported (no automatic release after a
    // restart).
    let contained = northnarrow_agent::response::containment::reconcile(executor.config());
    if !contained.still_contained.is_empty() {
        warn!(
            count = contained.still_contained.len(),
            "processes contained by an earlier run are still in the blocked / throttled scopes"
        );
    }
    if detect_only {
        warn!(
            "DETECT-ONLY mode active (--detect-only / NN_DETECT_ONLY / NORTHNARROW_DRY_RUN): \
             detection + posture run normally, but NO response action or COMBAT network \
             isolation will touch the system — verdicts are logged as \"would execute\" only"
        );
    }
    // Lab follow-up (lab PR 165): without `nft` the per-process outbound
    // block cannot work. Said once here, and in the signed chain once the
    // audit log is open (below), instead of only at the first block.
    let nft_gap = northnarrow_agent::response::block_outbound::nft_gap_at_boot();
    if let Some(gap) = &nft_gap {
        error!("{gap}");
        attest_degraded(audit_log.as_ref(), gap);
    }
    info!(
        own_pid = executor.own_pid(),
        protected = executor.protected().len(),
        detect_only,
        "response executor ready (KillProcess + KillProcessTree active)"
    );

    let correlation = CorrelationBuffer::with_default_capacity();

    // Tappa 7 task 7 / Tappa 8: anti-tamper response pipeline. The
    // NetworkIsolator owns the iptables shell-out; engage runs on
    // any non-Combat → Combat edge, release only fires for an
    // Ed25519-verified admin unlock (capability gated via
    // UnlockToken). If the ruleset is missing we WARN-and-continue
    // with no isolator, so the agent still boots in dev environments
    // without /etc/northnarrow/ provisioned.
    let isolator = match NetworkIsolator::new(cli.combat_rules.clone()) {
        Ok(i) => Some(Arc::new(
            i.with_allow_cidrs_path(cli.combat_allow_cidrs.clone())
                .with_rules_v6(cli.combat_rules_v6.clone())
                // External audit ATP-001 / DEP-003: the COMBAT files are
                // applied only as shipped or admin-signed.
                .with_overlay_gate(Arc::clone(overlay_gate)),
        )),
        Err(e) => {
            // ERROR, not WARN: besides losing isolation, no isolator means
            // the admin socket below is never started — nn-admin status /
            // unlock / detections all fail and the watchdog's STATUS ping
            // trips its stuck-recovery restart loop every 30 s.
            error!(
                error = %e,
                path = %cli.combat_rules.display(),
                "combat ruleset missing or invalid: COMBAT entry will NOT engage network \
                 isolation AND the admin socket will NOT be started (nn-admin unusable, \
                 watchdog STATUS ping will fail) — install combat-rules.v4 (configs/) and restart"
            );
            None
        }
    };
    // External audit ATP-014 (NN-AUD-262): the files COMBAT's isolation
    // runs — looked up in the system directories only, never on PATH —
    // named once at boot, or why the isolation could not run.
    if let Some(iso) = isolator.as_ref() {
        match iso.binaries() {
            Ok(files) => info!(binaries = %files, "COMBAT isolation binaries (system directories)"),
            Err(why) => error!(
                error = %why,
                "COMBAT isolation cannot run: no trusted iptables in /usr/sbin, /usr/bin, /sbin or \
                 /bin — a STAGE 3 isolation will fail (install iptables; a copy in /usr/local is \
                 not used)"
            ),
        }
    }
    Ok(Response {
        legacy_isolation_removed,
        execq_exec_cfg,
        executor,
        correlation,
        isolator,
    })
}

/// External audit CMB-006: the removal of an older agent's host-wide
/// nftables isolation at start is recorded in the signed audit chain.
fn attest_legacy_isolation_removed(
    audit_log: Option<&Arc<parking_lot::Mutex<northnarrow_agent::audit::AuditLog>>>,
) {
    let Some(log) = audit_log else {
        return;
    };
    let draft = northnarrow_agent::audit::AuditEntryDraft {
        op: northnarrow_agent::self_integrity::AUDIT_OP.to_string(),
        extra: serde_json::json!({
            "kind": "legacy_isolation_removed",
            "detail": "an older agent's nftables isolation chains (isolation_input, \
                       isolation_output) were found at start and removed",
            "at_boot": true,
        }),
        key_fp: "agent-self".to_string(),
        cosigner_fps: Vec::new(),
        result: "repaired".to_string(),
        client_pid: std::process::id(),
        client_uid: 0,
        client_comm: "northnarrow-agent".to_string(),
        client_exe: None,
    };
    if let Err(e) = log.lock().append(draft) {
        warn!(error = %e, "recording the removed legacy isolation failed");
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
