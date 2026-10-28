
/// SIGINT, SIGTERM and SIGHUP, registered before the event loop.
struct Signals {
    sigint: tokio::signal::unix::Signal,
    sigterm: tokio::signal::unix::Signal,
    sighup: tokio::signal::unix::Signal,
}

/// What [`boot_tasks`] started.
struct Tasks {
    execq_handle: Option<northnarrow_agent::execq::Handle>,
    execpol_handle: Option<northnarrow_agent::execpol::Handle>,
    signals: Signals,
}

/// The running agent's tasks: the posture's decay, the trusted-installer
/// window's deadline, the exec quarantine's and the exec policy's
/// controllers (EXPERIMENTAL; one that cannot start is signed); then the
/// shutdown signals, installed before the loop.
#[allow(clippy::too_many_arguments)]
fn boot_tasks(
    posture: &PostureMachine,
    installer_override: &Arc<
        northnarrow_agent::anti_tamper::trusted_installer::TrustedInstallerOverride,
    >,
    execq_mode: northnarrow_agent::execq::Mode,
    overlay_gate: &Arc<northnarrow_agent::config::overlay_auth::OverlayGate>,
    detection_sink: &Option<northnarrow_agent::detection_store::DetectionSink>,
    audit_log: &AuditHandle,
    execq_exec_cfg: ExecutorConfig,
    execpol_mode: northnarrow_agent::execpol::Mode,
) -> Result<Tasks> {
    // Decay loop: walks the posture down (ALERTED→OBSERVING after 1h
    // idle, ENGAGED→ALERTED after 24h idle, and — external audit POS-001 —
    // an unlocked COMBAT, reached on heuristics alone, to ENGAGED after
    // 30 min without a new escalation signal). A locked COMBAT never
    // decays; it requires an admin-signed release. The 60 s cadence is
    // a coarse heartbeat, not a precise deadline.
    let posture_decay = posture.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        tick.tick().await; // skip the immediate first tick
        loop {
            tick.tick().await;
            if let Some(new_state) = posture_decay.tick_decay() {
                info!(state = %new_state.kind(), "posture decay transition");
            }
        }
    });

    // External audit ATP-003: the trusted-installer window is closed — and
    // its close recorded — at its deadline, not at the next event. The
    // kernel grant ends at the same deadline by itself; this keeps the
    // in-memory state, the PID-1 stop grant and the audit chain on time,
    // and retries a zeroing that failed.
    let installer_ticker = installer_override.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            installer_ticker.close_if_expired(Instant::now());
        }
    });

    // Lab PR 223 (EXPERIMENTAL): the exec quarantine's controller and
    // scanner, once the detection chain and the audit log are open (every
    // decision is a signed record). Until its first heartbeat the kernel
    // holds nothing; a guard that cannot start is a signed degradation.
    let execq_handle = if execq_mode == northnarrow_agent::execq::Mode::Off {
        None
    } else {
        let cfg = northnarrow_agent::execq::config()
            .cloned()
            .unwrap_or_default();
        let (hashes, hashes_source) = match overlay_gate
            .verified(OverlayKind::ExecqHashes, &cfg.hashes_local)
        {
            northnarrow_agent::config::overlay_auth::Verified::Content { path, text } => {
                match nn_proto::execq::parse_hash_list(&text) {
                    Ok(l) => (l, format!("{} (signed)", path.display())),
                    Err(e) => {
                        error!(error = %e, path = %path.display(), "exec quarantine hash list unreadable — empty lists");
                        (
                            nn_proto::execq::HashList::default(),
                            format!("{}: {e}", path.display()),
                        )
                    }
                }
            }
            _ => (nn_proto::execq::HashList::default(), "none".to_string()),
        };
        let posture_for_execq = posture.clone();
        let recorder = northnarrow_agent::execq::record::SinkRecorder {
            sink: detection_sink.clone(),
            audit: audit_log.clone(),
            posture: Box::new(move || posture_for_execq.current_kind()),
        };
        match northnarrow_agent::execq::start(northnarrow_agent::execq::StartDeps {
            hashes,
            hashes_source,
            recorder: Box::new(recorder),
            exec_cfg: execq_exec_cfg,
        }) {
            Ok(h) => Some(h),
            Err(why) => {
                error!(reason = %why, "exec quarantine NOT running — the kernel holds nothing");
                attest_degraded(audit_log.as_ref(), &format!("exec quarantine: {why}"));
                None
            }
        }
    };

    // Lab PR 226 (EXPERIMENTAL): the exec policy's controller — the slices
    // and images published, the kernel's reports into signed records —
    // and each part of the policy that could not start, signed.
    let execpol_handle = if execpol_mode == northnarrow_agent::execpol::Mode::Off {
        None
    } else {
        let posture_for_execpol = posture.clone();
        let recorder = northnarrow_agent::execpol::record::SinkRecorder {
            sink: detection_sink.clone(),
            posture: Box::new(move || posture_for_execpol.current_kind()),
        };
        let execq_on = execq_handle.is_some();
        let handle = match northnarrow_agent::execpol::start(Box::new(recorder), execq_on) {
            Ok(h) => Some(h),
            Err(why) => {
                error!(reason = %why, "exec policy controller NOT running — nothing is recorded");
                attest_degraded(audit_log.as_ref(), &format!("exec policy: {why}"));
                None
            }
        };
        for why in northnarrow_agent::execpol::degradations() {
            attest_degraded(audit_log.as_ref(), &why);
        }
        handle
    };

    // Install the three shutdown signals up front, before the loop.
    // Re-creating the future inside `select!` every iteration (the
    // old `signal::ctrl_c()` shorthand) re-runs handler registration
    // each tick and interacts badly with `SIG_IGN` inherited from
    // `bash &` + `nohup` (live test 2026-05-12 found SIGINT and
    // SIGHUP silently dropped; only SIGQUIT brought the agent down).
    // A pre-registered `Signal` stream is the documented robust path.
    //
    // SIGTERM reaches the agent only from itself, the watchdog, PID 1
    // inside a signed trusted-installer window, or `systemd-shutdown` at
    // the end of a shutdown (the task_kill hook refuses everyone else) —
    // and from anyone on a kernel without `bpf` in its LSM chain.
    let sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
    let sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    let sighup = signal(SignalKind::hangup()).context("installing SIGHUP handler")?;
    Ok(Tasks {
        execq_handle,
        execpol_handle,
        signals: Signals {
            sigint,
            sigterm,
            sighup,
        },
    })
}

/// External audit MAIN-001: remove a former watchdog pid from
/// PROTECTED_PIDS unless it still runs the watchdog binary.
/// `pid` runs the watchdog binary at `watchdog_exe` (same file identity).
fn runs_watchdog_binary(pid: u32, watchdog_exe: &std::path::Path) -> bool {
    use northnarrow_agent::anti_tamper::ExeIdentity;
    let watchdog = ExeIdentity::of_file(watchdog_exe);
    watchdog.is_some() && ExeIdentity::of_process(pid) == watchdog
}

fn withdraw_watchdog_pid(
    bpffs_root: Option<&std::path::Path>,
    pid: u32,
    watchdog_exe: &std::path::Path,
) {
    use northnarrow_agent::anti_tamper::ExeIdentity;
    let watchdog = ExeIdentity::of_file(watchdog_exe);
    if watchdog.is_some() && ExeIdentity::of_process(pid) == watchdog {
        warn!(
            pid,
            "the watchdog pidfile no longer names the running watchdog — keeping it protected"
        );
        return;
    }
    match northnarrow_agent::anti_tamper::evict_protected_pid(bpffs_root, pid) {
        Ok(()) => info!(pid, "former watchdog pid removed from PROTECTED_PIDS"),
        Err(e) => {
            warn!(pid, error = %e, "could not remove a former watchdog pid from PROTECTED_PIDS")
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
