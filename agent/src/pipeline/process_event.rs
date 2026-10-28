//! One event through the agent (R11a, lab PR 261: from `main.rs`): the
//! canaries, the posture and the COMBAT ladder, the correlation buffer, the
//! rules, the executor, the detection store.

use std::time::Instant;

use nn_model::Event;
use northnarrow_agent::correlation::CorrelationBuffer;
use northnarrow_agent::decision::RuleEngine;
use northnarrow_agent::detection_budget::{self, Admit};
use northnarrow_agent::posture::PostureMachine;
use northnarrow_agent::response::Executor;
use tracing::{debug, error, info, warn};

use super::{host_stopping, systemd_state, HOST_STOPPING};

/// Categorise + log + evaluate + (maybe) execute.
///
/// Tappa 4 ships five sensors; Tappa 2 rules only match `ProcessSpawn`,
/// so non-spawn events flow through as DEBUG telemetry and bypass the
/// engine. The kill syscalls + verify retries can sleep up to 50 ms,
/// so any execution dispatch goes through `spawn_blocking`.
///
/// Tappa 6: every event also lands in the correlation buffer, the recent
/// events the posture triggers read. An event no rule matches gets no
/// verdict: the LLM advisor that judged such execs was removed in Wave 4
/// (lab PR 214).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn process_event(
    engine: &RuleEngine,
    executor: &Executor,
    correlation: &CorrelationBuffer,
    posture: &PostureMachine,
    ladder: &northnarrow_agent::combat::CombatLadder,
    canary_detector: Option<&northnarrow_agent::canary::detector::Detector>,
    // FIM-009 self-upgrade (§15.1): consulted for lazy TTL expiry.
    installer_override: &northnarrow_agent::anti_tamper::trusted_installer::TrustedInstallerOverride,
    // Tappa 9.0.a: detection-persistence sink. `None` ⇒ not persisting
    // this boot (e.g. signing key / store open failed at startup). All
    // record calls are off the hot path (bounded queue + writer task).
    detection_sink: Option<&northnarrow_agent::detection_store::DetectionSink>,
    event: Event,
) {
    // Lab PR 218: the deny self-test's own refused signal is the boot's
    // measurement, not an attempt on the agent — taken before the posture
    // (it would raise COMBAT) and the rules; any other denial goes on.
    if northnarrow_agent::boot::deny_selftest::take_expected_denial(&event) {
        return;
    }
    // Tappa 10.9 step 2: an exec event's path made absolute before any
    // consumer reads it (review 61).
    let mut event = event;
    northnarrow_agent::sensors::exe_identity::resolve(&mut event);
    // Lab PR 223: the exec quarantine resumes a held process only once
    // this exec has been judged — dropped at the end of this function,
    // after a kill the rules decided was carried out.
    let _execq_judged = northnarrow_agent::execq::SpawnGuard::for_event(&event);
    // FIM-009 self-upgrade (§15.1): lazy TTL expiry on the event path —
    // if a trusted-installer window has passed its deadline, close it
    // (re-engage the FS pin + audit) before handling this event. A cheap
    // no-op (a single atomic load) when no window is open. No timer:
    // detection already expires exactly at the deadline via the rule's
    // own is_window_open() read; this sweep re-syncs the kernel map.
    installer_override.close_if_expired(Instant::now());

    // External audit EBPF-001: while systemd stops the host, its SIGTERM to
    // the agent and the watchdog is refused until `systemd-shutdown` (the
    // units outlive their stop jobs). Expected, so neither an attempt nor a
    // posture signal.
    if let Event::FsProtectDenial {
        pid: 1,
        operation: nn_model::FsProtectOperation::Signal,
        target_dev: sig,
        target_ino: target,
        ..
    } = &event
    {
        let state = systemd_state().await;
        if state.as_deref() == Some("stopping") {
            info!(
                signal = sig,
                target,
                "systemd is stopping the host — its signal to a protected process is refused \
                 until systemd-shutdown's final stage (expected, not an attempt)"
            );
            host_stopping(ladder);
            return;
        }
        info!(
            signal = sig,
            target,
            systemd_state = state.as_deref().unwrap_or("(no answer)"),
            "signal relayed by systemd outside a trusted-installer window — not a shutdown"
        );
    }

    // Tappa 9.5 (K3): canary precedence over FIM rules per
    // §12 Q9 OPTION B inline-filter lock-in. The detector
    // checks the event against the deployed canary registry;
    // on match, it returns Some(Event::CanaryTripped { … }),
    // marks the canary as tripped (idempotent per §12 Q2),
    // and appends to the canary_access.jsonl chain. We
    // REPLACE the source event with the canary event so
    // downstream (correlation buffer push, posture observer,
    // rule engine) routes through the K5 canary rule family
    // instead of the K9 FIM rule layer.
    //
    // When `canary_detector` is `None` (early-boot path
    // before K6 wires the Detector handle), this is a no-op.
    let event = match canary_detector.and_then(|d| d.process_event(&event)) {
        Some(canary_event) => canary_event,
        None => event,
    };
    // Lab PR 163: the close of a connection that tripped a network canary
    // belongs to the trip (its row is in the signed netflow log already);
    // judged again, NN-L-CHAIN-003 answered the one access a second time.
    // Lab PR 246: every row of that connection, as the engine's flow ledger
    // keys it (the trip's accessor and connect time) — a close the flow
    // tracker synthesised included, and a row that follows the close.
    if engine.owned_by_trip(&event) {
        debug!("row of a network canary trip's connection — part of the trip, not judged again");
        return;
    }

    // Run posture detection BEFORE we push the focal event into the
    // correlation buffer — the trigger detector counts the focal as
    // a fresh +1 on top of `recent`, and `recent` already containing
    // the focal would double-count it.
    // Review 72: borrowed under the buffer's read lock, not cloned (up to
    // 1,000 events, for every event, was most of the agent's CPU under an
    // exec burst). Nothing pushes to the buffer until this returns.
    let host_stopping = HOST_STOPPING.load(std::sync::atomic::Ordering::SeqCst);
    if let Some((new_state, firing_trigger)) = (!host_stopping)
        .then(|| correlation.with_recent(|recent| posture.observe(&event, recent)))
        .flatten()
    {
        // BUG-015 observability: include the firing TriggerType so
        // operators can see in the journal what caused a transition.
        // `firing_trigger` is `Some` for any upward crossing and `None`
        // for same-tier re-arms; the latter case still gets a log line
        // because the kind() display alone is enough to follow state.
        warn!(
            state = %new_state.kind(),
            // External audit POS-001: a COMBAT reached on heuristics alone
            // is unlocked — no isolation, and it decays once quiet.
            locked = new_state.is_combat_locked(),
            trigger = ?firing_trigger,
            "POSTURE TRANSITION"
        );
        // On the non-Combat → Combat edge the combat-entry hook, inside
        // `observe`, has opened the ladder's episode (STAGE 1 INVESTIGATE,
        // network up) with the firing trigger, the evidence it cites and
        // the process the event names (lab PR 245: the posture's
        // `CombatEntry`; external audit EBPF-001: never init; CMB-004: with
        // the offender's start and a time it was running). Reaching COMBAT
        // does NOT isolate — the ladder does.
    }
    // While a COMBAT episode is active, feed every event to the ladder
    // for the jump-ahead check: an offender actively exfiltrating or
    // spawning children DURING INVESTIGATE pre-empts the time-bound
    // deadline and advances straight to NEUTRALIZE.
    if !host_stopping && ladder.current_stage().is_some() {
        ladder.observe(&event, Instant::now());
    }
    // Lab PR 222: a mass rewrite of existing files flags its writer for the
    // copy-on-first-write guard (a ransomware verdict's offender).
    northnarrow_agent::cow::observe_event(&event);
    // Lab PR 224: an open flow's rows (its connect, its snapshots, a
    // refused connect) are for the rules; the correlation buffer keeps its
    // `TcpConnect` and its closed row, as before.
    let open_flow_row = matches!(&event, Event::NetFlow(nf) if nf.phase.is_open());
    if !open_flow_row {
        correlation.push(event.clone());
    }

    // Review 71: per-event lines for the frequent events (every exec,
    // every flow, every open) are DEBUG. At INFO, an exec burst made
    // journald rate-limit the agent and drop its other lines (boot, sensor
    // arming, verdict context), and every command line on the host, with
    // any secret in its arguments, was copied into the journal. Exec and
    // flow records live in the detection store and the signed netflow log.
    // External audit Wave 3 (journal line injection, lab PR 167): a value
    // another user names (comm, file name, DNS name, the rule text quoting
    // them) is logged through Escaped, quoted when it holds a separator.
    use nn_model::log_escape::Escaped;
    match &event {
        Event::ProcessSpawn { .. } => debug!(event = ?event, "process spawn detected"),
        Event::ModuleLoad {
            method,
            loader_pid,
            loader_comm,
            path,
            ..
        } => info!(
            loader_pid = *loader_pid,
            loader_comm = %Escaped(loader_comm),
            method = ?method,
            path = path.as_deref().unwrap_or("none"),
            "kernel module load detected (BUG-034)"
        ),
        Event::IoUring {
            created,
            pid,
            comm,
            classes,
            count,
            sq_thread,
            ..
        } => info!(
            pid = *pid,
            comm = %Escaped(comm),
            created = *created,
            classes = ?nn_model::io_uring_class_names(*classes),
            count = *count,
            sq_thread = *sq_thread,
            "io_uring activity"
        ),
        Event::BpfSyscall {
            pid,
            comm,
            cmd,
            arg,
            ..
        } => info!(
            pid = *pid,
            comm = %Escaped(comm),
            cmd = common::wire::bpf_cmd_name(*cmd),
            arg = *arg,
            "bpf() syscall by a non-protected process"
        ),
        Event::FileOpen {
            filename,
            comm,
            pid,
            ..
        } => {
            debug!(pid, comm = %Escaped(comm), filename = %Escaped(filename), "file open")
        }
        Event::MassWrite {
            pid,
            comm,
            count,
            filename,
            cgroup_window: true,
            ..
        } => info!(
            pid = *pid,
            comm = %Escaped(comm),
            overwrites = *count,
            last = %Escaped(filename),
            "mass write: overwrite threshold crossed by the processes of one cgroup (counted in the kernel)"
        ),
        Event::MassWrite {
            pid,
            comm,
            count,
            filename,
            ..
        } => info!(
            pid = *pid,
            comm = %Escaped(comm),
            count = *count,
            last = %Escaped(filename),
            "mass write: write-open threshold crossed (counted in the kernel)"
        ),
        // Lab PR 225: the rename and unlink bursts (NN-L-IMP-001/002 read them).
        Event::FileBurst {
            pid,
            comm,
            kind,
            count,
            filename,
            ..
        } => info!(
            pid = *pid,
            comm = %Escaped(comm),
            kind = kind.as_str(),
            count = *count,
            last = %Escaped(filename),
            "file burst: rename or unlink threshold crossed (counted in the kernel)"
        ),
        // Lab PR 225: NN-L-EVA-003 reports it.
        Event::DefenderSignal {
            pid,
            comm,
            target_pid,
            signal,
            ..
        } => info!(
            pid = *pid,
            comm = %Escaped(comm),
            target_pid = *target_pid,
            signal = *signal,
            "signal to a security tool's process (task_kill, not refused)"
        ),
        Event::ExecCheck {
            filename,
            comm,
            pid,
            ..
        } => {
            debug!(pid, comm = %Escaped(comm), filename = %Escaped(filename), "exec_check")
        }
        Event::TcpConnect {
            dst_addr,
            dst_port,
            family,
            comm,
            pid,
            ..
        } => {
            debug!(
                pid, comm = %Escaped(comm), family,
                dst = %render_addr(*family, dst_addr),
                dst_port,
                "tcp_connect"
            )
        }
        Event::DnsQuery {
            dns_server,
            family,
            comm,
            pid,
            query_name,
            ..
        } => {
            debug!(
                pid, comm = %Escaped(comm),
                server = %render_addr(*family, dns_server),
                query = %Escaped(query_name),
                "dns_query"
            )
        }
        // Review 78: the rule (NN-L-NET-020) reports it.
        Event::DnsFlood {
            pid,
            comm,
            held,
            uid_level,
            ..
        } => debug!(pid, comm = %Escaped(comm), held, uid_level, "dns_flood"),
        // External audit EBPF-013: the rule (NN-L-NET-021) reports it.
        Event::SensorFlood {
            source,
            pid,
            comm,
            held,
            uid_level,
            ..
        } => debug!(
            pid,
            comm = %Escaped(comm),
            source = source.as_str(),
            held,
            uid_level,
            "sensor_flood"
        ),
        // Tappa 7: kernel-side LSM hook denied a tamper attempt on
        // protected state. The posture machine observed the event
        // at the top of this function and will route it through the
        // ConfirmedIntrusion trigger (anti-tamper denial = strongest
        // possible posture signal, ENGAGED → COMBAT).
        Event::FsProtectDenial {
            pid,
            uid,
            comm,
            target_dev,
            target_ino,
            operation,
            ..
        } => {
            // Short-circuit: a kernel deny is not something the
            // rule engine should re-evaluate. The
            // posture trigger above is the response. The attempt itself
            // is persisted as a signed detection (NN-L-AT-001, Log only:
            // the kernel already refused it) — the adversarial check found
            // refused attempts that left no record in the chain logs.
            use northnarrow_agent::decision::Rule as _;
            let at001 = northnarrow_agent::decision::rules::anti_tamper::NnLAt001AntiTamperDenial;
            let verdict = at001.evaluate(&event);
            // Review 75: a loop of denied attempts is logged and stored
            // within the rule's budget for that uid.
            let admit = match &verdict {
                Some(v) => budget_admit(&v.rule_id, *uid, &event),
                None => Admit::Record {
                    suppressed_before: 0,
                },
            };
            if admit.record() {
                warn!(
                    pid, uid, comm = %Escaped(comm),
                    op = %operation,
                    target_dev, target_ino,
                    "ANTI-TAMPER DENIAL"
                );
            }
            if let Some(verdict) = verdict {
                if let Admit::Record { suppressed_before } = admit {
                    warn!(
                        rule = %verdict.rule_id,
                        severity = ?verdict.severity,
                        reasoning = %Escaped(&verdict.reasoning),
                        "VERDICT (rule)"
                    );
                    if let Some(sink) = detection_sink {
                        sink.record_rule(
                            &event,
                            &verdict,
                            at001.attack(),
                            posture.current_kind(),
                            "denied in kernel (anti-tamper LSM hook)".to_string(),
                            suppressed_before,
                        );
                    }
                }
            }
            return;
        }
        // Lab PR 219: the exploit post-condition guard. The kernel already
        // did what the mode asks (enforce: SIGKILL before the return to user
        // mode; detect: nothing), so neither the rule engine nor the
        // executor runs: the finding is recorded as a signed detection
        // (NN-L-EPG-001/002) within the rule's budget, and the posture
        // trigger above observed it.
        Event::ExploitPostcondition {
            pid,
            tid,
            uid,
            comm,
            kind,
            killed,
            abi,
            syscall,
            ..
        } => {
            use northnarrow_agent::decision::rules::epg;
            let rule = epg::rule_for(&event);
            let verdict = rule.and_then(|r| r.evaluate(&event));
            let admit = match &verdict {
                Some(v) => budget_admit(&v.rule_id, *uid, &event),
                None => Admit::Record {
                    suppressed_before: 0,
                },
            };
            if admit.record() {
                error!(
                    pid, tid, uid, comm = %Escaped(comm),
                    kind = kind.as_str(),
                    call = %abi.describe_call(*syscall),
                    killed,
                    "EXPLOIT POST-CONDITION"
                );
            }
            if let Some(verdict) = verdict {
                if let Admit::Record { suppressed_before } = admit {
                    warn!(
                        rule = %verdict.rule_id,
                        severity = ?verdict.severity,
                        reasoning = %Escaped(&verdict.reasoning),
                        "VERDICT (rule)"
                    );
                    if let Some(sink) = detection_sink {
                        sink.record_rule(
                            &event,
                            &verdict,
                            rule.map_or(&[][..], |r| r.attack()),
                            posture.current_kind(),
                            epg::response_line(&event),
                            suppressed_before,
                        );
                    }
                }
            }
            return;
        }
        // Tappa 9 (C4): FIM drift events. The drain loop in
        // agent/src/fim/drain.rs already wrote the chained
        // fim_drift.jsonl audit row + emitted Event::Fim
        // here only if NOT rate-limited (§6.5). Log a one-
        // line summary; the rule engine (C5 NN-L-FIM-001..009)
        // picks up the event via the normal `engine.evaluate`
        // path below.
        Event::Fim(fe) => {
            // BUG-012 (v2): a read (op=Opened) is NOT an integrity
            // drift, so it must never be logged as "FIM DRIFT" — that
            // is semantically wrong and just quieter noise. An Opened
            // event reaches this arm ONLY for a credential path the
            // FIM drain forwarded for the NN-L-FIM-011..017 read rules
            // (every other read is dropped at the drain). It flows
            // silently to `engine.evaluate` below; if a cred-read rule
            // fires, THE RULE emits the alert with proper framing.
            // Only integrity-changing ops get the FIM DRIFT line.
            if fe.op == nn_model::telemetry::FimOp::Opened {
                debug!(
                    path = %Escaped(&fe.path),
                    modifier_pid = fe.modifier_pid,
                    modifier_comm = %Escaped(&fe.modifier_comm),
                    "fim credential-path read forwarded to rule engine (not drift)"
                );
            } else if budget_admit("FIM-DRIFT", fe.modifier_uid, &event).record() {
                // Review 76: every drift now reaches the rules; its journal
                // line has the per-uid budget (the signed fim_drift.jsonl
                // row is always written).
                warn!(
                    path = %Escaped(&fe.path),
                    op = ?fe.op,
                    modifier_pid = fe.modifier_pid,
                    modifier_uid = fe.modifier_uid,
                    modifier_comm = %Escaped(&fe.modifier_comm),
                    "FIM DRIFT"
                );
            }
        }
        // Tappa 9.5 (K3): canary trip events. The K3 inline
        // detector intercepts source events BEFORE they reach
        // this match arm and re-emits as `Event::CanaryTripped`
        // ONLY when a canary fires (§12 Q9 OPTION B inline-
        // filter lock-in). Reaching this arm via the regular
        // event-bus path means a downstream component
        // (correlation snapshot replay, future K6 admin
        // synthetic-event injection) re-fed the canary event;
        // we log + let the K5 rule layer fire the standard
        // KillProcessTree + posture→COMBAT response.
        Event::CanaryTripped {
            canary_id,
            canary_name,
            canary_type,
            access_kind,
            accessor_pid,
            accessor_uid,
            accessor_comm,
            ..
        } => {
            warn!(
                canary_id = %canary_id,
                canary_name = %Escaped(canary_name),
                canary_type = ?canary_type,
                access_kind = ?access_kind,
                accessor_pid = %accessor_pid,
                accessor_uid = %accessor_uid,
                accessor_comm = %Escaped(accessor_comm),
                "CANARY TRIPPED"
            );
        }
        // Tappa 10 (N6) — minimal logging arms; the N3 flow
        // tracker + N2 listener kprobe feed these into the rule
        // engine below. Full drain wiring is a follow-up commit.
        Event::NetFlow(nf) => {
            debug!(
                pid = %nf.pid,
                comm = %Escaped(&nf.comm),
                dst_addr = %nf.dst_addr,
                dst_port = %nf.dst_port,
                proto = %nf.proto,
                bytes_sent = %nf.bytes_sent,
                phase = nf.phase.as_str(),
                "net flow"
            );
        }
        Event::NetListener(nl) => {
            info!(
                pid = %nl.pid,
                comm = %Escaped(&nl.comm),
                bind_addr = %nl.bind_addr,
                bind_port = %nl.bind_port,
                "net listener"
            );
        }
    }

    // Lab PR 236 (multi-match): every rule judged the event; the decision
    // names the primary rule and every match, and runs, per target, the
    // strongest response the per-rule policy allows.
    if let Some(decision) = engine.decide(&event) {
        let verdict = &decision.verdict;
        // Review 75: every verdict is acted on; its log lines and its
        // record count against the primary rule's budget for the acting uid.
        let uid = northnarrow_agent::detection_store::Principal::from_event(&event).uid;
        let admit = budget_admit(&verdict.rule_id, uid, &event);
        if admit.record() {
            let also: Vec<&str> = decision
                .matches
                .iter()
                .filter(|m| m.rule_id != verdict.rule_id)
                .map(|m| m.rule_id)
                .collect();
            if decision.audit_only() {
                info!(
                    rule = %verdict.rule_id,
                    also = ?also,
                    severity = ?verdict.severity,
                    target_pid = verdict.event_pid,
                    reasoning = %Escaped(&verdict.reasoning),
                    "AUDIT (rule, per-rule policy)"
                );
            } else {
                warn!(
                    rule = %verdict.rule_id,
                    rule_name = %verdict.rule_name,
                    category = %verdict.category,
                    action = ?verdict.action,
                    severity = ?verdict.severity,
                    also = ?also,
                    target_pid = verdict.event_pid,
                    target_filename = %Escaped(&verdict.event_filename),
                    reasoning = %Escaped(&verdict.reasoning),
                    "VERDICT (rule)"
                );
            }
        }

        // External audit CMB-004: what the event says about the process
        // the verdict is about — its start (an exec), the event's time — so
        // a kill does not reach a process that took the PID after the event.
        let owner = northnarrow_agent::posture::triggers::event_owner_pid(&event);
        let (owner_start_ns, owner_seen_ns) =
            northnarrow_agent::posture::triggers::event_owner_seen(&event);
        let mut reports = Vec::new();
        if decision.responses.is_empty() {
            // A Log decision runs nothing: no blocking task for it.
            reports.push((
                None,
                executor.execute(nn_model::ResponseAction::Log, verdict.event_pid),
            ));
        }
        for response in &decision.responses {
            let exec = executor.clone();
            let action = response.action.clone();
            let target_pid = response.pid;
            let target_file = response.filename.clone();
            let (target_start_ns, target_seen_ns) = if owner == Some(target_pid) {
                (owner_start_ns, owner_seen_ns)
            } else {
                (0, 0)
            };
            let report = match tokio::task::spawn_blocking(move || {
                exec.execute_for_started(
                    action,
                    target_pid,
                    target_start_ns,
                    target_seen_ns,
                    &target_file,
                )
            })
            .await
            {
                Ok(r) => r,
                Err(e) => {
                    warn!(error = %e, "executor task join failed");
                    return;
                }
            };
            reports.push((Some(response), report));
        }
        // Lab PR 222: a ransomware rule's match flags its writer, and a kill
        // of that process (whichever matched rule's response it was)
        // neutralized it.
        for m in &decision.matches {
            let pid = m.verdict.event_pid;
            let neutralized = reports.iter().any(|(r, report)| {
                r.is_some_and(|r| r.pid == pid)
                    && matches!(
                        report.primary,
                        northnarrow_agent::response::ExecutionOutcome::Killed { .. }
                            | northnarrow_agent::response::ExecutionOutcome::AlreadyGone { .. }
                    )
            });
            northnarrow_agent::cow::after_rule_response(m.rule_id, pid, neutralized);
        }
        if let Admit::Record { suppressed_before } = admit {
            for (_, report) in &reports {
                info!(
                    action = ?report.action,
                    primary = ?report.primary,
                    additional_count = report.additional.len(),
                    elapsed_us = report.elapsed.as_micros() as u64,
                    "EXECUTED"
                );
            }
            // Tappa 9.0.a: persist the rule detection (off the hot path).
            if let Some(sink) = detection_sink {
                let response = match reports.as_slice() {
                    [(_, only)] => northnarrow_agent::detection_store::describe_response(only),
                    many => many
                        .iter()
                        .map(|(r, report)| {
                            format!(
                                "{} (pid {}, {})",
                                northnarrow_agent::detection_store::describe_response(report),
                                r.map_or(verdict.event_pid, |r| r.pid),
                                r.map_or("", |r| r.rule_id)
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("; "),
                };
                sink.record_decision(
                    &event,
                    &decision,
                    posture.current_kind(),
                    response,
                    suppressed_before,
                );
            }
        }
    }
}

/// [`detection_budget::admit`], plus one WARN when a (rule, uid) runs out
/// of budget (review 75). The counts of what it held back reach the
/// journal and the audit log through the budget's reporter task.
fn budget_admit(rule: &str, uid: u32, event: &Event) -> Admit {
    let admit = detection_budget::admit(rule, uid, || {
        northnarrow_agent::detection_store::held_sample(event)
    });
    if admit == (Admit::Hold { first: true }) {
        warn!(
            rule,
            uid,
            burst = detection_budget::BURST,
            "detections of this rule and uid exceed the record budget: further ones are acted on \
             and counted, one per second is logged and stored, until the rate falls"
        );
    }
    admit
}

/// Render a 16-byte address according to family (`2` = AF_INET → first
/// 4 bytes; `10` = AF_INET6 → full v6).
fn render_addr(family: u8, bytes: &[u8; 16]) -> String {
    // External audit NET-001: one form in the logs, IPv4-mapped folded.
    if family == 2 || family == 10 {
        nn_model::netaddr::canonical_ip(family, bytes).to_string()
    } else {
        format!("family={family}")
    }
}
