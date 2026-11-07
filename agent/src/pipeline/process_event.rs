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

use super::dispatch::{Decided, Dispatcher, ResponseJob};
use super::{HostStopping, SystemdAnswer, SystemdSnapshot};

/// Categorise + log + evaluate + (maybe) execute.
///
/// Tappa 4 ships five sensors; Tappa 2 rules only match `ProcessSpawn`,
/// so non-spawn events flow through as DEBUG telemetry and bypass the
/// engine.
///
/// Tappa 6: every event also lands in the correlation buffer, the recent
/// events the posture triggers read. An event no rule matches gets no
/// verdict: the LLM advisor that judged such execs was removed in Wave 4
/// (lab PR 214).
///
/// R12b (lab PR 269, plan §3.4): the decision thread's — no `await`, and no
/// blocking I/O of its own (the guard: xtask `decision_path_io`): an
/// exec's path is made absolute in its pump, systemd's state is the watch's
/// snapshot, the trusted-installer window's expiry is its tick's (external
/// audit ATP-003), the canary's access row its writer's. R12c (lab PR 270):
/// the responses a decision runs are handed to the response dispatcher
/// (`dispatch`: a queue push, never a wait), which signs each one's intent
/// before it acts and its outcome after; an acting decision's record is
/// never held by the record budget.
#[allow(clippy::too_many_arguments)]
pub(crate) fn process_event(
    engine: &RuleEngine,
    executor: &Executor,
    correlation: &CorrelationBuffer,
    posture: &PostureMachine,
    ladder: &northnarrow_agent::combat::CombatLadder,
    canary_detector: Option<&northnarrow_agent::canary::detector::Detector>,
    // Tappa 9.0.a: detection-persistence sink. `None` ⇒ not persisting
    // this boot (e.g. signing key / store open failed at startup). All
    // record calls are off the hot path (bounded queue + writer task).
    detection_sink: Option<&northnarrow_agent::detection_store::DetectionSink>,
    // R11c (lab PR 264): the run's handles the start gives the event loop
    // (they were process-wide statics): the self-test's own denial, the
    // host's stop, the copy-on-first-write guard.
    expected_denial: &northnarrow_agent::boot::deny_selftest::ExpectedDenial,
    host_stopping: &HostStopping,
    // R12b (lab PR 269): systemd's state, the watch's snapshot.
    systemd: &SystemdSnapshot,
    cow_guard: &northnarrow_agent::cow::CowGuard,
    // R12c (lab PR 270): where the decision's responses go.
    dispatcher: &Dispatcher,
    event: Event,
) {
    // Lab PR 218: the deny self-test's own refused signal is the boot's
    // measurement, not an attempt on the agent — taken before the posture
    // (it would raise COMBAT) and the rules; any other denial goes on.
    if expected_denial.take(&event) {
        return;
    }
    // Tappa 10.9 step 2: an exec event's path is absolute before any
    // consumer reads it (review 61) — R12b: made so in its pump
    // (`multiplexer::resolved`), right after the kernel recorded it.
    // Lab PR 223: the exec quarantine resumes a held process only once
    // this exec has been judged — dropped at the end of this function,
    // after a kill the rules decided was carried out.
    let _execq_judged = northnarrow_agent::execq::SpawnGuard::for_event(&event);
    // FIM-009 self-upgrade (§15.1): a trusted-installer window past its
    // deadline is closed by its tick (external audit ATP-003, every second;
    // the kernel's grant ends at the deadline by itself, and the rule reads
    // the window's own deadline) — R12b: no longer swept here.

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
        // R12b (lab PR 269): the watch's answer, at most a second old; an
        // older one hands the event to the watch, which asks systemd and
        // sends it back on the bus (`SystemdSnapshot`).
        let state = match systemd.judge(&event, Instant::now()) {
            SystemdAnswer::Judge(state) => state,
            SystemdAnswer::Deferred => {
                debug!(
                    signal = sig,
                    target, "signal relayed by systemd: judged once systemd has answered"
                );
                return;
            }
        };
        if state.as_deref() == Some("stopping") {
            info!(
                signal = sig,
                target,
                "systemd is stopping the host — its signal to a protected process is refused \
                 until systemd-shutdown's final stage (expected, not an attempt)"
            );
            host_stopping.stand_down(ladder);
            return;
        }
        info!(
            signal = sig,
            target,
            systemd_state = state.as_deref().unwrap_or("(no answer)"),
            "signal relayed by systemd outside a trusted-installer window — not a shutdown"
        );
    }

    // Lot 273c (the review of #490): PID 1's write of a protected resource
    // file, or its new drop-in, refused — a `systemctl set-property`
    // outside a window, which still set systemd's own copy of the property
    // for the unit's next start: a reload takes that copy back to the
    // unit's files (rate-limited, signed; the denial goes on as before).
    if let Event::FsProtectDenial {
        pid: 1,
        operation,
        target_dev,
        target_ino,
        ..
    } = &event
    {
        let op = match operation {
            nn_model::FsProtectOperation::CgroupLimit => Some("cgroup_limit"),
            nn_model::FsProtectOperation::Create => Some("create"),
            _ => None,
        };
        if let Some(op) = op {
            systemd.reload(northnarrow_agent::systemd_reload::Reason::Refused {
                op,
                dev: *target_dev,
                ino: *target_ino,
            });
        }
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
    // Lab PR 267 (review #471 A1), R12b (R-F): the event is judged on the
    // lineage as of its own time — on the priority bus an exec of its
    // process may have been taken, or handed over, ahead of it. Each judge
    // takes that time from the event itself
    // (`nn_core::posture::lineage::AsOf::of_event`), explicitly: no scope
    // set around the calls.
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
    let host_stopping = host_stopping.is_stopping();
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
    cow_guard.observe_event(&event);
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
            cgroup_id,
            ..
        } => info!(
            pid = *pid,
            comm = %Escaped(comm),
            overwrites = *count,
            last = %Escaped(filename),
            cgroup = *cgroup_id,
            "mass write: overwrite threshold crossed by the processes of one cgroup (counted in the kernel)"
        ),
        // Lot 282: the kernel counts distinct existing files rewritten and
        // files written new apart (it counted write-opens); the review of
        // #500: the rewrites of files under 4 KiB too (`small_files`), and
        // every crossing names its cgroup (the replacement's halves pair
        // there).
        Event::MassWrite {
            pid,
            comm,
            count,
            filename,
            overwrites: true,
            small_files,
            cgroup_id,
            ..
        } => info!(
            pid = *pid,
            comm = %Escaped(comm),
            rewritten = *count,
            small_files = *small_files,
            last = %Escaped(filename),
            cgroup = *cgroup_id,
            "mass write: distinct existing files rewritten crossed the threshold (counted in the kernel)"
        ),
        Event::MassWrite {
            pid,
            comm,
            count,
            filename,
            cgroup_id,
            ..
        } => info!(
            pid = *pid,
            comm = %Escaped(comm),
            created = *count,
            last = %Escaped(filename),
            cgroup = *cgroup_id,
            "mass write: files created crossed the threshold (files written new — created, or empty when opened; counted in the kernel)"
        ),
        // Lab PR 225: the rename and unlink bursts (NN-L-IMP-001/002 read them).
        Event::FileBurst {
            pid,
            comm,
            kind,
            count,
            filename,
            cgroup_id,
            ..
        } => info!(
            pid = *pid,
            comm = %Escaped(comm),
            kind = kind.as_str(),
            count = *count,
            last = %Escaped(filename),
            cgroup = *cgroup_id,
            "file burst: rename or destroyed-originals threshold crossed (counted in the kernel)"
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
            // Lot 281: code-injection access to a process (its first: the
            // kernel taints its mark) — signed only when an exemption of the
            // per-rule policy covered it: High, Critical from a non-root
            // injector or one outside an administrator's interactive
            // session. Any other process's is a debug line.
            let injection = *operation == nn_model::FsProtectOperation::ExemptInjection;
            let covered = injection
                .then(|| u32::try_from(*target_ino).ok())
                .flatten()
                .and_then(|t| engine.exempt_covering(t));
            if injection && covered.is_none() {
                debug!(
                    pid, uid, comm = %Escaped(comm),
                    injected_pid = target_ino,
                    detail = target_dev,
                    "code-injection access to a process no exemption covers (its mark tainted)"
                );
                return;
            }
            let verdict = match &covered {
                Some(exemption) => {
                    let admin = posture.interactive_admin_status(
                        *pid,
                        northnarrow_agent::posture::lineage::AsOf::of_event(&event),
                    );
                    northnarrow_agent::decision::rules::anti_tamper::exempt_injection(
                        &event, exemption, admin,
                    )
                }
                None => at001.evaluate(&event),
            };
            // Review 75: a loop of denied attempts is logged and stored
            // within the rule's budget for that uid.
            let admit = match &verdict {
                Some(v) => budget_admit(&v.rule_id, *uid, &event),
                None => Admit::Record {
                    suppressed_before: 0,
                },
            };
            // Lot 277: a move into a cgroup an exemption names is not a
            // refusal: the move went through, the moved tree lost its
            // exemptions by cgroup or unit (the kernel's mark).
            let joined = *operation == nn_model::FsProtectOperation::CgroupJoin;
            // Lot 280a: a write the signed per-sysctl opt-out let through —
            // recorded, not refused.
            let opted_out = *operation == nn_model::FsProtectOperation::SysctlOptOut;
            // Lot 280b: what the kernel-state round found — the kernel's own
            // record, not a refusal.
            // Lot 290: and its BPF cross-view.
            let found = matches!(
                operation,
                nn_model::FsProtectOperation::KernelTaint
                    | nn_model::FsProtectOperation::SysctlRootProg
                    | nn_model::FsProtectOperation::BpfUnseen
                    | nn_model::FsProtectOperation::BpfBaseline
            );
            // Lot 290: a load the signed per-loader opt-out let through.
            let loader_opted_out =
                *operation == nn_model::FsProtectOperation::BpfProgOptOut;
            let exemption = joined
                .then(|| {
                    nn_linux::cgroup_join::exemption_named(&engine.policy().current(), *target_dev)
                })
                .flatten();
            if admit.record() {
                if let Some(exemption) = &covered {
                    warn!(
                        pid, uid, comm = %Escaped(comm),
                        injected_pid = target_ino,
                        exemption = %exemption,
                        "EXEMPTION REVOKED: code-injection access to an exempt process — not \
                         refused; that process and what it forks are never exempt again"
                    );
                } else if joined {
                    warn!(
                        pid, uid, comm = %Escaped(comm),
                        moved = target_ino,
                        exemption = exemption.as_deref().unwrap_or("(a path too long to match)"),
                        "CGROUP EXEMPTION SPOOF: a process moved into an exempt cgroup by someone \
                         other than systemd — not refused; it and what it starts are never exempt \
                         by that cgroup or unit"
                    );
                } else if loader_opted_out {
                    warn!(
                        pid, uid, comm = %Escaped(comm),
                        prog_type = target_ino,
                        "BPF LOADER OPT-OUT: a refused program type's load let through by the \
                         signed per-rule policy's bpf-loader-allow (recorded, not refused)"
                    );
                } else if opted_out {
                    let (kind, value) = common::sysctl_judge::record_of(*target_dev, *target_ino);
                    warn!(
                        pid, uid, comm = %Escaped(comm),
                        sysctl = common::sysctl_judge::name_of_kind(kind).unwrap_or("?"),
                        value = ?value,
                        "SYSCTL OPT-OUT: a guarded sysctl's write let through by the signed \
                         per-rule policy's sysctl-allow (recorded, not refused)"
                    );
                } else if found {
                    warn!(
                        op = %operation,
                        target_dev, target_ino,
                        "KERNEL STATE: found by the kernel-state round (not refused)"
                    );
                } else {
                    warn!(
                        pid, uid, comm = %Escaped(comm),
                        op = %operation,
                        target_dev, target_ino,
                        "ANTI-TAMPER DENIAL"
                    );
                }
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
                        // Lot 273: who, by executable too.
                        let outcome = if let Some(exemption) = &covered {
                            format!(
                                "not refused: the exemption ({exemption}) and every other no \
                                 longer hold for pid {target_ino} or what it forks \
                                 (start-in-cgroup tracker, injection taint)"
                            )
                        } else if joined {
                            format!(
                                "not refused: the moved process and every process it starts are \
                                 never exempt by {} (start-in-cgroup tracker)",
                                exemption.as_deref().unwrap_or("the cgroup or the unit")
                            )
                        } else if opted_out {
                            "not refused: let through by the signed per-rule policy's \
                             sysctl-allow (cgroup/sysctl or the write deny)"
                                .to_string()
                        } else if *operation == nn_model::FsProtectOperation::KernelTaint {
                            "not refused: a taint flag of code entering the kernel, read by the \
                             kernel-state round"
                                .to_string()
                        } else if *operation == nn_model::FsProtectOperation::SysctlRootProg {
                            "not refused: found on the root cgroup's cgroup/sysctl slot by the \
                             kernel-state round"
                                .to_string()
                        } else if loader_opted_out {
                            "not refused: let through by the signed per-rule policy's \
                             bpf-loader-allow (the loader's executable and the type)"
                                .to_string()
                        } else if matches!(
                            operation,
                            nn_model::FsProtectOperation::BpfUnseen
                                | nn_model::FsProtectOperation::BpfBaseline
                        ) {
                            "not refused: found by the BPF cross-view of the kernel-state round"
                                .to_string()
                        } else if *operation == nn_model::FsProtectOperation::BpfProgType {
                            "denied in kernel (the bpf LSM hook: a refused program type)"
                                .to_string()
                        } else if *operation == nn_model::FsProtectOperation::BpfHandle {
                            "denied in kernel (the BPF guard: a handle on the agent's own object)"
                                .to_string()
                        } else if *operation == nn_model::FsProtectOperation::SysctlRootAttach {
                            "denied in kernel (the bpf LSM hook: an attach to the root cgroup)"
                                .to_string()
                        } else if *operation == nn_model::FsProtectOperation::SysctlValue {
                            "denied in kernel (cgroup/sysctl on the root cgroup, the kernel's \
                             copy of the write)"
                                .to_string()
                        } else {
                            "denied in kernel (anti-tamper LSM hook)".to_string()
                        };
                        sink.record_denial(
                            &event,
                            &verdict,
                            at001.attack(),
                            posture.current_kind(),
                            outcome,
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
            // R12c (lab PR 270): a task the kernel killed is an action —
            // its record is never held by the budget (its lines are).
            let admit = match &verdict {
                Some(v) if *killed => {
                    let a = budget_admit_acted(&v.rule_id, *uid);
                    if a.lines {
                        Admit::Record {
                            suppressed_before: a.suppressed_before,
                        }
                    } else {
                        Admit::Hold { first: false }
                    }
                }
                Some(v) => budget_admit(&v.rule_id, *uid, &event),
                None => Admit::Record {
                    suppressed_before: 0,
                },
            };
            let record_anyway = *killed;
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
                let recorded = match admit {
                    Admit::Record { suppressed_before } => {
                        warn!(
                            rule = %verdict.rule_id,
                            severity = ?verdict.severity,
                            reasoning = %Escaped(&verdict.reasoning),
                            "VERDICT (rule)"
                        );
                        Some(suppressed_before)
                    }
                    Admit::Hold { .. } if record_anyway => Some(0),
                    Admit::Hold { .. } => None,
                };
                if let (Some(suppressed_before), Some(sink)) = (recorded, detection_sink) {
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
        // Lot 275: one line per inbound flow row, DNS response and hello —
        // DEBUG, as the outbound flows (review 71); their records are the
        // netflow log and the rules'.
        Event::NetInbound(nf) => {
            debug!(
                pid = %nf.pid,
                comm = %Escaped(&nf.comm),
                peer = %nf.src_addr,
                peer_port = %nf.src_port,
                local_port = %nf.dst_port,
                phase = nf.phase.as_str(),
                "inbound flow"
            );
        }
        Event::DnsAnswer(a) => {
            debug!(
                pid = %a.pid,
                comm = %Escaped(&a.comm),
                query = %Escaped(a.query_name.as_deref().unwrap_or("")),
                answers = a.addrs.len(),
                rcode = a.rcode,
                "dns answer"
            );
        }
        Event::TlsClientHello(h) => {
            debug!(
                pid = %h.pid,
                comm = %Escaped(&h.comm),
                dst_addr = %h.dst_addr,
                dst_port = %h.dst_port,
                outcome = h.outcome.as_str(),
                ja4 = %Escaped(h.fingerprint.as_ref().map_or("", |f| f.ja4.as_str())),
                "tls client hello"
            );
        }
    }

    // Lab PR 236 (multi-match): every rule judged the event; the decision
    // names the primary rule and every match, and runs, per target, the
    // strongest response the per-rule policy allows. Lot 278: in the
    // posture the event left (observed above) — R009 kills in COMBAT only.
    // Review of #493 (note b): read once — the record and the response
    // name the posture the decision was made in (an admin release on
    // another thread may move it meanwhile).
    let judged_in = posture.current_kind();
    if let Some(decision) = engine.decide_in(&event, judged_in) {
        let verdict = &decision.verdict;
        // Review 75: every verdict is acted on; its log lines and its
        // record count against the primary rule's budget for the acting uid.
        // R12c (lab PR 270; plan §3.4): a decision that acts is always
        // recorded — the budget holds only its journal lines.
        let uid = northnarrow_agent::detection_store::Principal::from_event(&event).uid;
        let acts = !decision.responses.is_empty();
        let (record, lines, suppressed_before) = if acts {
            let a = budget_admit_acted(&verdict.rule_id, uid);
            (true, a.lines, a.suppressed_before)
        } else {
            match budget_admit(&verdict.rule_id, uid, &event) {
                Admit::Record { suppressed_before } => (true, true, suppressed_before),
                Admit::Hold { .. } => (false, false, 0),
            }
        };
        if lines {
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

        // Lab PR 222: a ransomware rule's match flags its writer for the
        // copy-on-first-write guard now; the dispatcher tells it the kill
        // that neutralized it once the kill ran.
        for m in &decision.matches {
            cow_guard.after_rule_response(m.rule_id, m.verdict.event_pid, false);
        }
        if !acts {
            // A Log decision runs nothing: no action, so no intent.
            if record {
                let report = executor.log_report(verdict.event_pid);
                if lines {
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
                    sink.record_decision(
                        &event,
                        &decision,
                        judged_in,
                        northnarrow_agent::detection_store::describe_response(&report),
                        suppressed_before,
                    );
                }
            }
            return;
        }
        // External audit CMB-004: what the event says about the process
        // the verdict is about — its start (an exec), the event's time — so
        // a kill does not reach a process that took the PID after the event.
        let owner = northnarrow_agent::posture::triggers::event_owner_pid(&event);
        let (owner_start_ns, owner_seen_ns) =
            northnarrow_agent::posture::triggers::event_owner_seen(&event);
        // R12c: the responses to the dispatcher — signed intent, the
        // action, signed outcome, then the record — off this thread.
        let decided = Decided::new(event, decision, judged_in, suppressed_before, lines);
        dispatcher.submit(ResponseJob::of(
            &decided,
            owner,
            owner_start_ns,
            owner_seen_ns,
        ));
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

/// R12c (lab PR 270): [`detection_budget::admit_acted`] — an acting
/// decision is always recorded; the WARN when its (rule, uid) runs out of
/// budget for journal lines.
fn budget_admit_acted(rule: &str, uid: u32) -> detection_budget::Acted {
    let a = detection_budget::admit_acted(rule, uid);
    if a.first {
        warn!(
            rule,
            uid,
            burst = detection_budget::BURST,
            "detections of this rule and uid exceed the record budget: their responses run and \
             their records and action rows are written; one journal line per second, until the \
             rate falls"
        );
    }
    a
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use nn_model::Event;
    use northnarrow_agent::response::journal::{ActionJournal, ActionRow};
    use northnarrow_agent::response::{Executor, ExecutorConfig};

    use super::*;
    use crate::pipeline::dispatch::{Dispatcher, Followups};

    fn exec_from_tmp(pid: u32, uid: u32) -> Event {
        Event::ProcessSpawn {
            pid,
            ppid: 1,
            uid,
            gid: uid,
            comm: "payload".to_string(),
            filename: "/tmp/nn-r12c-test/payload".to_string(),
            timestamp_ns: 1_000 + u64::from(pid),
            argv: Vec::new(),
            parent_comm: String::new(),
            parent_start_ns: 0,
            start_ns: 0,
            parent_is_kthread: false,
            exe: Default::default(),
            argv_truncated: false,
            filename_truncated: false,
            stdio: Default::default(),
        }
    }

    /// R12c (lab PR 270; plan §3.4): the decision hands its responses to
    /// the dispatcher, and an acting decision is recorded past the record
    /// budget — its journal lines held, never its record nor its action's
    /// rows. 150 execs from /tmp of one uid (NN-L-R001, KillProcessTree;
    /// the budget's burst is 100): 150 detection records, 150 intents each
    /// answered by its outcome (detect-only: none touches the host).
    #[test]
    fn an_acting_decision_is_dispatched_and_recorded_past_the_budget() {
        let tmp = tempfile::tempdir().unwrap();
        let exec = Executor::with_config(ExecutorConfig::for_test(tmp.path()));
        assert!(exec.config().dry_run);
        let journal = ActionJournal::memory();
        let sink = northnarrow_agent::detection_store::DetectionSink::for_test(4096, 0);
        let cow = northnarrow_agent::cow::CowGuard::off_for_test();
        let dispatcher = Dispatcher::start(
            exec.clone(),
            journal.clone(),
            Followups {
                sink: Some(sink.clone()),
                cow: cow.clone(),
            },
            None,
        );
        let engine = RuleEngine::with_default_rules();
        let correlation = CorrelationBuffer::with_default_capacity();
        let posture = PostureMachine::new();
        let ladder = northnarrow_agent::combat::CombatLadder::new(
            Box::new(northnarrow_agent::combat::SystemActuator::new(
                exec.clone(),
                None,
                true,
                journal.clone(),
            )),
            Box::new(northnarrow_agent::combat::AuditEvidence::new(None)),
            Box::new(northnarrow_agent::combat::NoProtectedProcs),
            northnarrow_agent::combat::LadderConfig::default(),
        );
        let expected = northnarrow_agent::boot::deny_selftest::ExpectedDenial::default();
        let stopping = HostStopping::default();
        let systemd = SystemdSnapshot::default();
        // a uid of this test's own: the budget is the process's; a system
        // account's (below UID_MIN): lot 283b records a person's exec from
        // /tmp below COMBAT, a system account's stays R001's kill
        let uid = 977;
        for i in 0..150u32 {
            process_event(
                &engine,
                &exec,
                &correlation,
                &posture,
                &ladder,
                None,
                Some(&sink),
                &expected,
                &stopping,
                &systemd,
                &cow,
                &dispatcher,
                exec_from_tmp(910_000 + i, uid),
            );
        }
        dispatcher.stop(Duration::from_secs(10));
        let records = sink.queued_for_test();
        let r001: Vec<_> = records
            .iter()
            .filter(|r| format!("{:?}", r.verdict).contains("KillProcessTree"))
            .collect();
        assert_eq!(r001.len(), 150, "every acting decision is recorded");
        assert!(
            r001.iter().all(|r| r.response.contains("detect-only")),
            "{r001:#?}"
        );
        let rows = journal.rows();
        let rule_intents: Vec<_> = rows
            .iter()
            .filter(|r| {
                r.row == ActionRow::Intent && r.intent.as_ref().is_some_and(|i| i.source == "rule")
            })
            .collect();
        assert_eq!(rule_intents.len(), 150, "an intent per response");
        for i in &rule_intents {
            assert!(
                rows.iter()
                    .any(|o| o.row == ActionRow::Outcome && o.run == i.run && o.action == i.action),
                "intent {} unanswered",
                i.action
            );
        }
        let st = dispatcher.status();
        assert_eq!(st.queue.lost(), 0);
        // recorded, so never counted as held (the signed detections_held
        // rows count what was not recorded)
        let held = northnarrow_agent::detection_budget::take_held();
        assert!(
            !held.iter().any(|h| h.uid == uid),
            "an acting decision counted held: {held:?}"
        );
    }

    /// R12c (lab PR 270): the exploit guard's kills in the kernel are
    /// recorded whatever the budget (120 of them, past its burst of 100);
    /// a Log decision runs nothing — no intent — and is recorded within it.
    #[test]
    fn the_kernel_s_kills_are_recorded_past_the_budget_and_a_log_decision_runs_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        // enforcing: nothing here acts (the kernel killed, `nc` is logged)
        let exec = Executor::with_config(ExecutorConfig {
            dry_run: false,
            ..ExecutorConfig::for_test(tmp.path())
        });
        let journal = ActionJournal::memory();
        let sink = northnarrow_agent::detection_store::DetectionSink::for_test(4096, 0);
        let cow = northnarrow_agent::cow::CowGuard::off_for_test();
        let dispatcher = Dispatcher::start(
            exec.clone(),
            journal.clone(),
            Followups {
                sink: Some(sink.clone()),
                cow: cow.clone(),
            },
            None,
        );
        let engine = RuleEngine::with_default_rules();
        let correlation = CorrelationBuffer::with_default_capacity();
        let posture = PostureMachine::new();
        let ladder = northnarrow_agent::combat::CombatLadder::new(
            Box::new(northnarrow_agent::combat::SystemActuator::new(
                exec.clone(),
                None,
                true,
                journal.clone(),
            )),
            Box::new(northnarrow_agent::combat::AuditEvidence::new(None)),
            Box::new(northnarrow_agent::combat::NoProtectedProcs),
            northnarrow_agent::combat::LadderConfig::default(),
        );
        let expected = northnarrow_agent::boot::deny_selftest::ExpectedDenial::default();
        let stopping = HostStopping::default();
        let systemd = SystemdSnapshot::default();
        let judge = |e: Event| {
            process_event(
                &engine,
                &exec,
                &correlation,
                &posture,
                &ladder,
                None,
                Some(&sink),
                &expected,
                &stopping,
                &systemd,
                &cow,
                &dispatcher,
                e,
            )
        };
        use nn_core::decision::rules::epg::testutil::epg_event;
        for _ in 0..120 {
            judge(epg_event(nn_model::EpgKind::CredNoMechanism, true));
        }
        let mut nc = exec_from_tmp(7_777, 77_002);
        if let Event::ProcessSpawn { comm, filename, .. } = &mut nc {
            *comm = "nc".to_string();
            *filename = "/usr/bin/nc".to_string();
        }
        judge(nc);
        dispatcher.stop(Duration::from_secs(10));
        let records = sink.queued_for_test();
        let killed = records
            .iter()
            .filter(|r| r.response.contains("killed in kernel"))
            .count();
        assert_eq!(killed, 120, "every kernel kill recorded");
        let nc_records: Vec<_> = records
            .iter()
            .filter(|r| r.principal.pid == 7_777)
            .collect();
        assert_eq!(nc_records.len(), 1, "{records:#?}");
        assert_eq!(
            nc_records[0].response, "none",
            "a Log decision runs nothing"
        );
        // R12c-3: the run's end is the journal's one row (the stop's)
        assert!(
            journal
                .rows()
                .iter()
                .all(|r| r.row == northnarrow_agent::response::journal::ActionRow::RunEnded),
            "no action: no intent ({:#?})",
            journal.rows()
        );
    }
}
