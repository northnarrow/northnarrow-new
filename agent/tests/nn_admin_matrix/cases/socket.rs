//! Every socket verb against the mock agent: each success reply the verb
//! renders differently, the ten refusals (every `AdminResult` but
//! `Success`), the transport faults (seven for a signed verb, five for an
//! unsigned one), no socket, and a socket nobody listens on.

use nn_model::posture_types::PostureKind;
use nn_proto::admin_protocol::{AdminMessage, AdminResult, StatusResponse};
use serde_json::{json, Value};

use crate::fixtures;
use crate::harness::{Case, Put, Special};
use crate::mock::{Reply, Script};

/// A message from its JSON (the wire types derive serde).
pub fn msg(v: Value) -> AdminMessage {
    serde_json::from_value(v.clone()).unwrap_or_else(|e| panic!("{v}: {e}"))
}

fn result_json(r: AdminResult) -> Value {
    serde_json::to_value(r).unwrap()
}

/// The ten refusals, by name.
pub fn refusals() -> Vec<(&'static str, AdminResult)> {
    vec![
        ("invalid-signature", AdminResult::InvalidSignature),
        ("no-pending-challenge", AdminResult::NoPendingChallenge),
        (
            "rate-limited",
            AdminResult::RateLimited {
                retry_after_secs: 7,
            },
        ),
        ("role-denied", AdminResult::RoleDenied),
        (
            "quorum-not-met",
            AdminResult::QuorumNotMet {
                required: 2,
                provided: 1,
            },
        ),
        (
            "timestamp-skew",
            AdminResult::TimestampSkew {
                server_ts: fixtures::FIXTURE_TS,
                max_skew_secs: 30,
            },
        ),
        ("agent-id-mismatch", AdminResult::AgentIdMismatch),
        ("unknown-operation", AdminResult::UnknownOperation),
        (
            "protocol-version-unsupported",
            AdminResult::ProtocolVersionUnsupported { server_version: 1 },
        ),
        ("action-failed", AdminResult::ActionFailed),
    ]
}

/// A message no verb expects.
fn stray() -> Reply {
    Reply::send(
        "LoopProgressResponse (no verb's reply)",
        msg(json!({"LoopProgressResponse": {"iterations": 3, "since_last_ms": 5}})),
    )
}

/// The transport faults of a signed verb (challenge, then the request).
pub fn signed_faults() -> Vec<(&'static str, Script)> {
    vec![
        ("closed-at-challenge", Script::Replies(vec![Reply::Close])),
        ("wrong-challenge", Script::Replies(vec![stray()])),
        ("closed-at-reply", Script::signed(Reply::Close)),
        ("garbage-reply", Script::signed(Reply::Garbage)),
        ("oversize-reply", Script::signed(Reply::Oversize)),
        ("truncated-reply", Script::signed(Reply::Truncated)),
        ("wrong-reply", Script::signed(stray())),
    ]
}

/// The transport faults of an unsigned verb (one request).
pub fn unsigned_faults() -> Vec<(&'static str, Script)> {
    vec![
        ("closed-at-reply", Script::unsigned(Reply::Close)),
        ("garbage-reply", Script::unsigned(Reply::Garbage)),
        ("oversize-reply", Script::unsigned(Reply::Oversize)),
        ("truncated-reply", Script::unsigned(Reply::Truncated)),
        ("wrong-reply", Script::unsigned(stray())),
    ]
}

/// One verb of the admin socket.
pub struct Verb {
    pub name: String,
    pub args: Vec<String>,
    pub signed: bool,
    /// The replies the verb renders on success, by name.
    pub success: Vec<(String, AdminMessage)>,
    /// The verb's reply carrying a refusal.
    pub refusal: Box<dyn Fn(AdminResult) -> AdminMessage>,
    pub put: Vec<Put>,
    pub special: Special,
}

fn words(s: &str) -> Vec<String> {
    s.split_whitespace().map(str::to_string).collect()
}

const SIGNED: &str = "--key key-a --agent-id-file agent_id --socket admin.sock";

fn verb(
    name: &str,
    args: &str,
    success: Vec<(&str, AdminMessage)>,
    refusal: impl Fn(AdminResult) -> AdminMessage + 'static,
) -> Verb {
    Verb {
        name: name.to_string(),
        args: words(args),
        signed: true,
        success: success
            .into_iter()
            .map(|(n, m)| (n.to_string(), m))
            .collect(),
        refusal: Box::new(refusal),
        put: Vec::new(),
        special: Special::None,
    }
}

/// A reply that is a bare `AdminResult` (`ShutdownResult(…)`, …).
fn bare(variant: &'static str) -> impl Fn(AdminResult) -> AdminMessage {
    move |r| msg(json!({ variant: result_json(r) }))
}

/// A reply `{result, …fields}`.
fn with(variant: &'static str, fields: Value) -> impl Fn(AdminResult) -> AdminMessage {
    move |r| {
        let mut f = fields.clone();
        f["result"] = result_json(r);
        msg(json!({ variant: f }))
    }
}

fn jsonl_reply(
    variant: &'static str,
) -> (
    impl Fn(AdminResult) -> AdminMessage,
    Vec<(&'static str, AdminMessage)>,
) {
    let make = with(
        variant,
        json!({"entries_jsonl": "", "entries_count": 0, "entries_truncated": false}),
    );
    let rows = "{\"seq\":0,\"ts\":\"2025-06-15T15:06:40Z\",\"path\":\"/etc/matrix/a\"}\n\
                {\"seq\":1,\"ts\":\"2025-06-15T15:06:41Z\",\"path\":\"/etc/matrix/b\"}\n";
    let one = |jsonl: &str, count: u32, truncated: bool| {
        msg(json!({ variant: {
            "result": "Success",
            "entries_jsonl": jsonl,
            "entries_count": count,
            "entries_truncated": truncated,
        }}))
    };
    let success = vec![
        ("two-rows", one(rows, 2, false)),
        ("empty", one("", 0, false)),
        ("truncated", one(rows, 2, true)),
    ];
    (make, success)
}

/// The status with every field the agent fills (a signed reply's).
pub fn full_status() -> StatusResponse {
    let mut v = serde_json::to_value(
        StatusResponse::public(
            PostureKind::Engaged,
            true,
            Some(42),
            Some("investigate".to_string()),
            Some(false),
        )
        .with_isolation_families(true, false),
    )
    .unwrap();
    let fill = json!({
        "ringbuf_drops_total": 3,
        "ringbuf_drops": [["exec", 2], ["file", 1]],
        "ringbuf_rejected_total": 1,
        "ringbuf_rejected": [["net", 1]],
        "netflow_rows_skipped_total": 4,
        "netflow_pending_evicted_total": 2,
        "net_inactive_rules": ["NN-L-NET-020"],
        "flow_sock_pending": 5,
        "flow_sock_capacity": 4096,
        "flow_sock_forgotten_min": 1,
        "detect_only": true,
        "detect_only_source": "config file",
        "combat_evidence_unrecorded": 1,
        "combat_evidence_pending": 2,
        "combat_evidence_dropped": 0,
        "net_dot_rows_total": 6,
        "net_dot_rows_resolver": 2,
        "net_quic_rows_total": 7,
        "deny_fail_open_total": 2,
        "deny_fail_open": [["file_open", 2]],
        "trust_level": 2,
        "trust_reasons": ["BTF offsets drifted: 5"],
        "degradations": ["bpf_lsm: anti-tamper: no enforcement"],
        "capability_manifest": capability_manifest(),
        "exploit_guard": {
            "mode": "strict detect", "checked_total": 12, "skipped_privileged_total": 30,
            "anomalies_total": 1, "kills_total": 0, "untracked_total": 2,
            "use_checks_total": 0, "denied_total": 0
        },
        "cow_guard": {
            "state": "active", "flags_source": "built-in", "auto_restore": false,
            "scopes": [{
                "path": "/srv/data", "mark": "fanotify", "journal": "/srv/data/.nn-cow",
                "copy_method": "reflink", "marks": 3, "budget_bytes": 1048576,
                "used_bytes": 4096, "entries": 2, "objects": 2
            }],
            "counters": [["copies", 2], ["skipped_budget", 1]]
        },
        "execq_state": "observe",
        "execq_held_total": 1, "execq_resumed_total": 1, "execq_killed_total": 0,
        "execq_quarantined_total": 0, "execq_defaulted_total": 0,
        "execq_known_identity_total": 3, "execq_known_hash_total": 2,
        "execq_not_held_total": 9, "execq_scanner_deaths_total": 0,
        "net_connect_verdicts_total": 11, "net_flow_snapshots_total": 12,
        "net_flow_snapshots_deferred_total": 1, "net_connect_denied_total": 0,
        "ransomware_decisive_total": 0, "ransomware_signals_total": 4,
        "ransomware_trusted_total": 1, "ransomware_samplings_total": 8,
        "defense_tamper_total": 1, "defense_tamper_sanctioned_total": 1,
        "defense_tools_watched": 6,
        "execpol_state": "audit",
        "execpol_denied_total": 0, "execpol_would_deny_total": 2,
        "execpol_quarantine_total": 0, "execpol_quarantine_inactive_total": 1,
        "execpol_env_denied_total": 0, "execpol_env_recorded_total": 1,
        "execpol_map_denied_total": 0, "execpol_map_recorded_total": 0,
        "execq_script_refused_total": 0,
        // Lab PR 267 (R12a): the event bus and the losses by stage.
        "event_bus": {
            "queues": [
                {"priority": "P0", "class": "tamper", "capacity": 1024,
                 "when_full": "wait 50 ms, then drop for FsProtectDenial (repeats within 1 s coalesced); other tamper events wait, 64 slots kept from denials and bpf() calls; denials and bpf() calls past 256 per uid a second counted, not queued",
                 "enqueued": 12, "dropped": 0,
                 "depth": 0, "max_depth": 3, "max_wait_us": 41, "recent_max_wait_us": 0, "waited": 0,
                 "send_wait_max_us": 0, "ahead": 0, "coalesced": 1499,
                 "decided": 12, "latency_p50_us": 120, "latency_p99_us": 900,
                 "latency_max_us": 950},
                {"priority": "P1", "class": "process", "capacity": 4096,
                 "when_full": "wait 10 ms, then drop", "enqueued": 800, "dropped": 0,
                 "depth": 2, "max_depth": 64, "max_wait_us": 3000, "recent_max_wait_us": 900, "waited": 1,
                 "send_wait_max_us": 2000, "ahead": 0, "coalesced": 0,
                 "decided": 798, "latency_p50_us": 40, "latency_p99_us": 2100,
                 "latency_max_us": 3100},
                {"priority": "P2", "class": "file", "capacity": 8192,
                 "when_full": "drop the new FileOpen (past 2048 opens queued); write-opens of CRITICAL/PERSIST files and other file events wait",
                 "enqueued": 90000, "dropped": 98, "depth": 2048, "max_depth": 2048,
                 "max_wait_us": 450000, "recent_max_wait_us": 300000, "waited": 2,
                 "send_wait_max_us": 1500, "ahead": 9, "coalesced": 0, "decided": 81808,
                 "latency_p50_us": 15, "latency_p99_us": 400000, "latency_max_us": 450000},
                {"priority": "P3", "class": "network", "capacity": 8192,
                 "when_full": "drop the new event", "enqueued": 40, "dropped": 0,
                 "depth": 0, "max_depth": 5, "max_wait_us": 9000, "recent_max_wait_us": 0, "waited": 0,
                 "send_wait_max_us": 0, "ahead": 1, "coalesced": 0,
                 "decided": 40, "latency_p50_us": null, "latency_p99_us": null,
                 "latency_max_us": null}
            ],
            "stages": [
                {"stage": 1, "name": "kernel ring", "total": 3,
                 "source": "RING_DROPS: a ring or map full"},
                {"stage": 2, "name": "kernel budget", "total": 0,
                 "source": "RING_DROPS dns_rate, listen_rate, io_uring_rate, task_denial_rate"},
                {"stage": 3, "name": "decode", "total": 1,
                 "source": "RejectThrottle: malformed records"},
                {"stage": 4, "name": "bus queue", "total": 98,
                 "source": "the event bus, per queue"},
                {"stage": 5, "name": "decision delay", "total": 7,
                 "source": "decisions later than their class's budget, from the record's kernel time"},
                {"stage": 6, "name": "response queue", "total": null,
                 "source": "not counted yet: R12c"},
                {"stage": 7, "name": "evidence writer queue", "total": null,
                 "source": "not counted yet: R12c"},
                {"stage": 8, "name": "export", "total": null,
                 "source": "not counted yet: R12c, the telemetry_loss rows; R15, the export"}
            ]
        },
        // R12b (lab PR 269): stage 5 per queue, P0's floods capped per uid.
        "event_bus_decision": {
            "queues": [
                {"priority": "P0", "budget_us": 100000, "timed": 12, "untimed": 0,
                 "delay_p50_us": 150, "delay_p99_us": 1100, "delay_max_us": 1200,
                 "over_budget": 0, "capped": 13},
                {"priority": "P1", "budget_us": 250000, "timed": 798, "untimed": 0,
                 "delay_p50_us": 60, "delay_p99_us": 2500, "delay_max_us": 3500,
                 "over_budget": 0, "capped": 0},
                {"priority": "P2", "budget_us": 1000000, "timed": 81808, "untimed": 0,
                 "delay_p50_us": 30, "delay_p99_us": 410000, "delay_max_us": 1400000,
                 "over_budget": 7, "capped": 0},
                {"priority": "P3", "budget_us": 500000, "timed": 30, "untimed": 10,
                 "delay_p50_us": null, "delay_p99_us": null, "delay_max_us": null,
                 "over_budget": 0, "capped": 0}
            ],
            "cap_per_uid": 256
        }
    });
    for (k, x) in fill.as_object().unwrap() {
        v[k] = x.clone();
    }
    serde_json::from_value(v).unwrap()
}

/// A boot's signed capability manifest (the shape of the agent's row).
pub fn capability_manifest() -> String {
    json!({
        "entry_hash": "ab".repeat(32),
        "manifest": {
            "manifest_version": 1, "agent_version": "0.0.1", "kernel": "6.8.0-matrix",
            "btf": true, "btf_offsets_resolved": 116, "btf_offsets_drifted": 5,
            "btf_offsets_absent": ["task_struct.loginuid"],
            "active_lsms": "lockdown,capability,landlock,yama,apparmor,bpf",
            "bpf_lsm": "active",
            "deny_hooks": {"expected": 19, "attached": 18, "missing": ["file_mprotect"], "observe_missing": []},
            "deny_self_test": "denied", "bpf_guard": "observe",
            "sensors": [
                {"sensor": "exec", "attach": "lsm:bprm_check_security"},
                {"sensor": "file", "attach": "fentry:vfs_write\u{1b}[31m"}
            ],
            "host_hardening": [
                {"id": "lockdown", "status": "warn", "value": "[none]"},
                {"id": "bpffs", "status": "ok", "value": "1"}
            ],
            "detect_only": false,
            "degradations": ["deny hook file_mprotect: not attached"],
            "trust_level": 1,
            "trust_reasons": ["a deny hook is missing"]
        }
    })
    .to_string()
}

fn public_status(posture: PostureKind, combat: bool) -> StatusResponse {
    if combat {
        StatusResponse::public(
            posture,
            true,
            Some(7),
            Some("contain".to_string()),
            Some(true),
        )
        .with_isolation_families(true, true)
    } else {
        StatusResponse::public(posture, false, None, None, None)
    }
}

fn status_msg(s: StatusResponse) -> AdminMessage {
    AdminMessage::StatusResponse(s)
}

fn telemetry(s: Option<StatusResponse>) -> AdminMessage {
    msg(json!({"TelemetryStatusResponse": {"result": "Success", "status": s}}))
}

fn telemetry_refusal(r: AdminResult) -> AdminMessage {
    msg(json!({"TelemetryStatusResponse": {"result": result_json(r), "status": null}}))
}

/// The verbs, each with its arguments and replies.
pub fn verbs() -> Vec<Verb> {
    let mut v = Vec::new();
    let unlock = |result: &str, released: bool, v4: bool, v6: bool, m: &str| {
        msg(json!({"SignedUnlockResponse": {
            "result": result, "released": released,
            "isolation_v4": v4, "isolation_v6": v6, "message": m,
        }}))
    };
    v.push(verb(
        "unlock",
        &format!("unlock {SIGNED}"),
        vec![
            (
                "released",
                unlock(
                    "Success",
                    true,
                    false,
                    false,
                    "COMBAT released: the isolation is torn down",
                ),
            ),
            (
                "release-failed",
                unlock(
                    "Success",
                    false,
                    true,
                    false,
                    "the NORTHNARROW_COMBAT chain is still in the IPv4 tables",
                ),
            ),
        ],
        move |r| {
            msg(json!({"SignedUnlockResponse": {
                "result": result_json(r), "released": false,
                "isolation_v4": true, "isolation_v6": true, "message": "refused by the mock",
            }}))
        },
    ));

    // The unsigned status and net status: one request, the public reply.
    for (name, args, special) in [
        (
            "status",
            "status --socket admin.sock",
            Special::StatusHostLine,
        ),
        (
            "status-json",
            "status --json --socket admin.sock",
            Special::None,
        ),
        (
            "net-status",
            "net status --socket admin.sock",
            Special::None,
        ),
        (
            "net-status-json",
            "net status --json --socket admin.sock",
            Special::None,
        ),
    ] {
        let mut full_unsigned = full_status();
        full_unsigned.capability_manifest = None;
        v.push(Verb {
            name: name.to_string(),
            args: words(args),
            signed: false,
            success: vec![
                (
                    "observing".to_string(),
                    status_msg(public_status(PostureKind::Observing, false)),
                ),
                (
                    "combat-locked".to_string(),
                    status_msg(public_status(PostureKind::Combat, true)),
                ),
                (
                    "older-agent-unsigned-telemetry".to_string(),
                    status_msg(full_unsigned),
                ),
            ],
            refusal: Box::new(|_| unreachable!("an unsigned verb has no refusal")),
            put: Vec::new(),
            special,
        });
    }
    // The signed telemetry read: status, net status, capabilities.
    for (name, args, special) in [
        (
            "status-key",
            format!("status {SIGNED}"),
            Special::StatusHostLine,
        ),
        (
            "status-key-json",
            format!("status --json {SIGNED}"),
            Special::None,
        ),
        (
            "net-status-key",
            format!("net status {SIGNED}"),
            Special::None,
        ),
        (
            "net-status-key-json",
            format!("net status --json {SIGNED}"),
            Special::None,
        ),
        (
            "capabilities",
            format!("capabilities {SIGNED}"),
            Special::None,
        ),
        (
            "capabilities-json",
            format!("capabilities --json {SIGNED}"),
            Special::None,
        ),
    ] {
        let mut not_json = full_status();
        not_json.capability_manifest = Some("{not json".to_string());
        let mut success = vec![
            ("full".to_string(), telemetry(Some(full_status()))),
            (
                "minimal".to_string(),
                telemetry(Some(public_status(PostureKind::Alerted, false))),
            ),
            ("success-without-status".to_string(), telemetry(None)),
        ];
        if name.starts_with("capabilities") {
            success.push(("manifest-not-json".to_string(), telemetry(Some(not_json))));
        }
        v.push(Verb {
            name: name.to_string(),
            args: words(&args),
            signed: true,
            success,
            refusal: Box::new(telemetry_refusal),
            put: Vec::new(),
            special,
        });
    }

    let (make, success) = jsonl_reply("DetectionsResponse");
    v.push(verb(
        "detections",
        &format!("detections {SIGNED}"),
        success,
        make,
    ));
    let (make, success) = jsonl_reply("DetectionsResponse");
    v.push(verb(
        "detections-filtered",
        &format!(
            "detections --limit 5 --since {ts} --until {ts2} --min-severity high --status open \
             --sensor exec --path /usr/bin/curl {SIGNED}",
            ts = fixtures::FIXTURE_TS,
            ts2 = fixtures::FIXTURE_TS + 3600
        ),
        success.into_iter().take(1).collect(),
        make,
    ));
    let set = |persist_failed: bool| {
        msg(json!({"DetectionSetStatusResponse": {
            "result": "Success", "id": 42, "new_status": "resolved", "persist_failed": persist_failed,
        }}))
    };
    v.push(verb(
        "detection-set-status",
        &format!("detection-set-status --id 42 --status resolved --note checked {SIGNED}"),
        vec![("set", set(false)), ("persist-failed", set(true))],
        with(
            "DetectionSetStatusResponse",
            json!({"id": 0, "new_status": "", "persist_failed": false}),
        ),
    ));
    v.push(verb(
        "shutdown",
        &format!("shutdown --cosign-key key-b --grace-secs 45 {SIGNED}"),
        vec![("acknowledged", msg(json!({"ShutdownResult": "Success"})))],
        bare("ShutdownResult"),
    ));
    v.push(verb(
        "force-posture",
        &format!("force-posture engaged {SIGNED}"),
        vec![("forced", msg(json!({"ForcePostureResult": "Success"})))],
        bare("ForcePostureResult"),
    ));
    v.push(verb(
        "rotate-keys-add",
        &format!(
            "rotate-keys add --new-pubkey {} --new-roles fim-read,net-read --cosign-key key-b {SIGNED}",
            fixtures::pub_hex(&fixtures::admin("key-c"))
        ),
        vec![("added", msg(json!({"RotateKeysAddResult": "Success"})))],
        bare("RotateKeysAddResult"),
    ));
    v.push(verb(
        "rotate-keys-revoke",
        &format!(
            "rotate-keys revoke --fingerprint {} --cosign-key key-b {SIGNED}",
            fixtures::fingerprint(&fixtures::admin("key-b").verifying_key())
        ),
        vec![("revoked", msg(json!({"RotateKeysRevokeResult": "Success"})))],
        bare("RotateKeysRevokeResult"),
    ));
    v.push(verb(
        "fim-baseline",
        &format!("fim baseline {SIGNED}"),
        vec![("queued", msg(json!({"FimBaselineResult": "Success"})))],
        bare("FimBaselineResult"),
    ));
    let (make, success) = jsonl_reply("FimReportResponse");
    v.push(verb(
        "fim-report",
        &format!("fim report --since {} {SIGNED}", fixtures::FIXTURE_TS),
        success,
        make,
    ));
    let fim_status = json!({
        "watched_paths_count": 12, "disabled_default_count": 1, "added_path_count": 2,
        "last_baseline_ts": "2025-06-15T15:06:40Z", "baseline_entries_total": 340,
        "drift_entries_total": 3, "high_remaining": 49, "high_cap_per_min": 50,
        "medium_remaining": 200, "medium_cap_per_min": 200, "bucket_window_resets_in_secs": 31
    });
    let mut ok_status = fim_status.clone();
    ok_status["result"] = json!("Success");
    v.push(verb(
        "fim-status",
        &format!("fim status {SIGNED}"),
        vec![("snapshot", msg(json!({"FimStatusResponse": ok_status})))],
        with("FimStatusResponse", fim_status),
    ));
    v.push(verb(
        "canary-deploy-file",
        &format!("canary deploy --name honeypot-file {SIGNED} file --path /srv/matrix/canary.txt"),
        vec![(
            "deployed",
            msg(json!({"CanaryDeployResponse": {"result": "Success", "canary_id": "c0ffee0123456789"}})),
        )],
        with("CanaryDeployResponse", json!({"canary_id": ""})),
    ));
    let (make, success) = jsonl_reply("CanaryListResponse");
    v.push(verb(
        "canary-list",
        &format!("canary list {SIGNED}"),
        success,
        make,
    ));
    v.push(verb(
        "canary-burn",
        &format!("canary burn --canary-id c0ffee0123456789 {SIGNED}"),
        vec![("burned", msg(json!({"CanaryBurnResult": "Success"})))],
        bare("CanaryBurnResult"),
    ));
    v.push(verb(
        "canary-refresh",
        &format!("canary refresh --canary-id c0ffee0123456789 {SIGNED}"),
        vec![("refreshed", msg(json!({"CanaryRefreshResult": "Success"})))],
        bare("CanaryRefreshResult"),
    ));
    let (make, success) = jsonl_reply("NetFlowsResponse");
    v.push(verb(
        "net-flows",
        &format!("net flows --since-unix {} {SIGNED}", fixtures::FIXTURE_TS),
        success,
        make,
    ));
    let (make, success) = jsonl_reply("NetListenersResponse");
    v.push(verb(
        "net-listeners",
        &format!("net listeners {SIGNED}"),
        success,
        make,
    ));
    let resolve = |q: Value, at: Value| {
        msg(
            json!({"NetResolveResponse": {"result": "Success", "qname": q, "queried_at_unix_ts": at}}),
        )
    };
    v.push(verb(
        "net-resolve",
        &format!("net resolve --ip 203.0.113.7 {SIGNED}"),
        vec![
            (
                "named",
                resolve(json!("updates.example.net"), json!(fixtures::FIXTURE_TS)),
            ),
            (
                "named-no-time",
                resolve(json!("updates.example.net"), Value::Null),
            ),
            ("unnamed", resolve(Value::Null, Value::Null)),
        ],
        with(
            "NetResolveResponse",
            json!({"qname": null, "queried_at_unix_ts": null}),
        ),
    ));
    let (make, success) = jsonl_reply("NetFingerprintResponse");
    v.push(verb(
        "net-fingerprint",
        &format!("net fingerprint --flow-id {} {SIGNED}", "0f".repeat(16)),
        success,
        make,
    ));
    v.push(verb(
        "trusted-installer-grant",
        &format!("trusted-installer-grant --window-secs 300 {SIGNED}"),
        vec![(
            "granted",
            msg(json!({"TrustedInstallerGrantResult": "Success"})),
        )],
        bare("TrustedInstallerGrantResult"),
    ));
    let response_status = |populated: bool| {
        let contained = if populated {
            json!([
                {"pid": 4242, "scope": "blocked", "origin": "/system.slice/x.service", "since": fixtures::FIXTURE_TS, "running": true},
                {"pid": 4343, "scope": "throttled", "origin": "", "since": fixtures::FIXTURE_TS + 5, "running": false}
            ])
        } else {
            json!([])
        };
        let quarantined = if populated {
            json!([{"vault_id": "1b".repeat(16), "original_path": "/tmp/dropper", "size_bytes": 4096, "captured_at": fixtures::FIXTURE_TS}])
        } else {
            json!([])
        };
        msg(json!({"ResponseStatusResponse": {
            "result": "Success",
            "contained": contained, "contained_total": if populated { 5 } else { 0 },
            "quarantined": quarantined, "quarantined_total": if populated { 3 } else { 0 },
            "combat_stage": if populated { json!("contain") } else { Value::Null },
            "combat_locked": if populated { json!(true) } else { Value::Null },
        }}))
    };
    v.push(verb(
        "response-status",
        &format!("response status {SIGNED}"),
        vec![
            ("populated", response_status(true)),
            ("empty", response_status(false)),
        ],
        with(
            "ResponseStatusResponse",
            json!({"contained": [], "contained_total": 0, "quarantined": [], "quarantined_total": 0,
                   "combat_stage": null, "combat_locked": null}),
        ),
    ));
    let release = |released: bool, m: &str| {
        msg(
            json!({"ResponseReleaseResponse": {"result": "Success", "released": released, "message": m}}),
        )
    };
    v.push(verb(
        "response-release",
        &format!("response release --pid 4242 {SIGNED}"),
        vec![
            (
                "released",
                release(true, "pid 4242 back in /system.slice/x.service"),
            ),
            ("not-done", release(false, "pid 4242 is not contained")),
        ],
        with(
            "ResponseReleaseResponse",
            json!({"released": false, "message": ""}),
        ),
    ));
    let restore = |restored: bool, path: &str, m: &str| {
        msg(
            json!({"ResponseRestoreResponse": {"result": "Success", "restored": restored, "path": path, "message": m}}),
        )
    };
    v.push(verb(
        "response-restore",
        &format!(
            "response restore --vault-id {} --to /srv/matrix/restored {SIGNED}",
            "1b".repeat(16)
        ),
        vec![
            (
                "restored",
                restore(
                    true,
                    "/srv/matrix/restored",
                    "restored 4096 bytes, mode 0600",
                ),
            ),
            ("not-done", restore(false, "", "the destination exists")),
        ],
        with(
            "ResponseRestoreResponse",
            json!({"restored": false, "path": "", "message": ""}),
        ),
    ));
    let remediate = |done: bool, rows: Value, total: u32, refused: u32| {
        msg(json!({"RemediateRansomwareResponse": {
            "result": "Success", "done": done, "message": if done { "2 file(s) restored" } else { "nothing restored" },
            "rows": rows, "rows_total": total, "restored": if done { 1 } else { 0 }, "recreated": 0,
            "kept_both": if done { 1 } else { 0 }, "unchanged": 0, "refused": refused, "skipped": 0,
        }}))
    };
    let rows = json!([
        {"path": "/srv/data/a.doc", "action": "restored", "entry": 1, "detail": "from the copy of 2025-06-15",
         "beside": null, "evidence": "/srv/data/.nn-evidence/1", "sha256_original": "aa".repeat(32), "sha256_after": null},
        {"path": "/srv/data/b.doc", "action": "kept-both", "entry": 2, "detail": "changed after the attack",
         "beside": "/srv/data/b.doc.nn-restored-2", "evidence": null, "sha256_original": "bb".repeat(32), "sha256_after": "cc".repeat(32)}
    ]);
    let remediate_refusal = with(
        "RemediateRansomwareResponse",
        json!({"done": false, "message": "", "rows": [], "rows_total": 0, "restored": 0, "recreated": 0,
               "kept_both": 0, "unchanged": 0, "refused": 0, "skipped": 0}),
    );
    v.push(verb(
        "remediate-ransomware",
        &format!("remediate ransomware --pid 4242 --since 2025-06-15T15:00:00Z {SIGNED}"),
        vec![
            ("restored", remediate(true, rows.clone(), 2, 0)),
            ("nothing-done", remediate(false, json!([]), 0, 0)),
            ("refused-rows", remediate(false, rows.clone(), 2, 1)),
        ],
        remediate_refusal,
    ));
    v.push(verb(
        "remediate-ransomware-json",
        &format!("remediate ransomware --since 1750000000 --dry-run --json {SIGNED}"),
        vec![("restored", remediate(true, rows, 2, 0))],
        with(
            "RemediateRansomwareResponse",
            json!({"done": false, "message": "", "rows": [], "rows_total": 0, "restored": 0, "recreated": 0,
                   "kept_both": 0, "unchanged": 0, "refused": 0, "skipped": 0}),
        ),
    ));
    let overlay_set = |stored: bool, m: &str| {
        msg(
            json!({"ConfigOverlaySetResponse": {"result": "Success", "stored": stored, "message": m}}),
        )
    };
    let mut set = verb(
        "config-overlay-set",
        &format!("config overlay set process-comm-allowlist --file overlay.local --cosign-key key-b {SIGNED}"),
        vec![
            ("stored", overlay_set(true, "process-comm-allowlist.local stored; loaded at the next start")),
            ("refused-by-the-agent", overlay_set(false, "the floor refuses an overlay signed before 1750000000")),
        ],
        with("ConfigOverlaySetResponse", json!({"stored": false, "message": "refused by the mock"})),
    );
    set.put.push(Put::file(
        "overlay.local",
        "# matrix overlay\nbackup-tool\nrsync\n",
        0o644,
    ));
    v.push(set);
    let mut pset = verb(
        "policy-set",
        &format!("policy set --file policy.local {SIGNED}"),
        vec![
            (
                "stored",
                overlay_set(true, "rule-policy.local stored and applied"),
            ),
            (
                "refused-by-the-agent",
                overlay_set(false, "the agent's parse refused it"),
            ),
        ],
        with(
            "ConfigOverlaySetResponse",
            json!({"stored": false, "message": "refused by the mock"}),
        ),
    );
    pset.put.push(Put::file(
        "policy.local",
        "# matrix policy\nenforce NN-L-IMP-001\n",
        0o644,
    ));
    v.push(pset);
    v
}

fn remediated() -> AdminMessage {
    msg(json!({"RemediateRansomwareResponse": {
        "result": "Success", "done": true, "message": "1 file(s) restored", "rows": [],
        "rows_total": 1, "restored": 1, "recreated": 0, "kept_both": 0, "unchanged": 0,
        "refused": 0, "skipped": 0,
    }}))
}

/// The success-only variants of a verb's arguments (other targets, other
/// kinds): the reply is the verb's first success.
fn variants() -> Vec<(&'static str, String, AdminMessage, Vec<Put>)> {
    let ok = |variant: &str| msg(json!({ variant: "Success" }));
    let deployed = msg(
        json!({"CanaryDeployResponse": {"result": "Success", "canary_id": "c0ffee0123456789"}}),
    );
    let mut v = vec![
        ("force-posture.observing", format!("force-posture observing {SIGNED}"), ok("ForcePostureResult"), vec![]),
        ("force-posture.alerted", format!("force-posture alerted {SIGNED}"), ok("ForcePostureResult"), vec![]),
        ("force-posture.combat", format!("force-posture combat {SIGNED}"), ok("ForcePostureResult"), vec![]),
        ("canary-deploy.process", format!("canary deploy --name decoy-proc {SIGNED} process --path /usr/local/bin/backupd --fake-arg0 backupd"), deployed.clone(), vec![]),
        ("canary-deploy.network", format!("canary deploy --name decoy-port {SIGNED} network --bind-addr 0.0.0.0 --bind-port 2222"), deployed.clone(), vec![]),
        ("canary-deploy.credential", format!("canary deploy --name aws-creds {SIGNED} credential --path /root/.aws/credentials --cred-family aws"), deployed, vec![]),
        ("trusted-installer-grant.default-window", format!("trusted-installer-grant {SIGNED}"), ok("TrustedInstallerGrantResult"), vec![]),
        ("trusted-installer-grant.clamped-up", format!("trusted-installer-grant --window-secs 0 {SIGNED}"), ok("TrustedInstallerGrantResult"), vec![]),
        ("trusted-installer-grant.clamped-down", format!("trusted-installer-grant --window-secs 3600 {SIGNED}"), ok("TrustedInstallerGrantResult"), vec![]),
        ("shutdown.default-grace", format!("shutdown --cosign-key key-b {SIGNED}"), ok("ShutdownResult"), vec![]),
        ("shutdown.same-key-twice", format!("shutdown --cosign-key key-a {SIGNED}"), msg(json!({"ShutdownResult": {"QuorumNotMet": {"required": 2, "provided": 1}}})), vec![]),
        ("shutdown.grace-over-cap", format!("shutdown --cosign-key key-b --grace-secs 301 {SIGNED}"), ok("ShutdownResult"), vec![]),
        ("rotate-keys-add.default-roles", format!("rotate-keys add --new-pubkey {} --cosign-key key-b {SIGNED}", fixtures::pub_hex(&fixtures::admin("key-c"))), ok("RotateKeysAddResult"), vec![]),
        ("rotate-keys-add.all-roles", format!("rotate-keys add --new-pubkey {} --new-roles all --cosign-key key-b {SIGNED}", fixtures::pub_hex(&fixtures::admin("key-c"))), ok("RotateKeysAddResult"), vec![]),
        ("rotate-keys-add.unknown-role", format!("rotate-keys add --new-pubkey {} --new-roles unlock,root --cosign-key key-b {SIGNED}", fixtures::pub_hex(&fixtures::admin("key-c"))), ok("RotateKeysAddResult"), vec![]),
        ("rotate-keys-add.empty-role", format!("rotate-keys add --new-pubkey {} --new-roles unlock,,audit-read --cosign-key key-b {SIGNED}", fixtures::pub_hex(&fixtures::admin("key-c"))), ok("RotateKeysAddResult"), vec![]),
        ("rotate-keys-add.short-pubkey", format!("rotate-keys add --new-pubkey abcd --cosign-key key-b {SIGNED}"), ok("RotateKeysAddResult"), vec![]),
        ("rotate-keys-add.pubkey-not-hex", format!("rotate-keys add --new-pubkey {} --cosign-key key-b {SIGNED}", "zz".repeat(32)), ok("RotateKeysAddResult"), vec![]),
        ("rotate-keys-revoke.short-fingerprint", format!("rotate-keys revoke --fingerprint abc --cosign-key key-b {SIGNED}"), ok("RotateKeysRevokeResult"), vec![]),
        ("rotate-keys-revoke.fingerprint-not-hex", format!("rotate-keys revoke --fingerprint zzzzzzzz --cosign-key key-b {SIGNED}"), ok("RotateKeysRevokeResult"), vec![]),
        ("detection-set-status.no-note", format!("detection-set-status --id 7 --status false-positive {SIGNED}"), msg(json!({"DetectionSetStatusResponse": {"result": "Success", "id": 7, "new_status": "false-positive", "persist_failed": false}})), vec![]),
        ("response-restore.original-path", format!("response restore --vault-id {} {SIGNED}", "1b".repeat(16)), msg(json!({"ResponseRestoreResponse": {"result": "Success", "restored": true, "path": "/tmp/dropper", "message": "restored"}})), vec![]),
        ("remediate-ransomware.since-not-a-time", format!("remediate ransomware --since yesterday {SIGNED}"), remediated(), vec![]),
        ("remediate-ransomware.neither-pid-nor-since", format!("remediate ransomware --dry-run {SIGNED}"), remediated(), vec![]),
        ("net-flows.no-since", format!("net flows {SIGNED}"), msg(json!({"NetFlowsResponse": {"result": "Success", "entries_jsonl": "", "entries_count": 0, "entries_truncated": false}})), vec![]),
        ("fim-report.no-since", format!("fim report {SIGNED}"), msg(json!({"FimReportResponse": {"result": "Success", "entries_jsonl": "", "entries_count": 0, "entries_truncated": false}})), vec![]),
        ("detections.limit-zero", format!("detections --limit 0 {SIGNED}"), msg(json!({"DetectionsResponse": {"result": "Success", "entries_jsonl": "", "entries_count": 0, "entries_truncated": false}})), vec![]),
    ];
    // config overlay set: every kind, a comment-only overlay (the loader's
    // parse decides), and an unknown kind.
    for kind in nn_proto::admin_signed_payload::OverlayKind::ALL {
        let id: &'static str =
            Box::leak(format!("config-overlay-set.kind.{}", kind.keyword()).into_boxed_str());
        v.push((
            id,
            format!("config overlay set {} --file overlay.local {SIGNED}", kind.keyword()),
            msg(json!({"ConfigOverlaySetResponse": {"result": "Success", "stored": true, "message": "stored"}})),
            vec![Put::file("overlay.local", "# matrix: comments only\n", 0o644)],
        ));
    }
    let stored = msg(
        json!({"ConfigOverlaySetResponse": {"result": "Success", "stored": true, "message": "stored"}}),
    );
    v.push((
        "config-overlay-set.unknown-kind",
        format!("config overlay set no-such-list --file overlay.local {SIGNED}"),
        stored.clone(),
        vec![Put::file("overlay.local", "x\n", 0o644)],
    ));
    v.push((
        "config-overlay-set.by-file-name",
        format!("config overlay set combat-rules.v4 --file overlay.local {SIGNED}"),
        stored.clone(),
        vec![Put::file("overlay.local", "# matrix\n", 0o644)],
    ));
    v.push((
        "config-overlay-set.missing-file",
        format!("config overlay set fim-paths --file absent.local {SIGNED}"),
        stored.clone(),
        vec![],
    ));
    v.push((
        "config-overlay-set.too-big",
        format!("config overlay set fim-paths --file big.local {SIGNED}"),
        stored.clone(),
        vec![Put::file("big.local", "#".repeat(32 * 1024 + 1), 0o644)],
    ));
    v.push((
        "config-overlay-set.bad-content",
        format!("config overlay set rule-policy --file overlay.local {SIGNED}"),
        stored.clone(),
        vec![Put::file("overlay.local", "enforce NO-SUCH-RULE\n", 0o644)],
    ));
    v.push((
        "config-overlay-set.not-utf8",
        format!("config overlay set fim-paths --file overlay.local {SIGNED}"),
        stored.clone(),
        vec![Put::file("overlay.local", [0xff, 0xfe, b'\n'], 0o644)],
    ));
    v.push((
        "policy-set.bad-line",
        format!("policy set --file policy.local {SIGNED}"),
        stored.clone(),
        vec![Put::file("policy.local", "enforce\n", 0o644)],
    ));
    v.push((
        "policy-set.exempts-uid-0",
        format!("policy set --file policy.local {SIGNED}"),
        stored.clone(),
        vec![Put::file(
            "policy.local",
            "enforce R020\nexempt R020 uid 0\n",
            0o644,
        )],
    ));
    v.push((
        "policy-set.missing-file",
        format!("policy set --file absent.local {SIGNED}"),
        stored.clone(),
        vec![],
    ));
    v.push((
        "policy-set.empty",
        format!("policy set --file policy.local {SIGNED}"),
        stored,
        vec![Put::file("policy.local", "", 0o644)],
    ));
    v
}

pub fn cases() -> Vec<Case> {
    let mut out = Vec::new();
    for verb in verbs() {
        let base = |id: String| {
            Case::args_owned("socket", id, verb.args.clone())
                .with(fixtures::base())
                .with(verb.put.clone())
                .special(verb.special)
        };
        for (name, reply) in &verb.success {
            let script = if verb.signed {
                Script::signed(Reply::send(
                    format!("{} ({name})", variant_name(reply)),
                    reply.clone(),
                ))
            } else {
                Script::unsigned(Reply::send(
                    format!("{} ({name})", variant_name(reply)),
                    reply.clone(),
                ))
            };
            out.push(base(format!("sock.{}.{name}", verb.name)).mock(script));
        }
        if verb.signed {
            for (name, r) in refusals() {
                let reply = (verb.refusal)(r);
                out.push(
                    base(format!("sock.{}.refused.{name}", verb.name)).mock(Script::signed(
                        Reply::send(format!("{} ({name})", variant_name(&reply)), reply),
                    )),
                );
            }
            for (name, s) in signed_faults() {
                out.push(base(format!("sock.{}.fault.{name}", verb.name)).mock(s));
            }
        } else {
            for (name, s) in unsigned_faults() {
                out.push(base(format!("sock.{}.fault.{name}", verb.name)).mock(s));
            }
        }
        out.push(base(format!("sock.{}.no-socket", verb.name)));
        out.push(base(format!("sock.{}.refused-connection", verb.name)).mock(Script::Refused));
    }
    for (id, args, reply, put) in variants() {
        out.push(
            Case::args_owned("socket", format!("sock.{id}"), words(&args))
                .with(fixtures::base())
                .with(put)
                .mock(Script::signed(Reply::send(variant_name(&reply), reply))),
        );
    }
    out
}

/// The variant's name (`ShutdownResult`, …), from its JSON.
pub fn variant_name(m: &AdminMessage) -> String {
    match serde_json::to_value(m).unwrap() {
        Value::Object(o) => o.keys().next().cloned().unwrap_or_default(),
        Value::String(s) => s,
        _ => "?".to_string(),
    }
}
