//! The verification pipeline's rejection table (R11d, lab PR 263): for
//! every signed verb and every reason the verification refuses a request,
//! the exact reply and the signed audit row — through `serve_request`, the
//! code a connection runs for each frame (dispatch, the verb's handler
//! entry and `verify::signed`, the audit row). For each verb also: a
//! request the pipeline accepts reaches its handler with its signers named
//! in the row, and a connection's third counted failure is answered
//! `RateLimited`, as is every request after it. And the requests that
//! carry no signature are answered as they are.
//!
//! The three tables — the refusals, the accepted requests, the rate limit
//! — are golden files (lab PR 263's review, L-2):
//! `agent/tests/golden/admin/expected/{rejections,accepted,rate-limited}.txt`,
//! compared byte for byte by every `cargo test`. A change of a reply or of a
//! row is a diff of them in the pull request that makes it: `cargo xtask
//! golden --update` (`NN_GOLDEN_UPDATE=1`) rewrites them for review, never
//! under CI (`docs/validation/GOLDEN_REPLAY.md` §7).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use parking_lot::Mutex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use nn_model::posture_types::PostureKind;
use nn_proto::admin_protocol::{
    AdminMessage, AdminResult, CanaryBurnRequest, CanaryDeployRequest, CanaryDeployResponse,
    CanaryListRequest, CanaryListResponse, CanaryRefreshRequest, ChallengeRequest,
    ConfigOverlaySetRequest, ConfigOverlaySetResponse, DetectionSetStatusRequest,
    DetectionSetStatusResponse, DetectionsRequest, DetectionsResponse, FimBaselineRequest,
    FimReportRequest, FimReportResponse, FimStatusRequest, FimStatusResponse, ForcePostureRequest,
    KeyedSignature, LoopProgressRequest, NetFingerprintRequest, NetFingerprintResponse,
    NetFlowsRequest, NetFlowsResponse, NetListenersRequest, NetListenersResponse,
    NetResolveRequest, NetResolveResponse, RemediateRansomwareRequest, RemediateRansomwareResponse,
    ResponseReleaseRequest, ResponseReleaseResponse, ResponseRestoreRequest,
    ResponseRestoreResponse, ResponseStatusRequest, ResponseStatusResponse, RotateKeysAddRequest,
    RotateKeysRevokeRequest, ShutdownRequest, SignedUnlockRequest, SignedUnlockResponse,
    StatusRequest, TelemetryStatusRequest, TelemetryStatusResponse, TrustedInstallerGrantRequest,
    UnlockRequest, UnlockResult,
};
use nn_proto::admin_quorum::role_keyword;
use nn_proto::admin_signed_payload::{
    sign, CanaryBurnExtra, CanaryDeployExtra, CanaryDeploymentWire, CanaryListExtra,
    CanaryRefreshExtra, CanaryTypeWire, ConfigOverlaySetExtra, DetectionSetStatusExtra,
    DetectionsExtra, FimBaselineExtra, FimReportExtra, FimStatusExtra, ForcePostureExtra,
    NetFingerprintExtra, NetFlowsExtra, NetListenersExtra, NetResolveExtra, OperationExtra,
    OverlayKind, RemediateRansomwareExtra, ResponseReleaseExtra, ResponseRestoreExtra,
    ResponseStatusExtra, Role, RotateKeysAddExtra, RotateKeysRevokeExtra, ShutdownExtra,
    SignedPayload, TelemetryStatusExtra, TrustedInstallerGrantExtra, UnlockExtra,
};
use nn_proto::shutdown_marker::SHUTDOWN_QUORUM;

use super::tests::{
    bare_context, build_test_audit_log, fake_client, read_audit_entries, rules_path,
};
use super::transport::serve_request;
use super::verify::{now_unix_secs, Quorum, Signed, RULES};
use super::{AdminHandles, AdminReadPaths, StatusPolls};
use crate::anti_tamper::admin_auth::{AdminAuth, ConnAuth};
use crate::anti_tamper::network_isolate::NetworkIsolator;
use crate::audit::{AuditEntry, AuditLog};
use crate::posture::PostureMachine;

const AGENT_ID: [u8; 16] = [0x5e; 16];

/// The install nonce of the bootstrap tests (`install.sh` draws 32 random
/// bytes).
const INSTALL_NONCE: [u8; 32] = [0x4e; 32];

/// The admin keys: two holding every role, two holding one role each
/// (no verb needs both), one not installed.
struct Keys {
    a: SigningKey,
    b: SigningKey,
    canary_read: SigningKey,
    net_read: SigningKey,
    stranger: SigningKey,
}

fn keys() -> Keys {
    Keys {
        a: SigningKey::from_bytes(&[0xa1; 32]),
        b: SigningKey::from_bytes(&[0xb2; 32]),
        canary_read: SigningKey::from_bytes(&[0xc3; 32]),
        net_read: SigningKey::from_bytes(&[0xd4; 32]),
        stranger: SigningKey::from_bytes(&[0xe5; 32]),
    }
}

/// The 8-hex-char fingerprint of design §9.1: SHA-256 of the public key,
/// its first four bytes.
fn fp_bytes(key: &SigningKey) -> [u8; 4] {
    let d = Sha256::digest(key.verifying_key().to_bytes());
    [d[0], d[1], d[2], d[3]]
}

fn fp(key: &SigningKey) -> String {
    hex::encode(fp_bytes(key))
}

/// An admin.pub line: the key and its roles (none: the default ones,
/// `unlock,audit-read`).
fn admin_line(key: &SigningKey, roles: &str) -> String {
    let hex = hex::encode(key.verifying_key().to_bytes());
    if roles.is_empty() {
        format!("{hex}\n")
    } else {
        format!("{hex} {roles}\n")
    }
}

/// One agent: its admin.pub (the keys above), audit log, posture,
/// isolator, marker and read verbs' files in a directory of its own.
struct Fixture {
    dir: TempDir,
    auth: AdminAuth,
    audit: Arc<Mutex<AuditLog>>,
    log_path: PathBuf,
    posture: PostureMachine,
    isolator: NetworkIsolator,
    marker: PathBuf,
    read_paths: AdminReadPaths,
    polls: StatusPolls,
    handles: AdminHandles,
}

impl Fixture {
    fn new(k: &Keys) -> Self {
        Self::with_admin_pub(
            &[
                admin_line(&k.a, "all"),
                admin_line(&k.b, "all"),
                admin_line(&k.canary_read, "canary-read"),
                admin_line(&k.net_read, "net-read"),
            ]
            .concat(),
        )
    }

    /// An agent whose admin.pub is `admin_pub`.
    fn with_admin_pub(admin_pub: &str) -> Self {
        let dir = TempDir::new().unwrap();
        let pub_path = dir.path().join("admin.pub");
        std::fs::write(&pub_path, admin_pub).unwrap();
        let auth = AdminAuth::load_with_agent_id(&pub_path, AGENT_ID).unwrap();
        let (log_path, audit) = build_test_audit_log(&dir);
        let read_paths = AdminReadPaths {
            fim_drift: dir.path().join("fim_drift.jsonl"),
            netflow: dir.path().join("netflow.jsonl"),
            netflow_listeners: dir.path().join("netflow_listeners.jsonl"),
        };
        Self {
            marker: dir.path().join("shutdown.marker"),
            posture: PostureMachine::new(),
            isolator: NetworkIsolator::new(rules_path()).unwrap(),
            polls: StatusPolls::default(),
            handles: AdminHandles::default(),
            read_paths,
            auth,
            audit,
            log_path,
            dir,
        }
    }

    /// `install.sh`'s one-key install (BUG-013): admin.pub holding `key`
    /// alone, every role, and beside it the install nonce and the sentinel
    /// over the nonce and admin.pub — the files the bootstrap gate reads
    /// (`verify::bootstrap_paths`: the test's own).
    fn bootstrap(key: &SigningKey) -> Self {
        let fx = Self::with_admin_pub(&admin_line(key, "all"));
        std::fs::write(fx.dir.path().join(".install_nonce"), INSTALL_NONCE).unwrap();
        fx.write_sentinel();
        fx
    }

    /// The sentinel over the install nonce and admin.pub as it is now: what
    /// `install.sh` writes, and what root, who can read the nonce, can
    /// write again.
    fn write_sentinel(&self) {
        let admin_pub = std::fs::read(self.dir.path().join("admin.pub")).unwrap();
        std::fs::write(
            self.sentinel(),
            crate::anti_tamper::bootstrap::compute_sentinel_content(&INSTALL_NONCE, &admin_pub),
        )
        .unwrap();
    }

    fn sentinel(&self) -> PathBuf {
        self.dir.path().join(".bootstrap")
    }

    /// The keys admin.pub holds now.
    fn admin_keys(&self) -> usize {
        std::fs::read_to_string(self.dir.path().join("admin.pub"))
            .unwrap()
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
            .count()
    }

    /// One frame of one connection, as `handle_connection` serves it.
    fn serve(&self, conn: &ConnAuth<'_>, msg: &AdminMessage) -> AdminMessage {
        serve_request(
            msg,
            conn,
            bare_context(
                &self.posture,
                &self.isolator,
                &self.marker,
                &self.read_paths,
                &self.handles,
            ),
            &fake_client(),
            Some(&self.audit),
            &self.polls,
        )
    }

    fn challenge(&self, conn: &ConnAuth<'_>) -> [u8; 32] {
        match self.serve(conn, &AdminMessage::ChallengeRequest(ChallengeRequest {})) {
            AdminMessage::Challenge(c) => c.nonce,
            other => panic!("challenge: {other:?}"),
        }
    }

    fn rows(&self) -> Vec<AuditEntry> {
        read_audit_entries(&self.log_path)
    }
}

/// One signed verb: how to build its request, its refusal reply and the
/// audit row a request of it gets.
struct Verb {
    /// The request's type in `verify::RULES`.
    request: &'static str,
    /// The audit row's `op`.
    op: &'static str,
    /// Distinct keys the verb needs (rotate-keys add: no bootstrap here).
    quorum: usize,
    /// The verb's extra (its payload: this extra and its operation).
    extra: fn(&Keys) -> OperationExtra,
    wrap: fn(SignedPayload, Vec<KeyedSignature>) -> AdminMessage,
    /// The reply to a refusal; `own` is false when the payload's extra is
    /// another verb's.
    refused: fn(AdminResult, bool) -> AdminMessage,
    /// The audit row's `extra` for a request with this payload.
    row: fn(&Keys, &SignedPayload, bool) -> Value,
}

fn empty_jsonl() -> Value {
    json!({ "entries_count": 0, "truncated": false })
}

fn verbs() -> Vec<Verb> {
    vec![
        Verb {
            request: "SignedUnlockRequest",
            op: "unlock",
            quorum: 1,
            extra: |_| OperationExtra::Unlock(UnlockExtra {}),
            wrap: |payload, signatures| {
                AdminMessage::SignedUnlockRequest(SignedUnlockRequest {
                    payload,
                    signatures,
                })
            },
            refused: |result, _| {
                AdminMessage::SignedUnlockResponse(SignedUnlockResponse {
                    result,
                    released: false,
                    isolation_v4: false,
                    isolation_v6: false,
                    message: "signature verification failed".to_string(),
                })
            },
            row: |_, _, _| {
                json!({
                    "protocol": "signed",
                    "released": false,
                    "isolation_v4": false,
                    "isolation_v6": false,
                    "detail": "signature verification failed",
                })
            },
        },
        Verb {
            request: "ShutdownRequest",
            op: "shutdown",
            quorum: usize::from(SHUTDOWN_QUORUM),
            extra: |_| OperationExtra::Shutdown(ShutdownExtra { grace_secs: 30 }),
            wrap: |payload, signatures| {
                AdminMessage::ShutdownRequest(ShutdownRequest {
                    payload,
                    signatures,
                })
            },
            refused: |r, _| AdminMessage::ShutdownResult(r),
            row: |_, _, own| json!({ "grace_secs": if own { 30 } else { 0 } }),
        },
        Verb {
            request: "ForcePostureRequest",
            op: "force_posture",
            quorum: 1,
            extra: |_| {
                OperationExtra::ForcePosture(ForcePostureExtra {
                    target: PostureKind::Alerted,
                })
            },
            wrap: |payload, signatures| {
                AdminMessage::ForcePostureRequest(ForcePostureRequest {
                    payload,
                    signatures,
                })
            },
            refused: |r, _| AdminMessage::ForcePostureResult(r),
            row: |_, _, own| json!({ "target": if own { "Alerted" } else { "?" } }),
        },
        Verb {
            request: "RotateKeysAddRequest",
            op: "rotate_keys_add",
            quorum: 2,
            extra: |k| {
                OperationExtra::RotateKeysAdd(RotateKeysAddExtra {
                    new_pubkey: k.stranger.verifying_key().to_bytes(),
                    roles: vec![Role::AuditRead],
                })
            },
            wrap: |payload, signatures| {
                AdminMessage::RotateKeysAddRequest(RotateKeysAddRequest {
                    payload,
                    signatures,
                })
            },
            refused: |r, _| AdminMessage::RotateKeysAddResult(r),
            row: |k, _, own| json!({ "new_key_fp": if own { fp(&k.stranger) } else { String::new() } }),
        },
        Verb {
            request: "RotateKeysRevokeRequest",
            op: "rotate_keys_revoke",
            quorum: 2,
            extra: |k| {
                OperationExtra::RotateKeysRevoke(RotateKeysRevokeExtra {
                    fingerprint: fp_bytes(&k.canary_read),
                })
            },
            wrap: |payload, signatures| {
                AdminMessage::RotateKeysRevokeRequest(RotateKeysRevokeRequest {
                    payload,
                    signatures,
                })
            },
            refused: |r, _| AdminMessage::RotateKeysRevokeResult(r),
            row: |k, _, own| json!({ "target_fp": if own { fp(&k.canary_read) } else { String::new() } }),
        },
        Verb {
            request: "FimBaselineRequest",
            op: "fim_baseline",
            quorum: 1,
            extra: |_| OperationExtra::FimBaseline(FimBaselineExtra {}),
            wrap: |payload, signatures| {
                AdminMessage::FimBaselineRequest(FimBaselineRequest {
                    payload,
                    signatures,
                })
            },
            refused: |r, _| AdminMessage::FimBaselineResult(r),
            row: |_, _, _| json!({}),
        },
        Verb {
            request: "FimReportRequest",
            op: "fim_report",
            quorum: 1,
            extra: |_| {
                OperationExtra::FimReport(FimReportExtra {
                    since_unix_ts: Some(1_700_000_000),
                })
            },
            wrap: |payload, signatures| {
                AdminMessage::FimReportRequest(FimReportRequest {
                    payload,
                    signatures,
                })
            },
            refused: |result, _| {
                AdminMessage::FimReportResponse(FimReportResponse {
                    result,
                    entries_jsonl: String::new(),
                    entries_count: 0,
                    entries_truncated: false,
                })
            },
            row: |_, _, own| {
                json!({
                    "since_unix_ts": if own { Some(1_700_000_000u64) } else { None },
                    "entries_count": 0,
                    "truncated": false,
                })
            },
        },
        Verb {
            request: "FimStatusRequest",
            op: "fim_status",
            quorum: 1,
            extra: |_| OperationExtra::FimStatus(FimStatusExtra {}),
            wrap: |payload, signatures| {
                AdminMessage::FimStatusRequest(FimStatusRequest {
                    payload,
                    signatures,
                })
            },
            refused: |result, _| {
                AdminMessage::FimStatusResponse(FimStatusResponse {
                    result,
                    watched_paths_count: 0,
                    disabled_default_count: 0,
                    added_path_count: 0,
                    last_baseline_ts: String::new(),
                    baseline_entries_total: 0,
                    drift_entries_total: 0,
                    high_remaining: 0,
                    high_cap_per_min: 0,
                    medium_remaining: 0,
                    medium_cap_per_min: 0,
                    bucket_window_resets_in_secs: 0,
                })
            },
            row: |_, _, _| {
                json!({
                    "watched_paths_count": 0,
                    "disabled_default_count": 0,
                    "added_path_count": 0,
                    "baseline_entries_total": 0,
                    "drift_entries_total": 0,
                })
            },
        },
        Verb {
            request: "CanaryDeployRequest",
            op: "canary_deploy",
            quorum: 1,
            extra: |_| {
                OperationExtra::CanaryDeploy(CanaryDeployExtra {
                    name: "decoy".to_string(),
                    canary_type: CanaryTypeWire::File,
                    deployment: CanaryDeploymentWire::File {
                        path: "/var/tmp/nn-r11d-decoy".to_string(),
                        template: None,
                    },
                })
            },
            wrap: |payload, signatures| {
                AdminMessage::CanaryDeployRequest(CanaryDeployRequest {
                    payload,
                    signatures,
                })
            },
            refused: |result, _| {
                AdminMessage::CanaryDeployResponse(CanaryDeployResponse {
                    result,
                    canary_id: String::new(),
                })
            },
            row: |_, _, own| {
                json!({
                    "name": if own { "decoy" } else { "" },
                    "canary_id": "",
                    "cred_family": "",
                })
            },
        },
        Verb {
            request: "CanaryListRequest",
            op: "canary_list",
            quorum: 1,
            extra: |_| OperationExtra::CanaryList(CanaryListExtra {}),
            wrap: |payload, signatures| {
                AdminMessage::CanaryListRequest(CanaryListRequest {
                    payload,
                    signatures,
                })
            },
            refused: |result, _| {
                AdminMessage::CanaryListResponse(CanaryListResponse {
                    result,
                    entries_jsonl: String::new(),
                    entries_count: 0,
                    entries_truncated: false,
                })
            },
            row: |_, _, _| empty_jsonl(),
        },
        Verb {
            request: "CanaryBurnRequest",
            op: "canary_burn",
            quorum: 1,
            extra: |_| {
                OperationExtra::CanaryBurn(CanaryBurnExtra {
                    canary_id: "cnry-1".to_string(),
                })
            },
            wrap: |payload, signatures| {
                AdminMessage::CanaryBurnRequest(CanaryBurnRequest {
                    payload,
                    signatures,
                })
            },
            refused: |r, _| AdminMessage::CanaryBurnResult(r),
            row: |_, _, own| json!({ "canary_id": if own { "cnry-1" } else { "" } }),
        },
        Verb {
            request: "CanaryRefreshRequest",
            op: "canary_refresh",
            quorum: 1,
            extra: |_| {
                OperationExtra::CanaryRefresh(CanaryRefreshExtra {
                    canary_id: "cnry-2".to_string(),
                })
            },
            wrap: |payload, signatures| {
                AdminMessage::CanaryRefreshRequest(CanaryRefreshRequest {
                    payload,
                    signatures,
                })
            },
            refused: |r, _| AdminMessage::CanaryRefreshResult(r),
            row: |_, _, own| json!({ "canary_id": if own { "cnry-2" } else { "" } }),
        },
        Verb {
            request: "NetFlowsRequest",
            op: "net_flows",
            quorum: 1,
            extra: |_| {
                OperationExtra::NetFlows(NetFlowsExtra {
                    since_unix_ts: Some(1_700_000_000),
                })
            },
            wrap: |payload, signatures| {
                AdminMessage::NetFlowsRequest(NetFlowsRequest {
                    payload,
                    signatures,
                })
            },
            refused: |result, _| {
                AdminMessage::NetFlowsResponse(NetFlowsResponse {
                    result,
                    entries_jsonl: String::new(),
                    entries_count: 0,
                    entries_truncated: false,
                })
            },
            row: |_, _, own| {
                json!({
                    "since_unix_ts": if own { Some(1_700_000_000u64) } else { None },
                    "entries_count": 0,
                    "truncated": false,
                })
            },
        },
        Verb {
            request: "NetListenersRequest",
            op: "net_listeners",
            quorum: 1,
            extra: |_| OperationExtra::NetListeners(NetListenersExtra {}),
            wrap: |payload, signatures| {
                AdminMessage::NetListenersRequest(NetListenersRequest {
                    payload,
                    signatures,
                })
            },
            refused: |result, _| {
                AdminMessage::NetListenersResponse(NetListenersResponse {
                    result,
                    entries_jsonl: String::new(),
                    entries_count: 0,
                    entries_truncated: false,
                })
            },
            row: |_, _, _| empty_jsonl(),
        },
        Verb {
            request: "NetResolveRequest",
            op: "net_resolve",
            quorum: 1,
            extra: |_| {
                OperationExtra::NetResolve(NetResolveExtra {
                    ip: "192.0.2.7".to_string(),
                })
            },
            wrap: |payload, signatures| {
                AdminMessage::NetResolveRequest(NetResolveRequest {
                    payload,
                    signatures,
                })
            },
            refused: |result, _| {
                AdminMessage::NetResolveResponse(NetResolveResponse {
                    result,
                    qname: None,
                    queried_at_unix_ts: None,
                })
            },
            row: |_, _, own| json!({ "ip": if own { "192.0.2.7" } else { "" }, "resolved": false }),
        },
        Verb {
            request: "NetFingerprintRequest",
            op: "net_fingerprint",
            quorum: 1,
            extra: |_| {
                OperationExtra::NetFingerprint(NetFingerprintExtra {
                    flow_id: "0abc12".to_string(),
                })
            },
            wrap: |payload, signatures| {
                AdminMessage::NetFingerprintRequest(NetFingerprintRequest {
                    payload,
                    signatures,
                })
            },
            refused: |result, _| {
                AdminMessage::NetFingerprintResponse(NetFingerprintResponse {
                    result,
                    entries_jsonl: String::new(),
                    entries_count: 0,
                    entries_truncated: false,
                })
            },
            row: |_, _, own| {
                json!({
                    "flow_id": if own { "0abc12" } else { "" },
                    "entries_count": 0,
                    "truncated": false,
                })
            },
        },
        Verb {
            request: "TrustedInstallerGrantRequest",
            op: "trusted_installer_grant",
            quorum: 1,
            extra: |_| {
                OperationExtra::TrustedInstallerGrant(TrustedInstallerGrantExtra {
                    window_secs: 300,
                })
            },
            wrap: |payload, signatures| {
                AdminMessage::TrustedInstallerGrantRequest(TrustedInstallerGrantRequest {
                    payload,
                    signatures,
                })
            },
            refused: |r, _| AdminMessage::TrustedInstallerGrantResult(r),
            row: |_, _, own| json!({ "window_secs": if own { 300 } else { 0 } }),
        },
        Verb {
            request: "DetectionsRequest",
            op: "detections",
            quorum: 1,
            extra: |_| {
                OperationExtra::Detections(DetectionsExtra {
                    limit: 10,
                    since_unix_ts: None,
                    until_unix_ts: None,
                    min_severity: None,
                    status: None,
                    sensor: None,
                    path: None,
                })
            },
            wrap: |payload, signatures| {
                AdminMessage::DetectionsRequest(DetectionsRequest {
                    payload,
                    signatures,
                })
            },
            refused: |result, _| {
                AdminMessage::DetectionsResponse(DetectionsResponse {
                    result,
                    entries_jsonl: String::new(),
                    entries_count: 0,
                    entries_truncated: false,
                })
            },
            row: |_, _, own| {
                if !own {
                    return json!({});
                }
                json!({
                    "limit": 10,
                    "since_unix_ts": null,
                    "until_unix_ts": null,
                    "min_severity": null,
                    "status": null,
                    "sensor": null,
                    "path": null,
                    "entries_count": 0,
                    "truncated": false,
                })
            },
        },
        Verb {
            request: "DetectionSetStatusRequest",
            op: "detection_set_status",
            quorum: 1,
            extra: |_| {
                OperationExtra::DetectionSetStatus(DetectionSetStatusExtra {
                    id: 7,
                    new_status: "acknowledged".to_string(),
                    note: Some("checked".to_string()),
                })
            },
            wrap: |payload, signatures| {
                AdminMessage::DetectionSetStatusRequest(DetectionSetStatusRequest {
                    payload,
                    signatures,
                })
            },
            // every reply echoes the id the extra names (0: not this verb's)
            refused: |result, own| {
                AdminMessage::DetectionSetStatusResponse(DetectionSetStatusResponse {
                    result,
                    id: if own { 7 } else { 0 },
                    new_status: String::new(),
                    persist_failed: false,
                })
            },
            row: |_, _, own| {
                if !own {
                    return json!({});
                }
                json!({ "id": 7, "new_status": "acknowledged", "note": "checked" })
            },
        },
        Verb {
            request: "ConfigOverlaySetRequest",
            op: "config_overlay_set",
            quorum: 1,
            extra: |_| {
                OperationExtra::ConfigOverlaySet(ConfigOverlaySetExtra {
                    kind: OverlayKind::FimPaths,
                    sha256: [0xab; 32],
                    len: 6,
                })
            },
            wrap: |payload, signatures| {
                AdminMessage::ConfigOverlaySetRequest(ConfigOverlaySetRequest {
                    payload,
                    signatures,
                    content: "+/srv\n".to_string(),
                })
            },
            refused: |result, _| {
                AdminMessage::ConfigOverlaySetResponse(ConfigOverlaySetResponse {
                    result,
                    stored: false,
                    message: "signature verification failed".to_string(),
                })
            },
            // the row names the payload's own time (the rollback guard)
            row: |_, payload, own| {
                let (kind, sha, bytes) = if own {
                    (OverlayKind::FimPaths.keyword(), "ab".repeat(32), 6)
                } else {
                    ("unknown", String::new(), 0)
                };
                json!({
                    "kind": kind,
                    "sha256": sha,
                    "signed_ts": payload.ts,
                    "bytes": bytes,
                    "detail": "signature verification failed",
                })
            },
        },
        Verb {
            request: "ResponseStatusRequest",
            op: "response_status",
            quorum: 1,
            extra: |_| OperationExtra::ResponseStatus(ResponseStatusExtra {}),
            wrap: |payload, signatures| {
                AdminMessage::ResponseStatusRequest(ResponseStatusRequest {
                    payload,
                    signatures,
                })
            },
            refused: |result, _| {
                AdminMessage::ResponseStatusResponse(ResponseStatusResponse {
                    result,
                    contained: Vec::new(),
                    contained_total: 0,
                    quarantined: Vec::new(),
                    quarantined_total: 0,
                    combat_stage: None,
                    combat_locked: None,
                })
            },
            row: |_, _, _| json!({ "contained_total": 0, "quarantined_total": 0, "combat_stage": null }),
        },
        Verb {
            request: "ResponseReleaseRequest",
            op: "response_release",
            quorum: 1,
            extra: |_| OperationExtra::ResponseRelease(ResponseReleaseExtra { pid: 4242 }),
            wrap: |payload, signatures| {
                AdminMessage::ResponseReleaseRequest(ResponseReleaseRequest {
                    payload,
                    signatures,
                })
            },
            refused: |result, _| {
                AdminMessage::ResponseReleaseResponse(ResponseReleaseResponse {
                    result,
                    released: false,
                    message: String::new(),
                })
            },
            row: |_, _, own| json!({ "pid": if own { Some(4242) } else { None }, "by": "admin", "detail": "" }),
        },
        Verb {
            request: "ResponseRestoreRequest",
            op: "response_restore",
            quorum: 1,
            extra: |_| {
                OperationExtra::ResponseRestore(ResponseRestoreExtra {
                    vault_id: "vault-1".to_string(),
                    to: None,
                })
            },
            wrap: |payload, signatures| {
                AdminMessage::ResponseRestoreRequest(ResponseRestoreRequest {
                    payload,
                    signatures,
                })
            },
            refused: |result, _| {
                AdminMessage::ResponseRestoreResponse(ResponseRestoreResponse {
                    result,
                    restored: false,
                    path: String::new(),
                    message: String::new(),
                })
            },
            row: |_, _, own| {
                json!({
                    "vault_id": if own { "vault-1" } else { "" },
                    "to": null,
                    "path": "",
                    "detail": "",
                })
            },
        },
        Verb {
            request: "TelemetryStatusRequest",
            op: "telemetry_status",
            quorum: 1,
            extra: |_| OperationExtra::TelemetryStatus(TelemetryStatusExtra {}),
            wrap: |payload, signatures| {
                AdminMessage::TelemetryStatusRequest(TelemetryStatusRequest {
                    payload,
                    signatures,
                })
            },
            refused: |result, _| {
                AdminMessage::TelemetryStatusResponse(TelemetryStatusResponse {
                    result,
                    status: None,
                })
            },
            row: |_, _, _| json!({}),
        },
        Verb {
            request: "RemediateRansomwareRequest",
            op: "remediate_ransomware",
            quorum: 1,
            extra: |_| {
                OperationExtra::RemediateRansomware(RemediateRansomwareExtra {
                    pid: Some(77),
                    since_unix: None,
                    dry_run: true,
                })
            },
            wrap: |payload, signatures| {
                AdminMessage::RemediateRansomwareRequest(RemediateRansomwareRequest {
                    payload,
                    signatures,
                })
            },
            refused: |result, _| {
                AdminMessage::RemediateRansomwareResponse(RemediateRansomwareResponse {
                    result,
                    done: false,
                    message: String::new(),
                    rows: Vec::new(),
                    rows_total: 0,
                    restored: 0,
                    recreated: 0,
                    kept_both: 0,
                    unchanged: 0,
                    refused: 0,
                    skipped: 0,
                })
            },
            row: |_, _, own| {
                json!({
                    "pid": if own { Some(77) } else { None },
                    "since_unix": null,
                    "dry_run": own,
                    "files": 0,
                    "restored": 0,
                    "recreated": 0,
                    "kept_both": 0,
                    "unchanged": 0,
                    "refused": 0,
                    "skipped": 0,
                    "detail": "",
                })
            },
        },
    ]
}

/// The verb's payload, signed by `signers`.
fn payload(
    op_extra: OperationExtra,
    nonce: [u8; 32],
    ts: u64,
    agent_id: [u8; 16],
) -> SignedPayload {
    SignedPayload {
        op: op_extra.op_code(),
        nonce,
        ts,
        agent_id,
        extra: op_extra,
    }
}

fn signatures(payload: &SignedPayload, signers: &[&SigningKey]) -> Vec<KeyedSignature> {
    signers
        .iter()
        .map(|k| KeyedSignature {
            signature: sign(payload, k).unwrap(),
        })
        .collect()
}

/// Another verb's extra: the telemetry status's, or the response status's
/// for the telemetry status itself.
fn foreign_extra(verb: &Verb) -> OperationExtra {
    if verb.request == "TelemetryStatusRequest" {
        OperationExtra::ResponseStatus(ResponseStatusExtra {})
    } else {
        OperationExtra::TelemetryStatus(TelemetryStatusExtra {})
    }
}

/// The keys that meet the verb's quorum.
fn quorum_keys<'k>(verb: &Verb, k: &'k Keys) -> Vec<&'k SigningKey> {
    if verb.quorum == 2 {
        vec![&k.a, &k.b]
    } else {
        vec![&k.a]
    }
}

/// Installed keys, as many as the quorum, holding none of the verb's
/// roles.
fn weak_keys<'k>(verb: &Verb, k: &'k Keys) -> Vec<&'k SigningKey> {
    match (verb.quorum, verb.request) {
        (2, _) => vec![&k.canary_read, &k.net_read],
        (_, "CanaryListRequest") => vec![&k.net_read],
        _ => vec![&k.canary_read],
    }
}

/// The audit row's `result` of a refusal (design §9.1).
fn failure(r: &AdminResult) -> String {
    match r {
        AdminResult::NoPendingChallenge => "failure: no_pending_challenge".to_string(),
        AdminResult::InvalidSignature => "failure: invalid_signature".to_string(),
        AdminResult::RoleDenied => "failure: role_denied".to_string(),
        AdminResult::AgentIdMismatch => "failure: agent_id_mismatch".to_string(),
        AdminResult::UnknownOperation => "failure: unknown_operation".to_string(),
        AdminResult::QuorumNotMet { required, provided } => {
            format!("failure: quorum_not_met (required={required}, provided={provided})")
        }
        AdminResult::TimestampSkew {
            server_ts,
            max_skew_secs,
        } => format!(
            "failure: timestamp_skew (server_ts={server_ts}, max_skew_secs={max_skew_secs})"
        ),
        AdminResult::RateLimited { retry_after_secs } => {
            format!("failure: rate_limited (retry_after_secs={retry_after_secs})")
        }
        other => panic!("not a refusal of the verification: {other:?}"),
    }
}

/// The `AdminResult` a reply carries.
fn result_of(reply: &AdminMessage) -> AdminResult {
    match reply {
        AdminMessage::ShutdownResult(r)
        | AdminMessage::ForcePostureResult(r)
        | AdminMessage::RotateKeysAddResult(r)
        | AdminMessage::RotateKeysRevokeResult(r)
        | AdminMessage::FimBaselineResult(r)
        | AdminMessage::CanaryBurnResult(r)
        | AdminMessage::CanaryRefreshResult(r)
        | AdminMessage::TrustedInstallerGrantResult(r) => *r,
        AdminMessage::SignedUnlockResponse(x) => x.result,
        AdminMessage::FimReportResponse(x) => x.result,
        AdminMessage::FimStatusResponse(x) => x.result,
        AdminMessage::CanaryDeployResponse(x) => x.result,
        AdminMessage::CanaryListResponse(x) => x.result,
        AdminMessage::NetFlowsResponse(x) => x.result,
        AdminMessage::NetListenersResponse(x) => x.result,
        AdminMessage::NetResolveResponse(x) => x.result,
        AdminMessage::NetFingerprintResponse(x) => x.result,
        AdminMessage::DetectionsResponse(x) => x.result,
        AdminMessage::DetectionSetStatusResponse(x) => x.result,
        AdminMessage::ConfigOverlaySetResponse(x) => x.result,
        AdminMessage::ResponseStatusResponse(x) => x.result,
        AdminMessage::ResponseReleaseResponse(x) => x.result,
        AdminMessage::ResponseRestoreResponse(x) => x.result,
        AdminMessage::TelemetryStatusResponse(x) => x.result,
        AdminMessage::RemediateRansomwareResponse(x) => x.result,
        other => panic!("not a signed verb's reply: {other:?}"),
    }
}

/// Why the verification refuses a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reason {
    /// No challenge asked on the connection.
    NoChallenge,
    /// Signed over another connection's challenge (captured, replayed).
    Replayed,
    /// The same request again on its connection: its challenge is spent.
    ChallengeSpent,
    /// The right keys' signatures, one byte flipped.
    BadSignature,
    /// Signed by a key admin.pub does not hold.
    UnknownKey,
    /// Signed by installed keys that hold none of the verb's roles.
    WrongRole,
    /// No signature at all.
    NoSignature,
    /// A 2-of-N verb signed twice by one key.
    OneKeyTwice,
    /// Its time 120 s before the server's clock (the window is ±60 s; a
    /// second's tick between the signing and the verify cannot bring it in).
    Expired,
    /// Its time 120 s after the server's clock.
    FromTheFuture,
    /// Another install's agent id.
    WrongAgentId,
    /// A valid signature over another verb's payload.
    AnotherVerbsPayload,
    /// The verb's operation, another verb's extra.
    ExtraOfAnotherVerb,
    /// Nine signatures (at most eight are taken).
    TooManySignatures,
}

const REASONS: [Reason; 14] = [
    Reason::NoChallenge,
    Reason::Replayed,
    Reason::ChallengeSpent,
    Reason::BadSignature,
    Reason::UnknownKey,
    Reason::WrongRole,
    Reason::NoSignature,
    Reason::OneKeyTwice,
    Reason::Expired,
    Reason::FromTheFuture,
    Reason::WrongAgentId,
    Reason::AnotherVerbsPayload,
    Reason::ExtraOfAnotherVerb,
    Reason::TooManySignatures,
];

/// What one request got: its reply and its audit row.
struct Served {
    reply: AdminMessage,
    row: AuditEntry,
}

/// `text` with the clocks masked: the server's (`server_ts: N`,
/// `server_ts=N`) and the payload's own time in a row (`"signed_ts":N`).
fn mask_clock(text: &str) -> String {
    let mut text = text.to_string();
    for key in ["server_ts", "\"signed_ts\""] {
        let mut out = String::with_capacity(text.len());
        let mut rest = text.as_str();
        while let Some(i) = rest.find(key) {
            let after = &rest[i + key.len()..];
            let sep = after.len() - after.trim_start_matches([':', '=', ' ']).len();
            let digits = after[sep..].bytes().take_while(u8::is_ascii_digit).count();
            out.push_str(&rest[..i + key.len() + sep]);
            if digits > 0 {
                out.push_str("<now>");
            }
            rest = &after[sep + digits..];
        }
        out.push_str(rest);
        text = out;
    }
    text
}

/// A reply as the table prints it: its `Debug`, but the telemetry status
/// an accepted request gets — the agent's counters, process-wide (other
/// tests of the crate move them), and not the pipeline's: their own tests
/// read them.
fn reply_text(reply: &AdminMessage) -> String {
    match reply {
        AdminMessage::TelemetryStatusResponse(TelemetryStatusResponse {
            result,
            status: Some(_),
        }) => format!(
            "TelemetryStatusResponse(TelemetryStatusResponse {{ result: {result:?}, \
             status: Some(<the agent's counters>) }})"
        ),
        other => format!("{other:?}"),
    }
}

/// One line of the table: a request's reply and row, the clock masked.
fn table_line(verb: &str, case: &str, s: &Served) -> String {
    let row = &s.row;
    mask_clock(&format!(
        "{verb} | {case} | reply {} | row op={} result={:?} key_fp={:?} cosigners={:?} \
         client={}/{}/{}/{:?} extra={}",
        reply_text(&s.reply),
        row.op,
        row.result,
        row.key_fp,
        row.cosigner_fps,
        row.client_pid,
        row.client_uid,
        row.client_comm,
        row.client_exe,
        row.extra,
    ))
}

/// Run one rejection: the request this reason builds, on a fresh agent.
/// Returns what the request got (after the accepted first sending of
/// `ChallengeSpent`), the answer the reason must get, and the payload sent.
fn reject(verb: &Verb, reason: Reason, k: &Keys) -> (Vec<Served>, AdminResult, SignedPayload) {
    let fx = Fixture::new(k);
    let conn = ConnAuth::new(&fx.auth);
    let now = now_unix_secs();
    let mut nonce = [0x11; 32];
    if reason != Reason::NoChallenge {
        nonce = fx.challenge(&conn);
    }
    if reason == Reason::Replayed {
        let other = ConnAuth::new(&fx.auth);
        nonce = fx.challenge(&other);
    }
    let ts = match reason {
        Reason::Expired => now - 120,
        Reason::FromTheFuture => now + 120,
        _ => now,
    };
    let agent_id = if reason == Reason::WrongAgentId {
        [0x99; 16]
    } else {
        AGENT_ID
    };
    let mut p = match reason {
        Reason::AnotherVerbsPayload => payload(foreign_extra(verb), nonce, ts, agent_id),
        _ => payload((verb.extra)(k), nonce, ts, agent_id),
    };
    if reason == Reason::ExtraOfAnotherVerb {
        p.extra = foreign_extra(verb);
    }
    let signers: Vec<&SigningKey> = match reason {
        Reason::UnknownKey => vec![&k.stranger],
        Reason::WrongRole => weak_keys(verb, k),
        Reason::NoSignature => Vec::new(),
        Reason::OneKeyTwice => vec![&k.a, &k.a],
        Reason::TooManySignatures => vec![&k.a; 9],
        _ => quorum_keys(verb, k),
    };
    let mut sigs = signatures(&p, &signers);
    if reason == Reason::BadSignature {
        for s in &mut sigs {
            s.signature[7] ^= 0x01;
        }
    }
    let sent = p.clone();
    let request = (verb.wrap)(p, sigs);
    let mut served = Vec::new();
    if reason == Reason::ChallengeSpent {
        // the request accepted once (whatever its handler then does) …
        let reply = fx.serve(&conn, &request);
        served.push(Served {
            reply,
            row: fx.rows().pop().expect("the accepted request's row"),
        });
    }
    // … and refused when it comes again
    let reply = fx.serve(&conn, &request);
    let rows = fx.rows();
    assert_eq!(
        rows.len(),
        served.len() + 1,
        "{} {reason:?}: one row per request",
        verb.op
    );
    served.push(Served {
        reply,
        row: rows.last().cloned().unwrap(),
    });
    let expected = match reason {
        Reason::NoChallenge | Reason::ChallengeSpent => AdminResult::NoPendingChallenge,
        Reason::Replayed | Reason::BadSignature | Reason::UnknownKey => {
            AdminResult::InvalidSignature
        }
        Reason::TooManySignatures => AdminResult::InvalidSignature,
        Reason::WrongRole => AdminResult::RoleDenied,
        Reason::NoSignature => AdminResult::QuorumNotMet {
            required: verb.quorum as u8,
            provided: 0,
        },
        Reason::OneKeyTwice => AdminResult::QuorumNotMet {
            required: 2,
            provided: 1,
        },
        Reason::Expired | Reason::FromTheFuture => {
            // the server's clock, read by the verify: between `now` and now
            match result_of(&served.last().unwrap().reply) {
                r @ AdminResult::TimestampSkew {
                    server_ts,
                    max_skew_secs: 60,
                } if (now..=now_unix_secs()).contains(&server_ts) => r,
                other => panic!("{} {reason:?}: {other:?}", verb.op),
            }
        }
        Reason::WrongAgentId => AdminResult::AgentIdMismatch,
        Reason::AnotherVerbsPayload | Reason::ExtraOfAnotherVerb => AdminResult::UnknownOperation,
    };
    (served, expected, sent)
}

/// Every signed verb × every reason the verification refuses: the exact
/// reply and the signed row, as `serve_request` gives them.
#[test]
fn every_verb_refuses_every_reason_with_its_reply_and_row() {
    let k = keys();
    let verbs = verbs();
    // the table covers every signed verb of the pipeline, by its rule
    assert_eq!(verbs.len(), RULES.len());
    for (verb, (name, rule)) in verbs.iter().zip(RULES) {
        assert_eq!(verb.request, *name);
        let quorum = match rule.quorum {
            Quorum::Of(n) | Quorum::Bootstrap(n) => usize::from(n),
        };
        assert_eq!(verb.quorum, quorum, "{name}");
    }
    let mut table = String::new();
    for verb in &verbs {
        for reason in REASONS {
            if reason == Reason::OneKeyTwice && verb.quorum < 2 {
                continue;
            }
            let (served, expected, sent) = reject(verb, reason, &k);
            let case = format!("{reason:?}");
            let last = served.last().unwrap();
            let own = !matches!(
                reason,
                Reason::AnotherVerbsPayload | Reason::ExtraOfAnotherVerb
            );
            let what = format!("{} {case}", verb.op);
            assert_eq!(last.reply, (verb.refused)(expected, own), "{what}: reply");
            let row = &last.row;
            assert_eq!(row.op, verb.op, "{what}");
            assert_eq!(row.result, failure(&expected), "{what}");
            assert_eq!(row.extra, (verb.row)(&k, &sent, own), "{what}: extra");
            // a refusal names no signer — but the read role the
            // telemetry status lacks, whose signer the row names (lab PR
            // 213, `Roles::AnyOf`)
            let telemetry_role = verb.op == "telemetry_status" && reason == Reason::WrongRole;
            let submitted = match reason {
                Reason::UnknownKey => 1,
                Reason::WrongRole => weak_keys(verb, &k).len(),
                Reason::NoSignature => 0,
                Reason::OneKeyTwice => 2,
                Reason::TooManySignatures => 9,
                _ => verb.quorum,
            };
            if telemetry_role {
                assert_eq!(row.key_fp, fp(&k.canary_read), "{what}");
                assert!(row.cosigner_fps.is_empty(), "{what}");
            } else {
                assert_eq!(row.key_fp, "", "{what}");
                assert_eq!(
                    row.cosigner_fps,
                    vec![String::new(); submitted.saturating_sub(1)],
                    "{what}"
                );
            }
            let client = fake_client();
            assert_eq!(
                (
                    row.client_pid,
                    row.client_uid,
                    &row.client_comm,
                    &row.client_exe
                ),
                (client.pid, client.uid, &client.comm, &client.exe),
                "{what}"
            );
            if reason == Reason::ChallengeSpent {
                // the first time, accepted: the row names its signers
                let first = &served[0].row;
                let signers = quorum_keys(verb, &k);
                assert_eq!(first.key_fp, fp(signers[0]), "{what}: accepted");
                assert_eq!(
                    first.cosigner_fps,
                    signers[1..].iter().map(|s| fp(s)).collect::<Vec<_>>(),
                    "{what}: accepted"
                );
                writeln!(
                    table,
                    "{}",
                    table_line(verb.op, "ChallengeSpent(first)", &served[0])
                )
                .unwrap();
            }
            writeln!(table, "{}", table_line(verb.op, &case, last)).unwrap();
        }
    }
    golden("rejections", &table);
}

/// A request the pipeline accepts reaches its handler: the reply is the
/// verb's (whatever its handler, here without its subsystem, answers) and
/// the row names the signers in admin.pub's order.
#[test]
fn an_accepted_request_reaches_its_handler_with_its_signers_named() {
    let k = keys();
    let mut table = String::new();
    for verb in verbs() {
        let fx = Fixture::new(&k);
        let conn = ConnAuth::new(&fx.auth);
        let nonce = fx.challenge(&conn);
        let p = payload((verb.extra)(&k), nonce, now_unix_secs(), AGENT_ID);
        let signers = quorum_keys(&verb, &k);
        let request = (verb.wrap)(p.clone(), signatures(&p, &signers));
        let reply = fx.serve(&conn, &request);
        assert_eq!(
            std::mem::discriminant(&reply),
            std::mem::discriminant(&(verb.refused)(AdminResult::Success, true)),
            "{}: {reply:?}",
            verb.op
        );
        let rows = fx.rows();
        let row = rows.last().expect("its row");
        assert_eq!(row.op, verb.op);
        assert_eq!(row.key_fp, fp(signers[0]), "{}", verb.op);
        assert_eq!(
            row.cosigner_fps,
            signers[1..].iter().map(|s| fp(s)).collect::<Vec<_>>(),
            "{}",
            verb.op
        );
        writeln!(
            table,
            "{}",
            table_line(
                verb.op,
                "Accepted",
                &Served {
                    reply,
                    row: row.clone()
                }
            )
        )
        .unwrap();
    }
    golden("accepted", &table);
}

/// A connection's third counted failure is answered `RateLimited` (its
/// row says so), and so is every request after it, a challenge included
/// (no row: the challenge has none).
#[test]
fn the_third_counted_failure_closes_the_connections_verification() {
    let k = keys();
    let mut table = String::new();
    for verb in verbs() {
        let fx = Fixture::new(&k);
        let conn = ConnAuth::new(&fx.auth);
        let bad = |nonce: [u8; 32]| {
            let p = payload((verb.extra)(&k), nonce, now_unix_secs(), AGENT_ID);
            let mut sigs = signatures(&p, &quorum_keys(&verb, &k));
            for s in &mut sigs {
                s.signature[7] ^= 0x01;
            }
            (verb.wrap)(p, sigs)
        };
        let limited = AdminResult::RateLimited {
            retry_after_secs: 1,
        };
        for want in [
            AdminResult::InvalidSignature,
            AdminResult::InvalidSignature,
            limited,
        ] {
            let nonce = fx.challenge(&conn);
            let reply = fx.serve(&conn, &bad(nonce));
            assert_eq!(reply, (verb.refused)(want, true), "{}", verb.op);
        }
        assert!(conn.exhausted(), "{}", verb.op);
        let reply = fx.serve(&conn, &AdminMessage::ChallengeRequest(ChallengeRequest {}));
        assert_eq!(
            reply,
            AdminMessage::UnlockResult(UnlockResult::RateLimited {
                retry_after_secs: 1
            }),
            "{}",
            verb.op
        );
        let p = payload((verb.extra)(&k), [0x22; 32], now_unix_secs(), AGENT_ID);
        let request = (verb.wrap)(p.clone(), signatures(&p, &quorum_keys(&verb, &k)));
        let reply = fx.serve(&conn, &request);
        assert_eq!(reply, (verb.refused)(limited, true), "{}", verb.op);
        let results: Vec<String> = fx.rows().into_iter().map(|r| r.result).collect();
        let rate_limited = failure(&limited);
        assert_eq!(
            results,
            [
                "failure: invalid_signature".to_string(),
                "failure: invalid_signature".to_string(),
                rate_limited.clone(),
                rate_limited,
            ],
            "{}",
            verb.op
        );
        for row in fx.rows() {
            writeln!(
                table,
                "{} | RateLimitSequence | row result={:?} key_fp={:?} cosigners={:?}",
                verb.op, row.result, row.key_fp, row.cosigner_fps
            )
            .unwrap();
        }
    }
    golden("rate-limited", &table);
}

/// The requests that carry no signature, answered as they are: a challenge
/// (no row), the public status (its poll row: at most one per peer and
/// hour), the loop's progress (no row), the legacy unlock — refused,
/// whatever it carries, its row written (lab PR 217) — and a reply sent as
/// a request (no row, and the connection's challenge kept).
#[test]
fn the_requests_without_a_signature_are_answered_as_they_are() {
    let k = keys();
    let fx = Fixture::new(&k);
    let conn = ConnAuth::new(&fx.auth);
    assert!(matches!(
        fx.serve(&conn, &AdminMessage::ChallengeRequest(ChallengeRequest {})),
        AdminMessage::Challenge(_)
    ));
    assert!(fx.rows().is_empty(), "a challenge has no row");
    assert!(matches!(
        fx.serve(&conn, &AdminMessage::Status(StatusRequest {})),
        AdminMessage::StatusResponse(_)
    ));
    assert!(matches!(
        fx.serve(&conn, &AdminMessage::LoopProgress(LoopProgressRequest {})),
        AdminMessage::LoopProgressResponse(_)
    ));
    let rows = fx.rows();
    assert_eq!(
        rows.iter().map(|r| r.op.as_str()).collect::<Vec<_>>(),
        [super::status_polls::STATUS_POLLED_OP],
        "the status poll's row only"
    );
    // a reply sent as a request: answered, no row, the challenge kept
    let nonce = fx.challenge(&conn);
    assert_eq!(
        fx.serve(&conn, &AdminMessage::ShutdownResult(AdminResult::Success)),
        AdminMessage::UnlockResult(UnlockResult::NoPendingChallenge)
    );
    assert_eq!(fx.rows().len(), 1);
    let verbs = verbs();
    let telemetry = verbs.iter().find(|v| v.op == "telemetry_status").unwrap();
    let p = payload((telemetry.extra)(&k), nonce, now_unix_secs(), AGENT_ID);
    let request = (telemetry.wrap)(p.clone(), signatures(&p, &[&k.a]));
    assert!(matches!(
        fx.serve(&conn, &request),
        AdminMessage::TelemetryStatusResponse(TelemetryStatusResponse {
            result: AdminResult::Success,
            ..
        })
    ));
    // the legacy unlock: refused, its challenge spent, its row written
    fx.challenge(&conn);
    assert_eq!(
        fx.serve(
            &conn,
            &AdminMessage::Unlock(UnlockRequest {
                signature: [0x33; 64]
            })
        ),
        AdminMessage::UnlockResult(UnlockResult::LegacyProtocolRefused)
    );
    let row = fx.rows().pop().unwrap();
    assert_eq!(
        (row.op.as_str(), row.result.as_str(), &row.extra),
        (
            "unlock",
            "failure: legacy_protocol_refused",
            &json!({ "protocol": "legacy" })
        )
    );
    let p = payload((telemetry.extra)(&k), nonce, now_unix_secs(), AGENT_ID);
    let request = (telemetry.wrap)(p.clone(), signatures(&p, &[&k.a]));
    assert_eq!(
        fx.serve(&conn, &request),
        (telemetry.refused)(AdminResult::NoPendingChallenge, true),
        "the legacy unlock spent the challenge"
    );
}

/// A signed request on a connection of its own, as nn-admin sends it: its
/// reply and its audit row.
fn send(
    fx: &Fixture,
    extra: OperationExtra,
    signers: &[&SigningKey],
) -> (AdminMessage, AuditEntry) {
    let conn = ConnAuth::new(&fx.auth);
    let nonce = fx.challenge(&conn);
    let p = payload(extra, nonce, now_unix_secs(), AGENT_ID);
    let signatures = signatures(&p, signers);
    let request = match &p.extra {
        OperationExtra::RotateKeysAdd(_) => {
            AdminMessage::RotateKeysAddRequest(RotateKeysAddRequest {
                payload: p,
                signatures,
            })
        }
        OperationExtra::RotateKeysRevoke(_) => {
            AdminMessage::RotateKeysRevokeRequest(RotateKeysRevokeRequest {
                payload: p,
                signatures,
            })
        }
        OperationExtra::Shutdown(_) => AdminMessage::ShutdownRequest(ShutdownRequest {
            payload: p,
            signatures,
        }),
        other => panic!("send: {other:?}"),
    };
    let reply = fx.serve(&conn, &request);
    (reply, fx.rows().pop().expect("its row"))
}

/// A `rotate-keys add` of `new` (`audit-read`), signed by `signers`.
fn add_key(fx: &Fixture, new: &SigningKey, signers: &[&SigningKey]) -> (AdminMessage, AuditEntry) {
    let extra = OperationExtra::RotateKeysAdd(RotateKeysAddExtra {
        new_pubkey: new.verifying_key().to_bytes(),
        roles: vec![Role::AuditRead],
    });
    send(fx, extra, signers)
}

/// 2-of-N refused to one key.
const ONE_OF_TWO: AdminResult = AdminResult::QuorumNotMet {
    required: 2,
    provided: 1,
};

/// The one-key bootstrap of `install.sh`, end to end through the pipeline
/// (BUG-013, external audit ATP-004; lab PR 263's review, M-1). While it
/// is armed the install's key alone adds the second key — its row names
/// it — and nothing else: shutdown and revoke stay 2-of-N. The add removes
/// the sentinel and spends the bootstrap: a second add with one key is
/// refused, and so it is after the keys went back to one and root wrote a
/// valid sentinel again — the add of a second key spent it for good.
#[test]
fn the_one_key_bootstrap_adds_one_key_and_is_then_spent() {
    let k = keys();
    let fx = Fixture::bootstrap(&k.a);
    let shutdown = OperationExtra::Shutdown(ShutdownExtra { grace_secs: 30 });
    assert_eq!(
        send(&fx, shutdown, &[&k.a]).0,
        AdminMessage::ShutdownResult(ONE_OF_TWO),
        "the bootstrap relaxes the add alone"
    );
    let revoke = OperationExtra::RotateKeysRevoke(RotateKeysRevokeExtra {
        fingerprint: fp_bytes(&k.a),
    });
    assert_eq!(
        send(&fx, revoke, &[&k.a]).0,
        AdminMessage::RotateKeysRevokeResult(ONE_OF_TWO)
    );

    // armed: one key adds the second
    let (reply, row) = add_key(&fx, &k.b, &[&k.a]);
    assert_eq!(
        reply,
        AdminMessage::RotateKeysAddResult(AdminResult::Success)
    );
    assert_eq!(
        (row.op.as_str(), row.result.as_str(), row.key_fp.as_str()),
        ("rotate_keys_add", "success", fp(&k.a).as_str())
    );
    assert!(row.cosigner_fps.is_empty());
    assert_eq!(row.extra, json!({ "new_key_fp": fp(&k.b) }));
    assert_eq!(fx.admin_keys(), 2);
    assert!(!fx.sentinel().exists(), "the add removes the sentinel");
    assert!(fx.auth.bootstrap_consumed(), "and spends the bootstrap");

    // spent: one key adds no other
    let (reply, row) = add_key(&fx, &k.canary_read, &[&k.a]);
    assert_eq!(reply, AdminMessage::RotateKeysAddResult(ONE_OF_TWO));
    assert_eq!(row.result, failure(&ONE_OF_TWO));
    assert_eq!(fx.admin_keys(), 2);

    // ATP-004: back to one key, a valid sentinel written again — still spent
    let revoke = OperationExtra::RotateKeysRevoke(RotateKeysRevokeExtra {
        fingerprint: fp_bytes(&k.b),
    });
    assert_eq!(
        send(&fx, revoke, &[&k.a, &k.b]).0,
        AdminMessage::RotateKeysRevokeResult(AdminResult::Success)
    );
    assert_eq!(fx.admin_keys(), 1);
    fx.write_sentinel();
    let (reply, row) = add_key(&fx, &k.canary_read, &[&k.a]);
    assert_eq!(
        reply,
        AdminMessage::RotateKeysAddResult(ONE_OF_TWO),
        "the bootstrap was armed again"
    );
    assert_eq!(row.result, failure(&ONE_OF_TWO));
    assert_eq!(fx.admin_keys(), 1);
}

/// ATP-004 at boot: the signed chain holds a second key's add
/// (`boot::admin` marks the bootstrap spent), and a one-key admin.pub with
/// a valid sentinel is 2-of-N.
#[test]
fn a_bootstrap_the_signed_chain_spent_stays_closed() {
    let k = keys();
    let fx = Fixture::bootstrap(&k.a);
    fx.auth.mark_bootstrap_consumed();
    let (reply, row) = add_key(&fx, &k.b, &[&k.a]);
    assert_eq!(reply, AdminMessage::RotateKeysAddResult(ONE_OF_TWO));
    assert_eq!(row.result, failure(&ONE_OF_TWO));
    assert_eq!(fx.admin_keys(), 1);
}

/// The gate is armed only when all its conditions hold (BUG-013): without
/// the sentinel, with a sentinel that is not the hash of the install nonce
/// and admin.pub, or without the nonce, one key adds no key. A sentinel
/// that does not match is left for the operator to see.
#[test]
fn a_bootstrap_gate_not_armed_keeps_the_add_two_of_n() {
    type Close = fn(&Fixture);
    let k = keys();
    let cases: [(&str, Close); 3] = [
        ("no sentinel", |fx| {
            std::fs::remove_file(fx.sentinel()).unwrap()
        }),
        ("a sentinel over another admin.pub", |fx| {
            std::fs::write(fx.sentinel(), "0".repeat(64)).unwrap()
        }),
        ("no install nonce", |fx| {
            std::fs::remove_file(fx.dir.path().join(".install_nonce")).unwrap()
        }),
    ];
    for (case, close) in cases {
        let fx = Fixture::bootstrap(&k.a);
        close(&fx);
        let (reply, row) = add_key(&fx, &k.b, &[&k.a]);
        assert_eq!(
            reply,
            AdminMessage::RotateKeysAddResult(ONE_OF_TWO),
            "{case}"
        );
        assert_eq!(row.result, failure(&ONE_OF_TWO), "{case}");
        assert_eq!(fx.admin_keys(), 1, "{case}");
        assert!(!fx.auth.bootstrap_consumed(), "{case}");
        if case == "a sentinel over another admin.pub" {
            assert!(fx.sentinel().exists(), "{case}: kept for the operator");
        }
    }
}

/// Lab PR 263's review (L-4): two `rotate-keys add` sent at once while the
/// one-key bootstrap is armed, on two connections, signed by the one key:
/// one adds its key, the other waits for the rotation lock and then finds
/// the bootstrap spent. Both used to read the gate armed and pass. Several
/// rounds, each on a fresh install.
#[test]
fn two_concurrent_bootstrap_adds_admit_one() {
    let k = keys();
    for round in 0..8 {
        let fx = Fixture::bootstrap(&k.a);
        let start = std::sync::Barrier::new(2);
        let replies: Vec<AdminMessage> = std::thread::scope(|s| {
            let threads: Vec<_> = [&k.b, &k.canary_read]
                .into_iter()
                .map(|new| {
                    let (fx, start) = (&fx, &start);
                    let a = &k.a;
                    s.spawn(move || {
                        let conn = ConnAuth::new(&fx.auth);
                        let nonce = fx.challenge(&conn);
                        let extra = OperationExtra::RotateKeysAdd(RotateKeysAddExtra {
                            new_pubkey: new.verifying_key().to_bytes(),
                            roles: vec![Role::AuditRead],
                        });
                        let p = payload(extra, nonce, now_unix_secs(), AGENT_ID);
                        let request = AdminMessage::RotateKeysAddRequest(RotateKeysAddRequest {
                            signatures: signatures(&p, &[a]),
                            payload: p,
                        });
                        start.wait();
                        fx.serve(&conn, &request)
                    })
                })
                .collect();
            threads.into_iter().map(|t| t.join().unwrap()).collect()
        });
        let mut results: Vec<AdminResult> = replies.iter().map(result_of).collect();
        results.sort_by_key(|r| format!("{r:?}"));
        assert_eq!(
            results,
            [ONE_OF_TWO, AdminResult::Success],
            "round {round}: one add, the other refused"
        );
        assert_eq!(fx.admin_keys(), 2, "round {round}");
    }
}

/// Lab PR 263's review (L-4): a `rotate-keys add` or `revoke` waits for the
/// rotation in flight before it reads the bootstrap gate or verifies —
/// here the test holds the lock, and spends the bootstrap meanwhile, as an
/// add in flight does.
#[test]
fn a_rotation_waits_for_the_one_in_flight() {
    let k = keys();
    let fx = Fixture::bootstrap(&k.a);
    let in_flight = fx.auth.rotation_lock();
    std::thread::scope(|s| {
        let (tx, rx) = std::sync::mpsc::channel();
        let (fx, k) = (&fx, &k);
        let add = {
            let tx = tx.clone();
            s.spawn(move || tx.send(("add", add_key(fx, &k.b, &[&k.a]).0)).unwrap())
        };
        let revoke = s.spawn(move || {
            let extra = OperationExtra::RotateKeysRevoke(RotateKeysRevokeExtra {
                fingerprint: fp_bytes(&k.a),
            });
            tx.send(("revoke", send(fx, extra, &[&k.a]).0)).unwrap()
        });
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(400))
                .is_err(),
            "a rotation ran beside the one in flight"
        );
        fx.auth.mark_bootstrap_consumed();
        drop(in_flight);
        add.join().unwrap();
        revoke.join().unwrap();
        let mut replies: Vec<(&str, AdminMessage)> = rx.iter().collect();
        replies.sort_by_key(|(verb, _)| *verb);
        assert_eq!(
            replies,
            [
                ("add", AdminMessage::RotateKeysAddResult(ONE_OF_TWO)),
                ("revoke", AdminMessage::RotateKeysRevokeResult(ONE_OF_TWO)),
            ],
            "after it, the add found the bootstrap spent"
        );
    });
    assert_eq!(fx.admin_keys(), 1);
}

/// Every role but `all`, by hand: a role the enum gains is a role these
/// tests must place (`every_role_is_in_the_role_tests`).
const EVERY_ROLE: [Role; 16] = [
    Role::Unlock,
    Role::Shutdown,
    Role::ForcePosture,
    Role::RotateKeys,
    Role::AuditRead,
    Role::FimManage,
    Role::FimRead,
    Role::CanaryRead,
    Role::CanaryManage,
    Role::NetRead,
    Role::NetManage,
    Role::TrustedInstaller,
    Role::TelemetryRead,
    Role::Triage,
    Role::ConfigManage,
    Role::ResponseManage,
];

/// The roles each signed verb needs, as its design names them (TAPPA8
/// §3.3 and §4, FIM §13 Q6, the deception layer's §12 Q7, Tappa 9.0.b/c,
/// 10 N1, 10.8, FIM-009, CMB-016, ASK-009, lab PR 222). Written here by
/// hand, not read from `verify::RULES`: a role changed in the table and in
/// its pin alike is still caught (lab PR 263's review, M-2).
fn designed_roles(op: &str) -> &'static [Role] {
    match op {
        "unlock" => &[Role::Unlock],
        "shutdown" => &[Role::Shutdown],
        "force_posture" => &[Role::ForcePosture],
        "rotate_keys_add" | "rotate_keys_revoke" => &[Role::RotateKeys],
        "fim_baseline" => &[Role::FimManage],
        "fim_report" | "fim_status" => &[Role::FimRead],
        "canary_deploy" | "canary_burn" | "canary_refresh" => &[Role::CanaryManage],
        "canary_list" => &[Role::CanaryRead],
        "net_flows" | "net_listeners" | "net_resolve" | "net_fingerprint" => &[Role::NetRead],
        "trusted_installer_grant" => &[Role::TrustedInstaller],
        "detections" => &[Role::TelemetryRead],
        "detection_set_status" => &[Role::Triage],
        "config_overlay_set" => &[Role::ConfigManage],
        "response_status" => &[Role::AuditRead],
        "response_release" | "response_restore" | "remediate_ransomware" => &[Role::ResponseManage],
        // either read role (lab PR 213)
        "telemetry_status" => &[Role::AuditRead, Role::TelemetryRead],
        other => panic!("{other}: a signed verb without a designed role"),
    }
}

/// The distinct keys each signed verb needs by its design: the shutdown
/// the watchdog's quorum (`shutdown_marker::SHUTDOWN_QUORUM`, which it
/// verifies the marker by), rotate-keys 2 (§7.2), every other verb one.
fn designed_quorum(op: &str) -> usize {
    match op {
        "shutdown" => usize::from(SHUTDOWN_QUORUM),
        "rotate_keys_add" | "rotate_keys_revoke" => 2,
        _ => 1,
    }
}

/// Every role but the ones `op` needs and the ones that carry them
/// (`triage` carries `telemetry-read`): an admin.pub role list.
fn every_other_role(op: &str) -> String {
    let designed = designed_roles(op);
    EVERY_ROLE
        .iter()
        .filter(|r| !designed.contains(r))
        .filter(|r| !(**r == Role::Triage && designed.contains(&Role::TelemetryRead)))
        .map(|r| role_keyword(*r))
        .collect::<Vec<_>>()
        .join(",")
}

/// A verb's request signed by `signers`, on a connection of its own: its
/// reply and its row.
fn send_verb(
    fx: &Fixture,
    verb: &Verb,
    k: &Keys,
    signers: &[&SigningKey],
) -> (AdminMessage, AuditEntry) {
    let conn = ConnAuth::new(&fx.auth);
    let nonce = fx.challenge(&conn);
    let p = payload((verb.extra)(k), nonce, now_unix_secs(), AGENT_ID);
    let request = (verb.wrap)(p.clone(), signatures(&p, signers));
    let reply = fx.serve(&conn, &request);
    (reply, fx.rows().pop().expect("its row"))
}

/// Two keys outside `Keys`, for admin.pub files of a test's own.
fn spare_keys() -> [SigningKey; 2] {
    [
        SigningKey::from_bytes(&[0x61; 32]),
        SigningKey::from_bytes(&[0x62; 32]),
    ]
}

/// Lab PR 263's review, M-2: every verb is refused, `RoleDenied`, to
/// keys holding every role but the ones its design names (and their
/// carriers) — as many keys as its quorum. The rejection table's
/// `WrongRole` signs with keys holding one read role; a role swapped for
/// another (`response-manage` → `audit-read`, the role every key holds)
/// passed it.
#[test]
fn every_verb_refuses_the_keys_of_every_other_role() {
    let k = keys();
    let spare = spare_keys();
    for verb in verbs() {
        let roles = every_other_role(verb.op);
        let fx = Fixture::with_admin_pub(
            &[admin_line(&spare[0], &roles), admin_line(&spare[1], &roles)].concat(),
        );
        let signers: Vec<&SigningKey> = spare.iter().take(designed_quorum(verb.op)).collect();
        let (reply, row) = send_verb(&fx, &verb, &k, &signers);
        let what = format!("{} signed by keys of {roles}", verb.op);
        assert_eq!(
            reply,
            (verb.refused)(AdminResult::RoleDenied, true),
            "{what}"
        );
        assert_eq!(row.result, "failure: role_denied", "{what}");
        // the telemetry status names the key that tried (lab PR 213)
        let named = if verb.op == "telemetry_status" {
            fp(&spare[0])
        } else {
            String::new()
        };
        assert_eq!(row.key_fp, named, "{what}");
    }
}

/// Lab PR 263's review, M-2: keys of the default roles (`unlock,audit-read`,
/// an admin.pub line without roles — `install.sh`'s bootstrap key among
/// them) reach the unlock, the response status and the telemetry status,
/// by their design, and are refused every other verb.
#[test]
fn a_key_of_the_default_roles_does_what_they_allow_and_nothing_else() {
    const REACHED: [&str; 3] = ["unlock", "response_status", "telemetry_status"];
    let k = keys();
    let spare = spare_keys();
    for verb in verbs() {
        let fx = Fixture::with_admin_pub(
            &[admin_line(&spare[0], ""), admin_line(&spare[1], "")].concat(),
        );
        let signers: Vec<&SigningKey> = spare.iter().take(designed_quorum(verb.op)).collect();
        let (reply, row) = send_verb(&fx, &verb, &k, &signers);
        if REACHED.contains(&verb.op) {
            assert_ne!(result_of(&reply), AdminResult::RoleDenied, "{}", verb.op);
            assert_ne!(row.result, "failure: role_denied", "{}", verb.op);
            assert_eq!(row.key_fp, fp(&spare[0]), "{}: verified", verb.op);
        } else {
            assert_eq!(
                reply,
                (verb.refused)(AdminResult::RoleDenied, true),
                "{}",
                verb.op
            );
            assert_eq!(row.result, "failure: role_denied", "{}", verb.op);
        }
    }
}

/// Lab PR 263's review, M-2: the agent asks a shutdown for the quorum the
/// watchdog verifies its marker by (`shutdown_marker::SHUTDOWN_QUORUM`):
/// with one key less it signs no "success" and writes no marker. Both the
/// table and the expected refusal take the watchdog's constant, not a
/// number of the agent's own.
#[test]
fn the_shutdown_needs_the_quorum_the_watchdog_verifies() {
    assert_eq!(
        <ShutdownRequest as Signed>::RULE.quorum,
        Quorum::Of(SHUTDOWN_QUORUM)
    );
    let k = keys();
    let holders = [&k.a, &k.b];
    let quorum = usize::from(SHUTDOWN_QUORUM);
    assert!((2..=holders.len()).contains(&quorum), "{quorum}");
    let fx = Fixture::new(&k);
    let shutdown = OperationExtra::Shutdown(ShutdownExtra { grace_secs: 30 });
    let short = AdminResult::QuorumNotMet {
        required: SHUTDOWN_QUORUM,
        provided: SHUTDOWN_QUORUM - 1,
    };
    let (reply, row) = send(&fx, shutdown.clone(), &holders[..quorum - 1]);
    assert_eq!(reply, AdminMessage::ShutdownResult(short));
    assert_eq!(row.result, failure(&short));
    assert!(!fx.marker.exists(), "no marker for the watchdog");
    let (reply, row) = send(&fx, shutdown, &holders[..quorum]);
    assert_eq!(reply, AdminMessage::ShutdownResult(AdminResult::Success));
    assert_eq!(row.result, "success");
    assert!(fx.marker.exists(), "the marker for the watchdog");
}

/// Every role a key can hold is in `EVERY_ROLE` (or is `all`).
#[test]
fn every_role_is_in_the_role_tests() {
    for b in 0..=u8::MAX {
        if let Ok(role) = Role::try_from(b) {
            assert!(
                role == Role::All || EVERY_ROLE.contains(&role),
                "{role:?}: place it in EVERY_ROLE"
            );
        }
    }
}

// ── R11c (lab PR 264): `nn-admin policy set`, applied at once ─────────

/// R11c (lab PR 264): the per-rule policy is one handle the start makes
/// and gives the engine, the posture and the admin socket (it was the
/// process-wide `rule_policy::global()`, which `install_global` swapped).
/// A signed `config overlay set` of the policy — what `nn-admin policy set`
/// sends — through the pipeline a connection runs (`serve_request`) is in
/// force at once on each: the engine's next decision gives R020 its held
/// kill back, the executor runs that response (`process_event`'s way: the
/// decision's responses, or `Log` when there are none; an enforcing
/// executor on the test's paths, whose target is the test's own child), and
/// the posture's next judgement takes the ransomware directive (COMBAT
/// without corroboration). The handles are shared as `boot::run` shares them: the
/// engine's, the posture's clone of it and the admin socket's
/// (`AdminHandles`); the start's own wiring is the boot tests'
/// `the_start_shares_one_policy_handle`.
#[test]
fn a_signed_policy_set_applies_at_once_to_the_engine_the_posture_and_the_executor() {
    use crate::posture::{AuthSessionTracker, ExemptPids};
    use crate::response::{ExecutionOutcome, Executor, ExecutorConfig};
    use nn_model::{Event, ResponseAction};

    // The engine (the shipped lists, an empty `/proc`), its handle the
    // start's: the built-in defaults, R020's kill held.
    let proc = TempDir::new().unwrap();
    let lineage = AuthSessionTracker::new(proc.path());
    let engine = crate::decision::replay::engine(crate::decision::replay::HostParts {
        configs: Path::new(concat!(env!("NN_REPO_ROOT"), "/configs")),
        proc_root: proc.path(),
        lineage: lineage.clone(),
        ransom: Arc::new(crate::impact::RansomTracker::new(lineage.clone())),
        resolvers: Vec::new(),
        policy: crate::decision::rule_policy::RulePolicy::builtin(),
    });
    let rule_policy = engine.policy().clone();
    // The posture on the same handle, judging rewrites with ciphertext left
    // behind as the ransomware combination (lab PR 225).
    struct Cipher;
    impl crate::impact::entropy::Sampler for Cipher {
        fn sample(&self, _: &str, _: std::time::Duration) -> crate::impact::entropy::Sample {
            crate::impact::entropy::Sample {
                examined: 4,
                high: 4,
                containers: 0,
            }
        }
        fn sample_copies(
            &self,
            copy: &str,
            _: &str,
            since: std::time::Duration,
        ) -> crate::impact::entropy::Sample {
            self.sample(copy, since)
        }
    }
    let posture = PostureMachine::new_with_hooks_and_exempt_and_auth(
        Arc::new(|_| {}),
        Arc::new(|_, _| Ok(String::new())),
        ExemptPids::default(),
        AuthSessionTracker::new(proc.path()),
    )
    .with_rule_policy(rule_policy.clone());
    posture.set_ransom_tracker(Arc::new(crate::impact::RansomTracker::with(
        lineage.clone(),
        crate::impact::trust::ProgramOwners::new(proc.path().join("no-package-db")),
        Arc::new(Cipher),
    )));
    // Enforcing, on the test's paths: its kill cgroup is no cgroup (the tree
    // is killed process by process), its target the test's own child.
    let executor = Executor::with_config(ExecutorConfig {
        dry_run: false,
        ..ExecutorConfig::for_test(proc.path())
    });
    // The admin socket on the same handle.
    let mut fx = Fixture::new(&keys());
    fx.handles = AdminHandles {
        rule_policy: rule_policy.clone(),
    };

    // R020's reverse shell: the shell of a web server, stdio on a socket it
    // connected out; the response's target a real process of the test's
    // own, so a kill that ran shows.
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let reverse_shell = |pid: u32| {
        let mut e = crate::decision::rules::testutil::spawn_as(33, "bash", "/usr/bin/bash");
        if let Event::ProcessSpawn {
            pid: p,
            ppid,
            stdio,
            exe,
            ..
        } = &mut e
        {
            *p = pid;
            *ppid = pid - 1;
            exe.path = "/usr/bin/bash".into();
            stdio.own = nn_model::StdioSocket {
                read: true,
                inet_fds: 3,
                outbound: true,
                proto: 6,
                peer: Some("203.0.113.7:4444".parse().unwrap()),
            };
        }
        e
    };
    let target = child.id();
    // What `process_event` does with a decision: its responses, or `Log`.
    let respond = |e: &Event| {
        if let Event::ProcessSpawn {
            pid,
            ppid,
            uid,
            filename,
            argv,
            timestamp_ns,
            exe,
            start_ns,
            ..
        } = e
        {
            lineage.ingest_exec(
                *pid,
                *ppid,
                exe.path_or(filename),
                argv,
                *timestamp_ns,
                *start_ns,
                *uid,
            );
        }
        let d = engine.decide(e).expect("R020 matches");
        let outcomes: Vec<(ResponseAction, ExecutionOutcome)> = if d.responses.is_empty() {
            let r = executor.execute(ResponseAction::Log, target);
            vec![(r.action, r.primary)]
        } else {
            d.responses
                .iter()
                .map(|r| {
                    let report =
                        executor.execute_for_started(r.action.clone(), target, 0, 0, &r.filename);
                    (report.action, report.primary)
                })
                .collect()
        };
        (
            d.verdict.action.clone(),
            d.primary().applied.name(),
            outcomes,
        )
    };
    // A ransomware run of its own for each judgement: an actor the lineage
    // knows, its rewrites with ciphertext left behind.
    let ransomware = |pid: u32| {
        lineage.ingest_exec(
            pid,
            1,
            "/usr/bin/python3",
            &["python3".into(), "/srv/nn-malsim/ransom-sim.py".into()],
            1_000_000_000,
            1_000_000_000,
            1000,
        );
        Event::MassWrite {
            pid,
            uid: 1000,
            comm: "python3".into(),
            count: 20,
            filename: "/srv/nn-malsim/f020".into(),
            timestamp_ns: 50_000_000_000,
            overwrites: true,
            cgroup_window: false,
        }
    };

    // Before: the built-in defaults everywhere.
    let (action, applied, outcomes) = respond(&reverse_shell(7601));
    assert_eq!(action, ResponseAction::Log, "R020's kill held");
    assert_eq!(applied, "builtin");
    assert!(
        matches!(
            outcomes.as_slice(),
            [(ResponseAction::Log, ExecutionOutcome::Refused { reason, .. })]
                if reason.starts_with("Log action")
        ),
        "{outcomes:?}"
    );
    assert!(child.try_wait().unwrap().is_none(), "nothing ran");
    assert!(!posture.ransomware_combat_without_corroboration());
    let _ = posture.observe(&ransomware(300), &[]);
    assert_eq!(
        posture.current_kind(),
        PostureKind::Engaged,
        "the combination alone needs corroboration"
    );

    // `nn-admin policy set`: the signed overlay through the pipeline.
    let content = "# lab PR 264\nenforce R020\ncombat-without-corroboration NN-L-IMP-001\n";
    let k = keys();
    let conn = ConnAuth::new(&fx.auth);
    let nonce = fx.challenge(&conn);
    let p = payload(
        OperationExtra::ConfigOverlaySet(ConfigOverlaySetExtra {
            kind: OverlayKind::RulePolicy,
            sha256: Sha256::digest(content.as_bytes()).into(),
            len: content.len() as u32,
        }),
        nonce,
        now_unix_secs(),
        AGENT_ID,
    );
    let reply = fx.serve(
        &conn,
        &AdminMessage::ConfigOverlaySetRequest(ConfigOverlaySetRequest {
            signatures: signatures(&p, &[&k.a]),
            payload: p,
            content: content.to_string(),
        }),
    );
    let AdminMessage::ConfigOverlaySetResponse(r) = &reply else {
        panic!("{reply:?}");
    };
    assert_eq!(r.result, AdminResult::Success, "{r:?}");
    assert!(r.stored && r.message.contains("applied now"), "{r:?}");
    assert!(
        r.message.contains("replaces built-in"),
        "the handle's own previous policy: {r:?}"
    );

    // After, with nothing else done: the next event of each.
    let (action, applied, outcomes) = respond(&reverse_shell(7602));
    assert_eq!(
        action,
        ResponseAction::KillProcessTree,
        "R020's kill given back"
    );
    assert_eq!(applied, "enforce");
    assert_eq!(
        outcomes,
        vec![(
            ResponseAction::KillProcessTree,
            ExecutionOutcome::Killed { pid: target }
        )],
        "the executor runs the enforced kill"
    );
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(child.wait().unwrap().signal(), Some(libc::SIGKILL));
    assert!(posture.ransomware_combat_without_corroboration());
    let _ = posture.observe(&ransomware(301), &[]);
    assert_eq!(
        posture.current_kind(),
        PostureKind::Combat,
        "the combination alone is decisive under the directive"
    );
    assert!(!posture.is_combat_locked(), "never locked (POS-001)");
    // The handle is the start's, not a copy: the engine's reads it.
    assert!(!engine.policy().current().is_builtin());
}

/// The tables' golden files (the module doc).
const GOLDEN_DIR: &str = concat!(env!("NN_REPO_ROOT"), "/agent/tests/golden/admin/expected");

/// The variable `cargo xtask golden --update` sets, as for the decision
/// and posture replays.
const UPDATE_ENV: &str = "NN_GOLDEN_UPDATE";

/// `table` is the committed `<part>.txt`, byte for byte — or, with
/// `NN_GOLDEN_UPDATE=1` (never under CI), becomes it.
fn golden(part: &str, table: &str) {
    let path = Path::new(GOLDEN_DIR).join(format!("{part}.txt"));
    if std::env::var(UPDATE_ENV).is_ok_and(|v| v == "1") {
        assert!(
            std::env::var_os("CI").is_none(),
            "{UPDATE_ENV}=1 with CI set: the golden files are written by a maintainer \
             (`cargo xtask golden --update`) and reviewed, never by CI"
        );
        std::fs::create_dir_all(GOLDEN_DIR).unwrap();
        if std::fs::read_to_string(&path).ok().as_deref() != Some(table) {
            std::fs::write(&path, table).unwrap();
            eprintln!("golden: wrote {}", path.display());
        }
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{}: {e} — `cargo xtask golden --update` writes it",
            path.display()
        )
    });
    if committed != table {
        let first = committed
            .lines()
            .zip(table.lines())
            .position(|(a, b)| a != b)
            .unwrap_or_else(|| committed.lines().count().min(table.lines().count()));
        panic!(
            "{}: line {} moved\n  committed: {}\n  now:       {}\n\
             a reply or an audit row of the admin socket changed — if it is intended, \
             `cargo xtask golden --update` and say in the pull request why",
            path.display(),
            first + 1,
            committed.lines().nth(first).unwrap_or("<no line>"),
            table.lines().nth(first).unwrap_or("<no line>"),
        );
    }
}
