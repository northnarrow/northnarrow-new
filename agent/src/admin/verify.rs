//! The verification of a signed admin request (R11d, lab PR 263): one
//! pipeline for every signed verb, in place of the copy each handler
//! carried.
//!
//! A frame that does not decode never gets here (the transport's
//! `read_frame` closes the connection). A signed request reaches its
//! handler through [`signed`] alone, which verifies it on its connection
//! by its verb's [`Rule`] — in `ConnAuth::verify_signed_payload_quorum_keys`
//! (nn-linux's `admin_auth`), in this order:
//!
//! 1. the connection's failure budget (`RateLimited` once spent);
//! 2. the challenge this connection issued, consumed whatever the outcome
//!    (a request without one is `NoPendingChallenge`; a replayed request
//!    finds none, or another nonce);
//! 3. the payload's operation and its extra are the verb's
//!    (`admin_signed_payload::check_op`, `UnknownOperation`);
//! 4. at most eight signatures (`InvalidSignature`);
//! 5. the payload's nonce is the challenge (`InvalidSignature`);
//! 6. the payload's agent id is this install's (`AgentIdMismatch`);
//! 7. the payload's time within ±60 s of the server's clock: a captured
//!    request expires (`TimestampSkew`);
//! 8. each signature against the loaded keys over the digest of the
//!    canonical payload, the quorum of distinct keys and the roles
//!    (`InvalidSignature`, `QuorumNotMet`, `RoleDenied`).
//!
//! The connection counts 3, 4, 5, 6 and a submission no key signed; the
//! third is answered `RateLimited` and the connection closed. The handler
//! then receives a [`Verified`] request, which only this module can make,
//! with the signers' keys and fingerprints. The fingerprints go to the
//! audit row (`fps_out`), which the transport signs once the reply is
//! built, for an accepted and a refused request alike, with the op names
//! and fields of `audit::emit_audit_for`.
//!
//! The rules are one table ([`signed_verbs!`] below). Two are not "n
//! distinct keys, each listed role carried by one of them":
//! `rotate-keys add` needs one key while the one-key bootstrap is armed
//! ([`Quorum::Bootstrap`]), and `telemetry-status` takes either of two
//! read roles ([`Roles::AnyOf`]). No verb needs the trusted-installer
//! window open: the window lets an upgrade past the kernel's deny hooks,
//! it does not gate the admin plane; `trusted-installer-grant` is the verb
//! that opens it. The verbs without a signature (the challenge, the public
//! status, the loop's progress, the refused legacy unlock, a debug build's
//! posture trigger) are `handlers::dispatch`'s own arms.

use nn_proto::admin_protocol::{
    AdminResult, CanaryBurnRequest, CanaryDeployRequest, CanaryListRequest, CanaryRefreshRequest,
    ConfigOverlaySetRequest, DetectionSetStatusRequest, DetectionsRequest, FimBaselineRequest,
    FimReportRequest, FimStatusRequest, ForcePostureRequest, KeyedSignature, NetFingerprintRequest,
    NetFlowsRequest, NetListenersRequest, NetResolveRequest, RemediateRansomwareRequest,
    ResponseReleaseRequest, ResponseRestoreRequest, ResponseStatusRequest, RotateKeysAddRequest,
    RotateKeysRevokeRequest, ShutdownRequest, SignedUnlockRequest, TelemetryStatusRequest,
    TrustedInstallerGrantRequest,
};
use nn_proto::admin_quorum::{role_keyword, AdminKey};
use nn_proto::admin_signed_payload::{
    CanaryBurnExtra, CanaryDeployExtra, CanaryListExtra, CanaryRefreshExtra, ConfigOverlaySetExtra,
    DetectionSetStatusExtra, DetectionsExtra, FimBaselineExtra, FimReportExtra, FimStatusExtra,
    ForcePostureExtra, NetFingerprintExtra, NetFlowsExtra, NetListenersExtra, NetResolveExtra,
    OperationCode, OperationExtra, RemediateRansomwareExtra, ResponseReleaseExtra,
    ResponseRestoreExtra, ResponseStatusExtra, Role, RotateKeysAddExtra, RotateKeysRevokeExtra,
    ShutdownExtra, SignedPayload, TelemetryStatusExtra, TrustedInstallerGrantExtra, UnlockExtra,
};
use tracing::warn;

use crate::anti_tamper::admin_auth::{AdminAuthError, ConnAuth, VerifiedSigners};
use crate::anti_tamper::network_isolate::UnlockToken;

/// Read the current wall-clock as UNIX seconds for the
/// `verify_signed_payload_quorum` skew check. Production-only
/// helper; tests can call the verify path directly with an
/// injected `server_now_unix_secs` value.
pub(super) fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The distinct admin keys a verb needs (design §3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Quorum {
    /// This many distinct keys.
    Of(u8),
    /// BUG-013 (PHASE 15.1), external audit ATP-004: one key while the
    /// one-key bootstrap is armed, else this many — `rotate-keys add`
    /// only, so that the install's single key can add the second. The gate
    /// is read before the verify, since it decides the threshold
    /// ([`bootstrap_armed`]).
    Bootstrap(u8),
}

/// The roles a verb needs of the keys that signed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Roles {
    /// Each role carried by at least one matched key (the quorum rule,
    /// `admin_quorum::quorum_decision`; external audit AUT-007: one signer
    /// holding the role, the others any installed key).
    Each(&'static [Role]),
    /// At least one matched key carrying one of these roles. External
    /// audit ASK-009 (lab PR 213), the signed telemetry status: the
    /// `audit-read` every key carries by default (the bootstrap key of
    /// `install.sh` included) or the `telemetry-read` of a dashboard key
    /// (`triage` and `all` imply it) — the counters are no more than an
    /// `audit-read` key reads in the signed audit log. The quorum is
    /// verified without a role (it would want each listed role), these
    /// after it; a refusal names the signers in its audit row (that lot's
    /// decision: the row says which key tried).
    AnyOf(&'static [Role]),
}

/// One signed verb's verification: its operation, the keys it needs and
/// their roles, and its name in the journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Rule {
    pub(super) op: OperationCode,
    pub(super) quorum: Quorum,
    pub(super) roles: Roles,
    /// The verb in the journal line of a payload the signing layer cannot
    /// digest ([`map_admin_auth_error`]).
    pub(super) name: &'static str,
}

/// A signed request of the wire: a payload, its signatures, and the
/// extra its verb's payload carries.
pub(super) trait Signed {
    /// The payload's extra for this verb.
    type Extra;
    /// The verb's verification.
    const RULE: Rule;
    fn payload(&self) -> &SignedPayload;
    fn signatures(&self) -> &[KeyedSignature];
    /// The payload's extra when it is this verb's (the verify refuses any
    /// other before it hands the request on: `check_op`).
    fn extra(&self) -> Option<&Self::Extra>;
}

/// The table of the signed verbs: request, operation (and the extra of
/// the same name), quorum, roles, journal name.
macro_rules! signed_verbs {
    ($($request:ident: $op:ident($extra:ident), $quorum:expr, $roles:expr, $name:literal;)+) => {
        $(
            impl Signed for $request {
                type Extra = $extra;
                const RULE: Rule = Rule {
                    op: OperationCode::$op,
                    quorum: $quorum,
                    roles: $roles,
                    name: $name,
                };
                fn payload(&self) -> &SignedPayload {
                    &self.payload
                }
                fn signatures(&self) -> &[KeyedSignature] {
                    &self.signatures
                }
                fn extra(&self) -> Option<&$extra> {
                    match &self.payload.extra {
                        OperationExtra::$op(extra) => Some(extra),
                        _ => None,
                    }
                }
            }
        )+

        /// Every signed verb's rule, in the table's order (the table test).
        #[cfg(test)]
        pub(super) const RULES: &[(&str, Rule)] = &[
            $((stringify!($request), <$request as Signed>::RULE)),+
        ];
    };
}

signed_verbs! {
    // Design §3.3: the release of COMBAT, 1-of-N (lab PR 217).
    SignedUnlockRequest: Unlock(UnlockExtra),
        Quorum::Of(1), Roles::Each(&[Role::Unlock]), "unlock";
    // §3.3, §10.3: 2-of-N, one signer holding `shutdown`.
    ShutdownRequest: Shutdown(ShutdownExtra),
        Quorum::Of(2), Roles::Each(&[Role::Shutdown]), "shutdown";
    // §3.3: 1-of-N; out of COMBAT also a signer holding `unlock`, which
    // the posture checks under its lock (external audit NN-AUD-083).
    ForcePostureRequest: ForcePosture(ForcePostureExtra),
        Quorum::Of(1), Roles::Each(&[Role::ForcePosture]), "force-posture";
    // §7.2: 2-of-N (1 while the one-key bootstrap is armed); the new key's
    // roles within the signers' (NN-AUD-084), checked by the handler.
    RotateKeysAddRequest: RotateKeysAdd(RotateKeysAddExtra),
        Quorum::Bootstrap(2), Roles::Each(&[Role::RotateKeys]), "rotate-keys-add";
    RotateKeysRevokeRequest: RotateKeysRevoke(RotateKeysRevokeExtra),
        Quorum::Of(2), Roles::Each(&[Role::RotateKeys]), "rotate-keys-revoke";
    // FIM design §13 Q6: 1-of-N, a workflow gate.
    FimBaselineRequest: FimBaseline(FimBaselineExtra),
        Quorum::Of(1), Roles::Each(&[Role::FimManage]), "fim-baseline";
    FimReportRequest: FimReport(FimReportExtra),
        Quorum::Of(1), Roles::Each(&[Role::FimRead]), "fim-report";
    FimStatusRequest: FimStatus(FimStatusExtra),
        Quorum::Of(1), Roles::Each(&[Role::FimRead]), "fim-status";
    // Deception design §12 Q7: manage and read split.
    CanaryDeployRequest: CanaryDeploy(CanaryDeployExtra),
        Quorum::Of(1), Roles::Each(&[Role::CanaryManage]), "canary-deploy";
    CanaryListRequest: CanaryList(CanaryListExtra),
        Quorum::Of(1), Roles::Each(&[Role::CanaryRead]), "canary-list";
    CanaryBurnRequest: CanaryBurn(CanaryBurnExtra),
        Quorum::Of(1), Roles::Each(&[Role::CanaryManage]), "canary-burn";
    CanaryRefreshRequest: CanaryRefresh(CanaryRefreshExtra),
        Quorum::Of(1), Roles::Each(&[Role::CanaryManage]), "canary-refresh";
    NetFlowsRequest: NetFlows(NetFlowsExtra),
        Quorum::Of(1), Roles::Each(&[Role::NetRead]), "net-flows";
    NetListenersRequest: NetListeners(NetListenersExtra),
        Quorum::Of(1), Roles::Each(&[Role::NetRead]), "net-listeners";
    NetResolveRequest: NetResolve(NetResolveExtra),
        Quorum::Of(1), Roles::Each(&[Role::NetRead]), "net-resolve";
    NetFingerprintRequest: NetFingerprint(NetFingerprintExtra),
        Quorum::Of(1), Roles::Each(&[Role::NetRead]), "net-fingerprint";
    // FIM-009 (§15.1): 1-of-N today, like COMBAT's release; raise the
    // quorum here to require co-signers.
    TrustedInstallerGrantRequest: TrustedInstallerGrant(TrustedInstallerGrantExtra),
        Quorum::Of(1), Roles::Each(&[Role::TrustedInstaller]), "trusted-installer-grant";
    // Tappa 9.0.b: read != control; `triage` and `all` imply the role.
    DetectionsRequest: Detections(DetectionsExtra),
        Quorum::Of(1), Roles::Each(&[Role::TelemetryRead]), "detections";
    // Tappa 9.0.c: one triage operator.
    DetectionSetStatusRequest: DetectionSetStatus(DetectionSetStatusExtra),
        Quorum::Of(1), Roles::Each(&[Role::Triage]), "detection_set_status";
    // Tappa 10.8: 1-of-N.
    ConfigOverlaySetRequest: ConfigOverlaySet(ConfigOverlaySetExtra),
        Quorum::Of(1), Roles::Each(&[Role::ConfigManage]), "config-overlay-set";
    // External audit CMB-016: the status with the role every key holds,
    // the undoing with `response-manage`.
    ResponseStatusRequest: ResponseStatus(ResponseStatusExtra),
        Quorum::Of(1), Roles::Each(&[Role::AuditRead]), "response-status";
    ResponseReleaseRequest: ResponseRelease(ResponseReleaseExtra),
        Quorum::Of(1), Roles::Each(&[Role::ResponseManage]), "response-release";
    ResponseRestoreRequest: ResponseRestore(ResponseRestoreExtra),
        Quorum::Of(1), Roles::Each(&[Role::ResponseManage]), "response-restore";
    // External audit ASK-009 (lab PR 213): either read role.
    TelemetryStatusRequest: TelemetryStatus(TelemetryStatusExtra),
        Quorum::Of(1), Roles::AnyOf(&[Role::AuditRead, Role::TelemetryRead]), "telemetry-status";
    // Lab PR 222: `response-manage`, a restore can put malware back.
    RemediateRansomwareRequest: RemediateRansomware(RemediateRansomwareExtra),
        Quorum::Of(1), Roles::Each(&[Role::ResponseManage]), "remediate-ransomware";
}

/// A signed request [`signed`] verified by its verb's [`Rule`]. Only this
/// module makes one (its fields are private), so a handler that takes one
/// runs on a verified request alone. It carries what the verify read under
/// one lock of the key set: the capability token, the matched keys and
/// their fingerprints.
pub(super) struct Verified<'a, R: Signed> {
    request: &'a R,
    extra: &'a R::Extra,
    signers: VerifiedSigners,
    server_now: u64,
    bootstrap: bool,
}

impl<'a, R: Signed> Verified<'a, R> {
    /// The request, as verified.
    pub(super) fn request(&self) -> &'a R {
        self.request
    }

    /// The payload's extra, its verb's.
    pub(super) fn extra(&self) -> &'a R::Extra {
        self.extra
    }

    /// The matched keys' fingerprints in admin.pub's order: the audit
    /// row's `key_fp`, then its cosigners (PHASE_D_004).
    pub(super) fn fingerprints(&self) -> &[String] {
        &self.signers.fingerprints
    }

    /// The first matched key's fingerprint (the row's `key_fp`).
    pub(super) fn signer_fp(&self) -> &str {
        self.signers
            .fingerprints
            .first()
            .map(String::as_str)
            .unwrap_or("")
    }

    /// The matched keys with their roles, read under the same lock as the
    /// signatures (external audit NN-AUD-083 / NN-AUD-084: what an
    /// operation does is confined to what its signers hold).
    pub(super) fn keys(&self) -> &[AdminKey] {
        &self.signers.keys
    }

    /// The server's clock the skew window was judged on.
    pub(super) fn server_now(&self) -> u64 {
        self.server_now
    }

    /// Whether the one-key bootstrap relaxed the quorum
    /// ([`Quorum::Bootstrap`]).
    pub(super) fn bootstrap_armed(&self) -> bool {
        self.bootstrap
    }

    /// The capability token the verify minted.
    pub(super) fn into_token(self) -> UnlockToken {
        self.signers.token
    }
}

/// A refusal of [`verify`]: the answer, and the fingerprints its audit row
/// names — none, but the signers of a request verified and then refused
/// for its roles ([`Roles::AnyOf`]).
struct Refusal {
    result: AdminResult,
    signers: Vec<String>,
}

/// The one way a signed request reaches its handler: verified on its
/// connection by its verb's [`Rule`] (the module doc), its signers'
/// fingerprints written to `fps_out` for the audit row, then `handle` with
/// the [`Verified`] request — or `refuse` with the answer of a refusal.
pub(super) fn signed<'a, R: Signed, T>(
    request: &'a R,
    auth: &ConnAuth<'_>,
    fps_out: &mut Vec<String>,
    refuse: impl FnOnce(AdminResult) -> T,
    handle: impl FnOnce(Verified<'a, R>) -> T,
) -> T {
    match verify(request, auth, now_unix_secs()) {
        Ok(verified) => {
            *fps_out = verified.signers.fingerprints.clone();
            handle(verified)
        }
        Err(refusal) => {
            *fps_out = refusal.signers;
            refuse(refusal.result)
        }
    }
}

fn verify<'a, R: Signed>(
    request: &'a R,
    auth: &ConnAuth<'_>,
    server_now: u64,
) -> Result<Verified<'a, R>, Refusal> {
    let rule = R::RULE;
    let (min_distinct, bootstrap) = match rule.quorum {
        Quorum::Of(n) => (n, false),
        Quorum::Bootstrap(n) => {
            let armed = bootstrap_armed(auth);
            (if armed { 1 } else { n }, armed)
        }
    };
    let each: &[Role] = match rule.roles {
        Roles::Each(roles) => roles,
        Roles::AnyOf(_) => &[],
    };
    let signatures: Vec<[u8; 64]> = request.signatures().iter().map(|s| s.signature).collect();
    let signers = auth
        .verify_signed_payload_quorum_keys(
            request.payload(),
            &signatures,
            min_distinct,
            each,
            rule.op,
            server_now,
        )
        .map_err(|e| Refusal {
            result: map_admin_auth_error(e, rule.name),
            signers: Vec::new(),
        })?;
    if let Roles::AnyOf(any) = rule.roles {
        if !signers
            .keys
            .iter()
            .any(|k| any.iter().any(|r| k.authorizes(*r)))
        {
            let required: Vec<&str> = any.iter().map(|r| role_keyword(*r)).collect();
            warn!(
                target: "anti_tamper.admin_auth.verify_failure",
                reason = "role_denied",
                required = %required.join(" or "),
                "{} refused: no signer holds any of its roles",
                rule.name
            );
            return Err(Refusal {
                result: AdminResult::RoleDenied,
                signers: signers.fingerprints,
            });
        }
    }
    // The verify's `check_op` refused a payload whose extra is not its
    // operation's (external audit AUT-001): not reached, and refused if it
    // ever were, as the handlers' own checks did.
    let Some(extra) = request.extra() else {
        warn!(
            op = ?rule.op,
            extra = ?request.payload().extra.op_code(),
            "{} payload extra is not its verb's after the verify — refused",
            rule.name
        );
        return Err(Refusal {
            result: AdminResult::UnknownOperation,
            signers: signers.fingerprints,
        });
    };
    Ok(Verified {
        request,
        extra,
        signers,
        server_now,
        bootstrap,
    })
}

/// BUG-013 (PHASE 15.1): the bootstrap-mode 1-of-N gate of
/// `rotate-keys add`, consulted BEFORE the verify so the relaxed
/// `min_distinct` (1) goes into it. The gate is evaluated against the key
/// set in memory (one key), the signed chain (no second key ever added)
/// and the sentinel + nonce on disk; ALL must hold, and any other outcome
/// falls through to the permanent 2-of-N path. See
/// `crate::anti_tamper::bootstrap` for the full security argument.
fn bootstrap_armed(auth: &ConnAuth<'_>) -> bool {
    match auth.config_path() {
        Some(admin_pub_path) => {
            let paths = crate::anti_tamper::bootstrap::BootstrapPaths::default_paths(
                admin_pub_path.to_path_buf(),
            );
            // External audit ATP-004: the keys in memory, and the
            // consumption recorded in the signed chain.
            matches!(
                crate::anti_tamper::bootstrap::evaluate_loaded(
                    &paths,
                    &auth.loaded_admin_pub(),
                    auth.bootstrap_consumed(),
                ),
                crate::anti_tamper::bootstrap::BootstrapGate::Armed
            )
        }
        // In-memory test builders have no config_path; bootstrap
        // gate is structurally inapplicable. Fall through to the
        // existing 2-of-N path.
        None => false,
    }
}

/// Shared mapper from [`AdminAuthError`] to the wire
/// [`AdminResult`]. Identical to the inline matches in
/// dispatch_shutdown / dispatch_force_posture; factored out by
/// A13 because dispatch_rotate_keys_add / _revoke would
/// duplicate the same 11-arm match otherwise.
pub(super) fn map_admin_auth_error(e: AdminAuthError, op_for_log: &str) -> AdminResult {
    match e {
        AdminAuthError::NoPendingChallenge => AdminResult::NoPendingChallenge,
        AdminAuthError::NonceMismatch => AdminResult::InvalidSignature,
        AdminAuthError::UnknownOperation { .. } => AdminResult::UnknownOperation,
        AdminAuthError::AgentIdMismatch => AdminResult::AgentIdMismatch,
        AdminAuthError::TimestampSkew {
            server_ts,
            max_skew_secs,
        } => AdminResult::TimestampSkew {
            server_ts,
            max_skew_secs,
        },
        AdminAuthError::InvalidSignature => AdminResult::InvalidSignature,
        AdminAuthError::QuorumNotMet { required, provided } => {
            AdminResult::QuorumNotMet { required, provided }
        }
        AdminAuthError::RoleDenied { .. } => AdminResult::RoleDenied,
        AdminAuthError::RateLimited { retry_after_secs } => {
            AdminResult::RateLimited { retry_after_secs }
        }
        // External audit AUT-005: no wire variant of its own; the journal
        // line of the verify names it.
        AdminAuthError::TooManySignatures { .. } => AdminResult::InvalidSignature,
        AdminAuthError::PayloadVerify(pe) => {
            warn!(op = op_for_log, error = ?pe, "payload verify failed at common layer");
            AdminResult::InvalidSignature
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rule of every signed verb, as its design sets it — TAPPA8 §3.3
    /// and §4 (unlock, shutdown, force-posture, rotate-keys), FIM §13 Q6,
    /// the deception layer's §12 Q7, Tappa 9.0.b/c, 10 N7, 10.8, FIM-009,
    /// CMB-016, ASK-009 (lab PR 213), lab PR 222. A change here changes
    /// who may do what: it changes this list too, on purpose.
    #[test]
    fn every_signed_verb_has_its_designed_rule() {
        use Role::*;
        let want: &[(&str, OperationCode, Quorum, Roles)] = &[
            (
                "SignedUnlockRequest",
                OperationCode::Unlock,
                Quorum::Of(1),
                Roles::Each(&[Unlock]),
            ),
            (
                "ShutdownRequest",
                OperationCode::Shutdown,
                Quorum::Of(2),
                Roles::Each(&[Shutdown]),
            ),
            (
                "ForcePostureRequest",
                OperationCode::ForcePosture,
                Quorum::Of(1),
                Roles::Each(&[ForcePosture]),
            ),
            (
                "RotateKeysAddRequest",
                OperationCode::RotateKeysAdd,
                Quorum::Bootstrap(2),
                Roles::Each(&[RotateKeys]),
            ),
            (
                "RotateKeysRevokeRequest",
                OperationCode::RotateKeysRevoke,
                Quorum::Of(2),
                Roles::Each(&[RotateKeys]),
            ),
            (
                "FimBaselineRequest",
                OperationCode::FimBaseline,
                Quorum::Of(1),
                Roles::Each(&[FimManage]),
            ),
            (
                "FimReportRequest",
                OperationCode::FimReport,
                Quorum::Of(1),
                Roles::Each(&[FimRead]),
            ),
            (
                "FimStatusRequest",
                OperationCode::FimStatus,
                Quorum::Of(1),
                Roles::Each(&[FimRead]),
            ),
            (
                "CanaryDeployRequest",
                OperationCode::CanaryDeploy,
                Quorum::Of(1),
                Roles::Each(&[CanaryManage]),
            ),
            (
                "CanaryListRequest",
                OperationCode::CanaryList,
                Quorum::Of(1),
                Roles::Each(&[CanaryRead]),
            ),
            (
                "CanaryBurnRequest",
                OperationCode::CanaryBurn,
                Quorum::Of(1),
                Roles::Each(&[CanaryManage]),
            ),
            (
                "CanaryRefreshRequest",
                OperationCode::CanaryRefresh,
                Quorum::Of(1),
                Roles::Each(&[CanaryManage]),
            ),
            (
                "NetFlowsRequest",
                OperationCode::NetFlows,
                Quorum::Of(1),
                Roles::Each(&[NetRead]),
            ),
            (
                "NetListenersRequest",
                OperationCode::NetListeners,
                Quorum::Of(1),
                Roles::Each(&[NetRead]),
            ),
            (
                "NetResolveRequest",
                OperationCode::NetResolve,
                Quorum::Of(1),
                Roles::Each(&[NetRead]),
            ),
            (
                "NetFingerprintRequest",
                OperationCode::NetFingerprint,
                Quorum::Of(1),
                Roles::Each(&[NetRead]),
            ),
            (
                "TrustedInstallerGrantRequest",
                OperationCode::TrustedInstallerGrant,
                Quorum::Of(1),
                Roles::Each(&[TrustedInstaller]),
            ),
            (
                "DetectionsRequest",
                OperationCode::Detections,
                Quorum::Of(1),
                Roles::Each(&[TelemetryRead]),
            ),
            (
                "DetectionSetStatusRequest",
                OperationCode::DetectionSetStatus,
                Quorum::Of(1),
                Roles::Each(&[Triage]),
            ),
            (
                "ConfigOverlaySetRequest",
                OperationCode::ConfigOverlaySet,
                Quorum::Of(1),
                Roles::Each(&[ConfigManage]),
            ),
            (
                "ResponseStatusRequest",
                OperationCode::ResponseStatus,
                Quorum::Of(1),
                Roles::Each(&[AuditRead]),
            ),
            (
                "ResponseReleaseRequest",
                OperationCode::ResponseRelease,
                Quorum::Of(1),
                Roles::Each(&[ResponseManage]),
            ),
            (
                "ResponseRestoreRequest",
                OperationCode::ResponseRestore,
                Quorum::Of(1),
                Roles::Each(&[ResponseManage]),
            ),
            (
                "TelemetryStatusRequest",
                OperationCode::TelemetryStatus,
                Quorum::Of(1),
                Roles::AnyOf(&[AuditRead, TelemetryRead]),
            ),
            (
                "RemediateRansomwareRequest",
                OperationCode::RemediateRansomware,
                Quorum::Of(1),
                Roles::Each(&[ResponseManage]),
            ),
        ];
        assert_eq!(RULES.len(), want.len());
        for ((name, rule), (wname, op, quorum, roles)) in RULES.iter().zip(want) {
            assert_eq!(name, wname);
            assert_eq!(rule.op, *op, "{name}");
            assert_eq!(rule.quorum, *quorum, "{name}");
            assert_eq!(rule.roles, *roles, "{name}");
        }
    }

    /// Every operation a payload can name has exactly one verb on the
    /// socket — but `audit-read`, which nn-admin performs on the file, not
    /// through the agent (no request carries it: a payload naming it is
    /// refused by every verb's `check_op`).
    #[test]
    fn every_operation_but_audit_read_has_one_rule() {
        let ops: Vec<OperationCode> = (0..=u8::MAX)
            .filter_map(|b| OperationCode::try_from(b).ok())
            .collect();
        assert!(ops.len() >= 26, "{ops:?}");
        for op in ops {
            let rules = RULES.iter().filter(|(_, r)| r.op == op).count();
            let want = usize::from(op != OperationCode::AuditRead);
            assert_eq!(rules, want, "{op:?}");
        }
        // a quorum of 0 would accept no signature: none is (the verify
        // also refuses one, `admin_quorum::quorum_decision`)
        for (name, rule) in RULES {
            match rule.quorum {
                Quorum::Of(n) | Quorum::Bootstrap(n) => assert!(n >= 1, "{name}"),
            }
            match rule.roles {
                Roles::Each(r) | Roles::AnyOf(r) => assert!(!r.is_empty(), "{name}: a role"),
            }
        }
    }
}
