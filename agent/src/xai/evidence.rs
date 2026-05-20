//! Concrete Ed25519 realisation of the crypto-free
//! [`EvidenceSigner`](common::xai_types::EvidenceSigner) seam, plus
//! offline verification of an [`XaiEvidenceChain`].
//!
//! `common` is dependency-light (compiled into eBPF/CLI/C2), so it owns
//! only the schema + the byte-abstract seam; the `ed25519-dalek` math
//! lives in the agent — the same split `anti_tamper::admin_auth` uses for
//! the admin protocol. Signing/verification operate on
//! [`XaiEvidenceChain::canonical_bytes`], which excludes `signature` by
//! construction, so the artifact is verifiable exactly as produced.
//!
//! `verify_strict` (not `verify`) mirrors `admin_auth`: it is constant
//! time and rejects signature malleability / non-canonical encodings.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use common::xai_types::{EvidenceSigner, XaiEvidenceChain, XaiSignature};

/// Why offline verification of an [`XaiEvidenceChain`] failed.
#[derive(Debug, thiserror::Error)]
pub enum XaiVerifyError {
    /// `chain.signature` is `None` — nothing to verify.
    #[error("XAI evidence chain is unsigned")]
    Unsigned,
    /// `signer_pubkey` is not a valid Ed25519 point.
    #[error("XAI evidence signer public key is not a valid Ed25519 key")]
    BadPublicKey,
    /// Signature does not verify over the chain's canonical bytes.
    #[error("XAI evidence Ed25519 signature verification failed")]
    BadSignature,
}

/// Ed25519 signer over an evidence chain's canonical bytes.
///
/// Tappa 6.9 ships this for tests/dev with an ephemeral key; the real
/// customer-admin-key-chain signer is wired by Tappa 8/10.5 (it only has
/// to implement the same [`EvidenceSigner`] seam).
pub struct Ed25519EvidenceSigner {
    key: SigningKey,
}

impl Ed25519EvidenceSigner {
    pub fn new(key: SigningKey) -> Self {
        Self { key }
    }

    /// The verifying key embedded into every signature this signer makes.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }
}

impl EvidenceSigner for Ed25519EvidenceSigner {
    fn sign(&self, msg: &[u8]) -> XaiSignature {
        let sig: Signature = self.key.sign(msg);
        XaiSignature {
            sig: sig.to_bytes(),
            signer_pubkey: self.key.verifying_key().to_bytes(),
        }
    }
}

/// Verify a signed [`XaiEvidenceChain`] against the `signer_pubkey`
/// embedded in its own signature record, over its canonical bytes.
///
/// The embedded key is *not* a trust root — it identifies which key
/// signed; trust is established by the caller checking that key against
/// the customer admin key chain (Tappa 8/10.5 concern, not 6.9).
pub fn verify_evidence(chain: &XaiEvidenceChain) -> Result<(), XaiVerifyError> {
    let sig_rec = chain.signature.as_ref().ok_or(XaiVerifyError::Unsigned)?;
    let vk = VerifyingKey::from_bytes(&sig_rec.signer_pubkey)
        .map_err(|_| XaiVerifyError::BadPublicKey)?;
    let signature = Signature::from_bytes(&sig_rec.sig);
    vk.verify_strict(&chain.canonical_bytes(), &signature)
        .map_err(|_| XaiVerifyError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::ade_types::{AdeAction, AdeSeverity};
    use common::xai_types::{
        InferenceSettings, OcclusionMode, Refinement, Region, SaliencyDelta, SaliencyEntry,
        SaliencyWeights, ThreadMode, XaiBaselineVerdict, XaiInputSnapshot, XaiMethod, XaiModelRef,
        XaiStatus, XAI_BUDGET_MS, XAI_SCHEMA_VERSION,
    };
    use rand::rngs::OsRng;

    fn unsigned_chain() -> XaiEvidenceChain {
        XaiEvidenceChain {
            schema_version: XAI_SCHEMA_VERSION.to_string(),
            xai_trace_id: "11111111-1111-4111-8111-111111111111".to_string(),
            ade_trace_id: "22222222-2222-4222-8222-222222222222".to_string(),
            timestamp_utc: "2026-05-17T12:00:00Z".to_string(),
            model: XaiModelRef {
                model_id: "foundation-sec-8b-reasoning".to_string(),
                model_quantization: "Q4_K_M".to_string(),
                backend: "candle-llama3.1".to_string(),
            },
            method: XaiMethod {
                kind: "perturbation/occlusion".to_string(),
                weights: SaliencyWeights {
                    w_action: 0.6,
                    w_severity: 0.25,
                    w_confidence: 0.15,
                },
                max_units: 12,
                region_refine_threshold: 0.3,
                total_budget_ms: XAI_BUDGET_MS,
                occlusion_mode: OcclusionMode::Drop,
                inference_settings: InferenceSettings {
                    temperature: 0.0,
                    top_k: 1,
                    top_p: 1.0,
                    seed: 0,
                    thread_mode: ThreadMode::SingleThread,
                },
            },
            input_snapshot: XaiInputSnapshot {
                focal_event_json: r#"{"ProcessSpawn":{"pid":1337}}"#.to_string(),
                recent_events_json: "[]".to_string(),
                host_context_json: "{}".to_string(),
                prompt_sha256: "a".repeat(64),
            },
            environment_hash: "b".repeat(64),
            baseline_verdict: XaiBaselineVerdict {
                verdict: AdeAction::Kill,
                severity: AdeSeverity::Critical,
                confidence: 0.94,
            },
            saliency_map: vec![SaliencyEntry {
                region: Region::Correlated,
                unit_id: "correlated:3".to_string(),
                human_label: "prior DNS beacon to known C2".to_string(),
                score: 0.81,
                refinement: Refinement::Fine,
                delta: SaliencyDelta {
                    action_flip: 1.0,
                    severity_shift: 0.5,
                    confidence_delta: 0.53,
                },
                attention_score: None,
            }],
            saliency_coverage: 1.0,
            status: XaiStatus::Complete,
            signature: None,
        }
    }

    fn signer() -> Ed25519EvidenceSigner {
        Ed25519EvidenceSigner::new(SigningKey::generate(&mut OsRng))
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let mut c = unsigned_chain();
        c.sign_with(&signer());
        assert!(c.signature.is_some());
        verify_evidence(&c).expect("freshly signed chain must verify");
    }

    #[test]
    fn unsigned_chain_is_rejected() {
        let c = unsigned_chain();
        assert!(matches!(verify_evidence(&c), Err(XaiVerifyError::Unsigned)));
    }

    #[test]
    fn tampering_any_signed_field_breaks_verification() {
        let mut c = unsigned_chain();
        c.sign_with(&signer());
        verify_evidence(&c).unwrap();

        // Mutate a signed field AFTER signing → canonical bytes change →
        // the (unchanged) signature no longer verifies.
        c.baseline_verdict.confidence = 0.93;
        assert!(matches!(
            verify_evidence(&c),
            Err(XaiVerifyError::BadSignature)
        ));
    }

    #[test]
    fn signature_from_a_different_key_is_rejected() {
        let mut c = unsigned_chain();
        c.sign_with(&signer());
        // Overwrite only the embedded pubkey with an unrelated valid key:
        // signature no longer matches the (now different) claimed signer.
        let other = signer();
        if let Some(s) = c.signature.as_mut() {
            s.signer_pubkey = other.verifying_key().to_bytes();
        }
        assert!(matches!(
            verify_evidence(&c),
            Err(XaiVerifyError::BadSignature)
        ));
    }

    #[test]
    fn corrupt_pubkey_never_verifies() {
        // Security invariant: a garbled embedded signer key must NEVER
        // verify. Whether `0xFF..` fails Edwards-point decompression
        // (BadPublicKey) or decompresses to an unrelated point that the
        // signature doesn't match (BadSignature) is a curve-internal
        // detail; both are correct rejections, so assert the invariant,
        // not the variant (keeps the test deterministic).
        let mut c = unsigned_chain();
        c.sign_with(&signer());
        if let Some(s) = c.signature.as_mut() {
            s.signer_pubkey = [0xFFu8; 32];
        }
        assert!(verify_evidence(&c).is_err());
    }
}
