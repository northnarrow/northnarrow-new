//! Tappa 6.9 — XAI Saliency Mapping forensic evidence schema (v1.0.0).
//!
//! This is the EU AI Act **Article 13** forensic artifact bound to every
//! (future, Tappa 10.5) synthesized rule: it records *which semantic input
//! units drove an ADE decision*, under fully deterministic inference
//! settings, in a form an external auditor can byte-reproduce years later.
//! See `docs/TAPPA6_9_XAI_PLAN.md` (P0.1, locked) for the design; §4 there
//! maps every field below to its Article-13 clause.
//!
//! ## Crate-boundary discipline (why this file is crypto-free)
//!
//! `common` is dependency-light by charter (it is compiled into the eBPF
//! program, the CLI and the future C2 backend). The signing **seam** lives
//! here as the byte-abstract [`EvidenceSigner`] trait + the raw-bytes
//! [`XaiSignature`] record; the concrete Ed25519 signer/verifier (which
//! needs `ed25519-dalek`) lives in `agent/src/xai/evidence.rs`, exactly as
//! `common::wire` carries a raw `[u8; 64]` admin signature while
//! `agent::anti_tamper::admin_auth` owns the curve math. No crypto crate is
//! pulled into `common`.
//!
//! ## Canonical bytes contract (the signed form)
//!
//! [`XaiEvidenceChain::canonical_bytes`] is a **hand-rolled, versioned,
//! length-prefixed, field-ordered, signature-excluded** encoding — NOT
//! `serde_json`. A regulatory signature must be reproducible bit-for-bit
//! independent of any serialization-library version; JSON float/whitespace
//! formatting is not a stable contract, a domain-separated binary encoding
//! is. The encoding is specified in [`XaiEvidenceChain::canonical_bytes`]
//! precisely enough for an auditor to re-derive it from this comment alone.
//! The serde derives below exist only for the stored/transmitted JSON
//! artifact and round-trip tests, never for what gets signed.

use alloc::string::String;
use alloc::vec::Vec;

#[cfg(test)]
use alloc::string::ToString;

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::ade_types::{AdeAction, AdeSeverity};

/// Schema version embedded in every XAI evidence chain. Bump on any
/// breaking change to the *schema*; the canonical *encoding* version is
/// independent (see [`CANON_DOMAIN`]).
pub const XAI_SCHEMA_VERSION: &str = "1.0.0";

/// Fail-closed XAI compute ceiling, in milliseconds (gating question Q2:
/// FIXED, deliberately NOT derived from `AdeConfig.timeout`).
///
/// Rationale: synthesis is hard-capped at ≤5 rules / 60 s; the
/// coarse-to-fine bounded-K path is ~16–19 model inferences worst case
/// at ~5 s/inference on the 8B-Q4_K_M CPU path ⇒ ~80–95 s. 90 s is that
/// envelope plus margin. Exceeding it returns `XaiUnavailable` ⇒
/// synthesis refuses the rule (regulatory fail-closed — an unexplained
/// rule must never deploy). Deriving this from another config would
/// create hidden coupling that harms regulatory predictability. Future
/// changes: a dedicated commit with a written rationale, never a
/// runtime computation.
pub const XAI_BUDGET_MS: u64 = 90_000;

/// Domain-separation prefix for [`XaiEvidenceChain::canonical_bytes`]. A
/// signature over an XAI chain can therefore never be replayed as a
/// signature over any other NorthNarrow artifact. The trailing `-v1`
/// versions the *encoding*; bump it (and only it) if the byte layout
/// below ever changes, so old signatures remain verifiable under the
/// encoding version they were produced with.
const CANON_DOMAIN: &[u8] = b"NN-XAI-EVIDENCE-CANON-v1\0";

// ───────────────────────── schema ─────────────────────────

/// Top-level Article-13 forensic evidence chain for one XAI explanation.
///
/// Field order here is normative: it is exactly the order
/// [`Self::canonical_bytes`] serializes (minus `signature`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct XaiEvidenceChain {
    pub schema_version: String,
    pub xai_trace_id: String,
    /// FK → `AdeVerdict.trace_id` of the explained decision.
    pub ade_trace_id: String,
    pub timestamp_utc: String,
    pub model: XaiModelRef,
    pub method: XaiMethod,
    pub input_snapshot: XaiInputSnapshot,
    /// Deployment identity hash. Computed at AdeEngine init and cached;
    /// embedded into every chain produced under this binary+model+rules+host.
    ///
    /// ```text
    /// environment_hash = lower_hex(sha256(
    ///     agent_binary_sha256_bytes ||
    ///     model_file_sha256_bytes ||
    ///     combat_rules_sha256_bytes ||
    ///     hostname_canonical_utf8 ||      // `hostname --fqdn` w/ hostname fallback
    ///     agent_build_commit_sha_utf8     // BUILD_SHA env at compile time
    /// ))
    /// ```
    ///
    /// 64 lower-case hex chars. Forward-compat: Tappa 14.x TEE attestation
    /// may evolve the inputs while preserving this field name; schema
    /// versioning handles the transition.
    pub environment_hash: String,
    pub baseline_verdict: XaiBaselineVerdict,
    pub saliency_map: Vec<SaliencyEntry>,
    /// Honesty field: fraction of perturbable units explained at unit
    /// granularity. Computed as:
    ///
    /// ```text
    /// saliency_coverage = units_with_refinement_eq_fine / units_total
    /// ```
    ///
    /// Range [0.0, 1.0]. A value < 1.0 means some regions were reported at
    /// block granularity (refinement: coarse) due to coarse-to-fine pruning
    /// or bounded-K capping with tail aggregation. The auditor MUST never
    /// assume finer attribution than this fraction admits.
    pub saliency_coverage: f64,
    pub status: XaiStatus,
    /// Ed25519 over `canonical_bytes()`. Structurally separate so it can
    /// never feed back into the signed bytes. `None` until signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<XaiSignature>,
}

/// Model identity (mirrors the relevant `AdeMetadata` fields).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct XaiModelRef {
    pub model_id: String,
    pub model_quantization: String,
    pub backend: String,
}

/// The saliency method + every parameter needed to reproduce the map.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct XaiMethod {
    /// Always `"perturbation/occlusion"` in v1.
    pub kind: String,
    pub weights: SaliencyWeights,
    pub max_units: u32,
    pub region_refine_threshold: f64,
    /// = [`XAI_BUDGET_MS`] at production time (recorded so an auditor sees
    /// the ceiling that was in force, even if the const later changes).
    pub total_budget_ms: u64,
    pub occlusion_mode: OcclusionMode,
    pub inference_settings: InferenceSettings,
}

/// Decision-delta scoring weights (sum need not be 1; recorded verbatim).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct SaliencyWeights {
    pub w_action: f64,
    pub w_severity: f64,
    pub w_confidence: f64,
}

/// How a perturbable unit is neutralised (gating question Q1: default
/// `Drop` — the legal "but-for" counterfactual).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OcclusionMode {
    /// Remove the unit entirely ("what if this had not happened").
    Drop,
    /// Replace with a typed neutral sentinel, preserving slot/position
    /// (use only when positional encoding is the analysis target).
    AnonymiseInPlace,
}

/// Deterministic-decoding settings (refinement R1). Recorded so the
/// explanation is bit-reproducible; production ADE may differ.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct InferenceSettings {
    pub temperature: f64,
    pub top_k: u32,
    pub top_p: f64,
    /// Recorded even though greedy ignores it (future sampling methods).
    pub seed: u64,
    pub thread_mode: ThreadMode,
}

/// CPU-kernel reduction mode. Multi-thread float reduction is
/// non-associative ⇒ non-reproducible, so the XAI path forbids it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreadMode {
    SingleThread,
    DeterministicReduce,
}

/// The exact (anonymised) inputs that were explained, captured as the
/// serialized text the agent produced — decoupled from evolving `Event`
/// internals, and what `prompt_sha256` is taken over.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct XaiInputSnapshot {
    pub focal_event_json: String,
    pub recent_events_json: String,
    pub host_context_json: String,
    /// Lower-case hex SHA-256 of the fully-assembled, sanitised prompt.
    pub prompt_sha256: String,
}

/// The baseline verdict `V0` the saliency map is computed against.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct XaiBaselineVerdict {
    pub verdict: AdeAction,
    pub severity: AdeSeverity,
    pub confidence: f64,
}

/// One ranked entry of the saliency map.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SaliencyEntry {
    pub region: Region,
    /// Stable id within the region (e.g. `"correlated:3"`, `"tail:N=7"`).
    pub unit_id: String,
    /// Human-auditable label for the Article-13 dossier.
    pub human_label: String,
    pub score: f64,
    pub refinement: Refinement,
    pub delta: SaliencyDelta,
    /// Reserved for the future hybrid attention seam (§7). Always `None`
    /// in v1; present in the schema so adding it is non-breaking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attention_score: Option<f64>,
}

/// Which input region a unit belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Region {
    Focal,
    Correlated,
    Host,
}

/// Whether a unit's attribution was computed at unit granularity or only
/// reported at block granularity (honesty marker — never imply finer
/// attribution than was computed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Refinement {
    Fine,
    Coarse,
}

/// The raw decision-delta components behind a unit's `score`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct SaliencyDelta {
    /// `1.0` if the verdict action changed when the unit was occluded.
    pub action_flip: f64,
    /// Normalised ordinal severity distance.
    pub severity_shift: f64,
    /// `|confidence(Vu) - confidence(V0)|`.
    pub confidence_delta: f64,
}

/// Completion status — never silent. `Degraded` carries the reason so the
/// dossier explains *why* coverage is partial.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum XaiStatus {
    Complete,
    Degraded(String),
}

/// Detached signature record (raw bytes; curve math lives in the agent).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XaiSignature {
    /// Ed25519 signature over [`XaiEvidenceChain::canonical_bytes`].
    #[serde(with = "BigArray")]
    pub sig: [u8; 64],
    /// Ed25519 verifying key, so the console/auditor can verify offline.
    pub signer_pubkey: [u8; 32],
}

// ───────────────────────── signer seam ─────────────────────────

/// Byte-abstract signing seam. The concrete Ed25519 implementation lives
/// in `agent/src/xai/evidence.rs` (keeps `common` crypto-free). `msg` is
/// ALWAYS the output of [`XaiEvidenceChain::canonical_bytes`].
pub trait EvidenceSigner {
    fn sign(&self, msg: &[u8]) -> XaiSignature;
}

// ───────────────────────── canonical encoding ─────────────────────────

/// Deterministic byte writer for the signed canonical form.
///
/// Rules (stable forever under a given [`CANON_DOMAIN`] version):
/// * strings  → `u32` big-endian byte length, then UTF-8 bytes
/// * `u32`/`u64` → fixed big-endian
/// * `f64`    → IEEE-754 bits, big-endian (exact; no text formatting); a
///   non-finite value is canonicalised to a fixed quiet-NaN bit pattern
///   (saliency values are finite by construction — this is defence in
///   depth, recorded here so the auditor knows the rule)
/// * enums    → their `&'static str` canonical tag, written as a string
/// * `Vec<T>` → `u32` big-endian count, then each element in order
/// * `Option` → one byte `0`/`1`, then the value if present
struct Canon {
    buf: Vec<u8>,
}

impl Canon {
    fn new() -> Self {
        let mut buf = Vec::with_capacity(512);
        buf.extend_from_slice(CANON_DOMAIN);
        Self { buf }
    }
    fn str(&mut self, s: &str) {
        self.buf
            .extend_from_slice(&(s.len() as u32).to_be_bytes());
        self.buf.extend_from_slice(s.as_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    fn f64(&mut self, v: f64) {
        let bits = if v.is_finite() {
            v.to_bits()
        } else {
            0x7ff8_0000_0000_0000 // canonical quiet NaN
        };
        self.buf.extend_from_slice(&bits.to_be_bytes());
    }
    fn opt_f64(&mut self, v: Option<f64>) {
        match v {
            Some(x) => {
                self.buf.push(1);
                self.f64(x);
            }
            None => self.buf.push(0),
        }
    }
}

/// Canonical `&'static str` tags. These are part of the signed form and
/// the Article-13 contract: they MUST NOT change without a [`CANON_DOMAIN`]
/// version bump, and the exhaustive `match`es (no `_` arm) force a
/// compile error — i.e. an explicit canonical-encoding review — if the
/// upstream `ade_types` enums ever grow a variant.
fn ade_action_tag(a: &AdeAction) -> &'static str {
    match a {
        AdeAction::Allow => "allow",
        AdeAction::Monitor => "monitor",
        AdeAction::Alert => "alert",
        AdeAction::Throttle => "throttle",
        AdeAction::Kill => "kill",
        AdeAction::KillTree => "kill_tree",
        AdeAction::Quarantine => "quarantine",
        AdeAction::BlockNetwork => "block_network",
        AdeAction::Isolate => "isolate",
        AdeAction::Escalate => "escalate",
    }
}
fn ade_severity_tag(s: &AdeSeverity) -> &'static str {
    match s {
        AdeSeverity::None => "none",
        AdeSeverity::Low => "low",
        AdeSeverity::Medium => "medium",
        AdeSeverity::High => "high",
        AdeSeverity::Critical => "critical",
    }
}
fn region_tag(r: &Region) -> &'static str {
    match r {
        Region::Focal => "focal",
        Region::Correlated => "correlated",
        Region::Host => "host",
    }
}
fn refinement_tag(r: &Refinement) -> &'static str {
    match r {
        Refinement::Fine => "fine",
        Refinement::Coarse => "coarse",
    }
}
fn occlusion_tag(m: &OcclusionMode) -> &'static str {
    match m {
        OcclusionMode::Drop => "drop",
        OcclusionMode::AnonymiseInPlace => "anonymise_in_place",
    }
}
fn thread_tag(t: &ThreadMode) -> &'static str {
    match t {
        ThreadMode::SingleThread => "single_thread",
        ThreadMode::DeterministicReduce => "deterministic_reduce",
    }
}

impl XaiEvidenceChain {
    /// The exact bytes a signature is taken over: domain-separated,
    /// length-prefixed, field-ordered (declaration order of every struct),
    /// and **excluding `signature`** by construction. Calling this twice
    /// on the same value yields identical bytes; mutating `signature`
    /// never changes the output.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut c = Canon::new();
        c.str(&self.schema_version);
        c.str(&self.xai_trace_id);
        c.str(&self.ade_trace_id);
        c.str(&self.timestamp_utc);

        // model
        c.str(&self.model.model_id);
        c.str(&self.model.model_quantization);
        c.str(&self.model.backend);

        // method
        c.str(&self.method.kind);
        c.f64(self.method.weights.w_action);
        c.f64(self.method.weights.w_severity);
        c.f64(self.method.weights.w_confidence);
        c.u32(self.method.max_units);
        c.f64(self.method.region_refine_threshold);
        c.u64(self.method.total_budget_ms);
        c.str(occlusion_tag(&self.method.occlusion_mode));
        c.f64(self.method.inference_settings.temperature);
        c.u32(self.method.inference_settings.top_k);
        c.f64(self.method.inference_settings.top_p);
        c.u64(self.method.inference_settings.seed);
        c.str(thread_tag(&self.method.inference_settings.thread_mode));

        // input_snapshot
        c.str(&self.input_snapshot.focal_event_json);
        c.str(&self.input_snapshot.recent_events_json);
        c.str(&self.input_snapshot.host_context_json);
        c.str(&self.input_snapshot.prompt_sha256);

        c.str(&self.environment_hash);

        // baseline_verdict
        c.str(ade_action_tag(&self.baseline_verdict.verdict));
        c.str(ade_severity_tag(&self.baseline_verdict.severity));
        c.f64(self.baseline_verdict.confidence);

        // saliency_map
        c.u32(self.saliency_map.len() as u32);
        for e in &self.saliency_map {
            c.str(region_tag(&e.region));
            c.str(&e.unit_id);
            c.str(&e.human_label);
            c.f64(e.score);
            c.str(refinement_tag(&e.refinement));
            c.f64(e.delta.action_flip);
            c.f64(e.delta.severity_shift);
            c.f64(e.delta.confidence_delta);
            c.opt_f64(e.attention_score);
        }

        c.f64(self.saliency_coverage);

        // status
        match &self.status {
            XaiStatus::Complete => c.str("complete"),
            XaiStatus::Degraded(reason) => {
                c.str("degraded");
                c.str(reason);
            }
        }

        // `signature` is intentionally NOT encoded.
        c.buf
    }

    /// Sign in place: `self.signature = Some(signer.sign(canonical_bytes))`.
    /// Idempotent w.r.t. the signed bytes (signature is excluded from them).
    pub fn sign_with(&mut self, signer: &dyn EvidenceSigner) {
        let msg = self.canonical_bytes();
        self.signature = Some(signer.sign(&msg));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> XaiEvidenceChain {
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
            saliency_map: alloc::vec![SaliencyEntry {
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

    #[test]
    fn constants_locked() {
        assert_eq!(XAI_SCHEMA_VERSION, "1.0.0");
        assert_eq!(XAI_BUDGET_MS, 90_000);
    }

    #[test]
    fn json_round_trip_is_lossless() {
        let c = sample();
        let s = serde_json::to_string(&c).unwrap();
        let back: XaiEvidenceChain = serde_json::from_str(&s).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn canonical_bytes_are_deterministic() {
        let c = sample();
        assert_eq!(c.canonical_bytes(), c.canonical_bytes());
    }

    #[test]
    fn canonical_bytes_start_with_domain_separator() {
        let c = sample();
        assert!(c.canonical_bytes().starts_with(CANON_DOMAIN));
    }

    #[test]
    fn signature_is_excluded_from_canonical_bytes() {
        let mut c = sample();
        let unsigned = c.canonical_bytes();
        c.signature = Some(XaiSignature {
            sig: [7u8; 64],
            signer_pubkey: [9u8; 32],
        });
        assert_eq!(
            unsigned,
            c.canonical_bytes(),
            "mutating signature must not change the signed bytes"
        );
    }

    #[test]
    fn canonical_bytes_are_tamper_sensitive() {
        let base = sample().canonical_bytes();

        let mut a = sample();
        a.baseline_verdict.confidence = 0.93;
        assert_ne!(base, a.canonical_bytes());

        let mut b = sample();
        b.saliency_map[0].score = 0.80;
        assert_ne!(base, b.canonical_bytes());

        let mut d = sample();
        d.schema_version = "1.0.1".to_string();
        assert_ne!(base, d.canonical_bytes());

        let mut e = sample();
        e.status = XaiStatus::Degraded("budget exceeded".to_string());
        assert_ne!(base, e.canonical_bytes());
    }

    fn lower_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| alloc::format!("{:02x}", b)).collect()
    }

    #[test]
    fn canonical_bytes_byte_locked_for_sample() {
        // Audit anchor: any accidental change to canonical_bytes (field
        // addition, encoding tweak, enum-tag change) flips this hash and
        // fails CI, forcing a DELIBERATE CANON_DOMAIN version bump plus a
        // rationale entry in the commit body. Complementary to
        // `canonical_bytes_are_tamper_sensitive` (which catches changes in
        // field *values*, not in the encoding *algorithm*). The sample()
        // fixture is fully deterministic and all f64 literals have
        // platform-independent IEEE-754 bit patterns, so this constant is
        // stable across hosts/toolchains.
        use sha2::{Digest, Sha256};
        let bytes = sample().canonical_bytes();
        let hash = lower_hex(Sha256::digest(&bytes).as_slice());
        assert_eq!(
            hash,
            "3514e399ef2ca32bd0bf078dd565b14d8e966330c3738e93b993dfc1835a88e6",
            "canonical encoding drifted — if intentional, bump CANON_DOMAIN \
             and update this lock with a rationale in the commit body"
        );
    }

    #[test]
    fn enum_canonical_tags_are_locked() {
        // Locks the signed-form contract: a rename/reorder is a breaking
        // change that MUST bump CANON_DOMAIN, and this test will catch it.
        assert_eq!(ade_action_tag(&AdeAction::KillTree), "kill_tree");
        assert_eq!(ade_action_tag(&AdeAction::BlockNetwork), "block_network");
        assert_eq!(ade_severity_tag(&AdeSeverity::Critical), "critical");
        assert_eq!(region_tag(&Region::Correlated), "correlated");
        assert_eq!(refinement_tag(&Refinement::Coarse), "coarse");
        assert_eq!(occlusion_tag(&OcclusionMode::AnonymiseInPlace), "anonymise_in_place");
        assert_eq!(thread_tag(&ThreadMode::SingleThread), "single_thread");
    }

    /// Crypto-free stub proving the [`EvidenceSigner`] seam wires through
    /// `sign_with` without `common` taking a crypto dependency. The real
    /// Ed25519 sign→verify→tamper test lives in `agent/src/xai/evidence.rs`.
    struct FixedSigner;
    impl EvidenceSigner for FixedSigner {
        fn sign(&self, msg: &[u8]) -> XaiSignature {
            let mut sig = [0u8; 64];
            sig[0] = msg.len() as u8; // deterministic, not cryptographic
            XaiSignature {
                sig,
                signer_pubkey: [1u8; 32],
            }
        }
    }

    #[test]
    fn sign_with_sets_signature_and_preserves_signed_bytes() {
        let mut c = sample();
        let before = c.canonical_bytes();
        assert!(c.signature.is_none());
        c.sign_with(&FixedSigner);
        assert!(c.signature.is_some());
        assert_eq!(
            before,
            c.canonical_bytes(),
            "signing must not alter the canonical (signed) bytes"
        );
    }
}
