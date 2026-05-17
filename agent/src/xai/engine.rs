//! Tappa 6.9 — P4: the `XaiEngine` public entrypoint + Article-13
//! evidence-chain assembly + signing, the `AdeEngine`→`DecisionProbe`
//! adapter, and the deployment `environment_hash`.
//!
//! `XaiEngine::explain` is the mandatory-guardrail seam (plan §1.3,
//! §3.6): it runs the P3 coarse-to-fine driver against a deterministic
//! ADE probe, assembles a [`XaiEvidenceChain`], and signs it. Any
//! [`XaiUnavailable`] propagates unchanged — the (future, Tappa 10.5)
//! synthesis path is contractually required to treat `Err` as "do not
//! deploy the rule".
//!
//! ## Determinism contract (plan §3.2-R1) — flagged for the audit
//!
//! `XaiEngine` consumes `AdeEngine` through the `evaluate` seam ONLY
//! (plan §6: no ADE internals, ADE byte-identical when XAI is not
//! invoked). ADE's sampling is fixed at engine *construction*
//! (`AdeConfig.temperature`/`top_p`/`num_threads`) and candle's
//! `LogitsProcessor` seed is the hard-coded `backend_candle.rs` constant
//! — none are per-call knobs `evaluate` could accept. So R1 is a
//! *construction contract*, not something the adapter can enforce at
//! call time: build the wrapped engine with
//! [`deterministic_ade_config`]. [`deterministic_inference_settings`]
//! records exactly what that path yields (temp 0 ⇒ greedy ArgMax ≡
//! top_k 1; single-thread) into `method.inference_settings`, so an
//! auditor re-executing `input_snapshot` reproduces the map bit-for-bit.
//!
//! The single ADE-surface addition this phase makes is the read-only
//! [`AdeEngine::assembled_prompt`] forensic accessor (no behaviour
//! change); everything else lives in `xai/`.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use common::ade_types::AdeVerdict;
use common::xai_types::{
    InferenceSettings, ThreadMode, XaiEvidenceChain, XaiInputSnapshot, XaiMethod, XaiModelRef,
    XAI_SCHEMA_VERSION,
};
use common::Event;

use crate::ade::{AdeConfig, AdeEngine, EventContext};
use crate::xai::saliency::{explain_saliency, SaliencyConfig, XaiUnavailable};
use crate::xai::source::{DecisionProbe, XaiProbeError};
use common::xai_types::EvidenceSigner;

/// The fixed candle `LogitsProcessor` seed (`backend_candle.rs`, the
/// `0xC0FFEE` literal). Greedy ArgMax decoding ignores it, but R1
/// records it verbatim so a future sampling method stays reproducible.
pub const XAI_DETERMINISTIC_SEED: u64 = 0x00C0_FFEE;

/// Force an [`AdeConfig`] onto the R1 bit-reproducible path: greedy
/// decoding (`temperature = 0` ⇒ candle `Sampling::ArgMax`), no
/// nucleus truncation (`top_p = 1.0`, inert under ArgMax but recorded),
/// and single-thread CPU kernels (multi-thread float reduction is
/// non-associative ⇒ non-reproducible). The XAI engine MUST be built
/// from an `AdeEngine` constructed with a config passed through this.
pub fn deterministic_ade_config(mut cfg: AdeConfig) -> AdeConfig {
    cfg.temperature = 0.0;
    cfg.top_p = 1.0;
    cfg.num_threads = Some(1);
    cfg
}

/// The inference settings the [`deterministic_ade_config`] path yields,
/// recorded verbatim into every chain's `method.inference_settings`.
pub fn deterministic_inference_settings() -> InferenceSettings {
    InferenceSettings {
        temperature: 0.0,
        // candle exposes no top_k knob; greedy ArgMax ≡ top_k = 1.
        top_k: 1,
        top_p: 1.0,
        seed: XAI_DETERMINISTIC_SEED,
        thread_mode: ThreadMode::SingleThread,
    }
}

/// Thin adapter: an [`AdeEngine`] as a re-runnable [`DecisionProbe`].
/// ADE internals are untouched — only `evaluate` is called; any
/// [`crate::ade::AdeError`] collapses to [`XaiProbeError`] (its
/// `Display`), which the driver maps to fail-closed
/// [`XaiUnavailable::Probe`].
pub struct AdeProbe<'a> {
    engine: &'a AdeEngine,
}

impl<'a> AdeProbe<'a> {
    pub fn new(engine: &'a AdeEngine) -> Self {
        Self { engine }
    }
}

impl DecisionProbe for AdeProbe<'_> {
    async fn probe(
        &self,
        focal: &Event,
        ctx: &EventContext,
    ) -> Result<AdeVerdict, XaiProbeError> {
        self.engine
            .evaluate(focal, ctx)
            .await
            .map_err(|e| XaiProbeError(e.to_string()))
    }
}

/// Filesystem inputs to the deployment-identity hash that are not
/// derivable from the running process alone.
#[derive(Debug, Clone)]
pub struct EnvironmentInputs {
    /// The GGUF model file (`AdeConfig.model_path`).
    pub model_path: PathBuf,
    /// The combat-rules file (`Cli.combat_rules`, default
    /// `/etc/northnarrow/combat-rules.v4`).
    pub combat_rules_path: PathBuf,
}

fn sha256_file(p: &Path) -> std::io::Result<[u8; 32]> {
    let bytes = std::fs::read(p)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(&bytes));
    Ok(out)
}

/// Canonical hostname, read the same way the rest of the agent does
/// (`/proc/sys/kernel/hostname`, as in `HostContext::discover`).
///
/// NOTE (flagged for audit): the D1 doc-comment illustrates this as
/// `hostname --fqdn`; the codebase standard is the procfs read, and
/// the deployment-identity hash must agree with the rest of the
/// agent's host identity — consistency wins over the illustrative
/// command. Fixed-name fallback keeps the hash total.
fn canonical_hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// `lower_hex(sha256( agent_binary_sha256 || model_file_sha256 ||
/// combat_rules_sha256 || hostname_utf8 || build_commit_sha_utf8 ))`,
/// exactly the D1 spec in `common::xai_types`. Computed once at
/// [`XaiEngine::new`] and cached into every chain.
pub fn compute_environment_hash(env: &EnvironmentInputs) -> std::io::Result<String> {
    let agent_binary = std::env::current_exe()?;
    let mut h = Sha256::new();
    h.update(sha256_file(&agent_binary)?);
    h.update(sha256_file(&env.model_path)?);
    h.update(sha256_file(&env.combat_rules_path)?);
    h.update(canonical_hostname().as_bytes());
    h.update(env!("BUILD_SHA").as_bytes());
    Ok(hex::encode(h.finalize()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn snapshot_err(what: &str, e: serde_json::Error) -> XaiUnavailable {
    // A snapshot we cannot serialise ⇒ no faithful chain ⇒ fail-closed.
    XaiUnavailable::Probe(XaiProbeError(format!("{what} snapshot serialise: {e}")))
}

/// The Article-13 explainability engine: wraps a *deterministic*
/// [`AdeEngine`], a signer, and the cached `environment_hash`.
pub struct XaiEngine<S: EvidenceSigner> {
    engine: AdeEngine,
    signer: S,
    saliency_cfg: SaliencyConfig,
    environment_hash: String,
    inference_settings: InferenceSettings,
}

impl<S: EvidenceSigner> XaiEngine<S> {
    /// `engine` MUST have been built from [`deterministic_ade_config`]
    /// (R1). Computes + caches the deployment `environment_hash`.
    pub fn new(
        engine: AdeEngine,
        signer: S,
        saliency_cfg: SaliencyConfig,
        env: &EnvironmentInputs,
    ) -> std::io::Result<Self> {
        Ok(Self {
            engine,
            signer,
            saliency_cfg,
            environment_hash: compute_environment_hash(env)?,
            inference_settings: deterministic_inference_settings(),
        })
    }

    /// Explain one ADE decision: run the P3 driver against the
    /// deterministic ADE probe, assemble the signed
    /// [`XaiEvidenceChain`]. `ade_verdict` is the explained production
    /// decision — used ONLY for the `ade_trace_id` FK and the model
    /// identity; the chain's `baseline_verdict` is the driver's own
    /// deterministic `V0` (plan §3.3, R1), NOT this verdict.
    pub async fn explain(
        &self,
        focal: &Event,
        ctx: &EventContext,
        ade_verdict: &AdeVerdict,
    ) -> Result<XaiEvidenceChain, XaiUnavailable> {
        let probe = AdeProbe::new(&self.engine);
        let run = explain_saliency(&self.saliency_cfg, focal, ctx, &probe).await?;

        // `assembled_prompt` shares evaluate's prompt path ⇒ the hash
        // binds the literal model prompt. `None` (injection escalate ⇒
        // no prompt) hashes the empty string, recorded honestly.
        let prompt = self.engine.assembled_prompt(focal, ctx).unwrap_or_default();

        let host = &ctx.host_context;
        let input_snapshot = XaiInputSnapshot {
            focal_event_json: serde_json::to_string(focal)
                .map_err(|e| snapshot_err("focal_event", e))?,
            recent_events_json: serde_json::to_string(&ctx.recent_events)
                .map_err(|e| snapshot_err("recent_events", e))?,
            // `serde_json::json!` (serde_json is a direct dep; the
            // `serde` derive macro is not) — Value's Map is sorted-key,
            // so this is deterministic without a derived mirror struct.
            host_context_json: serde_json::json!({
                "hostname": host.hostname,
                "host_id": host.host_id,
                "kernel_version": host.kernel_version,
                "agent_version": host.agent_version,
            })
            .to_string(),
            prompt_sha256: sha256_hex(prompt.as_bytes()),
        };

        let m = &ade_verdict.metadata;
        let mut chain = XaiEvidenceChain {
            schema_version: XAI_SCHEMA_VERSION.to_string(),
            xai_trace_id: uuid::Uuid::new_v4().to_string(),
            ade_trace_id: ade_verdict.trace_id.clone(),
            timestamp_utc: chrono::Utc::now().to_rfc3339(),
            model: XaiModelRef {
                model_id: m.model_id.clone(),
                model_quantization: m.model_quantization.clone(),
                backend: m.backend.clone(),
            },
            method: XaiMethod {
                kind: "perturbation/occlusion".to_string(),
                weights: self.saliency_cfg.weights,
                max_units: self.saliency_cfg.max_units,
                region_refine_threshold: self.saliency_cfg.region_refine_threshold,
                total_budget_ms: self.saliency_cfg.budget_ms,
                occlusion_mode: self.saliency_cfg.mode,
                inference_settings: self.inference_settings,
            },
            input_snapshot,
            environment_hash: self.environment_hash.clone(),
            baseline_verdict: run.baseline,
            saliency_map: run.saliency_map,
            saliency_coverage: run.saliency_coverage,
            status: run.status,
            signature: None,
        };
        chain.sign_with(&self.signer);
        Ok(chain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ade::{HostContext, InferenceBackend, MockBackend};
    use crate::xai::evidence::{verify_evidence, Ed25519EvidenceSigner};
    use common::xai_types::XaiStatus;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use std::io::Write;
    use std::sync::Arc;
    use tempfile::NamedTempFile;

    fn temp_with(bytes: &[u8]) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("temp");
        f.write_all(bytes).unwrap();
        f.flush().unwrap();
        f
    }

    fn env_inputs(model: &Path, rules: &Path) -> EnvironmentInputs {
        EnvironmentInputs {
            model_path: model.to_path_buf(),
            combat_rules_path: rules.to_path_buf(),
        }
    }

    async fn mock_engine(model: &Path, prompt: &Path) -> AdeEngine {
        let cfg = deterministic_ade_config(AdeConfig {
            model_path: model.to_path_buf(),
            system_prompt_path: prompt.to_path_buf(),
            ..AdeConfig::default()
        });
        let backend: Arc<dyn InferenceBackend> = Arc::new(MockBackend::new());
        AdeEngine::new_with_backend(cfg, backend).await.unwrap()
    }

    fn xmrig() -> Event {
        Event::ProcessSpawn {
            pid: 4242,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            comm: "xmrig".into(),
            filename: "/tmp/x".into(),
            timestamp_ns: 0,
        }
    }

    #[test]
    fn deterministic_config_forces_the_r1_path() {
        let c = deterministic_ade_config(AdeConfig::default());
        assert_eq!(c.temperature, 0.0);
        assert_eq!(c.top_p, 1.0);
        assert_eq!(c.num_threads, Some(1));
        let s = deterministic_inference_settings();
        assert_eq!(s.top_k, 1);
        assert_eq!(s.seed, XAI_DETERMINISTIC_SEED);
        assert_eq!(s.thread_mode, ThreadMode::SingleThread);
    }

    #[test]
    fn environment_hash_is_deterministic_and_tamper_sensitive() {
        let model = temp_with(b"gguf-bytes-v1");
        let rules = temp_with(b"combat-rules-v4");
        let e = env_inputs(model.path(), rules.path());

        let h1 = compute_environment_hash(&e).unwrap();
        let h2 = compute_environment_hash(&e).unwrap();
        assert_eq!(h1, h2, "same inputs ⇒ same hash");
        assert_eq!(h1.len(), 64);
        assert!(h1.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));

        // Flip one combat-rules byte ⇒ the deployment identity changes.
        let rules2 = temp_with(b"combat-rules-v5");
        let h3 = compute_environment_hash(&env_inputs(model.path(), rules2.path())).unwrap();
        assert_ne!(h1, h3);
    }

    #[test]
    fn environment_hash_errors_when_a_file_is_missing() {
        let model = temp_with(b"m");
        let e = env_inputs(model.path(), Path::new("/no/such/combat-rules"));
        assert!(compute_environment_hash(&e).is_err());
    }

    #[tokio::test]
    async fn explain_assembles_signs_and_verifies_a_full_chain() {
        let model = temp_with(b"gguf");
        let rules = temp_with(b"rules");
        let prompt = temp_with(b"# stub prompt\nmodel must produce valid JSON.\n");
        let engine = mock_engine(model.path(), prompt.path()).await;

        let focal = xmrig();
        let ctx = EventContext {
            recent_events: vec![],
            host_context: HostContext::discover(),
        };
        // The production verdict (FK + model identity source).
        let ade_verdict = engine.evaluate(&focal, &ctx).await.unwrap();

        let signer = Ed25519EvidenceSigner::new(SigningKey::generate(&mut OsRng));
        let xai = XaiEngine::new(
            engine,
            signer,
            SaliencyConfig::default(),
            &env_inputs(model.path(), rules.path()),
        )
        .unwrap();

        let chain = xai.explain(&focal, &ctx, &ade_verdict).await.unwrap();

        // Field mapping.
        assert_eq!(chain.schema_version, XAI_SCHEMA_VERSION);
        assert!(!chain.xai_trace_id.is_empty());
        assert_eq!(chain.ade_trace_id, ade_verdict.trace_id);
        assert_eq!(chain.model.model_id, ade_verdict.metadata.model_id);
        assert_eq!(chain.model.backend, ade_verdict.metadata.backend);
        assert_eq!(chain.method.kind, "perturbation/occlusion");
        assert_eq!(chain.method.max_units, 12);
        assert_eq!(chain.method.inference_settings.top_k, 1);
        assert_eq!(chain.environment_hash.len(), 64);
        assert_eq!(chain.input_snapshot.prompt_sha256.len(), 64);
        assert!(chain.input_snapshot.focal_event_json.contains("xmrig"));
        assert!(chain.input_snapshot.host_context_json.contains("hostname"));
        assert!(!chain.saliency_map.is_empty());
        assert!(chain.saliency_coverage >= 0.0 && chain.saliency_coverage <= 1.0);
        assert!(matches!(
            chain.status,
            XaiStatus::Complete | XaiStatus::Degraded(_)
        ));

        // Signed + verifiable + canonical round-trip.
        assert!(chain.signature.is_some());
        verify_evidence(&chain).expect("freshly signed chain must verify");
        let json = serde_json::to_string(&chain).unwrap();
        let back: XaiEvidenceChain = serde_json::from_str(&json).unwrap();
        assert_eq!(chain, back);

        // Tamper after signing ⇒ verification fails.
        let mut tampered = chain.clone();
        tampered.baseline_verdict.confidence += 0.01;
        assert!(verify_evidence(&tampered).is_err());
    }

    #[tokio::test]
    async fn baseline_is_the_deterministic_v0_not_the_passed_verdict() {
        let model = temp_with(b"gguf");
        let rules = temp_with(b"rules");
        let prompt = temp_with(b"# stub\nJSON.\n");
        let engine = mock_engine(model.path(), prompt.path()).await;
        let focal = xmrig();
        let ctx = EventContext {
            recent_events: vec![],
            host_context: HostContext::discover(),
        };
        let v = engine.evaluate(&focal, &ctx).await.unwrap();

        // Hand explain a verdict whose fields are deliberately wrong;
        // the chain baseline must reflect the probe's V0, not this.
        let mut bogus = v.clone();
        bogus.confidence = 0.123_456;
        let signer = Ed25519EvidenceSigner::new(SigningKey::generate(&mut OsRng));
        let xai = XaiEngine::new(
            engine,
            signer,
            SaliencyConfig::default(),
            &env_inputs(model.path(), rules.path()),
        )
        .unwrap();
        let chain = xai.explain(&focal, &ctx, &bogus).await.unwrap();
        assert_eq!(chain.ade_trace_id, bogus.trace_id, "FK still the passed verdict");
        assert!(
            (chain.baseline_verdict.confidence - 0.123_456).abs() > 1e-9,
            "baseline must be the deterministic V0, not the passed verdict"
        );
    }

    /// Opt-in real-candle latency bench (plan §11 P4, R-P3.2). Run with
    /// `NN_XAI_BENCH_MODEL=/path/to.gguf cargo test -p northnarrow-agent \
    ///  --release -- --ignored xai::engine::tests::candle_inference_bench
    /// --nocapture`. It PRINTS a paste-ready provenance line; promoting
    /// the measured value into `saliency::EST_INFERENCE_MS` is a
    /// separate deliberate commit (the R-P3.2 ledger contract), never
    /// an automatic edit.
    #[tokio::test]
    #[ignore = "needs a real GGUF model; opt-in via NN_XAI_BENCH_MODEL"]
    async fn candle_inference_bench() {
        let Ok(model_path) = std::env::var("NN_XAI_BENCH_MODEL") else {
            eprintln!("NN_XAI_BENCH_MODEL unset — nothing to bench");
            return;
        };
        let prompt = temp_with(b"# bench\nJSON.\n");
        let cfg = deterministic_ade_config(AdeConfig {
            model_path: PathBuf::from(&model_path),
            system_prompt_path: prompt.path().to_path_buf(),
            ..AdeConfig::default()
        });
        let engine = AdeEngine::new(cfg).await.expect("real candle engine");
        let focal = xmrig();
        let ctx = EventContext {
            recent_events: vec![],
            host_context: HostContext::discover(),
        };

        let mut samples = Vec::new();
        for _ in 0..7 {
            let t = std::time::Instant::now();
            engine.evaluate(&focal, &ctx).await.unwrap();
            samples.push(t.elapsed().as_millis() as u64);
        }
        samples.sort_unstable();
        let p50 = samples[samples.len() / 2];
        let p95 = samples[(samples.len() * 95 / 100).min(samples.len() - 1)];
        eprintln!(
            "R-P3.2 LEDGER UPDATE CANDIDATE — provenance: host={} date={} \
             model={} thread_mode=single n={} p50={}ms p95={}ms \
             (=> set saliency::EST_INFERENCE_MS to p95 in a dedicated commit)",
            canonical_hostname(),
            chrono::Utc::now().to_rfc3339(),
            model_path,
            samples.len(),
            p50,
            p95,
        );
    }
}
