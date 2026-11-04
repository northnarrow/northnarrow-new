//! The export (lot 276, R15's first step; `docs/operator/EXPORT.md`): the
//! agent's composition of nn-export, nn-linux's sandbox and its workers.
//!
//! - [`load`]: the signed overlay `/etc/northnarrow/export.local` read at
//!   the start, through the overlay gate (`config-manage`); off without it.
//! - [`worker::main`]: the `export` worker's life, in its sandbox
//!   (`nn_linux::sandbox::Profile::export`) — OCSF, the JSONL file, syslog
//!   over TLS run there and only there.
//! - [`controller`]: the core's `nn-export` thread — the chains read as
//!   the write-ahead log, the cursors kept, the worker fed, its answers
//!   checked, what it lost counted (stage 8) and signed.
//! - [`ExportHandle`]: what the status, the manifest and the beats read.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use nn_core::config::overlay_auth::Verified;
use nn_export::config::{ExportConfig, EXPORT_LOCAL};
use nn_proto::admin_protocol::{ExportSinkStatus, ExportStatus};
use nn_proto::admin_signed_payload::OverlayKind;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};

pub mod controller;
pub mod worker;

#[cfg(test)]
mod tests;

/// The export's configuration as the start found it.
#[derive(Debug, Clone)]
pub enum Loaded {
    /// No signed configuration: no export.
    Absent,
    /// Signed and parsed; `enabled = false` (`config.enabled` false) or on.
    Configured(Box<Configured>),
    /// Present, its signature refused (the gate signed the refusal).
    Refused,
    /// Signed, and it does not parse, or its CA file is not the one it
    /// pins.
    Failed { why: String, sha256: String },
}

/// A configuration that parsed, its CA bundle read and checked.
#[derive(Debug, Clone)]
pub struct Configured {
    pub config: ExportConfig,
    pub sha256: String,
    pub ca_pem: Option<Vec<u8>>,
}

/// Read the export's overlay through the gate.
pub fn load(gate: &crate::config::overlay_auth::OverlayGate) -> Loaded {
    load_from(gate, std::path::Path::new(EXPORT_LOCAL))
}

/// [`load`] from `path` (the tests').
pub(crate) fn load_from(
    gate: &crate::config::overlay_auth::OverlayGate,
    path: &std::path::Path,
) -> Loaded {
    match gate.verified(OverlayKind::Export, path) {
        Verified::Missing | Verified::ShippedDefault => Loaded::Absent,
        Verified::Refused => Loaded::Refused,
        Verified::Content { text, .. } => parse(&text),
    }
}

/// A signed text, parsed and its CA read (the CA is checked against the
/// digest the text pins).
pub fn parse(text: &str) -> Loaded {
    let sha256 = hex::encode(Sha256::digest(text.as_bytes()));
    let config = match ExportConfig::parse(text) {
        Ok(c) => c,
        Err(e) => {
            return Loaded::Failed {
                why: format!("{e:#}"),
                sha256,
            }
        }
    };
    let ca_pem = match &config.syslog {
        Some(s) if config.enabled => match nn_export::config::read_ca(&s.ca, &s.ca_sha256) {
            Ok(b) => Some(b),
            Err(e) => {
                return Loaded::Failed {
                    why: format!("{e:#}"),
                    sha256,
                }
            }
        },
        _ => None,
    };
    Loaded::Configured(Box::new(Configured {
        config,
        sha256,
        ca_pem,
    }))
}

/// What the start says of the configuration: on in the journal; refused
/// or failed a signed degradation (`export: …`); off or absent nothing.
pub fn report_load(loaded: &Loaded) {
    match loaded {
        Loaded::Absent => {}
        Loaded::Configured(c) if c.config.enabled => {
            tracing::info!(config = %c.config.summary(), sha256 = %c.sha256, "export: configured, on");
        }
        Loaded::Configured(_) => {
            tracing::info!("export: configured, enabled = false: off");
        }
        Loaded::Refused => {
            crate::boot::degradation::report(
                "export",
                "configured, refused: export.local's signature did not verify; nothing is exported",
            );
        }
        Loaded::Failed { why, .. } => {
            crate::boot::degradation::report(
                "export",
                &format!("configured, failed: {why}; nothing is exported"),
            );
        }
    }
}

/// The export's cursors' file: beside the detection log, in the agent's
/// state directory's `detections/` (root's, 0700).
pub fn cursors_path(detections_file: &std::path::Path) -> std::path::PathBuf {
    detections_file
        .parent()
        .map(|d| d.join(nn_export::wal::CURSORS_FILE))
        .unwrap_or_else(|| std::path::PathBuf::from(nn_export::wal::CURSORS))
}

/// Start the core's thread when the export is on (a thread that does not
/// start is a signed degradation).
#[allow(clippy::too_many_arguments)]
pub fn start_if_on(
    loaded: &Loaded,
    handle: Option<&ExportHandle>,
    workers: &nn_linux::worker::Workers,
    chains: crate::chains::ChainPaths,
    pubkey: Option<ed25519_dalek::VerifyingKey>,
    agent_id: [u8; 16],
    audit: &Option<Arc<Mutex<crate::audit::AuditLog>>>,
    detections_file: &std::path::Path,
) -> Option<controller::Running> {
    let (Some(c), Some(handle)) = (loaded.on(), handle) else {
        return None;
    };
    let Some(pubkey) = pubkey else {
        crate::boot::degradation::report(
            "export",
            "on, not started: the agent's public key is not known (rows could not be checked)",
        );
        return None;
    };
    match controller::start(controller::Params {
        configured: c.clone(),
        workers: workers.clone(),
        chains,
        pubkey,
        agent_id,
        audit: audit.clone(),
        cursors: cursors_path(detections_file),
        handle: handle.clone(),
    }) {
        Ok(r) => Some(r),
        Err(e) => {
            crate::boot::degradation::report(
                "export",
                &format!("on, its thread did not start: {e}"),
            );
            None
        }
    }
}

impl Loaded {
    /// The export runs: a worker to start, a controller to run.
    pub fn on(&self) -> Option<&Configured> {
        match self {
            Loaded::Configured(c) if c.config.enabled => Some(c),
            _ => None,
        }
    }

    fn state(&self) -> &'static str {
        match self {
            Loaded::Absent => "none",
            Loaded::Configured(c) if c.config.enabled => "on",
            Loaded::Configured(_) => "off",
            Loaded::Refused => "refused",
            Loaded::Failed { .. } => "failed",
        }
    }
}

#[derive(Debug, Default)]
struct Live {
    worker: String,
    port_pinned: Option<bool>,
    sinks: Vec<ExportSinkStatus>,
    cursors_saved: Option<String>,
    cursor_saves: u64,
    /// Since when the worker has not been ready (`None`: it is).
    not_ready_since: Option<std::time::Instant>,
}

/// How long the export's worker may be away (a restart, a backoff) before
/// the export says `degraded` (the review of #499, D4).
pub const NOT_READY_GRACE: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Debug)]
struct Shared {
    state: &'static str,
    why: Option<String>,
    config: Option<String>,
    sha256: Option<String>,
    chains: Vec<String>,
    sinks: Vec<String>,
    live: Mutex<Live>,
    lost: AtomicU64,
    /// Its controller runs (set by `start_if_on`; an export on whose
    /// controller never started is `failed`, never "on").
    running: std::sync::atomic::AtomicBool,
}

/// What the status, the manifest and the beats read of the export. Cheap
/// to clone.
#[derive(Debug, Clone)]
pub struct ExportHandle(Arc<Shared>);

/// The target of each configured sink, as the status names it.
fn targets(c: &ExportConfig) -> Vec<String> {
    let mut v = Vec::new();
    if c.file.is_some() {
        v.push(format!("file {}", nn_proto::ipc::EXPORT_DIR));
    }
    if let Some(s) = &c.syslog {
        v.push(format!("syslog {} ({})", s.addr, s.server_name));
    }
    v
}

impl ExportHandle {
    /// The handle of what the start loaded (`None`: no configuration at
    /// all — nothing to show).
    pub fn new(loaded: &Loaded) -> Option<Self> {
        let (why, config, sha256, chains, sinks) = match loaded {
            Loaded::Absent => return None,
            Loaded::Configured(c) => (
                (!c.config.enabled).then(|| "enabled = false".to_string()),
                Some(c.config.summary()),
                Some(c.sha256.clone()),
                c.config
                    .chains
                    .iter()
                    .map(|c| c.name().to_string())
                    .collect(),
                targets(&c.config),
            ),
            Loaded::Refused => (
                Some(
                    "its signature did not verify (the gate signed the refusal: \
                     unauthorized_overlay)"
                        .to_string(),
                ),
                None,
                None,
                Vec::new(),
                Vec::new(),
            ),
            Loaded::Failed { why, sha256 } => (
                Some(why.clone()),
                None,
                Some(sha256.clone()),
                Vec::new(),
                Vec::new(),
            ),
        };
        Some(Self(Arc::new(Shared {
            state: loaded.state(),
            why,
            config,
            sha256,
            chains,
            sinks,
            live: Mutex::new(Live {
                worker: "not started".to_string(),
                ..Live::default()
            }),
            lost: AtomicU64::new(0),
            running: std::sync::atomic::AtomicBool::new(false),
        })))
    }

    /// Stage 8: rows the export can no longer deliver (`None`: not on).
    pub fn lost(&self) -> Option<u64> {
        (self.0.state == "on").then(|| self.0.lost.load(Ordering::Relaxed))
    }

    pub(crate) fn add_lost(&self, n: u64) {
        self.0.lost.fetch_add(n, Ordering::Relaxed);
    }

    pub(crate) fn publish(
        &self,
        worker: String,
        port_pinned: Option<bool>,
        sinks: Vec<ExportSinkStatus>,
        cursors_saved: Option<String>,
        cursor_saves: u64,
    ) {
        let mut live = self.0.live.lock();
        let not_ready_since = if worker == "ready" {
            None
        } else {
            live.not_ready_since
                .or_else(|| Some(std::time::Instant::now()))
        };
        *live = Live {
            worker,
            port_pinned,
            sinks,
            cursors_saved,
            cursor_saves,
            not_ready_since,
        };
    }

    /// Its controller runs, or stopped.
    pub(crate) fn set_running(&self, running: bool) {
        self.0.running.store(running, Ordering::Relaxed);
    }

    /// The export's state as the status, the beat and the manifest say it:
    /// the configuration's (`on`, `off`, `refused`, `failed`, `none`), and
    /// for one `on`, what runs — `failed` when its controller is not
    /// running, `degraded` when its worker is disabled or unavailable, or
    /// away past [`NOT_READY_GRACE`]: never "on" for an export that does
    /// nothing (the review of #499, D4). With why.
    fn effective(&self, live: &Live) -> (String, Option<String>) {
        if self.0.state != "on" {
            return (self.0.state.to_string(), self.0.why.clone());
        }
        if !self.0.running.load(Ordering::Relaxed) {
            return (
                "failed".into(),
                Some("its controller is not running".into()),
            );
        }
        let away = live
            .not_ready_since
            .is_some_and(|t| t.elapsed() >= NOT_READY_GRACE);
        if matches!(live.worker.as_str(), "disabled" | "unavailable") || away {
            return (
                "degraded".into(),
                Some(format!("its worker is {}", live.worker)),
            );
        }
        ("on".into(), None)
    }

    /// `nn-admin export status --key`.
    pub fn status(&self) -> ExportStatus {
        let live = self.0.live.lock();
        let (state, why) = self.effective(&live);
        ExportStatus {
            state,
            why,
            config: self.0.config.clone(),
            config_sha256: self.0.sha256.clone(),
            ocsf_version: nn_export::OCSF_VERSION.to_string(),
            worker: live.worker.clone(),
            port_pinned: live.port_pinned,
            sinks: live.sinks.clone(),
            lost: self.0.lost.load(Ordering::Relaxed),
            cursors_saved: live.cursors_saved.clone(),
            cursor_saves: live.cursor_saves,
        }
    }

    /// The beat's view: the state and each sink's.
    pub fn beat(&self) -> nn_evidence::heartbeat::BeatExport {
        let live = self.0.live.lock();
        nn_evidence::heartbeat::BeatExport {
            state: self.effective(&live).0,
            worker: live.worker.clone(),
            sinks: live
                .sinks
                .iter()
                .map(|k| nn_evidence::heartbeat::BeatExportSink {
                    sink: k.sink.clone(),
                    state: k.state.clone(),
                    rows: k.rows,
                    behind_bytes: k.chains.iter().map(|c| c.behind_bytes).sum(),
                })
                .collect(),
        }
    }

    /// The manifest's entry: the configuration, and the pin measured.
    pub fn manifest_entry(&self) -> nn_core::contract::manifest::ExportEntry {
        let live = self.0.live.lock();
        let (state, why) = self.effective(&live);
        nn_core::contract::manifest::ExportEntry {
            state,
            why: why.unwrap_or_default(),
            ocsf_version: nn_export::OCSF_VERSION.to_string(),
            chains: self.0.chains.clone(),
            sinks: self.0.sinks.clone(),
            config_sha256: self.0.sha256.clone(),
            port_pinned: live.port_pinned,
        }
    }
}
