//! The workers' start (Wave 4 restructure, R14a — plan §3.1, §3.5;
//! `docs/architecture/PROCESS_MODEL.md`).
//!
//! In the subsystems phase, once the deny hooks are attached and
//! `PROTECTED_PIDS` is pinned (the attach phase): the supervisor of the
//! agent's workers (`nn_linux::worker::Workers`) on its own thread, which
//! starts the `parse` worker — this binary, from the descriptor `main`
//! opened at boot ([`SelfImage`]), as the `northnarrow-worker` account — and
//! registers its pid as protected and not exempt. A worker that cannot be
//! started (no account, no image) is a signed degradation; the agent runs
//! without what it gives, and never does its work in its own process.

use std::sync::Arc;

use nn_linux::worker::supervisor::{Config, ImageLauncher, NoPidRoles, PidRoles, PinnedPidRoles};
use nn_linux::worker::{SelfImage, WorkerAccount, Workers, WORKER_USER};
use nn_proto::ipc::WorkerKind;
use tracing::{info, warn};

use super::cli::Cli;

/// R14a: how this core starts its workers, for R004 (the launch from the
/// boot descriptor is the core's own, not a fileless exec). `None` when no
/// worker can start (no image, no account).
pub(crate) fn own_launch(
    image: &std::io::Result<SelfImage>,
) -> Option<nn_core::decision::rules::OwnWorkerLaunch> {
    let image = image.as_ref().ok()?;
    let account = WorkerAccount::lookup(WORKER_USER).ok()?;
    Some(nn_core::decision::rules::OwnWorkerLaunch {
        agent_pid: std::process::id(),
        exec_path: image.exec_path(),
        image: image.identity(),
        uid: account.uid,
    })
}

/// Start the supervisor. `image`: what `main` opened at boot.
pub(crate) fn start(cli: &Cli, image: std::io::Result<SelfImage>) -> Workers {
    let image = match image {
        Ok(i) => Some(i),
        Err(e) => {
            warn!(error = %e, "the agent's own image could not be opened at boot: no worker can start");
            None
        }
    };
    let account = WorkerAccount::lookup(WORKER_USER);
    let pins = std::path::Path::new(antitamper_bpf::DEFAULT_BPFFS_ROOT);
    let roles: Arc<dyn PidRoles> = if pins.join(antitamper_bpf::PROTECTED_PIDS_MAP_NAME).exists() {
        Arc::new(PinnedPidRoles {
            bpffs_root: pins.to_path_buf(),
        })
    } else {
        info!("no pinned PROTECTED_PIDS: the workers' pids are not registered with the deny hooks");
        Arc::new(NoPidRoles)
    };
    let workers = Workers::new(Config {
        launcher: Arc::new(ImageLauncher {
            image,
            account,
            extra_args: Vec::new(),
        }),
        roles,
        report: Arc::new(|source: &str, detail: &str| {
            northnarrow_agent::boot::degradation::report(source, detail);
        }),
        kinds: vec![WorkerKind::Parse],
        debug_dir: cli.admin_socket.parent().map(std::path::Path::to_path_buf),
    });
    if let Err(e) = workers.start() {
        northnarrow_agent::boot::degradation::report(
            "worker_parse",
            &format!("the workers' supervisor did not start: {e}"),
        );
    }
    workers
}
