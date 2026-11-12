//! The workers' start (Wave 4 restructure, R14a — plan §3.1, §3.5;
//! `docs/architecture/PROCESS_MODEL.md`).
//!
//! At the head of the attach phase (R14b: before the sensors, so the DNS
//! pump's first records find the parse worker ready): the supervisor of the
//! agent's workers (`nn_linux::worker::Workers`) on its own thread, which
//! starts the `parse` worker — this binary, from the descriptor `main`
//! opened at boot ([`SelfImage`]), as the `northnarrow-worker` account. Its
//! pid is registered as protected and not exempt once this boot's deny
//! hooks are attached and `PROTECTED_PIDS` is pinned ([`arm`]). A worker
//! that cannot be started (no account, no image) is a signed degradation;
//! the agent runs without what it gives, and never does its work in its own
//! process.

use std::sync::Arc;

use nn_linux::worker::supervisor::{Config, ImageLauncher, NoPidRoles, PidRoles, PinnedPidRoles};
use nn_linux::worker::{SelfImage, WorkerAccount, Workers, EXPORT_USER, WORKER_USER};
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
        // lot 310: as the exec sensor reports an executed file (the
        // kernel's device form)
        image: image.exec_identity(),
        uid: account.uid,
        export_uid: WorkerAccount::lookup(EXPORT_USER).ok().map(|a| a.uid),
    })
}

/// Lot 310 (BUG-103): systemd's executor by its identities, for R004 — the
/// files at its install paths and the ones systemd's managers hold open,
/// read now; the install paths again every minute
/// ([`super::tasks::spawn_executor_refresh`]), so an image an upgrade
/// unlinks was recorded while it was linked.
pub(crate) fn known_launches(
    own_worker: Option<nn_core::decision::rules::OwnWorkerLaunch>,
) -> nn_core::decision::rules::KnownLaunches {
    let executor = nn_core::decision::rules::ExecutorImages::default();
    let n = nn_linux::systemd_executor::seed(&executor);
    info!(
        identities = n,
        "R004: systemd-executor known by its identity (install paths, managers' open copies)"
    );
    nn_core::decision::rules::KnownLaunches {
        own_worker,
        executor,
    }
}

/// Start the supervisor. `image`: what `main` opened at boot; `export_on`:
/// the export's signed configuration turns it on (lot 276), its worker
/// starts beside the parse worker.
pub(crate) fn start(cli: &Cli, image: std::io::Result<SelfImage>, export_on: bool) -> Workers {
    let image = match image {
        Ok(i) => Some(i),
        Err(e) => {
            warn!(error = %e, "the agent's own image could not be opened at boot: no worker can start");
            None
        }
    };
    let account = WorkerAccount::lookup(WORKER_USER);
    let export_account = WorkerAccount::lookup(EXPORT_USER);
    // R14b: no role until this boot's deny hooks are attached ([`arm`]):
    // an earlier boot's pinned hooks read any entry as both roles
    let roles: Arc<dyn PidRoles> = Arc::new(NoPidRoles);
    let workers = Workers::new(Config {
        launcher: Arc::new(ImageLauncher {
            image,
            account,
            export_account,
            extra_args: Vec::new(),
        }),
        roles,
        report: Arc::new(|source: &str, detail: &str| {
            northnarrow_agent::boot::degradation::report(source, detail);
        }),
        kinds: if export_on {
            vec![WorkerKind::Parse, WorkerKind::Export]
        } else {
            vec![WorkerKind::Parse]
        },
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

/// R14b: this boot's deny hooks are attached and `PROTECTED_PIDS` pinned:
/// the workers' pids from now on (the running one at once) go there,
/// protected and not exempt.
pub(crate) fn arm(workers: &Workers) {
    let pins = std::path::Path::new(antitamper_bpf::DEFAULT_BPFFS_ROOT);
    if pins.join(antitamper_bpf::PROTECTED_PIDS_MAP_NAME).exists() {
        workers.arm_roles(Arc::new(PinnedPidRoles {
            bpffs_root: pins.to_path_buf(),
        }));
    } else {
        info!("no pinned PROTECTED_PIDS: the workers' pids are not registered with the deny hooks");
    }
}
