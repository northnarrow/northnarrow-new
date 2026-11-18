//! The log stream, the start's first lines (R11a, lab PR 261: from
//! `main.rs`'s `run`).

use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use super::cli::Cli;

/// The log stream (one event, one journal line: lab PR 167), then what the
/// start says before anything else — the removed advisor's settings, a
/// core-dump guard that failed, the OOM adjustment (R11a, lab PR 261:
/// `run`'s first lines).
pub(crate) fn init(cli: &Cli, undumpable: std::io::Result<()>) {
    // Lab finding (external audit EBPF-001 work): when the log stream is
    // gone — journald@northnarrow stopped, at shutdown or by root — the
    // fmt layer reported the failed write with `eprintln!`, which panics
    // on the same broken pipe; with `panic = "abort"` the agent died at its
    // next log line, and five such deaths tripped the watchdog's ceiling.
    // A lost log line must never cost the agent.
    // External audit Wave 3 (journal line injection, lab PR 167): one event
    // is one journal line whatever it holds, with no colour codes under
    // journald (nn_model::log_escape).
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .with_ansi(nn_model::log_escape::stdout_ansi())
        .with_writer(nn_model::log_escape::stdout_one_line)
        .log_internal_errors(false)
        .init();

    info!("NorthNarrow agent starting...");
    // Wave 4 (lab PR 214): the settings of the removed LLM advisor that an
    // older unit or drop-in still passes, each named, none fatal.
    northnarrow_agent::removed_settings::warn_removed(
        &cli.removed_flags(),
        &northnarrow_agent::removed_settings::removed_env_in_process(),
    );
    // Lab PR 216: a failure is an ERROR, not a refusal to protect.
    if let Err(e) = undumpable {
        error!(
            error = %e,
            "could not forbid core dumps (PR_SET_DUMPABLE 0, RLIMIT_CORE 0): a crash may write \
             the agent's memory, keys included, to disk"
        );
    }
    // Lot 370 (F10-4): never a candidate of the OOM killer — the unit's
    // OOMScoreAdjust=-999, written again whoever started the agent (the
    // self-integrity check expects it). It replaces external audit
    // DEP-005's raise to 0 where the memory cap cannot bind: the OOM
    // killer's SIGKILL, which no hook refuses, made the agent's role vacant
    // at a moment root could choose.
    match antitamper_bpf::pin_oom_score_adj() {
        Ok(None) => {}
        Ok(Some(from)) => tracing::info!(
            from,
            to = antitamper_bpf::PINNED_OOM_SCORE_ADJ,
            "oom_score_adj pinned: the host OOM killer's last pick (its memory cap still ends a leak)"
        ),
        Err(e) => error!(
            error = %e,
            "oom_score_adj NOT pinned: the OOM killer can take the agent (the self-integrity \
             check reports the value)"
        ),
    }
}
