
/// The log stream (one event, one journal line: lab PR 167), then what the
/// start says before anything else — the removed advisor's settings, a
/// core-dump guard that failed, the OOM adjustment (R11a, lab PR 261:
/// `run`'s first lines).
fn boot_logging(cli: &Cli, undumpable: std::io::Result<()>) {
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
    // External audit DEP-005 (NN-AUD-381): on a host where the unit's
    // memory cap cannot bind, the unit's OOMScoreAdjust=-500 is raised to 0
    // before anything grows (the self-integrity check expects it there).
    northnarrow_agent::self_integrity::relax_oom_score_adj();
}
