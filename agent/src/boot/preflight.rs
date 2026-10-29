//! `BootPhase::Preflight`, its first checks (R11a, lab PR 261: from
//! `main.rs`): the embedded eBPF object, the state directory, the kernel's
//! offsets from its BTF, the rlimits, the chains against their heads; and
//! `--btf-check`, the same resolution against another kernel's BTF.

use std::path::PathBuf;

use anyhow::Result;
use northnarrow_agent::anti_tamper::btf_revalidate::{
    publish_resolved, resolve_tracepoint_fields, RefuseReason, ResolveOutcome,
};
use northnarrow_agent::boot::checks::{self, Verdict};
use northnarrow_agent::boot::{BootSequence, BootStep};
use tracing::{error, info, warn};

use super::cli::Cli;
use super::refusal::{self, Refusal};

/// What [`check`] found, for the state files' bootstrap, the
/// identity and the attest phase.
pub(crate) struct Preflight {
    /// R11b (lab PR 262): the first of the eBPF object, the state directory
    /// and the BTF offsets that refused the start. The refusal is signed,
    /// with the identity read and the start registered, at the start of the
    /// integrity phase — before anything is loaded; the state files are not
    /// bootstrapped (review #466 F8).
    pub(crate) refused: Option<Refusal>,
    /// The start's phases (lab PR 218), opened by the preflight.
    pub(crate) boot: BootSequence,
    /// The review of #468, R4: the start's signing key, decided by the
    /// preflight's `signing_identity` and loaded once, at its first use: what
    /// every chain of the start signs with.
    pub(crate) signing_key: northnarrow_agent::keys::BootKey,
    /// Tracepoint fields left on their compiled offset (NN-AUD-098), signed
    /// once the audit log is open.
    pub(crate) tracepoint_degraded: Option<String>,
    /// LSM hook arguments whose position was not resolved (lab PR 164),
    /// signed once the audit log is open.
    pub(crate) hook_args_degraded: Option<String>,
    /// The chains' head anchor.
    pub(crate) heads_file: PathBuf,
    /// The chains the agent anchors.
    pub(crate) chain_targets: Vec<northnarrow_agent::chain_anchor::ChainTarget>,
    /// The chains against their anchored heads (lab PR 160).
    pub(crate) boot_chains: northnarrow_agent::chain_anchor::BootCheck,
    /// The signed overlays' rollback floor (LLMR-014).
    pub(crate) rollback_floor: northnarrow_agent::config::overlay_floor::RollbackFloor,
}

/// `BootPhase::Preflight`, its first checks: the embedded eBPF object, the
/// state directory, the kernel's offsets from its BTF (R11b, lab PR 262: a
/// refusal is kept in [`Preflight::refused`], signed and exited 78 at the
/// start of the integrity phase), the rlimits, the chains against their
/// heads and the overlays' rollback floor — nothing written yet, nothing
/// loaded into the kernel.
pub(crate) fn check(cli: &Cli) -> Result<Preflight> {
    // Lab PR 218 (external review G-09 / Q11-03): the start's phases, in an
    // order the code enforces (`northnarrow_agent::boot`). Preflight —
    // checks only — until `verify_integrity` hands out the proof the load,
    // the pins and the attaches take; a step out of its phase stops the
    // start. R11b (lab PR 262): the steps the proof requires are recorded by
    // their checks (`boot::checks`), each once it passed. Review #466 F3:
    // the process's one sequence — a second `begin` is refused.
    let mut boot = BootSequence::begin()?;

    // Lab PR 265 (review #466 F4-bis): first, before anything is read or
    // written — the start is the agent that ran before. A mount laid over
    // its own directories (a bind on the host, a runtime drop-in's
    // `BindPaths=` / `TemporaryFileSystem=`) hides the files it had, and its
    // key absent where an earlier identity is on record was removed or is
    // hidden: either way the start would mint a new key and restart every
    // chain under it. Refused at once, unsigned (nothing can sign them: the
    // key is the one hidden), before the registration, the bootstraps and
    // the identity read.
    let state_dirs = cli.state_dirs();
    let state_dirs: Vec<&std::path::Path> = state_dirs.iter().map(PathBuf::as_path).collect();
    if let Verdict::Refused(why) = checks::agent_mounts(&mut boot, &state_dirs)? {
        error!("refusing to start: {why}");
        refusal::refuse_unsigned(
            Refusal::new("agent_mounts", why),
            "a mount hides the agent's own files: a chain opened now would be in the view the \
             start refuses",
        );
    }
    // The review of #468, R4: the key is decided here, once — there (loaded,
    // never minted) or a first install's (minted once) —, and loaded once,
    // at its first use (the state files' bootstrap): every chain of the
    // start signs with that one key (`keys::BootKey`), none loads its own.
    let decision = match checks::signing_identity(&mut boot, &cli.identity_paths())? {
        checks::KeyVerdict::Decided(decision) => decision,
        checks::KeyVerdict::Refused(why) => {
            error!("refusing to start: {why}");
            refusal::refuse_unsigned(
                Refusal::new("signing_identity", why),
                "the agent's signing key is absent and a new one is not minted",
            );
        }
    };
    let signing_key = northnarrow_agent::keys::BootKey::decided(decision);

    // Boot preflight: prove the embedded eBPF half is real and intact
    // BEFORE doing any work. The build-time staleness guard
    // (agent/build.rs) refuses to embed a *stale* object; this refuses
    // to *start* on an *absent* (placeholder) or *corrupted* one. Fail
    // fast and loud — running without a matching kernel half would
    // silently disable every sensor, the anti-tamper LSM hooks, and
    // R011's PF_KTHREAD signal (the exact blindness that let R011
    // over-fire when a stale .o was embedded by a workspace build).
    let mut refused: Option<Refusal> = None;
    if let Verdict::Refused(why) = checks::ebpf_object(&mut boot)? {
        error!(error = %why, "eBPF object boot preflight failed — refusing to start");
        refused.get_or_insert(Refusal::new("ebpf_object", why));
    }
    // External audit ATP-007 (NN-AUD-260): the state directory, or one of
    // the agent's own entries in it, is not a symbolic link — checked before
    // anything below reads or writes there (the bootstraps would create
    // files in a link's target, the attach would protect it).
    let mut state_dir_linked = false;
    if let Verdict::Refused(why) = checks::state_dir(&mut boot)? {
        error!("{why}");
        state_dir_linked = true;
        refused.get_or_insert(Refusal::new("state_dir", why));
    }

    // External audit NN-AUD-098: tracepoint fields left on their compiled
    // offset, attested once the audit log is open.
    let mut tracepoint_degraded: Option<String> = None;
    // Lab PR 164: an LSM hook argument whose position was not resolved,
    // attested once the audit log is open.
    let mut hook_args_degraded: Option<String> = None;

    // BUG-036: revalidate every compiled-in kernel struct offset against
    // the RUNNING kernel's BTF before attaching any program. aya-ebpf has
    // no CO-RE, so these offsets are baked into the eBPF half; if the
    // running kernel's layout differs, the LSM hooks and sensors read the
    // WRONG kernel memory — silently corrupting every decision. Fail
    // CLOSED + LOUD rather than attach hooks that read garbage. Exit 78
    // (EX_CONFIG) so the Restart=no agent unit lands in a VISIBLE `failed`
    // state; the watchdog's 5/60s restart ceiling bounds any respawn.
    match checks::btf_offsets(&mut boot)? {
        ResolveOutcome::Resolved(r) => {
            if r.drifted.is_empty() {
                info!(
                    count = r.values.len(),
                    "BTF offsets resolved from the running kernel — all match the compiled-in values"
                );
            } else {
                info!(
                    count = r.values.len(),
                    drifted = r.drifted.len(),
                    "BTF offsets resolved from the running kernel — layout differs from the build \
                     kernel; the eBPF programs will read the resolved values (multi-kernel, level 1)"
                );
                for m in &r.drifted {
                    info!(
                        offset = m.name,
                        kernel_struct = m.struct_name,
                        compiled = m.expected,
                        runtime = ?m.actual,
                        "  offset resolved"
                    );
                }
            }
            for m in &r.absent {
                let effect = if m.struct_name.starts_with("btrfs_") {
                    "files on btrfs keep the superblock's device in their inode keys, so FIM \
                     and file protection do not match them (review 55)"
                } else if m.struct_name.starts_with("bpf_lsm_") {
                    // Lab PR 164: the programs reading it are not attached;
                    // a missing deny hook refuses the start unless
                    // NN_ANTI_TAMPER_ALLOW_DEGRADED=1.
                    northnarrow_agent::anti_tamper::btf_revalidate::hook_arg_effect(m.struct_name)
                } else {
                    "DNS QNAME decoding needs iov_iter.iter_type + ITER_UBUF/ITER_IOVEC"
                };
                warn!(
                    offset = m.name,
                    kernel_struct = m.struct_name,
                    detail = %m.detail,
                    effect,
                    "optional kernel field absent on this kernel — the dependent sensor path \
                     is disabled"
                );
            }
            info!(
                setattr_dentry_arg = ?r.setattr_dentry_arg(),
                setxattr_dentry_arg = ?r.hook_arg_position("INODE_SETXATTR_DENTRY_ARG"),
                removexattr_dentry_arg = ?r.hook_arg_position("INODE_REMOVEXATTR_DENTRY_ARG"),
                hook_args_checked = r.hook_args_checked,
                optional_deny_hooks = ?r.optional_deny_hooks,
                "LSM hook prototypes read from the running kernel — the fixed-position \
                 arguments are where the programs read them (lab PR 164)"
            );
            hook_args_degraded = r.hook_args_degraded_detail();
            for module in &r.modules_not_loaded {
                info!(
                    module,
                    "kernel module not loaded: no file on this host uses it, its offsets stay \
                     unset (btrfs: inode keys need no subvolume device, review 55)"
                );
            }
            // Tracepoint field offsets come from tracefs, not BTF: the
            // common header differs on vendor kernels (RHEL 9 shifts every
            // field by 4 — the exec sensor read an empty filename there).
            let mut r = r;
            let tp = resolve_tracepoint_fields();
            for (name, compiled, runtime) in &tp.drifted {
                info!(
                    offset = name,
                    compiled,
                    runtime,
                    "tracepoint field offset resolved from tracefs — differs from the build kernel"
                );
            }
            for (root, reason) in &tp.skipped_roots {
                warn!(
                    root = %root,
                    reason = %reason,
                    "tracefs root not used for tracepoint offsets — the filesystem there is not \
                     tracefs (external audit NN-AUD-098)"
                );
            }
            for (name, reason) in &tp.unresolved {
                warn!(
                    offset = name,
                    reason = %reason,
                    "tracepoint field offset NOT resolved — compiled-in value in use; on a kernel \
                     with a different tracepoint header the exec/open sensors read wrong bytes"
                );
            }
            tracepoint_degraded = tp.degraded_detail();
            r.values.extend(tp.values);
            publish_resolved(r);
        }
        ResolveOutcome::SkippedNoBtf { reason } => {
            warn!(
                reason,
                "BTF unavailable — offsets cannot be resolved. The LSM hooks require BTF \
                 to attach, so they will not attach this boot; whatever attaches uses the \
                 compiled-in offsets."
            );
        }
        ResolveOutcome::Refuse(reason) => {
            // sysexits.h EX_CONFIG: a non-zero code systemd surfaces as a
            // `failed` unit (Restart=no ⇒ no auto-restart loop). R11b (lab
            // PR 262): the refusal is signed at the start of the integrity
            // phase, before anything is loaded, then the start exits.
            const EX_CONFIG: i32 = super::refusal::EX_CONFIG;
            let detail = match &reason {
                RefuseReason::Drift(missing) => format!(
                    "BTF offset resolution failed: {} field(s), enumerator(s) or hook argument(s) \
                     the eBPF programs read are not on this kernel: {}",
                    missing.len(),
                    missing
                        .iter()
                        .map(|m| format!("{} ({}): {}", m.name, m.struct_name, m.detail))
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
                RefuseReason::ParseError(e) => format!("BTF present but unparseable: {e}"),
            };
            match reason {
                RefuseReason::Drift(missing) => {
                    error!(
                        count = missing.len(),
                        "BTF offset resolution FAILED — refusing to start. The running \
                         kernel does not expose a field the eBPF programs read, or an LSM \
                         hook's prototype no longer has an argument where its program reads \
                         it; attaching LSM hooks would read the wrong kernel memory (BUG-036)."
                    );
                    for m in &missing {
                        error!(
                            offset = m.name,
                            kernel_struct = m.struct_name,
                            detail = %m.detail,
                            "  field unresolvable"
                        );
                    }
                    error!(
                        "Fail-closed safety gate (BUG-036): this kernel needs a field \
                         variant in common::btf_offsets (multi-kernel, level 2). Exiting {EX_CONFIG}."
                    );
                }
                RefuseReason::ParseError(e) => {
                    error!(
                        error = %e,
                        "BTF present but unparseable — refusing to start. Cannot resolve \
                         kernel offsets, and aya may still attach hooks with unverified \
                         offsets. Fail-closed (BUG-036). Exiting {EX_CONFIG}."
                    );
                }
            }
            refused.get_or_insert(Refusal::new("btf_offsets", detail));
        }
    }

    // The COMBAT ladder holds a pidfd per attributed offender (external
    // audit CMB-004), up to its cap of 1 024, on top of the agent's own
    // ~140 descriptors: a soft limit of 1 024 (systemd's default) ran out
    // in the lab ("Too many open files" in the quarantine).
    match raise_nofile_rlimit() {
        Ok(n) => info!(open_files = n, "RLIMIT_NOFILE soft limit raised"),
        Err(e) => {
            warn!(error = %e, "failed to raise RLIMIT_NOFILE; a large COMBAT episode may exhaust descriptors")
        }
    }
    if let Err(e) = bump_memlock_rlimit() {
        warn!(error = %e, "failed to raise RLIMIT_MEMLOCK; eBPF maps may fail to allocate");
    }

    // External audit NN-AUD-108 / NN-AUD-109 / NN-AUD-174 (lab PR 160): the
    // chains compared with their anchored heads and manifest checkpoints,
    // before any writer opens them (O(1) per file). The findings are
    // attested once the audit log is open; a cut audit chain resets the
    // overlay rollback floor below.
    let heads_file = cli.resolved_chain_heads_file();
    let chain_targets = cli.chain_paths().targets();
    let boot_chains = match northnarrow_agent::keys::boot_verifying_key(&cli.signing_key_file) {
        // R11b (lab PR 262): a refused state directory is not read through
        // its link (the chains under it), the start exits before the attest
        _ if state_dir_linked => northnarrow_agent::chain_anchor::BootCheck::default(),
        Some(pk) => northnarrow_agent::chains::boot_check(&chain_targets, &heads_file, &pk),
        None => {
            info!("chain heads: no agent key yet (fresh install) — nothing anchored to check");
            northnarrow_agent::chain_anchor::BootCheck::default()
        }
    };
    // External audit LLMR-014: the signed overlays' rollback floor, from the
    // audit chain as this boot found it — verified, and read before the key
    // and the log below are bootstrapped (a log found missing must not look
    // like a fresh install).
    let rollback_floor = northnarrow_agent::config::overlay_floor::RollbackFloor::scan(
        &cli.audit_log_file,
        &cli.signing_key_file,
    );
    let rollback_floor = match boot_chains.audit_history_lost() {
        Some(why) => rollback_floor.reset_because(why),
        None => rollback_floor,
    };
    boot.done(BootStep::ChainHeads)?;
    Ok(Preflight {
        refused,
        boot,
        signing_key,
        tracepoint_degraded,
        hook_args_degraded,
        heads_file,
        chain_targets,
        boot_chains,
        rollback_floor,
    })
}

/// Raise the soft `RLIMIT_NOFILE` to the hard limit (at most 65 536).
/// Returns the new soft limit.
fn raise_nofile_rlimit() -> std::io::Result<u64> {
    let mut rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: a valid `rlimit` to fill.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let want = rlim.rlim_max.min(65_536);
    if rlim.rlim_cur >= want {
        return Ok(rlim.rlim_cur);
    }
    rlim.rlim_cur = want;
    // SAFETY: a valid `rlimit` passed by reference; the kernel only reads it.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(want)
}

/// Raise `RLIMIT_MEMLOCK` to infinity so older kernels accept large
/// eBPF map allocations. Best-effort: failure is logged and ignored.
fn bump_memlock_rlimit() -> std::io::Result<()> {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: a valid `rlimit` is passed by reference; the kernel only
    // reads from it. Failure is reported via the return code.
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// `--btf-check`: resolve the runtime offset table against a BTF file and
/// print a one-line verdict plus every drifted or missing entry.
pub(crate) fn btf_check(path: &std::path::Path) -> i32 {
    use northnarrow_agent::anti_tamper::btf_revalidate::resolve_offsets_from;
    match resolve_offsets_from(path) {
        ResolveOutcome::Resolved(r) => {
            println!(
                "btf-check {}: {} — {} slots resolved, {} differ from the build kernel, {} absent, {} hook arguments checked",
                path.display(),
                if r.absent.is_empty() {
                    "SUPPORTED"
                } else {
                    "SUPPORTED (degraded)"
                },
                r.values.len(),
                r.drifted.len(),
                r.absent.len(),
                r.hook_args_checked
            );
            for m in &r.absent {
                let effect = if m.struct_name.starts_with("bpf_lsm_") {
                    format!(
                        "not attached: {} (the agent starts only with NN_ANTI_TAMPER_ALLOW_DEGRADED=1)",
                        northnarrow_agent::anti_tamper::btf_revalidate::hook_arg_effect(m.struct_name)
                    )
                } else {
                    "dependent sensor path disabled".to_string()
                };
                println!(
                    "  absent  {:<34} {:<12} {} — {effect}",
                    m.name, m.struct_name, m.detail
                );
            }
            // Lab PR 174: the deny hooks only some kernels have, counted
            // as expected where the BTF has them.
            for (hook, present) in &r.optional_deny_hooks {
                let verdict = if *present {
                    format!(
                        "present — bpf_lsm_{hook} in the BTF: its deny program attaches and counts as an expected deny hook"
                    )
                } else {
                    format!("absent  — no bpf_lsm_{hook} in the BTF: no deny program on it, not expected")
                };
                println!("  optional {hook:<33} {verdict}");
            }
            for module in &r.modules_not_loaded {
                println!(
                    "  module  {module:<34} no BTF next to the vmlinux file — its types' offsets stay unset (not a degradation)"
                );
            }
            for m in &r.drifted {
                println!(
                    "  drift   {:<34} {:<12} compiled={:<6} runtime={}",
                    m.name,
                    m.struct_name,
                    m.expected,
                    m.actual
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "?".into())
                );
            }
            0
        }
        ResolveOutcome::SkippedNoBtf { reason } => {
            println!("btf-check {}: UNREADABLE — {reason}", path.display());
            3
        }
        ResolveOutcome::Refuse(RefuseReason::Drift(missing)) => {
            println!(
                "btf-check {}: NOT SUPPORTED — {} field(s)/enumerator(s)/hook argument(s) missing (the agent would refuse to start)",
                path.display(),
                missing.len()
            );
            for m in &missing {
                println!(
                    "  missing {:<34} {:<12} {}",
                    m.name, m.struct_name, m.detail
                );
            }
            2
        }
        ResolveOutcome::Refuse(RefuseReason::ParseError(e)) => {
            println!("btf-check {}: UNPARSEABLE — {e}", path.display());
            3
        }
    }
}
