//! `BootPhase::Run`, its first steps: the capability manifest and the trust
//! level signed, then READY (R11a, lab PR 261: from `main.rs`'s `run`).

use anyhow::Result;
use northnarrow_agent::boot::{BootPhase, BootSequence, BootStep};
use tracing::{debug, info, warn};

use super::evidence::AuditHandle;

/// The boot is over: the capability manifest and the trust level are
/// signed and systemd was told the agent is ready ([`arm`]); the
/// event loop takes it.
pub(crate) struct Armed {
    _private: (),
}

/// `BootPhase::Run` (lab PR 218, external review G-12): every attach of the
/// boot is done — the capability manifest and the trust level are signed
/// before systemd hears the agent is ready (`sd_notify`), then the boot's
/// transient heap goes back to the kernel (lab PR 231).
#[allow(clippy::too_many_arguments)]
pub(crate) fn arm(
    boot: &mut BootSequence,
    bpf_lsm_state: northnarrow_agent::boot::lsm::BpfLsm,
    self_test: northnarrow_agent::boot::deny_selftest::SelfTestOutcome,
    trust_inputs: &northnarrow_agent::boot::trust::TrustInputs,
    anti_tamper: &northnarrow_agent::anti_tamper::AttachReport,
    host_checks: Vec<northnarrow_agent::host_hardening::Check>,
    detect_only: bool,
    audit_log: &AuditHandle,
    capability_manifest: &northnarrow_agent::boot::manifest::SignedManifest,
) -> Result<Armed> {
    // Lab PR 218 (external review G-12): every attach of this boot is done.
    // The capability manifest — kernel, BTF, LSMs, deny hooks, self-test,
    // sensors, host hardening, degradations — and the trust level are
    // signed before systemd hears the agent is ready.
    boot.enter(BootPhase::Run)?;
    {
        use northnarrow_agent::boot::manifest;
        // R11c (lab PR 264): what the attach and the self-test measured, as
        // the phases hand it on (process-wide statics until then).
        let deny = anti_tamper.deny.clone().unwrap_or_default();
        let resolved = northnarrow_agent::anti_tamper::btf_revalidate::resolved();
        let trust =
            northnarrow_agent::boot::trust::current(Some(trust_inputs)).unwrap_or_else(|| {
                northnarrow_agent::boot::trust::Trust {
                    level: northnarrow_agent::boot::trust::TrustLevel::L0,
                    reasons: vec!["the boot measured nothing".to_string()],
                }
            });
        let m = manifest::CapabilityManifest {
            manifest_version: manifest::MANIFEST_VERSION,
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            kernel: manifest::kernel_release(),
            btf: std::path::Path::new("/sys/kernel/btf/vmlinux").exists(),
            btf_offsets_resolved: resolved.map_or(0, |r| r.values.len()),
            btf_offsets_drifted: resolved.map_or(0, |r| r.drifted.len()),
            btf_offsets_absent: resolved
                .map(|r| r.absent.iter().map(|m| m.name.to_string()).collect())
                .unwrap_or_default(),
            active_lsms: bpf_lsm_state.list().map(str::to_string),
            bpf_lsm: bpf_lsm_state.label().to_string(),
            deny_hooks: manifest::DenyHooks {
                expected: deny.expected,
                attached: deny.attached,
                missing: deny.missing,
                observe_missing: deny.observe_missing,
            },
            deny_self_test: self_test.describe(),
            bpf_guard: if northnarrow_agent::anti_tamper::bpf_defense::enforce_mode() {
                "enforce"
            } else {
                "observe"
            }
            .to_string(),
            sensors: manifest::sensors(),
            host_hardening: manifest::host_checks(&host_checks),
            detect_only,
            degradations: northnarrow_agent::boot::degradation::snapshot(),
            trust_level: trust.level.as_u8(),
            trust_reasons: trust.reasons.clone(),
        };
        if trust.level < northnarrow_agent::boot::trust::TrustLevel::L3 {
            warn!(
                trust_level = trust.level.name(),
                meaning = trust.level.meaning(),
                reasons = %trust.reasons.join("; "),
                "trust level below L3"
            );
        } else {
            info!(
                trust_level = trust.level.name(),
                "trust level L3: every mandatory deny hook attached and self-tested, nothing degraded"
            );
        }
        capability_manifest.sign(audit_log.as_ref(), m);
    }
    boot.done(BootStep::CapabilityManifest)?;
    northnarrow_agent::boot::degradation::mark_boot_over();

    // T7.10: the unit is `Type=notify`; tell systemd we are ready now
    // that every subsystem is wired (anti-tamper attached, decision
    // engine loaded, drains + admin socket spawned, signal
    // handlers installed) and we are about to enter the event loop.
    // Without this, systemd holds the unit `activating` until
    // `TimeoutStartSec` then marks it failed — and the agent's own
    // anti-tamper hook denies the resulting SIGTERM, stranding the
    // unit `failed` while the process runs and dragging the watchdog
    // down via `BindsTo`. No-op when not under systemd (NOTIFY_SOCKET
    // unset), so dev runs and tests are unaffected. Non-fatal: a send
    // failure is logged, not propagated — a healthy agent must not
    // refuse to run just because the readiness ping didn't land.
    if let Err(e) = northnarrow_agent::sd_notify::ready() {
        warn!(error = %e, "sd_notify(READY=1) failed; systemd may report the unit as not-ready");
    }
    // Lab PR 231: the boot's transient heap (the vmlinux BTF parses of the
    // attach) back to the kernel; under aya 0.14 glibc kept it.
    let released = northnarrow_agent::boot::release_boot_heap();
    debug!(released, "boot heap released after READY (malloc_trim)");
    Ok(Armed { _private: () })
}
