//! Lot 341 (the alpha profile; the coordinator's decision of 13/11): the
//! userland half of the host-wide denies' switch (`agent-ebpf/src/
//! host_deny.rs`).
//!
//! The start's resolved no-enforcement gate (`nn_core::response::profile::
//! DetectOnly`: the `alpha` profile, `--detect-only`, `NN_DETECT_ONLY`;
//! `LoadPlan::host_deny_observe`) is written into `HOST_DENY_MODE`
//! right after the object loads, before any of its programs attaches, and
//! the map is frozen: no descriptor writes it again, the agent's included.
//! A write that fails leaves the map's zero — every host-wide deny refuses
//! (fail closed), and under the gate that is a signed degradation: the
//! tester's tools are refused although the profile observes.

use anyhow::{anyhow, Context, Result};
use aya::maps::{Array, MapData};
use aya::Ebpf;
use common::wire::{HOST_DENY_ENFORCE, HOST_DENY_OBSERVE};

/// The kernel's switch, by name in the object.
pub const MODE_MAP: &str = "HOST_DENY_MODE";

/// The gate's answer for the userland half of the host-wide guards — the
/// integrity round's and a window's close's put-back of the guarded
/// sysctls (`crate::sysctl_guard::check`): under the gate they write
/// nothing. Set by [`arm`] at the start; `false` (enforce) before it, as
/// every caller outside the agent's start (the tests) expects.
static OBSERVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether this start's gate leaves the host-wide guards in observe (the
/// kernel's and the round's alike).
pub fn observing() -> bool {
    OBSERVE.load(std::sync::atomic::Ordering::Acquire)
}

/// The value of [`MODE_MAP`] for the gate's answer.
pub const fn mode_value(observe: bool) -> u32 {
    if observe {
        HOST_DENY_OBSERVE
    } else {
        HOST_DENY_ENFORCE
    }
}

/// Write the gate's answer into [`MODE_MAP`] and freeze it.
pub fn arm(ebpf: &mut Ebpf, observe: bool) -> Result<()> {
    // the round's half first: it follows the gate whatever the kernel's
    // write does (a tester's sysctl is never put back under the gate)
    OBSERVE.store(observe, std::sync::atomic::Ordering::Release);
    {
        let map = ebpf
            .map_mut(MODE_MAP)
            .with_context(|| format!("{MODE_MAP} missing from the eBPF object"))?;
        let mut mode: Array<&mut MapData, u32> =
            Array::try_from(map).with_context(|| format!("{MODE_MAP} is not an Array<u32>"))?;
        mode.set(0, mode_value(observe), 0)
            .with_context(|| format!("writing {MODE_MAP}"))?;
    }
    super::bpf_defense::freeze_named(ebpf, MODE_MAP).map_err(|e| anyhow!("freezing {e}"))?;
    Ok(())
}

/// The boot line's words for the switch in force.
pub fn describe(observe: bool) -> &'static str {
    if observe {
        "OBSERVED (the observe-only gate): a foreign tracing BPF program's load, a cgroup/sysctl \
         program on the root cgroup, the kprobes and lockdown switches, a kexec image, the sysctl \
         guard, a cgroup v1 write and a ptrace of PID 1 go through, each signed \"would deny\" \
         (the round puts no guarded sysctl back); the agent's self-protection is enforced"
    } else {
        "ENFORCED: a foreign tracing BPF program's load, a cgroup/sysctl program on the root \
         cgroup, the kprobes and lockdown switches, a kexec image, the sysctl guard, a cgroup v1 \
         write and a ptrace of PID 1 are refused outside a trusted-installer window"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Named (lot 341): the gate's answer is the kernel's value; enforcing
    /// is the map's zero (an agent that could not write it enforces).
    #[test]
    fn the_gate_s_answer_is_the_kernel_s_mode() {
        assert_eq!(mode_value(true), HOST_DENY_OBSERVE);
        assert_eq!(mode_value(false), HOST_DENY_ENFORCE);
        assert_eq!(mode_value(false), 0);
        assert!(describe(true).contains("would deny"));
        assert!(describe(true).contains("self-protection is enforced"));
    }

    /// Named (lot 341): the switch is per load and never pinned — each
    /// start's programs read that start's mode, and a frozen map is never
    /// reused by a start that must write another value.
    #[test]
    fn the_switch_is_per_load_not_pinned() {
        let src = include_str!(concat!(
            env!("NN_REPO_ROOT"),
            "/agent-ebpf/src/host_deny.rs"
        ));
        assert!(
            src.contains("pub static HOST_DENY_MODE: Array<u32> = Array::with_max_entries(1, 0);")
        );
        assert!(!src.contains("Array::pinned("));
        assert!(src.contains(&format!("static {MODE_MAP}:")));
    }
}
