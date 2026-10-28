//! The exec guards' kernel configuration, which the eBPF loader writes once
//! the exec sensor is attached (Wave 4 restructure, R09b, lab PR 254: cut
//! verbatim from `sensors::multiplexer`'s load, which calls it through its
//! [`ExecGuards`](crate::sensors::multiplexer::ExecGuards) seam). The exec
//! quarantine (lab PR 223) and the exec policy (lab PR 226) are the
//! agent's.

use aya::Ebpf;
use tracing::error;

use crate::sensors::multiplexer::ExecGuards;

/// The agent's exec guards: the exec quarantine, then the exec policy.
pub struct AgentExecGuards;

impl ExecGuards for AgentExecGuards {
    fn install(ebpf: &mut Ebpf) {
        // Lab PR 223 (EXPERIMENTAL): the exec quarantine's kernel
        // configuration, once the exec sensor's mode is known — written OFF
        // too, then frozen — and its maps for the controller. Not fatal:
        // an unwritten configuration is OFF, the kernel holds nothing.
        if let Err(e) = crate::execq::install(ebpf) {
            error!(
                error = format!("{e:#}"),
                "exec quarantine: kernel configuration failed — the guard is off"
            );
            if crate::execq::config().is_some_and(|c| c.mode != crate::execq::Mode::Off) {
                crate::execq::fail(format!("kernel configuration failed: {e:#}"));
            }
        }
        // Lab PR 226 (EXPERIMENTAL): the exec policy — its environment and
        // mapping programs, then its kernel configuration, written OFF too
        // and frozen. Not fatal: an unwritten configuration is OFF.
        let execq_on = crate::execq::config().is_some_and(|c| c.mode != crate::execq::Mode::Off)
            && !crate::execq::state().starts_with("degraded");
        if let Err(e) = crate::execpol::install(ebpf, execq_on) {
            error!(
                error = format!("{e:#}"),
                "exec policy: kernel configuration failed — the policy is off"
            );
            if crate::execpol::config().is_some_and(|c| c.mode != crate::execpol::Mode::Off) {
                crate::execpol::fail(format!("kernel configuration failed: {e:#}"));
            }
        }
    }
}
