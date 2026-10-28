//! R09b shim (Wave 4 restructure, lab PR 254; plan §4.1 rule 2, removed in
//! R17): the sensors are nn-linux's — the embedded eBPF object and its boot
//! preflight (`build.rs` embeds it there), the single loader that attaches
//! every program and pumps every ring into one channel, the exec, file-open,
//! DNS, connect-deny and exploit-guard sensors, the ring drops and the
//! rejected records.
//!
//! The agent keeps the paths it had. The loader takes the exec guards whose
//! kernel configuration its load writes as a type parameter
//! (`nn_linux::sensors::multiplexer::ExecGuards`); the agent's are the exec
//! quarantine and the exec policy ([`crate::exec_guards`]), and
//! [`SensorMultiplexer`] is the loader on them (an alias without a
//! parameter, as the posture's on `LinuxHost`). `main.rs` and the tests are
//! unchanged.

// R11b (lab PR 262): without `EBPF_BYTES`, which only nn-linux's loaders
// read (they take the start's integrity proof).
pub use nn_linux::sensors::{
    connect_deny, dns_sensor, ebpf_object, epg, exe_identity, exec, flow_sock, multiplexer,
    open_sensor, reject, ring_drops, ExecSensor,
};

/// [`nn_linux::sensors::SensorMultiplexer`] on the agent's exec guards.
pub type SensorMultiplexer =
    nn_linux::sensors::SensorMultiplexer<crate::exec_guards::AgentExecGuards>;
