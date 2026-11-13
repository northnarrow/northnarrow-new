//! Sensors: kernel-side primitives that turn raw OS events into the
//! common [`Event`](nn_model::Event) enum consumed by the decision
//! engine.
//!
//! Tappa 4 introduces the [`SensorMultiplexer`]: a single owner of
//! the loaded eBPF object that attaches every program (process exec,
//! file open, exec validation, TCP connect v4/v6, DNS via UDP) and
//! exposes the decoded events on one bus — a queue per class of events
//! since R12a (lab PR 267, [`bus`]). The Tappa 1
//! [`ExecSensor`] is preserved as a thin compatibility wrapper so the
//! existing live integration test keeps working.

/// Lab PR 267 (R12a): the priority event bus between the sensors and the
/// event loop.
pub mod bus;
pub mod connect_deny;
/// R13 (lab PR 271): the sensor contract's Linux values, one entry per
/// source of the bus.
pub mod contract;
pub mod dns_sensor;
pub mod ebpf_object;
/// Lab PR 219: the exploit post-condition guard (loader, mode, counters).
pub mod epg;
pub mod exe_identity;
pub mod exec;
/// Lot 310: what the exec pump reads of an exec's process while it runs.
pub mod exec_facts;
pub mod flow_sock;
/// Lot 279: the exec pump's reading of a module tool's exec (R011).
pub mod kmod_exec;
pub mod multiplexer;
/// Lot 275 (C07): the inbound, DNS response and TLS ClientHello sensors'
/// attach, and the pumps of the last two.
pub mod net_telemetry;
pub mod open_sensor;
/// R12b (lab PR 269): the ring pumps on threads of their own.
pub mod pump;
pub mod reject;
pub mod ring_drops;
/// Lot 332 (the review of #551, F1): the subordinate uid ranges the shares'
/// key resolves a user's subuids through.
pub mod share_subuid;
/// Lot 325: the `task_free` program, which removes the entries that live as
/// long as their task.
pub mod task_free;

pub use exec::ExecSensor;
pub use multiplexer::SensorMultiplexer;
