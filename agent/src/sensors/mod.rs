//! Sensors: kernel-side primitives that turn raw OS events into the
//! common [`Event`](common::Event) enum consumed by the decision
//! engine.
//!
//! Tappa 4 introduces the [`SensorMultiplexer`]: a single owner of
//! the loaded eBPF object that attaches every program (process exec,
//! file open, exec validation, TCP connect v4/v6, DNS via UDP) and
//! exposes a single tokio mpsc channel of decoded events. The Tappa 1
//! [`ExecSensor`] is preserved as a thin compatibility wrapper so the
//! existing live integration test keeps working.

pub mod ebpf_object;
pub mod exec;
pub mod multiplexer;

pub use ebpf_object::EBPF_BYTES;
pub use exec::ExecSensor;
pub use multiplexer::SensorMultiplexer;
