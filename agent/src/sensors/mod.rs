//! Sensors: kernel-side primitives that turn raw OS events into the
//! common [`crate::Event`] enum consumed by the decision engine.

pub mod exec;

pub use exec::ExecSensor;
