//! `nn-linux` — the Linux adapters: the eBPF loader and sensors, /proc, the
//! actuators, self-defence, systemd, the KeyStore and the sandbox.
//!
//! Why a crate of its own: the one place for aya, /proc, cgroups, netfilter,
//! systemd and keys on disk; another OS would be a sibling crate. The adapters
//! move here in R09.
//!
//! Created empty by the Wave 4 restructure, R01 (lab PR 239); the crates it may
//! depend on, and the rules of the pure crates, are in
//! docs/architecture/module-map.toml, checked by
//! xtask/tests/workspace_layers.rs.
