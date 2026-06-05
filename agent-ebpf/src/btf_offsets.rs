//! Kernel struct field offsets — re-exported from the single source.
//!
//! The constants (and the BUG-036 boot-time revalidation table) now
//! live in [`northnarrow_common::btf_offsets`] so the agent revalidates
//! the EXACT values these eBPF programs compile in — one source of
//! truth, no second copy to drift out of sync.
//!
//! aya-ebpf 0.1 emits no CO-RE field relocations, so each kernel
//! dereference in the LSM hooks / sensors still goes through one of
//! these byte offsets plus `bpf_probe_read_kernel`. Drift is caught at
//! the agent's boot (refuse-to-start), not here — these are the
//! fast-path values. This module preserves the `crate::btf_offsets::*`
//! import paths the hooks already use.

pub(crate) use northnarrow_common::btf_offsets::*;
