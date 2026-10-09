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

use aya_ebpf::{macros::map, maps::Array};
use northnarrow_common::btf_offsets::{BTF_OFFSETS_MAGIC, BTF_OFFSETS_SLOTS};

/// Runtime offset table, written by the agent before any program is
/// attached (multi-kernel, level 1). Slot 0 carries
/// [`BTF_OFFSETS_MAGIC`] once every slot is valid; until then [`rt`]
/// returns the compiled-in constant, so an unarmed map behaves exactly
/// like the build before runtime offsets existed.
#[map]
pub static BTF_OFFSETS: Array<u32> = Array::with_max_entries(BTF_OFFSETS_SLOTS, 0);

/// Offset for `slot`, resolved from the running kernel's BTF by the
/// agent, or `default` (the compiled-in constant) when the map is not
/// armed. Always inlined: two bounded array reads per use.
#[inline(always)]
pub fn rt(slot: u32, default: usize) -> usize {
    match BTF_OFFSETS.get(0) {
        Some(magic) if *magic == BTF_OFFSETS_MAGIC => match BTF_OFFSETS.get(slot) {
            Some(v) => *v as usize,
            None => default,
        },
        _ => default,
    }
}

/// `off!(FOO_OFFSET)` → the runtime value of that offset (see [`rt`]).
/// The constant stays referenced (it is the fallback), so the existing
/// `use crate::btf_offsets::FOO_OFFSET` imports remain in use.
macro_rules! off {
    ($name:ident) => {
        $crate::btf_offsets::rt($crate::btf_offsets::slot::$name, $name)
    };
}
