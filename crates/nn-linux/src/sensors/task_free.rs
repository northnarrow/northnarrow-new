//! Lot 325 (the cost of the FIM sensor's per-task buffers; the re-check of
//! #546, R6): the LSM `task_free` program (`agent-ebpf/src/task_scratch.rs`,
//! `nn_task_free`). It removes, when the kernel frees a `task_struct`, the
//! entries keyed by that address that outlive one run of a program: the
//! file-open sensor's buffers (kept between a task's opens: one lookup per
//! open instead of an insert and a delete), the exec quarantine's candidate
//! (a plain hash, no longer an LRU) and the exec policy's note for its
//! post-commit check.
//!
//! Attached once, by whichever needs it first (the file-open sensor, the
//! exec quarantine, the exec policy); then `TASK_FREE_ARMED[0]` is set and
//! the sensor keeps its entries between runs. Without it the sensor removes
//! its entry at the end of each run, as before (correct, and costlier).

use aya::maps::{Array, MapData};
use aya::{Btf, Ebpf};

use anyhow::{anyhow, Context, Result};

/// The program (`#[lsm(hook = "task_free")]`).
pub const PROGRAM: &str = "nn_task_free";
/// Its hook.
pub const HOOK: &str = "task_free";
/// The map whose slot 0 says it runs.
pub const ARMED_MAP: &str = "TASK_FREE_ARMED";

/// Whether [`PROGRAM`] is loaded in `ebpf` (attached by [`ensure`]).
pub fn loaded(ebpf: &Ebpf) -> bool {
    ebpf.program(PROGRAM).is_some_and(|p| p.fd().is_ok())
}

/// Attach [`PROGRAM`] unless it is attached, then arm it. `Ok(true)`: this
/// call attached it; `Ok(false)`: it was already.
pub fn ensure(ebpf: &mut Ebpf, btf: &Btf) -> Result<bool> {
    if loaded(ebpf) {
        return Ok(false);
    }
    antitamper_bpf::attach_transient(ebpf, PROGRAM, HOOK, btf)?;
    let map = ebpf
        .map_mut(ARMED_MAP)
        .ok_or_else(|| anyhow!("{ARMED_MAP} missing from the eBPF object"))?;
    let mut arr: Array<&mut MapData, u32> = Array::try_from(map).context(ARMED_MAP)?;
    arr.set(0, 1, 0).context("arming task_free")?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The names match the eBPF object's (`agent-ebpf/src/task_scratch.rs`).
    #[test]
    fn the_names_are_the_object_s() {
        let src = include_str!(concat!(
            env!("NN_REPO_ROOT"),
            "/agent-ebpf/src/task_scratch.rs"
        ));
        assert!(src.contains("#[lsm(hook = \"task_free\")]\npub fn nn_task_free("));
        assert!(src.contains("pub(crate) static TASK_FREE_ARMED: Array<u32>"));
        assert_eq!(
            (PROGRAM, HOOK, ARMED_MAP),
            ("nn_task_free", "task_free", "TASK_FREE_ARMED")
        );
    }
}
