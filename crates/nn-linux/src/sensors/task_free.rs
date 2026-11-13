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

use std::collections::BTreeMap;

use aya::maps::{Array, MapData};
use aya::{Btf, Ebpf};

use anyhow::{anyhow, Context, Result};

/// The program (`#[lsm(hook = "task_free")]`).
pub const PROGRAM: &str = "nn_task_free";
/// Its hook.
pub const HOOK: &str = "task_free";
/// The map whose slot 0 says it runs.
pub const ARMED_MAP: &str = "TASK_FREE_ARMED";

/// The review of #547 (F9): [`PROGRAM`] attached and armed — by this
/// process (its `Ebpf` object is the agent's one). "Loaded" (an fd) is not
/// "attached": a load whose attach failed made the second caller return
/// as if it ran, and nothing removed the entries.
static ATTACHED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether [`PROGRAM`] is attached and armed.
pub fn attached() -> bool {
    ATTACHED.load(std::sync::atomic::Ordering::Acquire)
}

/// Attach [`PROGRAM`] unless it is attached, then arm it. `Ok(true)`: this
/// call attached it; `Ok(false)`: it was already. A program loaded by an
/// earlier call whose attach failed is attached again.
pub fn ensure(ebpf: &mut Ebpf, btf: &Btf) -> Result<bool> {
    if attached() {
        return Ok(false);
    }
    let loaded = ebpf.program(PROGRAM).is_some_and(|p| p.fd().is_ok());
    if loaded {
        let prog: &mut aya::programs::Lsm = ebpf
            .program_mut(PROGRAM)
            .ok_or_else(|| anyhow!("program {PROGRAM} missing from the eBPF object"))?
            .try_into()
            .context(PROGRAM)?;
        prog.attach().context("attaching task_free")?;
    } else {
        antitamper_bpf::attach_transient(ebpf, PROGRAM, HOOK, btf)?;
    }
    let map = ebpf
        .map_mut(ARMED_MAP)
        .ok_or_else(|| anyhow!("{ARMED_MAP} missing from the eBPF object"))?;
    let mut arr: Array<&mut MapData, u32> = Array::try_from(map).context(ARMED_MAP)?;
    arr.set(0, 1, 0).context("arming task_free")?;
    ATTACHED.store(true, std::sync::atomic::Ordering::Release);
    Ok(true)
}

/// The review of #547 (F4, F6): beside two maps whose entries outlive a run
/// — the exec quarantine's candidates (`EXECQ_CAND`) and the file-open
/// sensor's task buffers (`OPEN_TASK`) — the kernel keeps each uid's share
/// (`EXECQ_CAND_UIDS`, `OPEN_TASK_UIDS`: uid → entries), so that one user's
/// tasks cannot take every other user's room. It updates a share with a
/// plain read-modify-write (no atomics in the eBPF crate: the re-review of
/// #494, R1): two runs that update one uid's share at the same instant can
/// lose one update, and a uid that holds nothing keeps a row at 0. The
/// agent recounts the shares from the entries ([`rewrite_shares`]): a drift
/// up (the uid refused before its share is taken) or down lasts until the
/// next recount, and the rows of uids that hold nothing go. An entry made
/// or removed while the recount runs can leave its uid off by one until the
/// next.
pub fn uid_shares(uids: impl IntoIterator<Item = u32>) -> BTreeMap<u32, u64> {
    let mut out = BTreeMap::new();
    for uid in uids {
        *out.entry(uid).or_insert(0) += 1;
    }
    out
}

/// A map of shares (uid → entries), as [`rewrite_shares`] reads and writes
/// it (a trait, so a test can stand in a map).
pub trait ShareRows {
    fn rows(&self) -> Result<Vec<(u32, u64)>>;
    fn put(&mut self, uid: u32, n: u64) -> Result<()>;
    fn take_out(&mut self, uid: u32) -> Result<()>;
}

impl ShareRows for aya::maps::HashMap<MapData, u32, u64> {
    fn rows(&self) -> Result<Vec<(u32, u64)>> {
        // at most the map's room: a key removed under the walk restarts it
        Ok(self
            .iter()
            .take(SHARE_ROWS_MAX)
            .filter_map(|r| r.ok())
            .collect())
    }
    fn put(&mut self, uid: u32, n: u64) -> Result<()> {
        Ok(self.insert(uid, n, 0)?)
    }
    fn take_out(&mut self, uid: u32) -> Result<()> {
        match self.remove(&uid) {
            Ok(()) | Err(aya::maps::MapError::KeyNotFound) => Ok(()),
            Err(aya::maps::MapError::SyscallError(e))
                if e.io_error.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }
}

/// The re-check of #547 (G5): `want` without the overflow row
/// (`OVERFLOW_SHARE`: the entries of the shares the rows' map had no room
/// for), whose count is kept in a map of its own; returns that count.
pub fn take_overflow(want: &mut BTreeMap<u32, u64>) -> u64 {
    want.remove(&common::wire::execq::OVERFLOW_SHARE).unwrap_or(0)
}

/// The rows of a shares map (`EXECQ_CAND_UIDS`, `OPEN_TASK_UIDS`: 4096).
pub const SHARE_ROWS_MAX: usize = 4096;

/// What [`rewrite_shares`] changed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Rewritten {
    /// Rows set to their count (it had drifted, or was missing).
    pub corrected: usize,
    /// Rows of uids that hold nothing, removed.
    pub removed: usize,
    /// Writes that failed (the next recount tries again).
    pub failed: usize,
}

/// Rewrite `rows` to `want` ([`uid_shares`] of the entries): a row that
/// differs is set, a missing one added, the row of a uid that holds nothing
/// removed.
pub fn rewrite_shares(rows: &mut impl ShareRows, want: &BTreeMap<u32, u64>) -> Result<Rewritten> {
    let have: BTreeMap<u32, u64> = rows.rows()?.into_iter().collect();
    let mut out = Rewritten::default();
    for (uid, n) in &have {
        if want.contains_key(uid) {
            continue;
        }
        match rows.take_out(*uid) {
            Ok(()) if *n == 0 => out.removed += 1,
            Ok(()) => {
                out.removed += 1;
                out.corrected += 1;
            }
            Err(_) => out.failed += 1,
        }
    }
    for (uid, n) in want {
        if have.get(uid) == Some(n) {
            continue;
        }
        match rows.put(*uid, *n) {
            Ok(()) => out.corrected += 1,
            Err(_) => out.failed += 1,
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Rows(BTreeMap<u32, u64>, bool);
    impl ShareRows for Rows {
        fn rows(&self) -> Result<Vec<(u32, u64)>> {
            Ok(self.0.iter().map(|(k, v)| (*k, *v)).collect())
        }
        fn put(&mut self, uid: u32, n: u64) -> Result<()> {
            if self.1 {
                return Err(anyhow!("full"));
            }
            self.0.insert(uid, n);
            Ok(())
        }
        fn take_out(&mut self, uid: u32) -> Result<()> {
            self.0.remove(&uid);
            Ok(())
        }
    }

    /// The review of #547 (F4, F6): a share that drifted (a lost update),
    /// a uid that holds nothing, a uid missing — all set to the entries'
    /// count; a share already right is not written.
    #[test]
    fn the_uids_shares_are_recounted_from_the_entries() {
        let want = uid_shares([1000, 1000, 1000, 0, 33]);
        assert_eq!(want, BTreeMap::from([(0, 1), (33, 1), (1000, 3)]));
        let mut rows = Rows(
            BTreeMap::from([(0, 1), (1000, 1024), (65534, 0), (7, 2)]),
            false,
        );
        let r = rewrite_shares(&mut rows, &want).unwrap();
        assert_eq!(rows.0, want);
        assert_eq!(
            r,
            Rewritten {
                corrected: 3,
                removed: 2,
                failed: 0
            }
        );
        // a write the map refuses is counted, not hidden
        let mut full = Rows(BTreeMap::new(), true);
        let r = rewrite_shares(&mut full, &want).unwrap();
        assert_eq!(r.failed, 3);
        // the re-check of #547 (G5): the overflow row is counted apart
        let mut want = uid_shares([1000, common::wire::execq::OVERFLOW_SHARE, 1000]);
        assert_eq!(take_overflow(&mut want), 1);
        assert_eq!(want, BTreeMap::from([(1000, 2)]));
        assert_eq!(take_overflow(&mut want), 0);
    }

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
