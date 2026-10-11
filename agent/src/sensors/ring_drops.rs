//! Userland side of the per-ring drop counters (`RING_DROPS` per-CPU map,
//! `common::ring_drops`). A sampler task sums the per-CPU values every
//! [`SAMPLE_SECS`], keeps the totals in process-wide atomics (read by the
//! admin socket for `nn-admin status`) and logs every increase at WARN
//! with the ring's name — a dropped event is a blind spot the operator
//! must see, not a silent counter.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use aya::maps::{MapData, PerCpuArray};
use aya::Ebpf;
use common::ring_drops::{RING_DROP_NAMES, RING_DROP_SLOTS};
use tracing::{debug, info, warn};

/// Sampling period.
pub const SAMPLE_SECS: u64 = 10;
/// Map name in the eBPF object.
pub const MAP_NAME: &str = "RING_DROPS";

static TOTALS: [AtomicU64; RING_DROP_SLOTS as usize] =
    [const { AtomicU64::new(0) }; RING_DROP_SLOTS as usize];

/// Cumulative drops per ring, `(name, count)`, every slot.
pub fn snapshot() -> Vec<(&'static str, u64)> {
    RING_DROP_NAMES
        .iter()
        .enumerate()
        .map(|(i, n)| (*n, TOTALS[i].load(Ordering::Relaxed)))
        .collect()
}

/// Only the rings that dropped something.
pub fn snapshot_nonzero() -> Vec<(String, u64)> {
    snapshot()
        .into_iter()
        .filter(|(_, c)| *c > 0)
        .map(|(n, c)| (n.to_string(), c))
        .collect()
}

/// Sum over every ring.
pub fn total() -> u64 {
    TOTALS.iter().map(|a| a.load(Ordering::Relaxed)).sum()
}

/// Sum the per-CPU values of every slot.
fn read_map(map: &PerCpuArray<MapData, u64>) -> Vec<u64> {
    (0..RING_DROP_SLOTS)
        .map(|slot| {
            map.get(&slot, 0)
                .map(|per_cpu| per_cpu.iter().sum::<u64>())
                .unwrap_or(0)
        })
        .collect()
}

/// Take the `RING_DROPS` map from the loaded object and start the
/// sampler. Missing map (an older object) is logged and ignored.
pub fn install(ebpf: &mut Ebpf) {
    let Some(map) = ebpf.take_map(MAP_NAME) else {
        warn!(
            map = MAP_NAME,
            "ring-drop counters not exported by the eBPF object — drops will not be counted"
        );
        return;
    };
    let map: PerCpuArray<MapData, u64> = match PerCpuArray::try_from(map) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, map = MAP_NAME, "ring-drop map has an unexpected type — drops will not be counted");
            return;
        }
    };
    info!(
        rings = RING_DROP_SLOTS,
        every_secs = SAMPLE_SECS,
        "ring-drop counters armed"
    );
    tokio::spawn(async move {
        let mut prev = vec![0u64; RING_DROP_SLOTS as usize];
        loop {
            tokio::time::sleep(Duration::from_secs(SAMPLE_SECS)).await;
            let now = read_map(&map);
            for (i, (&n, &p)) in now.iter().zip(prev.iter()).enumerate() {
                TOTALS[i].store(n, Ordering::Relaxed);
                if n > p {
                    warn!(
                        ring = RING_DROP_NAMES[i],
                        dropped_since_last_sample = n - p,
                        total = n,
                        "ring-buffer events DROPPED — the consumer fell behind; events of this sensor were lost"
                    );
                }
            }
            prev = now;
            debug!(total = total(), "ring-drop sample");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_names_match_slots_and_nonzero_filters() {
        let s = snapshot();
        assert_eq!(s.len(), RING_DROP_SLOTS as usize);
        assert_eq!(s[0].0, "exec");
        assert_eq!(s[10].0, "dns");
        // totals start at zero in a fresh process
        assert!(snapshot_nonzero().is_empty());
        assert_eq!(total(), 0);
    }
}
