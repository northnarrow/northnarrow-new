//! Lab PR 164: how full the kernel's `FLOW_SOCK_MAP` is.
//!
//! The TCP connect kprobes remember each outbound socket in `FLOW_SOCK_MAP`
//! (an LRU of [`FLOW_SOCK_MAP_MAX_ENTRIES`]) until its close. Beyond the
//! capacity the LRU forgets the least recently used socket, a long session
//! first, and that socket's close is never recorded. An LRU does not report
//! what it evicts, so the programs count instead (`FLOW_SOCK_COUNTS`, a
//! per-CPU array): sockets entered as a new key, sockets a close took out.
//! A sampler sums them every [`SAMPLE_SECS`]:
//!
//! - `pending` = entered − taken out: the sockets whose close has not been
//!   seen, open sessions and forgotten ones together;
//! - `forgotten_min`: the largest excess of `pending` over the capacity
//!   seen so far. Every live entry fits in the map, so at least that many
//!   sockets were forgotten (a lower bound: an excess between two samples
//!   is not seen).
//!
//! Read by `nn-admin net status` for the soak and the operator. An
//! increase of `forgotten_min` is a WARN, at most once a minute.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use aya::maps::{MapData, PerCpuArray};
use aya::Ebpf;
use common::wire::{flow_sock_slot, FLOW_SOCK_COUNT_SLOTS, FLOW_SOCK_MAP_MAX_ENTRIES};
use tracing::{info, warn};

/// Map name in the eBPF object (`agent-ebpf/src/tcp_connect.rs`).
pub const MAP_NAME: &str = "FLOW_SOCK_COUNTS";
/// Sampling period.
pub const SAMPLE_SECS: u64 = 10;
/// Least interval between two WARNs about forgotten sockets.
const WARN_EVERY: Duration = Duration::from_secs(60);

static ARMED: AtomicBool = AtomicBool::new(false);
static PENDING: AtomicU64 = AtomicU64::new(0);
static FORGOTTEN_MIN: AtomicU64 = AtomicU64::new(0);

/// One reading of the map's occupancy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowSockOccupancy {
    /// Sockets entered and not taken out by a close.
    pub pending: u64,
    /// `FLOW_SOCK_MAP`'s capacity.
    pub capacity: u64,
    /// Sockets forgotten at least (see the module documentation).
    pub forgotten_min: u64,
}

/// The latest sample, `None` when the counters are not armed (no eBPF
/// object, or an object without the map).
pub fn snapshot() -> Option<FlowSockOccupancy> {
    ARMED.load(Ordering::Relaxed).then(|| FlowSockOccupancy {
        pending: PENDING.load(Ordering::Relaxed),
        capacity: u64::from(FLOW_SOCK_MAP_MAX_ENTRIES),
        forgotten_min: FORGOTTEN_MIN.load(Ordering::Relaxed),
    })
}

/// Fold one sample of the two counters into the occupancy, given the lower
/// bound of the previous samples.
fn fold(inserted: u64, removed: u64, prev_forgotten_min: u64) -> FlowSockOccupancy {
    let capacity = u64::from(FLOW_SOCK_MAP_MAX_ENTRIES);
    let pending = inserted.saturating_sub(removed);
    FlowSockOccupancy {
        pending,
        capacity,
        forgotten_min: prev_forgotten_min.max(pending.saturating_sub(capacity)),
    }
}

/// Per-CPU sums of the two slots; `None` when a slot cannot be read.
fn read(map: &PerCpuArray<MapData, u64>) -> Option<(u64, u64)> {
    let sum = |slot: u32| {
        map.get(&slot, 0)
            .ok()
            .map(|v| v.iter().fold(0u64, |a, b| a.wrapping_add(*b)))
    };
    Some((
        sum(flow_sock_slot::INSERTED)?,
        sum(flow_sock_slot::REMOVED)?,
    ))
}

/// Take `FLOW_SOCK_COUNTS` from the loaded object and start the sampler.
/// A missing or mistyped map is a WARN: `nn-admin net status` then says
/// the occupancy is unknown.
pub fn install(ebpf: &mut Ebpf) {
    let Some(map) = ebpf.take_map(MAP_NAME) else {
        warn!(
            map = MAP_NAME,
            "FLOW_SOCK_MAP counters not exported by the eBPF object — its occupancy is unknown"
        );
        return;
    };
    let map: PerCpuArray<MapData, u64> = match PerCpuArray::try_from(map) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, map = MAP_NAME, "FLOW_SOCK_MAP counters have an unexpected type — its occupancy is unknown");
            return;
        }
    };
    ARMED.store(true, Ordering::Relaxed);
    info!(
        slots = FLOW_SOCK_COUNT_SLOTS,
        capacity = FLOW_SOCK_MAP_MAX_ENTRIES,
        every_secs = SAMPLE_SECS,
        "FLOW_SOCK_MAP occupancy counters armed"
    );
    tokio::spawn(async move {
        let mut last_warn: Option<Instant> = None;
        let mut warned_at = 0u64;
        loop {
            tokio::time::sleep(Duration::from_secs(SAMPLE_SECS)).await;
            let Some((inserted, removed)) = read(&map) else {
                continue;
            };
            let o = fold(inserted, removed, FORGOTTEN_MIN.load(Ordering::Relaxed));
            PENDING.store(o.pending, Ordering::Relaxed);
            FORGOTTEN_MIN.store(o.forgotten_min, Ordering::Relaxed);
            let due = last_warn.is_none_or(|t| t.elapsed() >= WARN_EVERY);
            if o.forgotten_min > warned_at && due {
                last_warn = Some(Instant::now());
                warned_at = o.forgotten_min;
                warn!(
                    pending = o.pending,
                    capacity = o.capacity,
                    forgotten_at_least = o.forgotten_min,
                    "FLOW_SOCK_MAP over capacity: the kernel forgot outbound sockets before \
                     their close — those flows will have no close record"
                );
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_is_entered_minus_taken_out() {
        let o = fold(10, 4, 0);
        assert_eq!(o.pending, 6);
        assert_eq!(o.capacity, u64::from(FLOW_SOCK_MAP_MAX_ENTRIES));
        assert_eq!(o.forgotten_min, 0);
        // per-CPU sums read apart can cross: never negative
        assert_eq!(fold(3, 5, 0).pending, 0);
    }

    /// Beyond the capacity at least the excess was forgotten, and the bound
    /// stays when the live sessions close afterwards.
    #[test]
    fn forgotten_is_a_lower_bound_that_does_not_go_back() {
        let cap = u64::from(FLOW_SOCK_MAP_MAX_ENTRIES);
        let held = fold(cap + 4_464, 0, 0);
        assert_eq!(held.forgotten_min, 4_464);
        let closed = fold(cap + 4_464, cap, held.forgotten_min);
        assert_eq!(closed.pending, 4_464);
        assert_eq!(closed.forgotten_min, 4_464);
    }

    /// Lab PR 164: the kernel map holds as many sockets as the userland flow
    /// tracker holds pending connects (it held 4,096 against 65,536, so the
    /// kernel forgot sessions the tracker still waited for).
    #[test]
    fn the_kernel_map_holds_what_the_tracker_holds() {
        assert_eq!(
            FLOW_SOCK_MAP_MAX_ENTRIES as usize,
            crate::net::flow_tracker::DEFAULT_PENDING_CAPACITY
        );
    }

    #[test]
    fn unarmed_counters_are_unknown() {
        if !ARMED.load(Ordering::Relaxed) {
            assert_eq!(snapshot(), None);
        }
    }
}
