//! Lab PR 224 (CM-02 c): the optional synchronous deny of a connect to a
//! policy-blocked destination (`--net-connect-deny`, off by default).
//!
//! NN-L-NET-001 answers a flow to an address of the operator blocklist
//! (`netflow-blocklist.{v1,local}`) with a kill of the process tree: the
//! connection was made, and a first exchange may have left. With the
//! deny on, the agent loads the same entries into the kernel tries of
//! `agent-ebpf/src/socket_connect.rs` and attaches the LSM program on
//! `socket_connect`: the `connect()` fails with `EPERM` before any packet
//! leaves, and the program's record becomes the signed NN-L-NET-001
//! verdict of the refused connect (`network` "… denied", `operation`
//! "connect").
//!
//! The kernel copy is a safety-bounded subset ([`deny_entries`]): an entry
//! wider than /8 (IPv4) or /16 (IPv6), one that covers loopback or the
//! unspecified address, and anything past [`NET_BLOCK_MAX_ENTRIES`] per
//! family stays out of it — a typo in the overlay must not cut the host
//! off its own services — and is still judged by NN-L-NET-001 at the
//! connect. An IPv4-mapped IPv6 entry is loaded as the IPv4 range it
//! maps. The list is the one loaded at boot; a change takes effect at the
//! next start, as for the rule.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use anyhow::{anyhow, Context, Result};
use aya::{
    maps::{
        lpm_trie::{Key, LpmTrie},
        Array, MapData,
    },
    programs::Lsm,
    Btf, Ebpf,
};
use common::wire::NET_BLOCK_MAX_ENTRIES;

use crate::net::blocklist::{NetBlocklist, NetBlocklistEntry};

/// The LSM program (`agent-ebpf/src/socket_connect.rs`).
pub const PROGRAM: &str = "socket_connect_deny";
/// Its hook.
pub const HOOK: &str = "socket_connect";
/// Its maps.
pub const MAP_V4: &str = "NET_BLOCK_V4";
pub const MAP_V6: &str = "NET_BLOCK_V6";
pub const MAP_MODE: &str = "NET_CONNECT_DENY_MODE";

/// Narrowest prefix loaded into the kernel, per family.
pub const MIN_PREFIX_V4: u8 = 8;
pub const MIN_PREFIX_V6: u8 = 16;

static ARMED: AtomicBool = AtomicBool::new(false);
static DENIED: AtomicU64 = AtomicU64::new(0);

/// Connects refused in the kernel since boot; `None` when the deny is
/// not armed (status surface).
pub fn denied_total() -> Option<u64> {
    ARMED
        .load(Ordering::Relaxed)
        .then(|| DENIED.load(Ordering::Relaxed))
}

/// Count one refused connect (the connect pump, per denial record).
pub fn note_denied() {
    DENIED.fetch_add(1, Ordering::Relaxed);
}

/// What [`deny_entries`] loads into the kernel, and what it leaves out.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DenyEntries {
    /// `(network, prefix length)`, host bits cleared.
    pub v4: Vec<([u8; 4], u32)>,
    pub v6: Vec<([u8; 16], u32)>,
    /// Entries kept out of the kernel tries, with why.
    pub skipped: Vec<(String, &'static str)>,
}

fn mask_v4(a: Ipv4Addr, prefix: u8) -> [u8; 4] {
    let bits = u32::from(a);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    (bits & mask).to_be_bytes()
}

fn mask_v6(a: Ipv6Addr, prefix: u8) -> [u8; 16] {
    let bits = u128::from(a);
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    };
    (bits & mask).to_be_bytes()
}

/// `true` when `net/prefix` (IPv4) contains a loopback or the unspecified
/// address.
fn v4_unsafe(net: [u8; 4], prefix: u8) -> bool {
    let contains = |addr: Ipv4Addr| mask_v4(addr, prefix) == net;
    contains(Ipv4Addr::LOCALHOST) || contains(Ipv4Addr::UNSPECIFIED) || {
        // 127.0.0.0/8 inside the entry, or the entry inside 127/8.
        net[0] == 127
    }
}

fn v6_unsafe(net: [u8; 16], prefix: u8) -> bool {
    let contains = |addr: Ipv6Addr| mask_v6(addr, prefix) == net;
    contains(Ipv6Addr::LOCALHOST) || contains(Ipv6Addr::UNSPECIFIED)
}

/// The entries of `blocklist` the kernel deny may refuse (module docs).
pub fn deny_entries(blocklist: &NetBlocklist) -> DenyEntries {
    let mut out = DenyEntries::default();
    let cap = NET_BLOCK_MAX_ENTRIES as usize;
    for entry in blocklist.entries() {
        let (addr, prefix) = match *entry {
            NetBlocklistEntry::Ip(ip) => (ip, if ip.is_ipv4() { 32 } else { 128 }),
            NetBlocklistEntry::Cidr { net, prefix } => (net, prefix),
        };
        let shown = format!("{addr}/{prefix}");
        // An IPv4-mapped IPv6 entry is the IPv4 range it maps (NET-001).
        let (addr, prefix) = match addr {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) if prefix >= 96 => (IpAddr::V4(v4), prefix - 96),
                Some(_) => {
                    out.skipped
                        .push((shown, "IPv4-mapped range wider than its IPv4 part"));
                    continue;
                }
                None => (addr, prefix),
            },
            v4 => (v4, prefix),
        };
        match addr {
            IpAddr::V4(v4) => {
                if prefix < MIN_PREFIX_V4 {
                    out.skipped.push((shown, "wider than /8"));
                    continue;
                }
                let net = mask_v4(v4, prefix);
                if v4_unsafe(net, prefix) {
                    out.skipped
                        .push((shown, "covers loopback or the unspecified address"));
                    continue;
                }
                if out.v4.len() >= cap {
                    out.skipped.push((shown, "over the kernel trie's capacity"));
                    continue;
                }
                out.v4.push((net, u32::from(prefix)));
            }
            IpAddr::V6(v6) => {
                if prefix < MIN_PREFIX_V6 {
                    out.skipped.push((shown, "wider than /16"));
                    continue;
                }
                let net = mask_v6(v6, prefix);
                if v6_unsafe(net, prefix) {
                    out.skipped
                        .push((shown, "covers loopback or the unspecified address"));
                    continue;
                }
                if out.v6.len() >= cap {
                    out.skipped.push((shown, "over the kernel trie's capacity"));
                    continue;
                }
                out.v6.push((net, u32::from(prefix)));
            }
        }
    }
    out
}

/// What `--net-connect-deny` does at boot ([`arming`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arming {
    /// Not requested: the program is not attached.
    Off,
    /// Requested by an agent in detect-only: not armed, not attached.
    DetectOnly,
    /// Requested: [`arm`] it.
    Arm,
}

/// Whether the deny is armed. Detect-only never refuses and never kills:
/// with `--detect-only` (or `NN_DETECT_ONLY`) a requested deny is reported
/// and left off — no entry is loaded, the mode stays 0 and the LSM program
/// is not attached — while NN-L-NET-001 still records the flow at the
/// connect and the executor's detect-only gate suppresses its kill.
pub fn arming(requested: bool, detect_only: bool) -> Arming {
    match (requested, detect_only) {
        (false, _) => Arming::Off,
        (true, true) => Arming::DetectOnly,
        (true, false) => Arming::Arm,
    }
}

/// What [`arm`] did.
#[derive(Debug)]
pub struct ArmReport {
    pub v4: usize,
    pub v6: usize,
    pub skipped: Vec<(String, &'static str)>,
}

/// Load the deny's entries, turn it on and attach it. The hook's argument
/// positions are fixed and checked at boot (`HOOK_ARG_CHECKS`), and the
/// protocol is read through an optional offset (`SOCKET_SK_OFFSET`), so
/// nothing here depends on the running kernel's layout. On an error the
/// deny stays off (the rule still kills at the connect).
pub fn arm(ebpf: &mut Ebpf, blocklist: &NetBlocklist) -> Result<ArmReport> {
    let entries = deny_entries(blocklist);
    {
        let map = ebpf
            .map_mut(MAP_V4)
            .ok_or_else(|| anyhow!("{MAP_V4} missing from the eBPF object"))?;
        let mut v4: LpmTrie<&mut MapData, [u8; 4], u8> =
            LpmTrie::try_from(map).with_context(|| format!("{MAP_V4} is not an LPM trie"))?;
        for (net, prefix) in &entries.v4 {
            v4.insert(&Key::new(*prefix, *net), 1u8, 0)
                .with_context(|| format!("loading {net:?}/{prefix} into {MAP_V4}"))?;
        }
    }
    {
        let map = ebpf
            .map_mut(MAP_V6)
            .ok_or_else(|| anyhow!("{MAP_V6} missing from the eBPF object"))?;
        let mut v6: LpmTrie<&mut MapData, [u8; 16], u8> =
            LpmTrie::try_from(map).with_context(|| format!("{MAP_V6} is not an LPM trie"))?;
        for (net, prefix) in &entries.v6 {
            v6.insert(&Key::new(*prefix, *net), 1u8, 0)
                .with_context(|| format!("loading {net:?}/{prefix} into {MAP_V6}"))?;
        }
    }
    {
        let map = ebpf
            .map_mut(MAP_MODE)
            .ok_or_else(|| anyhow!("{MAP_MODE} missing from the eBPF object"))?;
        let mut mode: Array<&mut MapData, u32> =
            Array::try_from(map).with_context(|| format!("{MAP_MODE} is not an array"))?;
        mode.set(0, 1, 0).context("turning the connect deny on")?;
    }
    let btf = Btf::from_sys_fs().context("loading vmlinux BTF for the connect deny")?;
    let prog: &mut Lsm = ebpf
        .program_mut(PROGRAM)
        .ok_or_else(|| anyhow!("program {PROGRAM} missing from the eBPF object"))?
        .try_into()
        .with_context(|| format!("program {PROGRAM} is not LSM"))?;
    prog.load(HOOK, &btf)
        .map_err(anyhow::Error::from)
        .map_err(|e| {
            anyhow!(
                "verifier rejected `{PROGRAM}`: {}",
                super::exe_identity::verifier_tail(&e)
            )
        })?;
    prog.attach()
        .with_context(|| format!("attaching `{PROGRAM}`"))?;
    ARMED.store(true, Ordering::Relaxed);
    Ok(ArmReport {
        v4: entries.v4.len(),
        v6: entries.v6.len(),
        skipped: entries.skipped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(entries: &[&str]) -> NetBlocklist {
        NetBlocklist::from_entries(entries.iter().map(|e| NetBlocklistEntry::parse(e).unwrap()))
    }

    /// Review A.1: `--detect-only` never arms the kernel deny, so a
    /// connect to a blocklisted destination is not refused; without the
    /// flag the request arms it.
    #[test]
    fn detect_only_never_arms_the_connect_deny() {
        assert_eq!(arming(true, true), Arming::DetectOnly);
        assert_eq!(arming(false, true), Arming::Off);
        assert_eq!(arming(false, false), Arming::Off);
        assert_eq!(arming(true, false), Arming::Arm);
    }

    /// The shipped documentation ranges load as they are; host bits are
    /// cleared; a single address is a /32 or /128.
    #[test]
    fn the_shipped_ranges_and_single_addresses_load() {
        let e = deny_entries(&list(&[
            "192.0.2.0/24",
            "198.51.100.77/24",
            "203.0.113.9",
            "2001:db8::/32",
            "2001:db8::1",
        ]));
        assert!(e.skipped.is_empty(), "{:?}", e.skipped);
        assert!(e.v4.contains(&([192, 0, 2, 0], 24)));
        assert!(e.v4.contains(&([198, 51, 100, 0], 24)));
        assert!(e.v4.contains(&([203, 0, 113, 9], 32)));
        assert_eq!(e.v6.len(), 2);
        assert!(e.v6.iter().any(|(_, p)| *p == 32) && e.v6.iter().any(|(_, p)| *p == 128));
    }

    /// An entry that would cut the host off its own services, or almost
    /// everything, never reaches the kernel.
    #[test]
    fn wide_loopback_and_unspecified_entries_stay_out_of_the_kernel() {
        let e = deny_entries(&list(&[
            "0.0.0.0/0",
            "10.0.0.0/7",
            "127.0.0.1",
            "127.0.0.0/8",
            "::1",
            "::/0",
            "2000::/3",
            "0.0.0.0",
        ]));
        assert!(e.v4.is_empty() && e.v6.is_empty(), "{e:?}");
        assert_eq!(e.skipped.len(), 8);
    }

    /// An IPv4-mapped IPv6 entry is the IPv4 range it maps.
    #[test]
    fn an_ipv4_mapped_entry_loads_as_its_ipv4_range() {
        let e = deny_entries(&list(&["::ffff:192.0.2.0/120", "::ffff:198.51.100.7"]));
        assert_eq!(e.v4.len(), 2);
        assert!(e.v4.contains(&([192, 0, 2, 0], 24)) && e.v4.contains(&([198, 51, 100, 7], 32)));
        assert!(e.v6.is_empty());
    }

    #[test]
    fn the_deny_reports_nothing_until_armed() {
        // Never armed in a unit test process.
        assert_eq!(denied_total(), None);
    }
}
