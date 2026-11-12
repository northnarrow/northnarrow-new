//! The exec quarantine's kernel objects (lab PR 223): the configuration
//! written once and frozen, and the maps and ring the controller owns.

use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::MetadataExt;

use anyhow::{anyhow, Context, Result};
use aya::maps::{Array, HashMap, MapData, PerCpuArray, RingBuf};
use aya::Ebpf;
use common::wire::execq::{conf_slot, counter, root_kind, ExecqKey, ExecqKnown, ExecqStopped};

/// `ExecqKey` for aya (its own `Pod` marker; the orphan rule forbids
/// implementing it on the `common` type).
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AyaKey(pub ExecqKey);
// SAFETY: `#[repr(C)]` over two u64, no padding; transparent wrapper.
unsafe impl aya::Pod for AyaKey {}

#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AyaKnown(pub ExecqKnown);
// SAFETY: `#[repr(C)]`, two i64 then two u32, no padding.
unsafe impl aya::Pod for AyaKnown {}

#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AyaStopped(pub ExecqStopped);
// SAFETY: `#[repr(C)]` over two u64.
unsafe impl aya::Pod for AyaStopped {}

/// What the controller holds.
pub struct Kernel {
    pub ring: RingBuf<MapData>,
    pub known: HashMap<MapData, AyaKey, AyaKnown>,
    pub stopped: HashMap<MapData, u32, AyaStopped>,
    pub alive: Array<MapData, u64>,
    pub roots: HashMap<MapData, AyaKey, u32>,
    pub counters: PerCpuArray<MapData, u64>,
    pub(crate) reject: crate::sensors::reject::RejectThrottle,
}

impl std::fmt::Debug for Kernel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Kernel").finish_non_exhaustive()
    }
}

/// `BPF_MAP_FREEZE`, from the one copy of the uapi numbers (lab PR 215,
/// `common::bpf_cmd`).
const BPF_MAP_FREEZE_CMD: libc::c_long = common::bpf_cmd::BPF_MAP_FREEZE as libc::c_long;

/// `BPF_MAP_FREEZE` on `map` (the exec policy freezes its own
/// configuration the same way).
pub(crate) fn freeze(map: &MapData) -> Result<()> {
    #[repr(C)]
    struct FreezeAttr {
        map_fd: u32,
    }
    let attr = FreezeAttr {
        map_fd: map.fd().as_fd().as_raw_fd() as u32,
    };
    // SAFETY: bpf(BPF_MAP_FREEZE) with a valid attr of its exact size.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_FREEZE_CMD,
            &attr as *const FreezeAttr as *const libc::c_void,
            std::mem::size_of::<FreezeAttr>() as u32,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error()).context("BPF_MAP_FREEZE on EXECQ_CONF");
    }
    Ok(())
}

/// Write `EXECQ_CONF` (mode, guarded classes, heartbeat bound) and freeze
/// it: from here no process, root included, can change the mode the
/// kernel applies. Called with `mode::OFF` too, so the guard cannot be
/// turned on behind the agent's back.
pub fn write_conf(ebpf: &mut Ebpf, mode: u64, classes: u32, heartbeat_max_ns: u64) -> Result<()> {
    let map = ebpf
        .map_mut("EXECQ_CONF")
        .ok_or_else(|| anyhow!("EXECQ_CONF missing from the eBPF object"))?;
    let mut arr: Array<&mut MapData, u64> = Array::try_from(map).context("EXECQ_CONF")?;
    arr.set(conf_slot::CLASSES, u64::from(classes), 0)?;
    arr.set(conf_slot::HEARTBEAT_MAX_NS, heartbeat_max_ns, 0)?;
    arr.set(conf_slot::MODE, mode, 0)?;
    let map = ebpf
        .map("EXECQ_CONF")
        .ok_or_else(|| anyhow!("EXECQ_CONF missing from the eBPF object"))?;
    let aya::maps::Map::Array(data) = map else {
        return Err(anyhow!("EXECQ_CONF is not an array"));
    };
    freeze(data)
}

/// Take the guard's maps and ring out of the object.
pub fn take(ebpf: &mut Ebpf) -> Result<Kernel> {
    let mut take = |name: &str| {
        ebpf.take_map(name)
            .ok_or_else(|| anyhow!("{name} missing from the eBPF object"))
    };
    Ok(Kernel {
        ring: RingBuf::try_from(take("EXECQ_EVENTS")?).context("EXECQ_EVENTS")?,
        known: HashMap::try_from(take("EXECQ_KNOWN")?).context("EXECQ_KNOWN")?,
        stopped: HashMap::try_from(take("EXECQ_STOPPED")?).context("EXECQ_STOPPED")?,
        alive: Array::try_from(take("EXECQ_ALIVE")?).context("EXECQ_ALIVE")?,
        roots: HashMap::try_from(take("EXECQ_ROOTS")?).context("EXECQ_ROOTS")?,
        counters: PerCpuArray::try_from(take("EXECQ_COUNTERS")?).context("EXECQ_COUNTERS")?,
        reject: crate::sensors::reject::RejectThrottle::new(),
    })
}

/// `CLOCK_MONOTONIC` now, in ns — `bpf_ktime_get_ns`'s clock.
pub fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: a valid clock id and a timespec to fill.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// `MEMBARRIER_CMD_GLOBAL` (`linux/membarrier.h`; `MEMBARRIER_CMD_SHARED`
/// before 4.16): `synchronize_rcu()` for the caller.
const MEMBARRIER_CMD_GLOBAL: libc::c_long = 1;

/// How long [`quiesce`] waits where `membarrier` is refused: a program
/// run takes microseconds.
pub const QUIESCE_FALLBACK: std::time::Duration = std::time::Duration::from_millis(50);

/// Lot 317 (bug hunt 1.4, BUG-118): return once every run of the exec
/// programs that read the heartbeat before it was cleared has ended — the
/// stop it decided is in `EXECQ_STOPPED`, where the agent's stop reads it.
/// `maybe_stop` runs in the `sched_process_exec` tracepoint's program, with
/// preemption off (a read-side section of RCU), and `membarrier(2)`'s
/// `MEMBARRIER_CMD_GLOBAL` is `synchronize_rcu()`: it returns after every
/// such section that began before the call has ended. Where it is refused
/// (`EINVAL` with `nohz_full` CPUs) a sleep of [`QUIESCE_FALLBACK`] stands
/// in for it. True: the kernel's grace period; false: the sleep.
pub fn quiesce() -> bool {
    // SAFETY: membarrier(2) with a command, flags 0 and cpu 0 (unused
    // without MEMBARRIER_CMD_FLAG_CPU), no pointers.
    let rc = unsafe { libc::syscall(libc::SYS_membarrier, MEMBARRIER_CMD_GLOBAL, 0, 0) };
    if rc != 0 {
        std::thread::sleep(QUIESCE_FALLBACK);
    }
    rc == 0
}

/// Lot 317 (review F5): whether the unstop of process `start_ns` removes the
/// map's entry of its pid, which names the process started at `found`
/// (`None`: no entry, nothing to keep) — only its own.
pub(crate) fn unstop_removes(found: Option<u64>, start_ns: u64) -> bool {
    found.is_none_or(|f| f == start_ns)
}

/// Lot 317 (review F2): `ExecqStopped::stop_ns` as the agent marks the map's
/// entry of a held process whose kill it owes (the kernel writes its stop
/// time there, never this): the next start kills the process instead of
/// resuming it.
pub const KILL_OWED: u64 = u64::MAX;

impl Kernel {
    /// Lot 317 (review F5): the map's entry of process `pid` goes when it is
    /// the one started at `start_ns` — a later holder of the pid, which the
    /// kernel holds in its turn, keeps its own.
    pub fn unstop(&mut self, pid: u32, start_ns: u64) {
        let found = self.stopped.get(&pid, 0).ok().map(|v| v.0.start_ns);
        if unstop_removes(found, start_ns) {
            let _ = self.stopped.remove(&pid);
        }
    }

    /// Lot 317 (review F2): mark the map's entry of process `(pid,
    /// start_ns)` [`KILL_OWED`] (an update of an existing key succeeds on a
    /// full map). A failure is logged: the process stays stopped, and is
    /// resumed by the next start instead of killed.
    pub fn owe_kill(&mut self, pid: u32, start_ns: u64) {
        let v = AyaStopped(ExecqStopped {
            start_ns,
            stop_ns: KILL_OWED,
        });
        if let Err(e) = self.stopped.insert(pid, v, 0) {
            tracing::warn!(pid, error = %e, "exec quarantine: the owed kill could not be marked in the map");
        }
    }

    /// The heartbeat a stop needs (0: the kernel stops nothing).
    pub fn beat(&mut self, ns: u64) {
        let _ = self.alive.set(0, ns, 0);
    }

    /// The per-CPU counters summed, `counter::*` order.
    pub fn counters(&self) -> [u64; counter::SLOTS as usize] {
        let mut out = [0u64; counter::SLOTS as usize];
        for (i, slot) in out.iter_mut().enumerate() {
            if let Ok(v) = self.counters.get(&(i as u32), 0) {
                *slot = v.iter().copied().fold(0u64, u64::wrapping_add);
            }
        }
        out
    }

    /// Replace the guarded mount roots with `roots`.
    pub fn set_roots(&mut self, roots: &[(ExecqKey, u32)]) {
        let old: Vec<AyaKey> = self.roots.keys().filter_map(|k| k.ok()).collect();
        for k in old {
            if !roots.iter().any(|(r, _)| *r == k.0) {
                let _ = self.roots.remove(&k);
            }
        }
        for (k, v) in roots {
            let _ = self.roots.insert(AyaKey(*k), *v, 0);
        }
    }
}

/// Mount points whose filesystem the guard watches as a whole: a separate
/// `/home`, `/tmp`, `/var/tmp`, `/root`, `/dev/shm`, `/run/user/<uid>`, or
/// a mount below them.
pub fn guarded_mount_point(mp: &str) -> bool {
    const GUARDED: &[&str] = &[
        "/tmp",
        "/var/tmp",
        "/home",
        "/root",
        "/dev/shm",
        "/run/user",
    ];
    GUARDED
        .iter()
        .any(|g| mp == *g || mp.strip_prefix(g).is_some_and(|r| r.starts_with('/')))
}

/// Lab PR 226: which guarded point `mp` is at ([`root_kind`]), so a file
/// on that filesystem gets the point's class (a tmpfs `/tmp` is `tmp`, a
/// separate `/home` is `home`).
pub fn root_kind_of(mp: &str) -> u32 {
    let under = |g: &str| mp == g || mp.strip_prefix(g).is_some_and(|r| r.starts_with('/'));
    let mut k = root_kind::GUARDED;
    if under("/tmp") {
        k |= root_kind::TMP;
    } else if under("/var/tmp") {
        k |= root_kind::VAR_TMP;
    } else if under("/dev/shm") {
        k |= root_kind::DEV_SHM;
    } else if under("/home") || under("/root") {
        k |= root_kind::HOME;
    }
    k
}

/// The roots of the guarded mounts in a `mountinfo` text: mounts of a
/// filesystem's own root (field 4 is `/`; a bind mount of a directory is
/// not the root the kernel's walk ends on) at a guarded mount point, with
/// the point's kind ([`root_kind_of`]).
pub fn guarded_roots(mountinfo: &str) -> Vec<(ExecqKey, u32)> {
    let mut out = Vec::new();
    for line in mountinfo.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        let (Some(root), Some(mp)) = (f.get(3), f.get(4)) else {
            continue;
        };
        if *root != "/" {
            continue;
        }
        let mp = crate::sensors::open_sensor::unescape_octal(mp);
        if !guarded_mount_point(&mp) {
            continue;
        }
        if let Ok(m) = std::fs::metadata(&mp) {
            let key = ExecqKey {
                dev: crate::anti_tamper::filesystem::stat_dev_to_kernel_dev(m.dev()),
                ino: m.ino(),
            };
            if !out.iter().any(|(k, _)| *k == key) {
                out.push((key, root_kind_of(&mp)));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lot 317 (review F5): an unstop removes the entry of its own process,
    /// never the one a later holder of the pid has.
    #[test]
    fn an_unstop_removes_only_its_own_process() {
        assert!(unstop_removes(Some(7), 7));
        assert!(!unstop_removes(Some(8), 7), "a later holder of the pid");
        assert!(unstop_removes(None, 7));
    }

    /// Lot 317 (BUG-118): the stop's wait for the exec programs is the
    /// kernel's grace period (`membarrier` GLOBAL), not the fallback's
    /// sleep, where the kernel offers it (`MEMBARRIER_CMD_QUERY`).
    #[test]
    fn quiesce_waits_on_the_kernel_not_on_a_sleep() {
        // SAFETY: membarrier(2) MEMBARRIER_CMD_QUERY (0), no pointers.
        let cmds = unsafe { libc::syscall(libc::SYS_membarrier, 0, 0, 0) };
        if cmds < 0 || cmds & MEMBARRIER_CMD_GLOBAL == 0 {
            eprintln!("membarrier GLOBAL not offered here ({cmds}): the fallback sleeps");
            return;
        }
        assert!(quiesce(), "membarrier GLOBAL refused: the fallback slept");
    }

    #[test]
    fn guarded_mount_points() {
        for yes in [
            "/home",
            "/tmp",
            "/var/tmp",
            "/root",
            "/dev/shm",
            "/run/user/1000",
            "/home/u/data",
        ] {
            assert!(guarded_mount_point(yes), "{yes}");
        }
        for no in ["/", "/usr", "/homes", "/tmpfoo", "/run", "/var", "/dev"] {
            assert!(!guarded_mount_point(no), "{no}");
        }
    }

    #[test]
    fn only_filesystem_roots_at_guarded_points_are_kept() {
        // a bind mount of a subdirectory (root field not `/`) and an
        // unguarded mount are ignored; /tmp itself exists on every host
        let text = "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n\
             2 1 0:5 / /tmp rw - tmpfs tmpfs rw\n\
             3 1 8:1 /srv/data /home rw - ext4 /dev/sda1 rw\n\
             4 1 0:6 / /usr rw - tmpfs tmpfs rw\n";
        let roots = guarded_roots(text);
        assert_eq!(roots.len(), 1, "{roots:?}");
        let m = std::fs::metadata("/tmp").unwrap();
        assert_eq!(roots[0].0.ino, m.ino());
        // lab PR 226: the kind of point it is mounted at
        assert_eq!(roots[0].1, root_kind::GUARDED | root_kind::TMP);
    }

    /// Lab PR 226: a file on a filesystem mounted at a guarded point gets
    /// that point's class.
    #[test]
    fn root_kinds() {
        assert_eq!(root_kind_of("/tmp"), root_kind::GUARDED | root_kind::TMP);
        assert_eq!(
            root_kind_of("/var/tmp"),
            root_kind::GUARDED | root_kind::VAR_TMP
        );
        assert_eq!(
            root_kind_of("/dev/shm"),
            root_kind::GUARDED | root_kind::DEV_SHM
        );
        assert_eq!(root_kind_of("/home"), root_kind::GUARDED | root_kind::HOME);
        assert_eq!(
            root_kind_of("/home/u/data"),
            root_kind::GUARDED | root_kind::HOME
        );
        assert_eq!(root_kind_of("/root"), root_kind::GUARDED | root_kind::HOME);
        assert_eq!(root_kind_of("/run/user/1000"), root_kind::GUARDED);
        assert_eq!(root_kind_of("/tmpx"), root_kind::GUARDED);
    }
}
