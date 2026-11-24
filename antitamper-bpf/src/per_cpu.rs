//! Lot 353 (the review of #563, F2): the per-CPU arrays read and written
//! with the CPU count [`crate::kernel_roots::possible_cpus`] read once at
//! the start, beneath the `/sys` root the start anchored.
//!
//! aya's `PerCpuArray::get` and `set` size their buffer with
//! `aya::util::nr_cpus()`, which reads `/sys/devices/system/cpu/possible`
//! by path once per thread. The samplers that read the agent's per-CPU
//! counters run on the runtime's threads, and a round moved off the
//! runtime (`block_in_place`) hands the worker's core to a fresh thread: a
//! fresh thread read the file through the `/sys` mounted now, and a FUSE
//! over `/sys` held it. [`get`] and [`set`] make the lookup and the update
//! themselves (`BPF_MAP_LOOKUP_ELEM`, `BPF_MAP_UPDATE_ELEM`, the value
//! `possible_cpus` slots of the value size rounded up to 8 bytes, as the
//! kernel lays it), on the map's descriptor: no file read at all.

use std::io;
use std::os::fd::{AsFd, AsRawFd};

use aya::Pod;
use aya::maps::{IterableMap, MapData, PerCpuArray};

/// `bpf(2)`'s attribute of the element commands.
#[repr(C)]
struct ElemAttr {
    map_fd: u32,
    _pad: u32,
    key: u64,
    value: u64,
    flags: u64,
}

use common::bpf_cmd::{BPF_MAP_LOOKUP_ELEM, BPF_MAP_UPDATE_ELEM};

/// One CPU's slot of a per-CPU value: its size rounded up to 8 bytes.
fn slot<V>() -> usize {
    std::mem::size_of::<V>().div_ceil(8) * 8
}

fn cpus() -> io::Result<usize> {
    crate::kernel_roots::possible_cpus().map_err(io::Error::other)
}

fn elem(cmd: u32, map: &MapData, key: &u32, value: *mut u8, flags: u64) -> io::Result<()> {
    let attr = ElemAttr {
        map_fd: map.fd().as_fd().as_raw_fd() as u32,
        _pad: 0,
        key: key as *const u32 as u64,
        value: value as u64,
        flags,
    };
    // SAFETY: `attr` names a live map descriptor, a key and a value buffer
    // the caller sized for the map (the possible CPUs' slots); the kernel
    // reads `attr` for its size and the buffers for the map's sizes.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            libc::c_long::from(cmd),
            &attr as *const ElemAttr,
            std::mem::size_of::<ElemAttr>(),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The values of element `index` of the per-CPU array `map`, one per
/// possible CPU.
pub fn get<V: Pod>(map: &PerCpuArray<MapData, V>, index: u32) -> io::Result<Vec<V>> {
    let n = cpus()?;
    let s = slot::<V>();
    let mut buf = vec![0u8; n * s];
    elem(BPF_MAP_LOOKUP_ELEM, map.map(), &index, buf.as_mut_ptr(), 0)?;
    Ok((0..n)
        // SAFETY: `buf` holds `n` slots of `s >= size_of::<V>()` bytes the
        // kernel wrote; `V` is plain old data, read unaligned.
        .map(|i| unsafe { std::ptr::read_unaligned(buf.as_ptr().add(i * s).cast::<V>()) })
        .collect())
}

/// The sum of element `index` of the per-CPU counter array `map` over the
/// CPUs (wrapping, as the counters do).
pub fn sum(map: &PerCpuArray<MapData, u64>, index: u32) -> io::Result<u64> {
    Ok(get(map, index)?.into_iter().fold(0u64, u64::wrapping_add))
}

/// Element `index` of the per-CPU array `map` set to `value` on every
/// possible CPU.
pub fn set<V: Pod>(
    map: &PerCpuArray<MapData, V>,
    index: u32,
    value: V,
    flags: u64,
) -> io::Result<()> {
    let n = cpus()?;
    let s = slot::<V>();
    let mut buf = vec![0u8; n * s];
    for i in 0..n {
        // SAFETY: slot `i` of `buf` has room for a `V` (`s >= size_of`).
        unsafe { std::ptr::write_unaligned(buf.as_mut_ptr().add(i * s).cast::<V>(), value) };
    }
    elem(
        BPF_MAP_UPDATE_ELEM,
        map.map(),
        &index,
        buf.as_mut_ptr(),
        flags,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The slots are laid as the kernel lays them (8-byte rounded).
    #[test]
    fn a_slot_is_the_value_rounded_up_to_eight_bytes() {
        assert_eq!(slot::<u64>(), 8);
        assert_eq!(slot::<u32>(), 8);
        assert_eq!(slot::<[u64; 2]>(), 16);
        assert_eq!(slot::<[u8; 9]>(), 16);
    }
}
