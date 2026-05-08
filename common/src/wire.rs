//! Plain-Old-Data wire types that cross the kernel↔userland boundary.
//!
//! Every struct here is `#[repr(C)]`, fixed-size, contains only
//! primitive types or fixed arrays, and never holds a heap pointer.
//! Both the eBPF program and the userland sensor must agree on the
//! exact byte layout — bytemuck's `Pod`/`Zeroable` derives (userland
//! only, behind the `std` feature) provide a compile-time check that
//! the struct really is plain-old-data.

/// `TASK_COMM_LEN` — the fixed length of the kernel `comm` field.
pub const TASK_COMM_LEN: usize = 16;

/// Maximum length stored for the executable path. Paths longer than
/// this are truncated; they always end with a `\0` if there is room.
pub const FILENAME_LEN: usize = 256;

/// Maximum length of a DNS QNAME we record (RFC 1035 §2.3.4).
pub const QNAME_LEN: usize = 253;

/// IPv6 / padded-IPv4 address byte length.
pub const ADDR_LEN: usize = 16;

/// One process exec event as captured by the eBPF tracepoint.
///
/// Layout MUST stay identical between the eBPF program and userland.
/// Adding fields means coordinating both sides and bumping a version
/// constant if we ever add one.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct ProcessSpawnRaw {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub filename: [u8; FILENAME_LEN],
    pub timestamp_ns: u64,
}

impl ProcessSpawnRaw {
    /// Zeroed instance, suitable as a starting point inside an eBPF
    /// program where stack memory is not implicitly zero-initialised.
    pub const fn zeroed() -> Self {
        Self {
            pid: 0,
            ppid: 0,
            uid: 0,
            gid: 0,
            comm: [0u8; TASK_COMM_LEN],
            filename: [0u8; FILENAME_LEN],
            timestamp_ns: 0,
        }
    }
}

/// File open event (LSM `file_open` hook).
///
/// `flags` is the kernel `f_flags` (O_RDONLY etc.) at open time; it
/// is reduced to a `u32` because BPF helpers don't expose the full
/// `int` width portably across architectures.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct FileOpenRaw {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub flags: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub filename: [u8; FILENAME_LEN],
    pub timestamp_ns: u64,
}

impl FileOpenRaw {
    pub const fn zeroed() -> Self {
        Self {
            pid: 0,
            uid: 0,
            gid: 0,
            flags: 0,
            comm: [0u8; TASK_COMM_LEN],
            filename: [0u8; FILENAME_LEN],
            timestamp_ns: 0,
        }
    }
}

/// Pre-exec validation event (LSM `bprm_check_security`).
///
/// Distinct from `ProcessSpawnRaw` (post-exec tracepoint): this fires
/// before the new image runs, which is the kernel's last opportunity
/// to refuse the exec. Tappa 4 only emits telemetry; Tappa 7 will
/// turn this hook into an enforcement point.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct ExecCheckRaw {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub _pad0: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub filename: [u8; FILENAME_LEN],
    pub timestamp_ns: u64,
}

impl ExecCheckRaw {
    pub const fn zeroed() -> Self {
        Self {
            pid: 0,
            ppid: 0,
            uid: 0,
            _pad0: 0,
            comm: [0u8; TASK_COMM_LEN],
            filename: [0u8; FILENAME_LEN],
            timestamp_ns: 0,
        }
    }
}

/// Outbound TCP connect attempt (kprobe `tcp_v[46]_connect`).
///
/// `src_addr`/`dst_addr` are 16 bytes regardless of family: IPv4
/// addresses are stored in the first 4 bytes with the rest zeroed.
/// Ports are network-order shorts converted to host order before
/// emission so userland doesn't have to know.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct TcpConnectRaw {
    pub pid: u32,
    pub uid: u32,
    pub family: u8,
    pub _pad0: [u8; 1],
    pub src_port: u16,
    pub dst_port: u16,
    pub _pad1: [u8; 2],
    pub src_addr: [u8; ADDR_LEN],
    pub dst_addr: [u8; ADDR_LEN],
    pub comm: [u8; TASK_COMM_LEN],
    pub timestamp_ns: u64,
}

impl TcpConnectRaw {
    pub const fn zeroed() -> Self {
        Self {
            pid: 0,
            uid: 0,
            family: 0,
            _pad0: [0; 1],
            src_port: 0,
            dst_port: 0,
            _pad1: [0; 2],
            src_addr: [0; ADDR_LEN],
            dst_addr: [0; ADDR_LEN],
            comm: [0u8; TASK_COMM_LEN],
            timestamp_ns: 0,
        }
    }
}

/// DNS query (kprobe `udp_sendmsg` filtered to dest port 53).
///
/// `query_name` is the **raw label-encoded QNAME** copied from the
/// UDP payload — the userland sensor decodes it to dotted notation.
/// Doing the decoding outside eBPF keeps the verifier happy and the
/// hot path bounded.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct DnsQueryRaw {
    pub pid: u32,
    pub uid: u32,
    pub qtype: u16,
    pub _pad0: [u8; 2],
    pub dns_server: [u8; ADDR_LEN],
    pub family: u8,
    pub _pad1: [u8; 1],
    pub qname_len: u16,
    pub query_name: [u8; QNAME_LEN],
    pub _pad2: [u8; 3],
    pub comm: [u8; TASK_COMM_LEN],
    pub timestamp_ns: u64,
}

impl DnsQueryRaw {
    pub const fn zeroed() -> Self {
        Self {
            pid: 0,
            uid: 0,
            qtype: 0,
            _pad0: [0; 2],
            dns_server: [0; ADDR_LEN],
            family: 0,
            _pad1: [0; 1],
            qname_len: 0,
            query_name: [0u8; QNAME_LEN],
            _pad2: [0; 3],
            comm: [0u8; TASK_COMM_LEN],
            timestamp_ns: 0,
        }
    }
}

/// Decode a fixed-size, possibly NUL-terminated byte buffer into a
/// borrowed `&str`, stopping at the first NUL or at the end of the
/// buffer. Invalid UTF-8 is replaced lossily by the caller.
#[cfg(feature = "std")]
pub fn cstr_lossy(buf: &[u8]) -> alloc::borrow::Cow<'_, str> {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    alloc::string::String::from_utf8_lossy(&buf[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, size_of};

    #[test]
    fn process_spawn_raw_layout_is_stable() {
        // 4 u32 + 16 + 256 + u64 = 16 + 16 + 256 + 8 = 296 bytes.
        // Aligned to 8 because of the trailing u64.
        assert_eq!(size_of::<ProcessSpawnRaw>(), 296);
        assert_eq!(align_of::<ProcessSpawnRaw>(), 8);
    }

    #[test]
    fn process_spawn_raw_round_trips_via_bytes() {
        let original = ProcessSpawnRaw {
            pid: 42,
            ppid: 7,
            uid: 1000,
            gid: 1000,
            comm: *b"ls\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            filename: {
                let mut f = [0u8; FILENAME_LEN];
                f[..8].copy_from_slice(b"/bin/ls\0");
                f
            },
            timestamp_ns: 1_700_000_000_000_000_000,
        };

        let bytes: &[u8] = bytemuck::bytes_of(&original);
        assert_eq!(bytes.len(), size_of::<ProcessSpawnRaw>());
        let restored: ProcessSpawnRaw = *bytemuck::from_bytes::<ProcessSpawnRaw>(bytes);
        assert_eq!(restored.pid, original.pid);
        assert_eq!(restored.ppid, original.ppid);
        assert_eq!(restored.uid, original.uid);
        assert_eq!(restored.gid, original.gid);
        assert_eq!(restored.comm, original.comm);
        assert_eq!(restored.filename, original.filename);
        assert_eq!(restored.timestamp_ns, original.timestamp_ns);
    }

    #[test]
    fn cstr_lossy_stops_at_nul() {
        let mut buf = [0u8; 16];
        buf[..2].copy_from_slice(b"ls");
        let s = cstr_lossy(&buf);
        assert_eq!(s, "ls");

        let s = cstr_lossy(b"abc\0xyz");
        assert_eq!(s, "abc");

        let s = cstr_lossy(b"no-nul-here");
        assert_eq!(s, "no-nul-here");
    }
}
