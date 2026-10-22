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

/// Bytes of a DNS query the socket-buffer sensor copies, from the start
/// of the name (Tappa 10.9 step 3): the longest legal name in wire form
/// (255 bytes, RFC 1035 §3.1), its type and its class fit.
pub const QNAME_WIRE_LEN: usize = 288;
const _: () = assert!(QNAME_WIRE_LEN >= 255 + 4);

/// `DnsQueryRaw::flags` (Tappa 10.9 step 3).
pub mod dns_flags {
    /// Read from the socket buffer the kernel built (`udp_send_skb` /
    /// `udp_v6_send_skb`): `query_name` holds `qname_len` wire bytes from
    /// the start of the name, and userland finds the name's end and the
    /// type. Without it the record comes from the `udp_sendmsg` kprobe: a
    /// string read from user memory, with `qtype` filled in the kernel.
    pub const SKB: u8 = 1 << 0;
    /// Part of the payload is in page fragments (`skb->data_len != 0`): a
    /// corked send, UDP GSO or zero copy. Only the linear part is read.
    pub const NONLINEAR: u8 = 1 << 1;
    /// Review 78: `held` counts queries of this process the kernel held
    /// back since its previous record (its own DNS budget ran out).
    pub const RATE_HELD: u8 = 1 << 2;
    /// Review 78: `held` includes queries of this process's user held back
    /// because the user's DNS budget ran out (counted on whichever of its
    /// processes records next).
    pub const RATE_HELD_UID: u8 = 1 << 3;
    /// Lab PR 229: a name the process asked systemd-resolved for through
    /// its NSS module (`agent-ebpf/src/dns_nss.rs`, a uprobe on
    /// `libnss_resolve.so.2`): `query_name` holds `qname_len` bytes of the
    /// name as the process passed it (text, not wire labels); no datagram
    /// was sent, so there is no server, family or type. It feeds the DNS
    /// attribution of the process's connects only.
    pub const NSS: u8 = 1 << 4;
}

/// IPv6 / padded-IPv4 address byte length.
pub const ADDR_LEN: usize = 16;

/// One process exec event as captured by the eBPF tracepoint.
///
/// Maximum bytes of the NUL-separated argv blob captured per spawn
/// (Tappa 10.6 §13 Q1). One bounded `bpf_probe_read_user` of
/// `[mm->arg_start, mm->arg_end)`; userland splits on NUL. 512 B covers
/// the overwhelming majority of real command lines.
pub const ARGV_LEN: usize = 512;

/// Layout MUST stay identical between the eBPF program and userland.
/// **Strict APPEND only** (Tappa 10.6 §13 Q5): the kernel↔userland
/// boundary is `bytemuck::Pod` validated by a size-checked
/// `try_from_bytes`, and the eBPF object is embedded in + rebuilt
/// atomically with the agent, so new fields go at the END and existing
/// fields are NEVER reordered (a reorder would silently corrupt the
/// cast). Explicit trailing padding keeps the struct free of implicit
/// padding bytes (a `bytemuck::Pod` requirement).
///
/// Tappa 10.6 D1 APPENDED `parent_comm` / `parent_start_ns` / `argv` /
/// `argv_len` (the argv + parent-context refit). The BPF side keeps
/// emitting zero for these until D2 wires the reads; userland decodes a
/// zeroed tail into empty/`0` defaults (mixed-fleet safe).
///
/// Cluster 15.3 APPENDED `parent_is_kthread` (one byte + 5 trailing
/// pad bytes reclaimed from the old 6-byte pad → total size
/// unchanged at 840). BPF reads
/// `parent->flags & PF_KTHREAD` and writes `1`/`0`; userland decodes
/// `0` → "false / unknown" → R011 fires (fail-secure). An old-BPF /
/// new-userland combination naturally surfaces a zeroed byte which is
/// the safe default — no fleet-wide upgrade required.
///
/// External audit EBPF-021 took the next pad byte for `trunc_flags`
/// ([`spawn_trunc`]); size and offsets unchanged.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct ProcessSpawnRaw {
    pub pid: u32,
    pub ppid: u32, // parent tgid — populated in D2 (was hard-coded 0)
    pub uid: u32,
    pub gid: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub filename: [u8; FILENAME_LEN],
    pub timestamp_ns: u64,
    // ── Tappa 10.6 APPENDED (never reorder the above) ──
    /// `real_parent->comm`, NUL-terminated (D2).
    pub parent_comm: [u8; TASK_COMM_LEN],
    /// `real_parent->group_leader->start_time` — PID-reuse-safe ancestry
    /// key (D2): the parent process's start, the `start_ns` its own exec
    /// reported, also when a thread other than its main one forked (lab
    /// PR 238; `real_parent->start_time`, the forking thread's, before).
    pub parent_start_ns: u64,
    /// NUL-separated argv blob from `[mm->arg_start, mm->arg_end)` (D2).
    pub argv: [u8; ARGV_LEN],
    /// Bytes written into `argv` (at most `ARGV_LEN - 1`). Whether the
    /// command line was longer is `trunc_flags` ([`spawn_trunc::ARGV`],
    /// external audit EBPF-021): the length alone cannot say it. `argc`
    /// is derived userland-side by counting NULs.
    pub argv_len: u16,
    /// Cluster 15.3 / R011: `1` iff the kernel marked the parent task
    /// with `PF_KTHREAD` at exec time (real kernel thread — kworker
    /// running udev/hardware-probe modprobe). `0` means either "not a
    /// kthread" OR "BPF could not read parent->flags" — both are
    /// treated identically by R011 (fail-secure FIRE). Non-forgeable
    /// from userspace: PF_KTHREAD is set by the kernel on kthread
    /// creation and cannot be cleared via `prctl(PR_SET_NAME)` or
    /// any other unprivileged op.
    pub parent_is_kthread: u8,
    /// External audit EBPF-021: [`spawn_trunc`] bits — what of the
    /// record is not the kernel's whole value (`argv` cut at
    /// `ARGV_LEN - 1` bytes or unread, `filename` cut at
    /// `FILENAME_LEN`). The first byte of the former `_pad`: an older
    /// eBPF object leaves it 0 ("not known to be cut").
    pub trunc_flags: u8,
    /// Explicit pad → no implicit `bytemuck::Pod` padding (size 840,
    /// align 8). Shrunk from 6 → 5 bytes when `parent_is_kthread`
    /// was added (cluster 15.3) and to 4 for `trunc_flags` (EBPF-021);
    /// total size unchanged.
    pub _pad: [u8; 4],
    // ── Tappa 10.9 step 2 APPENDED (never reorder the above) ──
    /// The file the caller named, as the LSM `bprm_check_security`
    /// program found it (pass 0, handed over through `EXEC_HANDOFF`):
    /// the canonical path the exec rules match (review 61). Zero in
    /// tracepoint mode.
    pub exe: exe::ExeIdentityRaw,
    // ── External audit POS-003 APPENDED (never reorder the above) ──
    /// The process's own `task->start_time` (its fork, CLOCK_MONOTONIC ns,
    /// the clock of `timestamp_ns`; exec keeps it): with `timestamp_ns`,
    /// what the lineage tracker orders an ancestor's exec against.
    pub start_ns: u64,
    // ── Lab PR 224 (CM-03) APPENDED (never reorder the above) ──
    /// The new image's standard streams (fds 0..2) as `sched_process_exec`
    /// found them: which are inet sockets, and the first one's peer
    /// ([`StdioRaw`]). Zero from an older eBPF object ("not read").
    pub stdio: StdioRaw,
    /// The same for the exec'ing task's real parent: a shell spawned on a
    /// pty by a process whose own stdio is a connected socket (the
    /// `pty.spawn` reverse shell: connect, `dup2` onto 0..2, spawn).
    pub parent_stdio: StdioRaw,
}

/// Lab PR 224 (CM-03): `StdioRaw::flags`.
pub mod stdio_flags {
    /// The task's file table was read (every offset resolved, the table
    /// reachable): the other bits are meaningful. Unset = unknown.
    pub const READ: u8 = 1 << 0;
    /// fd 0 (stdin) is an `AF_INET` / `AF_INET6` socket.
    pub const FD0_INET: u8 = 1 << 1;
    /// fd 1 (stdout) is an inet socket.
    pub const FD1_INET: u8 = 1 << 2;
    /// fd 2 (stderr) is an inet socket.
    pub const FD2_INET: u8 = 1 << 3;
    /// One of those sockets was connected out by a local process: its
    /// `struct sock` is in `FLOW_SOCK_MAP` (the `tcp_v[46]_connect`
    /// kprobe put it there). An accepted socket, a UDP socket, or a
    /// connect older than the agent is not.
    pub const OUTBOUND: u8 = 1 << 4;
    /// Any of fds 0..2 is an inet socket.
    pub const ANY_INET: u8 = FD0_INET | FD1_INET | FD2_INET;
}

/// Lab PR 224 (CM-03): one task's standard streams at an exec, read by
/// `sched_process_exec` through `task->files->fdt->fd[0..2]`: for a socket
/// (`S_IFSOCK`), `file->private_data` is the `struct socket`, whose `sk`
/// names the family, the protocol and the peer. 24 bytes, no implicit
/// padding.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct StdioRaw {
    /// [`stdio_flags`] bits.
    pub flags: u8,
    /// `sk_family` of the first inet socket on fds 0..2 (2 or 10), else 0.
    pub family: u8,
    /// Its peer port, host order (0 when not connected).
    pub peer_port: u16,
    /// Its `sk_protocol` (6 TCP, 17 UDP), 0 when unread.
    pub proto: u8,
    pub _pad: [u8; 3],
    /// Its peer address (IPv4 in the first four bytes).
    pub peer_addr: [u8; ADDR_LEN],
}

impl StdioRaw {
    pub const fn zeroed() -> Self {
        Self {
            flags: 0,
            family: 0,
            peer_port: 0,
            proto: 0,
            _pad: [0u8; 3],
            peer_addr: [0u8; ADDR_LEN],
        }
    }
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
            parent_comm: [0u8; TASK_COMM_LEN],
            parent_start_ns: 0,
            argv: [0u8; ARGV_LEN],
            argv_len: 0,
            parent_is_kthread: 0,
            trunc_flags: 0,
            _pad: [0u8; 4],
            exe: exe::ExeIdentityRaw::zeroed(),
            start_ns: 0,
            stdio: StdioRaw::zeroed(),
            parent_stdio: StdioRaw::zeroed(),
        }
    }
}

/// External audit EBPF-021: `ProcessSpawnRaw::trunc_flags`. Before them
/// the record could not say that a field was cut: an argument pushed past
/// byte 511 by filler options simply was not there, and the argv looked
/// complete.
pub mod spawn_trunc {
    /// `argv` is not the whole command line: `arg_end - arg_start` was
    /// over `ARGV_LEN` (the last argument kept may itself be cut), or the
    /// user read failed (`argv_len` 0).
    pub const ARGV: u8 = 1 << 0;
    /// `filename` (the caller's string, `bprm->filename`) was longer than
    /// `FILENAME_LEN` bytes with its NUL, and was cut.
    pub const FILENAME: u8 = 1 << 1;
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

/// Pre-exec event: one per binfmt pass of LSM `bprm_check_security`
/// (Tappa 10.9 step 2), or one per `execve` from `sys_enter_execve` in
/// tracepoint mode (the old sensor: user-memory filename, `exe` zero).
///
/// Distinct from `ProcessSpawnRaw` (post-exec tracepoint): this fires
/// before the new image runs, which is the kernel's last opportunity
/// to refuse the exec (the 10.9 inline-enforcement item).
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct ExecCheckRaw {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    /// The caller's `comm` (the hook runs before the exec takes effect).
    pub comm: [u8; TASK_COMM_LEN],
    /// `bprm->filename`: the caller's string, as the kernel copied it.
    pub filename: [u8; FILENAME_LEN],
    pub timestamp_ns: u64,
    /// The file this pass examines.
    pub exe: exe::ExeIdentityRaw,
}

impl ExecCheckRaw {
    pub const fn zeroed() -> Self {
        Self {
            pid: 0,
            ppid: 0,
            uid: 0,
            gid: 0,
            comm: [0u8; TASK_COMM_LEN],
            filename: [0u8; FILENAME_LEN],
            timestamp_ns: 0,
            exe: exe::ExeIdentityRaw::zeroed(),
        }
    }
}

/// Outbound TCP connect attempt (kprobe `tcp_v[46]_connect`).
///
/// `src_addr`/`dst_addr` are 16 bytes regardless of family: IPv4
/// addresses are stored in the first 4 bytes with the rest zeroed.
/// Ports are network-order shorts converted to host order before
/// emission so userland doesn't have to know.
///
/// Tappa 10 (N2) — appended `sk_ptr` field. The kernel-side
/// `struct sock` pointer is what `FLOW_SOCK_MAP` keys on, so
/// userland needs it to correlate this connect event with the
/// later `NetFlowCloseRaw` emitted by the `tcp_close` fexit
/// (which carries `flow_id` looked up from `FLOW_SOCK_MAP[sk_ptr]`).
/// Wire-size grew from 72 → 80 bytes; both kernel + userland are
/// rebuilt in the same N2 commit so there's no straddle window.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct TcpConnectRaw {
    pub pid: u32,
    pub uid: u32,
    pub family: u8,
    /// Lab PR 224: [`tcp_connect_flags`] (the former `_pad0`; 0 from the
    /// connect kprobe).
    pub flags: u8,
    pub src_port: u16,
    pub dst_port: u16,
    /// Lab PR 224: the socket's protocol for a record of the
    /// `socket_connect` deny (6, 17), 0 from the kprobe (TCP by
    /// construction). The former `_pad1[0]`.
    pub proto: u8,
    pub _pad1: [u8; 1],
    pub src_addr: [u8; ADDR_LEN],
    pub dst_addr: [u8; ADDR_LEN],
    pub comm: [u8; TASK_COMM_LEN],
    pub timestamp_ns: u64,
    /// Tappa 10 N2 — kernel `struct sock *` address. Opaque on
    /// the userland side (don't dereference); used as the key
    /// into `FLOW_SOCK_MAP` to correlate connect ↔ close.
    pub sk_ptr: u64,
}

impl TcpConnectRaw {
    pub const fn zeroed() -> Self {
        Self {
            pid: 0,
            uid: 0,
            family: 0,
            flags: 0,
            src_port: 0,
            dst_port: 0,
            proto: 0,
            _pad1: [0; 1],
            src_addr: [0; ADDR_LEN],
            dst_addr: [0; ADDR_LEN],
            comm: [0u8; TASK_COMM_LEN],
            timestamp_ns: 0,
            sk_ptr: 0,
        }
    }
}

/// Lab PR 224 (CM-02 c): entries of each of the `socket_connect` deny's
/// LPM tries (`NET_BLOCK_V4`, `NET_BLOCK_V6`). A blocklist with more is
/// loaded up to the bound (the rest is judged by NN-L-NET-001 at connect).
pub const NET_BLOCK_MAX_ENTRIES: u32 = 16_384;

/// Lab PR 224 (CM-02 c): `TcpConnectRaw::flags`.
pub mod tcp_connect_flags {
    /// The LSM `socket_connect` program refused this connect (`-EPERM`):
    /// its destination is in the operator blocklist and
    /// `--net-connect-deny` is on. No flow exists (`sk_ptr` is 0).
    pub const DENIED: u8 = 1 << 0;
}

// ── Tappa 10 (N2) — Network Observability BPF wire types ──────────────
//
// These are the `#[repr(C)]` POD records the new BPF programs emit
// into their ringbufs. Userland decodes via bytemuck, same pattern
// as `TcpConnectRaw` + `DnsQueryRaw` + `FimDriftRaw`.
//
// Capacity constants are shared with the eBPF crate (which is
// `no_std` but reads them via `northnarrow_common::wire::*`) so
// the byte sizing for ringbuf reservations + map max_entries is
// defined in ONE place — bumping a size doesn't require an
// out-of-band coordinated edit across two crates.

/// Tappa 10 (N2) — capacity of the `NET_FLOW_CLOSE_EVENTS` ringbuf
/// shared by `tcp_close` (TCP fexit) and `udp_sendmsg_outbound`
/// (UDP kprobe). Sized per design §5.3 — 256 KiB buffers ~3000
/// close events/s burst before back-pressure.
pub const NET_FLOW_CLOSE_EVENTS_BYTES: u32 = 256 * 1024;

/// Tappa 10 (N2) — capacity of the `NET_LISTEN_EVENTS` ringbuf.
/// Listener changes are rare; 64 KiB per §5.3.
pub const NET_LISTEN_EVENTS_BYTES: u32 = 64 * 1024;

/// Tappa 10 (N2) — `FLOW_SOCK_MAP` LRU HashMap entry cap: the outbound
/// TCP sockets the kernel remembers between their connect and their
/// close. Beyond it the LRU forgets the least recently used socket (a
/// long session first) and that socket's close is never recorded. Lab PR
/// 164: 65,536, the userland flow tracker's capacity
/// (`DEFAULT_PENDING_CAPACITY` in `agent/src/net/flow_tracker.rs`); it was
/// 4,096 (design §5.3). Kernel memory, preallocated when the map is
/// created: 72 bytes per element (a 48-byte `htab_elem` with its LRU node,
/// the 8-byte key, the 16-byte value) and a 16-byte bucket per element,
/// 65,536 × 88 B ≈ 5.5 MiB (was ≈ 0.34 MiB).
pub const FLOW_SOCK_MAP_MAX_ENTRIES: u32 = 65_536;

/// Lab PR 164 — size of the `FLOW_SOCK_COUNTS` per-CPU array: how many
/// sockets entered `FLOW_SOCK_MAP` as a new key, and how many a close
/// took out. An LRU does not say what it evicts. The difference is the
/// sockets whose close has not been seen, open sessions and forgotten
/// ones together; beyond the capacity, at least the excess was forgotten
/// (`nn-admin net status`).
pub const FLOW_SOCK_COUNT_SLOTS: u32 = 2;

/// Slots of `FLOW_SOCK_COUNTS`.
pub mod flow_sock_slot {
    /// A socket entered `FLOW_SOCK_MAP` (a new key: a reconnect of the
    /// same socket overwrites its entry and is not counted).
    pub const INSERTED: u32 = 0;
    /// A close found the socket and took it out.
    pub const REMOVED: u32 = 1;
}

/// Tappa 10 (N2) — `inet_csk_listen_start` kprobe event. Emitted
/// once per listen() syscall on a TCP/UDP socket, unconditionally
/// per design §13 Q6 (operator-visible filter happens rule-side
/// in N6 NN-L-NET-006 against the comm + port allowlist).
///
/// `bind_port` is host-order (the kernel stores `skc_num` host-order
/// after the bind syscall converts it). `bind_addr` is 16 bytes
/// regardless of family — IPv4 in bytes 0..4, IPv6 in bytes 0..16,
/// same pattern as `TcpConnectRaw`.
///
/// Layout chosen for natural u64 alignment with no implicit
/// padding before the trailing arrays: 8 + 4 + 4 + 1 + 1 + 2 + 2 +
/// 2 + 16 + 16 = 56 bytes, then the appended `held` / `held_uid`
/// (external audit EBPF-013): 64 bytes, 8-aligned (struct alignment =
/// u64).
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct NetListenRaw {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub family: u8,
    pub proto: u8,
    pub _pad0: [u8; 2],
    pub bind_port: u16,
    pub _pad1: [u8; 2],
    pub bind_addr: [u8; ADDR_LEN],
    pub comm: [u8; TASK_COMM_LEN],
    /// External audit EBPF-013: `listen()` calls of this process the
    /// kernel held back since its previous record (its own budget ran
    /// out); saturates at `u32::MAX`. Appended: older fields keep their
    /// offsets.
    pub held: u32,
    /// External audit EBPF-013: as `held`, for the budget of this
    /// process's user (across its processes).
    pub held_uid: u32,
}

impl NetListenRaw {
    pub const fn zeroed() -> Self {
        Self {
            timestamp_ns: 0,
            pid: 0,
            uid: 0,
            family: 0,
            proto: 0,
            _pad0: [0; 2],
            bind_port: 0,
            _pad1: [0; 2],
            bind_addr: [0; ADDR_LEN],
            comm: [0u8; TASK_COMM_LEN],
            held: 0,
            held_uid: 0,
        }
    }
}

/// Tappa 10 (N2) — flow close / outbound emission. UNIFIED record
/// across `tcp_close` (fexit, accurate byte counters via
/// `tcp_sock` reads) AND `udp_sendmsg_outbound` (kprobe, per-send
/// abbreviated). `proto` byte (IPPROTO_TCP / IPPROTO_UDP)
/// discriminates which kernel hook produced the row; both share
/// one ringbuf per design §13 Q3 lock-in ("UDP flow close is
/// conceptually equivalent to TCP flow close, single drain task").
///
/// TCP path populates:
///   - `flow_id` from `FLOW_SOCK_MAP[sk_ptr]` (set by the
///     connect kprobe at flow start).
///   - `bytes_sent` / `bytes_recv` from `tcp_sock` fields.
///   - `close_reason` from `sk->sk_err & 0xFF`: 0 = graceful
///     FIN exchange, 104 (ECONNRESET) = RST received, 110
///     (ETIMEDOUT) = keepalive timeout, other = errored close.
///
/// UDP path populates:
///   - `flow_id` = zeros (no sock-lifetime; N3 synthesises one
///     per (pid, five_tuple) burst window).
///   - `bytes_sent` = `len` arg of the udp_sendmsg call (this
///     send only — N3 accumulates across the burst window).
///   - `bytes_recv` = 0.
///   - `close_reason` = 0.
///
/// Layout: 8 + 8 + 8 + 16 + 4 + 4 + 16 + 16 + 16 + 1 + 1 + 1 +
/// 1 + 2 + 2 + 8 = 112 bytes, 8-aligned.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct NetFlowCloseRaw {
    pub timestamp_ns: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    /// 16-byte correlation ID. TCP: copied from `FLOW_SOCK_MAP[sk_ptr]`
    /// (written by the connect kprobe). UDP: zeros.
    pub flow_id: [u8; ADDR_LEN],
    pub pid: u32,
    pub uid: u32,
    pub src_addr: [u8; ADDR_LEN],
    pub dst_addr: [u8; ADDR_LEN],
    pub comm: [u8; TASK_COMM_LEN],
    pub family: u8,
    pub proto: u8,
    /// Low 8 bits of `sock->sk_err` for TCP fexit; 0 for UDP.
    /// 0 = graceful, 104 = ECONNRESET, 110 = ETIMEDOUT.
    pub close_reason: u8,
    pub _pad0: [u8; 1],
    pub src_port: u16,
    pub dst_port: u16,
    pub _pad1: [u8; 8],
}

impl NetFlowCloseRaw {
    pub const fn zeroed() -> Self {
        Self {
            timestamp_ns: 0,
            bytes_sent: 0,
            bytes_recv: 0,
            flow_id: [0u8; ADDR_LEN],
            pid: 0,
            uid: 0,
            src_addr: [0; ADDR_LEN],
            dst_addr: [0; ADDR_LEN],
            comm: [0u8; TASK_COMM_LEN],
            family: 0,
            proto: 0,
            close_reason: 0,
            _pad0: [0; 1],
            src_port: 0,
            dst_port: 0,
            _pad1: [0; 8],
        }
    }
}

/// DNS query: one per UDP datagram to port 53. From the kprobes on
/// `udp_send_skb` / `udp_v6_send_skb` (the kernel's copy, IPv4 and IPv6;
/// [`dns_flags::SKB`]) or, in `--dns-sensor sendmsg` mode, the kprobe on
/// `udp_sendmsg` (user memory, IPv4).
///
/// `query_name` is the **raw label-encoded QNAME** copied from the
/// UDP payload — the userland sensor decodes it to dotted notation.
/// Doing the decoding outside eBPF keeps the verifier happy and the
/// hot path bounded. 344 bytes.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct DnsQueryRaw {
    pub pid: u32,
    pub uid: u32,
    pub qtype: u16,
    /// Review 78: queries held back by the kernel's DNS budgets since the
    /// previous record ([`dns_flags::RATE_HELD`],
    /// [`dns_flags::RATE_HELD_UID`]); saturates at `u16::MAX`. The bytes
    /// were padding, so the layout is unchanged.
    pub held: u16,
    pub dns_server: [u8; ADDR_LEN],
    pub family: u8,
    /// [`dns_flags`].
    pub flags: u8,
    pub qname_len: u16,
    pub query_name: [u8; QNAME_WIRE_LEN],
    pub comm: [u8; TASK_COMM_LEN],
    pub timestamp_ns: u64,
}

impl DnsQueryRaw {
    pub const fn zeroed() -> Self {
        Self {
            pid: 0,
            uid: 0,
            qtype: 0,
            held: 0,
            dns_server: [0; ADDR_LEN],
            family: 0,
            flags: 0,
            qname_len: 0,
            query_name: [0u8; QNAME_WIRE_LEN],
            comm: [0u8; TASK_COMM_LEN],
            timestamp_ns: 0,
        }
    }
}

/// Composite key for the Tappa 7 `PROTECTED_INODES` BPF map.
///
/// Userland keys come from `stat(2)` (`st_dev`, `st_ino`); the eBPF
/// LSM hooks rebuild the same pair from `inode->i_sb->s_dev` and
/// `inode->i_ino`. We use `u64` for `dev` on both sides even though
/// the kernel `dev_t` is 32 bits — the wider type guarantees the
/// BPF map's key blob is naturally 8-aligned with no implicit pad.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "std",
    derive(
        bytemuck::Pod,
        bytemuck::Zeroable,
        serde::Serialize,
        serde::Deserialize
    )
)]
pub struct InodeKey {
    pub dev: u64,
    pub ino: u64,
}

/// External audit EBPF-010: the keys of the eBPF `OWN_PIN_NAMES` map —
/// FNV-1a (64-bit) of a link pin's final path component. The `bpf` LSM hook
/// hashes the final component of an `OBJ_GET` path in one pass, a loop the
/// verifier checks in linear time (copying it into a 32-byte key made it
/// explore every length and `/` position, past the million-instruction
/// budget); userland registers each pin name with [`pin_name_hash`].
pub const PIN_NAME_HASH_SEED: u64 = 0xcbf2_9ce4_8422_2325;
pub const PIN_NAME_HASH_PRIME: u64 = 0x0000_0100_0000_01b3;

/// [`PIN_NAME_HASH_SEED`] folded with `name`, byte by byte, as the hook does.
pub fn pin_name_hash(name: &[u8]) -> u64 {
    let mut h = PIN_NAME_HASH_SEED;
    let mut i = 0;
    while i < name.len() {
        h = (h ^ name[i] as u64).wrapping_mul(PIN_NAME_HASH_PRIME);
        i += 1;
    }
    h
}

/// External audit EBPF-001: the one slot of the pinned `KILL_GRANT` map —
/// when PID 1 (systemd) may signal a protected process. The agent writes
/// it only while a signed trusted-installer window is open (`systemctl
/// stop`/`restart` of the units during an upgrade or maintenance) and
/// zeroes it when the window closes and at every boot. The hook honours it
/// for a signal in `sig_mask` (bit `n` = signal `n`), before `expires_ns`
/// (`bpf_ktime_get_ns`, CLOCK_MONOTONIC), with `nonce` equal to this
/// boot's non-zero session nonce.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct KillGrant {
    pub nonce: u32,
    pub sig_mask: u32,
    pub expires_ns: u64,
}

impl KillGrant {
    /// The signals systemd sends to stop a unit: `KillSignal=` (SIGTERM),
    /// the SIGCONT that follows it, and `FinalKillSignal=` (SIGKILL).
    pub const STOP_SIGNALS: u32 = (1 << 15) | (1 << 18) | (1 << 9);

    /// Whether this grant lets PID 1 send `sig` at monotonic `now_ns`
    /// under session `session` — the kernel hook's test, kept here so it
    /// is unit-tested once.
    pub fn allows(&self, sig: i32, now_ns: u64, session: u32) -> bool {
        self.nonce != 0
            && self.nonce == session
            && (1..32).contains(&sig)
            && self.sig_mask & (1u32 << sig) != 0
            && now_ns < self.expires_ns
    }
}

/// External audit ATP-003: the one slot of the pinned `FS_GRANT` map —
/// the kernel half of the trusted-installer window. While active, the
/// filesystem deny hooks (and the kexec refusal, and the pin root's)
/// let a protected inode be changed. It replaces `FS_PROTECT_OVERRIDE`,
/// whose value was the session nonce alone: zeroing it on expiry was the
/// agent's job, done on the event path — a host whose events had stopped
/// kept every file unprotected past the deadline. The hooks now test the
/// deadline themselves (`bpf_ktime_get_ns`, CLOCK_MONOTONIC), as for
/// [`KillGrant`].
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct FsGrant {
    pub nonce: u32,
    pub _pad: u32,
    pub expires_ns: u64,
}

impl FsGrant {
    /// Whether the window is open at monotonic `now_ns` under session
    /// `session` — the kernel hooks' test, kept here so it is unit-tested
    /// once.
    pub fn active(&self, now_ns: u64, session: u32) -> bool {
        self.nonce != 0 && self.nonce == session && now_ns < self.expires_ns
    }
}

// Tappa 7 filesystem-protection denial codes. The eBPF inode hooks
// write one of these into `FsProtectDenialRaw.operation` when they
// return `-EPERM`. Userland inflates the byte into the typed
// `model::FsProtectOperation`.
/// `_IOC(dir, type, nr, size)` as `<asm-generic/ioctl.h>` builds it.
const fn ioc(dir: u32, ty: u8, nr: u8, size: u32) -> u32 {
    (dir << 30) | (size << 16) | ((ty as u32) << 8) | nr as u32
}
const IOC_WRITE: u32 = 1;

/// `FS_IOC_SETFLAGS = _IOW('f', 2, long)`: `chattr +i/-i/+a`.
pub const FS_IOC_SETFLAGS: u32 = ioc(IOC_WRITE, b'f', 2, 8);
/// `FS_IOC32_SETFLAGS = _IOW('f', 2, int)`: the same from a 32-bit binary.
pub const FS_IOC32_SETFLAGS: u32 = ioc(IOC_WRITE, b'f', 2, 4);
/// `FS_IOC_FSSETXATTR = _IOW('X', 32, struct fsxattr)` (28 bytes): the
/// same flags (`FS_XFLAG_IMMUTABLE`, `FS_XFLAG_APPEND`, ...) by the fsxattr
/// interface — `xfs_io -c 'chattr -i'`, and some `chattr` builds.
/// External audit EBPF-008: the eBPF side had `0x40285821` here, a number
/// no ioctl uses, and did not filter it anyway.
pub const FS_IOC_FSSETXATTR: u32 = ioc(IOC_WRITE, b'X', 32, 28);

pub const FS_OP_UNLINK: u8 = 1;
pub const FS_OP_RMDIR: u8 = 2;
pub const FS_OP_RENAME: u8 = 3;
pub const FS_OP_SETATTR: u8 = 4;
pub const FS_OP_IOCTL: u8 = 5;
/// at-authz-1: a write-intent `open(2)` (`file->f_mode & FMODE_WRITE`)
/// of a WRITE-protected inode. Denied by the `file_open` deny hook so an
/// `O_WRONLY|O_APPEND` / in-place `pwrite` (which touches no metadata, so
/// `inode_setattr` never fires) cannot mutate admin.pub / agent.sig.key /
/// the integrity chains.
pub const FS_OP_WRITE: u8 = 6;
/// BPF self-defence (Tappa 10.8): a foreign process opened one of the
/// agent's own BPF maps for writing (`bpf_map` LSM hook). `target_ino`
/// carries the map id, `target_dev` is 0.
pub const FS_OP_BPF_MAP: u8 = 7;
/// A handle to one of the agent's own BPF *links* refused to a foreign
/// process (`bpftool link show id N`, `bpftool link detach id N` / `…
/// pinned <path>`): by id through `LINK_GET_FD_BY_ID` (`target_ino` = link
/// id) or through `OBJ_GET` on the link's pin (`target_ino` = 0), or a
/// `LINK_DETACH` / `LINK_UPDATE` on a handle that names one of them
/// (`target_ino` = link id). Emitted by the `bpf` LSM observer in enforce
/// mode (Tappa 10.8 BPF self-defence, second half). The enumeration
/// (`LINK_GET_NEXT_ID`) gives no handle and is neither refused nor
/// recorded (lab PR 215).
pub const FS_OP_BPF_LINK: u8 = 8;
/// A signal to a protected pid refused by the `task_kill` LSM hook
/// (`target_ino` = target tgid, `target_dev` = signal number). Rate-limited
/// in the kernel (per caller and globally): evidence, not a flood channel.
pub const FS_OP_SIGNAL: u8 = 9;
/// A ptrace ATTACH-mode access to a protected pid refused by the
/// `ptrace_access_check` hook — debugger attach, `/proc/<pid>/mem`,
/// `process_vm_readv/writev` (`target_ino` = target tgid, `target_dev` = the
/// ptrace mode bits). READ-mode and NOAUDIT checks (`ps`, `lsof`, journald
/// reading `/proc/<pid>/exe`) are denied silently, as before.
pub const FS_OP_PTRACE: u8 = 10;
/// Review 82: a kexec kernel image load refused by the `kernel_read_file`
/// (`kexec_file_load`) or `kernel_load_data` (`kexec_load`) hook outside
/// the trusted-installer window (`target_dev` = the kernel's read/load id,
/// `target_ino` = 0). A loaded image lets root reboot straight into a
/// kernel without the agent.
pub const FS_OP_KEXEC: u8 = 11;
/// External audit EVD-001: an open of a READ-protected inode — the agent's
/// private signing key — by a process outside the agent's family, read
/// access included. Recorded, not a COMBAT trigger: a backup of `/etc`
/// meets it too.
pub const FS_OP_READ: u8 = 12;
/// External audit EBPF-015: a new entry in a NOCREATE directory, refused
/// by `inode_create` — `open(O_CREAT)`, `creat(2)`, `mknod(S_IFREG)`, a
/// bpffs pin (`target_*` = the directory).
pub const FS_OP_CREATE: u8 = 13;
/// A hard link made in a NOCREATE directory (`inode_link`; `target_*` =
/// the directory). Also how an `O_TMPFILE` file would get a name there.
pub const FS_OP_LINK: u8 = 14;
/// A symlink made in a NOCREATE directory (`inode_symlink`).
pub const FS_OP_SYMLINK: u8 = 15;
/// A subdirectory made in a NOCREATE directory (`inode_mkdir`).
pub const FS_OP_MKDIR: u8 = 16;
/// A device node, FIFO or socket made in a NOCREATE directory
/// (`inode_mknod`).
pub const FS_OP_MKNOD: u8 = 17;
/// An extended attribute set or removed on a protected inode
/// (`inode_setxattr` / `inode_removexattr`, and `inode_set_acl` /
/// `inode_remove_acl` where the kernel has them). `security.selinux` is
/// not refused: `restorecon` relabels the agent's files on SELinux hosts.
pub const FS_OP_XATTR: u8 = 18;

/// at-authz-1 PROTECTED_INODES value flag-mask. The map value (formerly an
/// unused `1u8` presence sentinel) now records WHICH deny classes apply to
/// each registered inode, so the WRITE-open deny can cover a secret/integrity
/// SUBSET without write-denying operator-tunable config files (which would be
/// an enforce-mode COMBAT footgun). Userland registration helpers set the bits
/// per file class; `deny_if_protected` is op-aware against them.
///
/// `FS_PROTECT_MUTATE` (bit0): the legacy modification denies
/// (unlink/rmdir/rename/setattr/ioctl) — set on EVERY registered member, so
/// "presence" semantics are preserved for the existing five hooks.
pub const FS_PROTECT_MUTATE: u8 = 0b01;
/// `FS_PROTECT_WRITE` (bit1): the new write-open deny (`FS_OP_WRITE`) — set
/// only on the secret/integrity subset (admin.pub, agent_id, audit.log,
/// agent.sig.key, the state chains, the agent binaries/units).
pub const FS_PROTECT_WRITE: u8 = 0b10;
/// `FS_PROTECT_READ` (bit2, external audit EVD-001): any open, read-only
/// included (`FS_OP_READ`) — set only on the agent's private signing key,
/// whose inode number also sits in `READ_PROTECTED_INOS` so the common
/// read path pays no map lookup.
pub const FS_PROTECT_READ: u8 = 0b100;
/// `FS_PROTECT_NOCREATE` (bit3, external audit EBPF-015): no new entry —
/// create, link, symlink, mkdir, mknod — in this directory. Set only on the
/// agent's own directories (`/etc/northnarrow`, `/var/lib/northnarrow` and
/// its chain sub-directory, the unit drop-in directory, the bpffs pin
/// root), never on the ordinary parent of a protected file.
pub const FS_PROTECT_NOCREATE: u8 = 0b1000;
/// Slots of the `READ_PROTECTED_INOS` array (inode numbers; 0 = empty).
pub const READ_PROTECTED_SLOTS: u32 = 4;

/// The `PROTECTED_INODES` flag a denial of `operation` requires — the
/// kernel deny's op-aware test (`deny_if_protected`), kept here so it is
/// unit-tested once. A write-open needs `FS_PROTECT_WRITE`, a read-open
/// `FS_PROTECT_READ`, a new entry `FS_PROTECT_NOCREATE` on the directory;
/// every other operation (unlink, rmdir, rename, setattr, the flag ioctls,
/// an extended attribute) `FS_PROTECT_MUTATE`, which every member has.
pub const fn fs_protect_required(operation: u8) -> u8 {
    match operation {
        FS_OP_WRITE => FS_PROTECT_WRITE,
        FS_OP_READ => FS_PROTECT_READ,
        FS_OP_CREATE | FS_OP_LINK | FS_OP_SYMLINK | FS_OP_MKDIR | FS_OP_MKNOD => {
            FS_PROTECT_NOCREATE
        }
        _ => FS_PROTECT_MUTATE,
    }
}

/// Audit record emitted whenever a Tappa 7 inode-protection LSM hook
/// returns `-EPERM`. The denial is the security event — userland
/// raises a WARN and feeds the agent's posture machine.
///
/// Field order chosen for natural u64 alignment with no implicit
/// padding gaps before `_pad`: 8 + 8 + 8 + 4 + 4 + 16 + 1 + 7 = 56.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct FsProtectDenialRaw {
    pub timestamp_ns: u64,
    pub target_dev: u64,
    pub target_ino: u64,
    pub attacker_pid: u32,
    pub attacker_uid: u32,
    pub attacker_comm: [u8; TASK_COMM_LEN],
    pub operation: u8,
    pub _pad: [u8; 7],
}

impl FsProtectDenialRaw {
    pub const fn zeroed() -> Self {
        Self {
            timestamp_ns: 0,
            target_dev: 0,
            target_ino: 0,
            attacker_pid: 0,
            attacker_uid: 0,
            attacker_comm: [0u8; TASK_COMM_LEN],
            operation: 0,
            _pad: [0u8; 7],
        }
    }
}

// ── bpf() syscall observation (Tappa 10.8, BPF self-defence) ────────────
/// Synthetic `cmd` values for [`BpfSyscallRaw`] beyond the uapi `bpf_cmd`
/// numbers: emitted by the `bpf_map` hook in observe mode when a foreign
/// process opens one of the agent's maps for writing (would be denied in
/// enforce mode).
pub const BPF_CMD_FOREIGN_MAP_WRITE: u32 = 0xFFFF_0001;
/// A foreign process obtained a handle to one of the agent's own objects
/// by id (`BPF_*_GET_FD_BY_ID`) — observe-mode counterpart of the deny.
pub const BPF_CMD_FOREIGN_GET_FD: u32 = 0xFFFF_0002;

/// Kernel→userland record of the `bpf()` syscall observer (40 bytes).
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct BpfSyscallRaw {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; TASK_COMM_LEN],
    /// uapi `enum bpf_cmd` value, or a `BPF_CMD_*` synthetic value.
    pub cmd: u32,
    /// Command-specific argument: `prog_type` (PROG_LOAD), `map_type`
    /// (MAP_CREATE), `attach_type` (PROG_ATTACH / LINK_CREATE), object id
    /// (`*_GET_FD_BY_ID`, synthetic cmds), 0 otherwise.
    pub arg: u32,
}

/// Name of a uapi `bpf_cmd` value (the ones the observer reports). Lab PR
/// 215: the numbers come from [`crate::bpf_cmd`]; this match had its own
/// copy, with `link_get_fd_by_id` at 31 (`BPF_LINK_GET_NEXT_ID`) and the
/// real 30 named "other".
pub const fn bpf_cmd_name(cmd: u32) -> &'static str {
    use crate::bpf_cmd::*;
    match cmd {
        BPF_MAP_CREATE => "map_create",
        BPF_PROG_LOAD => "prog_load",
        BPF_OBJ_PIN => "obj_pin",
        BPF_OBJ_GET => "obj_get",
        BPF_PROG_ATTACH => "prog_attach",
        BPF_PROG_DETACH => "prog_detach",
        BPF_PROG_GET_FD_BY_ID => "prog_get_fd_by_id",
        BPF_MAP_GET_FD_BY_ID => "map_get_fd_by_id",
        BPF_BTF_LOAD => "btf_load",
        BPF_LINK_CREATE => "link_create",
        BPF_LINK_UPDATE => "link_update",
        BPF_LINK_GET_FD_BY_ID => "link_get_fd_by_id",
        BPF_LINK_DETACH => "link_detach",
        BPF_CMD_FOREIGN_MAP_WRITE => "foreign_map_write",
        BPF_CMD_FOREIGN_GET_FD => "foreign_get_fd",
        _ => "other",
    }
}

// ── io_uring sensor (Tappa 10.8, the blind channel) ────────────────────
/// `IoUringRaw.kind`: a ring was created (`io_uring_setup`).
pub const IOURING_KIND_CREATE: u8 = 1;
/// `IoUringRaw.kind`: submissions on an existing ring, aggregated per pid
/// in kernel (emitted when a new opcode class appears or once per second).
pub const IOURING_KIND_ACTIVITY: u8 = 2;
/// Opcode classes (`IoUringRaw.classes` bitmap), one bit per `IORING_OP_*` family.
pub const IOURING_CLASS_FILE_OPEN: u32 = 1 << 0;
pub const IOURING_CLASS_FILE_RW: u32 = 1 << 1;
pub const IOURING_CLASS_NET_CONNECT: u32 = 1 << 2;
pub const IOURING_CLASS_NET_SENDRECV: u32 = 1 << 3;
pub const IOURING_CLASS_FS_MUTATE: u32 = 1 << 4;
pub const IOURING_CLASS_OTHER: u32 = 1 << 5;

/// Map an `IORING_OP_*` number (uapi/linux/io_uring.h, ABI-stable) to its class bit.
pub const fn io_uring_opcode_class(op: u8) -> u32 {
    match op {
        // OPENAT, OPENAT2
        18 | 28 => IOURING_CLASS_FILE_OPEN,
        // READV WRITEV READ_FIXED WRITE_FIXED READ WRITE SPLICE TEE READ_MULTISHOT
        1 | 2 | 4 | 5 | 22 | 23 | 30 | 33 | 49 => IOURING_CLASS_FILE_RW,
        // ACCEPT CONNECT SOCKET BIND LISTEN
        13 | 16 | 45 | 56 | 57 => IOURING_CLASS_NET_CONNECT,
        // SENDMSG RECVMSG SEND RECV SEND_ZC SENDMSG_ZC
        9 | 10 | 26 | 27 | 47 | 48 => IOURING_CLASS_NET_SENDRECV,
        // FALLOCATE RENAMEAT UNLINKAT MKDIRAT SYMLINKAT LINKAT FSETXATTR SETXATTR FTRUNCATE
        17 | 35 | 36 | 37 | 38 | 39 | 41 | 42 | 55 => IOURING_CLASS_FS_MUTATE,
        _ => IOURING_CLASS_OTHER,
    }
}

/// Kernel→userland record of the io_uring sensor (56 bytes, no implicit
/// padding; 48 before the appended `held` / `held_uid`).
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct IoUringRaw {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; TASK_COMM_LEN],
    /// [`IOURING_KIND_CREATE`] | [`IOURING_KIND_ACTIVITY`].
    pub kind: u8,
    /// Last `IORING_OP_*` seen (ACTIVITY); 0 for CREATE.
    pub last_opcode: u8,
    /// `sq_thread` of the last submission (SQPOLL kernel thread submitting).
    pub sq_thread: u8,
    pub _pad: u8,
    /// Classes seen by this pid since its first submission (ACTIVITY), or
    /// the ring `flags` (CREATE).
    pub classes: u32,
    /// Submissions since the previous ACTIVITY record, or `sq_entries` (CREATE).
    pub count: u32,
    /// Explicit tail padding: 44 → 48 bytes so `Pod` holds (8-byte alignment).
    pub _pad2: u32,
    /// External audit EBPF-013: ring creations of this process the kernel
    /// held back since its previous CREATE record (its own budget ran
    /// out); saturates at `u32::MAX`. Always 0 on ACTIVITY records.
    /// Appended: older fields keep their offsets.
    pub held: u32,
    /// External audit EBPF-013: as `held`, for the budget of this
    /// process's user (across its processes).
    pub held_uid: u32,
}

/// `ModuleLoadRaw.method` — `finit_module(2)` via the `kernel_read_file`
/// LSM hook (modern path; carries the source `.ko` path, filled in
/// stage 1b).
pub const MODULE_LOAD_FINIT: u8 = 1;
/// `ModuleLoadRaw.method` — `init_module(2)` via the `kernel_load_data`
/// LSM hook (legacy userspace-buffer path; no file, so no path).
pub const MODULE_LOAD_INIT: u8 = 2;
/// Max source-path bytes captured for a finit_module load (stage 1b):
/// 16 leaf→root components × 32-byte slots. Audit `abi-modpath-1`: with
/// 8 slots, ~20% of the modules under `/usr/lib/modules/<ver>/kernel/…`
/// (≥10 named components) lost the `/usr/lib/modules` prefix and R018
/// SIGKILLed + COMBATed benign loads. 16 covers every path in a stock
/// 6.8 tree; deeper paths are flagged via [`ModuleLoadRaw::path_truncated`].
pub const MODULE_PATH_LEN: usize = 512;
/// [`ModuleLoadRaw::path_truncated`]: the path is deeper than the walk's
/// slots — deeper than any module directory.
pub const MODULE_PATH_TOO_DEEP: u8 = 1;
/// [`ModuleLoadRaw::path_truncated`]: a kernel read failed during the walk.
pub const MODULE_PATH_UNREADABLE: u8 = 2;

/// Kernel module-load observation (BUG-034). Emitted by the
/// `kernel_read_file` / `kernel_load_data` BPF-LSM hooks
/// (`agent-ebpf/src/module_load.rs`) onto `MODULE_LOAD_EVENTS`. The
/// LOAD is the rootkit-LKM chokepoint that FIM-008 (file path) and
/// R011 (tool exec) both miss.
///
/// Field order chosen for natural u64 alignment with no implicit
/// padding: 8 + 4 + 4 + 16 + 16 + 1 + 1 + 2 + 1 + 3 + 512 + 8 + 8 = 584 (8-aligned).
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct ModuleLoadRaw {
    pub timestamp_ns: u64,
    pub loader_pid: u32,
    pub loader_uid: u32,
    pub loader_comm: [u8; TASK_COMM_LEN],
    /// Real-parent comm — stage 1b (pairs with the PF_KTHREAD exemption).
    pub parent_comm: [u8; TASK_COMM_LEN],
    /// [`MODULE_LOAD_FINIT`] | [`MODULE_LOAD_INIT`].
    pub method: u8,
    /// `1` if the real parent is a kernel thread (PF_KTHREAD) — a boot
    /// hardware-probe load. Stage 1b; `0` this commit.
    pub parent_is_kthread: u8,
    /// Bytes of `path` populated (`0` for init_module / stage 1).
    pub path_len: u16,
    /// `1` when the dentry walk ran out of slots BEFORE reaching the
    /// filesystem root: `path` then holds only the leaf-most components
    /// and its prefix is unknown. Userland reconstructs such a path
    /// WITHOUT a leading `/` so consumers can tell it apart.
    /// 0: the path reached the filesystem root. [`MODULE_PATH_TOO_DEEP`]:
    /// every slot was used first. [`MODULE_PATH_UNREADABLE`]: a kernel
    /// read failed (external audit PROC-004 tells the two apart).
    pub path_truncated: u8,
    pub _pad: [u8; 3],
    /// Source `.ko` path for a finit_module load (stage 1b); zeroed otherwise.
    pub path: [u8; MODULE_PATH_LEN],
    /// External audit PROC-005: the inode key of the filesystem root the
    /// walk reached (`path_truncated == 0`), which userland maps to its
    /// mount point: `path` is relative to that filesystem, so a `.ko` on a
    /// mount whose own tree reads `lib/modules/…` looked standard. Zero
    /// when the root was not reached.
    pub root_dev: u64,
    pub root_ino: u64,
}

impl ModuleLoadRaw {
    pub const fn zeroed() -> Self {
        Self {
            timestamp_ns: 0,
            loader_pid: 0,
            loader_uid: 0,
            loader_comm: [0u8; TASK_COMM_LEN],
            parent_comm: [0u8; TASK_COMM_LEN],
            method: 0,
            parent_is_kthread: 0,
            path_len: 0,
            path_truncated: 0,
            _pad: [0u8; 3],
            path: [0u8; MODULE_PATH_LEN],
            root_dev: 0,
            root_ino: 0,
        }
    }
}

// Tappa 9 (C1) — FIM drift detection codes. The kernel-side
// observe-only LSM hooks (agent-ebpf/src/fim_watch.rs, C2) write
// one of these into `FimDriftRaw.op` when they reserve a ringbuf
// slot. Userland inflates the byte into the typed
// `wire::FimOp` enum.
//
// Discriminants are stable wire bytes — never renumber; appending
// only. Mirrors the Tappa 7 `FS_OP_*` style.
pub const FIM_OP_MODIFIED: u8 = 1;
pub const FIM_OP_CREATED: u8 = 2;
pub const FIM_OP_DELETED: u8 = 3;
pub const FIM_OP_RENAMED: u8 = 4;
pub const FIM_OP_LINKED: u8 = 5;
/// Tappa 9 (C5.2): `file_open` LSM observation. Emitted by
/// `fim_file_open_observe` on EVERY open of a watched inode
/// (read or write). Userland C5.3 cred-read rules classify
/// downstream — the BPF layer doesn't filter by access mode
/// since the WATCHED_PATHS set is already operator-curated.
pub const FIM_OP_OPENED: u8 = 6;
/// Review 86: a file capability (`security.capability`) was set on the
/// file, by any route. Built in userland from the file-open sensor's
/// `inode_post_setxattr` record; never sent by the FIM watch.
pub const FIM_OP_CAPABILITY_SET: u8 = 7;
/// Wave 2 (TST-004): a watched file's mode, owner or group changed while
/// its content did not (`chmod u+s`, `chmod o+r /etc/shadow`, `chown`).
/// The kernel reports such a setattr as [`FIM_OP_MODIFIED`]; userland
/// tells it apart from a content change against the baseline. Never sent
/// by the FIM watch.
pub const FIM_OP_ATTR_CHANGED: u8 = 8;

/// Tappa 9 (BUG-022) — max bytes of a created/renamed-in child's
/// leaf name carried inline in [`FimDriftRaw::child_name`]. A NUL
/// terminator is included, so the longest fully-represented leaf is
/// `FIM_CHILD_NAME_LEN - 1` bytes; a longer leaf sets
/// [`FIM_CHILD_TRUNCATED`]. 64 covers every real `.ko` / `.service`
/// / `pam_*.so` / cron leaf; a >63-byte leaf in a system
/// persistence directory is itself anomalous and still fires the
/// rule (via the truncated flag) even though its suffix is lost.
pub const FIM_CHILD_NAME_LEN: usize = 64;

/// [`FimDriftRaw::child_name_flags`] bit: the child leaf was longer
/// than [`FIM_CHILD_NAME_LEN`] and was truncated into the buffer.
/// Userland mirrors it into [`FimEvent::child_truncated`] so the
/// dir-rooted persistence rules (NN-L-FIM-021/023) fire on a suffix
/// they can no longer see.
pub const FIM_CHILD_TRUNCATED: u8 = 0x01;

/// [`FimDriftRaw::op_flags`] bit (external audit FIMR-004): a rename put
/// another file over this watched inode — the watched path's content was
/// replaced in one call (`rename(2)` of a prepared file over a binary, a
/// PAM module, a unit), not moved away.
pub const FIM_RENAME_REPLACED: u8 = 0x01;

/// [`FimDriftRaw::op_flags`] bit (lab PR 225): a watched inode was renamed
/// and [`FimDriftRaw::child_name`] carries its NEW leaf name, with
/// `dest_dev`/`dest_ino` naming the directory it went to. Without the bit a
/// leaf in a `Renamed` record is the name of a file renamed INTO a watched
/// directory (BUG-022). NN-L-FIM-010 matched the destination directory's
/// path instead of the file's new name, so `x → x.locked` did not fire.
pub const FIM_RENAME_DEST_LEAF: u8 = 0x02;

/// Tappa 9 (C1) — kernel↔userland record emitted by the FIM
/// observation hooks (design §5). One record per watched-inode
/// drift event. Userland's `agent/src/fim/drain.rs` (C4) decodes
/// these into the richer userland [`FimEvent`].
///
/// Layout: timestamp + (dev,ino) target + (dev,ino) dest +
/// modifier triple + op byte + pad + child-name tail. **144 bytes**,
/// 8-byte aligned. Tappa 9 polish #3 (rename dest-path resolution)
/// grew this from 56 → 72 bytes by appending `dest_dev` + `dest_ino`
/// for `Renamed` events; BUG-022 (dir child-leaf reconstruction)
/// grew it 72 → 144 by appending `child_name` + flags. All additions
/// are strict-append (Tappa 10.6 §13 Q5) and older emitters zero the
/// tail. The layout stays a strict superset of the Tappa 7
/// [`FsProtectDenialRaw`] prefix so the C4 drain decode logic
/// is still byte-symmetric on the leading 56 bytes.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct FimDriftRaw {
    pub timestamp_ns: u64,
    pub target_dev: u64,
    pub target_ino: u64,
    pub modifier_pid: u32,
    pub modifier_uid: u32,
    pub modifier_comm: [u8; TASK_COMM_LEN],
    /// One of the `FIM_OP_*` discriminants above. Inflated by
    /// userland into [`FimOp`].
    pub op: u8,
    /// External audit FIMR-004: [`FIM_RENAME_REPLACED`] when the
    /// rename put another file over the watched inode (`new_dentry`).
    pub op_flags: u8,
    pub _pad: [u8; 6],
    /// Polish #3 — rename DEST `(dev, ino)`. Populated by
    /// `fim_rename_observe` when the SOURCE inode is in
    /// WATCHED_PATHS (and the dest dentry's inode is reachable
    /// from the kernel hook args). Userland's drain then
    /// attempts to resolve `(dest_dev, dest_ino)` → path via
    /// [`crate::wire::InodeKey`]; success populates
    /// `FimEvent::dest_path` so the NN-L-FIM-010 rule (and
    /// future dest-aware rules) can match on the destination
    /// extension. Zero for non-Rename ops AND for renames
    /// where the kernel-side couldn't extract a dest inode.
    pub dest_dev: u64,
    pub dest_ino: u64,
    /// Tappa 9 (BUG-022) — leaf name of the child created in (or
    /// renamed into) a watched DIRECTORY, NUL-terminated, decoded
    /// UTF-8-lossy by userland. Populated by `fim_create_observe`
    /// (the new child dentry) and the dest arm of
    /// `fim_rename_observe`; all-zero for every other op and for a
    /// create/rename whose target directory is not itself watched.
    /// Userland reconstructs `dir + "/" + leaf` so the child-prefix
    /// rules (NN-L-FIM-007/008/009/021/023) can match — without it
    /// the event carries only the bare watched-directory path, which
    /// no child-prefix rule matches (the BUG-022 dead-rule root).
    pub child_name: [u8; FIM_CHILD_NAME_LEN],
    /// Bit flags describing `child_name`; currently only
    /// [`FIM_CHILD_TRUNCATED`]. Zero when `child_name` is empty.
    pub child_name_flags: u8,
    pub _pad2: [u8; 7],
}

impl FimDriftRaw {
    pub const fn zeroed() -> Self {
        Self {
            timestamp_ns: 0,
            target_dev: 0,
            target_ino: 0,
            modifier_pid: 0,
            modifier_uid: 0,
            modifier_comm: [0u8; TASK_COMM_LEN],
            op: 0,
            op_flags: 0,
            _pad: [0u8; 6],
            dest_dev: 0,
            dest_ino: 0,
            child_name: [0u8; FIM_CHILD_NAME_LEN],
            child_name_flags: 0,
            _pad2: [0u8; 7],
        }
    }
}

/// Tappa 10.9 step 0 — sensor-feasibility probe records.
/// Lab PR 219 — the exploit post-condition guard's record.
pub mod epg;
pub mod exe;
/// Lab PR 226 (EXPERIMENTAL): synchronous exec policies and the exec
/// environment / executable mapping checks.
pub mod execpol;
/// Lab PR 223 (EXPERIMENTAL): exec quarantine at first sight.
pub mod execq;
pub mod open_sensor;
pub mod sensor_probe;

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

    /// External audit EBPF-001: PID 1 may signal a protected process only
    /// with a live grant of this boot, for a stop signal, before expiry.
    #[test]
    fn a_kill_grant_is_bounded_by_session_signal_and_time() {
        let g = KillGrant {
            nonce: 0xABCD,
            sig_mask: KillGrant::STOP_SIGNALS,
            expires_ns: 1_000,
        };
        assert!(g.allows(15, 999, 0xABCD), "SIGTERM inside the window");
        assert!(g.allows(9, 0, 0xABCD), "SIGKILL inside the window");
        assert!(g.allows(18, 0, 0xABCD), "SIGCONT inside the window");
        assert!(!g.allows(15, 1_000, 0xABCD), "expired");
        assert!(!g.allows(15, 0, 0x1234), "another boot's session");
        assert!(!g.allows(19, 0, 0xABCD), "SIGSTOP is not a stop signal");
        assert!(!g.allows(2, 0, 0xABCD), "SIGINT is not a stop signal");
        assert!(!g.allows(0, 0, 0xABCD) && !g.allows(32, 0, 0xABCD) && !g.allows(-1, 0, 0xABCD));
        assert!(
            !KillGrant::default().allows(15, 0, 0),
            "the zeroed slot grants nothing"
        );
    }
    /// External audit ATP-003: the window is bounded by its session and
    /// its deadline in the kernel itself.
    #[test]
    fn fs_grant_inactive_after_expiry_or_other_session() {
        let g = FsGrant {
            nonce: 0xABCD,
            _pad: 0,
            expires_ns: 1_000,
        };
        assert!(g.active(999, 0xABCD), "inside the window");
        assert!(!g.active(1_000, 0xABCD), "expired");
        assert!(!g.active(0, 0x1234), "another boot's session");
        assert!(
            !FsGrant::default().active(0, 0),
            "the zeroed slot grants nothing"
        );
        assert_eq!(core::mem::size_of::<FsGrant>(), 16);
    }
    use core::mem::{align_of, size_of};

    #[test]
    fn process_spawn_raw_layout_is_stable() {
        // Existing prefix: 4 u32 + 16 + 256 + u64 = 296 (offset of the
        // T10.6 APPEND). Appended: parent_comm 16 + parent_start_ns 8 +
        // argv 512 + argv_len 2 + _pad 6 = 544. Total 840, align 8.
        // The trailing _pad keeps the Pod free of implicit padding.
        // Tappa 10.9 step 2 appended `exe` (552) at 840: 1,392; POS-003
        // `start_ns` at 1,392: 1,400. Lab PR 224 appended `stdio` and
        // `parent_stdio` (24 each) at 1,400: 1,448.
        assert_eq!(size_of::<ProcessSpawnRaw>(), 1448);
        assert_eq!(core::mem::offset_of!(ProcessSpawnRaw, start_ns), 1392);
        assert_eq!(core::mem::offset_of!(ProcessSpawnRaw, stdio), 1400);
        assert_eq!(core::mem::offset_of!(ProcessSpawnRaw, parent_stdio), 1424);
        assert_eq!(size_of::<StdioRaw>(), 24);
        assert_eq!(align_of::<ProcessSpawnRaw>(), 8);
        // The existing-field prefix must not have shifted (strict APPEND).
        assert_eq!(core::mem::offset_of!(ProcessSpawnRaw, parent_comm), 296);
        assert_eq!(core::mem::offset_of!(ProcessSpawnRaw, exe), 840);
        // External audit EBPF-021: `trunc_flags` is the first byte of the
        // former 5-byte pad, after `parent_is_kthread`; nothing moved.
        assert_eq!(core::mem::offset_of!(ProcessSpawnRaw, argv_len), 832);
        assert_eq!(
            core::mem::offset_of!(ProcessSpawnRaw, parent_is_kthread),
            834
        );
        assert_eq!(core::mem::offset_of!(ProcessSpawnRaw, trunc_flags), 835);
        assert_eq!(core::mem::offset_of!(ProcessSpawnRaw, _pad), 836);
    }

    #[test]
    fn exec_check_raw_layout_is_stable() {
        assert_eq!(size_of::<ExecCheckRaw>(), 848);
        assert_eq!(align_of::<ExecCheckRaw>(), 8);
        assert_eq!(core::mem::offset_of!(ExecCheckRaw, exe), 296);
    }

    /// Tappa 10.9 step 3: the pad byte after `family` became `flags`, and
    /// `query_name` grew from 253 bytes (+3 pad) to 288, so the longest
    /// wire name, its type and its class fit. Nothing before it moved.
    #[test]
    fn dns_query_raw_layout_is_stable() {
        assert_eq!(size_of::<DnsQueryRaw>(), 344);
        assert_eq!(align_of::<DnsQueryRaw>(), 8);
        assert_eq!(core::mem::offset_of!(DnsQueryRaw, family), 28);
        assert_eq!(core::mem::offset_of!(DnsQueryRaw, flags), 29);
        assert_eq!(core::mem::offset_of!(DnsQueryRaw, qname_len), 30);
        assert_eq!(core::mem::offset_of!(DnsQueryRaw, query_name), 32);
        assert_eq!(core::mem::offset_of!(DnsQueryRaw, comm), 320);
        assert_eq!(core::mem::offset_of!(DnsQueryRaw, timestamp_ns), 336);
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
            parent_comm: *b"bash\0\0\0\0\0\0\0\0\0\0\0\0",
            parent_start_ns: 1_699_999_000_000_000_000,
            start_ns: 0,
            argv: {
                let mut a = [0u8; ARGV_LEN];
                a[..7].copy_from_slice(b"ls\0-la\0");
                a
            },
            argv_len: 7,
            parent_is_kthread: 0,
            trunc_flags: spawn_trunc::ARGV,
            _pad: [0u8; 4],
            exe: exe::ExeIdentityRaw::zeroed(),
            stdio: StdioRaw {
                flags: stdio_flags::READ | stdio_flags::FD0_INET | stdio_flags::OUTBOUND,
                family: 2,
                peer_port: 44401,
                proto: 6,
                _pad: [0; 3],
                peer_addr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            },
            parent_stdio: StdioRaw::zeroed(),
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
        assert_eq!(restored.parent_comm, original.parent_comm);
        assert_eq!(restored.parent_start_ns, original.parent_start_ns);
        assert_eq!(restored.argv, original.argv);
        assert_eq!(restored.argv_len, original.argv_len);
        assert_eq!(restored.trunc_flags, spawn_trunc::ARGV);
        assert_eq!(restored.stdio, original.stdio);
        assert_eq!(restored.parent_stdio, StdioRaw::zeroed());
    }

    #[test]
    fn fs_protect_denial_raw_layout_is_stable() {
        // 8+8+8+4+4+16+1+7 = 56, aligned to 8.
        assert_eq!(size_of::<FsProtectDenialRaw>(), 56);
        assert_eq!(align_of::<FsProtectDenialRaw>(), 8);
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

    // ── Tappa 9 C1 — FIM wire types ────────────────────────────────

    /// C1 (+ polish #3) test #1: [`FimDriftRaw`] layout matches
    /// the kernel↔userland ABI exactly. **144 bytes**, 8-aligned.
    /// Polish #3 grew this from 56 → 72 bytes by appending
    /// `dest_dev` + `dest_ino` (each `u64`); BUG-022 grew it
    /// 72 → 144 by appending the `child_name` tail so
    /// `fim_create_observe` / `fim_rename_observe` can communicate
    /// the dropped child's leaf to userland. Wire-byte stability
    /// matters — any change here is a coordinated kernel+user upgrade.
    #[test]
    fn fim_drift_raw_layout_is_stable() {
        // 8 + 8 + 8 + 4 + 4 + 16 + 1 + 7 + 8 + 8 (= 72, polish #3)
        // + 64 + 1 + 7 (= 144, BUG-022 child-name tail), 8-aligned.
        assert_eq!(size_of::<FimDriftRaw>(), 144);
        assert_eq!(align_of::<FimDriftRaw>(), 8);
        // FsProtectDenialRaw stays at the original 56-byte
        // shape; the FIM drift record is now a SUPERSET (first
        // 56 bytes identical, dest_dev + dest_ino appended).
        assert_eq!(size_of::<FsProtectDenialRaw>(), 56);
    }

    /// C1 (+ polish #3) test #2: [`FimDriftRaw`] bytemuck
    /// round-trip with the new dest fields populated. The
    /// kernel-side BPF serialises via `bytes_of`; userland
    /// decodes via `from_bytes`. Anchors the Pod/Zeroable
    /// derive on the expanded layout.
    #[test]
    fn fim_drift_raw_round_trips_via_bytes() {
        let original = FimDriftRaw {
            timestamp_ns: 1_700_000_000_000_000_000,
            target_dev: 0x800002,
            target_ino: 12345,
            modifier_pid: 42,
            modifier_uid: 0,
            modifier_comm: *b"sshd\0\0\0\0\0\0\0\0\0\0\0\0",
            op: FIM_OP_RENAMED,
            op_flags: 0,
            _pad: [0u8; 6],
            dest_dev: 0x800003,
            dest_ino: 67890,
            child_name: {
                let mut c = [0u8; FIM_CHILD_NAME_LEN];
                c[..7].copy_from_slice(b"evil.ko");
                c
            },
            child_name_flags: 0,
            _pad2: [0u8; 7],
        };
        let bytes: &[u8] = bytemuck::bytes_of(&original);
        assert_eq!(bytes.len(), size_of::<FimDriftRaw>());
        let restored: FimDriftRaw = *bytemuck::from_bytes::<FimDriftRaw>(bytes);
        assert_eq!(restored.timestamp_ns, original.timestamp_ns);
        assert_eq!(restored.target_dev, original.target_dev);
        assert_eq!(restored.target_ino, original.target_ino);
        assert_eq!(restored.modifier_pid, original.modifier_pid);
        assert_eq!(restored.modifier_comm, original.modifier_comm);
        assert_eq!(restored.op, original.op);
        assert_eq!(restored.dest_dev, original.dest_dev);
        assert_eq!(restored.dest_ino, original.dest_ino);
    }

    /// C1 test #3: [`FimOp`] discriminants lock in the wire bytes
    /// 1..=5. Variant order MUST track `FIM_OP_*` discriminant
    /// order — a reorder would silently change the byte semantics
    /// of every kernel-emitted `FimDriftRaw` record.
    /// External audit EBPF-008: the ioctl numbers the file_ioctl deny
    /// filters are the uapi ones (`<linux/fs.h>`, x86-64 and arm64).
    #[test]
    fn fs_ioctl_numbers_match_uapi() {
        assert_eq!(FS_IOC_SETFLAGS, 0x4008_6602);
        assert_eq!(FS_IOC32_SETFLAGS, 0x4004_6602);
        assert_eq!(FS_IOC_FSSETXATTR, 0x401c_5820);
    }

    /// Lab PR 215: each command the observer reports has its uapi name,
    /// the link handle by id included (it was "other", and the
    /// enumeration `BPF_LINK_GET_NEXT_ID` was named as the handle).
    #[test]
    fn bpf_cmd_names_follow_the_uapi_names() {
        use crate::bpf_cmd::{observed, UAPI};
        for (name, value) in UAPI {
            let want = name.trim_start_matches("BPF_").to_ascii_lowercase();
            if observed(value) {
                assert_eq!(bpf_cmd_name(value), want, "{name}");
            } else {
                assert_eq!(bpf_cmd_name(value), "other", "{name}");
            }
        }
        assert_eq!(bpf_cmd_name(30), "link_get_fd_by_id");
        assert_eq!(bpf_cmd_name(31), "other");
        assert_eq!(bpf_cmd_name(BPF_CMD_FOREIGN_GET_FD), "foreign_get_fd");
    }

    /// External audit EBPF-015: a new entry is refused only in a NOCREATE
    /// directory — never on the MUTATE bit every protected directory has,
    /// which would refuse every file created next to a protected one — and
    /// an extended attribute like any other change of a protected inode.
    #[test]
    fn fs_protect_required_matches_each_op_to_its_bit() {
        for op in [
            FS_OP_CREATE,
            FS_OP_LINK,
            FS_OP_SYMLINK,
            FS_OP_MKDIR,
            FS_OP_MKNOD,
        ] {
            assert_eq!(fs_protect_required(op), FS_PROTECT_NOCREATE, "op {op}");
        }
        for op in [
            FS_OP_UNLINK,
            FS_OP_RMDIR,
            FS_OP_RENAME,
            FS_OP_SETATTR,
            FS_OP_IOCTL,
            FS_OP_XATTR,
        ] {
            assert_eq!(fs_protect_required(op), FS_PROTECT_MUTATE, "op {op}");
        }
        assert_eq!(fs_protect_required(FS_OP_WRITE), FS_PROTECT_WRITE);
        assert_eq!(fs_protect_required(FS_OP_READ), FS_PROTECT_READ);
        let bits = [
            FS_PROTECT_MUTATE,
            FS_PROTECT_WRITE,
            FS_PROTECT_READ,
            FS_PROTECT_NOCREATE,
        ];
        for (i, a) in bits.iter().enumerate() {
            assert_eq!(a.count_ones(), 1);
            for b in &bits[i + 1..] {
                assert_eq!(a & b, 0, "flag bits overlap");
            }
        }
    }

    /// The denial codes are distinct: the record carries one byte.
    #[test]
    fn fs_op_codes_are_distinct() {
        let ops = [
            FS_OP_UNLINK,
            FS_OP_RMDIR,
            FS_OP_RENAME,
            FS_OP_SETATTR,
            FS_OP_IOCTL,
            FS_OP_WRITE,
            FS_OP_BPF_MAP,
            FS_OP_BPF_LINK,
            FS_OP_SIGNAL,
            FS_OP_PTRACE,
            FS_OP_KEXEC,
            FS_OP_READ,
            FS_OP_CREATE,
            FS_OP_LINK,
            FS_OP_SYMLINK,
            FS_OP_MKDIR,
            FS_OP_MKNOD,
            FS_OP_XATTR,
        ];
        for (i, a) in ops.iter().enumerate() {
            assert_ne!(*a, 0);
            for b in &ops[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    // ── Tappa 10 N2 — BPF emission wire types ──────────────────────

    /// N2 test #1: [`TcpConnectRaw`] layout after the N2 `sk_ptr`
    /// extension. The struct grew from 72 → 80 bytes; userland +
    /// kernel rebuild together in this commit so the wire change
    /// is atomic. Anchor the new size + 8-alignment so a future
    /// reorder fails fast.
    #[test]
    fn tcp_connect_raw_layout_is_stable_after_sk_ptr_extension() {
        // 4+4+1+1+2+2+2+16+16+16+8+8 = 80 bytes.
        assert_eq!(size_of::<TcpConnectRaw>(), 80);
        assert_eq!(align_of::<TcpConnectRaw>(), 8);
    }

    /// N2 test #2: [`TcpConnectRaw`] round-trip with the new
    /// `sk_ptr` field populated. Bytemuck-decoded record on
    /// userland MUST observe the same `sk_ptr` value the BPF
    /// kprobe stored — that's the load-bearing property for the
    /// userland `connect_event_by_sk_ptr` correlation map.
    #[test]
    fn tcp_connect_raw_round_trips_via_bytes() {
        let original = TcpConnectRaw {
            pid: 12345,
            uid: 1000,
            family: 2, // AF_INET
            flags: tcp_connect_flags::DENIED,
            src_port: 0,
            dst_port: 443,
            proto: 6,
            _pad1: [0; 1],
            src_addr: [0; ADDR_LEN],
            dst_addr: {
                let mut a = [0u8; ADDR_LEN];
                a[0] = 1;
                a[1] = 2;
                a[2] = 3;
                a[3] = 4;
                a
            },
            comm: *b"curl\0\0\0\0\0\0\0\0\0\0\0\0",
            timestamp_ns: 1_700_000_000_000_000_000,
            sk_ptr: 0xFFFF_FFFF_DEAD_BEEF,
        };
        let bytes: &[u8] = bytemuck::bytes_of(&original);
        assert_eq!(bytes.len(), size_of::<TcpConnectRaw>());
        let restored: TcpConnectRaw = *bytemuck::from_bytes::<TcpConnectRaw>(bytes);
        assert_eq!(restored.pid, original.pid);
        assert_eq!(restored.dst_port, original.dst_port);
        assert_eq!(restored.dst_addr, original.dst_addr);
        assert_eq!(restored.timestamp_ns, original.timestamp_ns);
        // Lab PR 224: the former pad bytes carry the deny flag and the
        // protocol; nothing else moved.
        assert_eq!(restored.flags, tcp_connect_flags::DENIED);
        assert_eq!(restored.proto, 6);
        assert_eq!(core::mem::offset_of!(TcpConnectRaw, flags), 9);
        assert_eq!(core::mem::offset_of!(TcpConnectRaw, dst_port), 12);
        assert_eq!(core::mem::offset_of!(TcpConnectRaw, proto), 14);
        assert_eq!(core::mem::offset_of!(TcpConnectRaw, src_addr), 16);
        assert_eq!(
            restored.sk_ptr, original.sk_ptr,
            "sk_ptr round-trip MUST preserve the kernel pointer bits"
        );
    }

    /// N2 test #3: [`NetListenRaw`] layout. 64 bytes, 8-aligned
    /// — anchor the wire size so an inadvertent field reorder
    /// surfaces here before reaching the BPF verifier.
    #[test]
    fn net_listen_raw_layout_is_stable() {
        // 8 + 4 + 4 + 1 + 1 + 2 + 2 + 2 + 16 + 16 = 56 bytes, then the
        // appended held counters (external audit EBPF-013) = 64.
        assert_eq!(size_of::<NetListenRaw>(), 64);
        assert_eq!(align_of::<NetListenRaw>(), 8);
        // The pre-EBPF-013 fields keep their offsets.
        assert_eq!(core::mem::offset_of!(NetListenRaw, bind_port), 20);
        assert_eq!(core::mem::offset_of!(NetListenRaw, bind_addr), 24);
        assert_eq!(core::mem::offset_of!(NetListenRaw, comm), 40);
        assert_eq!(core::mem::offset_of!(NetListenRaw, held), 56);
        assert_eq!(core::mem::offset_of!(NetListenRaw, held_uid), 60);
    }

    /// External audit EBPF-013: [`IoUringRaw`] layout, with the held
    /// counters appended after the former 48-byte record.
    #[test]
    fn io_uring_raw_layout_is_stable() {
        assert_eq!(size_of::<IoUringRaw>(), 56);
        assert_eq!(align_of::<IoUringRaw>(), 8);
        assert_eq!(core::mem::offset_of!(IoUringRaw, comm), 16);
        assert_eq!(core::mem::offset_of!(IoUringRaw, kind), 32);
        assert_eq!(core::mem::offset_of!(IoUringRaw, classes), 36);
        assert_eq!(core::mem::offset_of!(IoUringRaw, count), 40);
        assert_eq!(core::mem::offset_of!(IoUringRaw, held), 48);
        assert_eq!(core::mem::offset_of!(IoUringRaw, held_uid), 52);
    }

    /// N2 test #4: [`NetListenRaw`] bytemuck round-trip. The BPF
    /// program builds the record in ringbuf-reserved memory;
    /// userland decodes via `from_bytes`. This test pins the
    /// Pod / Zeroable derives on the wire shape.
    #[test]
    fn net_listen_raw_round_trips_via_bytes() {
        let original = NetListenRaw {
            timestamp_ns: 1_700_000_000_000_000_000,
            pid: 1234,
            uid: 0,
            family: 2, // AF_INET
            proto: 6,  // IPPROTO_TCP
            _pad0: [0; 2],
            bind_port: 22,
            _pad1: [0; 2],
            bind_addr: [0u8; ADDR_LEN],
            comm: *b"sshd\0\0\0\0\0\0\0\0\0\0\0\0",
            held: 300,
            held_uid: 7,
        };
        let bytes: &[u8] = bytemuck::bytes_of(&original);
        assert_eq!(bytes.len(), size_of::<NetListenRaw>());
        let restored: NetListenRaw = *bytemuck::from_bytes::<NetListenRaw>(bytes);
        assert_eq!(restored.held, 300);
        assert_eq!(restored.held_uid, 7);
        assert_eq!(restored.bind_port, original.bind_port);
        assert_eq!(restored.proto, original.proto);
        assert_eq!(restored.family, original.family);
        assert_eq!(restored.pid, original.pid);
        assert_eq!(restored.comm, original.comm);
    }

    /// N2 test #5: [`NetFlowCloseRaw`] layout. 112 bytes,
    /// 8-aligned. This struct is the LARGEST of the N2 wire
    /// types (carries 5-tuple + byte counters + correlation
    /// ID); an unexpected size regression here likely means a
    /// field reorder broke bytemuck Pod's no-padding contract.
    #[test]
    fn net_flow_close_raw_layout_is_stable() {
        // 8 + 8 + 8 + 16 + 4 + 4 + 16 + 16 + 16 + 1 + 1 + 1 + 1 +
        // 2 + 2 + 8 = 112 bytes.
        assert_eq!(size_of::<NetFlowCloseRaw>(), 112);
        assert_eq!(align_of::<NetFlowCloseRaw>(), 8);
    }

    /// N2 test #6: [`NetFlowCloseRaw`] bytemuck round-trip,
    /// exercising the unified TCP + UDP shape — populate
    /// every "TCP-only" field (`flow_id`, `bytes_recv`,
    /// `close_reason`) plus the shared 5-tuple so the test
    /// fixture covers both code paths' contributions to the
    /// wire bytes.
    #[test]
    fn net_flow_close_raw_round_trips_via_bytes() {
        let mut flow_id = [0u8; ADDR_LEN];
        for (i, b) in flow_id.iter_mut().enumerate() {
            *b = i as u8;
        }
        let original = NetFlowCloseRaw {
            timestamp_ns: 1_700_000_000_500_000_000,
            bytes_sent: 12_345,
            bytes_recv: 67_890,
            flow_id,
            pid: 8888,
            uid: 0,
            src_addr: [0; ADDR_LEN],
            dst_addr: {
                let mut a = [0u8; ADDR_LEN];
                a[0] = 1;
                a[1] = 2;
                a[2] = 3;
                a[3] = 4;
                a
            },
            comm: *b"curl\0\0\0\0\0\0\0\0\0\0\0\0",
            family: 2,
            proto: 6,
            close_reason: 104, // ECONNRESET
            _pad0: [0; 1],
            src_port: 54321,
            dst_port: 443,
            _pad1: [0; 8],
        };
        let bytes: &[u8] = bytemuck::bytes_of(&original);
        assert_eq!(bytes.len(), size_of::<NetFlowCloseRaw>());
        let restored: NetFlowCloseRaw = *bytemuck::from_bytes::<NetFlowCloseRaw>(bytes);
        assert_eq!(restored.flow_id, original.flow_id);
        assert_eq!(restored.bytes_sent, original.bytes_sent);
        assert_eq!(restored.bytes_recv, original.bytes_recv);
        assert_eq!(restored.close_reason, original.close_reason);
        assert_eq!(restored.proto, original.proto);
        assert_eq!(restored.dst_port, original.dst_port);
    }

    /// N2 test #7: capacity-constant lock-in. The byte sizes
    /// of the new ringbufs + the LRU map entry cap are
    /// design-doc literals (§5.3); a future "tune them" PR
    /// must update both the constant AND this test in the
    /// same commit so review catches sizing changes.
    #[test]
    fn n2_map_capacity_constants_lock_in() {
        assert_eq!(NET_FLOW_CLOSE_EVENTS_BYTES, 256 * 1024);
        assert_eq!(NET_LISTEN_EVENTS_BYTES, 64 * 1024);
        // Lab PR 164: the userland flow tracker's capacity (4,096 before).
        assert_eq!(FLOW_SOCK_MAP_MAX_ENTRIES, 65_536);
        assert_eq!(FLOW_SOCK_COUNT_SLOTS, 2);
        assert_eq!(flow_sock_slot::INSERTED, 0);
        assert_eq!(flow_sock_slot::REMOVED, 1);
    }
}
