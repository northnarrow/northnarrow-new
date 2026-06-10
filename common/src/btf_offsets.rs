//! Hard-coded kernel struct field offsets — the single source of truth.
//!
//! aya-ebpf 0.1 emits no CO-RE field relocations, so every kernel
//! pointer dereference in the LSM hooks and sensors goes through one of
//! these byte offsets plus `bpf_probe_read_kernel`. The values are
//! hard-coded for x86_64 Linux 6.8.x (Ubuntu 24.04), captured from
//! `/sys/kernel/btf/vmlinux` via `bpftool btf dump file ... format raw`;
//! each per-const comment cites the BTF query that produced it.
//!
//! These constants live in `common` so BOTH the eBPF crate (which
//! compiles them into the programs, `default-features = false`) and the
//! agent (which revalidates them) read the SAME values — there is no
//! second copy to drift out of sync.
//!
//! ## Revalidation — the safety contract (BUG-036)
//!
//! Drift is the failure mode to fear: a kernel upgrade can move any of
//! these, and a wrong offset makes every dependent LSM decision and
//! sensor read operate on the wrong kernel memory. The agent therefore
//! revalidates every entry in [`REVALIDATE`] against the RUNNING
//! kernel's BTF at boot, before attaching any program (see
//! `agent::anti_tamper::btf_revalidate`). On any mismatch it refuses to
//! start (exit 78 / `EX_CONFIG`) rather than attach hooks that read
//! garbage. These constants are the fast-path values; the boot-time
//! revalidation is what makes trusting them safe.
//!
//! NOTE: [`PF_KTHREAD`] is a kernel `#define` bitmask, not a struct
//! offset, so it is not in [`REVALIDATE`] (there is no layout to
//! re-derive — only the flag-test semantics, which fail CLOSED).

// ── Cluster 15.3 / R011 — process lineage + kthread signal ───────────

/// `struct task_struct.tgid` — thread-group id, the value
/// `getpid(2)` returns to userland. `bits_offset=19936` from BTF.
pub const TASK_STRUCT_TGID_OFFSET: usize = 2492;

/// `struct task_struct.flags` — `unsigned int` per-task flag bitmap
/// (`PF_KTHREAD=0x00200000` etc., see `include/linux/sched.h`).
///
/// Cluster 15.3 / R011: read off the PARENT task to obtain a
/// non-forgeable "is this exec spawned by a real kernel thread?"
/// signal. Replaces the userspace `/proc/<ppid>/exe` absence check
/// (BUG-008' P-7) which raced against kthread reaping and over-fired
/// on already-gone modprobe spawns.
///
/// Validated 2026-05-28 against `/sys/kernel/btf/vmlinux`
/// (`[204] STRUCT 'task_struct'` → `'flags' bits_offset=352`, byte 44).
/// `flags` sits right after `thread_info` (40 B on x86_64) and
/// `__state` (4 B), a structurally stable position across modern
/// x86_64 kernels. The boot-time BTF revalidator
/// (`agent::anti_tamper::btf_revalidate`) fails LOUD on drift, and
/// R011's PF_KTHREAD test fails CLOSED on an unreadable parent
/// (over-fire, not under-fire).
pub const TASK_STRUCT_FLAGS_OFFSET: usize = 44;

/// `PF_KTHREAD` per-task flag (bit 21) — `include/linux/sched.h`.
/// Set by the kernel on every genuine kernel thread (kworker,
/// ksoftirqd, etc.); userspace cannot set or clear it. The
/// canonical "is this a real kthread?" test. A `#define`, not a
/// struct offset — see the module note on [`REVALIDATE`].
pub const PF_KTHREAD: u32 = 0x0020_0000;

// ── Tappa 10.6 D2 — process-spawn argv + parent context ──────────────
//
// Validated 2026-05-21 against `/sys/kernel/btf/vmlinux` on
// `6.8.0-117-generic`. `[82] STRUCT 'task_struct' size=13696`;
// `[438] STRUCT 'mm_struct' size=1344`. Two-deref chains
// (`task → real_parent → field`, `task → mm → field`), each step a
// `bpf_probe_read_kernel`.

/// `struct task_struct.mm` — `struct mm_struct *` (the new image's mm
/// at `sched_process_exec`; argv lives off it). `'mm' bits_offset=18880`
/// = byte 2360.
pub const TASK_STRUCT_MM_OFFSET: usize = 2360;

/// `struct task_struct.real_parent` — `struct task_struct *` to the
/// real parent. `'real_parent' bits_offset=20032` = byte 2504. (Use
/// `real_parent`, not `parent`, for genuine lineage — `parent` can be a
/// ptracer.) The parent's pid is then `parent + TASK_STRUCT_TGID_OFFSET`.
pub const TASK_STRUCT_REAL_PARENT_OFFSET: usize = 2504;

/// `struct task_struct.start_time` — `u64` CLOCK_MONOTONIC nanoseconds
/// at task creation. `'start_time' bits_offset=22656` = byte 2832.
/// Chosen over `start_boottime` (byte 2840) because it shares the
/// `bpf_ktime_get_ns()` clock domain the CorrelationStore compares
/// against — the PID-reuse-safe ancestry key.
pub const TASK_STRUCT_START_TIME_OFFSET: usize = 2832;

/// `struct task_struct.comm` — `char[16]` (`TASK_COMM_LEN`).
/// `'comm' bits_offset=24256` = byte 3032. Read off the parent task
/// for `parent_comm`.
pub const TASK_STRUCT_COMM_OFFSET: usize = 3032;

/// `struct mm_struct.arg_start` — `unsigned long` USER pointer to the
/// start of the argv string block. `'arg_start' bits_offset=3008` =
/// byte 376.
pub const MM_STRUCT_ARG_START_OFFSET: usize = 376;

/// `struct mm_struct.arg_end` — `unsigned long` USER pointer to the end
/// of the argv block. `'arg_end' bits_offset=3072` = byte 384.
/// `[arg_start, arg_end)` is exactly the NUL-separated argv — one
/// bounded user read.
pub const MM_STRUCT_ARG_END_OFFSET: usize = 384;

// ── FIM / anti-tamper — dentry / inode / file ────────────────────────

/// `struct dentry.d_inode` — the `*inode` pointer. `bits_offset=384`.
pub const DENTRY_D_INODE_OFFSET: usize = 48;

/// `struct dentry.d_parent` — parent `*dentry`, for the BUG-034 module
/// source-path walk. `bits_offset=192` (byte 24) on 6.8 x86_64. Fails
/// SAFE: a bad offset → the walk reads null/garbage and stops, yielding
/// a short/empty path (the rule degrades to "couldn't resolve" — never
/// a false fire).
pub const DENTRY_D_PARENT_OFFSET: usize = 24;

// ── Tappa 9 (BUG-022) — dir child-leaf reconstruction ────────────────
//
// `fim_create_observe` / `fim_rename_observe` read the NEW child
// dentry's leaf name (`dentry->d_name.name`, a `struct qstr`). From BTF:
//   `[811] STRUCT 'dentry' size=192` → `'d_name' bits_offset=256` (byte 32)
//   `[806] STRUCT 'qstr'   size=16`  → `'name'   bits_offset=64`  (byte 8)
// The qstr `len` is the second word of the leading hash_len union
// (`hash`@0, `len`@4). A bad offset fails SAFE: `read_child_leaf`
// null/err-checks every probe and emits an empty leaf.

/// `struct dentry.d_name` — the embedded `struct qstr`. Byte 32.
pub const DENTRY_D_NAME_OFFSET: usize = 32;

/// `struct qstr.name` — `const unsigned char *` to the NUL-terminated
/// leaf. Byte 8 within the qstr, so `dentry.d_name.name` lives at
/// `DENTRY_D_NAME_OFFSET + QSTR_NAME_OFFSET` = byte 40.
pub const QSTR_NAME_OFFSET: usize = 8;

/// `struct qstr.len` — `u32` leaf length (second word of the `hash_len`
/// union, after the 4-byte `hash`). Byte 4 within the qstr; used only
/// to set the truncated flag when `len >= FIM_CHILD_NAME_LEN`.
pub const QSTR_LEN_OFFSET: usize = 4;

/// `struct inode.i_sb` — pointer to `super_block`. `bits_offset=448`.
pub const INODE_I_SB_OFFSET: usize = 56;

/// `struct inode.i_ino` — `unsigned long` (u64) inode number.
/// `bits_offset=640`.
pub const INODE_I_INO_OFFSET: usize = 80;

/// `struct super_block.s_dev` — `dev_t` (u32, packed major/minor).
/// `bits_offset=128`.
pub const SUPER_BLOCK_S_DEV_OFFSET: usize = 16;

/// `struct file.f_inode` — pointer to the file's inode.
/// `bits_offset=1344`.
pub const FILE_F_INODE_OFFSET: usize = 168;

/// `struct file.f_path` — the embedded `struct path` (BUG-034 module
/// source-path walk). `bits_offset=1216` (byte 152) on 6.8 x86_64. The
/// module's source dentry is
/// `*(file + FILE_F_PATH_OFFSET + PATH_DENTRY_OFFSET)`.
pub const FILE_F_PATH_OFFSET: usize = 152;

/// `struct path.dentry` — 2nd member of `struct path { vfsmount *mnt;
/// dentry *dentry; }`. `bits_offset=64` (byte 8).
pub const PATH_DENTRY_OFFSET: usize = 8;

/// `struct file.f_flags` — `unsigned int` open-flag bitmap
/// (`O_RDONLY` / `O_WRONLY` / `O_RDWR` / `O_TRUNC` / etc.).
/// `bits_offset=576` on 6.8.x (byte 72). The Tappa 9 C5.2
/// `fim_file_open_observe` reads this offset.
pub const FILE_F_FLAGS_OFFSET: usize = 72;

/// `struct file.f_mode` — `fmode_t` (`unsigned int`) holding `FMODE_*`
/// (read/write capability resolved at open time). `bits_offset=160`
/// (byte 20) on 6.8.0-124 x86_64 — verified against
/// `/sys/kernel/btf/vmlinux` (`'f_mode' ... bits_offset=160`). The
/// at-authz-1 `protected_open_deny` hook reads `f_mode & FMODE_WRITE`
/// to deny only write-intent opens (reads, incl. the agent's own
/// O_RDONLY admin.pub load, pass through).
pub const FILE_F_MODE_OFFSET: usize = 20;

// ── Tappa 10 (N2) — network observability offsets ────────────────────
//
// All offsets validated 2026-05-20 against `/sys/kernel/btf/vmlinux`
// on `6.8.0-117-generic`. `__sk_common` is at offset 0 of `struct
// sock` (sock_common is the first member), so byte offsets within
// sock_common ARE byte offsets within sock. `sock_common` size is 136
// bytes; full sock size is 760. REVALIDATE resolves the skc_* fields
// against `sock_common` directly (descending its anonymous unions).

/// `struct sock.__sk_common.skc_daddr` — destination IPv4 address
/// (network byte order). `bits_offset=0` in sock_common = byte 0.
pub const SOCK_SKC_DADDR_OFFSET: usize = 0;

/// `struct sock.__sk_common.skc_rcv_saddr` — source IPv4 address
/// (network byte order). `bits_offset=32` in sock_common = byte 4.
pub const SOCK_SKC_RCV_SADDR_OFFSET: usize = 4;

/// `struct sock.__sk_common.skc_dport` — destination port (network
/// byte order). `bits_offset=96` in sock_common = byte 12.
pub const SOCK_SKC_DPORT_OFFSET: usize = 12;

/// `struct sock.__sk_common.skc_num` — bound / source port (HOST byte
/// order — kernel converts at bind time). `bits_offset=112` in
/// sock_common = byte 14.
pub const SOCK_SKC_NUM_OFFSET: usize = 14;

/// `struct sock.__sk_common.skc_family` — address family
/// (`AF_INET=2` / `AF_INET6=10`). `bits_offset=128` in sock_common
/// = byte 16.
pub const SOCK_SKC_FAMILY_OFFSET: usize = 16;

/// `struct sock.__sk_common.skc_v6_daddr` — destination IPv6 address
/// (16 bytes, network byte order). `bits_offset=448` in sock_common
/// = byte 56.
pub const SOCK_SKC_V6_DADDR_OFFSET: usize = 56;

/// `struct sock.__sk_common.skc_v6_rcv_saddr` — source IPv6 address.
/// `bits_offset=576` in sock_common = byte 72.
pub const SOCK_SKC_V6_RCV_SADDR_OFFSET: usize = 72;

/// `struct sock.sk_protocol` — `u16` IP protocol number
/// (`IPPROTO_TCP=6` / `IPPROTO_UDP=17`). `bits_offset=4128` in
/// `struct sock` = byte 516.
pub const SOCK_SK_PROTOCOL_OFFSET: usize = 516;

/// `struct sock.sk_err` — `int` errno set by the network stack on
/// errors (`ECONNRESET` after RST, `ETIMEDOUT` after keepalive
/// timeout, `0` on graceful close). `bits_offset=4352` in sock = byte
/// 544. The Tappa 10 N2 `tcp_close` fexit squeezes the low 8 bits into
/// `NetFlowCloseRaw.close_reason`.
pub const SOCK_SK_ERR_OFFSET: usize = 544;

/// `struct tcp_sock.bytes_sent` — total bytes sent over this socket
/// (`u64`). `bits_offset=12352` in `struct tcp_sock` = byte 1544.
pub const TCP_SOCK_BYTES_SENT_OFFSET: usize = 1544;

/// `struct tcp_sock.bytes_received` — total bytes received (`u64`).
/// `bits_offset=13824` in tcp_sock = byte 1728.
pub const TCP_SOCK_BYTES_RECEIVED_OFFSET: usize = 1728;

// ── Tappa 4.1 — DNS observability refit (msghdr / iov_iter walk) ──────
//
// All offsets validated 2026-05-21 against `/sys/kernel/btf/vmlinux`
// on `6.8.0-117-generic`. The 6.x `iov_iter` is a TAGGED UNION. From
// BTF `[883] STRUCT 'iov_iter' size=40`:
//   'iter_type'   bits_offset=0    (byte 0, u8 enum)
//   'iov_offset'  bits_offset=64   (byte 8, size_t)
//   (anon UNION)  bits_offset=128  (byte 16) → ITER_UBUF: inline
//        `__ubuf_iovec` (`[871] STRUCT 'iovec'`); else `__iov` ptr/count
//   'nr_segs'     bits_offset=256  (byte 32)
// This refit handles the ITER_UBUF single-buffer path. REVALIDATE
// derives UBUF_BASE as the offset of the named `__ubuf_iovec` member
// (== the anon union base, since iovec.iov_base is at +0), and
// UBUF_LEN as `__ubuf_iovec` + `iovec.iov_len`.

/// `struct iov_iter.iter_type` — the union discriminant. Byte 0.
pub const IOV_ITER_ITER_TYPE_OFFSET: usize = 0;

/// `iov_iter` byte 16 — for `ITER_UBUF` this is the inline
/// `__ubuf_iovec.iov_base` (`iovec.iov_base` at +0), a **user** pointer
/// to the send buffer. The anon data union sits at `iov_iter`
/// bits_offset=128 = byte 16.
pub const IOV_ITER_UBUF_BASE_OFFSET: usize = 16;

/// `iov_iter` byte 24 — for `ITER_UBUF` the inline `__ubuf_iovec.iov_len`
/// (union-base 16 + `iovec.iov_len` 8 = byte 24); coincides with the
/// `count` field of the `ITER_IOVEC` variant. `size_t`.
pub const IOV_ITER_UBUF_LEN_OFFSET: usize = 24;

/// `struct iov_iter.nr_segs` — segment count. `[882] UNION` at
/// `iov_iter` bits_offset=256 = byte 32. Unused on the ITER_UBUF path
/// but documented for the ITER_IOVEC follow-up.
pub const IOV_ITER_NR_SEGS_OFFSET: usize = 32;

/// `struct iovec.iov_base` — `void *` to the data. `[871] STRUCT
/// 'iovec' size=16` → `'iov_base' bits_offset=0`. Byte 0.
pub const IOVEC_IOV_BASE_OFFSET: usize = 0;

/// `struct iovec.iov_len` — `size_t` byte count. `'iov_len'
/// bits_offset=64` = byte 8.
pub const IOVEC_IOV_LEN_OFFSET: usize = 8;

/// `struct msghdr.msg_iter` — the embedded (inline) `struct iov_iter`.
/// `[8038] STRUCT 'msghdr' size=104` → `'msg_iter' bits_offset=128` =
/// byte 16.
pub const MSGHDR_MSG_ITER_OFFSET: usize = 16;

/// `struct msghdr.msg_name` — `void *` to the destination socket address
/// (`sockaddr_in` / `sockaddr_in6`); the DNS refit reads it off the
/// `udp_sendmsg` path to recover the queried server's IP. `[8038] STRUCT
/// 'msghdr'` → `'msg_name' bits_offset=0` = byte 0. Folded in from a
/// `dns_query.rs`-local const so drift on it fail-closes via [`REVALIDATE`]
/// like the rest, instead of silently mis-reading (BUG-036 gap close).
pub const MSGHDR_NAME_OFFSET: usize = 0;

/// `struct msghdr.msg_namelen` — `int` byte length of `msg_name`, read to
/// tell an `AF_INET` sockaddr from an `AF_INET6` one. `'msg_namelen'
/// bits_offset=64` = byte 8. Folded in from a `dns_query.rs`-local const
/// (BUG-036 gap close — was outside the revalidation contract).
pub const MSGHDR_NAMELEN_OFFSET: usize = 8;

// ─────────────────────────────────────────────────────────────────────
//  Revalidation table — the contract the boot-time validator checks.
// ─────────────────────────────────────────────────────────────────────

/// One revalidation rule: a compiled-in offset const, plus the BTF
/// path the agent re-derives it from on the running kernel.
///
/// `field_path` is walked component-by-component from `struct_name`.
/// Each component is matched against the current struct's members,
/// descending transparently through *anonymous* union/struct members
/// (this is how the `skc_*` fields inside `sock_common`'s anon unions
/// and `qstr.len` inside its `hash_len` union resolve). A multi-element
/// path descends into the resolved member type for the next component
/// (embedded structs only — never through pointers), e.g.
/// `["__ubuf_iovec", "iov_len"]`.
#[derive(Debug, Clone, Copy)]
pub struct OffsetSpec {
    /// The const's identifier — printed verbatim in the drift report.
    pub name: &'static str,
    /// BTF struct (or union) to start resolution from.
    pub struct_name: &'static str,
    /// Field path within `struct_name` (see type docs).
    pub field_path: &'static [&'static str],
    /// The compiled-in byte offset this MUST equal on the running
    /// kernel. References the const above so there is exactly one copy
    /// of every value.
    pub expected: usize,
}

/// Every offset the boot-time revalidator checks against running-kernel
/// BTF. `PF_KTHREAD` is intentionally absent (a flag bitmask, not a
/// layout offset). 41 entries — kept in lockstep with the consts above
/// by `revalidate_table_is_complete` (test).
pub const REVALIDATE: &[OffsetSpec] = &[
    OffsetSpec { name: "TASK_STRUCT_TGID_OFFSET",        struct_name: "task_struct", field_path: &["tgid"],         expected: TASK_STRUCT_TGID_OFFSET },
    OffsetSpec { name: "TASK_STRUCT_FLAGS_OFFSET",       struct_name: "task_struct", field_path: &["flags"],        expected: TASK_STRUCT_FLAGS_OFFSET },
    OffsetSpec { name: "TASK_STRUCT_MM_OFFSET",          struct_name: "task_struct", field_path: &["mm"],           expected: TASK_STRUCT_MM_OFFSET },
    OffsetSpec { name: "TASK_STRUCT_REAL_PARENT_OFFSET", struct_name: "task_struct", field_path: &["real_parent"],  expected: TASK_STRUCT_REAL_PARENT_OFFSET },
    OffsetSpec { name: "TASK_STRUCT_START_TIME_OFFSET",  struct_name: "task_struct", field_path: &["start_time"],   expected: TASK_STRUCT_START_TIME_OFFSET },
    OffsetSpec { name: "TASK_STRUCT_COMM_OFFSET",        struct_name: "task_struct", field_path: &["comm"],         expected: TASK_STRUCT_COMM_OFFSET },
    OffsetSpec { name: "MM_STRUCT_ARG_START_OFFSET",     struct_name: "mm_struct",   field_path: &["arg_start"],     expected: MM_STRUCT_ARG_START_OFFSET },
    OffsetSpec { name: "MM_STRUCT_ARG_END_OFFSET",       struct_name: "mm_struct",   field_path: &["arg_end"],       expected: MM_STRUCT_ARG_END_OFFSET },
    OffsetSpec { name: "DENTRY_D_INODE_OFFSET",          struct_name: "dentry",      field_path: &["d_inode"],       expected: DENTRY_D_INODE_OFFSET },
    OffsetSpec { name: "DENTRY_D_PARENT_OFFSET",         struct_name: "dentry",      field_path: &["d_parent"],      expected: DENTRY_D_PARENT_OFFSET },
    OffsetSpec { name: "DENTRY_D_NAME_OFFSET",           struct_name: "dentry",      field_path: &["d_name"],        expected: DENTRY_D_NAME_OFFSET },
    OffsetSpec { name: "QSTR_NAME_OFFSET",               struct_name: "qstr",        field_path: &["name"],          expected: QSTR_NAME_OFFSET },
    OffsetSpec { name: "QSTR_LEN_OFFSET",                struct_name: "qstr",        field_path: &["len"],           expected: QSTR_LEN_OFFSET },
    OffsetSpec { name: "INODE_I_SB_OFFSET",              struct_name: "inode",       field_path: &["i_sb"],          expected: INODE_I_SB_OFFSET },
    OffsetSpec { name: "INODE_I_INO_OFFSET",             struct_name: "inode",       field_path: &["i_ino"],         expected: INODE_I_INO_OFFSET },
    OffsetSpec { name: "SUPER_BLOCK_S_DEV_OFFSET",       struct_name: "super_block", field_path: &["s_dev"],         expected: SUPER_BLOCK_S_DEV_OFFSET },
    OffsetSpec { name: "FILE_F_INODE_OFFSET",            struct_name: "file",        field_path: &["f_inode"],       expected: FILE_F_INODE_OFFSET },
    OffsetSpec { name: "FILE_F_PATH_OFFSET",             struct_name: "file",        field_path: &["f_path"],        expected: FILE_F_PATH_OFFSET },
    OffsetSpec { name: "PATH_DENTRY_OFFSET",             struct_name: "path",        field_path: &["dentry"],        expected: PATH_DENTRY_OFFSET },
    OffsetSpec { name: "FILE_F_FLAGS_OFFSET",            struct_name: "file",        field_path: &["f_flags"],       expected: FILE_F_FLAGS_OFFSET },
    OffsetSpec { name: "FILE_F_MODE_OFFSET",             struct_name: "file",        field_path: &["f_mode"],        expected: FILE_F_MODE_OFFSET },
    OffsetSpec { name: "SOCK_SKC_DADDR_OFFSET",          struct_name: "sock_common", field_path: &["skc_daddr"],     expected: SOCK_SKC_DADDR_OFFSET },
    OffsetSpec { name: "SOCK_SKC_RCV_SADDR_OFFSET",      struct_name: "sock_common", field_path: &["skc_rcv_saddr"], expected: SOCK_SKC_RCV_SADDR_OFFSET },
    OffsetSpec { name: "SOCK_SKC_DPORT_OFFSET",          struct_name: "sock_common", field_path: &["skc_dport"],     expected: SOCK_SKC_DPORT_OFFSET },
    OffsetSpec { name: "SOCK_SKC_NUM_OFFSET",            struct_name: "sock_common", field_path: &["skc_num"],       expected: SOCK_SKC_NUM_OFFSET },
    OffsetSpec { name: "SOCK_SKC_FAMILY_OFFSET",         struct_name: "sock_common", field_path: &["skc_family"],    expected: SOCK_SKC_FAMILY_OFFSET },
    OffsetSpec { name: "SOCK_SKC_V6_DADDR_OFFSET",       struct_name: "sock_common", field_path: &["skc_v6_daddr"],  expected: SOCK_SKC_V6_DADDR_OFFSET },
    OffsetSpec { name: "SOCK_SKC_V6_RCV_SADDR_OFFSET",   struct_name: "sock_common", field_path: &["skc_v6_rcv_saddr"], expected: SOCK_SKC_V6_RCV_SADDR_OFFSET },
    OffsetSpec { name: "SOCK_SK_PROTOCOL_OFFSET",        struct_name: "sock",        field_path: &["sk_protocol"],   expected: SOCK_SK_PROTOCOL_OFFSET },
    OffsetSpec { name: "SOCK_SK_ERR_OFFSET",             struct_name: "sock",        field_path: &["sk_err"],        expected: SOCK_SK_ERR_OFFSET },
    OffsetSpec { name: "TCP_SOCK_BYTES_SENT_OFFSET",     struct_name: "tcp_sock",    field_path: &["bytes_sent"],    expected: TCP_SOCK_BYTES_SENT_OFFSET },
    OffsetSpec { name: "TCP_SOCK_BYTES_RECEIVED_OFFSET", struct_name: "tcp_sock",    field_path: &["bytes_received"], expected: TCP_SOCK_BYTES_RECEIVED_OFFSET },
    OffsetSpec { name: "IOV_ITER_ITER_TYPE_OFFSET",      struct_name: "iov_iter",    field_path: &["iter_type"],     expected: IOV_ITER_ITER_TYPE_OFFSET },
    OffsetSpec { name: "IOV_ITER_UBUF_BASE_OFFSET",      struct_name: "iov_iter",    field_path: &["__ubuf_iovec"],  expected: IOV_ITER_UBUF_BASE_OFFSET },
    OffsetSpec { name: "IOV_ITER_UBUF_LEN_OFFSET",       struct_name: "iov_iter",    field_path: &["__ubuf_iovec", "iov_len"], expected: IOV_ITER_UBUF_LEN_OFFSET },
    OffsetSpec { name: "IOV_ITER_NR_SEGS_OFFSET",        struct_name: "iov_iter",    field_path: &["nr_segs"],       expected: IOV_ITER_NR_SEGS_OFFSET },
    OffsetSpec { name: "IOVEC_IOV_BASE_OFFSET",          struct_name: "iovec",       field_path: &["iov_base"],      expected: IOVEC_IOV_BASE_OFFSET },
    OffsetSpec { name: "IOVEC_IOV_LEN_OFFSET",           struct_name: "iovec",       field_path: &["iov_len"],       expected: IOVEC_IOV_LEN_OFFSET },
    OffsetSpec { name: "MSGHDR_MSG_ITER_OFFSET",         struct_name: "msghdr",      field_path: &["msg_iter"],      expected: MSGHDR_MSG_ITER_OFFSET },
    OffsetSpec { name: "MSGHDR_NAME_OFFSET",             struct_name: "msghdr",      field_path: &["msg_name"],      expected: MSGHDR_NAME_OFFSET },
    OffsetSpec { name: "MSGHDR_NAMELEN_OFFSET",          struct_name: "msghdr",      field_path: &["msg_namelen"],   expected: MSGHDR_NAMELEN_OFFSET },
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Lockstep guard: if a const is added/removed without updating
    /// REVALIDATE (or vice-versa), this count trips. 41 offsets
    /// (at-authz-1 added FILE_F_MODE_OFFSET).
    #[test]
    fn revalidate_table_is_complete() {
        assert_eq!(REVALIDATE.len(), 41, "REVALIDATE must cover all 41 offsets");
    }

    /// No duplicate const names in the table (a copy-paste guard).
    #[test]
    fn revalidate_names_unique() {
        let mut names: alloc::vec::Vec<&str> = REVALIDATE.iter().map(|s| s.name).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "duplicate name in REVALIDATE");
    }
}
