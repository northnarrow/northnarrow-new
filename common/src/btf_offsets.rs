//! Hard-coded kernel struct field offsets — the single source of truth.
//!
//! aya-ebpf (0.1, 0.2) emits no CO-RE field relocations: every kernel
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

/// `struct task_struct.group_leader` — `struct task_struct *` to the
/// thread-group leader. `'group_leader' bits_offset=20416` = byte 2552
/// (6.8.0-147). Lab PR 238 (lot 122): read off the real parent for
/// `parent_start_ns`. A child forked by a thread other than the parent's
/// main one has that thread as `real_parent`, whose `start_time` is the
/// thread's own; the leader's is the process's — the start the parent's
/// own exec reported (`start_ns`), the key the lineage is matched on.
pub const TASK_STRUCT_GROUP_LEADER_OFFSET: usize = 2552;

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

/// `struct inet_sock.inet_sport` — the source port (NETWORK byte order).
/// `bits_offset=6256` = byte 782 (6.8; 804 on 6.1, resolved at boot).
/// The TCP close fexit reads it when `skc_num` is 0: an abortive close
/// (`tcp_set_state(TCP_CLOSE)` → `inet_put_port`) zeroes `inet_num`
/// before the fexit runs, and the flow was recorded with source port 0.
pub const INET_SOCK_INET_SPORT_OFFSET: usize = 782;

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
/// `iov_iter.__iov` (6.4+; `iov` on ≤ 6.3): kernel pointer to the iovec
/// array for `ITER_IOVEC` sends (what glibc's `sendmmsg` resolver path
/// produces on kernels that do not fold a single iovec into
/// `ITER_UBUF`, i.e. ≤ 6.3). Shares the union with `ubuf` on 6.4+.
pub const IOV_ITER_IOV_OFFSET: usize = 16;

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
    /// Alternative field paths tried in order when `field_path` does not
    /// exist on the running kernel (multi-kernel, level 2: a field that
    /// was renamed or re-nested between kernel versions). Each must have
    /// the same meaning for the eBPF reader.
    pub alt_paths: &'static [&'static [&'static str]],
    /// `true` = the eBPF reader can do without this field (a feature
    /// degrades, nothing reads the wrong memory): a kernel lacking it is
    /// still supported, the slot carries [`BTF_OFFSETS_ABSENT`] and the
    /// program takes its no-op path. `false` = refuse to start.
    pub optional: bool,
}

/// One enum value the eBPF programs compare against (`iov_iter.iter_type`
/// discriminants move between kernel versions: `ITER_UBUF` is 6 on 6.1
/// and 0 on 6.4+). Resolved by name from the kernel's BTF and published
/// in the `BTF_OFFSETS` map like an offset.
#[derive(Debug, Clone, Copy)]
pub struct EnumSpec {
    /// Slot-table identifier.
    pub name: &'static str,
    /// BTF enum type name (`enum iter_type` → `"iter_type"`).
    pub enum_name: &'static str,
    /// Enumerator to look up.
    pub value_name: &'static str,
    /// Compiled-in value (the fallback for an unarmed map).
    pub compiled: u32,
    /// See [`OffsetSpec::optional`].
    pub optional: bool,
}

/// Slot value meaning "this field/enumerator does not exist on the
/// running kernel" (only ever written for `optional` entries).
pub const BTF_OFFSETS_ABSENT: u32 = u32::MAX;

/// `iov_iter.iter_type == ITER_UBUF` — the single-inline-buffer shape the
/// DNS sensor decodes. 0 on the build kernel (6.4+ reordered the enum).
pub const ITER_UBUF_VALUE: u32 = 0;

/// `iov_iter.iter_type == ITER_IOVEC` — scatter/gather `sendmsg`; 1 on
/// the build kernel (0 on ≤ 6.3).
pub const ITER_IOVEC_VALUE: u32 = 1;

/// Enum values resolved at boot (slots follow the offsets in
/// [`SLOT_TABLE`]).
pub const ENUM_VALUES: &[EnumSpec] = &[
    EnumSpec {
        name: "ITER_UBUF_VALUE",
        enum_name: "iter_type",
        value_name: "ITER_UBUF",
        compiled: ITER_UBUF_VALUE,
        // < 6.0: no ITER_UBUF at all — the DNS sensor then decodes the
        // QNAME only through the ITER_IOVEC path.
        optional: true,
    },
    EnumSpec {
        name: "ITER_IOVEC_VALUE",
        enum_name: "iter_type",
        value_name: "ITER_IOVEC",
        compiled: ITER_IOVEC_VALUE,
        // < 5.14: `enum iter_type` does not exist (the type lived in
        // `iov_iter.type` with flag bits) — QNAME decoding is skipped.
        optional: true,
    },
];

/// Every offset the boot-time revalidator checks against running-kernel
/// BTF. `PF_KTHREAD` is intentionally absent (a flag bitmask, not a
/// layout offset). 100 entries — kept in lockstep with the consts above
/// by `revalidate_table_is_complete` (test).
pub const REVALIDATE: &[OffsetSpec] = &[
    OffsetSpec {
        name: "TASK_STRUCT_TGID_OFFSET",
        struct_name: "task_struct",
        field_path: &["tgid"],
        expected: TASK_STRUCT_TGID_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "TASK_STRUCT_FLAGS_OFFSET",
        struct_name: "task_struct",
        field_path: &["flags"],
        expected: TASK_STRUCT_FLAGS_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "TASK_STRUCT_MM_OFFSET",
        struct_name: "task_struct",
        field_path: &["mm"],
        expected: TASK_STRUCT_MM_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "TASK_STRUCT_REAL_PARENT_OFFSET",
        struct_name: "task_struct",
        field_path: &["real_parent"],
        expected: TASK_STRUCT_REAL_PARENT_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "TASK_STRUCT_START_TIME_OFFSET",
        struct_name: "task_struct",
        field_path: &["start_time"],
        expected: TASK_STRUCT_START_TIME_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "TASK_STRUCT_COMM_OFFSET",
        struct_name: "task_struct",
        field_path: &["comm"],
        expected: TASK_STRUCT_COMM_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "MM_STRUCT_ARG_START_OFFSET",
        struct_name: "mm_struct",
        field_path: &["arg_start"],
        expected: MM_STRUCT_ARG_START_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "MM_STRUCT_ARG_END_OFFSET",
        struct_name: "mm_struct",
        field_path: &["arg_end"],
        expected: MM_STRUCT_ARG_END_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "DENTRY_D_INODE_OFFSET",
        struct_name: "dentry",
        field_path: &["d_inode"],
        expected: DENTRY_D_INODE_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "DENTRY_D_PARENT_OFFSET",
        struct_name: "dentry",
        field_path: &["d_parent"],
        expected: DENTRY_D_PARENT_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "DENTRY_D_NAME_OFFSET",
        struct_name: "dentry",
        field_path: &["d_name"],
        expected: DENTRY_D_NAME_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "QSTR_NAME_OFFSET",
        struct_name: "qstr",
        field_path: &["name"],
        expected: QSTR_NAME_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "QSTR_LEN_OFFSET",
        struct_name: "qstr",
        field_path: &["len"],
        expected: QSTR_LEN_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "INODE_I_SB_OFFSET",
        struct_name: "inode",
        field_path: &["i_sb"],
        expected: INODE_I_SB_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "INODE_I_INO_OFFSET",
        struct_name: "inode",
        field_path: &["i_ino"],
        expected: INODE_I_INO_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "SUPER_BLOCK_S_DEV_OFFSET",
        struct_name: "super_block",
        field_path: &["s_dev"],
        expected: SUPER_BLOCK_S_DEV_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "FILE_F_INODE_OFFSET",
        struct_name: "file",
        field_path: &["f_inode"],
        expected: FILE_F_INODE_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "FILE_F_PATH_OFFSET",
        struct_name: "file",
        field_path: &["f_path"],
        expected: FILE_F_PATH_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "PATH_DENTRY_OFFSET",
        struct_name: "path",
        field_path: &["dentry"],
        expected: PATH_DENTRY_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "FILE_F_FLAGS_OFFSET",
        struct_name: "file",
        field_path: &["f_flags"],
        expected: FILE_F_FLAGS_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "FILE_F_MODE_OFFSET",
        struct_name: "file",
        field_path: &["f_mode"],
        expected: FILE_F_MODE_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "SOCK_SKC_DADDR_OFFSET",
        struct_name: "sock_common",
        field_path: &["skc_daddr"],
        expected: SOCK_SKC_DADDR_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "SOCK_SKC_RCV_SADDR_OFFSET",
        struct_name: "sock_common",
        field_path: &["skc_rcv_saddr"],
        expected: SOCK_SKC_RCV_SADDR_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "SOCK_SKC_DPORT_OFFSET",
        struct_name: "sock_common",
        field_path: &["skc_dport"],
        expected: SOCK_SKC_DPORT_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "SOCK_SKC_NUM_OFFSET",
        struct_name: "sock_common",
        field_path: &["skc_num"],
        expected: SOCK_SKC_NUM_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "SOCK_SKC_FAMILY_OFFSET",
        struct_name: "sock_common",
        field_path: &["skc_family"],
        expected: SOCK_SKC_FAMILY_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "SOCK_SKC_V6_DADDR_OFFSET",
        struct_name: "sock_common",
        field_path: &["skc_v6_daddr"],
        expected: SOCK_SKC_V6_DADDR_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "SOCK_SKC_V6_RCV_SADDR_OFFSET",
        struct_name: "sock_common",
        field_path: &["skc_v6_rcv_saddr"],
        expected: SOCK_SKC_V6_RCV_SADDR_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "SOCK_SK_PROTOCOL_OFFSET",
        struct_name: "sock",
        field_path: &["sk_protocol"],
        expected: SOCK_SK_PROTOCOL_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "SOCK_SK_ERR_OFFSET",
        struct_name: "sock",
        field_path: &["sk_err"],
        expected: SOCK_SK_ERR_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "TCP_SOCK_BYTES_SENT_OFFSET",
        struct_name: "tcp_sock",
        field_path: &["bytes_sent"],
        expected: TCP_SOCK_BYTES_SENT_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "TCP_SOCK_BYTES_RECEIVED_OFFSET",
        struct_name: "tcp_sock",
        field_path: &["bytes_received"],
        expected: TCP_SOCK_BYTES_RECEIVED_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "IOV_ITER_ITER_TYPE_OFFSET",
        struct_name: "iov_iter",
        field_path: &["iter_type"],
        expected: IOV_ITER_ITER_TYPE_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "IOV_ITER_UBUF_BASE_OFFSET",
        struct_name: "iov_iter",
        field_path: &["__ubuf_iovec"],
        expected: IOV_ITER_UBUF_BASE_OFFSET,
        // 6.1–6.3: the user pointer is `ubuf` inside the union after
        // `count`; 6.4+ overlays `__ubuf_iovec` on it.
        alt_paths: &[&["ubuf"]],
        optional: true,
    },
    OffsetSpec {
        name: "IOV_ITER_UBUF_LEN_OFFSET",
        struct_name: "iov_iter",
        field_path: &["__ubuf_iovec", "iov_len"],
        expected: IOV_ITER_UBUF_LEN_OFFSET,
        // 6.1–6.3: the inline buffer length is `count`.
        alt_paths: &[&["count"]],
        optional: true,
    },
    OffsetSpec {
        name: "IOV_ITER_NR_SEGS_OFFSET",
        struct_name: "iov_iter",
        field_path: &["nr_segs"],
        expected: IOV_ITER_NR_SEGS_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "IOVEC_IOV_BASE_OFFSET",
        struct_name: "iovec",
        field_path: &["iov_base"],
        expected: IOVEC_IOV_BASE_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "IOVEC_IOV_LEN_OFFSET",
        struct_name: "iovec",
        field_path: &["iov_len"],
        expected: IOVEC_IOV_LEN_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "MSGHDR_MSG_ITER_OFFSET",
        struct_name: "msghdr",
        field_path: &["msg_iter"],
        expected: MSGHDR_MSG_ITER_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "MSGHDR_NAME_OFFSET",
        struct_name: "msghdr",
        field_path: &["msg_name"],
        expected: MSGHDR_NAME_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "MSGHDR_NAMELEN_OFFSET",
        struct_name: "msghdr",
        field_path: &["msg_namelen"],
        expected: MSGHDR_NAMELEN_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "IOV_ITER_IOV_OFFSET",
        struct_name: "iov_iter",
        field_path: &["__iov"],
        expected: IOV_ITER_IOV_OFFSET,
        // ≤ 6.3: the pointer is plainly `iov`.
        alt_paths: &[&["iov"]],
        optional: true,
    },
    // BPF self-defence: the agent's own maps/programs recognised by id.
    OffsetSpec {
        name: "BPF_MAP_ID_OFFSET",
        struct_name: "bpf_map",
        field_path: &["id"],
        expected: BPF_MAP_ID_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "BPF_MAP_MAP_TYPE_OFFSET",
        struct_name: "bpf_map",
        field_path: &["map_type"],
        expected: BPF_MAP_MAP_TYPE_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "BPF_MAP_NAME_OFFSET",
        struct_name: "bpf_map",
        field_path: &["name"],
        expected: BPF_MAP_NAME_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "BPF_PROG_TYPE_OFFSET",
        struct_name: "bpf_prog",
        field_path: &["type"],
        expected: BPF_PROG_TYPE_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "BPF_PROG_AUX_OFFSET",
        struct_name: "bpf_prog",
        field_path: &["aux"],
        expected: BPF_PROG_AUX_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "BPF_PROG_AUX_ID_OFFSET",
        struct_name: "bpf_prog_aux",
        field_path: &["id"],
        expected: BPF_PROG_AUX_ID_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "MM_STRUCT_EXE_FILE_OFFSET",
        struct_name: "mm_struct",
        field_path: &["exe_file"],
        expected: MM_STRUCT_EXE_FILE_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "SUPER_BLOCK_S_MAGIC_OFFSET",
        struct_name: "super_block",
        field_path: &["s_magic"],
        expected: SUPER_BLOCK_S_MAGIC_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    // Review 55: btrfs types, resolved from the btrfs module's BTF when
    // vmlinux does not carry them (see `BTF_MODULE_STRUCTS`).
    OffsetSpec {
        name: "BTRFS_INODE_ROOT_OFFSET",
        struct_name: "btrfs_inode",
        field_path: &["root"],
        expected: BTRFS_INODE_ROOT_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "BTRFS_INODE_VFS_INODE_OFFSET",
        struct_name: "btrfs_inode",
        field_path: &["vfs_inode"],
        expected: BTRFS_INODE_VFS_INODE_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "BTRFS_ROOT_ANON_DEV_OFFSET",
        struct_name: "btrfs_root",
        field_path: &["anon_dev"],
        expected: BTRFS_ROOT_ANON_DEV_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "INODE_I_MODE_OFFSET",
        struct_name: "inode",
        field_path: &["i_mode"],
        expected: INODE_I_MODE_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "TASK_STRUCT_LOGINUID_OFFSET",
        struct_name: "task_struct",
        field_path: &["loginuid"],
        expected: TASK_STRUCT_LOGINUID_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "LINUX_BINPRM_FILE_OFFSET",
        struct_name: "linux_binprm",
        field_path: &["file"],
        expected: LINUX_BINPRM_FILE_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "LINUX_BINPRM_FILENAME_OFFSET",
        struct_name: "linux_binprm",
        field_path: &["filename"],
        expected: LINUX_BINPRM_FILENAME_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "LINUX_BINPRM_INTERP_OFFSET",
        struct_name: "linux_binprm",
        field_path: &["interp"],
        expected: LINUX_BINPRM_INTERP_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "INODE_I_NLINK_OFFSET",
        struct_name: "inode",
        field_path: &["i_nlink"],
        expected: INODE_I_NLINK_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "TASK_STRUCT_FS_OFFSET",
        struct_name: "task_struct",
        field_path: &["fs"],
        expected: TASK_STRUCT_FS_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "FS_STRUCT_ROOT_OFFSET",
        struct_name: "fs_struct",
        field_path: &["root"],
        expected: FS_STRUCT_ROOT_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "SK_BUFF_HEAD_OFFSET",
        struct_name: "sk_buff",
        field_path: &["head"],
        expected: SK_BUFF_HEAD_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "SK_BUFF_TAIL_OFFSET",
        struct_name: "sk_buff",
        field_path: &["tail"],
        expected: SK_BUFF_TAIL_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "SK_BUFF_TRANSPORT_HEADER_OFFSET",
        struct_name: "sk_buff",
        field_path: &["transport_header"],
        expected: SK_BUFF_TRANSPORT_HEADER_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "SK_BUFF_DATA_LEN_OFFSET",
        struct_name: "sk_buff",
        field_path: &["data_len"],
        expected: SK_BUFF_DATA_LEN_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "FLOWI4_DADDR_OFFSET",
        struct_name: "flowi4",
        field_path: &["daddr"],
        expected: FLOWI4_DADDR_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "FLOWI4_ULI_OFFSET",
        struct_name: "flowi4",
        field_path: &["uli"],
        expected: FLOWI4_ULI_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "FLOWI6_DADDR_OFFSET",
        struct_name: "flowi6",
        field_path: &["daddr"],
        expected: FLOWI6_DADDR_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "FLOWI6_ULI_OFFSET",
        struct_name: "flowi6",
        field_path: &["uli"],
        expected: FLOWI6_ULI_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    // External audit EBPF-010: the link a BPF_LINK_DETACH / UPDATE names.
    OffsetSpec {
        name: "TASK_STRUCT_FILES_OFFSET",
        struct_name: "task_struct",
        field_path: &["files"],
        expected: TASK_STRUCT_FILES_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "FILES_STRUCT_FDT_OFFSET",
        struct_name: "files_struct",
        field_path: &["fdt"],
        expected: FILES_STRUCT_FDT_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "FDTABLE_MAX_FDS_OFFSET",
        struct_name: "fdtable",
        field_path: &["max_fds"],
        expected: FDTABLE_MAX_FDS_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "FDTABLE_FD_OFFSET",
        struct_name: "fdtable",
        field_path: &["fd"],
        expected: FDTABLE_FD_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "FILE_PRIVATE_DATA_OFFSET",
        struct_name: "file",
        field_path: &["private_data"],
        expected: FILE_PRIVATE_DATA_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "BPF_LINK_ID_OFFSET",
        struct_name: "bpf_link",
        field_path: &["id"],
        expected: BPF_LINK_ID_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "INET_SOCK_INET_SPORT_OFFSET",
        struct_name: "inet_sock",
        field_path: &["inet_sport"],
        expected: INET_SOCK_INET_SPORT_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "INODE_I_SIZE_OFFSET",
        struct_name: "inode",
        field_path: &["i_size"],
        expected: INODE_I_SIZE_OFFSET,
        alt_paths: &[],
        optional: false,
    },
    OffsetSpec {
        name: "TASK_STRUCT_CRED_OFFSET",
        struct_name: "task_struct",
        field_path: &["cred"],
        expected: TASK_STRUCT_CRED_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "TASK_STRUCT_NSPROXY_OFFSET",
        struct_name: "task_struct",
        field_path: &["nsproxy"],
        expected: TASK_STRUCT_NSPROXY_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "TASK_STRUCT_TI_STATUS_OFFSET",
        struct_name: "task_struct",
        field_path: &["thread_info", "status"],
        expected: TASK_STRUCT_TI_STATUS_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "CRED_UID_OFFSET",
        struct_name: "cred",
        field_path: &["uid"],
        expected: CRED_UID_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "CRED_FSGID_OFFSET",
        struct_name: "cred",
        field_path: &["fsgid"],
        expected: CRED_FSGID_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "CRED_CAP_PERMITTED_OFFSET",
        struct_name: "cred",
        field_path: &["cap_permitted"],
        expected: CRED_CAP_PERMITTED_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "CRED_CAP_EFFECTIVE_OFFSET",
        struct_name: "cred",
        field_path: &["cap_effective"],
        expected: CRED_CAP_EFFECTIVE_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "CRED_USER_NS_OFFSET",
        struct_name: "cred",
        field_path: &["user_ns"],
        expected: CRED_USER_NS_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "NSPROXY_MNT_NS_OFFSET",
        struct_name: "nsproxy",
        field_path: &["mnt_ns"],
        expected: NSPROXY_MNT_NS_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "NSPROXY_PID_NS_FOR_CHILDREN_OFFSET",
        struct_name: "nsproxy",
        field_path: &["pid_ns_for_children"],
        expected: NSPROXY_PID_NS_FOR_CHILDREN_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "NSPROXY_NET_NS_OFFSET",
        struct_name: "nsproxy",
        field_path: &["net_ns"],
        expected: NSPROXY_NET_NS_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "MNT_NAMESPACE_INUM_OFFSET",
        struct_name: "mnt_namespace",
        field_path: &["ns", "inum"],
        expected: MNT_NAMESPACE_INUM_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "PID_NAMESPACE_INUM_OFFSET",
        struct_name: "pid_namespace",
        field_path: &["ns", "inum"],
        expected: PID_NAMESPACE_INUM_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "NET_INUM_OFFSET",
        struct_name: "net",
        field_path: &["ns", "inum"],
        expected: NET_INUM_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "USER_NAMESPACE_INUM_OFFSET",
        struct_name: "user_namespace",
        field_path: &["ns", "inum"],
        expected: USER_NAMESPACE_INUM_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "TASK_STRUCT_REAL_CRED_OFFSET",
        struct_name: "task_struct",
        field_path: &["real_cred"],
        expected: TASK_STRUCT_REAL_CRED_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "INODE_I_UID_OFFSET",
        struct_name: "inode",
        field_path: &["i_uid"],
        expected: INODE_I_UID_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    // Lab PR 223 (EXPERIMENTAL exec quarantine): the inode's change time,
    // the stamp under which a judged executable skips the stop. Renamed
    // twice: `i_ctime` (timespec64) up to 6.5, `__i_ctime` 6.6–6.10,
    // `i_ctime_sec` / `i_ctime_nsec` from 6.11.
    OffsetSpec {
        name: "INODE_I_CTIME_SEC_OFFSET",
        struct_name: "inode",
        field_path: &["__i_ctime", "tv_sec"],
        expected: INODE_I_CTIME_SEC_OFFSET,
        alt_paths: &[&["i_ctime_sec"], &["i_ctime", "tv_sec"]],
        optional: true,
    },
    OffsetSpec {
        name: "INODE_I_CTIME_NSEC_OFFSET",
        struct_name: "inode",
        field_path: &["__i_ctime", "tv_nsec"],
        expected: INODE_I_CTIME_NSEC_OFFSET,
        alt_paths: &[&["i_ctime_nsec"], &["i_ctime", "tv_nsec"]],
        optional: true,
    },
    OffsetSpec {
        name: "SOCKET_SK_OFFSET",
        struct_name: "socket",
        field_path: &["sk"],
        expected: SOCKET_SK_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    // Lab PR 226 (EXPERIMENTAL exec policy): the caller's controlling
    // terminal (`task->signal->tty`, a signal of the interactive admin
    // tier). Optional: without it no caller is an interactive admin. A
    // file's owner (the home of another user; the exec quarantine's script
    // refusal) is lab PR 219's `INODE_I_UID_OFFSET`.
    OffsetSpec {
        name: "TASK_STRUCT_SIGNAL_OFFSET",
        struct_name: "task_struct",
        field_path: &["signal"],
        expected: TASK_STRUCT_SIGNAL_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    OffsetSpec {
        name: "SIGNAL_STRUCT_TTY_OFFSET",
        struct_name: "signal_struct",
        field_path: &["tty"],
        expected: SIGNAL_STRUCT_TTY_OFFSET,
        alt_paths: &[],
        optional: true,
    },
    // Lab PR 238 (lot 122): the parent's thread-group leader, whose
    // `start_time` is `parent_start_ns`. Appended (slot 100) so that no
    // earlier slot moves; required, as `real_parent` and `start_time` are.
    OffsetSpec {
        name: "TASK_STRUCT_GROUP_LEADER_OFFSET",
        struct_name: "task_struct",
        field_path: &["group_leader"],
        expected: TASK_STRUCT_GROUP_LEADER_OFFSET,
        alt_paths: &[],
        optional: false,
    },
];

/// Structs defined by a kernel module rather than vmlinux, and the module
/// whose BTF (`/sys/kernel/btf/<module>`, split on vmlinux) carries them
/// when it is not built in. Only optional [`REVALIDATE`] entries may use
/// them: a host without the module has nothing of that type to read.
pub const BTF_MODULE_STRUCTS: &[(&str, &str)] =
    &[("btrfs_inode", "btrfs"), ("btrfs_root", "btrfs")];

// ───────────────────────────────────────
//  Runtime offsets — the BTF_OFFSETS map contract (multi-kernel, level 1).
// ───────────────────────────────────────

/// The agent resolves every [`REVALIDATE`] entry from the running kernel's
/// BTF at boot and writes the values into the eBPF `BTF_OFFSETS` array map
/// (one `u32` per slot, slot 0 = [`BTF_OFFSETS_MAGIC`] once populated).
/// The eBPF programs read offsets through `off!(NAME)`, which falls back
/// to the compiled-in constant until the map is armed — so a kernel whose
/// layout matches the build runs identically with or without the map, and
/// a kernel whose layout differs (Debian 12 / 6.1: 20 of 41 offsets) runs
/// with the resolved values instead of being refused. A field that cannot
/// be resolved at all still refuses the boot (fail-closed, BUG-036).
///
/// Slot numbers follow the [`REVALIDATE`] order (index + 1); the
/// `slot_table_matches_revalidate` test pins the mapping. The consts keep
/// the full `*_OFFSET` name so `off!(NAME)` can map a constant to its slot.
pub mod slot {
    pub const TASK_STRUCT_TGID_OFFSET: u32 = 1;
    pub const TASK_STRUCT_FLAGS_OFFSET: u32 = 2;
    pub const TASK_STRUCT_MM_OFFSET: u32 = 3;
    pub const TASK_STRUCT_REAL_PARENT_OFFSET: u32 = 4;
    pub const TASK_STRUCT_START_TIME_OFFSET: u32 = 5;
    pub const TASK_STRUCT_COMM_OFFSET: u32 = 6;
    pub const MM_STRUCT_ARG_START_OFFSET: u32 = 7;
    pub const MM_STRUCT_ARG_END_OFFSET: u32 = 8;
    pub const DENTRY_D_INODE_OFFSET: u32 = 9;
    pub const DENTRY_D_PARENT_OFFSET: u32 = 10;
    pub const DENTRY_D_NAME_OFFSET: u32 = 11;
    pub const QSTR_NAME_OFFSET: u32 = 12;
    pub const QSTR_LEN_OFFSET: u32 = 13;
    pub const INODE_I_SB_OFFSET: u32 = 14;
    pub const INODE_I_INO_OFFSET: u32 = 15;
    pub const SUPER_BLOCK_S_DEV_OFFSET: u32 = 16;
    pub const FILE_F_INODE_OFFSET: u32 = 17;
    pub const FILE_F_PATH_OFFSET: u32 = 18;
    pub const PATH_DENTRY_OFFSET: u32 = 19;
    pub const FILE_F_FLAGS_OFFSET: u32 = 20;
    pub const FILE_F_MODE_OFFSET: u32 = 21;
    pub const SOCK_SKC_DADDR_OFFSET: u32 = 22;
    pub const SOCK_SKC_RCV_SADDR_OFFSET: u32 = 23;
    pub const SOCK_SKC_DPORT_OFFSET: u32 = 24;
    pub const SOCK_SKC_NUM_OFFSET: u32 = 25;
    pub const SOCK_SKC_FAMILY_OFFSET: u32 = 26;
    pub const SOCK_SKC_V6_DADDR_OFFSET: u32 = 27;
    pub const SOCK_SKC_V6_RCV_SADDR_OFFSET: u32 = 28;
    pub const SOCK_SK_PROTOCOL_OFFSET: u32 = 29;
    pub const SOCK_SK_ERR_OFFSET: u32 = 30;
    pub const TCP_SOCK_BYTES_SENT_OFFSET: u32 = 31;
    pub const TCP_SOCK_BYTES_RECEIVED_OFFSET: u32 = 32;
    pub const IOV_ITER_ITER_TYPE_OFFSET: u32 = 33;
    pub const IOV_ITER_UBUF_BASE_OFFSET: u32 = 34;
    pub const IOV_ITER_UBUF_LEN_OFFSET: u32 = 35;
    pub const IOV_ITER_NR_SEGS_OFFSET: u32 = 36;
    pub const IOVEC_IOV_BASE_OFFSET: u32 = 37;
    pub const IOVEC_IOV_LEN_OFFSET: u32 = 38;
    pub const MSGHDR_MSG_ITER_OFFSET: u32 = 39;
    pub const MSGHDR_NAME_OFFSET: u32 = 40;
    pub const MSGHDR_NAMELEN_OFFSET: u32 = 41;
    pub const IOV_ITER_IOV_OFFSET: u32 = 42;
    pub const BPF_MAP_ID_OFFSET: u32 = 43;
    pub const BPF_MAP_MAP_TYPE_OFFSET: u32 = 44;
    pub const BPF_MAP_NAME_OFFSET: u32 = 45;
    pub const BPF_PROG_TYPE_OFFSET: u32 = 46;
    pub const BPF_PROG_AUX_OFFSET: u32 = 47;
    pub const BPF_PROG_AUX_ID_OFFSET: u32 = 48;
    pub const MM_STRUCT_EXE_FILE_OFFSET: u32 = 49;
    pub const SUPER_BLOCK_S_MAGIC_OFFSET: u32 = 50;
    pub const BTRFS_INODE_ROOT_OFFSET: u32 = 51;
    pub const BTRFS_INODE_VFS_INODE_OFFSET: u32 = 52;
    pub const BTRFS_ROOT_ANON_DEV_OFFSET: u32 = 53;
    pub const INODE_I_MODE_OFFSET: u32 = 54;
    pub const TASK_STRUCT_LOGINUID_OFFSET: u32 = 55;
    pub const LINUX_BINPRM_FILE_OFFSET: u32 = 56;
    pub const LINUX_BINPRM_FILENAME_OFFSET: u32 = 57;
    pub const LINUX_BINPRM_INTERP_OFFSET: u32 = 58;
    pub const INODE_I_NLINK_OFFSET: u32 = 59;
    pub const TASK_STRUCT_FS_OFFSET: u32 = 60;
    pub const FS_STRUCT_ROOT_OFFSET: u32 = 61;
    pub const SK_BUFF_HEAD_OFFSET: u32 = 62;
    pub const SK_BUFF_TAIL_OFFSET: u32 = 63;
    pub const SK_BUFF_TRANSPORT_HEADER_OFFSET: u32 = 64;
    pub const SK_BUFF_DATA_LEN_OFFSET: u32 = 65;
    pub const FLOWI4_DADDR_OFFSET: u32 = 66;
    pub const FLOWI4_ULI_OFFSET: u32 = 67;
    pub const FLOWI6_DADDR_OFFSET: u32 = 68;
    pub const FLOWI6_ULI_OFFSET: u32 = 69;
    pub const TASK_STRUCT_FILES_OFFSET: u32 = 70;
    pub const FILES_STRUCT_FDT_OFFSET: u32 = 71;
    pub const FDTABLE_MAX_FDS_OFFSET: u32 = 72;
    pub const FDTABLE_FD_OFFSET: u32 = 73;
    pub const FILE_PRIVATE_DATA_OFFSET: u32 = 74;
    pub const BPF_LINK_ID_OFFSET: u32 = 75;
    pub const INET_SOCK_INET_SPORT_OFFSET: u32 = 76;
    pub const INODE_I_SIZE_OFFSET: u32 = 77;
    pub const TASK_STRUCT_CRED_OFFSET: u32 = 78;
    pub const TASK_STRUCT_NSPROXY_OFFSET: u32 = 79;
    pub const TASK_STRUCT_TI_STATUS_OFFSET: u32 = 80;
    pub const CRED_UID_OFFSET: u32 = 81;
    pub const CRED_FSGID_OFFSET: u32 = 82;
    pub const CRED_CAP_PERMITTED_OFFSET: u32 = 83;
    pub const CRED_CAP_EFFECTIVE_OFFSET: u32 = 84;
    pub const CRED_USER_NS_OFFSET: u32 = 85;
    pub const NSPROXY_MNT_NS_OFFSET: u32 = 86;
    pub const NSPROXY_PID_NS_FOR_CHILDREN_OFFSET: u32 = 87;
    pub const NSPROXY_NET_NS_OFFSET: u32 = 88;
    pub const MNT_NAMESPACE_INUM_OFFSET: u32 = 89;
    pub const PID_NAMESPACE_INUM_OFFSET: u32 = 90;
    pub const NET_INUM_OFFSET: u32 = 91;
    pub const USER_NAMESPACE_INUM_OFFSET: u32 = 92;
    pub const TASK_STRUCT_REAL_CRED_OFFSET: u32 = 93;
    pub const INODE_I_UID_OFFSET: u32 = 94;
    pub const INODE_I_CTIME_SEC_OFFSET: u32 = 95;
    pub const INODE_I_CTIME_NSEC_OFFSET: u32 = 96;
    pub const SOCKET_SK_OFFSET: u32 = 97;
    pub const TASK_STRUCT_SIGNAL_OFFSET: u32 = 98;
    pub const SIGNAL_STRUCT_TTY_OFFSET: u32 = 99;
    pub const TASK_STRUCT_GROUP_LEADER_OFFSET: u32 = 100;
    // enum slots 101–102 (`ITER_UBUF_VALUE_SLOT`, `ITER_IOVEC_VALUE_SLOT`)
    pub const TP_SCHED_EXEC_FILENAME_OFFSET: u32 = 103;
    pub const TP_SYS_ENTER_EXECVE_FILENAME_OFFSET: u32 = 104;
    pub const TP_SYS_ENTER_OPENAT_FILENAME_OFFSET: u32 = 105;
    pub const TP_SYS_ENTER_OPENAT_FLAGS_OFFSET: u32 = 106;
    pub const TP_IOURING_SUBMIT_OPCODE_OFFSET: u32 = 107;
    pub const TP_IOURING_SUBMIT_SQ_THREAD_OFFSET: u32 = 108;
    pub const TP_IOURING_CREATE_FD_OFFSET: u32 = 109;
    pub const TP_IOURING_CREATE_SQ_ENTRIES_OFFSET: u32 = 110;
    pub const TP_IOURING_CREATE_FLAGS_OFFSET: u32 = 111;
    pub const TP_SYS_ENTER_EXECVE_ENVP_OFFSET: u32 = 112;
    pub const TP_SYS_ENTER_EXECVEAT_ENVP_OFFSET: u32 = 113;
}

/// `(const name, slot)` in [`REVALIDATE`] order — the agent writes resolved
/// values into the map by slot.
pub const SLOT_TABLE: &[(&str, u32)] = &[
    ("TASK_STRUCT_TGID_OFFSET", 1),
    ("TASK_STRUCT_FLAGS_OFFSET", 2),
    ("TASK_STRUCT_MM_OFFSET", 3),
    ("TASK_STRUCT_REAL_PARENT_OFFSET", 4),
    ("TASK_STRUCT_START_TIME_OFFSET", 5),
    ("TASK_STRUCT_COMM_OFFSET", 6),
    ("MM_STRUCT_ARG_START_OFFSET", 7),
    ("MM_STRUCT_ARG_END_OFFSET", 8),
    ("DENTRY_D_INODE_OFFSET", 9),
    ("DENTRY_D_PARENT_OFFSET", 10),
    ("DENTRY_D_NAME_OFFSET", 11),
    ("QSTR_NAME_OFFSET", 12),
    ("QSTR_LEN_OFFSET", 13),
    ("INODE_I_SB_OFFSET", 14),
    ("INODE_I_INO_OFFSET", 15),
    ("SUPER_BLOCK_S_DEV_OFFSET", 16),
    ("FILE_F_INODE_OFFSET", 17),
    ("FILE_F_PATH_OFFSET", 18),
    ("PATH_DENTRY_OFFSET", 19),
    ("FILE_F_FLAGS_OFFSET", 20),
    ("FILE_F_MODE_OFFSET", 21),
    ("SOCK_SKC_DADDR_OFFSET", 22),
    ("SOCK_SKC_RCV_SADDR_OFFSET", 23),
    ("SOCK_SKC_DPORT_OFFSET", 24),
    ("SOCK_SKC_NUM_OFFSET", 25),
    ("SOCK_SKC_FAMILY_OFFSET", 26),
    ("SOCK_SKC_V6_DADDR_OFFSET", 27),
    ("SOCK_SKC_V6_RCV_SADDR_OFFSET", 28),
    ("SOCK_SK_PROTOCOL_OFFSET", 29),
    ("SOCK_SK_ERR_OFFSET", 30),
    ("TCP_SOCK_BYTES_SENT_OFFSET", 31),
    ("TCP_SOCK_BYTES_RECEIVED_OFFSET", 32),
    ("IOV_ITER_ITER_TYPE_OFFSET", 33),
    ("IOV_ITER_UBUF_BASE_OFFSET", 34),
    ("IOV_ITER_UBUF_LEN_OFFSET", 35),
    ("IOV_ITER_NR_SEGS_OFFSET", 36),
    ("IOVEC_IOV_BASE_OFFSET", 37),
    ("IOVEC_IOV_LEN_OFFSET", 38),
    ("MSGHDR_MSG_ITER_OFFSET", 39),
    ("MSGHDR_NAME_OFFSET", 40),
    ("MSGHDR_NAMELEN_OFFSET", 41),
    ("IOV_ITER_IOV_OFFSET", 42),
    ("BPF_MAP_ID_OFFSET", 43),
    ("BPF_MAP_MAP_TYPE_OFFSET", 44),
    ("BPF_MAP_NAME_OFFSET", 45),
    ("BPF_PROG_TYPE_OFFSET", 46),
    ("BPF_PROG_AUX_OFFSET", 47),
    ("BPF_PROG_AUX_ID_OFFSET", 48),
    ("MM_STRUCT_EXE_FILE_OFFSET", 49),
    ("SUPER_BLOCK_S_MAGIC_OFFSET", 50),
    ("BTRFS_INODE_ROOT_OFFSET", 51),
    ("BTRFS_INODE_VFS_INODE_OFFSET", 52),
    ("BTRFS_ROOT_ANON_DEV_OFFSET", 53),
    ("INODE_I_MODE_OFFSET", 54),
    ("TASK_STRUCT_LOGINUID_OFFSET", 55),
    ("LINUX_BINPRM_FILE_OFFSET", 56),
    ("LINUX_BINPRM_FILENAME_OFFSET", 57),
    ("LINUX_BINPRM_INTERP_OFFSET", 58),
    ("INODE_I_NLINK_OFFSET", 59),
    ("TASK_STRUCT_FS_OFFSET", 60),
    ("FS_STRUCT_ROOT_OFFSET", 61),
    ("SK_BUFF_HEAD_OFFSET", 62),
    ("SK_BUFF_TAIL_OFFSET", 63),
    ("SK_BUFF_TRANSPORT_HEADER_OFFSET", 64),
    ("SK_BUFF_DATA_LEN_OFFSET", 65),
    ("FLOWI4_DADDR_OFFSET", 66),
    ("FLOWI4_ULI_OFFSET", 67),
    ("FLOWI6_DADDR_OFFSET", 68),
    ("FLOWI6_ULI_OFFSET", 69),
    ("TASK_STRUCT_FILES_OFFSET", 70),
    ("FILES_STRUCT_FDT_OFFSET", 71),
    ("FDTABLE_MAX_FDS_OFFSET", 72),
    ("FDTABLE_FD_OFFSET", 73),
    ("FILE_PRIVATE_DATA_OFFSET", 74),
    ("BPF_LINK_ID_OFFSET", 75),
    ("INET_SOCK_INET_SPORT_OFFSET", 76),
    ("INODE_I_SIZE_OFFSET", 77),
    ("TASK_STRUCT_CRED_OFFSET", 78),
    ("TASK_STRUCT_NSPROXY_OFFSET", 79),
    ("TASK_STRUCT_TI_STATUS_OFFSET", 80),
    ("CRED_UID_OFFSET", 81),
    ("CRED_FSGID_OFFSET", 82),
    ("CRED_CAP_PERMITTED_OFFSET", 83),
    ("CRED_CAP_EFFECTIVE_OFFSET", 84),
    ("CRED_USER_NS_OFFSET", 85),
    ("NSPROXY_MNT_NS_OFFSET", 86),
    ("NSPROXY_PID_NS_FOR_CHILDREN_OFFSET", 87),
    ("NSPROXY_NET_NS_OFFSET", 88),
    ("MNT_NAMESPACE_INUM_OFFSET", 89),
    ("PID_NAMESPACE_INUM_OFFSET", 90),
    ("NET_INUM_OFFSET", 91),
    ("USER_NAMESPACE_INUM_OFFSET", 92),
    ("TASK_STRUCT_REAL_CRED_OFFSET", 93),
    ("INODE_I_UID_OFFSET", 94),
    ("INODE_I_CTIME_SEC_OFFSET", 95),
    ("INODE_I_CTIME_NSEC_OFFSET", 96),
    ("SOCKET_SK_OFFSET", 97),
    ("TASK_STRUCT_SIGNAL_OFFSET", 98),
    ("SIGNAL_STRUCT_TTY_OFFSET", 99),
    ("TASK_STRUCT_GROUP_LEADER_OFFSET", 100),
];

/// BPF self-defence (Tappa 10.8): `struct bpf_map`, `struct bpf_prog` and
/// `struct bpf_prog_aux` fields read by the `bpf_map` / `bpf` LSM hooks to
/// recognise the agent's own objects. Compiled values from the build kernel
/// (Ubuntu 24.04 / 6.8); the resolver places them per kernel (5.15 differs
/// only in `bpf_map.name`: 88).
pub const BPF_MAP_ID_OFFSET: usize = 52;
pub const BPF_MAP_MAP_TYPE_OFFSET: usize = 24;
pub const BPF_MAP_NAME_OFFSET: usize = 96;
pub const BPF_PROG_TYPE_OFFSET: usize = 4;
pub const BPF_PROG_AUX_OFFSET: usize = 56;
pub const BPF_PROG_AUX_ID_OFFSET: usize = 32;
/// `mm_struct.exe_file` — the caller's executable, so the `bpf_map` guard
/// can exempt the agent's own binaries (the watchdog registers itself in
/// PROTECTED_PIDS before it is a member). Compiled value: 6.8 build kernel.
pub const MM_STRUCT_EXE_FILE_OFFSET: usize = 1168;

/// `super_block.s_magic`: the filesystem type, read to recognise btrfs
/// inodes (review 55). Byte 96 on 6.8, 6.1 and 5.15.
pub const SUPER_BLOCK_S_MAGIC_OFFSET: usize = 96;
/// btrfs (review 55): `stat()` on btrfs reports the device of the inode's
/// subvolume (`BTRFS_I(inode)->root->anon_dev`), not the superblock's
/// `s_dev` that every other filesystem reports, so an inode key built by
/// userland with `stat()` never matched the kernel's. The eBPF inode
/// identity (`agent-ebpf/src/inode_dev.rs`) follows these three fields for
/// btrfs inodes. They come from the btrfs module's BTF
/// (`/sys/kernel/btf/btrfs`, split on vmlinux) or from vmlinux when btrfs
/// is built in, and are optional: without btrfs there is nothing to
/// adjust. Compiled values: the 6.8 build kernel's module.
pub const BTRFS_INODE_ROOT_OFFSET: usize = 0;
/// `btrfs_inode.vfs_inode`: the VFS inode embedded in the btrfs one.
pub const BTRFS_INODE_VFS_INODE_OFFSET: usize = 448;
/// `btrfs_root.anon_dev`: the subvolume's anonymous device.
pub const BTRFS_ROOT_ANON_DEV_OFFSET: usize = 888;

/// `inode.i_mode` — the file-open sensor (Tappa 10.9 step 1) invalidates
/// its directory-class cache on directory renames only (`S_ISDIR`).
/// Byte 0 on every supported kernel.
pub const INODE_I_MODE_OFFSET: usize = 0;
/// `inode.i_size` — the file-open sensor counts as an overwrite only an
/// existing file of a few KiB, read at open, before any `O_TRUNC`.
/// `bits_offset=768` = byte 96 on 6.8 (80 on 6.1, resolved at boot).
pub const INODE_I_SIZE_OFFSET: usize = 96;
/// `inode.__i_ctime.tv_sec` / `.tv_nsec` (lab PR 223, EXPERIMENTAL exec
/// quarantine): the change time a judged executable is cached under.
/// Optional: without them the guard cannot cache a verdict and stops every
/// exec of a guarded file. Compiled values: the 6.8 build kernel
/// (`i_size` 96, `__i_atime` 104, `__i_mtime` 120, `__i_ctime` 136).
/// Only the low 4 bytes of the nanoseconds are read (`tv_nsec` is a `long`
/// up to 6.10, `i_ctime_nsec` a `u32` from 6.11).
pub const INODE_I_CTIME_SEC_OFFSET: usize = 136;
pub const INODE_I_CTIME_NSEC_OFFSET: usize = 144;
/// `task_struct.signal` and `signal_struct.tty` (lab PR 226, EXPERIMENTAL
/// exec policy): the caller's controlling terminal. Compiled values:
/// `signal` three pointers after `files` on 6.8 (`files`, `io_uring`,
/// `nsproxy`), `tty` 408 as on 6.18 (both resolved at boot).
pub const TASK_STRUCT_SIGNAL_OFFSET: usize = 3128;
pub const SIGNAL_STRUCT_TTY_OFFSET: usize = 408;

// ── Lab PR 219 — exploit post-condition guard (`agent-ebpf/src/epg.rs`) ──
//
// The guard reads a task's credential, namespaces and root around every
// system call. All optional: on a kernel missing one, the guard does not
// start (it never runs on compiled values: its programs wait for the armed
// map) and the agent attests the degradation. Compiled values follow the
// 6.8 definitions (`atomic_long_t cred.usage` from 6.8, `CONFIG_KEYS`,
// `CONFIG_SECURITY`, `CONFIG_IO_URING`); the namespace `inum`s sit after
// layouts with many options and are resolved at boot like the rest.

/// `task_struct.cred` — the subjective credential (`current_cred()`, what
/// permission checks use). 3016 on 6.8 (`comm` at 3032 follows `cred`
/// and `cached_requested_key`).
pub const TASK_STRUCT_CRED_OFFSET: usize = 3016;
/// `task_struct.nsproxy` (after `fs`, `files`, `io_uring`).
pub const TASK_STRUCT_NSPROXY_OFFSET: usize = 3120;
/// `task_struct.thread_info.status` (x86: `TS_COMPAT` during a 32-bit
/// call; `thread_info` is the first member of `task_struct`).
pub const TASK_STRUCT_TI_STATUS_OFFSET: usize = 16;
/// `cred.uid`: the first of `uid, gid, suid, sgid, euid, egid, fsuid,
/// fsgid`, read as one block of 32 bytes (the agent checks that `fsgid` is
/// at `uid + 28` before it arms the guard).
pub const CRED_UID_OFFSET: usize = 8;
/// `cred.fsgid` — only for that layout check.
pub const CRED_FSGID_OFFSET: usize = 36;
/// `cred.cap_permitted` and `cred.cap_effective`, read as one block of 16
/// bytes (checked adjacent at boot). `kernel_cap_t` is 64 bits on every
/// supported kernel (`u32 cap[2]` before 6.3, `u64 val` since).
pub const CRED_CAP_PERMITTED_OFFSET: usize = 56;
pub const CRED_CAP_EFFECTIVE_OFFSET: usize = 64;
/// `cred.user_ns`.
pub const CRED_USER_NS_OFFSET: usize = 144;
/// `nsproxy.mnt_ns`, `.pid_ns_for_children`, `.net_ns`.
pub const NSPROXY_MNT_NS_OFFSET: usize = 24;
pub const NSPROXY_PID_NS_FOR_CHILDREN_OFFSET: usize = 32;
pub const NSPROXY_NET_NS_OFFSET: usize = 40;
/// `ns.inum` (the `/proc/<pid>/ns/*` inode number) of each namespace
/// structure, for the record.
pub const MNT_NAMESPACE_INUM_OFFSET: usize = 16;
pub const PID_NAMESPACE_INUM_OFFSET: usize = 128;
pub const NET_INUM_OFFSET: usize = 136;
pub const USER_NAMESPACE_INUM_OFFSET: usize = 232;
/// `task_struct.real_cred` — the objective credential, the one the lite
/// mode compares at its use points: `override_creds` (overlayfs, io_uring
/// personalities, `access(2)`, NFS) changes only `cred`. 3008 on 6.8.
pub const TASK_STRUCT_REAL_CRED_OFFSET: usize = 3008;
/// `inode.i_uid` — the lite mode's `file_open` filter (a file owned by uid
/// 0, not world-readable). Byte 4 on every supported kernel (after
/// `i_mode` and `i_opflags`).
pub const INODE_I_UID_OFFSET: usize = 4;
/// `task_struct.loginuid` — the mass-write counter skips a writer's own
/// runtime directory (`/run/user/<loginuid>`), as the posture arm did.
/// Optional: a kernel without `CONFIG_AUDIT` has no login uid, and that
/// carve-out is then off. 6.8 build kernel: byte 3232.
pub const TASK_STRUCT_LOGINUID_OFFSET: usize = 3232;

/// Tappa 10.9 step 2 — the exec sensor on LSM `bprm_check_security`
/// (`agent-ebpf/src/exec_lsm.rs`). All optional: without one of them the
/// agent stays on the `sys_enter_execve` tracepoint. `linux_binprm.file`
/// is the file the kernel opened for this binfmt pass, `.filename` the
/// caller's string and `.interp` the interpreter's (equal to `.filename`
/// on pass 0). Compiled values: the 6.8 build kernel.
pub const LINUX_BINPRM_FILE_OFFSET: usize = 64;
pub const LINUX_BINPRM_FILENAME_OFFSET: usize = 96;
pub const LINUX_BINPRM_INTERP_OFFSET: usize = 104;
/// `inode.i_nlink` (in an anonymous union): 0 for an unlinked file or an
/// `O_TMPFILE`.
pub const INODE_I_NLINK_OFFSET: usize = 72;
/// `task_struct.fs` and `fs_struct.root`: the exec'ing task's root, where
/// the path walk stops (a container or a chroot keeps its own view).
pub const TASK_STRUCT_FS_OFFSET: usize = 3040;
pub const FS_STRUCT_ROOT_OFFSET: usize = 24;

/// Tappa 10.9 step 3 — the DNS sensor on `udp_send_skb` /
/// `udp_v6_send_skb` (`agent-ebpf/src/dns_skb.rs`). All optional: without
/// one of them the agent stays on the `udp_sendmsg` kprobe. The payload the
/// kernel copied starts 8 bytes after `head + transport_header` (both
/// offsets from `head` on 64-bit kernels); the linear data ends at
/// `head + tail`, and `data_len` is the part held in page fragments. The
/// flow argument carries the destination: `daddr` and `uli` (whose first
/// field is the destination port). Compiled values: the 6.8 build kernel.
pub const SK_BUFF_HEAD_OFFSET: usize = 200;
pub const SK_BUFF_TAIL_OFFSET: usize = 188;
pub const SK_BUFF_TRANSPORT_HEADER_OFFSET: usize = 182;
pub const SK_BUFF_DATA_LEN_OFFSET: usize = 116;
pub const FLOWI4_DADDR_OFFSET: usize = 44;
pub const FLOWI4_ULI_OFFSET: usize = 48;
pub const FLOWI6_DADDR_OFFSET: usize = 40;
pub const FLOWI6_ULI_OFFSET: usize = 76;

/// External audit EBPF-010: the `bpf` LSM hook resolves the link fd of a
/// `BPF_LINK_DETACH` / `BPF_LINK_UPDATE` to the link it names —
/// `task->files->fdt->fd[fd]->private_data` is the `struct bpf_link`, whose
/// `id` says whether it is one of the agent's. All optional: without one of
/// them that deny is off (the kernels the agent supports refuse both on the
/// agent's link types anyway: no `.detach` / `.update_prog` on tracing, raw
/// tracepoint and perf links). Compiled values: the 6.8 build kernel (5.15
/// has `task_struct.files` at 3072).
pub const TASK_STRUCT_FILES_OFFSET: usize = 3104;
pub const FILES_STRUCT_FDT_OFFSET: usize = 32;
pub const FDTABLE_MAX_FDS_OFFSET: usize = 0;
pub const FDTABLE_FD_OFFSET: usize = 8;
pub const FILE_PRIVATE_DATA_OFFSET: usize = 200;
pub const BPF_LINK_ID_OFFSET: usize = 8;

/// Lab PR 224 (CM-03, CM-02 c): `struct socket.sk`, the `struct sock *` of
/// a socket file (`file->private_data` is the `struct socket` for
/// `S_IFSOCK`). The exec sensor reads it to tell an inet socket on a new
/// image's fds 0..2 (its `skc_family`, peer and protocol through the
/// `SOCK_*` offsets above), the `socket_connect` deny to name the
/// protocol of a refused connect. Optional: without it neither is read
/// (the exec record says "stdio not read"). After `state`, `type` and
/// `flags`, and `file`: byte 24 on 5.3 and later (the 6.8 build kernel).
pub const SOCKET_SK_OFFSET: usize = 24;

/// Tracepoint field offsets — the `read_at` positions inside a
/// `TracePointContext`. They come from the tracefs `format` file, not from
/// BTF, and the common header is NOT stable across vendor kernels: RHEL 9
/// (5.14 el9) adds `common_preempt_lazy_count` at offset 8, which pushes
/// `sched_process_exec.filename` from 8 to 12 (an exec sensor reading at 8
/// then sees an empty filename — and "shell from a non-standard path"
/// killed every `sh` on AlmaLinux 9). The agent resolves these from
/// `/sys/kernel/tracing/events/<cat>/<event>/format` at boot and publishes
/// them in the same `BTF_OFFSETS` map, after the enum slots.
pub const TP_SCHED_EXEC_FILENAME_OFFSET: usize = 8;
/// `syscalls/sys_enter_execve.filename` (the first syscall argument).
pub const TP_SYS_ENTER_EXECVE_FILENAME_OFFSET: usize = 16;
/// `syscalls/sys_enter_openat.filename` (second argument).
pub const TP_SYS_ENTER_OPENAT_FILENAME_OFFSET: usize = 24;
/// `syscalls/sys_enter_openat.flags` (third argument).
pub const TP_SYS_ENTER_OPENAT_FLAGS_OFFSET: usize = 32;
/// `io_uring/io_uring_submit_req.opcode` (6.8 layout; `io_uring_submit_sqe` on ≤ 6.1).
pub const TP_IOURING_SUBMIT_OPCODE_OFFSET: usize = 32;
/// `io_uring/io_uring_submit_req.sq_thread`.
pub const TP_IOURING_SUBMIT_SQ_THREAD_OFFSET: usize = 48;
/// `io_uring/io_uring_create.fd`.
pub const TP_IOURING_CREATE_FD_OFFSET: usize = 8;
/// `io_uring/io_uring_create.sq_entries`.
pub const TP_IOURING_CREATE_SQ_ENTRIES_OFFSET: usize = 24;
/// `io_uring/io_uring_create.flags`.
pub const TP_IOURING_CREATE_FLAGS_OFFSET: usize = 32;
/// `syscalls/sys_enter_execve.envp` (third argument; lab PR 226).
pub const TP_SYS_ENTER_EXECVE_ENVP_OFFSET: usize = 32;
/// `syscalls/sys_enter_execveat.envp` (fourth argument, after `fd`,
/// `filename` and `argv`; lab PR 226).
pub const TP_SYS_ENTER_EXECVEAT_ENVP_OFFSET: usize = 40;

/// One tracepoint field whose offset is resolved from tracefs at boot.
#[derive(Debug, Clone, Copy)]
pub struct TracepointFieldSpec {
    /// Slot-table identifier (the `TP_*_OFFSET` const name).
    pub name: &'static str,
    /// tracefs category (`sched`, `syscalls`).
    pub category: &'static str,
    /// tracefs event name (`sched_process_exec`).
    pub event: &'static str,
    /// `field:` name inside the `format` file.
    pub field: &'static str,
    /// Compiled-in offset (the fallback for an unarmed map or unreadable tracefs).
    pub compiled: u32,
    /// Alternative event name tried when `event` does not exist on the
    /// running kernel (`""` = none). io_uring renamed its submit
    /// tracepoint `io_uring_submit_sqe` → `io_uring_submit_req`; RHEL 9
    /// backported the new name onto 5.14.
    pub alt_event: &'static str,
    /// External audit NN-AUD-098: the field's width in bytes, the one the
    /// eBPF program reads (`read_at::<T>`). A `format` file that gives
    /// another width is not used: the compiled offset stays.
    pub size: u32,
}

/// The tracepoint fields read with a fixed offset in `agent-ebpf`.
pub const TRACEPOINT_FIELDS: &[TracepointFieldSpec] = &[
    TracepointFieldSpec {
        name: "TP_SCHED_EXEC_FILENAME_OFFSET",
        category: "sched",
        event: "sched_process_exec",
        field: "filename",
        compiled: TP_SCHED_EXEC_FILENAME_OFFSET as u32,
        alt_event: "",
        // the `__data_loc` word
        size: 4,
    },
    TracepointFieldSpec {
        name: "TP_SYS_ENTER_EXECVE_FILENAME_OFFSET",
        category: "syscalls",
        event: "sys_enter_execve",
        field: "filename",
        compiled: TP_SYS_ENTER_EXECVE_FILENAME_OFFSET as u32,
        alt_event: "",
        // a syscall argument is 8 bytes in tracefs, whatever its C type
        size: 8,
    },
    TracepointFieldSpec {
        name: "TP_SYS_ENTER_OPENAT_FILENAME_OFFSET",
        category: "syscalls",
        event: "sys_enter_openat",
        field: "filename",
        compiled: TP_SYS_ENTER_OPENAT_FILENAME_OFFSET as u32,
        alt_event: "",
        size: 8,
    },
    TracepointFieldSpec {
        name: "TP_SYS_ENTER_OPENAT_FLAGS_OFFSET",
        category: "syscalls",
        event: "sys_enter_openat",
        field: "flags",
        compiled: TP_SYS_ENTER_OPENAT_FLAGS_OFFSET as u32,
        alt_event: "",
        size: 8,
    },
    // io_uring (Tappa 10.8, the blind channel): opcode and sq_thread of a
    // submission, fd / sq_entries / flags of a ring creation. Compiled
    // values are the 6.8 layout; 5.15 has opcode at 24, 6.1 at 32, RHEL 9
    // at 40 — the tracefs resolver places them.
    TracepointFieldSpec {
        name: "TP_IOURING_SUBMIT_OPCODE_OFFSET",
        category: "io_uring",
        event: "io_uring_submit_req",
        field: "opcode",
        compiled: TP_IOURING_SUBMIT_OPCODE_OFFSET as u32,
        alt_event: "io_uring_submit_sqe",
        size: 1,
    },
    TracepointFieldSpec {
        name: "TP_IOURING_SUBMIT_SQ_THREAD_OFFSET",
        category: "io_uring",
        event: "io_uring_submit_req",
        field: "sq_thread",
        compiled: TP_IOURING_SUBMIT_SQ_THREAD_OFFSET as u32,
        alt_event: "io_uring_submit_sqe",
        size: 1,
    },
    TracepointFieldSpec {
        name: "TP_IOURING_CREATE_FD_OFFSET",
        category: "io_uring",
        event: "io_uring_create",
        field: "fd",
        compiled: TP_IOURING_CREATE_FD_OFFSET as u32,
        alt_event: "",
        size: 4,
    },
    TracepointFieldSpec {
        name: "TP_IOURING_CREATE_SQ_ENTRIES_OFFSET",
        category: "io_uring",
        event: "io_uring_create",
        field: "sq_entries",
        compiled: TP_IOURING_CREATE_SQ_ENTRIES_OFFSET as u32,
        alt_event: "",
        size: 4,
    },
    TracepointFieldSpec {
        name: "TP_IOURING_CREATE_FLAGS_OFFSET",
        category: "io_uring",
        event: "io_uring_create",
        field: "flags",
        compiled: TP_IOURING_CREATE_FLAGS_OFFSET as u32,
        alt_event: "",
        size: 4,
    },
    // Lab PR 226 (EXPERIMENTAL exec policy): the new environment, read at
    // the syscall's entry (a bounded prefix, `agent-ebpf/src/execpol.rs`).
    TracepointFieldSpec {
        name: "TP_SYS_ENTER_EXECVE_ENVP_OFFSET",
        category: "syscalls",
        event: "sys_enter_execve",
        field: "envp",
        compiled: TP_SYS_ENTER_EXECVE_ENVP_OFFSET as u32,
        alt_event: "",
        size: 8,
    },
    TracepointFieldSpec {
        name: "TP_SYS_ENTER_EXECVEAT_ENVP_OFFSET",
        category: "syscalls",
        event: "sys_enter_execveat",
        field: "envp",
        compiled: TP_SYS_ENTER_EXECVEAT_ENVP_OFFSET as u32,
        alt_event: "",
        size: 8,
    },
];

/// Tracepoint-field slots follow the enum slots.
pub const TRACEPOINT_SLOT_TABLE: &[(&str, u32)] = &[
    ("TP_SCHED_EXEC_FILENAME_OFFSET", 103),
    ("TP_SYS_ENTER_EXECVE_FILENAME_OFFSET", 104),
    ("TP_SYS_ENTER_OPENAT_FILENAME_OFFSET", 105),
    ("TP_SYS_ENTER_OPENAT_FLAGS_OFFSET", 106),
    ("TP_IOURING_SUBMIT_OPCODE_OFFSET", 107),
    ("TP_IOURING_SUBMIT_SQ_THREAD_OFFSET", 108),
    ("TP_IOURING_CREATE_FD_OFFSET", 109),
    ("TP_IOURING_CREATE_SQ_ENTRIES_OFFSET", 110),
    ("TP_IOURING_CREATE_FLAGS_OFFSET", 111),
    ("TP_SYS_ENTER_EXECVE_ENVP_OFFSET", 112),
    ("TP_SYS_ENTER_EXECVEAT_ENVP_OFFSET", 113),
];

/// Enum-value slots follow the offset slots.
pub const ENUM_SLOT_TABLE: &[(&str, u32)] = &[("ITER_UBUF_VALUE", 101), ("ITER_IOVEC_VALUE", 102)];

/// Slot of [`ITER_UBUF_VALUE`] in the `BTF_OFFSETS` map.
pub const ITER_UBUF_VALUE_SLOT: u32 = 101;
/// Slot of [`ITER_IOVEC_VALUE`] in the `BTF_OFFSETS` map.
pub const ITER_IOVEC_VALUE_SLOT: u32 = 102;

// ───────────────────────────────────────
//  LSM hook prototypes (lab PR 164).
// ───────────────────────────────────────
//
// An LSM program reads its hook's arguments by position in its context
// (`ctx[i]`), and a kernel that inserts an argument moves every later one:
// from 6.9 `inode_setattr` takes `(struct mnt_idmap *, struct dentry *,
// struct iattr *)`, where 6.8 and older take `(struct dentry *, struct
// iattr *)`; from 5.12 `inode_setxattr` and `inode_removexattr` take a
// `struct user_namespace *` (6.3: `struct mnt_idmap *`) before the
// dentry, where 5.7 to 5.11 (5.10 LTS) start with the dentry. The agent
// reads each hook's prototype from the BTF function the kernel generates
// for it (`bpf_lsm_<hook>`).

/// An argument whose position is resolved from the running kernel and
/// published in the `BTF_OFFSETS` map, from which the program reads it.
#[derive(Debug, Clone, Copy)]
pub struct HookArgSpec {
    /// Slot-table identifier.
    pub name: &'static str,
    /// BTF function of the hook (`bpf_lsm_<hook>`).
    pub func: &'static str,
    /// The argument is a pointer to the struct of this name, and no other
    /// argument of the prototype is.
    pub pointee: &'static str,
    /// The argument right after it must point to this type (a struct, or
    /// a scalar such as `char`), which the program may read as well. A
    /// prototype of another shape is not guessed at: the slot is then
    /// [`BTF_OFFSETS_ABSENT`].
    pub followed_by: Option<&'static str>,
    /// Position on the build kernel (6.8). Informational only: the
    /// program has no compiled fallback, an unarmed or absent slot makes
    /// it read nothing (`agent-ebpf/src/btf_offsets.rs::hook_arg`).
    pub compiled: u32,
}

/// The hook arguments read through `BTF_OFFSETS`. An absent one (no such
/// hook, or a prototype of another shape) is not an error at resolution:
/// the agent does not attach the programs that read it (a deny program is
/// then a deny-hook shortfall, the FIM setattr observer a FIM coverage
/// shortfall) and attests it as a signed `subsystem_degraded`.
pub const HOOK_ARGS: &[HookArgSpec] = &[
    HookArgSpec {
        name: "INODE_SETATTR_DENTRY_ARG",
        func: "bpf_lsm_inode_setattr",
        pointee: "dentry",
        followed_by: Some("iattr"),
        compiled: 0,
    },
    // The xattr deny reads the attribute name right after the dentry.
    HookArgSpec {
        name: "INODE_SETXATTR_DENTRY_ARG",
        func: "bpf_lsm_inode_setxattr",
        pointee: "dentry",
        followed_by: Some("char"),
        compiled: 1,
    },
    HookArgSpec {
        name: "INODE_REMOVEXATTR_DENTRY_ARG",
        func: "bpf_lsm_inode_removexattr",
        pointee: "dentry",
        followed_by: Some("char"),
        compiled: 1,
    },
];

/// Hook-argument slots follow the tracepoint slots.
pub const HOOK_ARG_SLOT_TABLE: &[(&str, u32)] = &[
    ("INODE_SETATTR_DENTRY_ARG", 114),
    ("INODE_SETXATTR_DENTRY_ARG", 115),
    ("INODE_REMOVEXATTR_DENTRY_ARG", 116),
];

/// Slot of the position of `inode_setattr`'s dentry: 0 up to 6.8, 1 from
/// 6.9.
pub const INODE_SETATTR_DENTRY_ARG_SLOT: u32 = 114;
/// Slot of the position of `inode_setxattr`'s dentry: 0 on 5.7 to 5.11,
/// 1 from 5.12. The attribute name follows it.
pub const INODE_SETXATTR_DENTRY_ARG_SLOT: u32 = 115;
/// Slot of the position of `inode_removexattr`'s dentry (as
/// `inode_setxattr`).
pub const INODE_REMOVEXATTR_DENTRY_ARG_SLOT: u32 = 116;

/// Upper bound on a resolved position: every hook the agent attaches has
/// at most six arguments. The eBPF reader bounds the slot value by it.
pub const HOOK_ARG_MAX: u32 = 6;

/// An argument read at a fixed position. Its hook has kept that position
/// on every kernel checked (`lsm_hook_defs.h` of 5.15, 6.1, 6.8, 6.9 and
/// 6.12, the BTF of the 6.18 WSL2 host), so the program reads the
/// compiled position, and the agent checks at boot (and `--btf-check`
/// offline) that the running kernel's prototype, a vendor kernel's
/// included, still has a pointer to `pointee` there.
/// A mismatch refuses the start like a missing field (BUG-036): the
/// program would read another argument. A hook the kernel does not have
/// (`inode_set_acl` before 6.2, `file_ioctl_compat` before 6.8 and its
/// stable backports) is not checked: its program does not attach. Only pointer arguments are listed; a prototype that shifts
/// moves them as well.
#[derive(Debug, Clone, Copy)]
pub struct HookArgCheck {
    /// BTF function of the hook (`bpf_lsm_<hook>`).
    pub func: &'static str,
    /// Position the program reads.
    pub position: u32,
    /// The struct (or union) the argument points to.
    pub pointee: &'static str,
}

const fn check(func: &'static str, position: u32, pointee: &'static str) -> HookArgCheck {
    HookArgCheck {
        func,
        position,
        pointee,
    }
}

/// Every pointer argument the LSM programs of `agent-ebpf` read at a fixed
/// position (`inode_protect.rs`, `fim_watch.rs`, `open_sensor.rs`,
/// `bpf_defense.rs`, `ptrace_check.rs`, `task_kill.rs`, `exec_lsm.rs`,
/// `module_load.rs`, `sensor_probe.rs`).
pub const HOOK_ARG_CHECKS: &[HookArgCheck] = &[
    check("bpf_lsm_inode_unlink", 0, "inode"),
    check("bpf_lsm_inode_unlink", 1, "dentry"),
    check("bpf_lsm_inode_rmdir", 0, "inode"),
    check("bpf_lsm_inode_rmdir", 1, "dentry"),
    check("bpf_lsm_inode_rename", 0, "inode"),
    check("bpf_lsm_inode_rename", 1, "dentry"),
    check("bpf_lsm_inode_rename", 2, "inode"),
    check("bpf_lsm_inode_rename", 3, "dentry"),
    check("bpf_lsm_inode_create", 0, "inode"),
    check("bpf_lsm_inode_create", 1, "dentry"),
    check("bpf_lsm_inode_mkdir", 0, "inode"),
    check("bpf_lsm_inode_mknod", 0, "inode"),
    check("bpf_lsm_inode_symlink", 0, "inode"),
    check("bpf_lsm_inode_link", 0, "dentry"),
    check("bpf_lsm_inode_link", 1, "inode"),
    // 6.2+ (the xattr hooks are in HOOK_ARGS): `(idmap, dentry, acl_name…)`.
    check("bpf_lsm_inode_set_acl", 1, "dentry"),
    check("bpf_lsm_inode_remove_acl", 1, "dentry"),
    check("bpf_lsm_inode_post_setxattr", 0, "dentry"),
    check("bpf_lsm_file_open", 0, "file"),
    check("bpf_lsm_file_ioctl", 0, "file"),
    // 6.8+ and the stable backports (lab PR 174): `(file, cmd, arg)`.
    check("bpf_lsm_file_ioctl_compat", 0, "file"),
    check("bpf_lsm_file_permission", 0, "file"),
    check("bpf_lsm_file_free_security", 0, "file"),
    check("bpf_lsm_kernel_read_file", 0, "file"),
    check("bpf_lsm_bprm_check_security", 0, "linux_binprm"),
    check("bpf_lsm_ptrace_access_check", 0, "task_struct"),
    check("bpf_lsm_task_kill", 0, "task_struct"),
    check("bpf_lsm_bpf_map", 0, "bpf_map"),
    check("bpf_lsm_bpf", 1, "bpf_attr"),
    // Lab PR 224 (`socket_connect.rs`, attached with --net-connect-deny):
    // `(sock, address, addrlen)`, unchanged since the hook exists.
    check("bpf_lsm_socket_connect", 0, "socket"),
    check("bpf_lsm_socket_connect", 1, "sockaddr"),
    // Lab PR 226: `(file, reqprot, prot, flags)`; the program reads the
    // file and `reqprot` (5.15 to 6.18).
    check("bpf_lsm_mmap_file", 0, "file"),
];

/// Slot 0 value once the agent has written every resolved offset.
pub const BTF_OFFSETS_MAGIC: u32 = 0xB7F0_0FF5;
/// Map size: the magic slot, one slot per revalidated offset, one per enum
/// value, one per tracepoint field, one per hook argument.
pub const BTF_OFFSETS_SLOTS: u32 = 1
    + REVALIDATE.len() as u32
    + ENUM_VALUES.len() as u32
    + TRACEPOINT_FIELDS.len() as u32
    + HOOK_ARGS.len() as u32;

#[cfg(test)]
mod tests {
    use super::*;

    /// Lockstep guard: if a const is added/removed without updating
    /// REVALIDATE (or vice-versa), this count trips. 41 offsets
    /// (at-authz-1 added FILE_F_MODE_OFFSET).
    #[test]
    fn revalidate_table_is_complete() {
        assert_eq!(
            REVALIDATE.len(),
            100,
            "REVALIDATE must cover all 100 offsets"
        );
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

    #[test]
    fn slot_table_matches_revalidate() {
        assert_eq!(SLOT_TABLE.len(), REVALIDATE.len());
        for (i, (spec, (name, slot))) in REVALIDATE.iter().zip(SLOT_TABLE).enumerate() {
            assert_eq!(spec.name, *name, "slot table out of order at {i}");
            assert_eq!(*slot, i as u32 + 1);
        }
        assert_eq!(BTF_OFFSETS_SLOTS, 117);
        assert_eq!(ENUM_SLOT_TABLE[0].1, ITER_UBUF_VALUE_SLOT);
        assert_eq!(ENUM_SLOT_TABLE[0].0, ENUM_VALUES[0].name);
        assert_eq!(ENUM_SLOT_TABLE[1].1, ITER_IOVEC_VALUE_SLOT);
        assert_eq!(ENUM_SLOT_TABLE[1].0, ENUM_VALUES[1].name);
        // enum slots must not collide with offset slots
        assert!(ENUM_SLOT_TABLE
            .iter()
            .all(|(_, s)| *s > REVALIDATE.len() as u32));
        assert_eq!(slot::TASK_STRUCT_TGID_OFFSET, 1);
        // lab PR 238: appended, no earlier slot moved
        assert_eq!(slot::TASK_STRUCT_GROUP_LEADER_OFFSET, 100);
        assert_eq!(slot::TASK_STRUCT_START_TIME_OFFSET, 5);
    }

    /// Tracepoint slots follow the enum slots and match TRACEPOINT_FIELDS
    /// one to one (name and order).
    #[test]
    fn tracepoint_slot_table_matches_fields() {
        assert_eq!(TRACEPOINT_SLOT_TABLE.len(), TRACEPOINT_FIELDS.len());
        let first = REVALIDATE.len() as u32 + ENUM_VALUES.len() as u32 + 1;
        for (i, (spec, (name, slot))) in TRACEPOINT_FIELDS
            .iter()
            .zip(TRACEPOINT_SLOT_TABLE)
            .enumerate()
        {
            assert_eq!(
                spec.name, *name,
                "tracepoint slot table out of order at {i}"
            );
            assert_eq!(*slot, first + i as u32);
            assert!(*slot < BTF_OFFSETS_SLOTS);
        }
        assert_eq!(slot::TP_SCHED_EXEC_FILENAME_OFFSET, 103);
        assert_eq!(slot::TP_SYS_ENTER_OPENAT_FLAGS_OFFSET, 106);
        assert_eq!(slot::TP_SYS_ENTER_EXECVEAT_ENVP_OFFSET, 113);
        assert_eq!(TP_SCHED_EXEC_FILENAME_OFFSET, 8);
    }

    /// Lab PR 164: hook-argument slots follow the tracepoint slots, one per
    /// spec in order, inside the map.
    #[test]
    fn hook_arg_slot_table_matches_specs() {
        assert_eq!(HOOK_ARG_SLOT_TABLE.len(), HOOK_ARGS.len());
        let first =
            REVALIDATE.len() as u32 + ENUM_VALUES.len() as u32 + TRACEPOINT_FIELDS.len() as u32 + 1;
        for (i, (spec, (name, slot))) in HOOK_ARGS.iter().zip(HOOK_ARG_SLOT_TABLE).enumerate() {
            assert_eq!(
                spec.name, *name,
                "hook-argument slot table out of order at {i}"
            );
            assert_eq!(*slot, first + i as u32);
            assert!(*slot < BTF_OFFSETS_SLOTS);
            assert!(spec.compiled < HOOK_ARG_MAX);
            assert!(spec.func.starts_with("bpf_lsm_"));
        }
        assert_eq!(INODE_SETATTR_DENTRY_ARG_SLOT, 114);
        assert_eq!(INODE_SETXATTR_DENTRY_ARG_SLOT, 115);
        assert_eq!(INODE_REMOVEXATTR_DENTRY_ARG_SLOT, 116);
        assert_eq!(HOOK_ARG_SLOT_TABLE[0], ("INODE_SETATTR_DENTRY_ARG", 114));
        assert_eq!(HOOK_ARG_SLOT_TABLE[1], ("INODE_SETXATTR_DENTRY_ARG", 115));
        assert_eq!(
            HOOK_ARG_SLOT_TABLE[2],
            ("INODE_REMOVEXATTR_DENTRY_ARG", 116)
        );
        // a position and the argument after it stay below the bound
        assert!(HOOK_ARGS.iter().all(|h| h.compiled + 1 < HOOK_ARG_MAX));
    }

    /// Lab PR 164: the fixed-position checks name hook functions, stay below
    /// the position bound, are not listed twice, and never cover the hook
    /// whose position is resolved at runtime.
    #[test]
    fn hook_arg_checks_are_well_formed() {
        let mut seen: alloc::vec::Vec<(&str, u32)> = alloc::vec::Vec::new();
        for c in HOOK_ARG_CHECKS {
            assert!(c.func.starts_with("bpf_lsm_"), "{}", c.func);
            assert!(c.position < HOOK_ARG_MAX, "{} {}", c.func, c.position);
            assert!(
                !seen.contains(&(c.func, c.position)),
                "{} {} twice",
                c.func,
                c.position
            );
            seen.push((c.func, c.position));
            assert!(
                HOOK_ARGS.iter().all(|h| h.func != c.func),
                "{} is resolved at runtime, not checked at a fixed position",
                c.func
            );
        }
        assert_eq!(HOOK_ARG_CHECKS.len(), 32);
    }
}
