//! Hard-coded kernel struct field offsets.
//!
//! aya-ebpf 0.1 does not emit CO-RE field relocations from Rust
//! struct definitions, so every kernel pointer dereference in the
//! Tappa 7 LSM hooks goes through one of these byte offsets plus
//! `bpf_probe_read_kernel`. The constants here are captured from
//! `/sys/kernel/btf/vmlinux` on Ubuntu 24.04.4 / Linux
//! 6.8.0-111-generic (2026-05-12); the userland anti-tamper loader
//! revalidates each one against the running kernel's BTF before
//! attaching the hooks (the validation is being added alongside
//! Tappa 7 task 4 follow-ups).
//!
//! Drift is the failure mode to fear: a kernel upgrade can shift any
//! of these. The validation step is therefore the actual safety
//! contract — these constants are only the fast-path values.

/// `struct task_struct.tgid` — thread-group id, the value
/// `getpid(2)` returns to userland. `bits_offset=19936` from BTF.
pub(crate) const TASK_STRUCT_TGID_OFFSET: usize = 2492;

/// `struct dentry.d_inode` — the `*inode` pointer. `bits_offset=384`.
pub(crate) const DENTRY_D_INODE_OFFSET: usize = 48;

/// `struct inode.i_sb` — pointer to `super_block`. `bits_offset=448`.
pub(crate) const INODE_I_SB_OFFSET: usize = 56;

/// `struct inode.i_ino` — `unsigned long` (u64) inode number.
/// `bits_offset=640`.
pub(crate) const INODE_I_INO_OFFSET: usize = 80;

/// `struct super_block.s_dev` — `dev_t` (u32, packed major/minor).
/// `bits_offset=128`.
pub(crate) const SUPER_BLOCK_S_DEV_OFFSET: usize = 16;

/// `struct file.f_inode` — pointer to the file's inode.
/// `bits_offset=1344`.
pub(crate) const FILE_F_INODE_OFFSET: usize = 168;

/// `struct file.f_flags` — `unsigned int` open-flag bitmap
/// (`O_RDONLY` / `O_WRONLY` / `O_RDWR` / `O_TRUNC` / etc.).
/// `bits_offset=576` on Ubuntu 24.04.x / kernel 6.8.x —
/// validated 2026-05-19 against `/sys/kernel/btf/vmlinux` on
/// `6.8.0-117-generic` via `bpftool btf dump file /sys/kernel/
/// btf/vmlinux format raw` (look for `STRUCT 'file' size=232`
/// → `'f_flags' type_id=6 bits_offset=576`). The Tappa 9 C5.2
/// `fim_file_open_observe` reads this offset; the C2-deferred
/// concern (untrusted BTF-offset guess) is closed by the
/// dump-verified value.
#[allow(dead_code)]
pub(crate) const FILE_F_FLAGS_OFFSET: usize = 72;

// ── Tappa 10 (N2) — network observability offsets ────────────────────
//
// All offsets validated 2026-05-20 against `/sys/kernel/btf/vmlinux`
// on `6.8.0-117-generic` via `bpftool btf dump file /sys/kernel/btf/
// vmlinux format raw` (same procedure + same kernel as the C5.2
// FILE_F_FLAGS_OFFSET above). For each offset the comment cites the
// BTF query path so a future kernel-upgrade re-validation reproduces
// the lookup.
//
// `__sk_common` is at offset 0 of `struct sock` (sock_common is the
// first member), so byte offsets within sock_common ARE byte offsets
// within sock. `sock_common` size is 136 bytes; full sock size is 760.

/// `struct sock.__sk_common.skc_daddr` — destination IPv4 address
/// (network byte order). `bits_offset=0` in sock_common = byte 0
/// in `struct sock`. From `[8236] STRUCT 'sock_common'` →
/// `(anon) [8225] UNION` (sock_common offset 0) → `[8224] STRUCT`
/// → `'skc_daddr' type_id=1845 bits_offset=0`.
#[allow(dead_code)]
pub(crate) const SOCK_SKC_DADDR_OFFSET: usize = 0;

/// `struct sock.__sk_common.skc_rcv_saddr` — source IPv4 address
/// (network byte order). `bits_offset=32` in sock_common = byte 4.
/// Same chain as SOCK_SKC_DADDR_OFFSET, sibling field in the anon
/// struct at type_id=8224.
#[allow(dead_code)]
pub(crate) const SOCK_SKC_RCV_SADDR_OFFSET: usize = 4;

/// `struct sock.__sk_common.skc_dport` — destination port (network
/// byte order). `bits_offset=96` in sock_common = byte 12. From
/// `[8236] STRUCT 'sock_common'` → `(anon) [8229] UNION` (sock_common
/// offset 96) → `[8228] STRUCT` → `'skc_dport' bits_offset=0`.
#[allow(dead_code)]
pub(crate) const SOCK_SKC_DPORT_OFFSET: usize = 12;

/// `struct sock.__sk_common.skc_num` — bound / source port (HOST
/// byte order — kernel converts at bind time). `bits_offset=112` in
/// sock_common = byte 14. Sibling of `skc_dport` in the anon struct
/// at type_id=8228 (`'skc_num' bits_offset=16` relative to that
/// struct + 96 base = 112).
#[allow(dead_code)]
pub(crate) const SOCK_SKC_NUM_OFFSET: usize = 14;

/// `struct sock.__sk_common.skc_family` — address family
/// (`AF_INET=2` / `AF_INET6=10`). `bits_offset=128` in sock_common
/// = byte 16. Direct field of `[8236] STRUCT 'sock_common'`
/// (`'skc_family' type_id=12 bits_offset=128`).
#[allow(dead_code)]
pub(crate) const SOCK_SKC_FAMILY_OFFSET: usize = 16;

/// `struct sock.__sk_common.skc_v6_daddr` — destination IPv6 address
/// (16 bytes, network byte order). `bits_offset=448` in sock_common
/// = byte 56. `'skc_v6_daddr' type_id=1878 bits_offset=448` (type_id=1878
/// is `struct in6_addr`).
#[allow(dead_code)]
pub(crate) const SOCK_SKC_V6_DADDR_OFFSET: usize = 56;

/// `struct sock.__sk_common.skc_v6_rcv_saddr` — source IPv6 address.
/// `bits_offset=576` in sock_common = byte 72. `'skc_v6_rcv_saddr'
/// type_id=1878 bits_offset=576`.
#[allow(dead_code)]
pub(crate) const SOCK_SKC_V6_RCV_SADDR_OFFSET: usize = 72;

/// `struct sock.sk_protocol` — `u16` IP protocol number
/// (`IPPROTO_TCP=6` / `IPPROTO_UDP=17`). `bits_offset=4128` in
/// `struct sock` = byte 516. From `[8042] STRUCT 'sock' size=760`
/// → `'sk_protocol' type_id=20 bits_offset=4128` (type_id=20 is
/// `TYPEDEF 'u16'`).
#[allow(dead_code)]
pub(crate) const SOCK_SK_PROTOCOL_OFFSET: usize = 516;

/// `struct sock.sk_err` — `int` errno set by the network stack on
/// errors (`ECONNRESET` after RST, `ETIMEDOUT` after keepalive
/// timeout, `0` on graceful close). The Tappa 10 N2 `tcp_close`
/// fexit reads this and squeezes the low 8 bits into
/// `NetFlowCloseRaw.close_reason` so userland can distinguish
/// graceful / RST / timeout closes without a separate emission.
/// `bits_offset=4352` in sock = byte 544. From `[8042] STRUCT 'sock'`
/// → `'sk_err' type_id=13 bits_offset=4352` (type_id=13 is `INT 'int'`).
#[allow(dead_code)]
pub(crate) const SOCK_SK_ERR_OFFSET: usize = 544;

/// `struct tcp_sock.bytes_sent` — total bytes sent over this socket
/// (`u64`). `bits_offset=12352` in `struct tcp_sock` = byte 1544.
/// From `[21780] STRUCT 'tcp_sock' size=2304` →
/// `'bytes_sent' type_id=23 bits_offset=12352` (type_id=23 is
/// `TYPEDEF 'u64'`).
#[allow(dead_code)]
pub(crate) const TCP_SOCK_BYTES_SENT_OFFSET: usize = 1544;

/// `struct tcp_sock.bytes_received` — total bytes received
/// (`u64`). `bits_offset=13824` in tcp_sock = byte 1728. Same
/// chain as TCP_SOCK_BYTES_SENT_OFFSET, neighbouring field.
#[allow(dead_code)]
pub(crate) const TCP_SOCK_BYTES_RECEIVED_OFFSET: usize = 1728;

// ── Tappa 4.1 — DNS observability refit (msghdr / iov_iter walk) ──────
//
// All offsets validated 2026-05-21 against `/sys/kernel/btf/vmlinux`
// on `6.8.0-117-generic` via `bpftool btf dump file /sys/kernel/btf/
// vmlinux format raw` (same procedure + kernel as the N2 set above).
//
// IMPORTANT — the 6.x `iov_iter` is a TAGGED UNION, not the flat
// pre-5.14 `{iter_type, iov, nr_segs, count}` struct. From BTF
// `[883] STRUCT 'iov_iter' size=40`:
//   'iter_type'   bits_offset=0    (byte 0,  u8 enum: ITER_UBUF=0,
//                                   ITER_IOVEC=1, ITER_BVEC=2, ITER_KVEC=3)
//   'iov_offset'  bits_offset=64   (byte 8,  size_t — consumed bytes)
//   (anon UNION)  bits_offset=128  (byte 16, `[881]`, 16 bytes) →
//        ITER_UBUF: inline `__ubuf_iovec` (`[871] STRUCT 'iovec'`)
//        else:      `[880]` { ptr-union `__iov`/kvec/… @0 ; count @8 }
//   'nr_segs'     bits_offset=256  (byte 32, `[882]` union, unsigned long)
// So byte 16 is the `iov_base` user pointer (ITER_UBUF) OR the `__iov`
// iovec pointer (ITER_IOVEC); byte 24 is `iov_len` (ITER_UBUF) or the
// equivalent `count`. This refit handles the ITER_UBUF single-buffer
// path (the shape glibc's connected-UDP `send()` emits); ITER_IOVEC is
// a documented follow-up. Offsets are `iov_iter`-relative.

/// `struct iov_iter.iter_type` — the union discriminant.
/// `[883] STRUCT 'iov_iter'` → `'iter_type' type_id=19 bits_offset=0`
/// (type_id=19 is `TYPEDEF 'u8'`). Byte 0.
pub(crate) const IOV_ITER_ITER_TYPE_OFFSET: usize = 0;

/// `iov_iter` byte 16 — for `ITER_UBUF` this is the inline
/// `__ubuf_iovec.iov_base` (`[871] 'iovec' 'iov_base' bits_offset=0`),
/// a **user** pointer to the send buffer. (For `ITER_IOVEC` the same
/// slot holds `__iov`, a pointer to an iovec array — not handled
/// here.) `[881] UNION` is at `iov_iter bits_offset=128` = byte 16.
pub(crate) const IOV_ITER_UBUF_BASE_OFFSET: usize = 16;

/// `iov_iter` byte 24 — for `ITER_UBUF` the inline
/// `__ubuf_iovec.iov_len` (`'iov_len' type_id=30 bits_offset=64`
/// within `iovec`, so union-base 16 + 8 = byte 24); coincides with the
/// `count` field of the `ITER_IOVEC` variant. `size_t`.
#[allow(dead_code)]
pub(crate) const IOV_ITER_UBUF_LEN_OFFSET: usize = 24;

/// `struct iov_iter.nr_segs` — segment count. `[882] UNION` at
/// `iov_iter bits_offset=256` = byte 32, `'nr_segs' type_id=1`
/// (`long unsigned int`). Unused on the ITER_UBUF path (single
/// buffer) but documented for the ITER_IOVEC follow-up.
#[allow(dead_code)]
pub(crate) const IOV_ITER_NR_SEGS_OFFSET: usize = 32;

/// `struct iovec.iov_base` — `void *` to the data. `[871] STRUCT
/// 'iovec' size=16` → `'iov_base' type_id=65 bits_offset=0`. Byte 0.
/// (Used when dereferencing the `ITER_IOVEC` `__iov` pointer; the
/// ITER_UBUF path reaches the same field inline via
/// `IOV_ITER_UBUF_BASE_OFFSET`.)
#[allow(dead_code)]
pub(crate) const IOVEC_IOV_BASE_OFFSET: usize = 0;

/// `struct iovec.iov_len` — `size_t` byte count. `'iov_len'
/// type_id=30 bits_offset=64` = byte 8.
#[allow(dead_code)]
pub(crate) const IOVEC_IOV_LEN_OFFSET: usize = 8;

/// `struct msghdr.msg_iter` — the embedded (inline, not a pointer)
/// `struct iov_iter`. `[8038] STRUCT 'msghdr' size=104` →
/// `'msg_iter' type_id=883 bits_offset=128` = byte 16. (The sibling
/// `msg_name`@0 / `msg_namelen`@8 offsets the kprobe already uses are
/// confirmed unchanged on this kernel.)
pub(crate) const MSGHDR_MSG_ITER_OFFSET: usize = 16;
