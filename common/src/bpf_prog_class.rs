//! Lot 290: foreign BPF — the program types the agent refuses to a loader
//! outside its family and outside a trusted-installer window, the names
//! the records carry, and the records of the cross-view's iterators.
//!
//! The uapi numbers (`enum bpf_prog_type`, `enum bpf_attach_type`, `enum
//! bpf_link_type` of `include/uapi/linux/bpf.h`) are each an index of a
//! table here; the tests compare every table with the build host's uapi
//! header.
//!
//! Refused by default ([`denied_by_default`]): the types that can rewrite
//! a process's memory (`bpf_probe_write_user`), override a kernel
//! function's return (`bpf_override_return`, `fmod_ret`), signal a
//! process (`bpf_send_signal`) or take a hook's place — `kprobe`,
//! `tracing` (fentry, fexit, fmod_ret, iterators), `lsm`, `ext`
//! (freplace) and `struct_ops`; and `tracepoint`, `raw_tracepoint`,
//! `raw_tracepoint_writable` and `perf_event`, which can call
//! `bpf_probe_write_user` and `bpf_send_signal` too (no workload of the
//! benign corpus loaded any of the nine; its harness's bpftrace probe now
//! loads inside a window). The other types
//! (cgroup device, skb, sock and sysctl programs of systemd and the
//! container runtimes, tc and XDP networking, socket filters) are let
//! through and recorded.

/// `BPF_PROG_TYPE_KPROBE`.
pub const PROG_TYPE_KPROBE: u32 = 2;
/// `BPF_PROG_TYPE_TRACEPOINT`.
pub const PROG_TYPE_TRACEPOINT: u32 = 5;
/// `BPF_PROG_TYPE_PERF_EVENT`.
pub const PROG_TYPE_PERF_EVENT: u32 = 7;
/// `BPF_PROG_TYPE_RAW_TRACEPOINT`.
pub const PROG_TYPE_RAW_TRACEPOINT: u32 = 17;
/// `BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE`.
pub const PROG_TYPE_RAW_TRACEPOINT_WRITABLE: u32 = 24;
/// `BPF_PROG_TYPE_TRACING` (fentry, fexit, fmod_ret, iterators).
pub const PROG_TYPE_TRACING: u32 = 26;
/// `BPF_PROG_TYPE_STRUCT_OPS`.
pub const PROG_TYPE_STRUCT_OPS: u32 = 27;
/// `BPF_PROG_TYPE_EXT` (freplace).
pub const PROG_TYPE_EXT: u32 = 28;
/// `BPF_PROG_TYPE_LSM`.
pub const PROG_TYPE_LSM: u32 = 29;
/// `BPF_PROG_TYPE_CGROUP_SYSCTL` (lot 304).
pub const PROG_TYPE_CGROUP_SYSCTL: u32 = 23;

/// `BPF_TRACE_ITER` (`enum bpf_attach_type`): an iterator's link.
pub const ATTACH_TRACE_ITER: u32 = 28;
/// `BPF_LSM_MAC` (`enum bpf_attach_type`): an LSM program's link (lot 304).
pub const ATTACH_LSM_MAC: u32 = 27;

/// The types refused by default, in uapi order.
pub const DENIED_BY_DEFAULT: [u32; 9] = [
    PROG_TYPE_KPROBE,
    PROG_TYPE_TRACEPOINT,
    PROG_TYPE_PERF_EVENT,
    PROG_TYPE_RAW_TRACEPOINT,
    PROG_TYPE_RAW_TRACEPOINT_WRITABLE,
    PROG_TYPE_TRACING,
    PROG_TYPE_STRUCT_OPS,
    PROG_TYPE_EXT,
    PROG_TYPE_LSM,
];

/// Whether a `BPF_PROG_LOAD` of `prog_type` by a loader outside the
/// agent's family is refused outside a window (and without the signed
/// per-loader opt-out). The `bpf` hook calls this function, so the host
/// tests check the same set.
#[inline(always)]
pub const fn denied_by_default(prog_type: u32) -> bool {
    matches!(
        prog_type,
        PROG_TYPE_KPROBE
            | PROG_TYPE_TRACEPOINT
            | PROG_TYPE_PERF_EVENT
            | PROG_TYPE_RAW_TRACEPOINT
            | PROG_TYPE_RAW_TRACEPOINT_WRITABLE
            | PROG_TYPE_TRACING
            | PROG_TYPE_STRUCT_OPS
            | PROG_TYPE_EXT
            | PROG_TYPE_LSM
    )
}

/// The bit of `prog_type` in an opt-out's type mask (0 for a type past
/// bit 31, which no opt-out names).
#[inline(always)]
pub const fn type_bit(prog_type: u32) -> u32 {
    if prog_type < 32 {
        1u32 << prog_type
    } else {
        0
    }
}

/// Lot 345: `BPF_MODIFY_RETURN` (`enum bpf_attach_type`): an fmod_ret
/// `tracing` program, which overrides the return of the function it is
/// attached to — any `security_*` hook's: `security_file_open` returning
/// `-EPERM` for the agent blinds it the way an LSM program would.
pub const ATTACH_MODIFY_RETURN: u32 = 26;

/// Lot 345: the byte offset of `expected_attach_type` in a `BPF_PROG_LOAD`
/// `union bpf_attr` (uapi-stable: `prog_type`, `insn_cnt`, `insns`,
/// `license`, `log_level`, `log_size`, `log_buf`, `kern_version`,
/// `prog_flags`, `prog_name[16]`, `prog_ifindex`, then it).
pub const PROG_LOAD_ATTACH_TYPE_OFFSET: usize = 68;

/// Lot 345: whether a load the signed per-loader opt-out lets through is
/// refused all the same for its expected attach type — an fmod_ret, which
/// no tracing tool loads (bpftrace's and BCC's probes are kprobes,
/// tracepoints, perf events, raw tracepoints, fentry and fexit), whatever
/// type it claims.
#[inline(always)]
pub const fn opt_out_refuses_attach(expected_attach_type: u32) -> bool {
    expected_attach_type == ATTACH_MODIFY_RETURN
}

/// Lot 345: the helpers a foreign program may not call, opted out or not —
/// by their uapi ids (`enum bpf_func_id`), in the order of the slots of the
/// content judge's targets: `bpf_probe_write_user` rewrites a process's
/// memory, `bpf_override_return` a kernel function's return,
/// `bpf_send_signal` and `bpf_send_signal_thread` kill the agent past its
/// `task_kill` hook (the kernel sends them as `SEND_SIG_PRIV`, which no LSM
/// sees).
pub const FORBIDDEN_HELPERS: [(u32, &str); 4] = [
    (36, "bpf_probe_write_user"),
    (58, "bpf_override_return"),
    (109, "bpf_send_signal"),
    (117, "bpf_send_signal_thread"),
];

/// Lot 345: the kfunc of the same reach (6.13 and later): a signal to any
/// task the program holds, the agent's from `bpf_task_from_pid`.
pub const FORBIDDEN_KFUNC: &str = "bpf_send_signal_task";

/// Lot 345: the content judge's targets — the four helpers' (slots 0 to 3,
/// a call with `src_reg` 0) and the kfunc's (slot 4, `src_reg`
/// [`PSEUDO_KFUNC_CALL`]), each the `imm` of the call instruction as the
/// judged copy holds it: the helper's id and the kfunc's BTF id in the
/// kernel's copy of a load (the `bpf_prog_load` hook, 6.9 and later); the
/// called address less `__bpf_call_base` once the verifier fixed the calls
/// up (the `bpf_prog` hook, before 6.9). 0: no such call on this kernel.
pub const CALL_TARGETS: usize = 5;

/// Lot 345: the content judge's configuration map's slots: the stage (0),
/// the [`CALL_TARGETS`] (1 to 5), then [`CONTENT_LOCKDOWN_SLOT`].
pub const CONTENT_CONF_SLOTS: u32 = 2 + CALL_TARGETS as u32;

/// Lot 345: the slot of the content judge's configuration that holds this
/// kernel's `LOCKDOWN_BPF_WRITE_USER` (`enum lockdown_reason`, from its
/// BTF; 0: not armed). Before 6.9 the verifier asks the `locked_down` hook
/// with it when a program calls `bpf_probe_write_user` — the one target the
/// agent cannot calibrate (a program calling it needs `CAP_SYS_ADMIN`,
/// which the agent's unit does not have): a foreign caller is refused
/// there, and the verifier refuses the program.
pub const CONTENT_LOCKDOWN_SLOT: u32 = 1 + CALL_TARGETS as u32;

/// Lot 345: the calibration the agent asks of the `bpf_prog` hook before
/// 6.9 (`PROG_CONTENT_CALIB`), while it loads one of its own calibration
/// programs: the signals' (`bpf_send_signal`, then
/// `bpf_send_signal_thread`) or the return override's. The hook writes the
/// verified call's `imm` (the helper's address less `__bpf_call_base`) to
/// its target's slot: no kernel address is read from `kallsyms`, which the
/// agent's capabilities hide.
pub const CALIB_NONE: u32 = 0;
pub const CALIB_SIGNALS: u32 = 1;
pub const CALIB_OVERRIDE: u32 = 2;

/// Lot 345: the configuration slot the `n`-th helper call (from 0) of
/// calibration `kind`'s program fills — `None` past its calls.
#[inline(always)]
pub const fn calibration_slot(kind: u32, n: u32) -> Option<u32> {
    // the slots of FORBIDDEN_HELPERS (0 write_user, 1 override, 2
    // send_signal, 3 send_signal_thread), past the stage's slot
    match (kind, n) {
        (CALIB_SIGNALS, 0) => Some(1 + 2),
        (CALIB_SIGNALS, 1) => Some(1 + 3),
        (CALIB_OVERRIDE, 0) => Some(1 + 1),
        _ => None,
    }
}

/// Lot 345: the instructions of a calibration program the hook reads.
pub const CALIB_MAX_INSNS: u32 = 16;

/// Lot 345: no content judge on this kernel (the targets unknown).
pub const CONTENT_STAGE_OFF: u32 = 0;
/// Lot 345: the content is judged at `bpf_prog_load`, on the kernel's
/// copy of the instructions before the verifier runs (6.9 and later): a
/// program refused there never had an id.
pub const CONTENT_STAGE_LOAD: u32 = 1;
/// Lot 345: the content is judged at `bpf_prog`, on every handle of a
/// program once verified — the load's and any later one by id or path
/// (before 6.9: the load's program has an id before its descriptor).
pub const CONTENT_STAGE_HANDLE: u32 = 2;

/// `BPF_JMP | BPF_CALL`.
pub const INSN_CALL: u8 = 0x85;
/// `BPF_PSEUDO_KFUNC_CALL`: a call's `src_reg` for a kfunc.
pub const PSEUDO_KFUNC_CALL: u8 = 2;

/// Lot 345: the most instructions the content judge reads
/// (`BPF_COMPLEXITY_LIMIT_INSNS`, the most a load may hold, rounded up to
/// its 64 × 64 × 256 scan): a longer program is refused unjudged.
pub const CONTENT_MAX_INSNS: u32 = 1 << 20;

/// Lot 345: the slot of [`CALL_TARGETS`] that instruction `insn` (a
/// `struct bpf_insn` read as one little-endian word: `code`, the registers
/// — `src_reg` in the high nibble — `off`, `imm`) calls, plus one; 0 when
/// it calls none of them.
#[inline(always)]
pub const fn forbidden_call(insn: u64, targets: &[u32; CALL_TARGETS]) -> u32 {
    if insn as u8 != INSN_CALL {
        return 0;
    }
    let src = ((insn >> 12) & 0xf) as u8;
    let imm = (insn >> 32) as u32;
    if imm == 0 {
        return 0;
    }
    if src == 0 {
        let mut slot = 0;
        while slot < CALL_TARGETS - 1 {
            if targets[slot] == imm {
                return slot as u32 + 1;
            }
            slot += 1;
        }
        return 0;
    }
    if src == PSEUDO_KFUNC_CALL && targets[CALL_TARGETS - 1] == imm {
        return CALL_TARGETS as u32;
    }
    0
}

/// Lot 345: a `bpf_prog_type` refusal's `target_dev` when the content
/// refused it (the type itself is 0): an fmod_ret let through by no opt-out.
pub const CONTENT_FMOD_RET: u8 = 1;
/// Lot 345: … a program the judge could not read whole (longer than
/// [`CONTENT_MAX_INSNS`], or a failed read): refused as if it called one.
pub const CONTENT_UNJUDGED: u8 = 2;
/// Lot 345: … a call of slot `n` of [`CALL_TARGETS`]: `CONTENT_CALL + n`.
pub const CONTENT_CALL: u8 = 8;

/// Lot 345: why the content refused a load, from a `bpf_prog_type`
/// record's `target_dev`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentRefusal {
    /// [`CONTENT_FMOD_RET`].
    FmodRet,
    /// [`CONTENT_UNJUDGED`].
    Unjudged,
    /// A call of [`FORBIDDEN_HELPERS`]`[n]`, or of [`FORBIDDEN_KFUNC`] (`n`
    /// 4).
    Call(u8),
}

/// Lot 345: [`ContentRefusal`] of a `target_dev` (`None`: the type's
/// refusal, a known probe's mark, anything else).
pub const fn content_refusal(target_dev: u64) -> Option<ContentRefusal> {
    if target_dev == CONTENT_FMOD_RET as u64 {
        Some(ContentRefusal::FmodRet)
    } else if target_dev == CONTENT_UNJUDGED as u64 {
        Some(ContentRefusal::Unjudged)
    } else if target_dev >= CONTENT_CALL as u64
        && target_dev < CONTENT_CALL as u64 + CALL_TARGETS as u64
    {
        Some(ContentRefusal::Call(
            (target_dev - CONTENT_CALL as u64) as u8,
        ))
    } else {
        None
    }
}

/// Lot 345: the helper or kfunc slot `n` of [`CALL_TARGETS`] names.
pub const fn call_target_name(n: u8) -> &'static str {
    if (n as usize) < FORBIDDEN_HELPERS.len() {
        FORBIDDEN_HELPERS[n as usize].1
    } else {
        FORBIDDEN_KFUNC
    }
}

/// Every type [`denied_by_default`] names, as a mask.
pub const DENIED_MASK: u32 = type_bit(PROG_TYPE_KPROBE)
    | type_bit(PROG_TYPE_TRACEPOINT)
    | type_bit(PROG_TYPE_PERF_EVENT)
    | type_bit(PROG_TYPE_RAW_TRACEPOINT)
    | type_bit(PROG_TYPE_RAW_TRACEPOINT_WRITABLE)
    | type_bit(PROG_TYPE_TRACING)
    | type_bit(PROG_TYPE_STRUCT_OPS)
    | type_bit(PROG_TYPE_EXT)
    | type_bit(PROG_TYPE_LSM);

/// `enum bpf_prog_type`, by value (the uapi names).
pub const PROG_TYPES: [&str; 33] = [
    "BPF_PROG_TYPE_UNSPEC",
    "BPF_PROG_TYPE_SOCKET_FILTER",
    "BPF_PROG_TYPE_KPROBE",
    "BPF_PROG_TYPE_SCHED_CLS",
    "BPF_PROG_TYPE_SCHED_ACT",
    "BPF_PROG_TYPE_TRACEPOINT",
    "BPF_PROG_TYPE_XDP",
    "BPF_PROG_TYPE_PERF_EVENT",
    "BPF_PROG_TYPE_CGROUP_SKB",
    "BPF_PROG_TYPE_CGROUP_SOCK",
    "BPF_PROG_TYPE_LWT_IN",
    "BPF_PROG_TYPE_LWT_OUT",
    "BPF_PROG_TYPE_LWT_XMIT",
    "BPF_PROG_TYPE_SOCK_OPS",
    "BPF_PROG_TYPE_SK_SKB",
    "BPF_PROG_TYPE_CGROUP_DEVICE",
    "BPF_PROG_TYPE_SK_MSG",
    "BPF_PROG_TYPE_RAW_TRACEPOINT",
    "BPF_PROG_TYPE_CGROUP_SOCK_ADDR",
    "BPF_PROG_TYPE_LWT_SEG6LOCAL",
    "BPF_PROG_TYPE_LIRC_MODE2",
    "BPF_PROG_TYPE_SK_REUSEPORT",
    "BPF_PROG_TYPE_FLOW_DISSECTOR",
    "BPF_PROG_TYPE_CGROUP_SYSCTL",
    "BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE",
    "BPF_PROG_TYPE_CGROUP_SOCKOPT",
    "BPF_PROG_TYPE_TRACING",
    "BPF_PROG_TYPE_STRUCT_OPS",
    "BPF_PROG_TYPE_EXT",
    "BPF_PROG_TYPE_LSM",
    "BPF_PROG_TYPE_SK_LOOKUP",
    "BPF_PROG_TYPE_SYSCALL",
    "BPF_PROG_TYPE_NETFILTER",
];

/// `enum bpf_attach_type`, by value (the uapi names).
pub const ATTACH_TYPES: [&str; 56] = [
    "BPF_CGROUP_INET_INGRESS",
    "BPF_CGROUP_INET_EGRESS",
    "BPF_CGROUP_INET_SOCK_CREATE",
    "BPF_CGROUP_SOCK_OPS",
    "BPF_SK_SKB_STREAM_PARSER",
    "BPF_SK_SKB_STREAM_VERDICT",
    "BPF_CGROUP_DEVICE",
    "BPF_SK_MSG_VERDICT",
    "BPF_CGROUP_INET4_BIND",
    "BPF_CGROUP_INET6_BIND",
    "BPF_CGROUP_INET4_CONNECT",
    "BPF_CGROUP_INET6_CONNECT",
    "BPF_CGROUP_INET4_POST_BIND",
    "BPF_CGROUP_INET6_POST_BIND",
    "BPF_CGROUP_UDP4_SENDMSG",
    "BPF_CGROUP_UDP6_SENDMSG",
    "BPF_LIRC_MODE2",
    "BPF_FLOW_DISSECTOR",
    "BPF_CGROUP_SYSCTL",
    "BPF_CGROUP_UDP4_RECVMSG",
    "BPF_CGROUP_UDP6_RECVMSG",
    "BPF_CGROUP_GETSOCKOPT",
    "BPF_CGROUP_SETSOCKOPT",
    "BPF_TRACE_RAW_TP",
    "BPF_TRACE_FENTRY",
    "BPF_TRACE_FEXIT",
    "BPF_MODIFY_RETURN",
    "BPF_LSM_MAC",
    "BPF_TRACE_ITER",
    "BPF_CGROUP_INET4_GETPEERNAME",
    "BPF_CGROUP_INET6_GETPEERNAME",
    "BPF_CGROUP_INET4_GETSOCKNAME",
    "BPF_CGROUP_INET6_GETSOCKNAME",
    "BPF_XDP_DEVMAP",
    "BPF_CGROUP_INET_SOCK_RELEASE",
    "BPF_XDP_CPUMAP",
    "BPF_SK_LOOKUP",
    "BPF_XDP",
    "BPF_SK_SKB_VERDICT",
    "BPF_SK_REUSEPORT_SELECT",
    "BPF_SK_REUSEPORT_SELECT_OR_MIGRATE",
    "BPF_PERF_EVENT",
    "BPF_TRACE_KPROBE_MULTI",
    "BPF_LSM_CGROUP",
    "BPF_STRUCT_OPS",
    "BPF_NETFILTER",
    "BPF_TCX_INGRESS",
    "BPF_TCX_EGRESS",
    "BPF_TRACE_UPROBE_MULTI",
    "BPF_CGROUP_UNIX_CONNECT",
    "BPF_CGROUP_UNIX_SENDMSG",
    "BPF_CGROUP_UNIX_RECVMSG",
    "BPF_CGROUP_UNIX_GETPEERNAME",
    "BPF_CGROUP_UNIX_GETSOCKNAME",
    "BPF_NETKIT_PRIMARY",
    "BPF_NETKIT_PEER",
];

/// `enum bpf_link_type`, by value (the uapi names).
pub const LINK_TYPES: [&str; 14] = [
    "BPF_LINK_TYPE_UNSPEC",
    "BPF_LINK_TYPE_RAW_TRACEPOINT",
    "BPF_LINK_TYPE_TRACING",
    "BPF_LINK_TYPE_CGROUP",
    "BPF_LINK_TYPE_ITER",
    "BPF_LINK_TYPE_NETNS",
    "BPF_LINK_TYPE_XDP",
    "BPF_LINK_TYPE_PERF_EVENT",
    "BPF_LINK_TYPE_KPROBE_MULTI",
    "BPF_LINK_TYPE_STRUCT_OPS",
    "BPF_LINK_TYPE_NETFILTER",
    "BPF_LINK_TYPE_TCX",
    "BPF_LINK_TYPE_UPROBE_MULTI",
    "BPF_LINK_TYPE_NETKIT",
];

/// The short name of a uapi name past `prefix` (`BPF_PROG_TYPE_KPROBE` →
/// `kprobe`), or `None` for a value past the table.
#[cfg(feature = "std")]
fn short(table: &[&'static str], prefix: &str, value: u32) -> Option<String> {
    table
        .get(value as usize)
        .map(|n| n.trim_start_matches(prefix).to_ascii_lowercase())
}

/// A program type's short name (`kprobe`, `cgroup_device`), `type <n>`
/// for one this table does not know.
#[cfg(feature = "std")]
pub fn prog_type_name(prog_type: u32) -> String {
    short(&PROG_TYPES, "BPF_PROG_TYPE_", prog_type).unwrap_or_else(|| format!("type {prog_type}"))
}

/// An attach type's short name (`lsm_mac`, `cgroup_device`).
#[cfg(feature = "std")]
pub fn attach_type_name(attach_type: u32) -> String {
    short(&ATTACH_TYPES, "BPF_", attach_type).unwrap_or_else(|| format!("attach {attach_type}"))
}

/// A link type's short name (`tracing`, `perf_event`).
#[cfg(feature = "std")]
pub fn link_type_name(link_type: u32) -> String {
    short(&LINK_TYPES, "BPF_LINK_TYPE_", link_type)
        .unwrap_or_else(|| format!("link type {link_type}"))
}

/// The type a `bpf-loader-allow` line names (`kprobe`, `tracepoint`,
/// `perf_event`, `raw_tracepoint`, `raw_tracepoint_writable`, `tracing`,
/// `struct_ops`, `ext`, `lsm`): only the types refused by default.
#[cfg(feature = "std")]
pub fn opt_out_type(name: &str) -> Option<u32> {
    DENIED_BY_DEFAULT
        .iter()
        .copied()
        .find(|t| prog_type_name(*t) == name)
}

/// The names of the types in `mask`, in uapi order, joined by `,`.
#[cfg(feature = "std")]
pub fn mask_names(mask: u32) -> String {
    DENIED_BY_DEFAULT
        .iter()
        .filter(|t| mask & type_bit(**t) != 0)
        .map(|t| prog_type_name(*t))
        .collect::<Vec<_>>()
        .join(",")
}

/// Lot 290 (the lab's rounds on 6.8): programs the kernel loads itself —
/// from a module's init, through its light skeleton — by their name and the
/// kernel function they are attached to (which the kernel checks at the
/// load: a program of that name elsewhere is not one of them). HID-BPF's
/// dispatcher (6.3 to 6.10; prog id 2 on the 6.8 guest, loaded when udev
/// loads `hid` in the initramfs, after PID 1 started: its load time does
/// not tell it) and `bpf_preload`'s iterators (`maps.debug`, `progs.debug`).
pub const KERNEL_PROGRAMS: [(&str, &str); 3] = [
    ("hid_tail_call", "__hid_bpf_tail_call"),
    ("dump_bpf_map", "bpf_iter_bpf_map"),
    ("dump_bpf_prog", "bpf_iter_bpf_prog"),
];

/// Whether `(name, attach function)` is one of [`KERNEL_PROGRAMS`].
pub fn is_kernel_program(name: &[u8], attach: &[u8]) -> bool {
    fn trim(b: &[u8]) -> &[u8] {
        let end = b.iter().position(|c| *c == 0).unwrap_or(b.len());
        &b[..end]
    }
    let (n, a) = (trim(name), trim(attach));
    KERNEL_PROGRAMS
        .iter()
        .any(|(kn, ka)| kn.as_bytes() == n && ka.as_bytes() == a)
}

/// Lot 304: how a known system program's loader holds it attached — the
/// link whose descriptor proves the loader (its `/proc/<pid>/fdinfo`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownLink {
    /// A cgroup link of the program to the ROOT cgroup, `BPF_CGROUP_SYSCTL`.
    RootCgroupSysctl,
    /// A tracing link, `BPF_LSM_MAC` (on the entry's attach function).
    Lsm,
}

/// Lot 304: a known system program — one a service the distribution ships
/// loads at its start and keeps attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnownSystemProgram {
    /// The program's name as the kernel keeps it (`BPF_OBJ_NAME_LEN`: at
    /// most 15 bytes, a longer name cut).
    pub name: &'static str,
    pub prog_type: u32,
    /// Its attach function (an LSM program's); empty for a cgroup program.
    pub attach: &'static str,
    pub link: KnownLink,
    /// The packaged executable that loads it and holds its link.
    pub loader: &'static str,
    /// What it is, for the record.
    pub what: &'static str,
}

/// Lot 304: the known system programs (measured on Debian 13, systemd
/// 257.13, and Ubuntu 26.04, systemd 259.5):
/// - systemd-networkd's `sysctl_monitor` (systemd 257+), linked to the root
///   cgroup's `cgroup/sysctl` slot (multi) at networkd's start: created by
///   uid `systemd-network`, its descriptor and its link's held by
///   networkd's main process — not PID 1;
/// - PID 1's `restrict_filesystems` (`RestrictFileSystems=`, on a kernel
///   with the BPF LSM), an LSM program on `bpf_lsm_file_open`, its tracing
///   link held by PID 1.
pub const KNOWN_SYSTEM_PROGRAMS: [KnownSystemProgram; 2] = [
    KnownSystemProgram {
        name: "sysctl_monitor",
        prog_type: PROG_TYPE_CGROUP_SYSCTL,
        attach: "",
        link: KnownLink::RootCgroupSysctl,
        loader: "/usr/lib/systemd/systemd-networkd",
        what: "systemd-networkd's sysctl monitor (systemd 257+: it logs a write by another \
               process to a sysctl networkd manages, and refuses nothing)",
    },
    KnownSystemProgram {
        name: "restrict_filesy",
        prog_type: PROG_TYPE_LSM,
        attach: "bpf_lsm_file_open",
        link: KnownLink::Lsm,
        loader: "/usr/lib/systemd/systemd",
        what: "systemd's RestrictFileSystems= (PID 1: it refuses a unit's process the opening \
               of a file on a filesystem type its unit does not allow)",
    },
];

/// Lot 304: the entry of [`KNOWN_SYSTEM_PROGRAMS`] a program of that name,
/// type and attach function would be, held by a link of kind `link` (an
/// entry of a cgroup link names no attach function).
pub fn known_system_program(
    name: &str,
    prog_type: u32,
    attach: &str,
    link: KnownLink,
) -> Option<usize> {
    KNOWN_SYSTEM_PROGRAMS.iter().position(|k| {
        k.link == link
            && k.name == name
            && k.prog_type == prog_type
            && (k.attach.is_empty() || k.attach == attach)
    })
}

/// Lot 304: `target_dev` of a `sysctl_root_prog` record whose program is a
/// known system program, its loader proven ([`root_prog_known_dev`]); 0 is
/// a program not proven one (High).
pub const ROOT_PROG_KNOWN_BIT: u64 = 1 << 63;
/// Lot 304: the loader was seen loading it by the agent's `bpf` hook (the
/// root attach that followed is one the hook lets through only inside a
/// trusted-installer window); without it the program was loaded before
/// the agent's start.
pub const ROOT_PROG_SEEN_BIT: u64 = 1 << 62;

/// Lot 304: the `target_dev` of a known root program's record: the known
/// bit, the seen bit, the entry of [`KNOWN_SYSTEM_PROGRAMS`] (bits 32–47)
/// and the id of the link to the root its loader holds (bits 0–31).
#[inline(always)]
pub const fn root_prog_known_dev(entry: u16, seen: bool, link_id: u32) -> u64 {
    let seen = if seen { ROOT_PROG_SEEN_BIT } else { 0 };
    ROOT_PROG_KNOWN_BIT | seen | ((entry as u64) << 32) | link_id as u64
}

/// Lot 304: `(entry, seen, link id)` of a known root program's record, or
/// `None` (a program not proven known, or an entry not in the table or
/// not one of the root's `cgroup/sysctl` slot).
#[inline(always)]
pub const fn root_prog_known_of(target_dev: u64) -> Option<(usize, bool, u32)> {
    let entry = ((target_dev >> 32) & 0xffff) as usize;
    if target_dev & ROOT_PROG_KNOWN_BIT == 0
        || entry >= KNOWN_SYSTEM_PROGRAMS.len()
        || !matches!(
            KNOWN_SYSTEM_PROGRAMS[entry].link,
            KnownLink::RootCgroupSysctl
        )
    {
        return None;
    }
    Some((
        entry,
        target_dev & ROOT_PROG_SEEN_BIT != 0,
        target_dev as u32,
    ))
}

/// Lot 340 (the alpha's daily false positives): a BPF load a packaged
/// system program makes — mostly a feature probe at its start (a program
/// loaded to learn whether the kernel supports its type, never attached) —
/// of a type the agent's `bpf` hook refuses outside a trusted-installer
/// window. Refused all the same; the record is Low and raises no posture
/// (so it never corroborates COMBAT) when its loader is proven.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnownSystemProbe {
    /// The packaged executable that makes the probe.
    pub loader: &'static str,
    /// The program type it loads.
    pub prog_type: u32,
    /// What it is, for the record.
    pub what: &'static str,
    /// The review of #552 (F5b): the loader must be PID 1 itself — the
    /// system manager, not a user manager or another instance of the same
    /// program.
    pub pid_one: bool,
}

/// Lot 340: systemd's own refused BPF loads, measured on Ubuntu 26.04
/// (systemd 259.5, kernel 7.0; lot 304's lab and this lot's): the user
/// manager (`systemd --user`) loads a `tracepoint` program at the user's
/// first login, systemd-networkd a `kprobe` program and another when it
/// starts (libbpf's feature probes) — each refused and signed High
/// (NN-L-AT-001, `bpf_prog_type`), raising ENGAGED every boot, and (the
/// coordinator's input from lot 332's lab) corroborating an unrelated mass
/// write into COMBAT. Debian 13 (systemd 257) makes none. The coordinator's
/// rule: systemd's own BPF loads, told by the packaged loader's identity,
/// are a known system program's — so the types systemd's programs load
/// that the hook refuses are listed for both loaders: `tracepoint` and
/// `kprobe` (libbpf's probes), and PID 1's `lsm` (the review of #552, F5b:
/// PID 1 itself, [`KnownSystemProbe::pid_one`]; `RestrictFileSystems=`,
/// loaded again at a `daemon-reexec`; before the agent's start it is lot
/// 304's known program). A load of any other type, or by any other loader,
/// keeps High. The index of an entry is its record's (`known_probe_dev`):
/// entries are only ever appended.
pub const KNOWN_SYSTEM_PROBES: [KnownSystemProbe; 5] = [
    KnownSystemProbe {
        loader: "/usr/lib/systemd/systemd",
        prog_type: PROG_TYPE_TRACEPOINT,
        what: "a systemd manager's feature probe (the user manager's at the first login)",
        pid_one: false,
    },
    KnownSystemProbe {
        loader: "/usr/lib/systemd/systemd-networkd",
        prog_type: PROG_TYPE_KPROBE,
        what: "systemd-networkd's feature probe at its start (libbpf)",
        pid_one: false,
    },
    KnownSystemProbe {
        loader: "/usr/lib/systemd/systemd-networkd",
        prog_type: PROG_TYPE_TRACEPOINT,
        what: "systemd-networkd's feature probe at its start (libbpf)",
        pid_one: false,
    },
    KnownSystemProbe {
        loader: "/usr/lib/systemd/systemd",
        prog_type: PROG_TYPE_KPROBE,
        what: "a systemd manager's feature probe (libbpf)",
        pid_one: false,
    },
    KnownSystemProbe {
        loader: "/usr/lib/systemd/systemd",
        prog_type: PROG_TYPE_LSM,
        what: "systemd's RestrictFileSystems= program, loaded again (a daemon-reexec); its units \
               run without it until the next boot or a trusted-installer window",
        pid_one: true,
    },
];

/// Lot 340: the entry of [`KNOWN_SYSTEM_PROBES`] for a load of `prog_type`
/// by a process that runs `loader` (its packaged path; the caller proves the
/// image is that file). The review of #552 (F5b): `pid` is the loader's, and
/// an entry for PID 1 only ([`KnownSystemProbe::pid_one`]) is no other's.
pub fn known_system_probe(loader: &str, prog_type: u32, pid: u32) -> Option<usize> {
    KNOWN_SYSTEM_PROBES
        .iter()
        .position(|k| k.loader == loader && k.prog_type == prog_type && (!k.pid_one || pid == 1))
}

/// Lot 340: `target_dev` of a `bpf_prog_type` record whose loader the agent
/// proved a known system probe's ([`known_probe_dev`]); the kernel's record
/// carries 0 there.
pub const KNOWN_PROBE_BIT: u64 = 1 << 63;

/// Lot 340: the `target_dev` of a proven known probe's record: the bit and
/// the entry of [`KNOWN_SYSTEM_PROBES`] (bits 0–15).
#[inline(always)]
pub const fn known_probe_dev(entry: u16) -> u64 {
    KNOWN_PROBE_BIT | entry as u64
}

/// Lot 340: the entry of [`KNOWN_SYSTEM_PROBES`] a `bpf_prog_type` record's
/// `target_dev` names, when the record's program type (`prog_type`, its
/// `target_ino`) is that entry's; `None` otherwise (the kernel's 0, any
/// other bit set, an entry not in the table, another type).
#[inline(always)]
pub const fn known_probe_of(target_dev: u64, prog_type: u64) -> Option<usize> {
    let entry = (target_dev & 0xffff) as usize;
    if target_dev & !(KNOWN_PROBE_BIT | 0xffff) != 0
        || target_dev & KNOWN_PROBE_BIT == 0
        || entry >= KNOWN_SYSTEM_PROBES.len()
        || KNOWN_SYSTEM_PROBES[entry].prog_type as u64 != prog_type
    {
        return None;
    }
    Some(entry)
}

/// Length of a program's name in the kernel (`BPF_OBJ_NAME_LEN`).
pub const OBJ_NAME_LEN: usize = 16;
/// The bytes of a program's attach function's name an iterator record
/// carries (a longer name is cut).
pub const ATTACH_NAME_LEN: usize = 64;

/// One program as the cross-view's `iter/bpf_prog` iterator writes it.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct ProgRecord {
    pub id: u32,
    pub prog_type: u32,
    pub expected_attach_type: u32,
    /// 1 when the attach function's name was read.
    pub attach_read: u32,
    /// When it was loaded (boot-time ns; 0: not read).
    pub load_time: u64,
    pub tag: [u8; 8],
    pub name: [u8; OBJ_NAME_LEN],
    pub attach: [u8; ATTACH_NAME_LEN],
}

/// One link as the cross-view's `iter/bpf_link` iterator writes it.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct LinkRecord {
    pub id: u32,
    pub link_type: u32,
    pub prog_id: u32,
    pub _pad: u32,
}

/// Who loaded a program the `bpf` hook saw loading (`SEEN_PROGS`' value,
/// keyed by the program's id).
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct SeenLoad {
    pub tgid: u32,
    pub uid: u32,
    /// The program's type (`u32::MAX`: not read).
    pub prog_type: u32,
    pub _pad: u32,
    pub comm: [u8; 16],
}

/// A NUL-padded name as text.
#[cfg(feature = "std")]
pub fn text(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// The cross-view's record of an object in an event (lot 290,
/// `FS_OP_BPF_UNSEEN` / `FS_OP_BPF_BASELINE`): `target_ino` carries
/// whether it is a link (this bit), its type (bits 32–62: the program's
/// or the link's) and its id (bits 0–31).
pub const CROSSVIEW_LINK_BIT: u64 = 1 << 63;
/// A cross-view record's bit for a program the kernel loaded before user
/// space started (its load time before PID 1's start): the kernel's own
/// (HID-BPF's `hid_tail_call`), not one loaded while the agent was not
/// running. The type takes bits 32–60.
pub const CROSSVIEW_EARLY_BIT: u64 = 1 << 62;
/// Lot 304: a cross-view record's bit for a baseline program proven a
/// known system program ([`KNOWN_SYSTEM_PROGRAMS`]): its loader holds its
/// link and runs the packaged executable, and loaded it before the agent
/// started (the record's pid and uid are the loader's). The types are far
/// below 2^29: a record written before this bit never has it.
pub const CROSSVIEW_KNOWN_BIT: u64 = 1 << 61;

/// `target_ino` of a cross-view record.
#[inline(always)]
pub const fn crossview_ino(is_link: bool, early: bool, object_type: u32, id: u32) -> u64 {
    let link = if is_link { CROSSVIEW_LINK_BIT } else { 0 };
    let early = if early { CROSSVIEW_EARLY_BIT } else { 0 };
    link | early | (((object_type as u64) & 0x1fff_ffff) << 32) | id as u64
}

/// `(is_link, early, type, id)` of a cross-view record's `target_ino`.
#[inline(always)]
pub const fn crossview_of(target_ino: u64) -> (bool, bool, u32, u32) {
    (
        target_ino & CROSSVIEW_LINK_BIT != 0,
        target_ino & CROSSVIEW_EARLY_BIT != 0,
        ((target_ino >> 32) & 0x1fff_ffff) as u32,
        target_ino as u32,
    )
}

/// A program's tag as the `target_dev` of a cross-view record (its eight
/// bytes, big-endian: printed as `bpftool` prints it).
#[inline(always)]
pub const fn tag_word(tag: [u8; 8]) -> u64 {
    u64::from_be_bytes(tag)
}

/// The tag's sixteen hex digits.
#[cfg(feature = "std")]
pub fn tag_hex(word: u64) -> String {
    format!("{word:016x}")
}

/// The `comm` of a cross-view record: the object's name and its attach
/// point (`name@attach`; a BPF object's name holds no `@`).
#[cfg(feature = "std")]
pub fn object_comm(name: &str, attach: &str) -> String {
    format!("{name}@{attach}")
}

/// `(name, attach point)` of a cross-view record's `comm`.
#[cfg(feature = "std")]
pub fn object_of_comm(comm: &str) -> (&str, &str) {
    comm.split_once('@').unwrap_or((comm, "?"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lot 340: a known probe's record names its entry only with the bit,
    /// for that entry's program type; the kernel's 0, a stray bit, an
    /// entry out of the table and another type name none.
    #[test]
    fn a_known_probe_s_record_names_its_entry_for_its_type_only() {
        for (n, k) in KNOWN_SYSTEM_PROBES.iter().enumerate() {
            let dev = known_probe_dev(n as u16);
            assert_eq!(known_probe_of(dev, u64::from(k.prog_type)), Some(n));
            assert_eq!(known_system_probe(k.loader, k.prog_type, 1), Some(n));
            assert_eq!(known_probe_of(dev, u64::from(PROG_TYPE_EXT)), None);
            assert_eq!(
                known_probe_of(dev | (1 << 40), u64::from(k.prog_type)),
                None
            );
        }
        assert_eq!(known_probe_of(0, u64::from(PROG_TYPE_KPROBE)), None);
        assert_eq!(
            known_probe_of(KNOWN_PROBE_BIT | 7, u64::from(PROG_TYPE_KPROBE)),
            None
        );
        assert_eq!(
            known_system_probe("/usr/lib/systemd/systemd-networkd", PROG_TYPE_LSM, 1),
            None
        );
        assert_eq!(
            known_system_probe("/tmp/systemd-networkd", PROG_TYPE_KPROBE, 868),
            None
        );
        // lot 340 (the coordinator's rule): systemd's own loads only, of the
        // types its programs use; an entry's index never moves
        let systemd = "/usr/lib/systemd/systemd";
        assert_eq!(
            known_system_probe(systemd, PROG_TYPE_TRACEPOINT, 2301),
            Some(0)
        );
        assert_eq!(known_system_probe(systemd, PROG_TYPE_LSM, 1), Some(4));
        assert_eq!(known_system_probe(systemd, PROG_TYPE_EXT, 1), None);
        // the review of #552 (F5b): `lsm` is PID 1's only — never a user
        // manager's or another instance's of the same program
        assert_eq!(known_system_probe(systemd, PROG_TYPE_LSM, 2301), None);
        assert_eq!(
            known_system_probe(systemd, PROG_TYPE_TRACEPOINT, 1),
            Some(0)
        );
        assert_eq!(
            known_system_probe("/usr/bin/bpftool", PROG_TYPE_TRACEPOINT, 1),
            None
        );
    }

    const UAPI_HEADER: &str = "/usr/include/linux/bpf.h";

    /// The enumerators of `enum <name>` in order of value (every one of
    /// these three enums counts up from 0, without aliases).
    fn enumerators(header: &str, name: &str) -> Vec<String> {
        let start = header
            .find(&format!("enum {name} {{"))
            .unwrap_or_else(|| panic!("enum {name} in the header"));
        let body = &header[start..];
        let body = &body[body.find('{').unwrap() + 1..body.find("};").unwrap()];
        let mut out = Vec::new();
        for line in body.lines() {
            let line = line.split("/*").next().unwrap().split("//").next().unwrap();
            for entry in line.split(',') {
                let ident = entry.split('=').next().unwrap().trim();
                if ident.is_empty() || ident.starts_with("__") {
                    continue;
                }
                if let Some(v) = entry.split_once('=').map(|(_, v)| v.trim()) {
                    assert_eq!(
                        v.parse::<usize>().ok(),
                        Some(out.len()),
                        "{ident} = {v}: counted from 0"
                    );
                }
                out.push(ident.to_string());
            }
        }
        out
    }

    /// Lot 290 (named): every table is the header's, value for value (a
    /// header newer than the table may add values at its end).
    #[test]
    fn the_type_tables_are_the_uapi_headers() {
        let header = std::fs::read_to_string(UAPI_HEADER)
            .unwrap_or_else(|e| panic!("{UAPI_HEADER}: {e} (linux-libc-dev)"));
        for (name, table) in [
            ("bpf_prog_type", &PROG_TYPES[..]),
            ("bpf_attach_type", &ATTACH_TYPES[..]),
            ("bpf_link_type", &LINK_TYPES[..]),
        ] {
            let got = enumerators(&header, name);
            assert!(got.len() >= table.len(), "{name}: {got:?}");
            for (i, n) in table.iter().enumerate() {
                assert_eq!(got[i], *n, "{name} value {i}");
            }
        }
        assert_eq!(
            PROG_TYPES[PROG_TYPE_KPROBE as usize],
            "BPF_PROG_TYPE_KPROBE"
        );
        assert_eq!(
            PROG_TYPES[PROG_TYPE_TRACING as usize],
            "BPF_PROG_TYPE_TRACING"
        );
        assert_eq!(
            PROG_TYPES[PROG_TYPE_STRUCT_OPS as usize],
            "BPF_PROG_TYPE_STRUCT_OPS"
        );
        assert_eq!(PROG_TYPES[PROG_TYPE_EXT as usize], "BPF_PROG_TYPE_EXT");
        assert_eq!(PROG_TYPES[PROG_TYPE_LSM as usize], "BPF_PROG_TYPE_LSM");
        assert_eq!(
            PROG_TYPES[PROG_TYPE_CGROUP_SYSCTL as usize],
            "BPF_PROG_TYPE_CGROUP_SYSCTL"
        );
        assert_eq!(ATTACH_TYPES[ATTACH_TRACE_ITER as usize], "BPF_TRACE_ITER");
        assert_eq!(ATTACH_TYPES[ATTACH_LSM_MAC as usize], "BPF_LSM_MAC");
    }

    /// Lot 290 (named): exactly the nine types are refused by default —
    /// the vehicles of `bpf_probe_write_user`, `bpf_override_return`,
    /// `bpf_send_signal` and of a hook's replacement, the tracepoint and
    /// perf_event types among them (the coordinator's decision after the
    /// benign corpus) — and the types of systemd's and the container
    /// runtimes' programs, of networking and of socket filters are not.
    #[test]
    fn only_the_rootkit_grade_types_are_refused_by_default() {
        let refused: Vec<u32> = (0..64).filter(|t| denied_by_default(*t)).collect();
        assert_eq!(refused, vec![2, 5, 7, 17, 24, 26, 27, 28, 29]);
        assert_eq!(refused, DENIED_BY_DEFAULT.to_vec());
        for allowed in [
            "socket_filter",
            "sched_cls",
            "sched_act",
            "xdp",
            "cgroup_skb",
            "cgroup_sock",
            "cgroup_device",
            "cgroup_sock_addr",
            "cgroup_sysctl",
            "cgroup_sockopt",
            "sk_lookup",
            "flow_dissector",
            "lirc_mode2",
            "sk_msg",
            "sk_skb",
            "sock_ops",
            "netfilter",
            "syscall",
        ] {
            let t = PROG_TYPES
                .iter()
                .position(|n| {
                    n.trim_start_matches("BPF_PROG_TYPE_")
                        .eq_ignore_ascii_case(allowed)
                })
                .unwrap_or_else(|| panic!("{allowed}")) as u32;
            assert!(!denied_by_default(t), "{allowed}");
        }
        // the coordinator's extension: the tracepoint family and perf
        // events (bpf_probe_write_user, bpf_send_signal)
        for refused in [
            "tracepoint",
            "raw_tracepoint",
            "raw_tracepoint_writable",
            "perf_event",
        ] {
            assert!(
                opt_out_type(refused).is_some_and(denied_by_default),
                "{refused}"
            );
        }
        assert_eq!(
            DENIED_MASK,
            (1 << 2)
                | (1 << 5)
                | (1 << 7)
                | (1 << 17)
                | (1 << 24)
                | (1 << 26)
                | (1 << 27)
                | (1 << 28)
                | (1 << 29)
        );
        assert_eq!(type_bit(31), 1 << 31);
        assert_eq!(type_bit(32), 0);
    }

    /// Lot 290: the names a record and a policy line use.
    #[test]
    fn the_names_are_the_short_uapi_names() {
        assert_eq!(prog_type_name(2), "kprobe");
        assert_eq!(prog_type_name(15), "cgroup_device");
        assert_eq!(prog_type_name(99), "type 99");
        assert_eq!(attach_type_name(27), "lsm_mac");
        assert_eq!(attach_type_name(6), "cgroup_device");
        assert_eq!(attach_type_name(999), "attach 999");
        assert_eq!(link_type_name(2), "tracing");
        assert_eq!(link_type_name(77), "link type 77");
        for (n, t) in [
            ("kprobe", 2),
            ("tracing", 26),
            ("struct_ops", 27),
            ("ext", 28),
            ("lsm", 29),
        ] {
            assert_eq!(opt_out_type(n), Some(t), "{n}");
        }
        assert_eq!(
            opt_out_type("xdp"),
            None,
            "not refused: nothing to opt out of"
        );
        assert_eq!(opt_out_type("KPROBE"), None);
        assert_eq!(mask_names(type_bit(2) | type_bit(29)), "kprobe,lsm");
        assert_eq!(mask_names(0), "");
        assert_eq!(text(b"abc\0\0x"), "abc");
        assert_eq!(text(b"abcdef"), "abcdef");
    }

    /// Lot 290: a cross-view record's fields go through the event and
    /// come back the same.
    #[test]
    fn a_cross_view_record_round_trips() {
        for (link, early, t, id) in [
            (false, false, 29, 7),
            (true, false, 2, u32::MAX),
            (false, true, 0, 0),
            (true, true, 13, 1),
            (false, true, 26, 2),
        ] {
            assert_eq!(
                crossview_of(crossview_ino(link, early, t, id)),
                (link, early, t, id)
            );
        }
        assert_eq!(crossview_ino(false, false, 29, 7), (29 << 32) | 7);
        assert_eq!(crossview_ino(false, true, 0, 0), 1 << 62);
        assert_eq!(
            tag_hex(tag_word([0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3])),
            "deadbeef00010203"
        );
        assert_eq!(
            object_of_comm(&object_comm("nn_x", "bpf_lsm_file_open")),
            ("nn_x", "bpf_lsm_file_open")
        );
        assert_eq!(object_of_comm("plain"), ("plain", "?"));
    }

    /// Lot 290 (named; the lab's rounds): the kernel's own programs by
    /// name AND attach function — the same name elsewhere is not one.
    #[test]
    fn the_kernel_s_own_programs_are_told_by_name_and_attach_point() {
        assert!(is_kernel_program(
            b"hid_tail_call\0\0\0",
            b"__hid_bpf_tail_call\0"
        ));
        assert!(is_kernel_program(b"dump_bpf_prog", b"bpf_iter_bpf_prog"));
        assert!(!is_kernel_program(b"hid_tail_call", b"bpf_lsm_file_open"));
        assert!(!is_kernel_program(b"hid_tail_cal", b"__hid_bpf_tail_call"));
        assert!(!is_kernel_program(b"rootkit", b"__hid_bpf_tail_call"));
        assert!(!is_kernel_program(b"", b""));
    }

    /// Lot 304 (named): a known root program's record carries its entry,
    /// how its load was established and its link — and nothing else is
    /// read as one: a record of 0 (a program not proven known), an entry
    /// past the table, an entry that is not a root `cgroup/sysctl` one.
    #[test]
    fn a_known_root_program_s_record_round_trips() {
        for (entry, seen, link) in [(0u16, false, 3u32), (0, true, u32::MAX), (0, false, 0)] {
            let dev = root_prog_known_dev(entry, seen, link);
            assert_eq!(root_prog_known_of(dev), Some((entry as usize, seen, link)));
            assert_ne!(dev, 0);
        }
        assert_eq!(root_prog_known_of(0), None);
        assert_eq!(root_prog_known_of(ROOT_PROG_SEEN_BIT | 3), None);
        assert_eq!(
            root_prog_known_of(root_prog_known_dev(
                KNOWN_SYSTEM_PROGRAMS.len() as u16,
                false,
                3
            )),
            None
        );
        // the LSM entry is no root program's
        assert_eq!(root_prog_known_of(root_prog_known_dev(1, false, 3)), None);
        // the layout: the entry in bits 32-47, the link in bits 0-31
        assert_eq!(
            root_prog_known_dev(1, true, 3),
            ROOT_PROG_KNOWN_BIT | ROOT_PROG_SEEN_BIT | (1 << 32) | 3
        );
    }

    /// Lot 304 (named): the known system programs, by name, type, attach
    /// function and link kind together — each alone is not one; the table
    /// holds kernel names (at most 15 bytes) and packaged loaders.
    #[test]
    fn a_known_system_program_is_told_by_all_its_traits() {
        use KnownLink::{Lsm, RootCgroupSysctl};
        assert_eq!(
            known_system_program("sysctl_monitor", 23, "", RootCgroupSysctl),
            Some(0)
        );
        // a cgroup entry names no attach function: whatever the census says
        assert_eq!(
            known_system_program("sysctl_monitor", 23, "cgroup", RootCgroupSysctl),
            Some(0)
        );
        assert_eq!(
            known_system_program("restrict_filesy", 29, "bpf_lsm_file_open", Lsm),
            Some(1)
        );
        for (n, t, a, l) in [
            ("sysctl_monitor", 23, "", Lsm),
            ("sysctl_monitor", 8, "", RootCgroupSysctl),
            ("sysctl_monitox", 23, "", RootCgroupSysctl),
            ("restrict_filesy", 29, "bpf_lsm_bprm_check_security", Lsm),
            ("restrict_filesy", 26, "bpf_lsm_file_open", Lsm),
            ("restrict_filesy", 29, "bpf_lsm_file_open", RootCgroupSysctl),
            ("restrict_files", 29, "bpf_lsm_file_open", Lsm),
        ] {
            assert_eq!(known_system_program(n, t, a, l), None, "{n} {t} {a} {l:?}");
        }
        for k in KNOWN_SYSTEM_PROGRAMS {
            assert!(!k.name.is_empty() && k.name.len() < OBJ_NAME_LEN, "{k:?}");
            assert!(k.loader.starts_with("/usr/lib/systemd/"), "{k:?}");
            assert_eq!(k.attach.is_empty(), k.link == RootCgroupSysctl, "{k:?}");
        }
        assert_eq!(
            KNOWN_SYSTEM_PROGRAMS[0].loader,
            "/usr/lib/systemd/systemd-networkd"
        );
        assert_eq!(KNOWN_SYSTEM_PROGRAMS[1].loader, "/usr/lib/systemd/systemd");
        // the cross-view's known bit is none of the others, and a type
        // keeps its bits below it
        assert_eq!(
            CROSSVIEW_KNOWN_BIT & (CROSSVIEW_LINK_BIT | CROSSVIEW_EARLY_BIT),
            0
        );
        let k = crossview_ino(false, false, 0x1fff_ffff, 7) | CROSSVIEW_KNOWN_BIT;
        assert_eq!(crossview_of(k), (false, false, 0x1fff_ffff, 7));
        assert_eq!(
            crossview_ino(false, false, PROG_TYPE_LSM, 21) & CROSSVIEW_KNOWN_BIT,
            0
        );
    }

    /// Lot 290: the iterators' records, as userland reads them.
    #[test]
    fn the_records_have_their_sizes() {
        assert_eq!(core::mem::size_of::<ProgRecord>(), 16 + 8 + 8 + 16 + 64);
        assert_eq!(core::mem::size_of::<LinkRecord>(), 16);
        assert_eq!(core::mem::size_of::<SeenLoad>(), 32);
    }

    /// Lot 345 (named; the re-check of #550, N2 and point 1 (ii)): the
    /// helpers the content judge refuses are the header's ids, the fmod_ret
    /// attach type is the header's, and `expected_attach_type` sits at byte
    /// 68 of a `BPF_PROG_LOAD` attr — the header's fields before it, by
    /// their sizes.
    #[test]
    fn the_content_judge_s_numbers_are_the_uapi_header_s() {
        let header = std::fs::read_to_string(UAPI_HEADER)
            .unwrap_or_else(|e| panic!("{UAPI_HEADER}: {e} (linux-libc-dev)"));
        for (id, name) in FORBIDDEN_HELPERS {
            let short = name.strip_prefix("bpf_").unwrap();
            assert!(
                header.contains(&format!("FN({short}, {id}, ##ctx)")),
                "{name} is helper {id}"
            );
        }
        assert_eq!(
            ATTACH_TYPES[ATTACH_MODIFY_RETURN as usize],
            "BPF_MODIFY_RETURN"
        );
        assert!(opt_out_refuses_attach(ATTACH_MODIFY_RETURN));
        for other in [0, 24, 25, 27, 28, 42] {
            assert!(!opt_out_refuses_attach(other), "{other}");
        }
        // the anonymous struct of BPF_PROG_LOAD, to expected_attach_type
        let start = header
            .find("struct { /* anonymous struct used by BPF_PROG_LOAD command */")
            .expect("BPF_PROG_LOAD's struct");
        let body = &header[start..];
        let body = &body[..body.find("};").unwrap()];
        let mut off = 0usize;
        let mut found = None;
        for line in body.lines().skip(1) {
            let decl = line.split("/*").next().unwrap().trim();
            let Some(decl) = decl.strip_suffix(';') else {
                continue;
            };
            let mut parts = decl.split_whitespace();
            let (ty, name) = (parts.next().unwrap(), parts.last().unwrap());
            if name == "expected_attach_type" {
                found = Some(off);
                break;
            }
            let size = match ty {
                "__u32" => 4,
                "__aligned_u64" => {
                    off = off.next_multiple_of(8);
                    8
                }
                "char" if name == "prog_name[BPF_OBJ_NAME_LEN]" => 16,
                other => panic!("an unexpected field before expected_attach_type: {other} {name}"),
            };
            off += size;
        }
        assert_eq!(found, Some(PROG_LOAD_ATTACH_TYPE_OFFSET));
    }

    /// Lot 345 (named): the judge finds a call of each target in its slot —
    /// a helper's with `src_reg` 0, the kfunc's with `src_reg` 2 — and no
    /// other instruction: another opcode with the same `imm`, a call of
    /// another helper, a bpf-to-bpf call (`src_reg` 1) to that offset, an
    /// absent target (0).
    #[test]
    fn the_content_judge_finds_the_forbidden_calls_only() {
        let insn = |code: u8, src: u8, imm: u32| -> u64 {
            code as u64 | ((src as u64) << 12) | ((imm as u64) << 32)
        };
        let pre = [36, 58, 109, 117, 9_001];
        for (slot, imm) in pre.iter().enumerate().take(4) {
            assert_eq!(
                forbidden_call(insn(INSN_CALL, 0, *imm), &pre),
                slot as u32 + 1
            );
            // the same number elsewhere
            assert_eq!(forbidden_call(insn(0xb7, 0, *imm), &pre), 0);
            assert_eq!(forbidden_call(insn(INSN_CALL, 1, *imm), &pre), 0);
            assert_eq!(
                forbidden_call(insn(INSN_CALL, PSEUDO_KFUNC_CALL, *imm), &pre),
                0
            );
        }
        assert_eq!(
            forbidden_call(insn(INSN_CALL, PSEUDO_KFUNC_CALL, 9_001), &pre),
            5
        );
        assert_eq!(forbidden_call(insn(INSN_CALL, 0, 9_001), &pre), 0);
        // a bpf-to-bpf call (src_reg 1) to an offset that is the kfunc's id
        assert_eq!(forbidden_call(insn(INSN_CALL, 1, 9_001), &pre), 0);
        // other helpers: bpf_map_lookup_elem, bpf_probe_read_kernel,
        // bpf_get_current_task, bpf_ringbuf_output
        for other in [1, 113, 35, 130] {
            assert_eq!(forbidden_call(insn(INSN_CALL, 0, other), &pre), 0);
        }
        // the registers' nibble of dst_reg does not matter; src_reg does
        assert_eq!(
            forbidden_call(insn(INSN_CALL, 0, 109) | (0x3 << 8), &pre),
            3
        );
        // a kernel without the kfunc (0): no call is it, not even imm 0
        let no_kfunc = [36, 58, 109, 117, 0];
        assert_eq!(
            forbidden_call(insn(INSN_CALL, PSEUDO_KFUNC_CALL, 0), &no_kfunc),
            0
        );
        assert_eq!(forbidden_call(insn(INSN_CALL, 0, 0), &[0; CALL_TARGETS]), 0);
        // after the fix-up: the address less __bpf_call_base, negative too
        let post = [0x0012_3450, 0xfff0_0010, 0x0001_0000, 0x7fff_fff0, 0];
        assert_eq!(forbidden_call(insn(INSN_CALL, 0, 0xfff0_0010), &post), 2);
        assert_eq!(forbidden_call(insn(INSN_CALL, 0, 109), &post), 0);
    }

    /// Lot 345 (named): each calibration fills the slot of the helper its
    /// program calls in that order, and nothing past its calls.
    #[test]
    fn a_calibration_fills_its_helpers_slots() {
        let name = |slot: Option<u32>| slot.map(|s| FORBIDDEN_HELPERS[s as usize - 1].1);
        assert_eq!(
            name(calibration_slot(CALIB_SIGNALS, 0)),
            Some("bpf_send_signal")
        );
        assert_eq!(
            name(calibration_slot(CALIB_SIGNALS, 1)),
            Some("bpf_send_signal_thread")
        );
        assert_eq!(
            name(calibration_slot(CALIB_OVERRIDE, 0)),
            Some("bpf_override_return")
        );
        for (kind, n) in [
            (CALIB_SIGNALS, 2),
            (CALIB_OVERRIDE, 1),
            (CALIB_NONE, 0),
            (9, 0),
        ] {
            assert_eq!(calibration_slot(kind, n), None, "{kind} {n}");
        }
        const { assert!(CONTENT_LOCKDOWN_SLOT < CONTENT_CONF_SLOTS) };
        assert_eq!(CONTENT_LOCKDOWN_SLOT, CALL_TARGETS as u32 + 1);
    }

    /// Lot 345 (named): a content refusal's record round-trips, and the
    /// type's own refusal (0) and a known probe's mark are none.
    #[test]
    fn a_content_refusal_s_record_round_trips() {
        assert_eq!(content_refusal(0), None);
        assert_eq!(
            content_refusal(CONTENT_FMOD_RET as u64),
            Some(ContentRefusal::FmodRet)
        );
        assert_eq!(
            content_refusal(CONTENT_UNJUDGED as u64),
            Some(ContentRefusal::Unjudged)
        );
        for n in 0..CALL_TARGETS as u8 {
            assert_eq!(
                content_refusal((CONTENT_CALL + n) as u64),
                Some(ContentRefusal::Call(n))
            );
        }
        assert_eq!(
            content_refusal((CONTENT_CALL + CALL_TARGETS as u8) as u64),
            None
        );
        assert_eq!(content_refusal(known_probe_dev(0)), None);
        assert_eq!(
            known_probe_of(CONTENT_FMOD_RET as u64, PROG_TYPE_TRACING as u64),
            None
        );
        assert_eq!(call_target_name(2), "bpf_send_signal");
        assert_eq!(call_target_name(4), FORBIDDEN_KFUNC);
    }
}
