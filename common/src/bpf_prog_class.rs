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
}
