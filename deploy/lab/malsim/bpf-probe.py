#!/usr/bin/env python3
# Lot 290 — a minimal bpf(2) client for foreign-bpf-check.sh (lab guests
# only, as root). Each command prints one line: "OK <detail>" or
# "ERR <errno name> <errno>".
#
#   bpf-probe.py load-kprobe-write-user [--pin PATH] [--name NAME]
#       [--type kprobe|tracepoint|perf_event|raw_tracepoint]
#       BPF_PROG_LOAD of a program that calls bpf_probe_write_user, a
#       kprobe unless --type names another tracing type that may call it
#       (never attached: the load itself is what the agent judges)
#   bpf-probe.py load-tracing [--type kprobe|tracepoint|perf_event|raw_tracepoint]
#       [--call none|write_user|send_signal|send_signal_thread|override_return]
#       [--name NAME] [--pin PATH]
#       (lot 345) BPF_PROG_LOAD of a tracing program that calls one helper
#       (none: `r0 = 0; exit`) — what the content judge reads; (lot 349)
#       with --pin, pinned at PATH and its id printed ("OK fd N id I …")
#   bpf-probe.py load-fmod-ret --func FUNC [--fentry] [--name NAME]
#       (lot 345) BPF_PROG_LOAD of a `tracing` program on kernel function
#       FUNC (its BTF id read from /sys/kernel/btf/vmlinux) as fmod_ret
#       (BPF_MODIFY_RETURN), or fentry with --fentry; `r0 = 0; exit`
#   bpf-probe.py load-kfunc-signal --type syscall|xdp|tc|cgroup_skb --pid PID
#       [--sig N] [--no-signal] [--run] [--name NAME] [--pin PATH]
#       (the review of #553, F1) BPF_PROG_LOAD of a program of a type any
#       root loads with no opt-out that does t = bpf_task_from_pid(PID);
#       bpf_send_signal_task(t, N, PIDTYPE_TGID, 0); bpf_task_release(t)
#       (--no-signal: the lookup and the release only); with --run and a
#       syscall program, BPF_PROG_RUN it. Kfunc ids from the kernel's BTF.
#       On a refused load the verifier's last line is printed when it ran.
#   bpf-probe.py load-socket-filter [--pin PATH] [--name NAME]
#       BPF_PROG_LOAD of a socket filter (a type the agent lets through)
#   bpf-probe.py map-fd-by-id ID [--rdonly]
#   bpf-probe.py prog-fd-by-id ID [--run]
#       (lot 349) with --run, BPF_PROG_RUN on the handle given (a syscall
#       program: "OK fd N run OK retval R")
#   bpf-probe.py prog-ids | map-ids
#       (lot 349) every program / map id on the host (*_GET_NEXT_ID: no
#       handle)
#   bpf-probe.py obj-get PATH [--rdonly]
#   bpf-probe.py link-ids
#       (lot 301) every link id on the host (BPF_LINK_GET_NEXT_ID: no handle)
#   bpf-probe.py link-fd-by-id ID [--detach]
#       (lot 301) BPF_LINK_GET_FD_BY_ID; a handle given is described ("OK fd
#       N prog P": BPF_OBJ_GET_INFO_BY_FD) and, with --detach, BPF_LINK_DETACH
#       is tried on it ("... detach OK" / "... detach ERR <errno>")
#
# A program loaded with --pin is pinned at PATH (its directory made) so it
# outlives this process.
import ctypes
import errno
import os
import struct
import sys

SYS_BPF = 321  # x86_64
BPF_MAP_GET_FD_BY_ID = 14
BPF_PROG_LOAD = 5
BPF_OBJ_PIN = 6
BPF_OBJ_GET = 7
BPF_PROG_GET_FD_BY_ID = 13
BPF_OBJ_GET_INFO_BY_FD = 15
BPF_PROG_GET_NEXT_ID = 11
BPF_MAP_GET_NEXT_ID = 12
BPF_LINK_GET_FD_BY_ID = 30
BPF_LINK_GET_NEXT_ID = 31
BPF_LINK_DETACH = 34
BPF_F_RDONLY = 1 << 3
PROG_TYPE_SOCKET_FILTER = 1
PROG_TYPE_KPROBE = 2
WRITE_USER_TYPES = {"kprobe": 2, "tracepoint": 5, "perf_event": 7, "raw_tracepoint": 17}
PROG_TYPE_TRACING = 26
BPF_TRACE_FENTRY = 24
BPF_MODIFY_RETURN = 26
# lot 345: the helpers the content judge refuses, by uapi id
CALLS = {"send_signal": 109, "send_signal_thread": 117, "override_return": 58, "write_user": 36}
# the review of #553 (F1): types any root loads, no opt-out needed
OPEN_TYPES = {"syscall": 31, "xdp": 6, "tc": 3, "cgroup_skb": 8}
BPF_PROG_TEST_RUN = 10
BPF_F_SLEEPABLE = 1 << 4
PSEUDO_KFUNC_CALL = 2
PIDTYPE_TGID = 1

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long


def bpf(cmd, attr):
    buf = ctypes.create_string_buffer(attr, 128)
    r = libc.syscall(ctypes.c_long(SYS_BPF), ctypes.c_long(cmd), buf, ctypes.c_long(128))
    if r < 0:
        e = ctypes.get_errno()
        return None, e
    return r, 0


def insn(code, dst=0, src=0, off=0, imm=0):
    return struct.pack("<BBhi", code, (src << 4) | dst, off, imm)


def prog_load(prog_type, insns, name):
    code = b"".join(insns)
    code_buf = ctypes.create_string_buffer(code, len(code))
    lic = ctypes.create_string_buffer(b"GPL\0")
    nm = name.encode()[:15].ljust(16, b"\0")
    attr = struct.pack(
        "<IIQQIIQII16s",
        prog_type,
        len(insns),
        ctypes.addressof(code_buf),
        ctypes.addressof(lic),
        0,
        0,
        0,
        0,
        0,
        nm,
    )
    return bpf(BPF_PROG_LOAD, attr)


def prog_load_logged(prog_type, insns, name, flags=0):
    """BPF_PROG_LOAD with prog_flags and the verifier's log (its last line
    returned on a refusal; empty when the verifier never ran)."""
    code = b"".join(insns)
    code_buf = ctypes.create_string_buffer(code, len(code))
    lic = ctypes.create_string_buffer(b"GPL\0")
    log = ctypes.create_string_buffer(1 << 16)
    nm = name.encode()[:15].ljust(16, b"\0")
    attr = struct.pack(
        "<IIQQIIQII16s",
        prog_type, len(insns), ctypes.addressof(code_buf), ctypes.addressof(lic),
        1, len(log), ctypes.addressof(log), 0, flags, nm,
    )
    fd, e = bpf(BPF_PROG_LOAD, attr)
    text = log.value.decode(errors="replace").strip().splitlines()
    return fd, e, (text[-1] if text else "")


def prog_load_attach(prog_type, insns, name, attach_type, btf_id):
    """BPF_PROG_LOAD with expected_attach_type (byte 68) and attach_btf_id
    (byte 108)."""
    code = b"".join(insns)
    code_buf = ctypes.create_string_buffer(code, len(code))
    lic = ctypes.create_string_buffer(b"GPL\0")
    nm = name.encode()[:15].ljust(16, b"\0")
    attr = struct.pack(
        "<IIQQIIQII16sIIIIQIIQII",
        prog_type, len(insns), ctypes.addressof(code_buf), ctypes.addressof(lic),
        0, 0, 0, 0, 0, nm,
        0,            # prog_ifindex (64)
        attach_type,  # expected_attach_type (68)
        0, 0, 0, 0, 0, 0, 0,  # prog_btf_fd … line_info_cnt
        btf_id,       # attach_btf_id (108)
    )
    assert struct.calcsize("<IIQQIIQII16sIIIIQIIQII") == 112
    return bpf(BPF_PROG_LOAD, attr)


def btf_func_id(name, path="/sys/kernel/btf/vmlinux"):
    """The type id of FUNC `name` in the kernel's BTF (None if absent)."""
    data = open(path, "rb").read()
    _magic, _ver, _flags, hdr_len = struct.unpack_from("<HBBI", data, 0)
    type_off, type_len, str_off, _str_len = struct.unpack_from("<IIII", data, 8)
    t0, s0 = hdr_len + type_off, hdr_len + str_off
    extra = {1: lambda v: 4, 3: lambda v: 12, 4: lambda v: 12 * v, 5: lambda v: 12 * v,
             6: lambda v: 8 * v, 13: lambda v: 8 * v, 14: lambda v: 4, 15: lambda v: 12 * v,
             17: lambda v: 4, 19: lambda v: 12 * v}
    want = name.encode()
    p, tid = t0, 1
    while p < t0 + type_len:
        name_off, info, _ = struct.unpack_from("<III", data, p)
        kind, vlen = (info >> 24) & 0x1F, info & 0xFFFF
        if kind == 12:
            end = data.index(b"\0", s0 + name_off)
            if data[s0 + name_off:end] == want:
                return tid
        p += 12 + extra.get(kind, lambda v: 0)(vlen)
        tid += 1
    return None


def pin(fd, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    p = ctypes.create_string_buffer(path.encode() + b"\0")
    return bpf(BPF_OBJ_PIN, struct.pack("<QII", ctypes.addressof(p), fd, 0))


def prog_id(fd):
    """(lot 349) the id of program `fd` (struct bpf_prog_info: type, id)."""
    info = ctypes.create_string_buffer(64)
    _, ie = bpf(BPF_OBJ_GET_INFO_BY_FD, struct.pack("<IIQ", fd, 64, ctypes.addressof(info)))
    return struct.unpack_from("<I", info.raw, 4)[0] if ie == 0 else f"? (info errno {ie})"


def test_run(fd):
    """BPF_PROG_RUN of program `fd` (no input): " run OK retval R" or " run ERR E"."""
    attr = struct.pack("<IIIIQQIIIIQQIII", fd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    buf = ctypes.create_string_buffer(attr, 128)
    r = libc.syscall(ctypes.c_long(SYS_BPF), ctypes.c_long(BPF_PROG_TEST_RUN), buf, ctypes.c_long(128))
    re = ctypes.get_errno() if r < 0 else 0
    retval = struct.unpack_from("<I", buf.raw, 4)[0]
    return f" run {'OK retval ' + str(retval) if r >= 0 else 'ERR ' + errno.errorcode.get(re, '?')}"


def pinned(fd, args):
    """(lot 349) `--pin PATH`: pin `fd` there; the id and the pin, or ""."""
    path = opt(args, "--pin")
    if fd is None or not path:
        return ""
    _, pe = pin(fd, path)
    return f" id {prog_id(fd)}" + (f" pinned {path}" if pe == 0 else f" PIN-ERR {pe}")


def enum_ids(cmd):
    """(lot 349) every id `cmd` (a *_GET_NEXT_ID) enumerates."""
    out, cur = [], 0
    while True:
        buf = ctypes.create_string_buffer(struct.pack("<II", cur, 0), 128)
        r = libc.syscall(ctypes.c_long(SYS_BPF), ctypes.c_long(cmd), buf, ctypes.c_long(128))
        if r < 0:
            e = ctypes.get_errno()
            if e == errno.ENOENT:
                return out, 0
            return out, e
        cur = struct.unpack_from("<I", buf.raw, 4)[0]
        out.append(cur)


def report(fd, e, extra=""):
    if fd is None:
        print(f"ERR {errno.errorcode.get(e, '?')} {e}")
        return 1
    print(f"OK fd {fd}{extra}")
    return 0


def opt(args, flag, default=None):
    if flag in args:
        return args[args.index(flag) + 1]
    return default


def main(argv):
    if not argv:
        print(__doc__ or "usage", file=sys.stderr)
        return 2
    cmd, args = argv[0], argv[1:]
    if cmd in ("load-kprobe-write-user", "load-socket-filter"):
        if cmd == "load-kprobe-write-user":
            insns = [
                insn(0x7A, dst=10, off=-8, imm=0),  # *(u64 *)(r10 - 8) = 0
                insn(0xB7, dst=1, imm=0),  # r1 = 0 (the user address)
                insn(0xBF, dst=2, src=10),  # r2 = r10
                insn(0x07, dst=2, imm=-8),  # r2 += -8
                insn(0xB7, dst=3, imm=8),  # r3 = 8
                insn(0x85, imm=36),  # call bpf_probe_write_user
                insn(0xB7, dst=0, imm=0),  # r0 = 0
                insn(0x95),  # exit
            ]
            kind = opt(args, "--type", "kprobe")
            if kind not in WRITE_USER_TYPES:
                print(f"unknown --type {kind}", file=sys.stderr)
                return 2
            t, name = WRITE_USER_TYPES[kind], opt(args, "--name", "k290_wu")
        else:
            insns = [insn(0xB7, dst=0, imm=0), insn(0x95)]
            t, name = PROG_TYPE_SOCKET_FILTER, opt(args, "--name", "k290_sf")
        fd, e = prog_load(t, insns, name)
        path = opt(args, "--pin")
        if fd is not None and path:
            _, pe = pin(fd, path)
            return report(fd, 0, f" pinned {path}" if pe == 0 else f" PIN-ERR {pe}")
        return report(fd, e)
    if cmd == "load-tracing":
        kind = opt(args, "--type", "kprobe")
        call = opt(args, "--call", "none")
        if kind not in WRITE_USER_TYPES or (call != "none" and call not in CALLS):
            print(f"unknown --type {kind} or --call {call}", file=sys.stderr)
            return 2
        if call == "none":
            body = []
        elif call == "write_user":
            body = [
                insn(0x7A, dst=10, off=-8, imm=0),  # *(u64 *)(r10 - 8) = 0
                insn(0xB7, dst=1, imm=0),  # r1 = 0
                insn(0xBF, dst=2, src=10),  # r2 = r10
                insn(0x07, dst=2, imm=-8),  # r2 += -8
                insn(0xB7, dst=3, imm=8),  # r3 = 8
                insn(0x85, imm=CALLS[call]),
            ]
        elif call == "override_return":
            # r1 is the context (pt_regs) at entry
            body = [insn(0xB7, dst=2, imm=0), insn(0x85, imm=CALLS[call])]
        else:
            body = [insn(0xB7, dst=1, imm=0), insn(0x85, imm=CALLS[call])]
        insns = body + [insn(0xB7, dst=0, imm=0), insn(0x95)]
        fd, e = prog_load(WRITE_USER_TYPES[kind], insns, opt(args, "--name", "k345_tr"))
        return report(fd, e, pinned(fd, args))
    if cmd == "load-kfunc-signal":
        kind = opt(args, "--type", "syscall")
        pid = opt(args, "--pid")
        if kind not in OPEN_TYPES or pid is None:
            print(f"unknown --type {kind} or no --pid", file=sys.stderr)
            return 2
        ids = {k: btf_func_id(k) for k in ("bpf_task_from_pid", "bpf_send_signal_task", "bpf_task_release")}
        missing = [k for k, v in ids.items() if v is None]
        if missing:
            print(f"ERR NOFUNC {' '.join(missing)} not in the kernel's BTF")
            return 1
        sig = int(opt(args, "--sig", "9"))
        kcall = lambda k: insn(0x85, src=PSEUDO_KFUNC_CALL, imm=ids[k])
        signal = [] if "--no-signal" in args else [
            insn(0xBF, dst=1, src=6),  # r1 = task
            insn(0xB7, dst=2, imm=sig),  # r2 = sig
            insn(0xB7, dst=3, imm=PIDTYPE_TGID),  # r3 = PIDTYPE_TGID
            insn(0xB7, dst=4, imm=0),  # r4 = 0 (value)
            kcall("bpf_send_signal_task"),
        ]
        tail = signal + [insn(0xBF, dst=1, src=6), kcall("bpf_task_release")]
        insns = [
            insn(0xB7, dst=1, imm=int(pid)),  # r1 = pid
            kcall("bpf_task_from_pid"),  # r0 = task or NULL
            insn(0x15, dst=0, off=1 + len(tail), imm=0),  # if r0 == 0 goto out
            insn(0xBF, dst=6, src=0),  # r6 = task
        ] + tail + [insn(0xB7, dst=0, imm=0), insn(0x95)]  # out: r0 = 0; exit
        flags = BPF_F_SLEEPABLE if kind == "syscall" else 0
        fd, e, last = prog_load_logged(OPEN_TYPES[kind], insns, opt(args, "--name", "k553_kf"), flags)
        if fd is None:
            print(f"ERR {errno.errorcode.get(e, '?')} {e}" + (f" verifier: {last[:160]}" if last else ""))
            return 1
        extra = pinned(fd, args)
        if "--run" in args and kind == "syscall":
            extra += test_run(fd)
        os.close(fd)
        print(f"OK fd {fd}{extra}")
        return 0
    if cmd == "load-fmod-ret":
        func = opt(args, "--func", "security_file_open")
        btf_id = btf_func_id(func)
        if btf_id is None:
            print(f"ERR NOFUNC {func} not in the kernel's BTF")
            return 1
        at = BPF_TRACE_FENTRY if "--fentry" in args else BPF_MODIFY_RETURN
        insns = [insn(0xB7, dst=0, imm=0), insn(0x95)]
        fd, e = prog_load_attach(PROG_TYPE_TRACING, insns, opt(args, "--name", "k345_fm"), at, btf_id)
        return report(fd, e, f" ({func} btf id {btf_id})")
    if cmd == "map-fd-by-id":
        flags = BPF_F_RDONLY if "--rdonly" in args else 0
        return report(*bpf(BPF_MAP_GET_FD_BY_ID, struct.pack("<III", int(args[0]), 0, flags)))
    if cmd == "prog-fd-by-id":
        fd, e = bpf(BPF_PROG_GET_FD_BY_ID, struct.pack("<III", int(args[0]), 0, 0))
        return report(fd, e, test_run(fd) if fd is not None and "--run" in args else "")
    if cmd in ("prog-ids", "map-ids"):
        found, e = enum_ids(BPF_PROG_GET_NEXT_ID if cmd == "prog-ids" else BPF_MAP_GET_NEXT_ID)
        if e:
            print(f"ERR {errno.errorcode.get(e, '?')} {e}")
            return 1
        print("OK " + " ".join(str(i) for i in found))
        return 0
    if cmd == "obj-get":
        flags = BPF_F_RDONLY if "--rdonly" in args else 0
        p = ctypes.create_string_buffer(args[0].encode() + b"\0")
        return report(*bpf(BPF_OBJ_GET, struct.pack("<QII", ctypes.addressof(p), 0, flags)))
    if cmd == "link-ids":
        ids, cur = [], 0
        while True:
            buf = ctypes.create_string_buffer(struct.pack("<II", cur, 0), 128)
            r = libc.syscall(ctypes.c_long(SYS_BPF), ctypes.c_long(BPF_LINK_GET_NEXT_ID), buf, ctypes.c_long(128))
            if r < 0:
                e = ctypes.get_errno()
                if e == errno.ENOENT:
                    break
                print(f"ERR {errno.errorcode.get(e, '?')} {e}")
                return 1
            cur = struct.unpack_from("<I", buf.raw, 4)[0]
            ids.append(cur)
        print("OK " + " ".join(str(i) for i in ids))
        return 0
    if cmd == "link-fd-by-id":
        fd, e = bpf(BPF_LINK_GET_FD_BY_ID, struct.pack("<III", int(args[0]), 0, 0))
        if fd is None:
            return report(fd, e)
        # struct bpf_link_info: type, id, prog_id (then the type's union)
        info = ctypes.create_string_buffer(64)
        _, ie = bpf(BPF_OBJ_GET_INFO_BY_FD, struct.pack("<IIQ", fd, 64, ctypes.addressof(info)))
        prog = struct.unpack_from("<I", info.raw, 8)[0] if ie == 0 else f"? (info errno {ie})"
        extra = f" prog {prog}"
        if "--detach" in args:
            _, de = bpf(BPF_LINK_DETACH, struct.pack("<I", fd))
            extra += " detach OK" if de == 0 else f" detach ERR {errno.errorcode.get(de, '?')} {de}"
        os.close(fd)
        return report(fd, 0, extra)
    print(f"unknown command {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
