#!/usr/bin/env python3
"""Lot 277 (the review of #494, N10): the start-in-cgroup tracker's pinned
maps read on a lab guest, read-only (BPF_OBJ_GET with BPF_F_RDONLY: the
agent's BPF map guard refuses a write handle to any other process).

usage (root): cgroup-marks.py mark PID...   one line per pid:
                  "<pid> moved|born|inherited <by>", "<pid> lost",
                  (lot 281) "<pid> injected <by>", "<pid> taint-inherited
                  <by>", or the placement and the taint joined by "+"
                  ("moved+injected <by>"),
                  "<pid> pre-epoch" (started before the marks' last reset:
                  not known) or "<pid> -"
              cgroup-marks.py stat           "lost N roots N inherited N into_exempt N injected N"
              cgroup-marks.py dir            the tracker's pin directory
              cgroup-marks.py epoch          "mono N boot N" (0 0: no reset this boot)
              cgroup-marks.py plant DIR      (a lab case) DIR made, an LRU hash
                                             shaped like the marks pinned in it
                                             as CGROUP_JOINED

The re-review of #494 (R1, R2) and its third review: the maps are in the
tracker's own pin directory beside the pin root, the one the agent
registered in /run/northnarrow/cgroup-join-pins
(/sys/fs/bpf/northnarrow-cgroup-join-v<schema>_<generation>);
CGROUP_JOIN_LOST holds a byte per tgid (64 an entry); CGROUP_JOIN_EPOCH the
last reset's instant.
"""
import ctypes
import glob
import os
import struct
import sys

PIN_ROOT = "/sys/fs/bpf/northnarrow"
STATE = "/run/northnarrow/cgroup-join-pins"


def tracker_dir():
    try:
        for line in open(STATE):
            if line.startswith("dir "):
                d = line.split(None, 1)[1].strip()
                if os.path.isdir(d):
                    return d
    except OSError:
        pass
    dirs = sorted(glob.glob(PIN_ROOT + "-cgroup-join-v*"))
    if len(dirs) != 1:
        raise SystemExit(f"cgroup-marks: {len(dirs)} tracker pin directories: {dirs}")
    return dirs[0]


SYS_BPF = 321  # x86_64
BPF_MAP_CREATE = 0
BPF_MAP_LOOKUP_ELEM = 1
BPF_OBJ_PIN = 6
BPF_OBJ_GET = 7
BPF_F_RDONLY = 1 << 3
LRU_HASH = 9
HOW = {1: "moved", 2: "born", 3: "inherited"}

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long


def obj_get(name):
    path = ctypes.create_string_buffer(f"{tracker_dir()}/{name}".encode())
    attr = (ctypes.c_uint8 * 128)()
    struct.pack_into("<QII", attr, 0, ctypes.addressof(path), 0, BPF_F_RDONLY)
    fd = libc.syscall(SYS_BPF, BPF_OBJ_GET, ctypes.byref(attr), ctypes.c_uint(128))
    if fd < 0:
        raise OSError(ctypes.get_errno(), f"BPF_OBJ_GET {name}")
    return fd


def lookup(fd, key, size):
    k = ctypes.create_string_buffer(key, len(key))
    v = ctypes.create_string_buffer(size)
    attr = (ctypes.c_uint8 * 128)()
    struct.pack_into("<IIQQQ", attr, 0, fd, 0, ctypes.addressof(k), ctypes.addressof(v), 0)
    r = libc.syscall(SYS_BPF, BPF_MAP_LOOKUP_ELEM, ctypes.byref(attr), ctypes.c_uint(128))
    return v.raw if r == 0 else None


def epoch():
    fd = obj_get("CGROUP_JOIN_EPOCH")
    return [struct.unpack("<Q", lookup(fd, struct.pack("<I", i), 8))[0] for i in range(2)]


def start_boot_ns(pid):
    stat = open(f"/proc/{pid}/stat").read()
    ticks = int(stat.rsplit(")", 1)[1].split()[19])
    return ticks * (1_000_000_000 // os.sysconf("SC_CLK_TCK"))


def plant(d):
    os.makedirs(d, mode=0o700, exist_ok=True)
    attr = (ctypes.c_uint8 * 128)()
    struct.pack_into("<IIIII", attr, 0, LRU_HASH, 4, 16, 64, 0)
    fd = libc.syscall(SYS_BPF, BPF_MAP_CREATE, ctypes.byref(attr), ctypes.c_uint(128))
    if fd < 0:
        raise SystemExit("map create: errno %d" % ctypes.get_errno())
    path = ctypes.create_string_buffer((d + "/CGROUP_JOINED").encode())
    attr = (ctypes.c_uint8 * 128)()
    struct.pack_into("<QI", attr, 0, ctypes.addressof(path), fd)
    if libc.syscall(SYS_BPF, BPF_OBJ_PIN, ctypes.byref(attr), ctypes.c_uint(128)) != 0:
        raise SystemExit("pin: errno %d" % ctypes.get_errno())
    print("planted", d + "/CGROUP_JOINED")


def main():
    cmd = sys.argv[1:2]
    if cmd == ["dir"]:
        print(tracker_dir())
        return
    if cmd == ["plant"]:
        plant(sys.argv[2])
        return
    if cmd == ["epoch"]:
        mono, boot = epoch()
        print("mono", mono, "boot", boot)
        return
    if cmd == ["stat"]:
        fd = obj_get("CGROUP_JOIN_STATS")
        vals = [struct.unpack("<Q", lookup(fd, struct.pack("<I", i), 8))[0] for i in range(5)]
        print("lost %d roots %d inherited %d into_exempt %d injected %d" % tuple(vals))
        return
    joined, lost = obj_get("CGROUP_JOINED"), obj_get("CGROUP_JOIN_LOST")
    epoch_boot = epoch()[1]
    for p in sys.argv[2:]:
        pid = int(p)
        entry = lookup(lost, struct.pack("<I", pid // 64), 64)
        if entry and entry[pid % 64] != 0:
            print(pid, "lost")
            continue
        if epoch_boot and start_boot_ns(pid) <= epoch_boot:
            print(pid, "pre-epoch")
            continue
        rec = lookup(joined, struct.pack("<I", pid), 16)
        if rec is None:
            print(pid, "-")
            continue
        _, info = struct.unpack("<QQ", rec)
        how = (info >> 32) & 0xFF
        words = [HOW.get(how & 0x0F, "?")] if how & 0x0F else []
        if how & 0x80:
            words.append("injected")
        elif how & 0x40:
            words.append("taint-inherited")
        print(pid, "+".join(words) or "?", info & 0xFFFFFFFF)


if __name__ == "__main__":
    main()
