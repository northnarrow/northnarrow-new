#!/usr/bin/env python3
"""Lot 277 (the review of #494, N10): the start-in-cgroup tracker's pinned
maps read on a lab guest, read-only (BPF_OBJ_GET with BPF_F_RDONLY: the
agent's BPF map guard refuses a write handle to any other process).

usage (root): cgroup-marks.py mark PID...   one line per pid:
                  "<pid> moved|born|inherited <by>", "<pid> lost" or "<pid> -"
              cgroup-marks.py stat           "lost N roots N inherited N into_exempt N"
              cgroup-marks.py dir            the tracker's pin directory

The re-review of #494 (R1, R2): the maps are in the tracker's own pin
directory beside the pin root (/sys/fs/bpf/northnarrow-cgroup-join-v<schema>-
<entries>), and CGROUP_JOIN_LOST holds a byte per tgid (64 an entry).
"""
import ctypes
import glob
import struct
import sys

PIN_ROOT = "/sys/fs/bpf/northnarrow"


def tracker_dir():
    dirs = sorted(glob.glob(PIN_ROOT + "-cgroup-join-v*-*"))
    if len(dirs) != 1:
        raise SystemExit(f"cgroup-marks: {len(dirs)} tracker pin directories: {dirs}")
    return dirs[0]


SYS_BPF = 321  # x86_64
BPF_MAP_LOOKUP_ELEM = 1
BPF_OBJ_GET = 7
BPF_F_RDONLY = 1 << 3
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


def main():
    if sys.argv[1:2] == ["dir"]:
        print(tracker_dir())
        return
    if sys.argv[1:2] == ["stat"]:
        fd = obj_get("CGROUP_JOIN_STATS")
        vals = [struct.unpack("<Q", lookup(fd, struct.pack("<I", i), 8))[0] for i in range(4)]
        print("lost %d roots %d inherited %d into_exempt %d" % tuple(vals))
        return
    joined, lost = obj_get("CGROUP_JOINED"), obj_get("CGROUP_JOIN_LOST")
    for p in sys.argv[2:]:
        pid = int(p)
        entry = lookup(lost, struct.pack("<I", pid // 64), 64)
        if entry and entry[pid % 64] != 0:
            print(pid, "lost")
            continue
        rec = lookup(joined, struct.pack("<I", pid), 16)
        if rec is None:
            print(pid, "-")
            continue
        _, info = struct.unpack("<QQ", rec)
        print(pid, HOW.get(info >> 32, "?"), info & 0xFFFFFFFF)


if __name__ == "__main__":
    main()
