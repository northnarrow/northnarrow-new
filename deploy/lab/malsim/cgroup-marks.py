#!/usr/bin/env python3
"""Lot 277 (the review of #494, N10): the start-in-cgroup tracker's pinned
maps read on a lab guest, read-only (BPF_OBJ_GET with BPF_F_RDONLY: the
agent's BPF map guard refuses a write handle to any other process).

usage (root): cgroup-marks.py mark PID...   one line per pid:
                  "<pid> moved|born|inherited <by>", "<pid> lost" or "<pid> -"
              cgroup-marks.py stat           "lost N roots N inherited N into_exempt N"
"""
import ctypes
import struct
import sys

ROOT = "/sys/fs/bpf/northnarrow"
SYS_BPF = 321  # x86_64
BPF_MAP_LOOKUP_ELEM = 1
BPF_OBJ_GET = 7
BPF_F_RDONLY = 1 << 3
HOW = {1: "moved", 2: "born", 3: "inherited"}

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long


def obj_get(name):
    path = ctypes.create_string_buffer(f"{ROOT}/{name}".encode())
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
    if sys.argv[1:2] == ["stat"]:
        fd = obj_get("CGROUP_JOIN_STATS")
        vals = [struct.unpack("<Q", lookup(fd, struct.pack("<I", i), 8))[0] for i in range(4)]
        print("lost %d roots %d inherited %d into_exempt %d" % tuple(vals))
        return
    joined, lost = obj_get("CGROUP_JOINED"), obj_get("CGROUP_JOIN_LOST")
    for p in sys.argv[2:]:
        pid = int(p)
        word = lookup(lost, struct.pack("<I", pid >> 6), 8)
        if word and struct.unpack("<Q", word)[0] & (1 << (pid & 63)):
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
