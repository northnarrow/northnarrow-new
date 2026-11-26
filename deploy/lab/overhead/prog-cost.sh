#!/usr/bin/env bash
# Lot 275 (review of #495, D5): the per-call cost of the agent's BPF
# programs on the hot paths a workload drives — run_time_ns / run_cnt, with
# kernel.bpf_stats_enabled=1 for the measurement only (the stats add two
# clock reads to every call; the A/B overhead rounds run with them off, as
# lot 273c's). Each workload runs alone; the programs whose name starts
# with one of the prefixes are read before and after it.
#
# usage: sudo prog-cost.sh [prefix…]
#        sudo prog-cost.sh --lru-capacity <files> [map…]
#   default prefixes: the lot 275 programs (dns_answer, inbound_accept,
#   tls_client_hel — the kernel keeps 15 characters of a name) and lot
#   1.4's (fim_file_open_s, fim_unlink_obse, tcp_close)
#   PROG_COST_WORKLOADS="<name> <count>;…" picks the workloads (default:
#   every one below, in this order).
# Prints one line per workload and program: calls and ns per call.
#
# The workloads: nn-bench's `udprecv`, `udp`, `tcpsend`, `connect`, `open`,
# `wopen` (deploy/lab/overhead/nn-bench.c), and lot 1.4's, in python (the
# per-call cost of a program does not depend on the loop around it):
#   udpconn  a datagram received on a CONNECTED UDP socket from a port other
#            than 53 (the DNS response program's port filter, F8)
#   passwd   a read-only open of /etc/passwd (FIM-watched and sensitive: the
#            read-repeat filter judges every one, F7)
#   create   a file created then unlinked, each a new name (the file-open
#            sensor's OPEN_CREATED / OPEN_DESTROY_SEEN inserts, F9)
#   create4  the same, four writers at once, one per CPU (the LRU maps'
#            common list under contention, F9)
# --lru-capacity <n>: n files created, kept, on CPU 0 alone, then each map
# named (default: lot 1.4's three "safe" LRU maps of the sensor) counted —
# how many entries a burst on one CPU keeps (F9: a per-CPU LRU list holds
# max_entries / possible CPUs).
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
[[ $(id -u) -eq 0 ]] || { echo "prog-cost: run as root" >&2; exit 2; }
command -v bpftool >/dev/null || { echo "prog-cost: no bpftool" >&2; exit 2; }
# As run.sh: a fresh root-only work directory, the binary root-owned in a
# root-owned tree — an image run from /tmp, /var/tmp or a user's home is
# what R001, R003 and R009 kill (the lab's first round: every workload
# killed under the agent).
WORK=$(mktemp -d /var/tmp/nn-bench.XXXXXXXX)
BIN=/usr/local/libexec/nn-lab/nn-bench-cost
before=$(sysctl -n kernel.bpf_stats_enabled)
cleanup() { sysctl -qw kernel.bpf_stats_enabled="$before"; rm -rf "$WORK"; }
trap cleanup EXIT

# The python workloads (`python3 -I -B`: no site, no bytecode left behind).
PY_UDPCONN='
import socket, sys
n = int(sys.argv[1])
r = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
r.bind(("127.0.0.1", 0))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 0))
r.connect(s.getsockname())
s.connect(r.getsockname())
buf = b"c" * 64
for _ in range(n):
    s.send(buf)
    r.recv(64)
'
PY_PASSWD='
import os, sys
n = int(sys.argv[1])
for _ in range(n):
    fd = os.open("/etc/passwd", os.O_RDONLY)
    os.read(fd, 64)
    os.close(fd)
'
PY_CREATE='
import os, sys
n, d = int(sys.argv[1]), sys.argv[2]
for i in range(n):
    p = os.path.join(d, "c%d" % i)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, b"n" * 64)
    os.close(fd)
    os.unlink(p)
'
PY_KEEP='
import os, sys
n, d = int(sys.argv[1]), sys.argv[2]
for i in range(n):
    fd = os.open(os.path.join(d, "k%d" % i), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
'

# The number of entries of the map named `$1` (bpftool keeps 15 characters).
map_count() {
    bpftool map dump name "${1:0:15}" -j 2>/dev/null | python3 -I -c '
import json, sys
try:
    print(len(json.load(sys.stdin)))
except Exception:
    print("unreadable")
'
}

if [[ ${1:-} == --lru-capacity ]]; then
    n=${2:?files}; shift 2
    maps=${*:-OPEN_CREATED OPEN_OVERWRITE_SEEN OPEN_DESTROY_SEEN}
    echo "# lru-capacity $(uname -r) $(date -u +%FT%TZ) online $(nproc) possible $(cat /sys/devices/system/cpu/possible)"
    for m in $maps; do
        echo "map $m before: $(map_count "$m") entries ($(bpftool map show name "${m:0:15}" 2>/dev/null | head -1 | grep -oE 'flags 0x[0-9a-f]+' || echo 'flags ?'))"
    done
    mkdir -p "$WORK/keep"
    taskset -c 0 python3 -I -B -c "$PY_KEEP" "$n" "$WORK/keep" </dev/null
    for m in $maps; do
        echo "map $m after $n creations on CPU 0: $(map_count "$m") entries"
    done
    exit 0
fi

if [[ $# -gt 0 ]]; then
    PREFIXES="$*"
else
    PREFIXES="dns_answer inbound_accept tls_client_hel fim_file_open_s fim_unlink_obse tcp_close"
fi
WORKLOADS=${PROG_COST_WORKLOADS:-"udprecv 200000;udp 200000;udpconn 200000;tcpsend 200000;connect 20000;open 200000;wopen 50000;passwd 200000;create 50000;create4 20000"}
mkdir -p /usr/local/libexec/nn-lab
cc -O2 -o "$BIN" "$HERE/nn-bench.c" || exit 2
sysctl -qw kernel.bpf_stats_enabled=1
snap() {
    bpftool prog show -j | PREFIXES="$PREFIXES" python3 -I -c '
import json, os, sys
pre = tuple(os.environ["PREFIXES"].split())
for p in json.load(sys.stdin):
    n = p.get("name", "")
    if n.startswith(pre):
        print(p["id"], n, p.get("run_time_ns", 0), p.get("run_cnt", 0))
'
}
# One workload, `$1` its name and `$2` its count.
run_workload() {
    case $1 in
        udpconn) python3 -I -B -c "$PY_UDPCONN" "$2" </dev/null ;;
        passwd) python3 -I -B -c "$PY_PASSWD" "$2" </dev/null ;;
        create) mkdir -p "$WORK/c" && python3 -I -B -c "$PY_CREATE" "$2" "$WORK/c" </dev/null ;;
        create4)
            local cpus i pids=()
            cpus=$(nproc)
            for i in 0 1 2 3; do
                mkdir -p "$WORK/c4-$i"
                taskset -c $((i % cpus)) python3 -I -B -c "$PY_CREATE" "$2" "$WORK/c4-$i" </dev/null &
                pids+=($!)
            done
            wait "${pids[@]}"
            ;;
        *) "$BIN" "$1" "$2" "$WORK" >/dev/null ;;
    esac
}
echo "# prog-cost $(uname -r) $(date -u +%FT%TZ)"
printf '%-9s %-16s %10s %10s\n' workload program calls ns/call
IFS=';' read -ra list <<< "$WORKLOADS"
for w in "${list[@]}"; do
    set -- $w
    a=$(snap)
    run_workload "$1" "$2" || echo "prog-cost: $1 failed" >&2
    b=$(snap)
    python3 -I - "$1" <<PY
import sys
w = sys.argv[1]
def rows(t):
    out = {}
    for line in t.strip().splitlines():
        i, n, rt, c = line.split()
        out[i] = (n, int(rt), int(c))
    return out
a = rows("""$a""")
b = rows("""$b""")
for i, (n, rt, c) in sorted(b.items()):
    n0, rt0, c0 = a.get(i, (n, 0, 0))
    dc, drt = c - c0, rt - rt0
    if dc > 0:
        print(f"{w:<9} {n:<16} {dc:>10} {drt / dc:>10.1f}")
PY
done
