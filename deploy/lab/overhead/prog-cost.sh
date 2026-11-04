#!/usr/bin/env bash
# Lot 275 (review of #495, D5): the per-call cost of the agent's BPF
# programs on the hot paths a workload drives — run_time_ns / run_cnt, with
# kernel.bpf_stats_enabled=1 for the measurement only (the stats add two
# clock reads to every call; the A/B overhead rounds run with them off, as
# lot 273c's). Each workload of nn-bench runs alone; the programs whose name
# starts with one of the prefixes are read before and after it.
#
# usage: sudo prog-cost.sh [prefix…]
#   default prefixes: the lot 275 programs (dns_answer, inbound_accept,
#   tls_client_hel — the kernel keeps 15 characters of a name)
# Prints one line per workload and program: calls and ns per call.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
[[ $(id -u) -eq 0 ]] || { echo "prog-cost: run as root" >&2; exit 2; }
command -v bpftool >/dev/null || { echo "prog-cost: no bpftool" >&2; exit 2; }
if [[ $# -gt 0 ]]; then PREFIXES="$*"; else PREFIXES="dns_answer inbound_accept tls_client_hel"; fi
# As run.sh: a fresh root-only work directory, the binary root-owned in a
# root-owned tree — an image run from /tmp, /var/tmp or a user's home is
# what R001, R003 and R009 kill (the lab's first round: every workload
# killed under the agent).
WORK=$(mktemp -d /var/tmp/nn-bench.XXXXXXXX)
BIN=/usr/local/libexec/nn-lab/nn-bench-cost
before=$(sysctl -n kernel.bpf_stats_enabled)
cleanup() { sysctl -qw kernel.bpf_stats_enabled="$before"; rm -rf "$WORK"; }
trap cleanup EXIT
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
echo "# prog-cost $(uname -r) $(date -u +%FT%TZ)"
printf '%-9s %-16s %10s %10s\n' workload program calls ns/call
for w in "udprecv 200000" "udp 200000" "tcpsend 200000" "connect 20000"; do
    set -- $w
    a=$(snap)
    "$BIN" "$1" "$2" "$WORK" >/dev/null || echo "prog-cost: $1 failed" >&2
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
