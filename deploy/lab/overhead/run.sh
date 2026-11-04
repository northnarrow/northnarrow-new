#!/usr/bin/env bash
# Runs on the guest as root: every nn-bench workload once, and — when the
# agent is running — the agent's own CPU time spent while the workload ran
# (utime+stime delta of its pid). Output: "<workload> <ops/s> <agent_cpu_ms>".
# R14a: and of its workers — the live ones (its children running its
# binary, `nn-worker-*`) and those it reaped (cutime+cstime): the parsing a
# worker does is the agent's cost.
set -euo pipefail
BIN=${1:?usage: run.sh <nn-bench binary>}
# External audit LAB-008: a fresh root-only directory (mktemp: 0700, an
# unpredictable name). The fixed /var/tmp/nn-bench could be created first by
# any user, with links that root's writes would follow.
WORK=$(mktemp -d /var/tmp/nn-bench.XXXXXXXX)
trap 'rm -rf "$WORK"' EXIT
agent_ticks() {
    local p own w t
    p=$(cat /run/northnarrow/agent.pid 2>/dev/null) || { echo 0; return; }
    # utime+stime, and the children it waited for (cutime+cstime)
    own=$(awk '{print $14 + $15 + $16 + $17}' "/proc/$p/stat" 2>/dev/null || echo 0)
    w=0
    for t in /proc/[0-9]*; do
        [[ $(awk '{print $4}' "$t/stat" 2>/dev/null) == "$p" ]] || continue
        [[ $(cat "$t/comm" 2>/dev/null) == nn-worker-* ]] || continue
        w=$(( w + $(awk '{print $14 + $15}' "$t/stat" 2>/dev/null || echo 0) ))
    done
    echo $(( own + w ))
}
hz=$(getconf CLK_TCK)
for w in "open 200000" "wopen 50000" "exec 2000" "connect 5000" "udp 200000" "dns 20000" "tcpsend 200000" "udprecv 200000" "getppid 5000000" "rdzero 2000000"; do
    t0=$(agent_ticks)
    r=$("$BIN" $w "$WORK")
    t1=$(agent_ticks)
    echo "$r $(( (t1 - t0) * 1000 / hz ))"
done
