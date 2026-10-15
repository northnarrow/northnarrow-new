#!/usr/bin/env bash
# Runs on the guest as root: every nn-bench workload once, and — when the
# agent is running — the agent's own CPU time spent while the workload ran
# (utime+stime delta of its pid). Output: "<workload> <ops/s> <agent_cpu_ms>".
set -euo pipefail
BIN=${1:?usage: run.sh <nn-bench binary>}
# External audit LAB-008: a fresh root-only directory (mktemp: 0700, an
# unpredictable name). The fixed /var/tmp/nn-bench could be created first by
# any user, with links that root's writes would follow.
WORK=$(mktemp -d /var/tmp/nn-bench.XXXXXXXX)
trap 'rm -rf "$WORK"' EXIT
agent_ticks() {
    local p
    p=$(cat /run/northnarrow/agent.pid 2>/dev/null) || { echo 0; return; }
    awk '{print $14 + $15}' "/proc/$p/stat" 2>/dev/null || echo 0
}
hz=$(getconf CLK_TCK)
for w in "open 200000" "wopen 50000" "exec 2000" "connect 5000" "udp 200000" "dns 20000"; do
    t0=$(agent_ticks)
    r=$("$BIN" $w "$WORK")
    t1=$(agent_ticks)
    echo "$r $(( (t1 - t0) * 1000 / hz ))"
done
