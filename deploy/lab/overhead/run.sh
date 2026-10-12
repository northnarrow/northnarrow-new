#!/usr/bin/env bash
# Runs on the guest as root: every nn-bench workload once, and — when the
# agent is running — the agent's own CPU time spent while the workload ran
# (utime+stime delta of its pid). Output: "<workload> <ops/s> <agent_cpu_ms>".
set -euo pipefail
BIN=${1:?usage: run.sh <nn-bench binary>}
WORK=/var/tmp/nn-bench
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
rm -rf "$WORK"
