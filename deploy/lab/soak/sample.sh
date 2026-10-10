#!/usr/bin/env bash
# deploy/lab/soak/sample.sh — periodic resource sampler for the soak test
# (runs ON THE GUEST as root, started by `nn-lab.sh soak start`).
#
# Appends one CSV row every $SOAK_INTERVAL seconds to $SOAK_DIR/samples.csv:
# memory and CPU of the agent and watchdog, fds/threads, systemd restart
# counters, journal warning/error counts since the start, chain-log
# sizes, eBPF map occupancy (LRU/hash maps that could grow) and the
# ring-buffer drop counter. Stops when $SOAK_DIR/stop exists.
set -u
SOAK_DIR=${SOAK_DIR:-/home/nn/soak}
INTERVAL=${SOAK_INTERVAL:-60}
OUT="$SOAK_DIR/samples.csv"
START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "$$" > "$SOAK_DIR/sample.pid"
echo "$START" > "$SOAK_DIR/start"
if [ ! -s "$OUT" ]; then
    echo "epoch,agent_pid,agent_rss_kb,agent_vsz_kb,agent_cpu_pct,agent_threads,agent_fds,wd_rss_kb,agent_restarts,wd_restarts,journal_warn,journal_err,combat_lines,det_bytes,status_bytes,audit_bytes,fim_bytes,flow_sock,udp_seen,fim_dirty,protected_pids,ringbuf_dropped,generate_iter" > "$OUT"
fi

map_count() { # elements of the first map named $1 (0 when absent)
    bpftool map dump name "$1" 2>/dev/null | grep -c '^key' || true
}
prev_ticks=0; prev_time=0; hz=$(getconf CLK_TCK)
while [ ! -e "$SOAK_DIR/stop" ]; do
    pid=$(cat /run/northnarrow/agent.pid 2>/dev/null || pgrep -o -f '^/usr/local/bin/northnarrow-agent' || echo 0)
    now=$(date +%s)
    rss=0; vsz=0; thr=0; fds=0; cpu=0
    if [ "$pid" != 0 ] && [ -r "/proc/$pid/stat" ]; then
        read -r rss vsz thr < <(awk '/^VmRSS/{r=$2} /^VmSize/{v=$2} /^Threads/{t=$2} END{print r+0, v+0, t+0}' "/proc/$pid/status")
        fds=$(ls "/proc/$pid/fd" 2>/dev/null | wc -l)
        ticks=$(awk '{print $14+$15}' "/proc/$pid/stat")
        if [ "$prev_time" != 0 ] && [ "$now" -gt "$prev_time" ]; then
            cpu=$(( (ticks - prev_ticks) * 100 / hz / (now - prev_time) ))
            [ "$cpu" -lt 0 ] && cpu=0
        fi
        prev_ticks=$ticks; prev_time=$now
    fi
    wdpid=$(pgrep -o -f '^/usr/local/bin/northnarrow-watchdog' || echo 0)
    wdrss=0; [ "$wdpid" != 0 ] && wdrss=$(awk '/^VmRSS/{print $2}' "/proc/$wdpid/status" 2>/dev/null || echo 0)
    ar=$(systemctl show -p NRestarts --value northnarrow-agent 2>/dev/null || echo 0)
    wr=$(systemctl show -p NRestarts --value northnarrow-watchdog 2>/dev/null || echo 0)
    jw=$(journalctl -u northnarrow-agent --since "$START" -p 4 -q --no-pager 2>/dev/null | wc -l)
    je=$(journalctl -u northnarrow-agent --since "$START" -p 3 -q --no-pager 2>/dev/null | wc -l)
    cb=$(journalctl -u northnarrow-agent --since "$START" -q --no-pager 2>/dev/null | grep -c "COMBAT" || true)
    sz() { stat -c %s "$1" 2>/dev/null || echo 0; }
    det=$(sz /var/lib/northnarrow/detections/detections.jsonl)
    sts=$(sz /var/lib/northnarrow/detections/status_events.jsonl)
    aud=$(sz /etc/northnarrow/audit.log)
    fim=$(sz /var/lib/northnarrow/fim_drift.jsonl)
    fs=$(map_count FLOW_SOCK_MAP); us=$(map_count UDP_UNCONNECTED_SEEN); fd=$(map_count FIM_DIRTY_INODES); pp=$(map_count PROTECTED_PIDS)
    # per-CPU u64 counter: bpftool prints one `value (cpu N): 0x…` or
    # decimal line per CPU; sum them without gawk-only builtins.
    drops=$(bpftool map dump name DROPPED 2>/dev/null | grep -i 'value' | grep -oE '(0x[0-9a-f]+|[0-9]+)$' | while read -r v; do printf '%d\n' "$v"; done | awk '{s+=$1} END{print s+0}')
    gi=$(cat "$SOAK_DIR/generate.iter" 2>/dev/null || echo 0)
    echo "$now,$pid,$rss,$vsz,$cpu,$thr,$fds,$wdrss,$ar,$wr,$jw,$je,$cb,$det,$sts,$aud,$fim,$fs,$us,$fd,$pp,$drops,$gi" >> "$OUT"
    sleep "$INTERVAL"
done
rm -f "$SOAK_DIR/sample.pid"
